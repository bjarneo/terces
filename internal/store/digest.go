package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// AgeBucket counts open findings in an age range.
type AgeBucket struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// Digest summarizes the open findings by age.
type Digest struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Open        int            `json:"open"`
	BySeverity  map[string]int `json:"by_severity"`
	ByAge       []AgeBucket    `json:"by_age"`
	ByOrg       map[string]int `json:"by_org"`
	// Oldest lists the oldest open critical and high findings.
	Oldest []Secret `json:"oldest"`
}

// Digest returns the data for the weekly digest.
func (s *Store) Digest(ctx context.Context) (*Digest, error) {
	d := &Digest{GeneratedAt: time.Now().UTC(), BySeverity: map[string]int{}, ByOrg: map[string]int{}}
	rows, err := s.pool.Query(ctx, `select severity, count(*) from secrets where state = 'open' group by severity`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, err
		}
		d.BySeverity[sev] = n
		d.Open += n
	}
	rows.Close()

	var b [4]int
	err = s.pool.QueryRow(ctx, `select
			count(*) filter (where first_seen_at > now() - interval '7 days'),
			count(*) filter (where first_seen_at <= now() - interval '7 days' and first_seen_at > now() - interval '30 days'),
			count(*) filter (where first_seen_at <= now() - interval '30 days' and first_seen_at > now() - interval '90 days'),
			count(*) filter (where first_seen_at <= now() - interval '90 days')
		from secrets where state = 'open'`).Scan(&b[0], &b[1], &b[2], &b[3])
	if err != nil {
		return nil, err
	}
	d.ByAge = []AgeBucket{
		{"less than 7 days", b[0]},
		{"7 to 30 days", b[1]},
		{"30 to 90 days", b[2]},
		{"more than 90 days", b[3]},
	}

	rows, err = s.pool.Query(ctx, `select r.org, count(distinct s.fingerprint)
		from secrets s join locations l on l.fingerprint = s.fingerprint join repos r on r.id = l.repo_id
		where s.state = 'open' group by r.org`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var org string
		var n int
		if err := rows.Scan(&org, &n); err != nil {
			rows.Close()
			return nil, err
		}
		d.ByOrg[org] = n
	}
	rows.Close()

	oldest, err := s.ListSecrets(ctx, ListFilter{State: StateOpen, MinSeverity: 3, Limit: 200})
	if err != nil {
		return nil, err
	}
	// ListSecrets orders by severity first. The digest wants age first.
	for i := 1; i < len(oldest); i++ {
		for j := i; j > 0 && oldest[j].FirstSeenAt.Before(oldest[j-1].FirstSeenAt); j-- {
			oldest[j], oldest[j-1] = oldest[j-1], oldest[j]
		}
	}
	if len(oldest) > 10 {
		oldest = oldest[:10]
	}
	d.Oldest = oldest
	return d, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
