package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"terces/internal/rules"
	"terces/internal/safetext"
	"terces/internal/scanner"
)

// The finding states.
const (
	StateOpen          = "open"
	StateRevoked       = "revoked"
	StateFalsePositive = "false_positive"
	StateIgnored       = "ignored"
)

// ValidState reports whether s is a finding state.
func ValidState(s string) bool {
	switch s {
	case StateOpen, StateRevoked, StateFalsePositive, StateIgnored:
		return true
	}
	return false
}

// Lookup implements scanner.Cache.
func (s *Store) Lookup(ctx context.Context, version int64, shas []string) (map[string]scanner.BlobResult, error) {
	out := map[string]scanner.BlobResult{}
	rows, err := s.pool.Query(ctx, `select sha, capped from scanned_blobs where sha = any($1) and rules_version = $2`, shas, version)
	if err != nil {
		return nil, err
	}
	var scanned []string
	var sha string
	var capped bool
	if _, err := pgx.ForEachRow(rows, []any{&sha, &capped}, func() error {
		scanned = append(scanned, sha)
		out[sha] = scanner.BlobResult{Findings: []scanner.BlobFinding{}, Capped: capped}
		return nil
	}); err != nil {
		return nil, err
	}
	if len(scanned) == 0 {
		return out, nil
	}
	rows, err = s.pool.Query(ctx, `select blob_sha, fingerprint, rule_id, severity, preview, line, decoded, path_allow
		from blob_findings where blob_sha = any($1) and rules_version = $2`, scanned, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sha, sev string
		var bf scanner.BlobFinding
		var pathAllow []int32
		if err := rows.Scan(&sha, &bf.Fingerprint, &bf.RuleID, &sev, &bf.Preview, &bf.Line, &bf.Decoded, &pathAllow); err != nil {
			return nil, err
		}
		bf.Severity, _ = rules.ParseSeverity(sev)
		for _, k := range pathAllow {
			bf.PathAllow = append(bf.PathAllow, int(k))
		}
		r := out[sha]
		r.Findings = append(r.Findings, bf)
		out[sha] = r
	}
	return out, rows.Err()
}

// Save implements scanner.Cache.
func (s *Store) Save(ctx context.Context, version int64, results map[string]scanner.BlobResult) error {
	// Sorted keys make concurrent transactions lock rows in the same
	// order, which prevents deadlocks.
	shas := make([]string, 0, len(results))
	for sha := range results {
		shas = append(shas, sha)
	}
	sort.Strings(shas)
	var (
		fBlob, fRule, fSev, fPrev, fDec, fAllow []string
		fFP                                     [][]byte
		fLine                                   []int32
		capped                                  = make([]bool, len(shas))
	)
	for i, sha := range shas {
		capped[i] = results[sha].Capped
		for _, bf := range results[sha].Findings {
			fBlob = append(fBlob, sha)
			fFP = append(fFP, bf.Fingerprint)
			fRule = append(fRule, bf.RuleID)
			fSev = append(fSev, bf.Severity.String())
			fPrev = append(fPrev, safetext.Display(bf.Preview))
			fLine = append(fLine, int32(bf.Line))
			fDec = append(fDec, bf.Decoded)
			parts := make([]string, len(bf.PathAllow))
			for i, k := range bf.PathAllow {
				parts[i] = strconv.Itoa(k)
			}
			fAllow = append(fAllow, strings.Join(parts, ","))
		}
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `delete from blob_findings where blob_sha = any($1) and rules_version <> $2`, shas, version); err != nil {
			return err
		}
		if len(fBlob) > 0 {
			if _, err := tx.Exec(ctx, `
				insert into blob_findings (blob_sha, rules_version, fingerprint, rule_id, severity, preview, line, decoded, path_allow)
				select b, $1, f, r, sv, p, l, d, coalesce(string_to_array(nullif(pa, ''), ',')::int[], '{}')
				from unnest($2::text[], $3::bytea[], $4::text[], $5::text[], $6::text[], $7::int[], $8::text[], $9::text[])
					as t(b, f, r, sv, p, l, d, pa)
				on conflict (blob_sha, fingerprint, rule_id) do update set
					rules_version = excluded.rules_version, severity = excluded.severity,
					preview = excluded.preview, line = excluded.line, decoded = excluded.decoded,
					path_allow = excluded.path_allow`,
				version, fBlob, fFP, fRule, fSev, fPrev, fLine, fDec, fAllow); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `insert into scanned_blobs (sha, rules_version, capped)
			select s, $2, c from unnest($1::text[], $3::boolean[]) as t(s, c)
			on conflict (sha) do update set rules_version = excluded.rules_version, capped = excluded.capped`, shas, version, capped)
		return err
	})
}

// RecordResult lists what RecordFindings added.
type RecordResult struct {
	// NewSecrets are findings whose fingerprint the store did not have.
	NewSecrets []scanner.Finding
	// NewLocations counts locations that the store did not have.
	NewLocations int
}

// RecordFindings stores the findings of a repository scan.
func (s *Store) RecordFindings(ctx context.Context, repoID int64, findings []scanner.Finding) (*RecordResult, error) {
	res := &RecordResult{}
	if len(findings) == 0 {
		return res, nil
	}
	// Sort a copy, so that concurrent transactions lock rows in the same
	// order.
	findings = append([]scanner.Finding(nil), findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if c := bytes.Compare(a.Fingerprint, b.Fingerprint); c != 0 {
			return c < 0
		}
		if a.BlobSHA != b.BlobSHA {
			return a.BlobSHA < b.BlobSHA
		}
		return a.Path < b.Path
	})
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		batch := &pgx.Batch{}
		for i := range findings {
			f := &findings[i]
			batch.Queue(`insert into secrets (fingerprint, rule_id, preview, severity) values ($1, $2, $3, $4)
				on conflict (fingerprint) do update set severity = excluded.severity
				where severity_rank(excluded.severity) > severity_rank(secrets.severity)
				returning (xmax = 0)`, f.Fingerprint, f.RuleID, safetext.Display(f.Preview), f.Severity.String())
			var committed *time.Time
			if t, err := time.Parse(time.RFC3339, f.CommittedAt); err == nil {
				committed = &t
			}
			// Repository content is untrusted. Store paths and emails in
			// display form, so that invalid UTF-8 or a long path cannot
			// fail the transaction and block all findings of the repository.
			pathHash := sha256.Sum256([]byte(f.Path))
			batch.Queue(`insert into locations (fingerprint, repo_id, blob_sha, path_hash, path, line, severity, commit_sha, author_email, committed_at)
				values ($1, $2, $3, $4, $5, $6, $7, nullif($8, ''), nullif($9, ''), $10)
				on conflict (fingerprint, repo_id, blob_sha, path_hash) do update set
					commit_sha = coalesce(locations.commit_sha, excluded.commit_sha),
					author_email = coalesce(locations.author_email, excluded.author_email),
					committed_at = coalesce(locations.committed_at, excluded.committed_at)
				returning (xmax = 0)`,
				f.Fingerprint, repoID, f.BlobSHA, pathHash[:], safetext.Display(f.Path), f.Line, f.Severity.String(),
				f.CommitSHA, safetext.Display(f.AuthorEmail), committed)
		}
		br := tx.SendBatch(ctx, batch)
		newFP := map[string]bool{}
		for i := range findings {
			var inserted bool
			err := br.QueryRow().Scan(&inserted)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
			case err != nil:
				br.Close()
				return err
			case inserted:
				key := string(findings[i].Fingerprint)
				if !newFP[key] {
					newFP[key] = true
					res.NewSecrets = append(res.NewSecrets, findings[i])
				}
			}
			if err := br.QueryRow().Scan(&inserted); err != nil {
				br.Close()
				return err
			}
			if inserted {
				res.NewLocations++
			}
		}
		return br.Close()
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// SecretStates returns the state of each known fingerprint. The key is
// the raw fingerprint as a string.
func (s *Store) SecretStates(ctx context.Context, fps [][]byte) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `select fingerprint, state from secrets where fingerprint = any($1)`, fps)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var fp []byte
		var state string
		if err := rows.Scan(&fp, &state); err != nil {
			return nil, err
		}
		out[string(fp)] = state
	}
	return out, rows.Err()
}

// Secret is one row of the secrets table plus location totals.
type Secret struct {
	Fingerprint  []byte     `json:"-"`
	FPHex        string     `json:"fingerprint"`
	RuleID       string     `json:"rule"`
	Preview      string     `json:"preview"`
	Severity     string     `json:"severity"`
	State        string     `json:"state"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy   string     `json:"resolved_by,omitempty"`
	ResolvedNote string     `json:"resolved_note,omitempty"`
	Repos        []string   `json:"repos"`
	Locations    int        `json:"locations"`
	IntroducedAt *time.Time `json:"introduced_at,omitempty"`
}

// ListFilter selects secrets. Empty fields match all values.
type ListFilter struct {
	Org         string
	Repo        string // org/name
	State       string
	MinSeverity rules.Severity
	RuleID      string
	Limit       int
}

// ListSecrets returns the secrets that match the filter, the most severe
// and oldest first.
func (s *Store) ListSecrets(ctx context.Context, f ListFilter) ([]Secret, error) {
	if f.Limit <= 0 {
		f.Limit = 1000
	}
	rows, err := s.pool.Query(ctx, `
		select s.fingerprint, s.rule_id, s.preview, s.severity, s.state, s.first_seen_at, s.resolved_at,
			coalesce(s.resolved_by, ''), coalesce(s.resolved_note, ''),
			array_agg(distinct r.org || '/' || r.name), count(*), min(l.committed_at)
		from secrets s
		join locations l on l.fingerprint = s.fingerprint
		join repos r on r.id = l.repo_id
		where ($1 = '' or s.state = $1)
			and severity_rank(s.severity) >= $2
			and ($3 = '' or s.rule_id = $3)
			and ($4 = '' or lower(r.org) = lower($4))
			and ($5 = '' or lower(r.org || '/' || r.name) = lower($5))
		group by s.fingerprint
		order by severity_rank(s.severity) desc, s.first_seen_at, s.fingerprint
		limit $6`,
		f.State, int(f.MinSeverity), f.RuleID, f.Org, f.Repo, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		var x Secret
		if err := rows.Scan(&x.Fingerprint, &x.RuleID, &x.Preview, &x.Severity, &x.State, &x.FirstSeenAt,
			&x.ResolvedAt, &x.ResolvedBy, &x.ResolvedNote, &x.Repos, &x.Locations, &x.IntroducedAt); err != nil {
			return nil, err
		}
		x.FPHex = hex.EncodeToString(x.Fingerprint)
		out = append(out, x)
	}
	return out, rows.Err()
}

// ResolveFingerprint finds the one fingerprint that starts with a hex
// prefix.
func (s *Store) ResolveFingerprint(ctx context.Context, prefix string) ([]byte, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) < 6 {
		return nil, fmt.Errorf("use 6 or more hex characters of the fingerprint")
	}
	if _, err := hex.DecodeString(prefix[:len(prefix)/2*2]); err != nil {
		return nil, fmt.Errorf("the fingerprint %q is not hex", prefix)
	}
	rows, err := s.pool.Query(ctx, `select fingerprint from secrets where encode(fingerprint, 'hex') like $1 || '%' limit 2`, prefix)
	if err != nil {
		return nil, err
	}
	fps, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	if err != nil {
		return nil, err
	}
	switch len(fps) {
	case 0:
		return nil, fmt.Errorf("no finding has a fingerprint that starts with %s", prefix)
	case 1:
		return fps[0], nil
	default:
		return nil, fmt.Errorf("more than one finding has a fingerprint that starts with %s: use a longer prefix", prefix)
	}
}

// Location is one place where a secret occurs.
type Location struct {
	Org         string     `json:"org"`
	Repo        string     `json:"repo"`
	Path        string     `json:"path"`
	Line        int        `json:"line"`
	Severity    string     `json:"severity"`
	BlobSHA     string     `json:"blob"`
	CommitSHA   string     `json:"commit,omitempty"`
	AuthorEmail string     `json:"author_email,omitempty"`
	CommittedAt *time.Time `json:"committed_at,omitempty"`
	FirstSeenAt time.Time  `json:"first_seen_at"`
}

// GetSecret returns one secret and all its locations.
func (s *Store) GetSecret(ctx context.Context, fp []byte) (*Secret, []Location, error) {
	var x Secret
	err := s.pool.QueryRow(ctx, `select fingerprint, rule_id, preview, severity, state, first_seen_at, resolved_at,
			coalesce(resolved_by, ''), coalesce(resolved_note, '') from secrets where fingerprint = $1`, fp).
		Scan(&x.Fingerprint, &x.RuleID, &x.Preview, &x.Severity, &x.State, &x.FirstSeenAt, &x.ResolvedAt, &x.ResolvedBy, &x.ResolvedNote)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	x.FPHex = hex.EncodeToString(x.Fingerprint)
	rows, err := s.pool.Query(ctx, `select r.org, r.name, l.path, coalesce(l.line, 0), l.severity, l.blob_sha,
			coalesce(l.commit_sha, ''), coalesce(l.author_email, ''), l.committed_at, l.first_seen_at
		from locations l join repos r on r.id = l.repo_id
		where l.fingerprint = $1
		order by l.committed_at nulls last, r.org, r.name, l.path`, fp)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var locs []Location
	repos := map[string]bool{}
	for rows.Next() {
		var l Location
		if err := rows.Scan(&l.Org, &l.Repo, &l.Path, &l.Line, &l.Severity, &l.BlobSHA, &l.CommitSHA, &l.AuthorEmail, &l.CommittedAt, &l.FirstSeenAt); err != nil {
			return nil, nil, err
		}
		locs = append(locs, l)
		if name := l.Org + "/" + l.Repo; !repos[name] {
			repos[name] = true
			x.Repos = append(x.Repos, name)
		}
		if l.CommittedAt != nil && (x.IntroducedAt == nil || l.CommittedAt.Before(*x.IntroducedAt)) {
			t := *l.CommittedAt
			x.IntroducedAt = &t
		}
	}
	x.Locations = len(locs)
	return &x, locs, rows.Err()
}

// Resolve sets the state of a secret and writes an audit log entry in the
// same transaction.
func (s *Store) Resolve(ctx context.Context, fp []byte, state, actor, note string) error {
	if !ValidState(state) {
		return fmt.Errorf("unknown state %q: use open, revoked, false_positive or ignored", state)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var old string
		err := tx.QueryRow(ctx, `select state from secrets where fingerprint = $1 for update`, fp).Scan(&old)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if state == StateOpen {
			_, err = tx.Exec(ctx, `update secrets set state = 'open', resolved_at = null, resolved_by = null,
				resolved_note = nullif($2, '') where fingerprint = $1`, fp, note)
		} else {
			_, err = tx.Exec(ctx, `update secrets set state = $2, resolved_at = now(), resolved_by = $3,
				resolved_note = nullif($4, '') where fingerprint = $1`, fp, state, actor, note)
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, actor, "resolve", fp, map[string]any{"from": old, "to": state, "note": note})
	})
}

// Audit writes an audit log entry.
func (s *Store) Audit(ctx context.Context, actor, action string, fp []byte, detail map[string]any) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return audit(ctx, tx, actor, action, fp, detail)
	})
}

func audit(ctx context.Context, tx pgx.Tx, actor, action string, fp []byte, detail map[string]any) error {
	data, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `insert into audit_log (actor, action, fingerprint, detail) values ($1, $2, $3, $4)`,
		actor, action, fp, data)
	return err
}

// ReportRow is one group of open findings.
type ReportRow struct {
	Org        string    `json:"org"`
	Repo       string    `json:"repo"`
	RuleID     string    `json:"rule"`
	Severity   string    `json:"severity"`
	Open       int       `json:"open"`
	OldestSeen time.Time `json:"oldest_first_seen_at"`
	MaxAgeDays int       `json:"max_age_days"`
}

// Report groups the open findings by org, repository, rule and severity.
func (s *Store) Report(ctx context.Context, org string) ([]ReportRow, error) {
	rows, err := s.pool.Query(ctx, `
		select r.org, r.name, s.rule_id, s.severity, count(distinct s.fingerprint), min(s.first_seen_at)
		from secrets s
		join locations l on l.fingerprint = s.fingerprint
		join repos r on r.id = l.repo_id
		where s.state = 'open' and ($1 = '' or lower(r.org) = lower($1))
		group by r.org, r.name, s.rule_id, s.severity
		order by severity_rank(s.severity) desc, min(s.first_seen_at), r.org, r.name, s.rule_id`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportRow
	now := time.Now()
	for rows.Next() {
		var x ReportRow
		if err := rows.Scan(&x.Org, &x.Repo, &x.RuleID, &x.Severity, &x.Open, &x.OldestSeen); err != nil {
			return nil, err
		}
		x.MaxAgeDays = int(now.Sub(x.OldestSeen).Hours() / 24)
		out = append(out, x)
	}
	return out, rows.Err()
}
