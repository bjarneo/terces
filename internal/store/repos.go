package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Repo is one GitHub repository.
type Repo struct {
	ID             int64      `json:"id"`
	Org            string     `json:"org"`
	Name           string     `json:"name"`
	InstallationID int64      `json:"installation_id"`
	DefaultBranch  string     `json:"default_branch"`
	HasWiki        bool       `json:"has_wiki"`
	Private        bool       `json:"private"`
	Archived       bool       `json:"archived"`
	RemovedAt      *time.Time `json:"removed_at,omitempty"`
	LastFetchedAt  *time.Time `json:"last_fetched_at,omitempty"`
	LastScannedAt  *time.Time `json:"last_scanned_at,omitempty"`
	Tips           *Tips      `json:"-"`
}

// FullName returns "org/name".
func (r *Repo) FullName() string { return r.Org + "/" + r.Name }

// Tips are the ref tips of the last scan. The next scan leaves out the
// history of these commits.
type Tips struct {
	// Version is the scanner cache version of the scan. A scan with
	// another version ignores the tips and covers the full history.
	Version int64             `json:"version,omitempty"`
	Repo    map[string]string `json:"repo,omitempty"`
	Wiki    map[string]string `json:"wiki,omitempty"`
}

// Values returns the unique commit IDs of a ref map.
func Values(m map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range m {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

const repoColumns = `id, org, name, coalesce(installation_id, 0), coalesce(default_branch, ''),
	has_wiki, private, archived, removed_at, last_fetched_at, last_scanned_at, last_scanned_tips`

func scanRepo(row pgx.Row) (*Repo, error) {
	var r Repo
	var tips []byte
	err := row.Scan(&r.ID, &r.Org, &r.Name, &r.InstallationID, &r.DefaultBranch,
		&r.HasWiki, &r.Private, &r.Archived, &r.RemovedAt, &r.LastFetchedAt, &r.LastScannedAt, &tips)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(tips) > 0 {
		r.Tips = &Tips{}
		if err := json.Unmarshal(tips, r.Tips); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

// UpsertResult describes the state of a repository before an upsert.
type UpsertResult struct {
	Created     bool
	WasArchived bool
	WasRemoved  bool
}

// UpsertRepo inserts or updates the metadata of a repository. It clears
// removed_at, because the app can see the repository again.
func (s *Store) UpsertRepo(ctx context.Context, r *Repo) (UpsertResult, error) {
	var res UpsertResult
	var oldArchived, oldRemoved *bool
	err := s.pool.QueryRow(ctx, `
		with old as (select archived, removed_at is not null as removed from repos where id = $1)
		insert into repos (id, org, name, installation_id, default_branch, has_wiki, private, archived)
		values ($1, $2, $3, nullif($4, 0), nullif($5, ''), $6, $7, $8)
		on conflict (id) do update set
			org = excluded.org,
			name = excluded.name,
			installation_id = coalesce(excluded.installation_id, repos.installation_id),
			default_branch = coalesce(excluded.default_branch, repos.default_branch),
			has_wiki = excluded.has_wiki,
			private = excluded.private,
			archived = excluded.archived,
			removed_at = null,
			updated_at = now()
		returning (select archived from old), (select removed from old)`,
		r.ID, r.Org, r.Name, r.InstallationID, r.DefaultBranch, r.HasWiki, r.Private, r.Archived,
	).Scan(&oldArchived, &oldRemoved)
	if err != nil {
		return res, err
	}
	res.Created = oldArchived == nil
	res.WasArchived = oldArchived != nil && *oldArchived
	res.WasRemoved = oldRemoved != nil && *oldRemoved
	return res, nil
}

// RenameRepo updates the owner and the name of a repository.
func (s *Store) RenameRepo(ctx context.Context, id int64, org, name string) error {
	_, err := s.pool.Exec(ctx, `update repos set org = $2, name = $3, updated_at = now() where id = $1`, id, org, name)
	return err
}

// SetArchived updates the archived flag.
func (s *Store) SetArchived(ctx context.Context, id int64, archived bool) error {
	_, err := s.pool.Exec(ctx, `update repos set archived = $2, updated_at = now() where id = $1`, id, archived)
	return err
}

// MarkRemoved sets removed_at for the repositories. Their findings stay.
func (s *Store) MarkRemoved(ctx context.Context, ids ...int64) error {
	_, err := s.pool.Exec(ctx, `update repos set removed_at = now(), updated_at = now()
		where id = any($1) and removed_at is null`, ids)
	return err
}

// MarkRemovedExcept marks all repositories of an installation as removed,
// except the listed ones. It returns the number of changed rows.
func (s *Store) MarkRemovedExcept(ctx context.Context, installationID int64, keep []int64) (int64, error) {
	// pgx sends a nil slice as NULL, and "id = any(NULL)" matches no row.
	if keep == nil {
		keep = []int64{}
	}
	tag, err := s.pool.Exec(ctx, `update repos set removed_at = now(), updated_at = now()
		where installation_id = $1 and removed_at is null and not (id = any($2))`, installationID, keep)
	return tag.RowsAffected(), err
}

// GetRepo returns a repository by ID.
func (s *Store) GetRepo(ctx context.Context, id int64) (*Repo, error) {
	return scanRepo(s.pool.QueryRow(ctx, "select "+repoColumns+" from repos where id = $1", id))
}

// FindRepo returns a repository by its current owner and name. The
// comparison ignores case, as GitHub does.
func (s *Store) FindRepo(ctx context.Context, org, name string) (*Repo, error) {
	// A deleted repository and a new one can share a name. Prefer the
	// active row, then the most recent one.
	return scanRepo(s.pool.QueryRow(ctx, "select "+repoColumns+
		` from repos where lower(org) = lower($1) and lower(name) = lower($2)
		order by removed_at is not null, updated_at desc limit 1`, org, name))
}

// ListRepos returns the repositories of an org, or of all orgs when org is
// empty.
func (s *Store) ListRepos(ctx context.Context, org string, includeRemoved bool) ([]*Repo, error) {
	rows, err := s.pool.Query(ctx, "select "+repoColumns+` from repos
		where ($1 = '' or lower(org) = lower($1)) and ($2 or removed_at is null)
		order by lower(org), lower(name)`, org, includeRemoved)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Repo
	for rows.Next() {
		r, err := scanRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetFetched records a successful fetch.
func (s *Store) SetFetched(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `update repos set last_fetched_at = now() where id = $1`, id)
	return err
}

// SetScanned records the ref tips of a finished scan.
func (s *Store) SetScanned(ctx context.Context, id int64, tips *Tips) error {
	data, err := json.Marshal(tips)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `update repos set last_scanned_tips = $2, last_scanned_at = now() where id = $1`, id, data)
	return err
}
