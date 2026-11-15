-- Severity order for comparisons. A higher number is more severe.
create function severity_rank(s text) returns int
language sql immutable as $$
  select case s
    when 'critical' then 4
    when 'high' then 3
    when 'medium' then 2
    when 'low' then 1
    else 0
  end
$$;

create table repos (
  id                bigint primary key,      -- GitHub repo.id
  org               text not null,
  name              text not null,
  installation_id   bigint,
  default_branch    text,
  has_wiki          boolean not null default false,
  private           boolean not null default true,
  archived          boolean not null default false,
  removed_at        timestamptz,             -- deleted, or no longer visible to the app
  last_fetched_at   timestamptz,
  last_scanned_tips jsonb,
  last_scanned_at   timestamptz,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);
create index repos_org_name on repos (lower(org), lower(name));

create table secrets (
  fingerprint     bytea primary key,         -- HMAC-SHA256, dedupes across repos and orgs
  rule_id         text not null,
  preview         text not null,
  severity        text not null,
  state           text not null default 'open'
                  check (state in ('open', 'revoked', 'false_positive', 'ignored')),
  first_seen_at   timestamptz not null default now(),
  resolved_at     timestamptz,
  resolved_by     text,
  resolved_note   text
);
create index secrets_state on secrets (state, severity);

create table locations (
  fingerprint     bytea not null references secrets,
  repo_id         bigint not null references repos,
  blob_sha        text not null,
  path_hash       bytea not null,            -- SHA-256 of the raw path bytes
  path            text not null,             -- display form, see internal/safetext
  line            int,
  severity        text not null,             -- severity at this path
  commit_sha      text,                      -- introducing commit, found lazily
  author_email    text,
  committed_at    timestamptz,
  first_seen_at   timestamptz not null default now(),
  -- The key uses the path hash: a raw path can be longer than the btree
  -- limit, and two raw paths can have the same display form.
  primary key (fingerprint, repo_id, blob_sha, path_hash)
);
create index locations_repo on locations (repo_id);

-- Blobs that the scanner has read, by cache version. A new version
-- rescans all blobs.
create table scanned_blobs (
  sha             text primary key,
  rules_version   bigint not null,
  capped          boolean not null default false  -- a rule reached the match limit
);

-- Content findings for each scanned blob, before the path rules. The same
-- blob in another repository reuses these rows. No plaintext is stored.
create table blob_findings (
  blob_sha        text not null,
  rules_version   bigint not null,
  fingerprint     bytea not null,
  rule_id         text not null,
  severity        text not null,
  preview         text not null,
  line            int not null,
  decoded         text not null default '',
  path_allow      int[] not null default '{}',
  primary key (blob_sha, fingerprint, rule_id)
);

create table audit_log (
  id              bigserial primary key,
  at              timestamptz not null default now(),
  actor           text not null,
  db_user         text not null default session_user,
  action          text not null,
  fingerprint     bytea,
  detail          jsonb
);

create table jobs (
  id              bigserial primary key,
  kind            text not null,
  dedupe_key      text,
  payload         jsonb not null default '{}',
  state           text not null default 'queued'
                  check (state in ('queued', 'running', 'done', 'failed')),
  attempts        int not null default 0,
  run_after       timestamptz not null default now(),
  locked_at       timestamptz,
  last_error      text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);
create unique index jobs_dedupe on jobs (kind, dedupe_key) where state = 'queued';
create index jobs_ready on jobs (run_after, id) where state = 'queued';
create index jobs_kind_created on jobs (kind, created_at);
