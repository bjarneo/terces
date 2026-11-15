-- Least-privilege roles for terces.
--
-- Run this file after `terces migrate`, as the owner of the tables.
-- The migrate role owns the schema. The scanner role writes findings. The
-- analyst role reads findings and resolves them. Set the passwords with
-- \password or use certificate authentication.

create role terces_scanner login;
create role terces_analyst login;

grant usage on schema public to terces_scanner, terces_analyst;
grant select on schema_migrations to terces_scanner, terces_analyst;

-- The scanner: `serve`, `sync` and `scan repo` or `scan org`.
grant select, insert, update on repos, secrets, locations, scanned_blobs to terces_scanner;
grant select, insert, update, delete on blob_findings, jobs to terces_scanner;
grant usage on sequence jobs_id_seq to terces_scanner;

-- The analyst: `findings list`, `findings show`, `findings resolve` and `report`.
-- The analyst cannot change repositories, locations or the blob cache.
grant select on repos, secrets, locations to terces_analyst;
grant update (state, resolved_at, resolved_by, resolved_note) on secrets to terces_analyst;
grant insert on audit_log to terces_analyst;
grant usage on sequence audit_log_id_seq to terces_analyst;

-- Nobody but the owner can change or delete audit log entries.
revoke update, delete, truncate on audit_log from public;
