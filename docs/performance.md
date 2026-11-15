# Performance

## Benchmarks

These numbers come from one laptop with 16 CPU threads.

| Target | Blobs listed | Blobs scanned | Size | Findings | Time |
|---|---|---|---|---|---|
| gitleaks repository, full history of 4,026 commits | 10,306 | 7,785 | 46 MB | 6,287 | 3.2 s |
| This repository, `scan path .` | 92 | 89 | 0.4 MB | 0 | 33 ms |

The gitleaks repository is a worst case. Its test data holds thousands of fake secrets, and most of its blobs match a keyword.

## Regex windows give the same findings

Before the windows went in, a comparison checked that they give the same findings:

1. The comparison used 196 public mirrors: the gitleaks repository and 195 other repositories with less than 50 MB of history.
2. It scanned each mirror with `scan history` two times: with the engine before the windows, and with the engine after them. Both runs used the same HMAC key.
3. It compared the sorted lists of fingerprint, rule, path, line, commit and decoding for each repository.

The lists were the same for all 196 repositories, with 6,412 findings in total. The first comparison found 1 difference, in a rule whose regex can match without its keyword. The engine now proves for each rule that every match contains a keyword, and it runs the other rules on the full blob.

`TestWindowedScanMatchesFullScan` repeats this check on generated text for every built-in rule.

## What makes a scan fast

- **Each blob one time.** A blob that occurs in 1,000 commits gets one read. The cache shares results across repositories, forks and orgs.
- **Incremental scans.** A push scan reads only the blobs that the new commits add.
- **Keyword prefilter.** One Aho-Corasick pass over each blob selects the rules to run.
- **Regex windows.** A regex runs only near its keyword hits. On a 3.7 MB JSON file with 18 keyword hits, the scan time went from 7.1 s to 0.3 s. On the gitleaks benchmark, it went from 5.6 s to 3.2 s. The findings stayed the same.
- **One history walk.** One `git log` pass finds all paths and the first commit of every blob with a finding. One `git log --find-object` for each blob took 123 s on the gitleaks benchmark.

## Measure your largest repository

```bash
git clone --mirror https://github.com/my-org/large-repo.git
terces scan history --git-dir large-repo.git --format json --summary | jq '.stats'
```

| Field | Meaning |
|---|---|
| `blobs_listed` | Blobs in the history. |
| `blobs_scanned` | Blobs that the engine read. |
| `skipped_path`, `skipped_binary` | Blobs that the scan did not read. |
| `capped` | Blobs at the match limit. |
| `prefilter_hits` | Blobs where a keyword occurred. A high rate means generic rules run often. |
| `bytes_scanned` | Text that the engine read. |
| `duration_ns` | Wall time. |

## Tune

| Problem | Change |
|---|---|
| The scan uses too many CPUs. | Lower `--workers`. |
| A repository with large generated files is slow. | Add the paths to `skip_paths` in `rules/allowlist.yaml`. |
| The first sync of many repositories takes long. | Raise `sync --concurrency`. The default is 4. |
| A large repository fails to fetch in time. | Raise `--fetch-timeout`, such as `--fetch-timeout 3h`. |
| A rule selects too many blobs. | Use a more specific keyword. See [Rules: Keywords](rules.md#keywords). |
