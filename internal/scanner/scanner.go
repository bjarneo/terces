// Package scanner applies the engine to blobs, git history, staged changes,
// commit ranges and directories.
package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"

	"terces/internal/engine"
	"terces/internal/fingerprint"
	"terces/internal/mirror"
	"terces/internal/repoconfig"
	"terces/internal/rules"
)

// DefaultMaxBlobSize is the default size limit for one blob.
const DefaultMaxBlobSize = 5 << 20

const listBatchSize = 2000

// BlobFinding is a finding in one blob, before the scanner applies the
// path rules. It holds no plaintext, so the blob cache can store it.
type BlobFinding struct {
	Fingerprint []byte
	RuleID      string
	Severity    rules.Severity
	Preview     string
	Line        int
	Decoded     string
	PathAllow   []int
}

// Finding is a secret at a path.
type Finding struct {
	Fingerprint []byte         `json:"-"`
	FPHex       string         `json:"fingerprint"`
	RuleID      string         `json:"rule"`
	Description string         `json:"description,omitempty"`
	Severity    rules.Severity `json:"severity"`
	Preview     string         `json:"preview"`
	Path        string         `json:"path"`
	Line        int            `json:"line"`
	BlobSHA     string         `json:"blob,omitempty"`
	Decoded     string         `json:"decoded,omitempty"`
	CommitSHA   string         `json:"commit,omitempty"`
	AuthorName  string         `json:"author_name,omitempty"`
	AuthorEmail string         `json:"author_email,omitempty"`
	CommittedAt string         `json:"committed_at,omitempty"`
}

// BlobResult is the content result of one scanned blob.
type BlobResult struct {
	Findings []BlobFinding
	// Capped is true when a rule reached the match limit in the blob. The
	// blob can then hold more secrets than Findings.
	Capped bool
}

// Cache stores blob results by SHA and cache version.
type Cache interface {
	// Lookup returns the results of the blobs that were scanned with the
	// version. A blob that was not scanned has no key.
	Lookup(ctx context.Context, version int64, shas []string) (map[string]BlobResult, error)
	// Save stores the results of newly scanned blobs.
	Save(ctx context.Context, version int64, results map[string]BlobResult) error
}

// Gap is a blob that the scan did not read in full. A gap can hide a
// secret, so the scan reports it.
type Gap struct {
	Blob string `json:"blob"`
	Path string `json:"path"`
	// Reason is GapTooLarge or GapMatchLimit.
	Reason string `json:"reason"`
	Size   int64  `json:"size,omitempty"`
}

// Gap reasons.
const (
	// GapTooLarge is a blob above the size limit. The scanner does not
	// read it.
	GapTooLarge = "too_large"
	// GapMatchLimit is a blob where a rule reached the match limit.
	GapMatchLimit = "match_limit"
)

// maxGaps limits the gaps that Stats lists. The counts include all gaps.
const maxGaps = 100

// Stats counts the work of one scan.
type Stats struct {
	BlobsListed   int           `json:"blobs_listed"`
	BlobsScanned  int           `json:"blobs_scanned"`
	BlobsCached   int           `json:"blobs_cached"`
	SkippedPath   int           `json:"skipped_path"`
	SkippedSize   int           `json:"skipped_size"`
	SkippedBinary int           `json:"skipped_binary"`
	Capped        int           `json:"capped"`
	PrefilterHits int           `json:"prefilter_hits"`
	BytesScanned  int64         `json:"bytes_scanned"`
	Duration      time.Duration `json:"duration_ns"`
	// Gaps lists up to 100 blobs that the scan did not read in full.
	Gaps []Gap `json:"gaps,omitempty"`
	// Warnings describe problems that did not stop the scan, such as an
	// invalid .terces.yaml.
	Warnings []string `json:"warnings,omitempty"`
	mu       sync.Mutex
}

func (st *Stats) warn(msg string) {
	st.mu.Lock()
	st.Warnings = append(st.Warnings, msg)
	st.mu.Unlock()
}

// Warn adds a warning to the stats.
func (st *Stats) Warn(msg string) { st.warn(msg) }

// addGap counts a gap and lists the first maxGaps of them.
func (st *Stats) addGap(g Gap) {
	st.mu.Lock()
	defer st.mu.Unlock()
	switch g.Reason {
	case GapTooLarge:
		st.SkippedSize++
	case GapMatchLimit:
		st.Capped++
	}
	if len(st.Gaps) < maxGaps {
		st.Gaps = append(st.Gaps, g)
	}
}

// Add adds the counts of o to st.
func (st *Stats) Add(o *Stats) {
	st.Duration += o.Duration
	st.BlobsListed += o.BlobsListed
	st.BlobsScanned += o.BlobsScanned
	st.BlobsCached += o.BlobsCached
	st.SkippedPath += o.SkippedPath
	st.SkippedSize += o.SkippedSize
	st.SkippedBinary += o.SkippedBinary
	st.Capped += o.Capped
	st.PrefilterHits += o.PrefilterHits
	st.BytesScanned += o.BytesScanned
	for _, g := range o.Gaps {
		if len(st.Gaps) < maxGaps {
			st.Gaps = append(st.Gaps, g)
		}
	}
	st.Warnings = append(st.Warnings, o.Warnings...)
}

// Summary returns one line with the counts and the throughput.
func (st *Stats) Summary() string {
	rate := 0.0
	if st.Duration > 0 {
		rate = float64(st.BlobsScanned) / st.Duration.Seconds()
	}
	hitRate := 0.0
	if st.BlobsScanned > 0 {
		hitRate = 100 * float64(st.PrefilterHits) / float64(st.BlobsScanned)
	}
	blobs := "blobs"
	if st.BlobsListed == 1 {
		blobs = "blob"
	}
	line := fmt.Sprintf("%d %s listed, %d scanned, %d cached, %d skipped (path %d, size %d, binary %d), %.0f blobs/s, prefilter hit rate %.1f%%, %s",
		st.BlobsListed, blobs, st.BlobsScanned, st.BlobsCached,
		st.SkippedPath+st.SkippedSize+st.SkippedBinary, st.SkippedPath, st.SkippedSize, st.SkippedBinary,
		rate, hitRate, st.Duration.Round(time.Millisecond))
	if st.Capped > 0 {
		line += fmt.Sprintf(", %d at the match limit", st.Capped)
	}
	return line
}

// Scanner scans content. It is safe for concurrent use.
type Scanner struct {
	Engine      *engine.Engine
	Hasher      *fingerprint.Hasher
	MaxBlobSize int64
	Workers     int
}

// Version returns the blob cache version. It changes with the rules, the
// engine, the size limit and the HMAC key. The cache stores fingerprints,
// so results from another key must not be reused.
func (s *Scanner) Version() int64 {
	h := sha256.New()
	fmt.Fprintf(h, "%d:", s.Engine.CacheVersion(s.MaxBlobSize))
	h.Write(s.Hasher.KeyID())
	return int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]) & 0x7fffffffffffffff)
}

func (s *Scanner) workers() int {
	if s.Workers > 0 {
		return s.Workers
	}
	return 4
}

// ScanContent scans one blob. A binary blob gets an empty result. ok is
// false for a blob above the size limit: the scanner did not read it, so
// the result must not go to the cache.
func (s *Scanner) ScanContent(data []byte, st *Stats) (res BlobResult, ok bool) {
	if int64(len(data)) > s.MaxBlobSize {
		return BlobResult{}, false
	}
	if mirror.IsBinary(data) {
		st.incr(&st.SkippedBinary)
		return BlobResult{}, true
	}
	matches, info := s.Engine.ScanStats(data)
	st.mu.Lock()
	st.BlobsScanned++
	st.BytesScanned += int64(len(data))
	if info.Hit {
		st.PrefilterHits++
	}
	st.mu.Unlock()
	res.Capped = info.Capped
	if len(matches) == 0 {
		return res, true
	}
	out := make([]BlobFinding, 0, len(matches))
	for _, m := range matches {
		out = append(out, BlobFinding{
			Fingerprint: s.Hasher.Fingerprint(m.Secret),
			RuleID:      m.Rule.ID,
			Severity:    m.Rule.Sev,
			Preview:     fingerprint.Preview(m.Secret),
			Line:        m.Line,
			Decoded:     m.Decoded,
			PathAllow:   m.PathAllow,
		})
		clear(m.Secret)
	}
	res.Findings = out
	return res, true
}

func (st *Stats) incr(field *int) {
	st.mu.Lock()
	*field++
	st.mu.Unlock()
}

// Localize applies the path rules and the repository config to the
// findings of one blob at one path. It keeps one finding per fingerprint.
func (s *Scanner) Localize(bfs []BlobFinding, blobSHA, path string, cfg *repoconfig.Config) []Finding {
	byFP := map[string]int{}
	var out []Finding
	for _, bf := range bfs {
		sev, reason := s.Engine.ApplyPath(bf.RuleID, bf.PathAllow, bf.Severity, path)
		if reason != "" || cfg.Ignored(bf.Fingerprint) {
			continue
		}
		f := Finding{
			Fingerprint: bf.Fingerprint,
			FPHex:       fingerprint.Hex(bf.Fingerprint),
			RuleID:      bf.RuleID,
			Severity:    sev,
			Preview:     bf.Preview,
			Path:        path,
			Line:        bf.Line,
			BlobSHA:     blobSHA,
			Decoded:     bf.Decoded,
		}
		if r, ok := s.Engine.Rules().ByID[bf.RuleID]; ok {
			f.Description = r.Description
		}
		if i, ok := byFP[f.FPHex]; ok {
			prev := &out[i]
			if f.Severity > prev.Severity || f.Severity == prev.Severity && f.Line < prev.Line {
				*prev = f
			}
			continue
		}
		byFP[f.FPHex] = len(out)
		out = append(out, f)
	}
	return out
}

// scanBlobs returns the blob results for blobs, keyed by SHA. It reads
// only the blobs that the cache does not have. It does not read a blob at
// a path that the allowlist excludes, and returns those blobs as skipped.
// A blob above the size limit has no result and is a gap.
func (s *Scanner) scanBlobs(ctx context.Context, reader *mirror.BatchReader, blobs []mirror.Blob, cache Cache, st *Stats) (map[string][]BlobFinding, []mirror.Blob, error) {
	version := s.Version()
	results := map[string][]BlobFinding{}
	fresh := map[string]BlobResult{}
	pathOf := map[string]string{}
	var want []string
	var skipped, large []mirror.Blob
	for _, b := range blobs {
		st.BlobsListed++
		if s.Engine.SkipPath(b.Path) {
			st.SkippedPath++
			skipped = append(skipped, b)
			continue
		}
		if _, ok := pathOf[b.SHA]; ok {
			continue
		}
		pathOf[b.SHA] = b.Path
		if b.Size > s.MaxBlobSize {
			// The cache does not keep this blob, so each scan reports it
			// again. A binary blob is not a gap.
			large = append(large, b)
			continue
		}
		want = append(want, b.SHA)
	}
	use := func(sha string, r BlobResult) {
		results[sha] = r.Findings
		if r.Capped {
			st.addGap(Gap{Blob: sha, Path: pathOf[sha], Reason: GapMatchLimit})
		}
	}

	if cache != nil && len(want) > 0 {
		hits, err := cache.Lookup(ctx, version, want)
		if err != nil {
			return nil, nil, fmt.Errorf("blob cache lookup: %w", err)
		}
		missing := want[:0]
		for _, sha := range want {
			if r, ok := hits[sha]; ok {
				use(sha, r)
				st.BlobsCached++
				continue
			}
			missing = append(missing, sha)
		}
		want = missing
	}

	if len(want) > 0 {
		type item struct {
			sha  string
			data []byte
		}
		type result struct {
			sha  string
			res  BlobResult
			ok   bool
			size int
		}
		items := make(chan item, s.workers()*2)
		out := make(chan result, s.workers()*2)
		var wg sync.WaitGroup
		for i := 0; i < s.workers(); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for it := range items {
					res, ok := s.ScanContent(it.data, st)
					out <- result{it.sha, res, ok, len(it.data)}
				}
			}()
		}
		readErr := make(chan error, 1)
		go func() {
			defer close(items)
			for _, sha := range want {
				if ctx.Err() != nil {
					readErr <- ctx.Err()
					return
				}
				data, err := reader.Read(sha)
				if err == mirror.ErrMissing {
					continue
				}
				if err != nil {
					readErr <- err
					return
				}
				items <- item{sha, data}
			}
			readErr <- nil
		}()
		go func() {
			wg.Wait()
			close(out)
		}()
		for r := range out {
			if !r.ok {
				st.addGap(Gap{Blob: r.sha, Path: pathOf[r.sha], Reason: GapTooLarge, Size: int64(r.size)})
				continue
			}
			use(r.sha, r.res)
			fresh[r.sha] = r.res
		}
		if err := <-readErr; err != nil {
			return nil, nil, fmt.Errorf("read blobs: %w", err)
		}
	}

	for _, b := range large {
		head, err := reader.Peek(b.SHA, binaryProbe)
		if err == mirror.ErrMissing {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read blobs: %w", err)
		}
		if mirror.IsBinary(head) {
			st.incr(&st.SkippedBinary)
			continue
		}
		st.addGap(Gap{Blob: b.SHA, Path: b.Path, Reason: GapTooLarge, Size: b.Size})
	}

	if cache != nil && len(fresh) > 0 {
		if err := cache.Save(ctx, version, fresh); err != nil {
			return nil, nil, fmt.Errorf("blob cache save: %w", err)
		}
	}
	return results, skipped, nil
}

// binaryProbe is the number of bytes that IsBinary checks.
const binaryProbe = 8192

// HistoryOptions controls ScanHistory.
type HistoryOptions struct {
	// Exclude holds commits whose history the scan leaves out, such as
	// the ref tips of the last scan.
	Exclude []string
	Cache   Cache
	Config  *repoconfig.Config
	// PathPrefix goes in front of each path, for example "wiki:".
	PathPrefix string
}

// ScanHistory scans all blobs that are reachable from the refs of a
// repository.
func (s *Scanner) ScanHistory(ctx context.Context, g *mirror.Git, opts HistoryOptions) ([]Finding, *Stats, error) {
	start := time.Now()
	st := &Stats{}
	reader, err := g.NewBatchReader(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer reader.Close()
	findings, err := s.scanReachable(ctx, g, reader, []string{"--all"}, opts.Exclude, opts.Cache, opts.Config, opts.PathPrefix, st)
	if err != nil {
		return nil, nil, err
	}
	st.Duration = time.Since(start)
	return findings, st, nil
}

// scanReachable scans the blobs that revs reach, without the history of
// exclude. It returns one finding for each secret at each path.
//
// git rev-list reports each blob at one path only, and an incremental
// listing leaves out a blob that the old tips already reach. One history
// walk over the same commits finds the missing cases:
//   - all paths and the first commit of each blob with a finding,
//   - a blob that rev-list reported at a skipped path, but that a commit
//     also adds at a normal path,
//   - in an incremental scan, a blob from older history that a new commit
//     adds at a new path, such as a copy or a revert.
//
// Without the walk, a secret in both node_modules/ and src/ goes
// unreported, and so does a secret that moves from vendor/ to src/.
func (s *Scanner) scanReachable(ctx context.Context, g *mirror.Git, reader *mirror.BatchReader, revs, exclude []string, cache Cache, cfg *repoconfig.Config, prefix string, st *Stats) ([]Finding, error) {
	incremental := len(exclude) > 0
	found := map[string][]BlobFinding{}
	listed := map[string]string{}
	skipped := map[string]mirror.Blob{}
	// seen holds every listed blob, but only for an incremental scan. A
	// full scan lists every reachable blob, so it needs no such set.
	seen := map[string]bool{}
	err := g.ListBlobs(ctx, revs, exclude, listBatchSize, func(blobs []mirror.Blob) error {
		res, skip, err := s.scanBlobs(ctx, reader, blobs, cache, st)
		if err != nil {
			return err
		}
		for _, b := range blobs {
			if incremental {
				seen[b.SHA] = true
			}
			if bfs := res[b.SHA]; len(bfs) > 0 {
				found[b.SHA] = bfs
				if _, ok := listed[b.SHA]; !ok {
					listed[b.SHA] = b.Path
				}
			}
		}
		for _, b := range skip {
			if _, ok := skipped[b.SHA]; !ok {
				skipped[b.SHA] = b
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	want := func(sha string) bool {
		if _, ok := found[sha]; ok {
			return true
		}
		if _, ok := skipped[sha]; ok {
			return true
		}
		return incremental && !seen[sha]
	}
	if len(found) == 0 && len(skipped) == 0 && !incremental {
		return nil, nil
	}
	hist, err := g.BlobHistory(ctx, want, revs, exclude)
	if err != nil {
		return nil, fmt.Errorf("walk history: %w", err)
	}

	// Scan the blobs that the walk found at a normal path and that the
	// listing did not scan.
	var extra []mirror.Blob
	for sha, info := range hist {
		if _, ok := found[sha]; ok {
			continue
		}
		_, wasSkipped := skipped[sha]
		if !wasSkipped && (!incremental || seen[sha]) {
			continue
		}
		for _, p := range info.Paths {
			if !s.Engine.SkipPath(p) {
				extra = append(extra, mirror.Blob{SHA: sha, Path: p})
				break
			}
		}
	}
	if len(extra) > 0 {
		sort.Slice(extra, func(i, j int) bool { return extra[i].SHA < extra[j].SHA })
		if err := fillSizes(ctx, g, extra); err != nil {
			return nil, err
		}
		tmp := &Stats{}
		res, _, err := s.scanBlobs(ctx, reader, extra, cache, tmp)
		if err != nil {
			return nil, err
		}
		st.addReads(tmp)
		for _, b := range extra {
			if bfs := res[b.SHA]; len(bfs) > 0 {
				found[b.SHA] = bfs
			}
		}
	}

	shas := make([]string, 0, len(found))
	for sha := range found {
		shas = append(shas, sha)
	}
	sort.Strings(shas)
	var findings []Finding
	for _, sha := range shas {
		// The walk reads paths from NUL-separated output. rev-list prints a
		// path with a newline in it as two lines, so its path is only a
		// fallback.
		var paths []string
		info := hist[sha]
		if info != nil {
			paths = info.Paths
		}
		if p, ok := listed[sha]; ok && len(paths) == 0 {
			paths = []string{p}
		}
		for _, p := range paths {
			if s.Engine.SkipPath(p) {
				continue
			}
			fs := s.Localize(found[sha], sha, prefix+p, cfg)
			if info != nil && info.First != nil {
				for i := range fs {
					fs[i].CommitSHA = info.First.SHA
					fs[i].AuthorName = info.First.AuthorName
					fs[i].AuthorEmail = info.First.AuthorEmail
					fs[i].CommittedAt = info.First.Date
				}
			}
			findings = append(findings, fs...)
		}
	}
	return findings, nil
}

// addReads adds the read and scan counts of o to st, but not the listed
// and skipped counts. A rescued blob is already listed.
func (st *Stats) addReads(o *Stats) {
	st.BlobsScanned += o.BlobsScanned
	st.BlobsCached += o.BlobsCached
	st.SkippedSize += o.SkippedSize
	st.SkippedBinary += o.SkippedBinary
	st.Capped += o.Capped
	st.PrefilterHits += o.PrefilterHits
	st.BytesScanned += o.BytesScanned
	for _, g := range o.Gaps {
		if len(st.Gaps) < maxGaps {
			st.Gaps = append(st.Gaps, g)
		}
	}
	st.Warnings = append(st.Warnings, o.Warnings...)
}

// SortFindings orders findings by severity, then by path and line.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
}
