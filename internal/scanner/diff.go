package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"terces/internal/mirror"
	"terces/internal/repoconfig"
)

// A diff scan reports only new secrets. A finding is new when its
// fingerprint does not occur in the old side of the change. An edit to a
// file that already holds a known secret therefore does not fail the
// check again. A secret that moves to another file is also not new.

// rawEntry is one line of "git diff --raw" or "git log --raw" output.
type rawEntry struct {
	oldMode, newMode string
	oldSHA, newSHA   string
	status           string
	path             string
}

// parseRaw parses NUL-separated raw diff output.
func parseRaw(out []byte) []rawEntry {
	var entries []rawEntry
	tokens := strings.Split(string(out), "\x00")
	for i := 0; i < len(tokens); i++ {
		t := strings.TrimLeft(tokens[i], "\n")
		if !strings.HasPrefix(t, ":") {
			continue
		}
		f := strings.Fields(t[1:])
		if len(f) < 5 || i+1 >= len(tokens) {
			continue
		}
		i++
		entries = append(entries, rawEntry{
			oldMode: f[0], newMode: f[1],
			oldSHA: f[2], newSHA: f[3],
			status: f[4], path: tokens[i],
		})
	}
	return entries
}

func isFileMode(mode string) bool {
	// 100644, 100755 and 120000 are files and symlinks. 160000 is a
	// submodule commit and 000000 is "no file".
	return strings.HasPrefix(mode, "100") || mode == "120000"
}

// ScanStaged scans the changes in the index of the repository in g.
func (s *Scanner) ScanStaged(ctx context.Context, g *mirror.Git) ([]Finding, *Stats, error) {
	start := time.Now()
	out, err := g.Run(ctx, "diff", "--cached", "--raw", "-z", "--no-renames", "--no-abbrev", "--ignore-submodules")
	if err != nil {
		return nil, nil, err
	}
	var newBlobs, oldBlobs []mirror.Blob
	for _, e := range parseRaw(out) {
		if e.newSHA != mirror.ZeroSHA && isFileMode(e.newMode) {
			newBlobs = append(newBlobs, mirror.Blob{SHA: e.newSHA, Path: e.path})
		}
		if e.oldSHA != mirror.ZeroSHA && isFileMode(e.oldMode) {
			oldBlobs = append(oldBlobs, mirror.Blob{SHA: e.oldSHA, Path: e.path})
		}
	}
	cfg, err := loadConfig(ctx, g, ":")
	if err != nil {
		return nil, nil, err
	}
	findings, st, err := s.diffScan(ctx, g, newBlobs, oldBlobs, nil, cfg)
	if err != nil {
		return nil, nil, err
	}
	st.Duration = time.Since(start)
	return findings, st, nil
}

// RangeOptions controls ScanRange.
type RangeOptions struct {
	Cache Cache
	// Config overrides the .terces.yaml file at base.
	Config *repoconfig.Config
}

// ScanRange scans the blobs that the commits in base..head introduce.
// This includes blobs of intermediate commits that a later commit in the
// range removes. It reads .terces.yaml at base, not at head.
// Otherwise a change could add an ignore entry for its own secret.
func (s *Scanner) ScanRange(ctx context.Context, g *mirror.Git, base, head string, opts RangeOptions) ([]Finding, *Stats, error) {
	start := time.Now()
	for _, rev := range []string{base, head} {
		if _, err := g.Run(ctx, "rev-parse", "--verify", "--quiet", rev+"^{commit}"); err != nil {
			return nil, nil, fmt.Errorf("unknown commit %q", rev)
		}
	}
	cfg := opts.Config
	if cfg == nil {
		var err error
		if cfg, err = loadConfig(ctx, g, base); err != nil {
			return nil, nil, err
		}
	}
	reader, err := g.NewBatchReader(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer reader.Close()

	st := &Stats{}
	findings, err := s.scanReachable(ctx, g, reader, []string{head}, []string{base}, opts.Cache, cfg, "", st)
	if err != nil {
		return nil, nil, err
	}
	if len(findings) == 0 {
		st.Duration = time.Since(start)
		return nil, st, nil
	}

	// The old side: blobs that a commit in the range changes or deletes,
	// and that no commit in the range adds.
	out, err := g.Run(ctx, "log", "--format=", "--raw", "-z", "--no-renames", "--no-abbrev", "--ignore-submodules", head, "^"+base, "--")
	if err != nil {
		return nil, nil, err
	}
	entries := parseRaw(out)
	added := map[string]bool{}
	for _, e := range entries {
		added[e.newSHA] = true
	}
	var oldBlobs []mirror.Blob
	seenOld := map[string]bool{}
	for _, e := range entries {
		if e.oldSHA == mirror.ZeroSHA || !isFileMode(e.oldMode) || added[e.oldSHA] || seenOld[e.oldSHA] {
			continue
		}
		seenOld[e.oldSHA] = true
		oldBlobs = append(oldBlobs, mirror.Blob{SHA: e.oldSHA, Path: e.path})
	}
	existing, err := s.fingerprintsOf(ctx, g, reader, oldBlobs, opts.Cache)
	if err != nil {
		return nil, nil, err
	}
	kept := findings[:0]
	for _, f := range findings {
		if !existing[string(f.Fingerprint)] {
			kept = append(kept, f)
		}
	}
	st.Duration = time.Since(start)
	return kept, st, nil
}

// fingerprintsOf returns the fingerprints of all content findings in the
// blobs, before the path rules.
func (s *Scanner) fingerprintsOf(ctx context.Context, g *mirror.Git, reader *mirror.BatchReader, blobs []mirror.Blob, cache Cache) (map[string]bool, error) {
	out := map[string]bool{}
	if len(blobs) == 0 {
		return out, nil
	}
	if err := fillSizes(ctx, g, blobs); err != nil {
		return nil, err
	}
	res, _, err := s.scanBlobs(ctx, reader, blobs, cache, &Stats{})
	if err != nil {
		return nil, err
	}
	for _, bfs := range res {
		for _, bf := range bfs {
			out[string(bf.Fingerprint)] = true
		}
	}
	return out, nil
}

func (s *Scanner) diffScan(ctx context.Context, g *mirror.Git, newBlobs, oldBlobs []mirror.Blob, cache Cache, cfg *repoconfig.Config) ([]Finding, *Stats, error) {
	st := &Stats{}
	if len(newBlobs) == 0 {
		return nil, st, nil
	}
	reader, err := g.NewBatchReader(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer reader.Close()

	existing, err := s.fingerprintsOf(ctx, g, reader, oldBlobs, cache)
	if err != nil {
		return nil, nil, err
	}
	// Fill in sizes, so that large blobs are skipped before they are read.
	if err := fillSizes(ctx, g, newBlobs); err != nil {
		return nil, nil, err
	}
	newRes, _, err := s.scanBlobs(ctx, reader, newBlobs, cache, st)
	if err != nil {
		return nil, nil, err
	}
	var findings []Finding
	for _, b := range newBlobs {
		// The same blob can be staged at a skipped path and at a normal
		// path. Report only the normal path.
		if s.Engine.SkipPath(b.Path) {
			continue
		}
		for _, f := range s.Localize(newRes[b.SHA], b.SHA, b.Path, cfg) {
			if !existing[string(f.Fingerprint)] {
				findings = append(findings, f)
			}
		}
	}
	return findings, st, nil
}

// fillSizes sets the Size field of each blob.
func fillSizes(ctx context.Context, g *mirror.Git, blobs []mirror.Blob) error {
	if len(blobs) == 0 {
		return nil
	}
	var in strings.Builder
	for _, b := range blobs {
		in.WriteString(b.SHA + "\n")
	}
	out, err := g.RunInput(ctx, []byte(in.String()), "cat-file", "--batch-check=%(objectname) %(objectsize)")
	if err != nil {
		return err
	}
	sizes := map[string]int64{}
	for _, line := range strings.Split(string(out), "\n") {
		var sha string
		var size int64
		if n, _ := fmt.Sscanf(line, "%s %d", &sha, &size); n == 2 {
			sizes[sha] = size
		}
	}
	for i := range blobs {
		blobs[i].Size = sizes[blobs[i].SHA]
	}
	return nil
}

// loadConfig reads .terces.yaml at rev. Use ":" for the index.
func loadConfig(ctx context.Context, g *mirror.Git, rev string) (*repoconfig.Config, error) {
	data, err := g.ReadFile(ctx, rev, repoconfig.FileName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", repoconfig.FileName, err)
	}
	if data == nil {
		return nil, nil
	}
	return repoconfig.Parse(data)
}

// LoadConfig reads .terces.yaml at rev of a repository.
func LoadConfig(ctx context.Context, g *mirror.Git, rev string) (*repoconfig.Config, error) {
	return loadConfig(ctx, g, rev)
}
