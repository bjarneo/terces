package scanner

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"terces/internal/mirror"
	"terces/internal/repoconfig"
)

// ScanDir scans the regular files below root. It does not use git and it
// skips .git directories. Paths in the findings are relative to root.
func (s *Scanner) ScanDir(ctx context.Context, root string) ([]Finding, *Stats, error) {
	start := time.Now()
	st := &Stats{}
	cfg := readDirConfig(root, st)

	type item struct{ abs, rel string }
	items := make(chan item, s.workers()*2)
	var mu sync.Mutex
	var findings []Finding
	var firstErr error
	var wg sync.WaitGroup
	for i := 0; i < s.workers(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range items {
				data, err := os.ReadFile(it.abs)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					continue
				}
				res, ok := s.ScanContent(data, st)
				if !ok {
					st.addGap(Gap{Path: it.rel, Reason: GapTooLarge, Size: int64(len(data))})
					continue
				}
				if res.Capped {
					st.addGap(Gap{Path: it.rel, Reason: GapMatchLimit})
				}
				if len(res.Findings) == 0 {
					continue
				}
				fs := s.Localize(res.Findings, "", it.rel, cfg)
				mu.Lock()
				findings = append(findings, fs...)
				mu.Unlock()
			}
		}()
	}

	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			// A probe path below the directory tells if a directory
			// pattern such as "node_modules/" excludes it.
			if rel != "." && s.Engine.SkipPath(rel+"/\x00") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		st.mu.Lock()
		st.BlobsListed++
		st.mu.Unlock()
		if s.Engine.SkipPath(rel) {
			st.incr(&st.SkippedPath)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > s.MaxBlobSize {
			// A large binary file, such as a build output, is not a gap.
			if isBinaryFile(p) {
				st.incr(&st.SkippedBinary)
			} else {
				st.addGap(Gap{Path: rel, Reason: GapTooLarge, Size: info.Size()})
			}
			return nil
		}
		items <- item{abs: p, rel: rel}
		return nil
	})
	close(items)
	wg.Wait()
	if walkErr != nil {
		return nil, nil, walkErr
	}
	if firstErr != nil {
		return nil, nil, firstErr
	}
	st.Duration = time.Since(start)
	return findings, st, nil
}

// readDirConfig reads .terces.yaml at root. It reads only a regular file,
// never a link: a link can point to /dev/zero or to a key file. A file
// that it cannot use adds a warning, and the scan ignores nothing.
func readDirConfig(root string, st *Stats) *repoconfig.Config {
	p := filepath.Join(root, repoconfig.FileName)
	info, err := os.Lstat(p)
	if err != nil {
		return nil
	}
	if !info.Mode().IsRegular() {
		st.warn(repoconfig.FileName + " is not a regular file, so the scan ignores it")
		return nil
	}
	if info.Size() > repoconfig.MaxSize {
		st.warn(repoconfig.FileName + " is larger than 1 MB, so the scan ignores it")
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		st.warn("cannot read " + repoconfig.FileName + ", so the scan ignores it")
		return nil
	}
	cfg, err := repoconfig.Parse(data)
	if err != nil {
		st.warn(err.Error() + ". The scan ignores the file")
		return nil
	}
	return cfg
}

// isBinaryFile reports whether the first bytes of a file hold a NUL byte.
func isBinaryFile(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, binaryProbe)
	n, _ := io.ReadFull(f, head)
	return mirror.IsBinary(head[:n])
}
