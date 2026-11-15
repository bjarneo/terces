// Package mirror manages bare mirrors of GitHub repositories and reads
// objects from git repositories.
package mirror

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ZeroSHA is the object ID that git uses for "no object".
const ZeroSHA = "0000000000000000000000000000000000000000"

// Git runs git commands against one repository.
type Git struct {
	// Dir is the working tree or the bare repository.
	Dir string
	// Bare makes Git use --git-dir instead of -C.
	Bare bool
	// Env holds extra environment variables, such as the auth header.
	Env []string
}

func (g *Git) command(ctx context.Context, args ...string) *exec.Cmd {
	var full []string
	if g.Bare {
		full = append(full, "--git-dir="+g.Dir)
	} else if g.Dir != "" {
		full = append(full, "-C", g.Dir)
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	// On cancel, ask git to stop first, so that it can remove its lock
	// files. Kill it when it does not stop in time.
	setCancel(cmd)
	cmd.WaitDelay = 10 * time.Second
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=true",
		"LC_ALL=C",
	)
	cmd.Env = append(cmd.Env, g.Env...)
	return cmd
}

// Run runs git and returns stdout. The error includes stderr.
func (g *Git) Run(ctx context.Context, args ...string) ([]byte, error) {
	return g.RunInput(ctx, nil, args...)
}

// RunInput runs git with stdin and returns stdout.
func (g *Git) RunInput(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd := g.command(ctx, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), &Error{Args: args, Stderr: strings.TrimSpace(stderr.String()), Err: err}
	}
	return stdout.Bytes(), nil
}

// Error is a failed git command.
type Error struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	sub := ""
	for i := 0; i < len(e.Args); i++ {
		if e.Args[i] == "-c" {
			i++
			continue
		}
		sub = e.Args[i]
		break
	}
	if e.Stderr != "" {
		return fmt.Sprintf("git %s: %v: %s", sub, e.Err, e.Stderr)
	}
	return fmt.Sprintf("git %s: %v", sub, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// AuthEnv returns environment variables that send a GitHub token as an
// HTTP header to the host of baseURL. The token stays out of the remote
// URL, out of .git/config and out of the process arguments.
func AuthEnv(baseURL, token string) []string {
	if token == "" {
		return nil
	}
	cred := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return []string{
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=http." + strings.TrimSuffix(baseURL, "/") + "/.extraheader",
		"GIT_CONFIG_VALUE_0=AUTHORIZATION: basic " + cred,
		"GIT_CONFIG_KEY_1=credential.helper",
		"GIT_CONFIG_VALUE_1=",
	}
}

// MaxConfigFileSize is the largest file that ReadFile returns. Config
// files such as .terces.yaml and CODEOWNERS are much smaller.
const MaxConfigFileSize = 1 << 20

// ErrTooLarge means that a file is larger than MaxConfigFileSize.
var ErrTooLarge = errors.New("file is larger than 1 MB")

// ReadFile returns the content of path at rev, such as "HEAD" or ":" for
// the index. It returns nil and no error when the file does not exist, and
// ErrTooLarge for a file larger than MaxConfigFileSize.
func (g *Git) ReadFile(ctx context.Context, rev, path string) ([]byte, error) {
	spec := rev + ":" + path
	if rev == ":" {
		spec = ":" + path
	}
	out, err := g.Run(ctx, "cat-file", "-s", spec)
	if err != nil {
		return nil, nil
	}
	if size, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err != nil || size > MaxConfigFileSize {
		return nil, ErrTooLarge
	}
	return g.Run(ctx, "cat-file", "blob", spec)
}

// Existing returns the objects in shas that the repository has. A tip of an
// earlier scan can be gone after a fetch prunes its branch and gc runs.
func (g *Git) Existing(ctx context.Context, shas []string) ([]string, error) {
	if len(shas) == 0 {
		return nil, nil
	}
	var in strings.Builder
	for _, sha := range shas {
		in.WriteString(sha + "\n")
	}
	out, err := g.RunInput(ctx, []byte(in.String()), "cat-file", "--batch-check=%(objectname) %(objecttype)")
	if err != nil {
		return nil, err
	}
	var keep []string
	for _, line := range strings.Split(string(out), "\n") {
		sha, typ, ok := strings.Cut(line, " ")
		if ok && typ != "missing" && isHex(sha) {
			keep = append(keep, sha)
		}
	}
	return keep, nil
}

func isHex(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Tips returns the object ID of each ref.
func (g *Git) Tips(ctx context.Context) (map[string]string, error) {
	out, err := g.Run(ctx, "for-each-ref", "--format=%(objectname) %(refname)")
	if err != nil {
		return nil, err
	}
	tips := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		sha, ref, ok := strings.Cut(line, " ")
		if ok {
			tips[ref] = sha
		}
	}
	return tips, nil
}

// Commit is the commit that introduced a blob.
type Commit struct {
	SHA         string
	AuthorName  string
	AuthorEmail string
	Date        string
}

// BlobInfo is what the history says about one blob.
type BlobInfo struct {
	// First is the oldest commit that adds or changes the blob.
	First *Commit
	// Paths lists each path at which a commit adds the blob.
	Paths []string
}

// BlobHistory walks the history one time and returns, for each blob that
// want accepts, its first commit and all its paths. revs selects the
// history, for example "--all". The history of each commit in exclude is
// left out.
//
// git rev-list reports only one path for each blob. This walk finds the
// other paths. With -m, git diffs a merge against each parent, so a blob
// that only a merge resolution adds gets the merge commit.
//
// The output uses NUL bytes between all fields. A path or an author name
// can hold any other byte, so no other separator is safe.
func (g *Git) BlobHistory(ctx context.Context, want func(sha string) bool, revs, exclude []string) (map[string]*BlobInfo, error) {
	out := map[string]*BlobInfo{}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// git log, unlike rev-list, fails on a missing commit, also with
	// --ignore-missing.
	exclude, err := g.Existing(ctx, exclude)
	if err != nil {
		return nil, err
	}
	args := []string{"log", "--stdin", "--reverse", "-m", "--format=%x01%H%x00%an%x00%ae%x00%aI", "--raw", "--no-renames", "--no-abbrev", "-z"}
	args = append(args, revs...)
	cmd := g.command(ctx, append(args, "--")...)
	var stdin strings.Builder
	for _, sha := range exclude {
		stdin.WriteString("^" + sha + "\n")
	}
	cmd.Stdin = strings.NewReader(stdin.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(stdout, 1<<16)
	var current *Commit
	var pending *BlobInfo
	// header holds the fields of a commit header while they arrive. The
	// tokens are \x01<sha>, <name>, <email> and <date>.
	var header []string
	for {
		tok, err := r.ReadString(0)
		if err != nil && err != io.EOF {
			break
		}
		tok = strings.TrimSuffix(tok, "\x00")
		switch {
		case header != nil:
			header = append(header, tok)
			if len(header) == 4 {
				current = nil
				if isHex(header[0]) {
					current = &Commit{SHA: header[0], AuthorName: header[1], AuthorEmail: header[2], Date: header[3]}
				}
				header = nil
			}
		case pending != nil:
			// This token is the path of the previous raw entry.
			if !contains(pending.Paths, tok) {
				pending.Paths = append(pending.Paths, tok)
			}
			pending = nil
		default:
			t := strings.TrimLeft(tok, "\n")
			if strings.HasPrefix(t, "\x01") {
				header = []string{t[1:]}
				break
			}
			if strings.HasPrefix(t, ":") {
				f := strings.Fields(t[1:])
				// Read the path token even when the blob is not a target.
				// Skip deletions and submodule commits.
				pending = &BlobInfo{}
				if len(f) >= 4 && f[3] != ZeroSHA && isFileMode(f[1]) && want(f[3]) {
					info := out[f[3]]
					if info == nil {
						info = &BlobInfo{First: current}
						out[f[3]] = info
					}
					pending = info
				}
			}
		}
		if err == io.EOF {
			break
		}
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		return nil, &Error{Args: []string{"log"}, Stderr: strings.TrimSpace(stderr.String()), Err: err}
	}
	return out, nil
}

// isFileMode reports whether a tree mode is a file or a symlink.
func isFileMode(mode string) bool {
	return strings.HasPrefix(mode, "100") || mode == "120000"
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Blob is one blob and one path at which it occurs.
type Blob struct {
	SHA  string
	Path string
	Size int64
}

// ListBlobs lists the blobs that rev-list reaches from revs, such as
// "--all" or "base..head". The history of each commit in exclude is left
// out. The exclude list goes to rev-list on stdin, because it can hold
// thousands of commits. The callback receives the blobs in batches.
func (g *Git) ListBlobs(ctx context.Context, revs, exclude []string, batchSize int, fn func([]Blob) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	args := append([]string{"rev-list", "--objects", "--ignore-missing", "--stdin"}, revs...)
	revList := g.command(ctx, append(args, "--")...)
	var stdin strings.Builder
	for _, sha := range exclude {
		stdin.WriteString("^" + sha + "\n")
	}
	revList.Stdin = strings.NewReader(stdin.String())
	var revErr bytes.Buffer
	revList.Stderr = &revErr

	check := g.command(ctx, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize) %(rest)")
	var checkErr bytes.Buffer
	check.Stderr = &checkErr
	checkOut, err := check.StdoutPipe()
	if err != nil {
		return err
	}

	// An OS pipe connects the two processes. The parent closes both ends
	// after the start. When cat-file exits early, rev-list then gets
	// SIGPIPE and does not block on a full pipe.
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	revList.Stdout = pw
	check.Stdin = pr
	if err := revList.Start(); err != nil {
		pr.Close()
		pw.Close()
		return err
	}
	if err := check.Start(); err != nil {
		pr.Close()
		pw.Close()
		cancel()
		_ = revList.Wait()
		return err
	}
	pr.Close()
	pw.Close()

	batch := make([]Blob, 0, batchSize)
	sc := bufio.NewScanner(checkOut)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var cbErr error
	for sc.Scan() {
		line := sc.Text()
		// Format: <sha> <type> <size> <path>. The path can contain spaces.
		f := strings.SplitN(line, " ", 4)
		if len(f) < 3 || f[1] != "blob" {
			continue
		}
		size, _ := strconv.ParseInt(f[2], 10, 64)
		path := ""
		if len(f) == 4 {
			path = f[3]
		}
		batch = append(batch, Blob{SHA: f[0], Path: path, Size: size})
		if len(batch) >= batchSize {
			if cbErr = fn(batch); cbErr != nil {
				break
			}
			batch = make([]Blob, 0, batchSize)
		}
	}
	if cbErr == nil {
		cbErr = sc.Err()
	}
	if cbErr != nil {
		cancel()
		_ = check.Wait()
		_ = revList.Wait()
		return cbErr
	}
	if err := check.Wait(); err != nil {
		cancel()
		_ = revList.Wait()
		return &Error{Args: []string{"cat-file"}, Stderr: strings.TrimSpace(checkErr.String()), Err: err}
	}
	if err := revList.Wait(); err != nil {
		return &Error{Args: []string{"rev-list"}, Stderr: strings.TrimSpace(revErr.String()), Err: err}
	}
	if len(batch) > 0 {
		return fn(batch)
	}
	return nil
}

// BatchReader reads object contents through one "git cat-file --batch"
// process. It is not safe for concurrent use.
type BatchReader struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *bufio.Reader
}

// NewBatchReader starts the cat-file process. Call Close when done.
func (g *Git) NewBatchReader(ctx context.Context) (*BatchReader, error) {
	cmd := g.command(ctx, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &BatchReader{cmd: cmd, stdin: stdin, out: bufio.NewReaderSize(stdout, 1<<16)}, nil
}

// ErrMissing means that the object does not exist.
var ErrMissing = errors.New("object is missing")

// Read returns the content of an object.
func (b *BatchReader) Read(sha string) ([]byte, error) {
	if _, err := io.WriteString(b.stdin, sha+"\n"); err != nil {
		return nil, err
	}
	header, err := b.out.ReadString('\n')
	if err != nil {
		return nil, err
	}
	f := strings.Fields(header)
	if len(f) == 2 && f[1] == "missing" {
		return nil, ErrMissing
	}
	if len(f) != 3 {
		return nil, fmt.Errorf("cat-file: unexpected header %q", strings.TrimSpace(header))
	}
	size, err := strconv.Atoi(f[2])
	if err != nil {
		return nil, fmt.Errorf("cat-file: bad size in header %q", strings.TrimSpace(header))
	}
	data := make([]byte, size+1)
	if _, err := io.ReadFull(b.out, data); err != nil {
		return nil, err
	}
	return data[:size], nil
}

// Peek returns up to n bytes from the start of an object, and reads past
// the rest. Use it to test a large blob for binary content.
func (b *BatchReader) Peek(sha string, n int) ([]byte, error) {
	if _, err := io.WriteString(b.stdin, sha+"\n"); err != nil {
		return nil, err
	}
	header, err := b.out.ReadString('\n')
	if err != nil {
		return nil, err
	}
	f := strings.Fields(header)
	if len(f) == 2 && f[1] == "missing" {
		return nil, ErrMissing
	}
	if len(f) != 3 {
		return nil, fmt.Errorf("cat-file: unexpected header %q", strings.TrimSpace(header))
	}
	size, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("cat-file: bad size in header %q", strings.TrimSpace(header))
	}
	head := make([]byte, min(int64(n), size))
	if _, err := io.ReadFull(b.out, head); err != nil {
		return nil, err
	}
	// Discard the rest of the object and the newline after it.
	if _, err := io.CopyN(io.Discard, b.out, size-int64(len(head))+1); err != nil {
		return nil, err
	}
	return head, nil
}

// Close stops the cat-file process.
func (b *BatchReader) Close() error {
	_ = b.stdin.Close()
	return b.cmd.Wait()
}

// IsBinary reports whether the first 8 KB of data contain a NUL byte.
func IsBinary(data []byte) bool {
	if len(data) > 8192 {
		data = data[:8192]
	}
	return bytes.IndexByte(data, 0) >= 0
}
