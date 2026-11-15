package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"terces/internal/engine"
	"terces/internal/fingerprint"
	"terces/internal/githubapp"
	"terces/internal/mirror"
	"terces/internal/notify"
	"terces/internal/pipeline"
	"terces/internal/rules"
	"terces/internal/scanner"
	"terces/internal/store"
	rulesdata "terces/rules"
)

const envPrefix = "TERCES_"

// app holds the global flags and the shared resources of one command.
type app struct {
	databaseURL  string
	rulesDir     string
	hmacKeyFile  string
	mirrorDir    string
	appID        string
	appKeyFile   string
	githubAPIURL string
	githubURL    string
	slackURLFile string
	maxBlobSize  int64
	fetchTimeout time.Duration
	workers      int
	logLevel     string
	actor        string

	log     *slog.Logger
	ruleSet *rules.Set
	db      *store.Store
	ghApp   *githubapp.App
	hasher  *fingerprint.Hasher
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(envPrefix + name); ok {
		return v
	}
	return def
}

func envDuration(name string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(envPrefix + name); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envInt(name string, def int64) int64 {
	if v, ok := os.LookupEnv(envPrefix + name); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// secretValue returns the value of the environment variable
// TERCES_<name>, or the content of file. Secrets are never flags,
// because other users can read process arguments.
func secretValue(name, file string) (string, error) {
	// Trim the value. An env file with CRLF line ends adds "\r".
	if v := strings.TrimSpace(os.Getenv(envPrefix + name)); v != "" {
		return v, nil
	}
	if file == "" {
		return "", nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (a *app) bindFlags(root *cobra.Command) {
	f := root.PersistentFlags()
	// The default stays empty, so that --help never prints a password
	// from the environment. store() reads the environment variable.
	f.StringVar(&a.databaseURL, "database-url", "", "Postgres connection URL (env "+envPrefix+"DATABASE_URL)")
	f.StringVar(&a.rulesDir, "rules", env("RULES_DIR", ""), "directory with rule files. The default is the rules built into the binary (env "+envPrefix+"RULES_DIR)")
	f.StringVar(&a.hmacKeyFile, "hmac-key-file", env("HMAC_KEY_FILE", ""), "file with the fingerprint HMAC key in hex or base64. "+envPrefix+"HMAC_KEY sets the key directly")
	f.StringVar(&a.mirrorDir, "mirror-dir", env("MIRROR_DIR", "/data/mirrors"), "directory for the repository mirrors (env "+envPrefix+"MIRROR_DIR)")
	f.StringVar(&a.appID, "github-app-id", env("GITHUB_APP_ID", ""), "GitHub App ID or client ID (env "+envPrefix+"GITHUB_APP_ID)")
	f.StringVar(&a.appKeyFile, "github-app-key-file", env("GITHUB_APP_KEY_FILE", ""), "file with the GitHub App private key in PEM format. "+envPrefix+"GITHUB_APP_KEY sets the key directly")
	f.StringVar(&a.githubAPIURL, "github-api-url", env("GITHUB_API_URL", "https://api.github.com"), "GitHub REST API URL (env "+envPrefix+"GITHUB_API_URL)")
	f.StringVar(&a.githubURL, "github-url", env("GITHUB_URL", "https://github.com"), "GitHub git URL (env "+envPrefix+"GITHUB_URL)")
	f.StringVar(&a.slackURLFile, "slack-webhook-url-file", env("SLACK_WEBHOOK_URL_FILE", ""), "file with the Slack incoming webhook URL. "+envPrefix+"SLACK_WEBHOOK_URL sets the URL directly")
	f.Int64Var(&a.maxBlobSize, "max-blob-size", envInt("MAX_BLOB_SIZE", scanner.DefaultMaxBlobSize), "skip blobs larger than this number of bytes (env "+envPrefix+"MAX_BLOB_SIZE)")
	f.DurationVar(&a.fetchTimeout, "fetch-timeout", envDuration("FETCH_TIMEOUT", pipeline.DefaultFetchTimeout), "time limit for the fetch of one repository (env "+envPrefix+"FETCH_TIMEOUT)")
	f.IntVar(&a.workers, "workers", int(envInt("WORKERS", int64(runtime.NumCPU()))), "number of parallel scan workers (env "+envPrefix+"WORKERS)")
	f.StringVar(&a.logLevel, "log-level", env("LOG_LEVEL", "info"), "log level: debug, info, warn or error (env "+envPrefix+"LOG_LEVEL)")
	f.StringVar(&a.actor, "actor", env("ACTOR", ""), "name to record in the audit log. The default is the OS user (env "+envPrefix+"ACTOR)")
}

func (a *app) setup() error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(a.logLevel)); err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	a.log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if a.actor == "" {
		if u, err := user.Current(); err == nil {
			a.actor = u.Username
		} else {
			a.actor = "unknown"
		}
	}
	return nil
}

func (a *app) close() {
	if a.db != nil {
		a.db.Close()
	}
}

func (a *app) rules() (*rules.Set, error) {
	if a.ruleSet != nil {
		return a.ruleSet, nil
	}
	var err error
	if a.rulesDir != "" {
		a.ruleSet, err = rules.LoadDir(a.rulesDir)
	} else {
		a.ruleSet, err = rules.LoadFS(rulesdata.FS, "built-in")
	}
	return a.ruleSet, err
}

// fingerprinter returns the HMAC hasher. When requireKey is false and no
// key is set, it returns a hasher with a random key for this process.
func (a *app) fingerprinter(requireKey bool) (*fingerprint.Hasher, error) {
	if a.hasher != nil {
		return a.hasher, nil
	}
	key, err := fingerprint.LoadKey(os.Getenv(envPrefix+"HMAC_KEY"), a.hmacKeyFile)
	if err != nil {
		return nil, err
	}
	if key == nil {
		if requireKey {
			return nil, fmt.Errorf("no HMAC key: set %sHMAC_KEY or --hmac-key-file. Generate a key with: openssl rand -hex 32", envPrefix)
		}
		a.hasher = fingerprint.NewEphemeral()
		return a.hasher, nil
	}
	a.hasher, err = fingerprint.New(key)
	return a.hasher, err
}

func (a *app) scanner(requireKey bool) (*scanner.Scanner, error) {
	set, err := a.rules()
	if err != nil {
		return nil, err
	}
	h, err := a.fingerprinter(requireKey)
	if err != nil {
		return nil, err
	}
	return &scanner.Scanner{
		Engine:      engine.New(set),
		Hasher:      h,
		MaxBlobSize: a.maxBlobSize,
		Workers:     a.workers,
	}, nil
}

func (a *app) store(ctx context.Context) (*store.Store, error) {
	if a.db != nil {
		return a.db, nil
	}
	if a.databaseURL == "" {
		a.databaseURL = os.Getenv(envPrefix + "DATABASE_URL")
	}
	if a.databaseURL == "" {
		return nil, fmt.Errorf("no database: set %sDATABASE_URL or --database-url", envPrefix)
	}
	db, err := store.Open(ctx, a.databaseURL)
	if err != nil {
		return nil, err
	}
	a.db = db
	return db, nil
}

func (a *app) github() (*githubapp.App, error) {
	if a.ghApp != nil {
		return a.ghApp, nil
	}
	if a.appID == "" {
		return nil, fmt.Errorf("no GitHub App ID: set %sGITHUB_APP_ID or --github-app-id", envPrefix)
	}
	pem, err := secretValue("GITHUB_APP_KEY", a.appKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read GitHub App key: %w", err)
	}
	if pem == "" {
		return nil, fmt.Errorf("no GitHub App private key: set %sGITHUB_APP_KEY or --github-app-key-file", envPrefix)
	}
	a.ghApp, err = githubapp.New(a.appID, []byte(pem), a.githubAPIURL)
	return a.ghApp, err
}

func (a *app) mirrors() *mirror.Store {
	return &mirror.Store{Root: a.mirrorDir, BaseURL: a.githubURL}
}

// slack returns nil when no webhook URL is set.
func (a *app) slack() (*notify.Slack, error) {
	url, err := secretValue("SLACK_WEBHOOK_URL", a.slackURLFile)
	if err != nil {
		return nil, fmt.Errorf("read Slack webhook URL: %w", err)
	}
	if url == "" {
		return nil, nil
	}
	return notify.NewSlack(url, a.githubURL), nil
}

// pipeline builds the pipeline for commands that use GitHub, the
// mirrors and the database.
func (a *app) pipeline(ctx context.Context, needGitHub bool) (*pipeline.Pipeline, error) {
	db, err := a.store(ctx)
	if err != nil {
		return nil, err
	}
	sc, err := a.scanner(true)
	if err != nil {
		return nil, err
	}
	sw := &pipeline.Pipeline{
		Store:        db,
		Mirrors:      a.mirrors(),
		Scanner:      sc,
		Log:          a.log,
		FetchTimeout: a.fetchTimeout,
	}
	if needGitHub {
		if sw.GitHub, err = a.github(); err != nil {
			return nil, err
		}
	}
	if sw.Slack, err = a.slack(); err != nil {
		return nil, err
	}
	return sw, nil
}
