package render

import (
	"encoding/json"
	"io"
	"net/url"
	"sort"

	"terces/internal/fingerprint"
	"terces/internal/rules"
	"terces/internal/scanner"
)

// SARIFOptions controls SARIFLog.
type SARIFOptions struct {
	// ToolVersion is the terces version.
	ToolVersion string
	// StableFingerprints adds the HMAC fingerprint of each secret as a
	// partial fingerprint, so that GitHub tracks one alert across scans.
	// Set it only with the server HMAC key: a key for one run gives new
	// fingerprints on each run.
	StableFingerprints bool
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version,omitempty"`
	Rules   []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	ShortDescription     sarifText         `json:"shortDescription"`
	Help                 sarifText         `json:"help"`
	DefaultConfiguration sarifLevel        `json:"defaultConfiguration"`
	Properties           sarifRuleProperty `json:"properties"`
}

type sarifLevel struct {
	Level string `json:"level"`
}

type sarifRuleProperty struct {
	// SecuritySeverity is the GitHub score from 0.1 to 10.0. GitHub shows
	// 9.0 and higher as critical, 7.0 to 8.9 as high, 4.0 to 6.9 as medium
	// and lower as low.
	SecuritySeverity string   `json:"security-severity"`
	Tags             []string `json:"tags"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// sarifSeverity maps a severity to the SARIF level and the GitHub score.
func sarifSeverity(s rules.Severity) (level, score string) {
	switch s {
	case rules.SeverityCritical:
		return "error", "9.5"
	case rules.SeverityHigh:
		return "error", "8.0"
	case rules.SeverityMedium:
		return "warning", "5.5"
	default:
		return "note", "2.0"
	}
}

// SARIFLog writes findings as one SARIF 2.1.0 run. GitHub code scanning
// accepts the file. A path is relative to the repository root. GitHub
// takes one file for each repository, so call SARIFLog for one repository
// only.
func SARIFLog(w io.Writer, findings []scanner.Finding, set *rules.Set, opts SARIFOptions) error {
	scanner.SortFindings(findings)
	index := map[string]int{}
	var ids []string
	for _, f := range findings {
		if _, ok := index[f.RuleID]; !ok {
			index[f.RuleID] = 0
			ids = append(ids, f.RuleID)
		}
	}
	sort.Strings(ids)
	var sr []sarifRule
	for i, id := range ids {
		index[id] = i
		desc := id
		sev := rules.SeverityHigh
		if r, ok := set.ByID[id]; ok {
			if r.Description != "" {
				desc = r.Description
			}
			sev = r.Sev
		}
		level, score := sarifSeverity(sev)
		sr = append(sr, sarifRule{
			ID:                   id,
			ShortDescription:     sarifText{desc},
			Help:                 sarifText{"Treat the secret as compromised. Revoke it at its provider first. Then remove it from the code, and use a secret manager."},
			DefaultConfiguration: sarifLevel{level},
			Properties:           sarifRuleProperty{SecuritySeverity: score, Tags: []string{"security", "secret"}},
		})
	}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		level, _ := sarifSeverity(f.Severity)
		msg := "Possible secret, rule " + f.RuleID + ". Preview: " + f.Preview + "."
		if f.Description != "" {
			msg = f.Description + " Preview: " + f.Preview + "."
		}
		line := f.Line
		if line < 1 {
			line = 1
		}
		res := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: index[f.RuleID],
			Level:     level,
			Message:   sarifText{msg},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				// url.URL encodes the path and puts ./ in front of a first
				// segment with a colon, such as wiki:Home.md.
				ArtifactLocation: sarifArtifact{URI: (&url.URL{Path: f.Path}).String(), URIBaseID: "%SRCROOT%"},
				Region:           sarifRegion{StartLine: line},
			}}},
		}
		if opts.StableFingerprints {
			res.PartialFingerprints = map[string]string{"tercesFingerprint/v1": fingerprint.Hex(f.Fingerprint)}
		}
		if f.CommitSHA != "" {
			res.Properties = map[string]string{"commit": f.CommitSHA}
		}
		results = append(results, res)
	}
	if sr == nil {
		sr = []sarifRule{}
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "terces", Version: opts.ToolVersion, Rules: sr}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
