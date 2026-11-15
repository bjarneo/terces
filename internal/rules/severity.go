package rules

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity is the impact level of a finding. A higher value is more severe.
type Severity int

// The severity levels, from the lowest to the highest.
const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// ParseSeverity converts a name such as "high" to a Severity.
func ParseSeverity(s string) (Severity, error) {
	for sev, name := range severityNames {
		if strings.EqualFold(strings.TrimSpace(s), name) {
			return sev, nil
		}
	}
	return SeverityUnknown, fmt.Errorf("unknown severity %q: use low, medium, high or critical", s)
}

// String returns the lowercase name of the severity.
func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "unknown"
}

// MarshalJSON writes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON reads the severity from its name.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	v, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = v
	return nil
}
