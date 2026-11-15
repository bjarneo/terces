# Rule fixtures

Each `*.yaml` file lists positive and negative fixtures for rules. The test
in `rules/rules_test.go` expands the placeholders at test time and runs the
engine on each fixture.

The fixtures hold templates, not fake secrets. A committed fake token trips
GitHub push protection and other scanners. Use these placeholders:

- `{{rand:<charset>:<n>}}` gives `n` random characters from the charset, for example `{{rand:A-Z2-7:16}}`.
- `{{dashes}}` gives five dashes. Use it for PEM headers.

A positive fixture must give one or more findings of the rule. A negative
fixture must give no finding of the rule. The optional `path` field sets the
file path of the fixture.
