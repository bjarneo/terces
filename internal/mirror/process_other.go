//go:build !unix

package mirror

import "os/exec"

// setCancel keeps the default cancel, which kills the git process.
func setCancel(cmd *exec.Cmd) {}
