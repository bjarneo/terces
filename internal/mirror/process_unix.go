//go:build unix

package mirror

import (
	"os/exec"
	"syscall"
)

// setCancel makes git run in its own process group. On cancel, the group
// gets SIGTERM, so that helpers such as git-remote-https also stop and git
// can remove its lock files.
func setCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}
