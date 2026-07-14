//go:build windows

package verify

import "os/exec"

func configureProcess(cmd *exec.Cmd) {}

func stopProcess(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
}
