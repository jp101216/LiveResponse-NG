//go:build !windows

package analyst

import (
	"os/exec"
	"runtime"
)

func browserCommand(url string) *exec.Cmd { return fallbackBrowserCommand(runtime.GOOS, url) }
