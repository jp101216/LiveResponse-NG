//go:build !windows && !linux

package collector

import "errors"

func listProcesses() ([]procInfo, error) {
	return nil, errors.New("process listing is implemented for windows and linux only")
}
