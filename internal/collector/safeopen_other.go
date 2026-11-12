//go:build !unix && !windows

package collector

import "os"

func openNoBlock(path string) (*os.File, error) { return os.Open(path) }

func remotePath(string) bool { return false }
