//go:build !windows && !linux

package collector

// The AI agent collector runs on Windows and Linux; elsewhere it has nothing
// to read.
func aiHomes() []string { return nil }

var aiClientConfigs, aiSystemConfigs []aiClientConfig
