package collector

import "context"

// sessionsCollector enumerates terminal (interactive and RDP) sessions on the
// host: the session id, its state, the window-station name, the signed-in
// user, and — for a remote session — the connecting client. It answers "who
// is or was logged on, and from where" at collection time.
type sessionsCollector struct{}

func (sessionsCollector) Name() string        { return "sessions" }
func (sessionsCollector) Platforms() []string { return []string{"windows"} }

func (sessionsCollector) Collect(ctx context.Context) (Result, error) {
	return collectSessions(ctx)
}

func init() { Register(sessionsCollector{}) }
