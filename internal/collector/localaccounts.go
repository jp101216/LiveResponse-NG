package collector

import "context"

// localAccountsCollector lists local user accounts (with privilege level and
// the account flags that matter for triage — disabled, locked out, password
// not required, password never expires) and the members of the built-in
// Administrators and Remote Desktop Users groups.
type localAccountsCollector struct{}

func (localAccountsCollector) Name() string        { return "localaccounts" }
func (localAccountsCollector) Platforms() []string { return []string{"windows", "linux"} }

func (localAccountsCollector) Collect(ctx context.Context) (Result, error) {
	return collectLocalAccounts(ctx)
}

func init() { Register(localAccountsCollector{}) }
