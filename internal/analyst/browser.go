package analyst

import "os/exec"

// OpenBrowser passes the generated loopback URL directly as an argument. No
// shell or report-derived text participates in command construction.
func OpenBrowser(url string) error {
	command := browserCommand(url)
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}

// fallbackBrowserCommand is the launcher for an OS without a fixed system
// location to pin it to.
func fallbackBrowserCommand(goos, url string) *exec.Cmd {
	if goos == "darwin" {
		return exec.Command("open", url)
	}
	return exec.Command("xdg-open", url)
}
