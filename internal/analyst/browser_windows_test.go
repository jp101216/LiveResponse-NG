//go:build windows

package analyst

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The launcher must be an absolute path to the real rundll32, never a name
// left to a PATH search.
func TestBrowserCommandUsesTheSystemDirectory(t *testing.T) {
	cmd := browserCommand("http://127.0.0.1:1/x/")
	if !filepath.IsAbs(cmd.Path) || !strings.EqualFold(filepath.Base(cmd.Path), "rundll32.exe") {
		t.Fatalf("launcher path = %q", cmd.Path)
	}
	if _, err := os.Stat(cmd.Path); err != nil {
		t.Fatalf("launcher does not exist: %v", err)
	}
	if len(cmd.Args) != 3 || cmd.Args[1] != "url.dll,FileProtocolHandler" || cmd.Args[2] != "http://127.0.0.1:1/x/" {
		t.Fatalf("arguments = %q", cmd.Args)
	}
}
