package collector

import (
	"os"
	"runtime"
	"testing"
)

func TestSelfExclusionRespectsPathCase(t *testing.T) {
	opts := RunOptions{SelfPID: 101, SelfPaths: []string{"", "/opt/lrng"}}
	if !opts.isSelf(101, "") || !opts.isSelf(202, "/opt/lrng") {
		t.Fatal("the agent and its components must remain excluded")
	}
	if opts.isSelf(202, "") || opts.isSelf(202, "/opt/other") {
		t.Fatal("an unrelated process was excluded")
	}
	want := runtime.GOOS == "windows"
	if got := opts.isSelf(202, "/opt/LRNG"); got != want {
		t.Fatalf("case-only path difference: isSelf = %v, want %v on %s", got, want, runtime.GOOS)
	}
	if !(RunOptions{}).isSelf(uint32(os.Getpid()), "") {
		t.Fatal("the default self PID must be the running process")
	}
}
