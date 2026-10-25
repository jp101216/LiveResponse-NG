package hostinfo

import (
	"testing"
	"time"
)

func TestWindowsProductName(t *testing.T) {
	cases := map[[2]string]string{
		{"Windows 10 Pro", "22631.4317"}:                 "Windows 11 Pro",
		{"Windows 10 Enterprise", "19045.5011"}:          "Windows 10 Enterprise",
		{"Windows Server 2022 Datacenter", "20348.2700"}: "Windows Server 2022 Datacenter",
		{"Windows 10 Pro", "garbage"}:                    "Windows 10 Pro",
	}
	for in, want := range cases {
		if got := windowsProductName(in[0], in[1]); got != want {
			t.Errorf("%v -> %q, want %q", in, got, want)
		}
	}
	if timePtr(time.Time{}) != nil {
		t.Fatal("zero time must be omitted")
	}
}

func TestGatherDoesNotPanic(t *testing.T) {
	_ = Gather()
}
