//go:build windows

package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyKnownBinaries runs the real WinVerifyTrust path against a binary
// that must verify (kernel32.dll, catalog-signed on every Windows host) and one
// that can't (a junk file), closing the loop the portable tests can't.
func TestVerifyKnownBinaries(t *testing.T) {
	if underWine() {
		t.Skip("Wine's kernel32.dll is its own unsigned build, and the catalog APIs are incomplete")
	}

	kernel32 := filepath.Join(systemRoot(), `System32\kernel32.dll`)
	r := verifyAuthenticode(kernel32)
	if r.State != SigTrusted {
		t.Errorf("kernel32.dll verified as %s (%s), want trusted", r.State, r.Detail)
	}
	// Signed by Microsoft through a catalog ("Microsoft Windows").
	if !strings.Contains(strings.ToLower(r.Signer), "microsoft") {
		t.Errorf("kernel32.dll signer = %q, want a Microsoft signer", r.Signer)
	}
	t.Logf("kernel32.dll: state=%s catalog=%v signer=%q", r.State, r.Catalog, r.Signer)

	tmp := filepath.Join(t.TempDir(), "unsigned.exe")
	if err := os.WriteFile(tmp, []byte("MZ this is not a signed PE file"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = verifyAuthenticode(tmp)
	if r.State == SigTrusted {
		t.Errorf("a junk file verified as trusted: %+v", r)
	}
	if r.Signer != "" {
		t.Errorf("a junk file has no signature, but signer = %q", r.Signer)
	}
	t.Logf("junk file: state=%s detail=%q", r.State, r.Detail)
}

// TestSignerOfEmbeddedSignature checks the embedded-signature path end to end
// against a file signed with a throwaway certificate: LRNG_SIGNED_SAMPLE names
// the file and LRNG_SIGNED_SAMPLE_SIGNER the certificate's common name. The
// certificate isn't trusted, so the verdict is untrusted, but the signer must
// still be read back. Skipped unless both are set; it runs under Wine too.
func TestSignerOfEmbeddedSignature(t *testing.T) {
	path, want := os.Getenv("LRNG_SIGNED_SAMPLE"), os.Getenv("LRNG_SIGNED_SAMPLE_SIGNER")
	if path == "" || want == "" {
		t.Skip("set LRNG_SIGNED_SAMPLE and LRNG_SIGNED_SAMPLE_SIGNER to check a self-signed file")
	}
	r := verifyAuthenticode(path)
	if r.Catalog {
		t.Errorf("an embedded signature was reported as catalog-verified: %+v", r)
	}
	if r.State != SigUntrusted && r.State != SigTrusted {
		t.Errorf("signed sample verified as %s (%s), want untrusted (or trusted if its root was installed)", r.State, r.Detail)
	}
	if r.Signer != want {
		t.Errorf("signer = %q, want %q", r.Signer, want)
	}
	t.Logf("signed sample: state=%s signer=%q detail=%q", r.State, r.Signer, r.Detail)
}
