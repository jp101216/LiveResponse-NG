package collector

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unicode"
)

// Authenticode signature verification for reported binaries. The path
// heuristics say where a program runs from; this says whether the code is
// signed and trusted — the stronger check. A binary with the name and location
// of a Windows system file but no valid signature is either tampered or a
// look-alike dropped into a trusted-looking path.
//
// The trust decision (embedded signature, then a security-catalog fallback) is
// made by WinVerifyTrust in authenticode_windows.go; verification is offline
// (no revocation network traffic). The same call names the signer: the display
// name of the primary signer's certificate, read from WinVerifyTrust's state
// before it is released — for a catalog-signed file, the catalog's signer. An
// untrusted signature still names who it claims to be from, which is often the
// most telling part. This file holds the portable result type, the per-run
// cache, the record fields, the signer-name sanitizer and the finding logic,
// all unit-tested on any OS. verifyAuthenticode is the platform-specific half.

// SigState is the outcome of verifying a file's signature.
type SigState int

const (
	SigUnknown   SigState = iota // not checked
	SigTrusted                   // a valid signature chaining to a trusted root
	SigUntrusted                 // signed, but the signature or chain didn't validate
	SigUnsigned                  // no embedded signature and no catalog entry
	SigError                     // verification couldn't be completed
)

func (s SigState) String() string {
	switch s {
	case SigTrusted:
		return "trusted"
	case SigUntrusted:
		return "untrusted"
	case SigUnsigned:
		return "unsigned"
	case SigError:
		return "error"
	default:
		return "unknown"
	}
}

// SignatureResult is the verdict for one file.
type SignatureResult struct {
	State SigState
	// Signer is the display name of the primary signer's certificate (for a
	// catalog-signed file, the catalog's signer), sanitized by cleanSignerName.
	// Best-effort: empty when there is no signature or the name can't be read.
	Signer  string
	Catalog bool   // verified via a security catalog rather than an embedded signature
	Detail  string // a status explanation (e.g. the WinVerifyTrust status) for untrusted/error
}

// maxSignerRunes caps a reported signer name.
const maxSignerRunes = 256

// cleanSignerName makes a certificate's display name safe to report. Anyone
// can sign a file with a certificate they made themselves, so the subject is
// attacker-chosen text: surrounding space is trimmed, every non-printable rune
// — control characters, and format characters such as the bidi overrides that
// can make a name read as something it isn't — is written as a visible \uXXXX
// escape (the evidence is kept, but it can't disguise itself), and an over-long
// name is cut with "…".
func cleanSignerName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxSignerRunes {
			b.WriteString("…")
			break
		}
		switch {
		case unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xFFFF:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			fmt.Fprintf(&b, `\U%08X`, r)
		}
		n++
	}
	return b.String()
}

// SignatureVerifier verifies the binaries a run reports, caching per path so a
// file named by several records is verified once. A nil verifier (checking
// disabled) does nothing. Safe for concurrent use.
type SignatureVerifier struct {
	mu    sync.Mutex
	cache map[string]SignatureResult
}

// NewSignatureVerifier returns a ready verifier.
func NewSignatureVerifier() *SignatureVerifier { return &SignatureVerifier{} }

// Verify returns the signature verdict for path, cached per path.
func (v *SignatureVerifier) Verify(_ context.Context, path string) SignatureResult {
	if v == nil || path == "" {
		return SignatureResult{State: SigUnknown}
	}
	key := strings.ToLower(path)
	v.mu.Lock()
	if v.cache == nil {
		v.cache = map[string]SignatureResult{}
	}
	if r, ok := v.cache[key]; ok {
		v.mu.Unlock()
		return r
	}
	v.mu.Unlock()

	r := verifyAuthenticode(path)

	v.mu.Lock()
	v.cache[key] = r
	v.mu.Unlock()
	return r
}

// Fields verifies path and records the verdict on a record. A nil verifier, an
// empty path or a path still holding an unexpanded %VARIABLE% adds nothing. It
// returns the result so the caller can also derive findings.
func (v *SignatureVerifier) Fields(ctx context.Context, fields map[string]any, path string) SignatureResult {
	if v == nil || path == "" || strings.Contains(path, "%") {
		return SignatureResult{}
	}
	r := v.Verify(ctx, path)
	applySignatureFields(fields, r)
	return r
}

// applySignatureFields writes a result onto a record's fields. Kept separate so
// it can be unit-tested without the Windows verifier.
func applySignatureFields(fields map[string]any, r SignatureResult) {
	switch r.State {
	case SigTrusted, SigUntrusted, SigUnsigned:
		fields["signature_state"] = r.State.String()
	case SigError:
		fields["signature_state"] = "error"
		if r.Detail != "" {
			fields["signature_error"] = r.Detail
		}
	default:
		return
	}
	if r.Signer != "" {
		fields["signer"] = r.Signer
	}
	if r.Catalog {
		fields["signature_catalog"] = true
	}
}

// signatureFindings flags a process image in a Windows system directory whose
// signature didn't validate. Genuine system binaries there are catalog- or
// embedded-signed, so an unsigned or untrusted one is a masquerade/tamper
// signal (T1036.005). Only confident verdicts are flagged: SigError (the check
// couldn't be completed) never raises a finding.
func signatureFindings(imagePath string, r SignatureResult, systemRoot string) []Finding {
	if imagePath == "" || !underSystemDir(imagePath, systemRoot) {
		return nil
	}
	var sev Severity
	var what string
	switch r.State {
	case SigUnsigned:
		sev, what = SevNotable, "is unsigned"
	case SigUntrusted:
		sev, what = SevSuspect, "has an untrusted signature"
		if r.Signer != "" {
			// Who the signature claims to be from: a "Microsoft" name on a
			// signature that doesn't validate is itself the tell.
			what += ` from "` + r.Signer + `"`
		}
	default:
		return nil
	}
	detail := fmt.Sprintf("%s runs from a Windows system directory but %s; binaries there are normally signed", imagePath, what)
	if r.Detail != "" {
		detail += " (" + r.Detail + ")"
	}
	return []Finding{{
		Rule:       "integrity.unsigned_system_binary",
		Severity:   sev,
		Technique:  "T1036.005",
		Confidence: 50,
		Detail:     detail,
	}}
}

// underSystemDir reports whether a path is inside System32 or SysWOW64 of the
// Windows directory — where unsigned executables don't belong.
func underSystemDir(imagePath, systemRoot string) bool {
	p := strings.ToLower(strings.ReplaceAll(imagePath, "/", `\`))
	root := strings.ToLower(strings.ReplaceAll(strings.TrimRight(systemRoot, `\`), "/", `\`))
	if root == "" {
		root = `c:\windows`
	}
	return strings.HasPrefix(p, root+`\system32\`) || strings.HasPrefix(p, root+`\syswow64\`)
}
