//go:build !windows

package collector

// verifyAuthenticode is a stub off Windows. Authenticode is a Windows concept
// and the only collector that verifies signatures (processes) is Windows-only,
// so this is never reached in practice; it exists so the portable half of the
// verifier compiles everywhere.
func verifyAuthenticode(string) SignatureResult {
	return SignatureResult{State: SigError, Detail: "signature verification is windows-only"}
}
