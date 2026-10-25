//go:build windows

package collector

import (
	"syscall"
	"unsafe"
)

// Authenticode verification via WinVerifyTrust: first the embedded signature,
// then, for the many Windows binaries signed by a security catalog rather than
// in-file, a catalog lookup. Verification is offline — no revocation traffic —
// so it leaves no network footprint, at the cost of not detecting revoked
// certificates. Between the verify and close calls the signer is read from the
// verification state (WTHelperProvDataFromStateData → the first signer → its
// leaf certificate → CertGetNameStringW), so naming the signer costs no extra
// file access. All structs use natural Go alignment (no manual padding) and
// set cbStruct from unsafe.Sizeof, so the layout is correct on amd64, 386 and
// arm64 alike.

var (
	modWintrust = syscall.NewLazyDLL("wintrust.dll")
	modCrypt32  = syscall.NewLazyDLL("crypt32.dll")

	procWinVerifyTrust                  = modWintrust.NewProc("WinVerifyTrust")
	procCatAdminAcquireContext2         = modWintrust.NewProc("CryptCATAdminAcquireContext2")
	procCatAdminCalcHashFromFileHandle2 = modWintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCatAdminEnumCatalogFromHash     = modWintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCatCatalogInfoFromContext       = modWintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCatAdminReleaseCatalogContext   = modWintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCatAdminReleaseContext          = modWintrust.NewProc("CryptCATAdminReleaseContext")

	procWTHelperProvDataFromStateData  = modWintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain = modWintrust.NewProc("WTHelperGetProvSignerFromChain")
	procWTHelperGetProvCertFromChain   = modWintrust.NewProc("WTHelperGetProvCertFromChain")
	procCertGetNameStringW             = modCrypt32.NewProc("CertGetNameStringW")
)

// CERT_NAME_SIMPLE_DISPLAY_TYPE: the subject's common name (or the closest
// equivalent), as Explorer's "Digital Signatures" tab shows it.
const certNameSimpleDisplayType = 4

// maxSignerChars bounds the name buffer; real subjects are far shorter.
const maxSignerChars = 16384

// cryptProviderCert is the head of CRYPT_PROVIDER_CERT; only pCert is read.
type cryptProviderCert struct {
	cbStruct uint32
	pCert    uintptr // PCCERT_CONTEXT
}

type winGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// WINTRUST_ACTION_GENERIC_VERIFY_V2
var winTrustActionVerifyV2 = winGUID{0x00AAC56B, 0xCD44, 0x11D0, [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}

const (
	wtdUINone                = 2
	wtdRevokeNone            = 0
	wtdChoiceFile            = 1
	wtdChoiceCatalog         = 2
	wtdStateActionVerify     = 1
	wtdStateActionClose      = 2
	wtdSaferFlag             = 0x00000100
	wtdRevocationCheckNone   = 0x00000010
	wtdCacheOnlyURLRetrieval = 0x00001000
)

// WinVerifyTrust status codes we distinguish.
const (
	sTrustENoSignature        = 0x800B0100
	sTrustEBadDigest          = 0x80096010
	sTrustESubjectFormUnknown = 0x800B0003
	sTrustEProviderUnknown    = 0x800B0001
	sTrustEExplicitDistrust   = 0x800B0111
	sCertEExpired             = 0x800B0101
	sCertEUntrustedRoot       = 0x800B0109
	sCertEChaining            = 0x800B010A
	sCertERevoked             = 0x800B010C
)

var invalidHandleValue = ^uintptr(0)

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          syscall.Handle
	pgKnownSubject uintptr
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pInfo               uintptr // union: *wintrustFileInfo or *wintrustCatalogInfo
	dwStateAction       uint32
	hWVTStateData       uintptr
	pwszURLReference    uintptr
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

type catalogInfo struct {
	cbStruct       uint32
	wszCatalogFile [260]uint16
}

type wintrustCatalogInfo struct {
	cbStruct             uint32
	dwCatalogVersion     uint32
	pcwszCatalogFilePath *uint16
	pcwszMemberTag       *uint16
	pcwszMemberFilePath  *uint16
	hMemberFile          syscall.Handle
	pbCalculatedFileHash *byte
	cbCalculatedFileHash uint32
	pcCatalogContext     uintptr
	hCatAdmin            uintptr
}

func verifyAuthenticode(path string) SignatureResult {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return SignatureResult{State: SigError, Detail: err.Error()}
	}
	st, signer := winVerifyEmbedded(p)
	switch st {
	case 0:
		return SignatureResult{State: SigTrusted, Signer: signer}
	case sTrustENoSignature, sTrustESubjectFormUnknown, sTrustEProviderUnknown:
		// No usable embedded signature — the file may be catalog-signed.
		return verifyViaCatalog(path, p, st)
	default:
		// Signed, but it didn't validate: the signer is still worth naming.
		return SignatureResult{State: SigUntrusted, Signer: signer, Detail: trustStatusString(st)}
	}
}

func winVerifyEmbedded(path *uint16) (uint32, string) {
	fi := wintrustFileInfo{pcwszFilePath: path}
	fi.cbStruct = uint32(unsafe.Sizeof(fi))
	return winVerify(wtdChoiceFile, unsafe.Pointer(&fi))
}

// winVerify runs a verify/close pair against the generic-verify action and
// returns the verify call's status and the signer it recorded.
func winVerify(unionChoice uint32, info unsafe.Pointer) (uint32, string) {
	wd := wintrustData{
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice:       unionChoice,
		pInfo:               uintptr(info),
		dwStateAction:       wtdStateActionVerify,
		dwProvFlags:         wtdRevocationCheckNone | wtdCacheOnlyURLRetrieval | wtdSaferFlag,
	}
	wd.cbStruct = uint32(unsafe.Sizeof(wd))
	r, _, _ := procWinVerifyTrust.Call(invalidHandleValue,
		uintptr(unsafe.Pointer(&winTrustActionVerifyV2)), uintptr(unsafe.Pointer(&wd)))
	// The state holds the parsed signature whether or not it validated, so
	// read the signer now — the close call below frees it.
	signer := signerFromState(wd.hWVTStateData)
	// Always close to free the state data the verify call allocated.
	wd.dwStateAction = wtdStateActionClose
	procWinVerifyTrust.Call(invalidHandleValue,
		uintptr(unsafe.Pointer(&winTrustActionVerifyV2)), uintptr(unsafe.Pointer(&wd)))
	return uint32(r), signer
}

// signerFromState names the leaf certificate of the first signer recorded in
// a WinVerifyTrust state handle, or returns "" when there's none (no
// signature, or verification stopped before the signer was parsed). Every
// pointer it follows was allocated by wintrust and stays valid until the
// state is closed.
func signerFromState(state uintptr) string {
	if state == 0 || !signerAPIsPresent() {
		return ""
	}
	prov, _, _ := procWTHelperProvDataFromStateData.Call(state)
	if prov == 0 {
		return ""
	}
	// Signer 0, not a counter-signer (a counter-signature is the timestamp).
	sgnr, _, _ := procWTHelperGetProvSignerFromChain.Call(prov, 0, 0, 0)
	if sgnr == 0 {
		return ""
	}
	// Chain element 0 is the signing (leaf) certificate.
	cert, _, _ := procWTHelperGetProvCertFromChain.Call(sgnr, 0)
	if cert == 0 {
		return ""
	}
	// Reinterpret the returned address rather than convert a uintptr to a
	// Pointer: the memory belongs to wintrust, not the Go heap.
	pc := (*cryptProviderCert)(*(*unsafe.Pointer)(unsafe.Pointer(&cert)))
	if pc.pCert == 0 {
		return ""
	}
	return certDisplayName(pc.pCert)
}

// certDisplayName returns a certificate's simple display name, sanitized.
func certDisplayName(cert uintptr) string {
	// The first call sizes the name (characters, including the terminator); a
	// certificate with no usable name returns 1, the empty string.
	n, _, _ := procCertGetNameStringW.Call(cert, certNameSimpleDisplayType, 0, 0, 0, 0)
	if n <= 1 || n > maxSignerChars {
		return ""
	}
	buf := make([]uint16, n)
	got, _, _ := procCertGetNameStringW.Call(cert, certNameSimpleDisplayType, 0, 0,
		uintptr(unsafe.Pointer(&buf[0])), n)
	if got <= 1 || got > n {
		return ""
	}
	return cleanSignerName(syscall.UTF16ToString(buf[:got]))
}

// signerAPIsPresent reports whether the helpers that read the signer exist
// (they do on every supported Windows; this keeps a missing export from
// panicking a collection run).
func signerAPIsPresent() bool {
	for _, p := range [...]*syscall.LazyProc{
		procWTHelperProvDataFromStateData, procWTHelperGetProvSignerFromChain,
		procWTHelperGetProvCertFromChain, procCertGetNameStringW,
	} {
		if p.Find() != nil {
			return false
		}
	}
	return true
}

// verifyViaCatalog hashes the file, finds the security catalog that vouches for
// that hash, and verifies against it. An API failure yields SigError (so we
// never call a catalog-signed binary "unsigned" because the check broke); only
// a confirmed absence of any catalog entry yields SigUnsigned.
func verifyViaCatalog(path string, pathPtr *uint16, embeddedStatus uint32) SignatureResult {
	if procCatAdminAcquireContext2.Find() != nil {
		return SignatureResult{State: SigError, Detail: "security-catalog API unavailable"}
	}
	var hCatAdmin uintptr
	algo, _ := syscall.UTF16PtrFromString("SHA256")
	if r, _, _ := procCatAdminAcquireContext2.Call(
		uintptr(unsafe.Pointer(&hCatAdmin)), 0, uintptr(unsafe.Pointer(algo)), 0, 0); r == 0 {
		return SignatureResult{State: SigError, Detail: "CryptCATAdminAcquireContext2 failed"}
	}
	defer procCatAdminReleaseContext.Call(hCatAdmin, 0)

	h, err := syscall.CreateFile(pathPtr, cGenericRead,
		cShareRead|cShareWrite|cShareDelete, nil, cOpenExisting, 0, 0)
	if err != nil {
		return SignatureResult{State: SigError, Detail: "open for hashing: " + err.Error()}
	}
	defer syscall.CloseHandle(h)

	var cbHash uint32
	procCatAdminCalcHashFromFileHandle2.Call(hCatAdmin, uintptr(h), uintptr(unsafe.Pointer(&cbHash)), 0, 0)
	if cbHash == 0 || cbHash > 1024 {
		return SignatureResult{State: SigError, Detail: "catalog hash sizing failed"}
	}
	hash := make([]byte, cbHash)
	_, _ = syscall.Seek(h, 0, 0) // rewind: the sizing call may have advanced the pointer
	if r, _, _ := procCatAdminCalcHashFromFileHandle2.Call(
		hCatAdmin, uintptr(h), uintptr(unsafe.Pointer(&cbHash)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 {
		return SignatureResult{State: SigError, Detail: "catalog hash failed"}
	}

	hCatInfo, _, _ := procCatAdminEnumCatalogFromHash.Call(
		hCatAdmin, uintptr(unsafe.Pointer(&hash[0])), uintptr(cbHash), 0, 0)
	if hCatInfo == 0 {
		// No catalog vouches for this hash, and there was no embedded
		// signature: the file is genuinely unsigned.
		_ = embeddedStatus
		return SignatureResult{State: SigUnsigned}
	}
	defer procCatAdminReleaseCatalogContext.Call(hCatAdmin, hCatInfo, 0)

	var ci catalogInfo
	ci.cbStruct = uint32(unsafe.Sizeof(ci))
	if r, _, _ := procCatCatalogInfoFromContext.Call(hCatInfo, uintptr(unsafe.Pointer(&ci)), 0); r == 0 {
		return SignatureResult{State: SigError, Detail: "catalog info unavailable"}
	}

	tag, err := syscall.UTF16PtrFromString(hexUpper(hash))
	if err != nil {
		return SignatureResult{State: SigError, Detail: err.Error()}
	}
	wci := wintrustCatalogInfo{
		pcwszCatalogFilePath: &ci.wszCatalogFile[0],
		pcwszMemberTag:       tag,
		pcwszMemberFilePath:  pathPtr,
		hMemberFile:          h,
		pbCalculatedFileHash: &hash[0],
		cbCalculatedFileHash: cbHash,
		hCatAdmin:            hCatAdmin,
	}
	wci.cbStruct = uint32(unsafe.Sizeof(wci))
	// For a catalog-signed file the signer is the catalog's (on a Windows
	// binary, "Microsoft Windows").
	st, signer := winVerify(wtdChoiceCatalog, unsafe.Pointer(&wci))
	if st == 0 {
		return SignatureResult{State: SigTrusted, Catalog: true, Signer: signer}
	}
	return SignatureResult{State: SigUntrusted, Catalog: true, Signer: signer, Detail: trustStatusString(st)}
}

func hexUpper(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[2*i] = digits[c>>4]
		out[2*i+1] = digits[c&0xf]
	}
	return string(out)
}

func trustStatusString(st uint32) string {
	switch st {
	case sTrustENoSignature:
		return "no signature"
	case sTrustEBadDigest:
		return "file digest does not match the signature (tampered)"
	case sCertEExpired:
		return "signing certificate expired"
	case sCertEUntrustedRoot:
		return "signature chains to an untrusted root"
	case sCertEChaining:
		return "signature chain could not be built"
	case sCertERevoked:
		return "signing certificate revoked"
	case sTrustEExplicitDistrust:
		return "signature is explicitly distrusted"
	case sTrustESubjectFormUnknown, sTrustEProviderUnknown:
		return "file type not supported for signature verification"
	default:
		return trustStatusHex(st)
	}
}

func trustStatusHex(st uint32) string {
	const digits = "0123456789abcdef"
	var b [10]byte
	b[0], b[1] = '0', 'x'
	for i := 0; i < 8; i++ {
		b[2+i] = digits[(st>>uint(28-4*i))&0xf]
	}
	return "status " + string(b[:])
}
