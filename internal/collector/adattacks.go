package collector

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// adattacks.go — attacks on Active Directory, read from the logs of the
// servers that see them: a domain controller's Security log (directory access
// and changes, Kerberos ticket requests), its System log (the KDC's
// certificate-mapping errors) and a certificate authority's Security log
// (certificate requests and templates). Portable like the rest of the event
// analytics, so offline triage of a DC's exported logs gets the same findings.
//
// The events need their audit policies. Domain controllers audit Kerberos and
// directory access out of the box; directory changes (5136, "Audit Directory
// Service Changes") and Certificate Services (4886-4899, the CA's AuditFilter)
// have to be switched on.

// Replication extended rights, the control-access rights a domain controller
// holds on the domain to replicate it.
const (
	rightGetChanges         = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	rightGetChangesAll      = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	rightGetChangesFiltered = "89e95b76-444d-4c62-991a-0facbeda640c"
	rightInstallReplica     = "9923a32a-3607-11d2-b9be-0000f87a36b2"
)

// replicationRights in the order they are reported. secrets marks the rights
// that return password hashes.
var replicationRights = []struct {
	guid, name string
	secrets    bool
}{
	{rightGetChangesAll, "DS-Replication-Get-Changes-All", true},
	{rightGetChangesFiltered, "DS-Replication-Get-Changes-In-Filtered-Set", true},
	{rightGetChanges, "DS-Replication-Get-Changes", false},
	{rightInstallReplica, "DS-Install-Replica", false},
}

// Certificate enrollment extended rights on a certificate template.
const (
	rightEnroll     = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	rightAutoEnroll = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
)

// domainDNSClass is the schema GUID of the domain object (domainDNS), which a
// 4662 names as its object type.
const domainDNSClass = "19195a5b-6da0-11d0-afd3-00c04fd930c9"

// drsuapiSPN is the replication (DRSUAPI) interface a domain controller
// registers as a service principal name, as DCShadow does for its rogue DC.
const drsuapiSPN = "E3514235-4B06-11D1-AB04-00C04FC2DCD2/"

// authEKUs are the extended key usages that let a certificate log on.
var authEKUs = []struct{ oid, name string }{
	{"1.3.6.1.5.5.7.3.2", "Client Authentication"},
	{"1.3.6.1.5.2.3.4", "PKINIT Client Authentication"},
	{"1.3.6.1.4.1.311.20.2.2", "Smart Card Logon"},
	{"2.5.29.37.0", "Any Purpose"},
}

// directoryAccessFindings judges a directory-service access check (4662):
// replication rights exercised by an account that isn't a domain controller
// (DCSync), the domain's DPAPI backup key read, the domain object opened to
// rewrite its permissions, and a DNS record name built to reflect
// authentication.
func directoryAccessFindings(ev winEvent) []Finding {
	var out []Finding
	if f, ok := dcsyncFinding(ev); ok {
		out = append(out, f)
	}
	if f, ok := backupKeyFinding(ev); ok {
		out = append(out, f)
	}
	if f, ok := domainDACLFinding(ev); ok {
		out = append(out, f)
	}
	if f, ok := reflectionRecordFinding(ev, evData(ev, "AdditionalInfo")); ok {
		out = append(out, f)
	}
	return out
}

// directoryInfrastructure reports whether the subject of a directory event
// is a party that replicates or acts as the directory itself: a computer
// account (domain controllers replicate as their NAME$), the system, the
// Window Manager virtual accounts, or Azure AD Connect's MSOL_ connector
// account, which replicates password hashes to Entra ID by design.
func directoryInfrastructure(ev winEvent) bool {
	user := strings.TrimSpace(evData(ev, "SubjectUserName"))
	upper := strings.ToUpper(user)
	switch {
	case strings.HasSuffix(user, "$"),
		strings.HasPrefix(upper, "MSOL_"),
		strings.HasPrefix(upper, "NT AUT"),
		strings.EqualFold(evData(ev, "SubjectDomainName"), "Window Manager"):
		return true
	}
	switch evData(ev, "SubjectUserSid") {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return true
	}
	return false
}

// subjectOf names the account behind a directory event for a detail line.
func subjectOf(ev winEvent) string {
	u := evData(ev, "SubjectUserName")
	if u == "" {
		return firstNonEmpty(ev.SecurityUser, "an account")
	}
	if d := evData(ev, "SubjectDomainName"); d != "" {
		return d + "\\" + u
	}
	return u
}

// dcsyncFinding: replication rights checked for an account that isn't a
// domain controller. Get-Changes-All (or the RODC filtered set) returns
// password hashes; Get-Changes alone is also what directory-sync products
// hold to follow changes.
func dcsyncFinding(ev winEvent) (Finding, bool) {
	props := strings.ToLower(evData(ev, "Properties"))
	if props == "" {
		return Finding{}, false
	}
	var names []string
	secrets := false
	for _, r := range replicationRights {
		if strings.Contains(props, r.guid) {
			names = append(names, r.name)
			secrets = secrets || r.secrets
		}
	}
	if len(names) == 0 || directoryInfrastructure(ev) {
		return Finding{}, false
	}
	if secrets {
		return Finding{Rule: "cred.dcsync", Severity: SevCritical, Technique: "T1003.006", Confidence: 80,
			Detail: fmt.Sprintf("%s used %s on the domain%s: the rights domain controllers replicate with, which return every "+
				"account's password hash, krbtgt's included. Only domain controllers and Azure AD Connect's MSOL_ account replicate; "+
				"any other account doing it is DCSync (Mimikatz lsadump::dcsync, Impacket secretsdump)",
				subjectOf(ev), strings.Join(names, " and "), onComputer(ev))}, true
	}
	return Finding{Rule: "cred.dcsync", Severity: SevSuspect, Technique: "T1003.006", Confidence: 55,
		Detail: fmt.Sprintf("%s used %s on the domain%s. These replication rights don't return passwords on their own "+
			"(directory-sync products hold them to follow changes), but DCSync starts with them; look for "+
			"DS-Replication-Get-Changes-All from the same account", subjectOf(ev), strings.Join(names, " and "), onComputer(ev))}, true
}

// onComputer says which domain controller logged an event.
func onComputer(ev winEvent) string {
	if ev.Computer == "" {
		return ""
	}
	return " (logged by " + ev.Computer + ")"
}

// parseMask reads an access mask as an event gives it ("0x40000").
func parseMask(s string) uint64 {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "0x") {
		v, _ := strconv.ParseUint(s[2:], 16, 64)
		return v
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// backupKeyFinding: the domain's DPAPI backup key, the LSA secret
// BCKUPKEY_*, read by an account other than the system. It decrypts every
// domain user's DPAPI master keys and is never rotated.
func backupKeyFinding(ev winEvent) (Finding, bool) {
	name := evData(ev, "ObjectName")
	if !strings.EqualFold(strings.TrimSpace(evData(ev, "ObjectType")), "SecretObject") ||
		!strings.Contains(strings.ToUpper(name), "BCKUPKEY") || parseMask(evData(ev, "AccessMask"))&0x2 == 0 ||
		directoryInfrastructure(ev) {
		return Finding{}, false
	}
	return Finding{Rule: "cred.dpapi_backup_key", Severity: SevCritical, Technique: "T1003.004", Confidence: 80,
		Detail: fmt.Sprintf("%s read the domain's DPAPI backup key (%s)%s. It decrypts every domain user's DPAPI master keys, "+
			"and with them saved passwords, browser cookies and certificate private keys, and it is never rotated "+
			"(Mimikatz lsadump::backupkeys, SharpDPAPI backupkey)", subjectOf(ev), excerpt(name, 120), onComputer(ev))}, true
}

// domainDACLFinding: the domain object opened with WRITE_DAC, to rewrite who
// may do what to the domain. That is how a relayed or stolen account grants
// itself DCSync (ntlmrelayx --escalate-user, PrivExchange, Add-DomainObjectAcl);
// an administrator delegating rights does the same, rarely.
func domainDACLFinding(ev winEvent) (Finding, bool) {
	if !strings.EqualFold(strings.TrimSpace(evData(ev, "ObjectServer")), "DS") {
		return Finding{}, false
	}
	ot := strings.ToLower(evData(ev, "ObjectType"))
	if !strings.Contains(ot, domainDNSClass) && strings.Trim(ot, "%{} ") != "domaindns" {
		return Finding{}, false
	}
	if parseMask(evData(ev, "AccessMask"))&0x40000 == 0 {
		return Finding{}, false
	}
	switch evData(ev, "SubjectUserSid") {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return Finding{}, false
	}
	return Finding{Rule: "persistence.domain_acl_changed", Severity: SevSuspect, Technique: "T1098", Confidence: 60,
		Detail: fmt.Sprintf("%s opened the domain object to change its permissions (WRITE_DAC)%s. That is how a relayed or "+
			"stolen account grants itself replication rights for DCSync (ntlmrelayx --escalate-user, PrivExchange, "+
			"Add-DomainObjectAcl); an administrator delegating rights looks the same. The directory change that follows "+
			"(5136, if audited) shows what was granted", subjectOf(ev), onComputer(ev))}, true
}

// reflectionRecordFinding: a DNS record whose name carries a marshalled
// CREDENTIAL_TARGET_INFORMATION blob ("…1UWhRCAAAAA…BAAAA"). Windows' SMB
// client strips that blob when it builds the server's name, so a host made to
// connect to the record authenticates as if to itself, and the attacker
// relays that back to it (Kerberos and NTLM reflection, CVE-2025-33073). The
// blob is case-sensitive base64, so the markers are matched exactly.
func reflectionRecordFinding(ev winEvent, name string) (Finding, bool) {
	if !strings.Contains(name, "UWhRCA") || !strings.Contains(name, "BAAAA") ||
		!strings.Contains(strings.ToUpper(name), "CN=MICROSOFTDNS") {
		return Finding{}, false
	}
	return Finding{Rule: "privesc.reflection_dns_record", Severity: SevCritical, Technique: "T1187", Confidence: 80,
		Detail: fmt.Sprintf("a DNS record whose name carries a marshalled target-information blob was written to "+
			"AD-integrated DNS%s: %s. A host coerced into connecting to that name authenticates as if to itself, which an "+
			"attacker relays back to the host as SYSTEM (Kerberos and NTLM reflection, CVE-2025-33073)",
			whoBy(ev), excerpt(name, 200))}, true
}

// valueAdded reports whether a 5136 added a value (a modification is logged
// as the old value deleted and the new one added).
func valueAdded(op string) bool {
	op = strings.TrimSpace(op)
	return op == "%%14674" || strings.EqualFold(op, "Value Added")
}

// directoryChangeFindings judges a directory object change (5136) or
// creation (5137): credentials, delegation and SPNs written to accounts,
// replication rights granted on the domain, AdminSDHolder's permissions, and
// DNS records named for reflection.
func directoryChangeFindings(ev winEvent) []Finding {
	dn := evData(ev, "ObjectDN")
	class := strings.ToLower(strings.TrimSpace(evData(ev, "ObjectClass")))
	if class == "dnsnode" {
		if f, ok := reflectionRecordFinding(ev, dn); ok {
			return []Finding{f}
		}
	}
	if ev.EventID != 5136 || !valueAdded(evData(ev, "OperationType")) {
		return nil
	}
	val := evData(ev, "AttributeValue")
	switch strings.ToLower(strings.TrimSpace(evData(ev, "AttributeLDAPDisplayName"))) {
	case "msds-keycredentiallink":
		return shadowCredentialFindings(ev, dn)
	case "msds-allowedtoactonbehalfofotheridentity":
		granted := ""
		if t := aceTrustees(val); len(t) > 0 {
			granted = " to " + strings.Join(t, ", ")
		}
		return []Finding{{Rule: "privesc.rbcd_configured", Severity: SevSuspect, Technique: "T1098", Confidence: 70,
			Detail: fmt.Sprintf("resource-based constrained delegation was granted%s on %s%s "+
				"(msDS-AllowedToActOnBehalfOfOtherIdentity): those accounts can now get Kerberos tickets to that computer as any "+
				"user, administrators included (S4U). Intruders set it through a relayed or writable computer account "+
				"(ntlmrelayx --delegate-access, rbcd.py, Rubeus s4u)", granted, excerpt(dn, 160), whoBy(ev))}}
	case "msds-allowedtodelegateto":
		return []Finding{constrainedDelegationFinding(ev, dn, val)}
	case "serviceprincipalname":
		return spnFindings(ev, dn, class, val)
	case "ntsecuritydescriptor":
		return securityDescriptorFindings(ev, dn, class, val)
	}
	return nil
}

// shadowCredentialFindings: a key credential added to an account. Whoever
// holds the matching private key can get a Kerberos ticket, and the NT hash,
// as that account without its password. Azure AD Connect writes Windows Hello
// for Business keys (skipped); a computer adding a key to its own account is
// how device registration works, and also how a relayed computer account is
// turned into shadow credentials (kept, as notable).
func shadowCredentialFindings(ev winEvent, dn string) []Finding {
	subject := strings.TrimSpace(evData(ev, "SubjectUserName"))
	if strings.HasPrefix(strings.ToUpper(subject), "MSOL_") {
		return nil
	}
	f := Finding{Rule: "cred.shadow_credentials", Severity: SevSuspect, Technique: "T1556", Confidence: 75,
		Detail: fmt.Sprintf("a key credential was added to %s%s (msDS-KeyCredentialLink): whoever holds the matching private key "+
			"can now get a Kerberos ticket, and the NT hash, as that account without its password (shadow credentials: "+
			"Whisker, pyWhisker, Certipy shadow). Windows Hello for Business provisioning writes this attribute too",
			excerpt(dn, 160), whoBy(ev))}
	if strings.HasSuffix(subject, "$") && strings.HasPrefix(strings.ToUpper(dn), "CN="+strings.ToUpper(strings.TrimSuffix(subject, "$"))+",") {
		f.Severity, f.Confidence = SevNotable, 40
		f.Detail = fmt.Sprintf("the computer %s added a key credential to its own account (msDS-KeyCredentialLink, %s). Device "+
			"registration does this; it is also what an NTLM relay of the computer account to LDAP leaves behind when the "+
			"intruder turns it into shadow credentials (ntlmrelayx --shadow-credentials)", subject, excerpt(dn, 160))
	}
	return []Finding{f}
}

// constrainedDelegationFinding: services added to an account's constrained
// delegation list (5136 msDS-AllowedToDelegateTo, or 4738/4742's
// AllowedToDelegateTo). The account can then get tickets to those services as
// any user.
func constrainedDelegationFinding(ev winEvent, account, services string) Finding {
	return Finding{Rule: "privesc.constrained_delegation_configured", Severity: SevSuspect, Technique: "T1098", Confidence: 55,
		Detail: fmt.Sprintf("constrained delegation to %s was granted to %s%s: that account can now get tickets to those services "+
			"as any user, administrators included. An intruder who controls an account sets it to reach a server as its "+
			"administrators; administrators set it for multi-tier applications", excerpt(services, 160), excerpt(account, 160), whoBy(ev))}
}

// spnFindings: a service principal name added. A domain controller's
// replication or global-catalog SPN on a computer outside the Domain
// Controllers OU is DCShadow registering a rogue DC; any SPN on a user account
// makes it Kerberoastable (an intruder with write access adds one to roast a
// chosen user).
func spnFindings(ev winEvent, dn, class, spn string) []Finding {
	upper := strings.ToUpper(strings.TrimSpace(spn))
	if strings.HasPrefix(upper, "GC/") || strings.HasPrefix(upper, drsuapiSPN) {
		if strings.Contains(strings.ToUpper(dn), "OU=DOMAIN CONTROLLERS,") {
			return nil
		}
		return []Finding{{Rule: "defense.dcshadow", Severity: SevSuspect, Technique: "T1207", Confidence: 60,
			Detail: fmt.Sprintf("a domain controller's service principal name (%s) was added to %s%s, which isn't in the Domain "+
				"Controllers OU. Outside a DC promotion that is DCShadow (Mimikatz lsadump::dcshadow) registering a rogue domain "+
				"controller to push changes into the directory without the usual audit trail", excerpt(spn, 120), excerpt(dn, 160), whoBy(ev))}}
	}
	if class != "user" {
		return nil
	}
	return []Finding{{Rule: "cred.spn_added_to_user", Severity: SevNotable, Technique: "T1558.003", Confidence: 45,
		Detail: fmt.Sprintf("the service principal name %q was added to the user account %s%s: any domain user can now ask for a "+
			"ticket encrypted with that account's password and crack it offline. Administrators add SPNs to service accounts; "+
			"an intruder with write access adds one to roast a chosen user (targeted Kerberoasting)", excerpt(spn, 120), excerpt(dn, 160), whoBy(ev))}}
}

// securityDescriptorFindings: a new security descriptor on AdminSDHolder
// (SDProp copies it onto every protected account and group within the hour,
// so an entry added there keeps coming back), or one on the domain object that
// grants replication rights to an account that isn't a domain controller or
// an administrators group (a DCSync backdoor).
func securityDescriptorFindings(ev winEvent, dn, class, sddl string) []Finding {
	if strings.HasPrefix(strings.ToUpper(dn), "CN=ADMINSDHOLDER,CN=SYSTEM,") {
		f := Finding{Rule: "persistence.adminsdholder_modified", Severity: SevSuspect, Technique: "T1098", Confidence: 70,
			Detail: fmt.Sprintf("the permissions on AdminSDHolder were changed%s. Every hour SDProp copies them onto the protected "+
				"accounts and groups (Domain Admins, Administrators, krbtgt and the rest), so an entry added here returns on all of "+
				"them however often it is removed", whoBy(ev))}
		if custom := customTrustees(sddl); len(custom) > 0 {
			f.Confidence = 80
			f.Detail += "; it now grants rights to " + strings.Join(custom, ", ") + ", accounts outside the built-in groups"
		}
		return []Finding{f}
	}
	if class != "domaindns" && !(class == "" && domainRootDN(dn)) {
		return nil
	}
	grants := replicationGrants(sddl)
	if len(grants) == 0 {
		return nil
	}
	return []Finding{{Rule: "persistence.dcsync_rights_granted", Severity: SevCritical, Technique: "T1098", Confidence: 80,
		Detail: fmt.Sprintf("the domain's permissions were changed%s and now give replication rights to %s, which isn't a domain "+
			"controller or an administrators group: that account can DCSync every password hash whenever it likes. "+
			"Azure AD Connect's MSOL_ account legitimately holds these rights", whoBy(ev), strings.Join(grants, "; "))}}
}

// domainRootDN reports whether a DN names a domain object (only DC= parts).
func domainRootDN(dn string) bool {
	if dn == "" {
		return false
	}
	for _, rdn := range strings.Split(dn, ",") {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(rdn)), "DC=") {
			return false
		}
	}
	return true
}

// sddlACE is one access-control entry of an SDDL string.
type sddlACE struct {
	kind, flags, rights, object, trustee string
}

// allows reports whether the entry grants (not denies or audits) access.
func (a sddlACE) allows() bool {
	switch a.kind {
	case "A", "OA", "XA", "ZA":
		return true
	}
	return false
}

// hasRight reports whether the entry's rights include a two-letter SDDL right
// (CR, GA, …) or, for a numeric mask, the matching bit.
func (a sddlACE) hasRight(right string) bool {
	if strings.HasPrefix(strings.ToLower(a.rights), "0x") {
		m := parseMask(a.rights)
		switch right {
		case "CR":
			return m&0x100 != 0
		case "GA":
			return m&0x10000000 != 0
		}
		return false
	}
	return sddlToken(a.rights, right)
}

// inheritOnly reports whether the entry applies only to child objects.
func (a sddlACE) inheritOnly() bool { return sddlToken(a.flags, "IO") }

// sddlToken reports whether a run of two-letter SDDL tokens ("CIIO",
// "RPWPCR…") holds tok, reading it in pairs so "CIOI" doesn't hold "IO".
func sddlToken(s, tok string) bool {
	for i := 0; i+1 < len(s); i += 2 {
		if s[i:i+2] == tok {
			return true
		}
	}
	return false
}

// sddlACEs parses the entries of an SDDL string, DACL and SACL alike; callers
// keep the kinds they care about.
func sddlACEs(sddl string) []sddlACE {
	var out []sddlACE
	for {
		open := strings.IndexByte(sddl, '(')
		if open < 0 {
			return out
		}
		end := strings.IndexByte(sddl[open:], ')')
		if end < 0 {
			return out
		}
		parts := strings.Split(sddl[open+1:open+end], ";")
		sddl = sddl[open+end+1:]
		if len(parts) < 6 {
			continue
		}
		out = append(out, sddlACE{
			kind:    strings.ToUpper(strings.TrimSpace(parts[0])),
			flags:   strings.ToUpper(strings.TrimSpace(parts[1])),
			rights:  strings.ToUpper(strings.TrimSpace(parts[2])),
			object:  strings.ToLower(strings.TrimSpace(parts[3])),
			trustee: strings.TrimSpace(parts[5]),
		})
	}
}

// sidRID returns the last sub-authority of a domain SID (S-1-5-21-…-RID).
func sidRID(sid string) (uint64, bool) {
	if !strings.HasPrefix(strings.ToUpper(sid), "S-1-5-21-") {
		return 0, false
	}
	i := strings.LastIndexByte(sid, '-')
	rid, err := strconv.ParseUint(sid[i+1:], 10, 32)
	return rid, err == nil
}

// defaultReplicator reports whether a trustee holds replication rights on a
// domain by default: the domain controller groups, the administrators groups,
// and the system.
func defaultReplicator(trustee string) bool {
	switch strings.ToUpper(trustee) {
	case "BA", "DA", "EA", "DD", "ED", "RO", "SY", "S-1-5-9", "S-1-5-18", "S-1-5-32-544":
		return true
	}
	if rid, ok := sidRID(trustee); ok {
		switch rid {
		case 498, 512, 516, 519, 521: // Enterprise RODCs, Domain Admins, DCs, Enterprise Admins, RODCs
			return true
		}
	}
	return false
}

// replicationGrants lists the entries of a domain's security descriptor that
// give replication rights (or every extended right) to a trustee that doesn't
// have them by default.
func replicationGrants(sddl string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range sddlACEs(sddl) {
		if !a.allows() || a.inheritOnly() || defaultReplicator(a.trustee) {
			continue
		}
		what := ""
		switch {
		case a.object == "" && (a.hasRight("CR") || a.hasRight("GA")):
			what = "every extended right, replication included"
		case a.hasRight("CR"):
			for _, r := range replicationRights[:3] {
				if a.object == r.guid {
					what = r.name
				}
			}
		}
		if what == "" {
			continue
		}
		g := a.trustee + " (" + what + ")"
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

// customTrustees lists the accounts (domain SIDs with a RID of 1000 or more,
// i.e. not built-in groups) that an SDDL string grants anything to.
func customTrustees(sddl string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range sddlACEs(sddl) {
		if !a.allows() {
			continue
		}
		if rid, ok := sidRID(a.trustee); ok && rid >= 1000 && !seen[a.trustee] {
			seen[a.trustee] = true
			out = append(out, a.trustee)
		}
	}
	return out
}

// aceTrustees lists every trustee an SDDL string grants access to.
func aceTrustees(sddl string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range sddlACEs(sddl) {
		if a.allows() && a.trustee != "" && !seen[a.trustee] {
			seen[a.trustee] = true
			out = append(out, a.trustee)
		}
	}
	return out
}

// broadTrusteeNames names the SDDL aliases and well-known SIDs that mean
// "most of the domain".
var broadTrusteeNames = map[string]string{
	"DU": "Domain Users", "AU": "Authenticated Users", "WD": "Everyone", "DC": "Domain Computers",
	"S-1-5-11": "Authenticated Users", "S-1-1-0": "Everyone",
}

// broadEnrollers names the large groups a template's security descriptor
// lets enroll (or control the template outright).
func broadEnrollers(sddl string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range sddlACEs(sddl) {
		if !a.allows() {
			continue
		}
		name := broadTrusteeNames[strings.ToUpper(a.trustee)]
		if rid, ok := sidRID(a.trustee); ok {
			switch rid {
			case 513:
				name = "Domain Users"
			case 515:
				name = "Domain Computers"
			}
		}
		if name == "" || seen[name] {
			continue
		}
		enroll := a.hasRight("GA") || (a.hasRight("CR") && (a.object == "" || a.object == rightEnroll || a.object == rightAutoEnroll))
		if enroll {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// noValue reports whether an event field holds nothing: empty, "-", or the
// "<value not set>" message insert.
func noValue(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || s == "-" || s == "%%1793"
}

// privilegedRIDs are the RIDs of the accounts and groups whose SID in an
// account's SID history makes it a domain administrator.
var privilegedRIDs = map[uint64]string{500: "Administrator", 512: "Domain Admins", 518: "Schema Admins", 519: "Enterprise Admins"}

// sidHistoryFinding: SIDs added to an account's SID history (4765, 4738,
// 4742), which gives it every right those SIDs have.
func sidHistoryFinding(ev winEvent, account, sids string) Finding {
	f := Finding{Rule: "persistence.sid_history_added", Severity: SevSuspect, Technique: "T1134.005", Confidence: 70,
		Detail: fmt.Sprintf("SID history %s was added to %s%s: the account now carries those SIDs' rights. Domain migrations "+
			"use SID history; outside one it is a hidden-privilege backdoor (Mimikatz sid::add, DSInternals)",
			excerpt(sids, 200), excerpt(account, 120), whoBy(ev))}
	for _, sid := range sidPattern.FindAllString(sids, -1) {
		if rid, ok := sidRID(sid); ok && privilegedRIDs[rid] != "" {
			f.Severity, f.Confidence = SevCritical, 85
			f.Detail += fmt.Sprintf(" — %s is %s, so the account is now one", sid, privilegedRIDs[rid])
			break
		}
	}
	if s := strings.ToUpper(sids); strings.Contains(s, "S-1-5-32-544") && f.Severity != SevCritical {
		f.Severity, f.Confidence = SevCritical, 85
		f.Detail += " — S-1-5-32-544 is the Administrators group"
	}
	return f
}

// sidPattern matches a domain account's SID.
var sidPattern = regexp.MustCompile(`S-1-5-21-\d+-\d+-\d+-\d+`)

// accountChangeFindings judges a changed user (4738) or computer (4742)
// account: SID history and constrained delegation written to it.
func accountChangeFindings(ev winEvent) []Finding {
	account := logonUser(ev)
	var out []Finding
	if v := evData(ev, "SidHistory"); !noValue(v) {
		out = append(out, sidHistoryFinding(ev, account, v))
	}
	if v := evData(ev, "AllowedToDelegateTo"); !noValue(v) {
		out = append(out, constrainedDelegationFinding(ev, account, v))
	}
	return out
}

// sidHistoryEventFindings judges 4765 (SID history added to an account) and
// 4766 (an attempt failed).
func sidHistoryEventFindings(ev winEvent) []Finding {
	account := logonUser(ev)
	sids := firstNonEmpty(strings.TrimSpace(strings.Trim(evData(ev, "SidList"), "{}")), evData(ev, "SourceSid"), "(unrecorded)")
	if ev.EventID == 4766 {
		return []Finding{{Rule: "persistence.sid_history_added", Severity: SevNotable, Technique: "T1134.005", Confidence: 50,
			Detail: fmt.Sprintf("an attempt to add SID history %s to %s failed%s", excerpt(sids, 200), account, whoBy(ev))}}
	}
	return []Finding{sidHistoryFinding(ev, account, sids)}
}

// dsrmFindings: the Directory Services Restore Mode password set (4794). DSRM
// is a domain controller's local administrator; with
// Lsa\DsrmAdminLogonBehavior = 2 it logs on over the network.
func dsrmFindings(ev winEvent) []Finding {
	status := strings.TrimSpace(evData(ev, "Status"))
	f := Finding{Rule: "persistence.dsrm_password_set", Severity: SevSuspect, Technique: "T1098", Confidence: 60,
		Detail: "the Directory Services Restore Mode administrator password was set" + whoBy(ev) + onComputer(ev) + ". DSRM is a " +
			"domain controller's local administrator; with Lsa\\DsrmAdminLogonBehavior = 2 it logs on over the network, a known " +
			"way to keep administrator access to a DC. Expected when a DC is installed or the password is rotated"}
	if status != "" && parseMask(status) != 0 {
		f.Severity, f.Confidence = SevNotable, 40
		f.Detail = fmt.Sprintf("an attempt to set the Directory Services Restore Mode password failed (status %s)%s%s",
			status, whoBy(ev), onComputer(ev))
	}
	return []Finding{f}
}

// kerberosOK reports whether a Kerberos event's Status is success.
func kerberosOK(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && s != "-" && parseMask(s) == 0
}

// rc4 reports whether a ticket encryption type is RC4 (0x17, or 0x18 export).
func rc4(etype string) bool {
	switch parseMask(etype) {
	case 0x17, 0x18:
		return true
	}
	return false
}

// clientAddress trims the IPv4-mapped prefix Kerberos events give addresses.
func clientAddress(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "::ffff:")
}

// tgtRequestFindings judges a Kerberos TGT request (4768): one issued without
// pre-authentication (AS-REP roastable), and a computer account logging on
// with a certificate (how a relayed DC certificate is used).
func tgtRequestFindings(ev winEvent) []Finding {
	if !kerberosOK(evData(ev, "Status")) {
		return nil
	}
	account := logonUser(ev)
	addr := firstNonEmpty(clientAddress(evData(ev, "IpAddress")), "an unrecorded address")
	var out []Finding
	if strings.TrimSpace(evData(ev, "PreAuthType")) == "0" {
		f := Finding{Rule: "cred.asrep_roasting", Severity: SevNotable, Technique: "T1558.004", Confidence: 40,
			Detail: fmt.Sprintf("a Kerberos ticket for %s was issued without pre-authentication (request from %s): the account has "+
				"\"Do not require Kerberos preauthentication\" set, so anyone can ask for its AS-REP and crack the password out of it",
				account, addr)}
		if rc4(evData(ev, "TicketEncryptionType")) {
			f.Severity, f.Confidence = SevSuspect, 65
			f.Detail += ". The reply was RC4-encrypted, which is what AS-REP roasting tools ask for (Rubeus asreproast, Impacket GetNPUsers)"
		}
		out = append(out, f)
	}
	if thumb := evData(ev, "CertThumbprint"); strings.HasSuffix(evData(ev, "TargetUserName"), "$") && !noValue(thumb) {
		if a := clientAddress(evData(ev, "IpAddress")); a != "::1" && a != "127.0.0.1" {
			out = append(out, Finding{Rule: "cred.computer_certificate_logon", Severity: SevSuspect, Technique: "T1649", Confidence: 60,
				Detail: fmt.Sprintf("the computer account %s got a Kerberos ticket with a certificate (PKINIT; issuer %s) from %s. "+
					"Computers normally log on with their password; a certificate logon as a computer, above all a domain "+
					"controller, is how a certificate obtained by relaying it to AD CS web enrollment is used (PetitPotam + ESC8, "+
					"Certipy auth)", account, firstNonEmpty(evData(ev, "CertIssuerName"), "unrecorded"), addr)})
		}
	}
	return out
}

// isKDC reports whether an event comes from the Kerberos Key Distribution
// Center (Kernel-Power also writes a 41).
func isKDC(ev winEvent) bool {
	p := strings.ToLower(ev.Provider)
	return strings.Contains(p, "kerberos-key-distribution-center") || p == "kdc"
}

// kdcCertificateFindings judges the KDC's event 41: a certificate logon
// refused because the SID in the certificate isn't the SID of the account the
// certificate maps to. The certificate names one account and was issued to
// another: a certificate requested for someone else (ESC1/ESC6-style abuse)
// meeting the SID the CA stamps in. (Windows Server 2008 R2 used 41 for an
// unmapped certificate; that version names one SID at most and is skipped.)
func kdcCertificateFindings(ev winEvent) []Finding {
	var sids []string
	seen := map[string]bool{}
	add := func(s string) {
		for _, sid := range sidPattern.FindAllString(s, -1) {
			if !seen[strings.ToUpper(sid)] {
				seen[strings.ToUpper(sid)] = true
				sids = append(sids, sid)
			}
		}
	}
	keys := make([]string, 0, len(ev.Data))
	for k := range ev.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var named []string
	for _, k := range keys {
		add(ev.Data[k])
		if v := strings.TrimSpace(ev.Data[k]); v != "" {
			named = append(named, k+"="+v)
		}
	}
	for _, v := range ev.DataList {
		add(v)
	}
	if len(sids) < 2 {
		return nil
	}
	fields := strings.Join(named, "; ")
	if fields == "" {
		fields = strings.Join(ev.DataList, "; ")
	}
	return []Finding{{Rule: "privesc.certificate_sid_mismatch", Severity: SevSuspect, Technique: "T1649", Confidence: 75,
		Detail: fmt.Sprintf("the KDC refused a certificate logon because the certificate's SID and the SID of the account it maps "+
			"to differ (%s): the certificate was issued to one account and names another, which is how a certificate requested "+
			"for someone else looks once the CA stamps the requester's SID into it (ESC1/ESC6-style abuse, Certipy). %s",
			strings.Join(sids, " vs "), excerpt(fields, 300))}}
}

// requestAttributes parses a certificate request's attributes as the CA logs
// them: "Name:value" lines, names case-insensitive.
func requestAttributes(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' }) {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
	}
	return out
}

// certRequestFindings judges a certificate request the CA issued (4887),
// denied (4888) or left pending (4889) by its attributes: a subject
// alternative name the requester supplied (how ESC1 and ESC6 are abused —
// Certipy sends one for -upn, -dns and -sid), and application policies the
// requester supplied (ESC15).
func certRequestFindings(ev winEvent) []Finding {
	attrs := requestAttributes(evData(ev, "Attributes"))
	requester := firstNonEmpty(evData(ev, "Requester"), "an unrecorded requester")
	what := map[int]string{4887: "issued", 4888: "denied", 4889: "left pending"}[ev.EventID]
	template := firstNonEmpty(attrs["certificatetemplate"], "an unnamed template")
	id := firstNonEmpty(evData(ev, "RequestId"), "?")
	var out []Finding
	if san := attrs["san"]; san != "" {
		var identities, hosts []string
		for _, part := range strings.Split(san, "&") {
			kind, value, _ := strings.Cut(strings.TrimSpace(part), "=")
			switch strings.ToLower(strings.TrimSpace(kind)) {
			case "upn", "email":
				identities = append(identities, value)
			case "url":
				if strings.Contains(strings.ToLower(value), ":sid:") {
					identities = append(identities, value)
				}
			case "dns":
				hosts = append(hosts, value)
			}
		}
		switch {
		case len(identities) > 0:
			f := Finding{Rule: "privesc.adcs_alternate_identity", Severity: SevSuspect, Technique: "T1649", Confidence: 75,
				Detail: fmt.Sprintf("the CA %s request %s from %s (template %s) whose subject alternative name the requester "+
					"supplied: %s. A certificate naming another user logs on as that user; supplying the SAN is how ESC1 and ESC6 "+
					"are abused (Certipy req -upn)", what, id, requester, template, excerpt(strings.Join(identities, ", "), 200))}
			if !sameAccount(requester, identities) {
				f.Confidence = 80
				f.Detail += ". The name isn't the requester's own"
			}
			if ev.EventID == 4888 {
				f.Severity, f.Confidence = SevNotable, 50
			}
			out = append(out, f)
		case len(hosts) > 0:
			out = append(out, Finding{Rule: "privesc.adcs_alternate_identity", Severity: SevNotable, Technique: "T1649", Confidence: 40,
				Detail: fmt.Sprintf("the CA %s request %s from %s (template %s) whose subject alternative name the requester "+
					"supplied: DNS names %s. Normal for a web-server certificate; with a template that allows client "+
					"authentication it impersonates those computers", what, id, requester, template, excerpt(strings.Join(hosts, ", "), 200))})
		}
	}
	if pol := attrs["applicationpolicies"]; pol != "" {
		f := Finding{Rule: "privesc.adcs_application_policies", Severity: SevSuspect, Technique: "T1649", Confidence: 70,
			Detail: fmt.Sprintf("the CA %s request %s from %s (template %s) carrying application policies the requester chose (%s): "+
				"a schema-version-1 template copies them into the certificate, turning a template anyone may enroll in into a "+
				"client-authentication or enrollment-agent certificate (ESC15, CVE-2024-49019)", what, id, requester, template, excerpt(pol, 160))}
		if ev.EventID == 4888 {
			f.Severity, f.Confidence = SevNotable, 45
		}
		out = append(out, f)
	}
	return out
}

// sameAccount reports whether every identity a request named is the
// requester's own account (DOMAIN\user against user@… or the bare name).
func sameAccount(requester string, identities []string) bool {
	_, user, ok := strings.Cut(requester, "\\")
	if !ok {
		user = requester
	}
	user = strings.ToLower(strings.TrimSpace(user))
	for _, id := range identities {
		name, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(id)), "@")
		if name != user {
			return false
		}
	}
	return true
}

// certTemplateFindings judges a template the CA loaded (4898) or updated
// (4899): one that lets the requester supply the subject and issues
// certificates that log on is ESC1 — whoever may enroll gets a certificate as
// any user. A template changed into that shape is ESC4 being used: an
// intruder with write access makes it vulnerable, enrolls, and changes it back.
func certTemplateFindings(ev winEvent) []Finding {
	name := firstNonEmpty(evData(ev, "TemplateInternalName"), evData(ev, "TemplateDSObjectFQDN"), "(unnamed)")
	content, sd := evData(ev, "TemplateContent"), evData(ev, "SecurityDescriptor")
	if ev.EventID == 4899 {
		content, sd = evData(ev, "NewTemplateContent"), firstNonEmpty(evData(ev, "NewSecurityDescriptor"), sd)
	}
	const suppliesSubject = "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT"
	if !strings.Contains(strings.ToUpper(content), suppliesSubject) {
		return nil
	}
	var ekus []string
	for _, e := range authEKUs {
		if strings.Contains(content, e.oid) {
			ekus = append(ekus, e.name)
		}
	}
	if len(ekus) == 0 {
		return nil
	}
	f := Finding{Rule: "privesc.adcs_vulnerable_template", Severity: SevSuspect, Technique: "T1649", Confidence: 60,
		Detail: fmt.Sprintf("certificate template %s lets the requester supply the subject and issues %s certificates (ESC1): "+
			"whoever may enroll in it can get a certificate that logs on as any user, Domain Admins included", name, strings.Join(ekus, ", "))}
	if broad := broadEnrollers(sd); len(broad) > 0 {
		f.Confidence = 80
		f.Detail += "; " + strings.Join(broad, " and ") + " may enroll"
	}
	if strings.Contains(strings.ToUpper(content), "CT_FLAG_PEND_ALL_REQUESTS") {
		f.Severity, f.Confidence = SevNotable, 40
		f.Detail += "; requests wait for a CA manager's approval, which blunts it"
	}
	if old := evData(ev, "OldTemplateContent"); ev.EventID == 4899 && old != "" && !strings.Contains(strings.ToUpper(old), suppliesSubject) {
		f.Severity, f.Confidence = SevSuspect, 80
		f.Detail = fmt.Sprintf("certificate template %s was changed%s so that the requester supplies the subject of %s "+
			"certificates: from now on whoever may enroll can get a certificate as any user (ESC1). Changing a template into "+
			"that shape, enrolling, and changing it back is how write access to a template is abused (ESC4, Certipy template)",
			name, whoBy(ev), strings.Join(ekus, ", "))
	}
	return []Finding{f}
}

// Kerberoasting shows in a domain controller's log as one account asking,
// within minutes, for RC4-encrypted service tickets to many services that run
// as user accounts: each ticket is encrypted with that account's password
// hash and cracks offline. One RC4 ticket proves nothing — domains that still
// allow RC4 issue them all day — so the tracker counts distinct services per
// account and client address in a sliding window, across the whole log.
const (
	kerberoastWindow       = 15 * time.Minute
	kerberoastMin          = 4  // distinct services within the window to report
	kerberoastCritical     = 10 // … to report as critical
	kerberoastMaxPerClient = 20000
	kerberoastMaxClients   = 20000
	kerberoastListMax      = 50
)

type roastTicket struct {
	when    time.Time
	service string
}

type roastClient struct {
	account, address string
	tickets          []roastTicket
}

// kerberoastTracker gathers RC4 service-ticket requests (4769) over a run.
type kerberoastTracker struct {
	clients map[string]*roastClient
	names   map[string]string // service names, interned
}

func newKerberoastTracker() *kerberoastTracker {
	return &kerberoastTracker{clients: map[string]*roastClient{}, names: map[string]string{}}
}

// roastable reports whether a 4769 is a successful RC4 ticket, requested by a
// user, for a service that runs as a user account (not krbtgt, not a
// computer's NAME$).
func roastable(ev winEvent) bool {
	if ev.EventID != 4769 || !kerberosOK(evData(ev, "Status")) || !rc4(evData(ev, "TicketEncryptionType")) {
		return false
	}
	svc := strings.ToLower(strings.TrimSpace(evData(ev, "ServiceName")))
	if svc == "" || svc == "krbtgt" || strings.HasSuffix(svc, "$") {
		return false
	}
	return !strings.Contains(evData(ev, "TargetUserName"), "$@")
}

// observe folds one event in.
func (t *kerberoastTracker) observe(ev winEvent) {
	if t == nil || ev.EventID != 4769 || ev.TimeCreated.IsZero() || !roastable(ev) {
		return
	}
	account := strings.TrimSpace(evData(ev, "TargetUserName"))
	addr := clientAddress(evData(ev, "IpAddress"))
	key := strings.ToLower(account) + "|" + addr
	c := t.clients[key]
	if c == nil {
		if len(t.clients) >= kerberoastMaxClients {
			return
		}
		c = &roastClient{account: account, address: addr}
		t.clients[key] = c
	}
	if len(c.tickets) >= kerberoastMaxPerClient {
		return
	}
	svc := strings.TrimSpace(evData(ev, "ServiceName"))
	low := strings.ToLower(svc)
	if n, ok := t.names[low]; ok {
		svc = n
	} else {
		t.names[low] = svc
	}
	c.tickets = append(c.tickets, roastTicket{when: ev.TimeCreated, service: svc})
}

// flush reports each account and address whose busiest window held enough
// distinct services, as one synthetic record.
func (t *kerberoastTracker) flush() []Record {
	if t == nil {
		return nil
	}
	keys := make([]string, 0, len(t.clients))
	for k := range t.clients {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Record
	for _, k := range keys {
		c := t.clients[k]
		sort.SliceStable(c.tickets, func(i, j int) bool { return c.tickets[i].when.Before(c.tickets[j].when) })
		counts := map[string]int{}
		best, bi, bj := 0, 0, 0
		for i, j := 0, 0; j < len(c.tickets); j++ {
			counts[strings.ToLower(c.tickets[j].service)]++
			for c.tickets[j].when.Sub(c.tickets[i].when) > kerberoastWindow {
				s := strings.ToLower(c.tickets[i].service)
				if counts[s]--; counts[s] == 0 {
					delete(counts, s)
				}
				i++
			}
			if len(counts) > best {
				best, bi, bj = len(counts), i, j
			}
		}
		if best < kerberoastMin {
			continue
		}
		var services []string
		seen := map[string]bool{}
		for _, tk := range c.tickets[bi : bj+1] {
			if low := strings.ToLower(tk.service); !seen[low] {
				seen[low] = true
				services = append(services, tk.service)
			}
		}
		sort.Strings(services)
		listed := services
		if len(listed) > kerberoastListMax {
			listed = append(append([]string(nil), listed[:kerberoastListMax]...), fmt.Sprintf("… and %d more", len(services)-kerberoastListMax))
		}
		first, last := c.tickets[bi].when.UTC(), c.tickets[bj].when.UTC()
		addr := firstNonEmpty(c.address, "an unrecorded address")
		f := Finding{Rule: "cred.kerberoasting", Severity: SevSuspect, Technique: "T1558.003", Confidence: 70,
			Detail: fmt.Sprintf("%s (from %s) asked for RC4-encrypted tickets to %d different services that run as user accounts "+
				"between %s and %s: each ticket cracks offline to its service account's password, and a burst of them is "+
				"Kerberoasting (Rubeus kerberoast, Impacket GetUserSPNs). Services: %s", c.account, addr, best,
				first.Format(time.RFC3339), last.Format(time.RFC3339), strings.Join(listed, ", "))}
		if best >= kerberoastCritical {
			f.Severity, f.Confidence = SevCritical, 80
		}
		out = append(out, Record{
			Fields: map[string]any{
				"aggregation":    "kerberoasting",
				"account":        c.account,
				"client_address": c.address,
				"services":       listed,
				"service_count":  best,
				"tickets":        bj - bi + 1,
				"time_created":   first,
				"last":           last,
				"window":         kerberoastWindow.String(),
			},
			Findings: []Finding{f},
		})
	}
	return out
}
