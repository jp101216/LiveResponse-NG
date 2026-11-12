package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dcEvent builds a normalized Security-log event as a domain controller logs it.
func dcEvent(id int, kv ...string) winEvent {
	ev := winEvent{EventID: id, Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", Computer: "DC01.corp.local",
		Data: map[string]string{}, UserData: map[string]string{}, TimeCreated: time.Date(2026, 10, 30, 2, 0, 0, 0, time.UTC)}
	for i := 0; i+1 < len(kv); i += 2 {
		ev.Data[kv[i]] = kv[i+1]
	}
	return ev
}

// only asserts that fs holds exactly one finding, with the rule and severity
// given, and returns it.
func only(t *testing.T, name string, fs []Finding, rule string, sev Severity) Finding {
	t.Helper()
	if len(fs) != 1 || fs[0].Rule != rule || fs[0].Severity != sev || fs[0].Technique == "" || fs[0].Detail == "" {
		t.Fatalf("%s: got %+v, want one %s at %s", name, fs, rule, sev)
	}
	return fs[0]
}

func none(t *testing.T, name string, fs []Finding) {
	t.Helper()
	if len(fs) != 0 {
		t.Errorf("%s: want nothing, got %+v", name, fs)
	}
}

func TestDCSync(t *testing.T) {
	props := "%%7688\r\n{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}\r\n{19195a5b-6da0-11d0-afd3-00c04fd930c9}"
	f := only(t, "dcsync", eventFindings(dcEvent(4662, "SubjectUserName", "jdoe", "SubjectDomainName", "CORP",
		"SubjectUserSid", "S-1-5-21-1-2-3-1105", "ObjectServer", "DS", "AccessMask", "0x100", "Properties", props)),
		"cred.dcsync", SevCritical)
	if !strings.Contains(f.Detail, `CORP\jdoe`) || !strings.Contains(f.Detail, "Get-Changes-All") || !strings.Contains(f.Detail, "DC01.corp.local") {
		t.Errorf("detail: %s", f.Detail)
	}
	// Upper-case GUIDs, and Get-Changes alone (what sync products hold).
	only(t, "get-changes", eventFindings(dcEvent(4662, "SubjectUserName", "svc_sync", "SubjectDomainName", "CORP",
		"Properties", "%%7688 {1131F6AA-9C07-11D1-F79F-00C04FC2DCD2}")), "cred.dcsync", SevSuspect)
	// Domain controllers, the system and Azure AD Connect replicate.
	for _, who := range [][2]string{{"DC02$", "CORP"}, {"MSOL_0123abcd", "CORP"}, {"DWM-1", "Window Manager"}} {
		none(t, who[0], eventFindings(dcEvent(4662, "SubjectUserName", who[0], "SubjectDomainName", who[1], "Properties", props)))
	}
	none(t, "system", eventFindings(dcEvent(4662, "SubjectUserSid", "S-1-5-18", "SubjectUserName", "SYSTEM", "Properties", props)))
	none(t, "other property", eventFindings(dcEvent(4662, "SubjectUserName", "jdoe", "Properties", "%%7685 {bf967a86-0de6-11d0-a285-00aa003049e2}")))
}

func TestDirectoryAccess(t *testing.T) {
	f := only(t, "backup key", eventFindings(dcEvent(4662, "SubjectUserName", "admin", "SubjectDomainName", "CORP",
		"ObjectServer", "LSA", "ObjectType", "SecretObject", "ObjectName", `Policy\Secrets\G$BCKUPKEY_PREFERRED`, "AccessMask", "0x2")),
		"cred.dpapi_backup_key", SevCritical)
	if !strings.Contains(f.Detail, "BCKUPKEY_PREFERRED") {
		t.Errorf("detail: %s", f.Detail)
	}
	none(t, "backup key by DC", eventFindings(dcEvent(4662, "SubjectUserName", "DC01$", "ObjectType", "SecretObject",
		"ObjectName", `Policy\Secrets\G$BCKUPKEY_P`, "AccessMask", "0x2")))
	none(t, "other secret", eventFindings(dcEvent(4662, "SubjectUserName", "admin", "ObjectType", "SecretObject",
		"ObjectName", `Policy\Secrets\DPAPI_SYSTEM`, "AccessMask", "0x2")))

	only(t, "write dac", eventFindings(dcEvent(4662, "SubjectUserName", "EXCH01$", "SubjectDomainName", "CORP",
		"SubjectUserSid", "S-1-5-21-1-2-3-1201", "ObjectServer", "DS", "ObjectType", "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
		"AccessMask", "0x40000")), "persistence.domain_acl_changed", SevSuspect)
	none(t, "write dac by system", eventFindings(dcEvent(4662, "SubjectUserSid", "S-1-5-18", "ObjectServer", "DS",
		"ObjectType", "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}", "AccessMask", "0x40000")))
	none(t, "read on domain", eventFindings(dcEvent(4662, "SubjectUserName", "jdoe", "ObjectServer", "DS",
		"ObjectType", "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}", "AccessMask", "0x10")))

	record := "DC=srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local"
	only(t, "reflection 4662", eventFindings(dcEvent(4662, "SubjectUserName", "jdoe", "SubjectDomainName", "CORP",
		"ObjectServer", "DS", "AccessMask", "0x20", "AdditionalInfo", record)), "privesc.reflection_dns_record", SevCritical)
	only(t, "reflection 5137", eventFindings(dcEvent(5137, "ObjectClass", "dnsNode", "ObjectDN", record)),
		"privesc.reflection_dns_record", SevCritical)
	// The blob is case-sensitive base64; lower-cased it doesn't unmarshal.
	none(t, "lower-case", eventFindings(dcEvent(5137, "ObjectClass", "dnsNode", "ObjectDN", strings.ToLower(record))))
	none(t, "ordinary record", eventFindings(dcEvent(5137, "ObjectClass", "dnsNode",
		"ObjectDN", "DC=web01,DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local")))
}

func TestDirectoryChanges(t *testing.T) {
	change := func(class, dn, attr, value string, kv ...string) []Finding {
		return eventFindings(dcEvent(5136, append([]string{"SubjectUserName", "attacker", "SubjectDomainName", "CORP",
			"ObjectClass", class, "ObjectDN", dn, "AttributeLDAPDisplayName", attr, "AttributeValue", value,
			"OperationType", "%%14674"}, kv...)...))
	}
	key := "B:828:0002000020000108...:CN=Domain Admin,CN=Users,DC=corp,DC=local"
	f := only(t, "shadow", change("user", "CN=Domain Admin,CN=Users,DC=corp,DC=local", "msDS-KeyCredentialLink", key),
		"cred.shadow_credentials", SevSuspect)
	if !strings.Contains(f.Detail, "CN=Domain Admin") || !strings.Contains(f.Detail, `CORP\attacker`) {
		t.Errorf("detail: %s", f.Detail)
	}
	only(t, "shadow self", change("computer", "CN=WS01,CN=Computers,DC=corp,DC=local", "msDS-KeyCredentialLink", key,
		"SubjectUserName", "WS01$"), "cred.shadow_credentials", SevNotable)
	none(t, "shadow by AAD Connect", change("user", "CN=jdoe,CN=Users,DC=corp,DC=local", "msDS-KeyCredentialLink", key,
		"SubjectUserName", "MSOL_8f2a"))
	none(t, "value deleted", change("user", "CN=jdoe,CN=Users,DC=corp,DC=local", "msDS-KeyCredentialLink", key,
		"OperationType", "%%14675"))

	f = only(t, "rbcd", change("computer", "CN=FS01,CN=Computers,DC=corp,DC=local", "msDS-AllowedToActOnBehalfOfOtherIdentity",
		"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-1112)"), "privesc.rbcd_configured", SevSuspect)
	if !strings.Contains(f.Detail, "S-1-5-21-1-2-3-1112") || !strings.Contains(f.Detail, "CN=FS01") {
		t.Errorf("detail: %s", f.Detail)
	}
	only(t, "constrained", change("user", "CN=svc_web,CN=Users,DC=corp,DC=local", "msDS-AllowedToDelegateTo",
		"cifs/dc01.corp.local"), "privesc.constrained_delegation_configured", SevSuspect)

	only(t, "spn on user", change("user", "CN=Domain Admin,CN=Users,DC=corp,DC=local", "servicePrincipalName",
		"fake/roastme"), "cred.spn_added_to_user", SevNotable)
	none(t, "spn on computer", change("computer", "CN=WS01,CN=Computers,DC=corp,DC=local", "servicePrincipalName", "HOST/WS01"))
	only(t, "dcshadow", change("computer", "CN=WS01,CN=Computers,DC=corp,DC=local", "servicePrincipalName",
		"GC/WS01.corp.local/corp.local"), "defense.dcshadow", SevSuspect)
	only(t, "dcshadow drsuapi", change("computer", "CN=WS01,CN=Computers,DC=corp,DC=local", "servicePrincipalName",
		"E3514235-4B06-11D1-AB04-00C04FC2DCD2/6b1f9e0a-0000-0000-0000-000000000000/corp.local"), "defense.dcshadow", SevSuspect)
	none(t, "real dc", change("computer", "CN=DC02,OU=Domain Controllers,DC=corp,DC=local", "servicePrincipalName",
		"GC/DC02.corp.local/corp.local"))
}

func TestDomainSecurityDescriptor(t *testing.T) {
	const domain = "DC=corp,DC=local"
	defaults := "O:BAG:BAD:AI(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)" +
		"(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;S-1-5-21-1-2-3-498)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" +
		"(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)" +
		"S:AI(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
	sd := func(class, dn, value string) []Finding {
		return eventFindings(dcEvent(5136, "SubjectUserName", "attacker", "SubjectDomainName", "CORP", "ObjectClass", class,
			"ObjectDN", dn, "AttributeLDAPDisplayName", "nTSecurityDescriptor", "AttributeValue", value, "OperationType", "%%14674"))
	}
	none(t, "defaults", sd("domainDNS", domain, defaults))
	f := only(t, "granted", sd("domainDNS", domain, defaults+"(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-1-2-3-1105)"),
		"persistence.dcsync_rights_granted", SevCritical)
	if !strings.Contains(f.Detail, "S-1-5-21-1-2-3-1105 (DS-Replication-Get-Changes-All)") {
		t.Errorf("detail: %s", f.Detail)
	}
	f = only(t, "full control", sd("domainDNS", domain, defaults+"(A;CIOI;GA;;;S-1-5-21-1-2-3-1106)"), "persistence.dcsync_rights_granted", SevCritical)
	if !strings.Contains(f.Detail, "S-1-5-21-1-2-3-1106 (every extended right") {
		t.Errorf("detail: %s", f.Detail)
	}
	// Inherit-only entries apply to children, where replication rights mean nothing.
	none(t, "inherit only", sd("domainDNS", domain, defaults+"(OA;CIIO;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-1-2-3-1105)"))
	none(t, "deny", sd("domainDNS", domain, defaults+"(OD;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-1-2-3-1105)"))
	none(t, "not the domain", sd("organizationalUnit", "OU=Staff,"+domain, defaults+"(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-1-2-3-1105)"))
	only(t, "no class", sd("", domain, defaults+"(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;DC)"), "persistence.dcsync_rights_granted", SevCritical)

	holder := "CN=AdminSDHolder,CN=System," + domain
	f = only(t, "adminsdholder", sd("container", holder, "O:DAG:DAD:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"),
		"persistence.adminsdholder_modified", SevSuspect)
	if f.Confidence != 70 {
		t.Errorf("confidence %d", f.Confidence)
	}
	f = only(t, "adminsdholder backdoor", sd("container", holder, "O:DAG:DAD:PAI(A;;GA;;;S-1-5-21-1-2-3-1105)(A;;LCRPLORC;;;AU)"),
		"persistence.adminsdholder_modified", SevSuspect)
	if f.Confidence != 80 || !strings.Contains(f.Detail, "S-1-5-21-1-2-3-1105") {
		t.Errorf("%+v", f)
	}
}

func TestSDDLParsing(t *testing.T) {
	aces := sddlACEs("O:BAG:BAD:AI(OA;CIIO;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;0x100;;;S-1-5-21-1-2-3-1105)(junk)")
	if len(aces) != 2 || aces[0].kind != "OA" || !aces[0].inheritOnly() || aces[0].object != rightGetChangesAll || aces[0].trustee != "BA" {
		t.Fatalf("%+v", aces)
	}
	if !aces[1].hasRight("CR") || aces[1].hasRight("GA") || aces[1].inheritOnly() {
		t.Errorf("numeric mask: %+v", aces[1])
	}
	if sddlToken("CIOI", "IO") || !sddlToken("CIIO", "IO") || sddlToken("RPWPCC", "PW") {
		t.Error("tokens are read in pairs")
	}
	if got := broadEnrollers("D:(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)(A;;LCRPRC;;;AU)(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;S-1-5-21-1-2-3-515)"); strings.Join(got, ",") != "Domain Users,Domain Computers" {
		t.Errorf("broad enrollers: %v", got)
	}
	if !domainRootDN("DC=corp,DC=local") || domainRootDN("CN=x,DC=corp") || domainRootDN("") {
		t.Error("domainRootDN")
	}
}

func TestAccountBackdoors(t *testing.T) {
	f := only(t, "sid history", eventFindings(dcEvent(4765, "TargetUserName", "jdoe", "TargetDomainName", "CORP",
		"SidList", "{S-1-5-21-1-2-3-512}", "SubjectUserName", "admin", "SubjectDomainName", "CORP")),
		"persistence.sid_history_added", SevCritical)
	if !strings.Contains(f.Detail, "Domain Admins") || !strings.Contains(f.Detail, `CORP\jdoe`) {
		t.Errorf("detail: %s", f.Detail)
	}
	only(t, "sid history failed", eventFindings(dcEvent(4766, "TargetUserName", "jdoe", "SidList", "{S-1-5-21-1-2-3-512}")),
		"persistence.sid_history_added", SevNotable)
	only(t, "4738 sid history", eventFindings(dcEvent(4738, "TargetUserName", "jdoe", "TargetDomainName", "CORP",
		"SidHistory", "S-1-5-21-9-9-9-1234")), "persistence.sid_history_added", SevSuspect)
	only(t, "4738 builtin admins", eventFindings(dcEvent(4738, "TargetUserName", "jdoe", "SidHistory", "S-1-5-32-544")),
		"persistence.sid_history_added", SevCritical)
	only(t, "4742 delegation", eventFindings(dcEvent(4742, "TargetUserName", "WEB01$", "TargetDomainName", "CORP",
		"AllowedToDelegateTo", "cifs/dc01.corp.local", "SidHistory", "-")), "privesc.constrained_delegation_configured", SevSuspect)
	none(t, "4738 unchanged", eventFindings(dcEvent(4738, "TargetUserName", "jdoe", "SidHistory", "%%1793", "AllowedToDelegateTo", "-")))

	only(t, "dsrm", eventFindings(dcEvent(4794, "SubjectUserName", "admin", "SubjectDomainName", "CORP", "Status", "0x0")),
		"persistence.dsrm_password_set", SevSuspect)
	only(t, "dsrm failed", eventFindings(dcEvent(4794, "SubjectUserName", "admin", "Status", "0xC0000022")),
		"persistence.dsrm_password_set", SevNotable)
}

func TestKerberosTGT(t *testing.T) {
	tgt := func(kv ...string) []Finding {
		return eventFindings(dcEvent(4768, append([]string{"TargetUserName", "svc_legacy", "TargetDomainName", "CORP",
			"Status", "0x0", "IpAddress", "::ffff:10.0.0.5", "PreAuthType", "2", "TicketEncryptionType", "0x12"}, kv...)...))
	}
	f := only(t, "asrep rc4", tgt("PreAuthType", "0", "TicketEncryptionType", "0x17"), "cred.asrep_roasting", SevSuspect)
	if !strings.Contains(f.Detail, "10.0.0.5") || strings.Contains(f.Detail, "::ffff:") {
		t.Errorf("detail: %s", f.Detail)
	}
	only(t, "asrep aes", tgt("PreAuthType", "0"), "cred.asrep_roasting", SevNotable)
	none(t, "pre-authenticated", tgt())
	none(t, "failed", tgt("PreAuthType", "0", "Status", "0x18"))

	f = only(t, "pkinit dc", tgt("TargetUserName", "DC01$", "CertIssuerName", "corp-CA01-CA", "CertSerialNumber", "1a0000000ef",
		"CertThumbprint", "8F3AC1D2E4B5A6978877665544332211FFEEDDCC", "PreAuthType", "16", "IpAddress", "::ffff:10.0.0.66"),
		"cred.computer_certificate_logon", SevSuspect)
	if !strings.Contains(f.Detail, "corp-CA01-CA") || !strings.Contains(f.Detail, "10.0.0.66") {
		t.Errorf("detail: %s", f.Detail)
	}
	none(t, "pkinit local", tgt("TargetUserName", "DC01$", "CertThumbprint", "8F3A", "IpAddress", "::1"))
	none(t, "pkinit user", tgt("TargetUserName", "jdoe", "CertThumbprint", "8F3A"))
	none(t, "computer password", tgt("TargetUserName", "WS01$", "CertThumbprint", ""))
}

func TestKDCCertificateMismatch(t *testing.T) {
	ev := dcEvent(41, "AccountName", "Administrator", "Subject", "CN=jdoe", "CertificateSid", "S-1-5-21-1-2-3-1105",
		"AccountSid", "S-1-5-21-1-2-3-500")
	ev.Provider, ev.Channel = "Microsoft-Windows-Kerberos-Key-Distribution-Center", "System"
	f := only(t, "sid mismatch", eventFindings(ev), "privesc.certificate_sid_mismatch", SevSuspect)
	if !strings.Contains(f.Detail, "S-1-5-21-1-2-3-1105") || !strings.Contains(f.Detail, "S-1-5-21-1-2-3-500") || !strings.Contains(f.Detail, "AccountName=Administrator") {
		t.Errorf("detail: %s", f.Detail)
	}
	// The same SID twice, or a single one, isn't a mismatch.
	ev.Data["CertificateSid"] = "S-1-5-21-1-2-3-500"
	none(t, "same sid", eventFindings(ev))
	// Kernel-Power's 41 (an unexpected reboot) shares the id.
	power := dcEvent(41, "BugcheckCode", "0", "A", "S-1-5-21-1-2-3-1105", "B", "S-1-5-21-1-2-3-500")
	power.Provider, power.Channel = "Microsoft-Windows-Kernel-Power", "System"
	none(t, "kernel-power", eventFindings(power))
}

func TestCertificateRequests(t *testing.T) {
	req := func(id int, requester, attrs string) []Finding {
		return eventFindings(dcEvent(id, "RequestId", "4242", "Requester", requester, "Attributes", attrs,
			"Disposition", "3", "Subject", "CN=jdoe"))
	}
	f := only(t, "esc1", req(4887, `CORP\jdoe`, "CertificateTemplate:CorpVPN\nSAN:upn=administrator@corp.local"),
		"privesc.adcs_alternate_identity", SevSuspect)
	if f.Confidence != 80 || !strings.Contains(f.Detail, "administrator@corp.local") || !strings.Contains(f.Detail, "CorpVPN") ||
		!strings.Contains(f.Detail, "4242") || !strings.Contains(f.Detail, "issued") {
		t.Errorf("%+v", f)
	}
	f = only(t, "own upn", req(4887, `CORP\jdoe`, "CertificateTemplate:User\r\nSAN:upn=JDoe@corp.local"), "privesc.adcs_alternate_identity", SevSuspect)
	if f.Confidence != 75 {
		t.Errorf("own name: confidence %d", f.Confidence)
	}
	only(t, "sid url", req(4889, `CORP\jdoe`, "CertificateTemplate:User\nSAN:upn=administrator@corp.local&url=tag:microsoft.com,2022-09-14:sid:S-1-5-21-1-2-3-500"),
		"privesc.adcs_alternate_identity", SevSuspect)
	only(t, "denied", req(4888, `CORP\jdoe`, "CertificateTemplate:User\nSAN:upn=administrator@corp.local"), "privesc.adcs_alternate_identity", SevNotable)
	only(t, "dns", req(4887, `CORP\web01$`, "CertificateTemplate:WebServer\nSAN:dns=www.corp.local&dns=web01.corp.local"),
		"privesc.adcs_alternate_identity", SevNotable)
	only(t, "esc15", req(4887, `CORP\jdoe`, "CertificateTemplate:WebServer\nApplicationPolicies:1.3.6.1.5.5.7.3.2"),
		"privesc.adcs_application_policies", SevSuspect)
	none(t, "plain", req(4887, `CORP\jdoe`, "CertificateTemplate:User\nccm:WS01.corp.local"))
	if got := requestAttributes("CertificateTemplate:User\nSAN:upn=a@b\n\nnot an attribute"); got["certificatetemplate"] != "User" || got["san"] != "upn=a@b" || len(got) != 2 {
		t.Errorf("requestAttributes: %v", got)
	}
}

func TestCertificateTemplates(t *testing.T) {
	content := "flags = 0x2023a (131642)\n  CT_FLAG_ADD_EMAIL\nmsPKI-Certificate-Name-Flag = 0x1 (1)\n  CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1\n" +
		"pKIExtendedKeyUsage =\n  1.3.6.1.5.5.7.3.2 Client Authentication\n"
	sd := "O:S-1-5-21-1-2-3-519G:S-1-5-21-1-2-3-519D:PAI(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)(A;;LCRPLORC;;;AU)"
	f := only(t, "esc1", eventFindings(dcEvent(4898, "TemplateInternalName", "CorpVPN", "TemplateContent", content, "SecurityDescriptor", sd)),
		"privesc.adcs_vulnerable_template", SevSuspect)
	if f.Confidence != 80 || !strings.Contains(f.Detail, "CorpVPN") || !strings.Contains(f.Detail, "Domain Users may enroll") ||
		!strings.Contains(f.Detail, "Client Authentication") {
		t.Errorf("%+v", f)
	}
	only(t, "approval", eventFindings(dcEvent(4898, "TemplateInternalName", "CorpVPN", "TemplateContent",
		content+"msPKI-Enrollment-Flag = 0x2 (2)\n  CT_FLAG_PEND_ALL_REQUESTS -- 2\n", "SecurityDescriptor", sd)),
		"privesc.adcs_vulnerable_template", SevNotable)
	none(t, "web server", eventFindings(dcEvent(4898, "TemplateInternalName", "WebServer", "TemplateContent",
		strings.Replace(content, "1.3.6.1.5.5.7.3.2 Client Authentication", "1.3.6.1.5.5.7.3.1 Server Authentication", 1))))
	none(t, "subject from AD", eventFindings(dcEvent(4898, "TemplateInternalName", "User", "TemplateContent",
		strings.Replace(content, "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT", "CT_FLAG_SUBJECT_ALT_REQUIRE_UPN", 1))))
	old := strings.Replace(content, "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT", "CT_FLAG_SUBJECT_ALT_REQUIRE_UPN", 1)
	f = only(t, "esc4", eventFindings(dcEvent(4899, "TemplateInternalName", "User", "SubjectUserName", "jdoe", "SubjectDomainName", "CORP",
		"OldTemplateContent", old, "NewTemplateContent", content+"  CT_FLAG_PEND_ALL_REQUESTS\n")), "privesc.adcs_vulnerable_template", SevSuspect)
	if f.Confidence != 80 || !strings.Contains(f.Detail, "ESC4") || !strings.Contains(f.Detail, `CORP\jdoe`) {
		t.Errorf("%+v", f)
	}
}

func TestKerberoastTracker(t *testing.T) {
	base := time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC)
	tgs := func(at time.Duration, account, service string, kv ...string) winEvent {
		ev := dcEvent(4769, append([]string{"TargetUserName", account, "ServiceName", service, "IpAddress", "::ffff:10.0.0.5",
			"Status", "0x0", "TicketEncryptionType", "0x17", "TicketOptions", "0x40810010"}, kv...)...)
		ev.TimeCreated = base.Add(at)
		return ev
	}
	tr := newKerberoastTracker()
	// A roast: twelve services in two minutes, logged newest first.
	for i := 11; i >= 0; i-- {
		tr.observe(tgs(time.Duration(i)*10*time.Second, "jdoe@CORP.LOCAL", "svc_"+itoa(i)))
	}
	// The same service again doesn't count twice.
	tr.observe(tgs(30*time.Second, "jdoe@CORP.LOCAL", "SVC_3"))
	// A user reaching three services: not enough.
	for i := 0; i < 3; i++ {
		tr.observe(tgs(time.Duration(i)*time.Minute, "amy@CORP.LOCAL", "svc_"+itoa(i), "IpAddress", "10.0.0.7"))
	}
	// Six services, but spread over hours.
	for i := 0; i < 6; i++ {
		tr.observe(tgs(time.Duration(i)*20*time.Minute, "bob@CORP.LOCAL", "svc_"+itoa(i), "IpAddress", "10.0.0.8"))
	}
	// Five in a burst: suspect, not critical.
	for i := 0; i < 5; i++ {
		tr.observe(tgs(time.Duration(i)*time.Minute, "eve@CORP.LOCAL", "svc_"+itoa(i), "IpAddress", "10.0.0.9"))
	}
	// Not roastable: AES, krbtgt, computer services, computers asking, failures, other events.
	for i := 0; i < 8; i++ {
		tr.observe(tgs(time.Second, "carl@CORP.LOCAL", "svc_"+itoa(i), "TicketEncryptionType", "0x12"))
		tr.observe(tgs(time.Second, "carl@CORP.LOCAL", "FS0"+itoa(i)+"$"))
		tr.observe(tgs(time.Second, "WS01$@CORP.LOCAL", "svc_"+itoa(i)))
		tr.observe(tgs(time.Second, "dave@CORP.LOCAL", "svc_"+itoa(i), "Status", "0x1b"))
		ev := tgs(time.Second, "carl@CORP.LOCAL", "svc_"+itoa(i))
		ev.EventID = 4768
		tr.observe(ev)
	}
	tr.observe(tgs(time.Second, "carl@CORP.LOCAL", "krbtgt"))
	recs := tr.flush()
	if len(recs) != 2 {
		t.Fatalf("records: %+v", recs)
	}
	roast, small := recs[1], recs[0] // sorted by account: eve, jdoe
	f := roast.Findings[0]
	if f.Rule != "cred.kerberoasting" || f.Severity != SevCritical || roast.Fields["service_count"] != 12 ||
		roast.Fields["account"] != "jdoe@CORP.LOCAL" || roast.Fields["client_address"] != "10.0.0.5" ||
		!strings.Contains(f.Detail, "12 different services") || !strings.Contains(f.Detail, "svc_11") ||
		!roast.Fields["time_created"].(time.Time).Equal(base) {
		t.Errorf("roast: %+v %+v", roast.Fields, f)
	}
	if small.Fields["account"] != "eve@CORP.LOCAL" || small.Findings[0].Severity != SevSuspect || small.Fields["service_count"] != 5 {
		t.Errorf("burst of five: %+v", small)
	}
	var nilTracker *kerberoastTracker
	nilTracker.observe(tgs(0, "x", "y"))
	if nilTracker.flush() != nil {
		t.Error("nil tracker")
	}
}

// TestKerberoastingOffline runs a roast through the offline .evtx path: one
// record per file, the way the bruteforce sample does it.
func TestKerberoastingOffline(t *testing.T) {
	dir := t.TempDir()
	var files []string
	for i := 0; i < 6; i++ {
		ft := ftJun2021 + uint64(i)*30*10_000_000 // 30 seconds apart
		img := buildEvtx(uint64(i+1), ft, encFragmentAt(recordBase, encNode{name: "Event", children: []encNode{
			sysNode("Microsoft-Windows-Security-Auditing", 4769, "Security"),
			dataNode([2]string{"TargetUserName", "jdoe@CORP.LOCAL"}, [2]string{"ServiceName", "svc_sql" + itoa(i)},
				[2]string{"IpAddress", "::ffff:10.0.0.5"}, [2]string{"Status", "0x0"}, [2]string{"TicketEncryptionType", "0x17"}),
		}}))
		p := filepath.Join(dir, "tgs-"+itoa(i)+".evtx")
		if err := os.WriteFile(p, img, 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	res := ParseEventLogFiles(context.Background(), files, nil)
	var found *Record
	for i := range res.Records {
		if res.Records[i].Fields["source_log"] == "builtin:aggregation" {
			found = &res.Records[i]
		}
	}
	if found == nil || hasFinding(found.Findings, "cred.kerberoasting") == nil || found.Fields["service_count"] != 6 {
		t.Fatalf("records: %+v", res.Records)
	}
	// The individual 4769s carry no finding of their own, so they aren't kept.
	if len(res.Records) != 1 {
		t.Errorf("want only the aggregate record, got %d", len(res.Records))
	}
}

func TestKerberoastingWithAES(t *testing.T) {
	base := time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC)
	tgs := func(at time.Duration, account, service, etype string) winEvent {
		ev := dcEvent(4769, "TargetUserName", account, "ServiceName", service, "IpAddress", "::ffff:10.0.0.5",
			"Status", "0x0", "TicketEncryptionType", etype)
		ev.TimeCreated = base.Add(at)
		return ev
	}
	tr := newKerberoastTracker()
	for i := 0; i < 30; i++ { // thirty AES tickets in five minutes
		tr.observe(tgs(time.Duration(i)*10*time.Second, "jdoe@CORP.LOCAL", "svc_"+itoa(i), "0x12"))
	}
	for i := 0; i < 13; i++ { // thirteen, mixed AES-128/256: notable
		tr.observe(tgs(time.Duration(i)*time.Minute, "amy@CORP.LOCAL", "svc_"+itoa(i), []string{"0x11", "0x12"}[i%2]))
	}
	for i := 0; i < 11; i++ { // eleven: below the AES bar
		tr.observe(tgs(time.Duration(i)*time.Minute, "bob@CORP.LOCAL", "svc_"+itoa(i), "0x12"))
	}
	for i := 0; i < 20; i++ { // twenty, but over hours
		tr.observe(tgs(time.Duration(i)*20*time.Minute, "carl@CORP.LOCAL", "svc_"+itoa(i), "0x12"))
	}
	for i := 0; i < 15; i++ { // RC4 and AES mixed: the five RC4 decide it
		etype := "0x12"
		if i < 5 {
			etype = "0x17"
		}
		tr.observe(tgs(time.Duration(i)*time.Second, "eve@CORP.LOCAL", "svc_"+itoa(i), etype))
	}
	spoofed := tgs(0, "zed@CORP.LOCAL", "svc_1", "0x17")
	spoofed.Provider = "SomeApp"
	tr.observe(spoofed)
	recs := tr.flush()
	if len(recs) != 3 {
		t.Fatalf("records: %+v", recs)
	}
	amy, eve, jdoe := recs[0], recs[1], recs[2]
	if amy.Fields["encryption"] != "AES" || amy.Findings[0].Severity != SevNotable || amy.Fields["service_count"] != 13 {
		t.Errorf("amy: %+v %+v", amy.Fields, amy.Findings)
	}
	if eve.Fields["encryption"] != "RC4" || eve.Findings[0].Severity != SevSuspect || eve.Fields["service_count"] != 5 || eve.Fields["tickets"] != 5 {
		t.Errorf("eve: %+v %+v", eve.Fields, eve.Findings)
	}
	if jdoe.Fields["encryption"] != "AES" || jdoe.Findings[0].Severity != SevSuspect || jdoe.Fields["service_count"] != 30 ||
		!strings.Contains(jdoe.Findings[0].Detail, "AES-encrypted") {
		t.Errorf("jdoe: %+v %+v", jdoe.Fields, jdoe.Findings)
	}
}

func TestDCSyncByMachineAccount(t *testing.T) {
	props := "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}"
	repl := func(computer, account string) winEvent {
		ev := dcEvent(4662, "SubjectUserName", account, "SubjectDomainName", "CORP", "SubjectUserSid", "S-1-5-21-1-2-3-1000",
			"ObjectServer", "DS", "Properties", props)
		ev.Computer = computer
		return ev
	}
	kdc := func(computer string) winEvent {
		ev := dcEvent(4769, "TargetUserName", "x@CORP", "ServiceName", "svc", "Status", "0x0", "TicketEncryptionType", "0x12")
		ev.Computer = computer
		return ev
	}

	// One DC's log: DC02 replicates from it, so does WS17. Neither is known.
	tr := newMachineReplTracker()
	tr.observe(repl("DC01.corp.local", "DC02$"))
	tr.observe(repl("DC01.corp.local", "WS17$"))
	tr.observe(repl("DC01.corp.local", "WS17$"))
	tr.observe(repl("DC01.corp.local", "DC01$")) // the DC itself
	getChanges := repl("DC01.corp.local", "SYNC01$")
	getChanges.Data["Properties"] = "%%7688 {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"
	tr.observe(getChanges) // Get-Changes alone returns no secrets
	recs := tr.flush()
	if len(recs) != 2 || recs[0].Fields["account"] != `CORP\DC02$` || recs[1].Fields["account"] != `CORP\WS17$` ||
		recs[1].Fields["count"] != 2 || recs[1].Findings[0].Severity != SevNotable || recs[1].Findings[0].Rule != "cred.dcsync_machine_account" {
		t.Fatalf("one DC's log: %+v", recs)
	}

	// Two DCs' logs: DC02 shows up as a DC; WS17 doesn't, and is suspect.
	tr = newMachineReplTracker()
	tr.observe(repl("DC01.corp.local", "DC02$"))
	tr.observe(repl("DC01.corp.local", "WS17$"))
	tr.observe(kdc("DC02.corp.local"))
	recs = tr.flush()
	if len(recs) != 1 || recs[0].Fields["account"] != `CORP\WS17$` || recs[0].Findings[0].Severity != SevSuspect ||
		!strings.Contains(recs[0].Findings[0].Detail, "DC01.corp.local, DC02.corp.local") {
		t.Fatalf("two DCs' logs: %+v", recs)
	}

	// A long DNS name: the account carries its 15-character NetBIOS name.
	tr = newMachineReplTracker()
	tr.observe(kdc("VERYLONGDCNAME01.corp.local"))
	tr.observe(repl("DC01.corp.local", "VERYLONGDCNAME0$"))
	if recs := tr.flush(); len(recs) != 0 {
		t.Fatalf("NetBIOS-truncated DC: %+v", recs)
	}

	// The system, users (cred.dcsync's), other providers and object servers.
	tr = newMachineReplTracker()
	sys := repl("DC01.corp.local", "DC01$")
	sys.Data["SubjectUserSid"] = "S-1-5-18"
	tr.observe(sys)
	tr.observe(repl("DC01.corp.local", "jdoe"))
	spoof := repl("DC01.corp.local", "WS17$")
	spoof.Provider = "SomeApp"
	tr.observe(spoof)
	other := kdc("FILESRV.corp.local")
	other.EventID, other.Data["ObjectServer"] = 4662, "Security Account Manager"
	tr.observe(other)
	if recs := tr.flush(); len(recs) != 0 || len(tr.dcs) != 1 {
		t.Fatalf("not machine replication: %+v (dcs %v)", recs, tr.dcs)
	}
	var nilTracker *machineReplTracker
	nilTracker.observe(sys)
	if nilTracker.flush() != nil {
		t.Error("nil tracker")
	}
}
