package collector

import (
	"debug/pe"
	"fmt"
	"strings"
)

// The .NET Framework runtime loaded into a program that isn't a .NET
// program: how in-memory assembly execution looks from outside (T1620).
// execute-assembly starts or injects into a native process and hosts the CLR
// there through the unmanaged hosting interfaces, so clr.dll (or the 2.0
// runtime's mscorwks.dll) shows up in a module list whose main image carries
// no CLR header. No build tag: pure logic, unit-tested on any OS.

// peKind says what the main image of a process is.
type peKind int

const (
	peUnknown peKind = iota // unreadable or not a PE file
	peNative
	peManaged // has a CLR header: a .NET assembly, mixed-mode C++/CLI included
)

func (k peKind) String() string {
	switch k {
	case peNative:
		return "native"
	case peManaged:
		return "managed"
	}
	return "unknown"
}

// managedPE reads a PE file's headers and reports whether it carries a CLR
// (COM descriptor) header.
func managedPE(path string) peKind {
	f, _, err := openRegular(path)
	if err != nil {
		return peUnknown
	}
	defer f.Close()
	p, err := pe.NewFile(f)
	if err != nil {
		return peUnknown
	}
	defer p.Close()
	var dirs []pe.DataDirectory
	switch oh := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dirs = oh.DataDirectory[:min(int(oh.NumberOfRvaAndSizes), len(oh.DataDirectory))]
	case *pe.OptionalHeader64:
		dirs = oh.DataDirectory[:min(int(oh.NumberOfRvaAndSizes), len(oh.DataDirectory))]
	default:
		return peUnknown
	}
	if len(dirs) > pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR && dirs[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0 {
		return peManaged
	}
	return peNative
}

// clrModule reports the .NET Framework runtime's engine DLL: clr.dll for 4.x,
// mscorwks.dll for 2.0 to 3.5. (.NET Core and .NET 5+ load coreclr.dll through
// hostfxr, which the apphosts in front of those programs do every day.)
func clrModule(path string) bool {
	switch baseName(path) {
	case "clr.dll", "mscorwks.dll":
		return true
	}
	return false
}

// managedLOLBins are .NET programs themselves: the runtime in them is normal.
var managedLOLBins = set("msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe")

// benignRundll32CLR matches the rundll32 command lines that load the runtime
// for Windows itself: Windows Installer's managed custom actions (WiX DTF)
// and ClickOnce's launcher.
func benignRundll32CLR(cmdline string) bool {
	low := strings.ToLower(cmdline)
	return strings.Contains(low, "zzzzinvokemanagedcustomaction") || strings.Contains(low, "dfshim.dll")
}

// vbsHosts run VBScript and JScript, which reach .NET classes through COM
// (CreateObject("System.Collections.ArrayList") is common in admin scripts),
// so the runtime in them is only context.
var vbsHosts = set("wscript.exe", "cscript.exe")

// clrHostVerdict grades a process with the .NET Framework runtime loaded.
// Managed programs carry it as a matter of course and pass, as do native
// programs installed in Program Files or the Windows folder that host it for
// add-ins and snap-ins (Office, MMC, PowerShell, IIS, SQL Server), unless the
// program is one C2 frameworks use as a sacrificial process.
func clrHostVerdict(image, cmdline string, kind peKind) (sev Severity, conf int, why string, ok bool) {
	name := baseName(image)
	if kind == peManaged || managedLOLBins[name] || image == "" {
		return "", 0, "", false
	}
	lvl, where := pathRisk(image)
	switch {
	case spawnToHosts[name]:
		if name == "rundll32.exe" && benignRundll32CLR(cmdline) {
			return "", 0, "", false
		}
		if vbsHosts[name] {
			return SevNotable, 35, "a script host: DotNetToJScript and GadgetToJScript run .NET payloads from scripts this " +
				"way, and admin scripts that create .NET objects through COM load it too", true
		}
		return SevSuspect, 70, "a program C2 frameworks use as a sacrificial process, which never needs the runtime itself", true
	case kind != peNative:
		return "", 0, "", false // can't tell whether it is a .NET program
	case lvl == riskHigh:
		return SevSuspect, 65, "a native program running from " + where, true
	case installedProgram(image):
		return "", 0, "", false
	}
	return SevNotable, 40, "a native program outside Program Files and the Windows folder", true
}

const clrHostMeaning = "That is how running a .NET assembly in memory looks from outside (execute-assembly, or an implant " +
	"hosting the CLR itself)"

// clrInNativeFinding judges a live process's module list.
func clrInNativeFinding(label, image, clrPath, cmdline string, kind peKind) (Finding, bool) {
	sev, conf, why, ok := clrHostVerdict(image, cmdline, kind)
	if !ok {
		return Finding{}, false
	}
	return Finding{Rule: "modules.clr_in_native_process", Severity: sev, Technique: "T1620", Confidence: conf,
		Detail: fmt.Sprintf("%s has the .NET Framework runtime (%s) loaded, and its image %s is %s. %s",
			label, clrPath, image, why, clrHostMeaning)}, true
}

// clrImageLoadFindings judges Sysmon's event 7 (an image loaded) for the
// runtime loading into a sacrificial process. The event can't say whether
// the process's own image is a .NET program, so only programs known to be
// native are judged.
func clrImageLoadFindings(ev winEvent) []Finding {
	img, loaded := evData(ev, "Image"), evData(ev, "ImageLoaded")
	if !clrModule(loaded) || !spawnToHosts[baseName(img)] {
		return nil
	}
	sev, conf, why, ok := clrHostVerdict(img, "", peNative)
	if !ok {
		return nil
	}
	f := Finding{Rule: "modules.clr_in_native_process", Severity: sev, Technique: "T1620", Confidence: conf - 10,
		Detail: fmt.Sprintf("%s (pid %s) loaded the .NET Framework runtime (%s)%s; it is %s. %s", img,
			firstNonEmpty(evData(ev, "ProcessId"), "?"), loaded, eventTime(ev), why, clrHostMeaning)}
	if baseName(img) == "rundll32.exe" {
		f.Detail += ". Windows Installer's managed custom actions (an msiexec parent, " +
			"zzzzInvokeManagedCustomActionOutOfProc on the command line) and ClickOnce (dfshim.dll) also load it in rundll32"
	}
	return []Finding{f}
}
