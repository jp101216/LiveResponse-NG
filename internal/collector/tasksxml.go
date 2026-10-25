package collector

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"unicode/utf16"
)

// Parsing for Task Scheduler 2.0 job definitions (the XML files under
// %SystemRoot%\System32\Tasks).
//
// No build tag: it decodes plain bytes, so it's unit-tested on any OS even
// though only Windows has the task store. Two wrinkles are handled here: the
// files are usually UTF-16 with a BOM (and declare encoding="UTF-16", which
// Go's XML decoder rejects without a CharsetReader), and the <Task> element
// sits in a default namespace, so matching is by local element name.

// taskExec is one Exec action: a program plus its arguments.
type taskExec struct {
	Command          string
	Arguments        string
	WorkingDirectory string
}

// taskDef is the cleaned, analyst-facing view of a task definition.
type taskDef struct {
	Author      string
	Description string
	Date        string
	RunAs       string // UserId or GroupId of the first principal
	LogonType   string
	RunLevel    string
	Enabled     bool // tasks default to enabled when <Settings><Enabled> is absent
	Hidden      bool
	Execs       []taskExec
	ComHandlers []string // ClassId of any ComHandler actions
	Triggers    []string // element names of the triggers (LogonTrigger, ...)
}

// xmlTask mirrors the parts of the task schema we report.
type xmlTask struct {
	RegistrationInfo struct {
		Author      string `xml:"Author"`
		Description string `xml:"Description"`
		Date        string `xml:"Date"`
	} `xml:"RegistrationInfo"`
	Principals struct {
		Principal []struct {
			UserID    string `xml:"UserId"`
			GroupID   string `xml:"GroupId"`
			LogonType string `xml:"LogonType"`
			RunLevel  string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings struct {
		Enabled *bool `xml:"Enabled"`
		Hidden  *bool `xml:"Hidden"`
	} `xml:"Settings"`
	Actions struct {
		Exec []struct {
			Command          string `xml:"Command"`
			Arguments        string `xml:"Arguments"`
			WorkingDirectory string `xml:"WorkingDirectory"`
		} `xml:"Exec"`
		ComHandler []struct {
			ClassID string `xml:"ClassId"`
		} `xml:"ComHandler"`
	} `xml:"Actions"`
	Triggers struct {
		Any []struct {
			XMLName xml.Name
		} `xml:",any"`
	} `xml:"Triggers"`
}

// parseTaskXML decodes one task-definition file.
func parseTaskXML(raw []byte) (taskDef, error) {
	dec := xml.NewDecoder(bytes.NewReader(xmlToUTF8(raw)))
	// The bytes are already UTF-8; accept whatever encoding the declaration
	// names (typically UTF-16) by passing the reader through unchanged.
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }

	var t xmlTask
	if err := dec.Decode(&t); err != nil {
		return taskDef{}, err
	}

	def := taskDef{
		Author:      strings.TrimSpace(t.RegistrationInfo.Author),
		Description: strings.TrimSpace(t.RegistrationInfo.Description),
		Date:        strings.TrimSpace(t.RegistrationInfo.Date),
		Enabled:     t.Settings.Enabled == nil || *t.Settings.Enabled,
		Hidden:      t.Settings.Hidden != nil && *t.Settings.Hidden,
	}
	if len(t.Principals.Principal) > 0 {
		p := t.Principals.Principal[0]
		def.RunAs = p.UserID
		if def.RunAs == "" {
			def.RunAs = p.GroupID
		}
		def.LogonType = p.LogonType
		def.RunLevel = p.RunLevel
	}
	for _, e := range t.Actions.Exec {
		def.Execs = append(def.Execs, taskExec{
			Command:          strings.TrimSpace(e.Command),
			Arguments:        strings.TrimSpace(e.Arguments),
			WorkingDirectory: strings.TrimSpace(e.WorkingDirectory),
		})
	}
	for _, c := range t.Actions.ComHandler {
		if cid := strings.TrimSpace(c.ClassID); cid != "" {
			def.ComHandlers = append(def.ComHandlers, cid)
		}
	}
	for _, tr := range t.Triggers.Any {
		def.Triggers = append(def.Triggers, tr.XMLName.Local)
	}
	return def, nil
}

// xmlToUTF8 converts a task file to UTF-8, honouring a leading byte-order mark.
// UTF-16 (either endianness) and a UTF-8 BOM are handled; anything else is
// assumed to be UTF-8 already.
func xmlToUTF8(raw []byte) []byte {
	switch {
	case len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE:
		return utf16ToUTF8(raw[2:], false)
	case len(raw) >= 2 && raw[0] == 0xFE && raw[1] == 0xFF:
		return utf16ToUTF8(raw[2:], true)
	case len(raw) >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF:
		return raw[3:]
	default:
		return raw
	}
}

// utf16ToUTF8 decodes UTF-16 bytes (bigEndian selects byte order) to UTF-8.
func utf16ToUTF8(b []byte, bigEndian bool) []byte {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		if bigEndian {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			u[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
		}
	}
	return []byte(string(utf16.Decode(u)))
}
