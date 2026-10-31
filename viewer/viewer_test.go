package viewer

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the page's content security policy hashes")

var (
	styleRe  = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	scriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	cspRe    = regexp.MustCompile(`script-src '[^']*'; style-src '[^']*'`)
)

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// The policy allows exactly the page's one stylesheet and one script, by hash.
// Editing either without refreshing the hashes leaves the page blank, so this
// fails first (and -update fixes it).
func TestContentSecurityPolicy(t *testing.T) {
	// Browsers hash the text after the HTML parser has turned CRLF and CR into
	// LF, so a checkout with Windows line endings still matches.
	src := strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(string(page))
	styles := styleRe.FindAllStringSubmatch(src, -1)
	scripts := scriptRe.FindAllStringSubmatch(src, -1)
	if len(styles) != 1 || len(scripts) != 1 {
		t.Fatalf("want one <style> and one <script> (the report's data block aside), got %d and %d", len(styles), len(scripts))
	}
	want := "script-src '" + hash(scripts[0][1]) + "'; style-src '" + hash(styles[0][1]) + "'"
	if *update {
		out := cspRe.ReplaceAllString(src, want)
		if err := os.WriteFile("lrng-viewer.html", []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated: %s", want)
		return
	}
	if got := cspRe.FindString(src); got != want {
		t.Fatalf("stale content security policy in lrng-viewer.html (run: go test ./viewer -update)\n got: %s\nwant: %s", got, want)
	}
	for _, d := range []string{"default-src 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(src, d) {
			t.Errorf("the policy lost %q", d)
		}
	}
	if strings.Contains(src, "unsafe-") {
		t.Error("the policy must not allow unsafe-inline or unsafe-eval")
	}
}

// Report strings only ever become Text nodes or attribute values. The page
// uses none of the APIs that parse markup or code.
func TestNoMarkupOrCodeParsing(t *testing.T) {
	script := scriptRe.FindStringSubmatch(string(page))[1]
	for _, api := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\"", "createContextualFragment", "srcdoc", "DOMParser"} {
		if strings.Contains(script, api) {
			t.Errorf("the viewer script uses %s", api)
		}
	}
	if n := strings.Count(string(page), placeholder); n != 1 {
		t.Fatalf("placeholder appears %d times, want 1", n)
	}
}

func TestRenderEmbedsTheReportSafely(t *testing.T) {
	hostile := map[string]any{
		"tool": "liveresponse-ng", "host": `</script><script>alert(1)</script>`,
		"results": []any{map[string]any{"collector": "processes", "records": []any{map[string]any{"fields": map[string]any{
			"name": `<img src=x onerror=alert(2)>`, "command_line": "<!-- \u2028 \u2029 & > --!>",
		}}}}},
	}
	report, err := json.Marshal(hostile)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Render(&buf, report); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	start := strings.Index(out, `<script type="application/json" id="lrng-report">`)
	if start < 0 {
		t.Fatal("no data block")
	}
	start += len(`<script type="application/json" id="lrng-report">`)
	end := strings.Index(out[start:], "</script>")
	data := out[start : start+end]
	for _, bad := range []string{"<", ">", "\u2028", "\u2029"} {
		if strings.Contains(data, bad) {
			t.Errorf("the embedded report contains a raw %q", bad)
		}
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(data), &back); err != nil {
		t.Fatalf("the embedded report doesn't parse back: %v", err)
	}
	if back["host"] != hostile["host"] {
		t.Errorf("host round-tripped as %q", back["host"])
	}
	// Everything outside the data block is the page, unchanged.
	if out[:start-len(`<script type="application/json" id="lrng-report">`)]+placeholder+out[start+end+len("</script>"):] != string(page) {
		t.Error("Render changed the page outside the data block")
	}
	if err := Render(&buf, []byte("{not json")); err == nil {
		t.Error("invalid JSON was embedded")
	}
	if !bytes.Equal(Page(), page) {
		t.Error("Page differs from the embedded page")
	}
}
