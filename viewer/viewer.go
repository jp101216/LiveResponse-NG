// Package viewer holds the report viewer: one self-contained HTML page
// (lrng-viewer.html) that opens an lrng report, either dropped onto it or
// embedded in it. Opened on its own it is the standalone viewer; Render writes
// it with a report inside, which is what `-format html` produces.
//
// The page treats every string in a report as plain text, and its content
// security policy (hashes of its one script and one stylesheet, nothing else)
// blocks every network connection, so a report can neither inject code nor
// make the page reach out. viewer_test.go checks those hashes against the
// page; after editing it, run `go test ./viewer -update` to refresh them.
package viewer

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
)

//go:embed lrng-viewer.html
var page []byte

// placeholder is the empty data block a report is written into.
const placeholder = `<script type="application/json" id="lrng-report"></script>`

// Page returns the standalone viewer.
func Page() []byte { return bytes.Clone(page) }

// Render writes the viewer with report (a JSON report, as lrng writes it)
// embedded. The JSON is HTML-escaped first (<, >, & and the JavaScript line
// separators become \u escapes, which JSON.parse reads back unchanged), so no
// value in it can close the data block or open markup.
func Render(w io.Writer, report []byte) error {
	if !json.Valid(report) {
		return errors.New("viewer: the report isn't valid JSON")
	}
	i := bytes.Index(page, []byte(placeholder))
	if i < 0 {
		return errors.New("viewer: the page has no report placeholder")
	}
	var data bytes.Buffer
	json.HTMLEscape(&data, report)
	open := len(placeholder) - len("</script>")
	for _, part := range [][]byte{page[:i+open], data.Bytes(), page[i+open:]} {
		if _, err := w.Write(part); err != nil {
			return err
		}
	}
	return nil
}
