package analyst

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/config"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

const testSession = "test-browser-session"

// testConsole returns a console whose session the test client has already
// claimed; request sends that client's cookie.
func testConsole(t *testing.T, run func(context.Context, config.Config, func(collector.Result)) (output.Report, error)) (*console, *httptest.Server) {
	return testConsoleWith(t, run, true, nil)
}

// testConsoleWith returns a console that is either already claimed or still
// waiting for its first browser, with an optional operator-warning hook.
func testConsoleWith(t *testing.T, run func(context.Context, config.Config, func(collector.Result)) (output.Report, error), claimed bool, warn func(string)) (*console, *httptest.Server) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	c := &console{ctx: ctx, stop: stop, prefix: "/test-session/", session: testSession, claimed: claimed, opts: Options{Version: "test", Directory: t.TempDir(), Run: run, Warn: warn}}
	s := httptest.NewUnstartedServer(c)
	c.host = s.Listener.Addr().String()
	c.origin = "http://" + c.host
	s.Start()
	t.Cleanup(func() { stop(); s.Close(); c.workers.Wait() })
	return c, s
}
func request(t *testing.T, s *httptest.Server, c *console, method, path, body string) (int, []byte, http.Header) {
	t.Helper()
	r, err := http.NewRequest(method, s.URL+c.prefix+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: testSession})
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", c.origin)
	}
	response, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data, response.Header
}

func TestConsoleRejectsForeignRequestsAndCommands(t *testing.T) {
	c, s := testConsole(t, nil)
	for _, test := range []struct {
		name, path, origin, host, kind, body string
		code                                 int
	}{
		{"host", "api/info", "", "attacker.example", "", "", 421},
		{"origin", "api/jobs", "https://attacker.example", "", "application/json", `{"profile":"quick"}`, 403},
		{"form", "api/jobs", "", "", "text/plain", `{"profile":"quick"}`, 415},
		{"command", "api/jobs", "", "", "application/json", `{"profile":"quick","command":"whoami"}`, 400},
		{"path", "api/jobs", "", "", "application/json", `{"profile":"quick","out":"/tmp/replace"}`, 400},
		{"profile", "api/jobs", "", "", "application/json", `{"profile":"memory"}`, 400},
		{"extra JSON", "api/jobs", "", "", "application/json", `{"profile":"quick"} {}`, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			method := http.MethodPost
			if test.path == "api/info" {
				method = http.MethodGet
			}
			r := httptest.NewRequest(method, s.URL+c.prefix+test.path, strings.NewReader(test.body))
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: testSession})
			r.Host = c.host
			if test.host != "" {
				r.Host = test.host
			}
			r.Header.Set("Origin", test.origin)
			r.Header.Set("Content-Type", test.kind)
			w := httptest.NewRecorder()
			c.ServeHTTP(w, r)
			if w.Code != test.code {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, s.URL+"/wrong-session/api/info", nil)
	r.Host = c.host
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("session path was not required")
	}
	code, data, header := request(t, s, c, "GET", "", "")
	if code != 200 || !strings.Contains(string(data), "Start an investigation") || !strings.Contains(header.Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatal("console page or policy missing")
	}
}

func TestCancellationKeepsReportAndSeparatesDownloads(t *testing.T) {
	configs := make(chan config.Config, 1)
	c, s := testConsole(t, func(ctx context.Context, cfg config.Config, progress func(collector.Result)) (output.Report, error) {
		configs <- cfg
		<-ctx.Done()
		result := collector.Result{Collector: cfg.Collectors[0], Records: []collector.Record{{Fields: map[string]any{"name": "sample"}}}, Errors: []string{"cancelled"}}
		progress(result)
		rep := output.Report{Tool: "liveresponse-ng", Schema: output.SchemaVersion, Host: "fixture", RunID: "cancelled", Run: output.RunInfo{Interrupted: true}, Results: []collector.Result{result}}
		_, err := output.WriteFile(cfg.Output, rep, "json", true, false)
		return rep, err
	})
	code, data, header := request(t, s, c, "POST", "api/jobs", `{"profile":"quick","case":"../../not-a-path"}`)
	if code != 202 || !strings.Contains(header.Get("Content-Type"), "application/json") {
		t.Fatalf("start %d: %s", code, data)
	}
	var started job
	if err := json.Unmarshal(data, &started); err != nil {
		t.Fatal(err)
	}
	cfg := <-configs
	if !cfg.NoDNS || !cfg.Graph || !cfg.Timeline || !cfg.IOCs || !cfg.Intel || cfg.Adaptive || cfg.Force || cfg.MemIncludeLsass || cfg.YaraRules != "" || !strings.HasPrefix(cfg.Output, c.opts.Directory+string(filepath.Separator)) {
		t.Fatalf("profile escaped boundaries: %+v", cfg)
	}
	for _, name := range cfg.Collectors {
		if name == "memory" || name == "dnscache" {
			t.Fatal("intrusive opt-in collector selected")
		}
	}
	if code, _, _ := request(t, s, c, "POST", "api/jobs", `{"profile":"quick"}`); code != 409 {
		t.Fatal("overlapping collection accepted")
	}
	if code, _, _ := request(t, s, c, "POST", "api/close", `{}`); code != 409 {
		t.Fatal("closed over active collection")
	}
	if code, _, _ := request(t, s, c, "GET", "api/jobs/"+started.ID+"/report.json", ""); code != 409 {
		t.Fatal("unfinished report served")
	}
	if code, _, _ := request(t, s, c, "POST", "api/jobs/"+started.ID+"/cancel", `{}`); code != 200 {
		t.Fatal("cancel rejected")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, data, _ = request(t, s, c, "GET", "api/jobs", "")
		var jobs []job
		_ = json.Unmarshal(data, &jobs)
		if jobs[0].State == "partial" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancel did not finish: %s", data)
		}
		time.Sleep(10 * time.Millisecond)
	}
	code, data, _ = request(t, s, c, "GET", "api/jobs/"+started.ID+"/report.json", "")
	if code != 200 || !strings.Contains(string(data), `"interrupted": true`) {
		t.Fatalf("partial report lost: %d %s", code, data)
	}
	_, manifest, _ := request(t, s, c, "GET", "api/jobs/"+started.ID+"/checksum", "")
	if string(manifest) != fmt.Sprintf("%x  %s-report.json\n", sha256.Sum256(data), started.ID) {
		t.Fatal("checksum does not match downloaded file")
	}
	code, html, _ := request(t, s, c, "GET", "api/jobs/"+started.ID+"/report.html", "")
	if code != 200 || !strings.Contains(string(html), `id="lrng-report">{`) || !strings.Contains(string(html), "default-src 'none'") {
		t.Fatal("viewer or offline policy missing")
	}
	if _, err := os.Stat(cfg.Output + ".sha256"); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := request(t, s, c, "GET", "api/jobs/../../report.json", ""); code != 404 {
		t.Fatal("unknown file path served")
	}
}

func TestServeUsesLoopbackAndCloses(t *testing.T) {
	ready := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- Serve(ctx, Options{Directory: t.TempDir(), Run: func(context.Context, config.Config, func(collector.Result)) (output.Report, error) {
			return output.Report{}, nil
		}, Ready: func(url string) { ready <- url }})
	}()
	var url string
	select {
	case url = <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("console did not start")
	}
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatal("not loopback", url)
	}
	closeWith := func(client *http.Client) int {
		r, _ := http.NewRequest("POST", url+"api/close", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	// Knowing the address is not enough to drive the console.
	if code := closeWith(http.DefaultClient); code != 403 {
		t.Fatal("console closed by a client that never opened it", code)
	}
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	page, err := browser.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	page.Body.Close()
	if page.StatusCode != 200 {
		t.Fatal("console page refused its first browser", page.StatusCode)
	}
	if code := closeWith(browser); code != 200 {
		t.Fatal("close failed", code)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("console did not close")
	}
}

// The console address reaches the browser on a command line that other local
// accounts can read, so it must not work as a credential on its own.
func TestConsoleBindsToFirstBrowser(t *testing.T) {
	var mu sync.Mutex
	var warnings []string
	c, s := testConsoleWith(t, nil, false, func(message string) { mu.Lock(); warnings = append(warnings, message); mu.Unlock() })
	do := func(client *http.Client, method, path, cookie string) (int, string) {
		t.Helper()
		r, err := http.NewRequest(method, s.URL+c.prefix+path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
		}
		if cookie != "" {
			r.Header.Set("Cookie", cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(data)
	}
	other := &http.Client{}

	// Nothing but the console page itself answers before a browser opens it.
	if code, _ := do(other, "GET", "api/info", ""); code != 403 {
		t.Fatal("API served before any browser opened the console", code)
	}

	// The first page load claims the session with a narrowly scoped cookie.
	jar, _ := cookiejar.New(nil)
	analyst := &http.Client{Jar: jar}
	r, _ := http.NewRequest("GET", s.URL+c.prefix, nil)
	response, err := analyst.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("first browser refused", response.StatusCode)
	}
	var issued *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == sessionCookie {
			issued = cookie
		}
	}
	if issued == nil || issued.Value != testSession || !issued.HttpOnly || issued.SameSite != http.SameSiteStrictMode || issued.Path != c.prefix {
		t.Fatalf("session cookie missing or too broad: %+v", issued)
	}

	// The claimant keeps working: page reloads, API calls and report routes.
	for _, path := range []string{"", "api/info", "api/jobs", "console.js", "demo"} {
		if code, _ := do(analyst, "GET", path, ""); code != 200 {
			t.Fatalf("claimant refused %q: %d", path, code)
		}
	}

	// Anyone else with the address is refused everywhere, with an explanation,
	// and so is a guessed or empty cookie.
	for _, attempt := range []struct{ method, path, cookie string }{
		{"GET", "", ""}, {"GET", "api/info", ""}, {"GET", "api/jobs", ""}, {"GET", "console.js", ""},
		{"GET", "viewer", ""}, {"POST", "api/jobs", ""}, {"POST", "api/close", ""},
		{"GET", "api/jobs", sessionCookie + "=guess"}, {"GET", "api/jobs", sessionCookie + "="},
	} {
		code, body := do(other, attempt.method, attempt.path, attempt.cookie)
		if code != 403 || !strings.Contains(body, "already open in another browser") {
			t.Fatalf("%s %q with cookie %q: %d %s", attempt.method, attempt.path, attempt.cookie, code, body)
		}
	}

	// The operator is warned once, not once per request.
	mu.Lock()
	defer mu.Unlock()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "possible sign of compromise") {
		t.Fatalf("terminal warnings: %q", warnings)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refused != 10 {
		t.Fatalf("refused %d requests, want 10", c.refused)
	}
}
