// Package analyst provides a local, single-operator collection console.
// Its HTTP interface accepts named profiles, never shell commands or paths.
package analyst

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/config"
	"github.com/jp101216/liveresponse-ng/internal/hostinfo"
	"github.com/jp101216/liveresponse-ng/internal/output"
	"github.com/jp101216/liveresponse-ng/viewer"
)

//go:embed console.html console.css console.js
var assets embed.FS

// Options supplies the collection engine and optional storage/ready hooks.
// Warn, when set, receives operator warnings such as a refused request from
// something other than the browser that opened the console.
type Options struct {
	Version   string
	Directory string
	Run       func(context.Context, config.Config, func(collector.Result)) (output.Report, error)
	Ready     func(string)
	Warn      func(string)
}

// sessionCookie carries the secret that binds the console to the first
// browser that opens its address.
const sessionCookie = "lrng_console"

const refusedMessage = `This console is already open in another browser. Only the browser that first opened its address can use it.

If you opened it yourself, return to that browser. If you did not, another program or user on this computer may have copied the console address: stop the console and treat this as a possible sign of compromise.
`

const refusedWarning = "Warning: the analyst console refused a request that did not come from the browser that opened it. " +
	"If you did not open the console in a second browser, another program or user on this computer may have its address. " +
	"Stop the console (Ctrl+C) and treat this as a possible sign of compromise."

type profile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Collectors  []string `json:"collectors"`
}

func profiles() []profile {
	filter := func(names ...string) []string {
		var out []string
		for _, n := range names {
			if _, ok := collector.Lookup(n); ok {
				out = append(out, n)
			}
		}
		return out
	}
	var defaults []string
	for _, c := range collector.Defaults() {
		defaults = append(defaults, c.Name())
	}
	return []profile{
		{"quick", "Quick triage", "Start with processes, connections, startup entries, services and host defenses.", filter("processes", "network", "autoruns", "services", "defenses")},
		{"full", "Full triage", "Collect all standard artifacts available on this operating system, with the bundled event-log rules.", defaults},
		{"persistence", "Persistence review", "Focus on programs and settings that can keep running after a restart or sign-in.", filter("processes", "autoruns", "services", "scheduledtasks", "wmi", "drivers", "aiagents")},
	}
}

type completed struct {
	Name    string `json:"name"`
	Records int    `json:"records"`
	Errors  int    `json:"errors"`
}
type job struct {
	ID        string      `json:"id"`
	Case      string      `json:"case"`
	Profile   string      `json:"profile"`
	State     string      `json:"state"`
	Started   time.Time   `json:"started"`
	Finished  *time.Time  `json:"finished,omitempty"`
	Total     int         `json:"total"`
	Completed []completed `json:"completed"`
	Findings  int         `json:"findings"`
	Error     string      `json:"error,omitempty"`
	Path      string      `json:"path"`
	cancel    context.CancelFunc
	ready     bool
}
type console struct {
	opts                 Options
	ctx                  context.Context
	stop                 context.CancelFunc
	host, origin, prefix string
	session              string // cookie value given to the first browser
	mu                   sync.Mutex
	claimed              bool // guarded by mu
	refused              int  // guarded by mu
	jobs                 []*job
	workers              sync.WaitGroup
}

func randomID() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Serve listens only on IPv4 loopback at an OS-selected port. A random session
// path, exact Host checking, Origin checking, JSON-only mutations, and no CORS
// keep ordinary websites from invoking the collector through the browser.
//
// The session path is not a credential on its own. The console address reaches
// the browser on a command line, which any local account can read on Linux, so
// the first load of the console page claims the session with an HttpOnly
// cookie and every later request must carry it. See authorize.
func Serve(ctx context.Context, opts Options) error {
	if opts.Run == nil {
		return errors.New("analyst console needs a collection engine")
	}
	if opts.Directory == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		opts.Directory = filepath.Join(home, "LiveResponse-NG", "Reports")
	}
	var err error
	opts.Directory, err = filepath.Abs(opts.Directory)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(opts.Directory, 0o700); err != nil {
		return fmt.Errorf("create report folder: %w", err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	token, err := randomID()
	if err != nil {
		return err
	}
	session, err := randomID()
	if err != nil {
		return err
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	c := &console{opts: opts, ctx: ctx, stop: stop, host: ln.Addr().String(), prefix: "/" + token + "/", session: session}
	c.origin = "http://" + c.host
	srv := &http.Server{Handler: c, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	if opts.Ready != nil {
		opts.Ready(c.origin + c.prefix)
	}
	select {
	case <-ctx.Done():
	case err = <-done:
		stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	wait := make(chan struct{})
	go func() { c.workers.Wait(); close(wait) }()
	select {
	case <-wait:
	case <-time.After(10 * time.Second):
	}
	c.mu.Lock()
	refused := c.refused
	c.mu.Unlock()
	if refused > 1 && opts.Warn != nil {
		opts.Warn(fmt.Sprintf("The analyst console refused %d requests that did not come from the browser that opened it.", refused))
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (c *console) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	if r.Host != c.host {
		http.Error(w, "Use the local console address.", http.StatusMisdirectedRequest)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != c.origin {
		http.Error(w, "Foreign origin rejected.", http.StatusForbidden)
		return
	}
	if len(r.URL.Path) < len(c.prefix) || subtle.ConstantTimeCompare([]byte(r.URL.Path[:len(c.prefix)]), []byte(c.prefix)) != 1 {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, c.prefix)
	if !c.authorize(w, r, path) {
		return
	}
	if r.Method == http.MethodPost {
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "JSON required.", http.StatusUnsupportedMediaType)
			return
		}
	} else if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	if path == "api/jobs" && r.Method == http.MethodPost {
		c.start(w, r)
		return
	}
	if path == "api/close" && r.Method == http.MethodPost {
		c.mu.Lock()
		busy := c.busy()
		c.mu.Unlock()
		if busy {
			http.Error(w, "Stop the active collection before closing.", http.StatusConflict)
			return
		}
		writeJSON(w, map[string]bool{"closed": true})
		c.stop()
		return
	}
	if path == "api/info" && r.Method == http.MethodGet {
		host, _ := os.Hostname()
		elevated, err := hostinfo.Elevated()
		elevation := "unknown"
		if err == nil {
			elevation = fmt.Sprint(elevated)
		}
		writeJSON(w, map[string]any{"host": host, "os": runtime.GOOS, "arch": runtime.GOARCH, "version": c.opts.Version, "elevated": elevation, "directory": c.opts.Directory, "profiles": profiles()})
		return
	}
	if path == "api/jobs" && r.Method == http.MethodGet {
		c.mu.Lock()
		defer c.mu.Unlock()
		writeJSON(w, c.jobs)
		return
	}
	if strings.HasPrefix(path, "api/jobs/") {
		c.jobRequest(w, r, strings.TrimPrefix(path, "api/jobs/"))
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	switch path {
	case "viewer", "demo":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(viewer.Page())
	case "", "console.js", "console.css":
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		file, kind := path, "text/html; charset=utf-8"
		if file == "" {
			file = "console.html"
		} else if file == "console.js" {
			kind = "text/javascript; charset=utf-8"
		} else {
			kind = "text/css; charset=utf-8"
		}
		data, _ := assets.ReadFile(file)
		w.Header().Set("Content-Type", kind)
		_, _ = w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

// authorize binds the console to one browser. The session path reaches the
// browser on a command line (rundll32 or xdg-open, then the browser itself),
// where on Linux every local account can read it from /proc, so knowing the
// path is not enough. The first GET of the console page claims the session and
// receives an HttpOnly, SameSite=Strict cookie scoped to the session path.
// Every later request must present it: the claimant's page loads, API calls,
// report tabs and downloads all carry it automatically. Anything else is
// refused with an explanation, and the operator's terminal is warned once.
//
// The first page load wins. If another account races the browser to it, the
// analyst's own browser is refused and the terminal shows the warning, which
// is the signal to stop the console and treat the host as compromised.
func (c *console) authorize(w http.ResponseWriter, r *http.Request, path string) bool {
	if cookie, err := r.Cookie(sessionCookie); err == nil && c.session != "" &&
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(c.session)) == 1 {
		return true
	}
	c.mu.Lock()
	claim := !c.claimed && c.session != "" && path == "" && r.Method == http.MethodGet
	first := false
	if claim {
		c.claimed = true
	} else {
		c.refused++
		first = c.refused == 1
	}
	c.mu.Unlock()
	if claim {
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: c.session, Path: c.prefix, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		return true
	}
	if first && c.opts.Warn != nil {
		c.opts.Warn(refusedWarning)
	}
	http.Error(w, refusedMessage, http.StatusForbidden)
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (c *console) busy() bool {
	for _, j := range c.jobs {
		if j.State == "running" || j.State == "stopping" {
			return true
		}
	}
	return false
}
func (c *console) start(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Profile string `json:"profile"`
		Case    string `json:"case"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid collection request.", http.StatusBadRequest)
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		http.Error(w, "One request at a time.", http.StatusBadRequest)
		return
	}
	if len(req.Case) > 120 || strings.ContainsAny(req.Case, "\r\n\x00") {
		http.Error(w, "Case label must fit on one line (120 bytes).", http.StatusBadRequest)
		return
	}
	var chosen *profile
	for _, p := range profiles() {
		if p.ID == req.Profile {
			copy := p
			chosen = &copy
		}
	}
	if chosen == nil || len(chosen.Collectors) == 0 {
		http.Error(w, "Choose an available collection profile.", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil || c.busy() {
		http.Error(w, "A collection is already running or the console is closing.", http.StatusConflict)
		return
	}
	if len(c.jobs) >= 16 {
		http.Error(w, "Session history is full. Close and reopen the console; saved reports remain on disk.", http.StatusConflict)
		return
	}
	id, err := randomID()
	if err != nil {
		http.Error(w, "Could not allocate a collection.", http.StatusInternalServerError)
		return
	}
	dir := filepath.Join(c.opts.Directory, time.Now().UTC().Format("20060102T150405Z")+"-"+id[:12])
	if err = os.Mkdir(dir, 0o700); err != nil {
		http.Error(w, "Cannot create a new report folder.", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, 20*time.Minute)
	j := &job{ID: id, Case: strings.TrimSpace(req.Case), Profile: chosen.Name, State: "running", Started: time.Now().UTC(), Total: len(chosen.Collectors), Completed: []completed{}, Path: filepath.Join(dir, "report.json"), cancel: cancel}
	c.jobs = append(c.jobs, j)
	cfg := config.Default()
	cfg.Collectors = chosen.Collectors
	cfg.NoDNS, cfg.Timeline, cfg.IOCs, cfg.Graph, cfg.Intel, cfg.Quiet = true, true, true, true, true, true
	cfg.Output = j.Path
	if req.Profile == "full" {
		for _, n := range chosen.Collectors {
			if n == "eventlog" {
				cfg.SigmaRules = "builtin"
			}
		}
	}
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		defer cancel()
		rep, err := c.opts.Run(ctx, cfg, func(r collector.Result) {
			c.mu.Lock()
			defer c.mu.Unlock()
			j.Completed = append(j.Completed, completed{r.Collector, len(r.Records), len(r.Errors)})
		})
		c.mu.Lock()
		defer c.mu.Unlock()
		finished := time.Now().UTC()
		j.Finished = &finished
		if err != nil {
			j.State = "failed"
			j.Error = err.Error()
			return
		}
		j.ready = true
		j.State = "complete"
		for _, result := range rep.Results {
			if len(result.Errors) > 0 {
				j.State = "partial"
			}
			for _, rec := range result.Records {
				j.Findings += len(rec.Findings)
			}
		}
		if ctx.Err() != nil || rep.Run.Interrupted {
			j.State = "partial"
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, j)
}

func (c *console) jobRequest(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	c.mu.Lock()
	var target *job
	for _, j := range c.jobs {
		if j.ID == parts[0] {
			target = j
			break
		}
	}
	if target == nil {
		c.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if parts[1] == "cancel" && r.Method == http.MethodPost {
		if target.State == "running" {
			target.State = "stopping"
			target.cancel()
		}
		writeJSON(w, target)
		c.mu.Unlock()
		return
	}
	ready, file := target.ready, target.Path
	c.mu.Unlock()
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	if !ready {
		http.Error(w, "The report is not ready yet.", http.StatusConflict)
		return
	}
	info, err := os.Stat(file)
	if err != nil || info.Size() > 192<<20 {
		http.Error(w, "Report unavailable or larger than the 192 MiB viewer limit; use the saved file with offline tools.", http.StatusConflict)
		return
	}
	data, err := os.ReadFile(file)
	if err != nil {
		http.Error(w, "Cannot read the saved report.", http.StatusInternalServerError)
		return
	}
	switch parts[1] {
	case "report.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", `attachment; filename="`+target.ID+`-report.html"`)
		}
		if err := viewer.Render(w, data); err != nil {
			return
		}
	case "report.json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+target.ID+`-report.json"`)
		_, _ = w.Write(data)
	case "checksum":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+target.ID+`-report.json.sha256"`)
		sum := sha256.Sum256(data)
		_, _ = fmt.Fprintf(w, "%x  %s-report.json\n", sum, target.ID)
	default:
		http.NotFound(w, r)
	}
}
