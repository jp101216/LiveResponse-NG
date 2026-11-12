package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// aiagents.go — how the AI agents on a host are set up: the MCP servers each
// AI client starts or reaches (Claude Desktop, Claude Code, Cursor, VS Code,
// Windsurf, Cline, Roo Code, Gemini CLI, Codex, Zed), the shell hooks Claude
// Code runs, and the instruction files agents read from projects (CLAUDE.md,
// AGENTS.md, .cursorrules, copilot-instructions.md…), checked for text a
// person reading them can't see.
//
// An MCP server is a program an AI client starts by itself, with the user's
// rights, every time it starts: an autostart that no other autostart list
// shows, and a supply-chain entry point (a server fetched from a URL at each
// start runs whatever is published there that day). Instruction files are
// prompts: an agent follows them, so text hidden in one with Unicode tag
// characters, bidirectional controls or zero-width characters steers the
// agent without the developer seeing it (the "rules file backdoor").
//
// Portable: the per-OS files list the home directories and where each client
// keeps its configuration.

type aiAgentsCollector struct{}

func (*aiAgentsCollector) Name() string           { return "aiagents" }
func (*aiAgentsCollector) Platforms() []string    { return []string{"windows", "linux"} }
func (*aiAgentsCollector) Timeout() time.Duration { return 2 * time.Minute }

func (*aiAgentsCollector) Collect(ctx context.Context) (Result, error) {
	return collectAIAgents(ctx, aiHomes(), aiClientConfigs, aiSystemConfigs), nil
}

func init() { Register(func() Collector { return &aiAgentsCollector{} }) }

// aiClientConfig is where an AI client keeps its MCP servers or hooks.
type aiClientConfig struct {
	Client string
	Path   string // relative to a home directory (absolute for system-wide files), "/"-separated
	TOML   bool   // Codex's config.toml
}

// Bounds on the sweep for project instruction files.
var (
	aiWalkDepth      = 6      // directory levels below a home
	aiWalkMaxEntries = 400000 // directory entries visited across all homes
	aiMaxAgentFiles  = 500    // instruction files recorded
	aiMaxFileBytes   = int64(2 << 20)
)

// aiSkipDirs are directory names the sweep doesn't enter: package caches,
// build output, virtual environments and editors' own extension stores are
// large and hold other people's files, not the user's projects.
var aiSkipDirs = set("node_modules", ".git", ".hg", ".svn", "appdata", "library", ".cache", ".npm", ".pnpm-store", ".yarn",
	".cargo", ".rustup", ".m2", ".gradle", ".nuget", "site-packages", "dist-packages", ".venv", "venv", "__pycache__", ".tox",
	"target", ".vscode-server", ".cursor-server", ".windsurf-server", "extensions", "$recycle.bin", ".trash", "trash", "snap",
	".local", ".conda", "anaconda3", "miniconda3", ".pyenv", ".nvm", ".rbenv", ".gem", ".docker", "go")

// mcpServer is one MCP server an AI client is set to start or reach.
type mcpServer struct {
	Client, Config, Name string
	Scope                string // "project <path>" for a per-project server in Claude Code's file
	Command              string
	Args                 []string
	URL                  string
	EnvNames             []string // names only: the values are usually API keys
	Disabled             bool
}

// agentHook is a shell command an agent runs on an event (Claude Code hooks).
type agentHook struct {
	Client, Config, Event, Matcher, Command string
}

// collectAIAgents reads every home's client configurations, then sweeps the
// homes for project instruction files and project configurations.
func collectAIAgents(ctx context.Context, homes []string, configs []aiClientConfig, system []aiClientConfig) Result {
	res := NewResult("aiagents")
	seen := map[string]bool{}
	servers, hooks := 0, 0
	readConfig := func(client, path string, toml bool) {
		key := pathKey(filepath.Clean(path))
		if seen[key] {
			return
		}
		seen[key] = true
		data, err := readBounded(path, aiMaxFileBytes)
		if err != nil {
			if !os.IsNotExist(err) {
				res.Fail(path + ": " + err.Error())
			}
			return
		}
		ss, hs, err := parseAIConfig(client, path, data, toml)
		if err != nil {
			res.Fail(path + ": " + err.Error())
		}
		for _, s := range ss {
			res.Add(s.fields(), judgeMCPServer(s)...)
		}
		for _, h := range hs {
			res.Add(h.fields(), judgeAgentHook(h)...)
		}
		servers += len(ss)
		hooks += len(hs)
		if fs := hiddenTextFindings(path, string(data)); len(fs) > 0 {
			res.Add(map[string]any{"kind": "agent_config", "client": client, "path": path}, fs...)
		}
	}
	for _, c := range system {
		readConfig(c.Client, filepath.FromSlash(c.Path), c.TOML)
	}
	for _, home := range homes {
		for _, c := range configs {
			readConfig(c.Client, filepath.Join(home, filepath.FromSlash(c.Path)), c.TOML)
		}
	}

	// Project instruction files and project-level configurations.
	visited, recorded, truncated := 0, 0, false
	for _, home := range homes {
		if ctx.Err() != nil || truncated {
			break
		}
		base := strings.Count(filepath.Clean(home), string(filepath.Separator))
		_ = filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			visited++
			if visited > aiWalkMaxEntries {
				truncated = true
				return filepath.SkipAll
			}
			name := d.Name()
			if d.IsDir() {
				if path != home && (aiSkipDirs[strings.ToLower(name)] ||
					strings.Count(path, string(filepath.Separator))-base > aiWalkDepth) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			parent := filepath.Base(filepath.Dir(path))
			grand := filepath.Base(filepath.Dir(filepath.Dir(path)))
			if client, toml, ok := projectConfigKind(name, parent); ok {
				readConfig(client, path, toml)
				return nil
			}
			kind := agentFileKind(name, parent, grand)
			if kind == "" {
				return nil
			}
			if recorded >= aiMaxAgentFiles {
				truncated = true
				return nil
			}
			recorded++
			fields := map[string]any{"kind": "agent_instructions", "type": kind, "path": path}
			var findings []Finding
			if info, err := d.Info(); err == nil {
				fields["size"] = info.Size()
				fields["modified"] = info.ModTime().UTC()
			}
			if data, err := readBounded(path, aiMaxFileBytes); err == nil {
				findings = hiddenTextFindings(path, string(data))
			} else {
				fields["read_error"] = err.Error()
			}
			res.Add(fields, findings...)
			return nil
		})
	}
	res.SetMeta("homes", homes)
	res.SetMeta("mcp_servers", servers)
	res.SetMeta("agent_hooks", hooks)
	res.SetMeta("instruction_files", recorded)
	res.SetMeta("entries_visited", visited)
	if truncated {
		res.SetMeta("sweep_truncated", true)
		res.SetMeta("note", fmt.Sprintf("the sweep for project instruction files stopped at %d directory entries or %d files",
			aiWalkMaxEntries, aiMaxAgentFiles))
	}
	if ctx.Err() != nil {
		res.Fail("cancelled: " + ctx.Err().Error())
	}
	return res.Finish()
}

// readBounded reads a whole file of at most max bytes.
func readBounded(path string, max int64) ([]byte, error) {
	f, st, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size() > max {
		return nil, fmt.Errorf("%d bytes, larger than the %d-byte cap", st.Size(), max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than the %d-byte cap", max)
	}
	return b, nil
}

// projectConfigKind recognises the MCP and settings files a project carries.
func projectConfigKind(name, parent string) (client string, toml, ok bool) {
	n, p := strings.ToLower(name), strings.ToLower(parent)
	switch {
	case n == ".mcp.json":
		return "Claude Code (project)", false, true
	case n == "mcp.json" && p == ".cursor":
		return "Cursor (project)", false, true
	case n == "mcp.json" && p == ".vscode":
		return "VS Code (project)", false, true
	case (n == "settings.json" || n == "settings.local.json") && p == ".claude":
		return "Claude Code (project)", false, true
	case n == "settings.json" && p == ".gemini":
		return "Gemini CLI (project)", false, true
	case n == "config.toml" && p == ".codex":
		return "Codex (project)", true, true
	}
	return "", false, false
}

// agentFileKind names the kind of an agent instruction file, "" if the file
// isn't one.
func agentFileKind(name, parent, grand string) string {
	n, p, g := strings.ToLower(name), strings.ToLower(parent), strings.ToLower(grand)
	switch n {
	case ".cursorrules", ".windsurfrules", ".clinerules", ".roorules", ".continuerules", ".goosehints",
		"claude.md", "claude.local.md", "agents.md", "gemini.md":
		return n
	case "copilot-instructions.md":
		if p == ".github" {
			return ".github/copilot-instructions.md"
		}
	}
	switch {
	case strings.HasSuffix(n, ".mdc") && p == "rules" && g == ".cursor":
		return ".cursor/rules"
	case strings.HasSuffix(n, ".instructions.md") && p == "instructions" && g == ".github":
		return ".github/instructions"
	case strings.HasSuffix(n, ".prompt.md") && p == "prompts" && g == ".github":
		return ".github/prompts"
	case strings.HasSuffix(n, ".md") && (p == "commands" || p == "agents") && g == ".claude":
		return ".claude/" + p
	case strings.HasSuffix(n, ".md") && (p == ".clinerules" || p == ".windsurfrules" || p == ".roo" || p == "rules" && g == ".windsurf"):
		return p
	}
	return ""
}

// stripJSONC turns JSON with comments and trailing commas (VS Code's and
// Zed's settings) into JSON: comments go first, then commas that close
// nothing.
func stripJSONC(b []byte) []byte {
	return dropTrailingCommas(dropComments(b))
}

// dropComments removes // and /* */ comments outside strings.
func dropComments(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	return out
}

// dropTrailingCommas removes each comma whose next significant character
// closes an object or array.
func dropTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			out = append(out, c)
			continue
		}
		if c == '"' {
			inStr = true
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\r' || b[j] == '\n') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// parseAIConfig reads the MCP servers and hooks out of one client
// configuration, with anything that looks like a credential in their
// arguments, URLs and commands redacted.
func parseAIConfig(client, path string, data []byte, toml bool) ([]mcpServer, []agentHook, error) {
	servers, hooks, err := parseAIConfigRaw(client, path, data, toml)
	for i := range servers {
		servers[i].Command = redactSecrets(servers[i].Command)
		servers[i].Args = redactArgs(servers[i].Args)
		servers[i].URL = redactURL(servers[i].URL)
	}
	for i := range hooks {
		hooks[i].Command = redactSecrets(hooks[i].Command)
	}
	return servers, hooks, err
}

// Credentials in configuration: well-known token shapes, "name=value" and
// "name: value" pairs whose name says secret, and the argument after a flag
// whose name does.
var (
	reSecretToken = regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|` +
		`xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|` +
		`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	reSecretAssign = regexp.MustCompile(`(?i)((?:api[_-]?key|access[_-]?key|token|secret|password|passwd|authorization|bearer|credential)s?["']?\s*[=:]\s*["']?(?:bearer\s+)?)[^\s"'&]+`)
	reSecretFlag   = regexp.MustCompile(`(?i)^--?[a-z0-9_-]*(?:key|token|secret|password|passwd|auth|credential)[a-z0-9_-]*$`)
	reSecretParam  = regexp.MustCompile(`(?i)key|token|secret|password|passwd|auth|sig|credential`)
)

// redactSecrets replaces credential-shaped text with "[redacted]".
func redactSecrets(s string) string {
	s = reSecretToken.ReplaceAllString(s, "[redacted]")
	return reSecretAssign.ReplaceAllString(s, "${1}[redacted]")
}

// redactArgs redacts each argument, and the value after a secret-named flag.
func redactArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	for i, a := range args {
		if i > 0 && reSecretFlag.MatchString(args[i-1]) && !strings.HasPrefix(a, "-") {
			out[i] = "[redacted]"
			continue
		}
		out[i] = redactSecrets(a)
	}
	return out
}

// redactURL drops a URL's password and redacts query values whose names say
// secret.
func redactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return redactSecrets(raw)
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), "redacted")
	}
	q := u.Query()
	changed := false
	for k := range q {
		if reSecretParam.MatchString(k) {
			q.Set(k, "redacted")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return redactSecrets(u.String())
}

func parseAIConfigRaw(client, path string, data []byte, toml bool) ([]mcpServer, []agentHook, error) {
	if toml {
		return parseCodexTOML(client, path, string(data)), nil, nil
	}
	data = []byte(strings.TrimPrefix(string(data), "\uFEFF"))
	var root map[string]any
	if err := json.Unmarshal(stripJSONC(data), &root); err != nil {
		return nil, nil, fmt.Errorf("not JSON: %v", err)
	}
	var servers []mcpServer
	add := func(m any, scope string) {
		obj, _ := m.(map[string]any)
		names := make([]string, 0, len(obj))
		for k := range obj {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			if s, ok := mcpServerFrom(obj[name]); ok {
				s.Client, s.Config, s.Name, s.Scope = client, path, name, scope
				servers = append(servers, s)
			}
		}
	}
	add(root["mcpServers"], "")
	add(root["context_servers"], "") // Zed
	if strings.HasSuffix(strings.ToLower(path), "mcp.json") {
		add(root["servers"], "") // VS Code's mcp.json
	}
	if m, ok := root["mcp"].(map[string]any); ok {
		add(m["servers"], "") // VS Code's settings.json
	}
	if projects, ok := root["projects"].(map[string]any); ok { // Claude Code's ~/.claude.json
		keys := make([]string, 0, len(projects))
		for k := range projects {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if p, ok := projects[k].(map[string]any); ok {
				add(p["mcpServers"], "project "+k)
			}
		}
	}
	var hooks []agentHook
	if hm, ok := root["hooks"].(map[string]any); ok {
		events := make([]string, 0, len(hm))
		for k := range hm {
			events = append(events, k)
		}
		sort.Strings(events)
		for _, ev := range events {
			groups, _ := hm[ev].([]any)
			for _, g := range groups {
				gm, _ := g.(map[string]any)
				matcher, _ := gm["matcher"].(string)
				list, _ := gm["hooks"].([]any)
				for _, h := range list {
					hmap, _ := h.(map[string]any)
					if cmd, _ := hmap["command"].(string); strings.TrimSpace(cmd) != "" {
						hooks = append(hooks, agentHook{Client: client, Config: path, Event: ev, Matcher: matcher, Command: cmd})
					}
				}
			}
		}
	}
	return servers, hooks, nil
}

// mcpServerFrom reads one server entry: a command (a string, or Zed's
// {path, args, env}), its arguments and environment, or a URL.
func mcpServerFrom(v any) (mcpServer, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return mcpServer{}, false
	}
	var s mcpServer
	strs := func(v any) []string {
		var out []string
		list, _ := v.([]any)
		for _, a := range list {
			if str, ok := a.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	envNames := func(v any) []string {
		env, _ := v.(map[string]any)
		out := make([]string, 0, len(env))
		for k := range env {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	switch c := m["command"].(type) {
	case string:
		s.Command = c
	case map[string]any: // Zed's older form
		s.Command, _ = c["path"].(string)
		s.Args = strs(c["args"])
		s.EnvNames = envNames(c["env"])
	}
	if a := strs(m["args"]); len(a) > 0 {
		s.Args = a
	}
	if e := envNames(m["env"]); len(e) > 0 {
		s.EnvNames = e
	}
	for _, k := range []string{"url", "serverUrl", "httpUrl"} {
		if u, ok := m[k].(string); ok && u != "" {
			s.URL = u
			break
		}
	}
	s.Disabled, _ = m["disabled"].(bool)
	if s.Command == "" && s.URL == "" {
		return mcpServer{}, false
	}
	return s, true
}

// parseCodexTOML reads [mcp_servers.<name>] tables out of Codex's
// config.toml: command, args, url and the env table's key names. Only the
// TOML that configuration uses (strings, arrays of strings, inline tables).
func parseCodexTOML(client, path, text string) []mcpServer {
	var out []mcpServer
	var cur *mcpServer
	inEnv := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.Trim(line, "[] ")
			inEnv = false
			rest, ok := strings.CutPrefix(section, "mcp_servers.")
			if !ok {
				cur = nil
				continue
			}
			name, sub, _ := strings.Cut(rest, ".")
			name = strings.Trim(name, `"'`)
			if cur == nil || cur.Name != name {
				out = append(out, mcpServer{Client: client, Config: path, Name: name})
				cur = &out[len(out)-1]
			}
			inEnv = sub == "env"
			continue
		}
		if cur == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if inEnv {
			cur.EnvNames = append(cur.EnvNames, strings.Trim(key, `"'`))
			continue
		}
		switch key {
		case "command":
			cur.Command = tomlString(value)
		case "url":
			cur.URL = tomlString(value)
		case "args":
			cur.Args = tomlStrings(value)
		case "env":
			for _, kv := range strings.Split(strings.Trim(value, "{} "), ",") {
				if k, _, ok := strings.Cut(kv, "="); ok {
					cur.EnvNames = append(cur.EnvNames, strings.Trim(strings.TrimSpace(k), `"'`))
				}
			}
		case "enabled":
			cur.Disabled = value == "false"
		}
	}
	kept := out[:0]
	for _, s := range out {
		if s.Command != "" || s.URL != "" {
			kept = append(kept, s)
		}
	}
	return kept
}

func tomlString(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		if end := strings.LastIndexByte(v, v[0]); end > 0 {
			s := v[1:end]
			if v[0] == '"' {
				s = strings.ReplaceAll(strings.ReplaceAll(s, `\\`, "\x00"), `\"`, `"`)
				s = strings.ReplaceAll(s, "\x00", `\`)
			}
			return s
		}
	}
	return v
}

func tomlStrings(v string) []string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "[") {
		return nil
	}
	var out []string
	for i := 1; i < len(v); i++ {
		if v[i] != '"' && v[i] != '\'' {
			continue
		}
		q := v[i]
		j := i + 1
		for j < len(v) && (v[j] != q || (q == '"' && v[j-1] == '\\')) {
			j++
		}
		if j >= len(v) {
			break
		}
		out = append(out, tomlString(v[i:j+1]))
		i = j
	}
	return out
}

func (s mcpServer) fields() map[string]any {
	f := map[string]any{"kind": "mcp_server", "client": s.Client, "config": s.Config, "name": s.Name}
	if s.Scope != "" {
		f["scope"] = s.Scope
	}
	if s.Command != "" {
		f["transport"] = "stdio"
		f["command"] = s.Command
		if len(s.Args) > 0 {
			f["args"] = s.Args
		}
	}
	if s.URL != "" {
		f["transport"] = "http"
		f["url"] = s.URL
	}
	if len(s.EnvNames) > 0 {
		f["env_names"] = s.EnvNames
	}
	if s.Disabled {
		f["disabled"] = true
	}
	return f
}

func (h agentHook) fields() map[string]any {
	f := map[string]any{"kind": "agent_hook", "client": h.Client, "config": h.Config, "event": h.Event, "command": h.Command}
	if h.Matcher != "" {
		f["matcher"] = h.Matcher
	}
	return f
}

// joinCommand renders a command and its arguments as one command line.
func joinCommand(cmd string, args []string) string {
	parts := []string{quoteArg(cmd)}
	for _, a := range args {
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " ")
}

func quoteArg(a string) string {
	if a == "" || strings.ContainsAny(a, " \t") {
		return `"` + a + `"`
	}
	return a
}

// packageRunners fetch a package and run it in one step.
var packageRunners = set("npx", "npx.cmd", "bunx", "pnpx", "uvx", "uvx.exe", "deno", "deno.exe", "pipx", "pipx.exe", "pnpm", "yarn", "bun", "bun.exe")

// remoteCodeSpec returns the argument by which a package runner fetches
// code from a URL or a git repository rather than a registry.
func remoteCodeSpec(cmd string, args []string) string {
	if !packageRunners[baseName(cmd)] {
		return ""
	}
	for _, a := range args {
		l := strings.ToLower(a)
		for _, p := range []string{"github:", "gitlab:", "bitbucket:", "gist:", "git+", "git://", "https://", "http://"} {
			if strings.HasPrefix(l, p) || strings.Contains(l, "="+p) {
				return a
			}
		}
		if strings.HasSuffix(l, ".tgz") || strings.HasSuffix(l, ".tar.gz") || strings.HasSuffix(l, ".whl") {
			return a
		}
	}
	return ""
}

// judgeMCPServer judges one configured MCP server.
func judgeMCPServer(s mcpServer) []Finding {
	where := fmt.Sprintf("MCP server %q in %s's configuration (%s)", s.Name, s.Client, s.Config)
	var out []Finding
	if s.Command != "" {
		line := joinCommand(s.Command, s.Args)
		out = append(out, aiCommandFindings(where+" runs a command that", s.Command, line)...)
		if lvl, why := aiPathRisk(s.Command); lvl == riskHigh {
			out = append(out, Finding{Rule: "ai.mcp_server_unusual_path", Severity: SevSuspect, Technique: "T1546", Confidence: 65,
				Detail: fmt.Sprintf("%s starts %s, in %s: the client runs it with the user's rights every time it starts", where, s.Command, why)})
		}
		if spec := remoteCodeSpec(s.Command, s.Args); spec != "" {
			out = append(out, Finding{Rule: "ai.mcp_server_remote_code", Severity: SevNotable, Technique: "T1195.002", Confidence: 45,
				Detail: fmt.Sprintf("%s fetches and runs %s each time the client starts: whatever is published there that day runs "+
					"with the user's rights, unpinned and unreviewed", where, spec)})
		}
	}
	if s.URL != "" {
		if f, ok := judgeMCPURL(where, s.URL); ok {
			out = append(out, f)
		}
	}
	return out
}

// judgeMCPURL judges a remote MCP server's address: a bare public IP, or
// plain HTTP to anything but this host or the local network.
func judgeMCPURL(where, raw string) (Finding, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return Finding{}, false
	}
	host := u.Hostname()
	ip, err := netip.ParseAddr(host)
	switch {
	case err == nil && publicIP(ip.String()):
		return Finding{Rule: "ai.mcp_server_url", Severity: SevSuspect, Technique: "T1071.001", Confidence: 55,
			Detail: fmt.Sprintf("%s is reached at a bare public IP address (%s): the tools it offers, and the instructions in their "+
				"descriptions, come from a host with no name behind it", where, raw)}, true
	case strings.EqualFold(u.Scheme, "http") && !(err == nil && (ip.IsLoopback() || ip.IsPrivate())) && !strings.EqualFold(host, "localhost"):
		return Finding{Rule: "ai.mcp_server_url", Severity: SevNotable, Technique: "T1071.001", Confidence: 40,
			Detail: fmt.Sprintf("%s is reached over plain HTTP (%s): anyone on the path can change the tools and their descriptions", where, raw)}, true
	}
	return Finding{}, false
}

// judgeAgentHook judges a hook command: the command analytics, and code run
// from a temporary or downloads folder.
func judgeAgentHook(h agentHook) []Finding {
	where := fmt.Sprintf("%s hook %s in %s", h.Client, h.Event, h.Config)
	out := aiCommandFindings(where+" runs a command that", "", h.Command)
	lvl, why, culprit := commandPathRisk(h.Command)
	if prog := firstProgram(h.Command); strings.HasPrefix(prog, "/") {
		lvl, why = unixPathRisk(prog)
		culprit = prog
	}
	if lvl == riskHigh {
		out = append(out, Finding{Rule: "ai.agent_hook_unusual_path", Severity: SevSuspect, Technique: "T1546", Confidence: 60,
			Detail: fmt.Sprintf("%s runs code from %s (%s) whenever the agent reaches that event", where, why, culprit)})
	}
	return out
}

// aiCommandFindings runs the Windows and the Unix command analytics both: AI
// client configs look the same on every OS, and nothing in an MCP server or
// hook entry says which shell will run it ("bash -c 'curl x | sh'" and a
// /dev/tcp reverse shell are Unix-only patterns; encoded PowerShell is not).
func aiCommandFindings(source, image, line string) []Finding {
	return mergeFindings(analyzeCommandLine(source, image, line), analyzeUnixCommandLine(source, image, line)...)
}

// aiPathRisk grades a program path by its shape: a POSIX path by the Unix
// rules (/tmp, /dev/shm, hidden home folders), anything else by Windows ones.
func aiPathRisk(p string) (riskLevel, string) {
	if strings.HasPrefix(p, "/") {
		return unixPathRisk(p)
	}
	return pathRisk(p)
}

// hiddenText is text in a file that a person reading it can't see.
type hiddenText struct {
	Tags      []rune // ASCII spelled out in Unicode tag characters
	TagCount  int
	Bidi      int    // bidirectional embeddings, overrides and isolates
	ZeroWidth int    // zero-width characters outside emoji and scripts that need them
	Carried   []byte // bytes carried by runs of variation selectors
}

// findHiddenText scans text for invisible content: Unicode tag characters
// (U+E0000-E007F, an invisible copy of ASCII), bidirectional controls,
// zero-width characters, and runs of variation selectors (which can carry a
// byte each: U+FE00-FE0F for 0-15, U+E0100-E01EF for 16-255).
func findHiddenText(s string) hiddenText {
	var h hiddenText
	runes := []rune(s)
	var run []byte
	flush := func() {
		if len(run) >= 4 {
			h.Carried = append(h.Carried, run...)
		}
		run = run[:0]
	}
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if end := flagTagSequenceEnd(runes, i); end > 0 {
			flush()
			i = end // a subdivision flag (England, Scotland, Wales): tag characters by design
			continue
		}
		switch {
		case r >= 0xFE00 && r <= 0xFE0F:
			run = append(run, byte(r-0xFE00))
			continue
		case r >= 0xE0100 && r <= 0xE01EF:
			run = append(run, byte(r-0xE0100+16))
			continue
		}
		flush()
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			h.TagCount++
			if r >= 0xE0020 && r <= 0xE007E {
				h.Tags = append(h.Tags, r-0xE0000)
			}
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			h.Bidi++
		case r == 0x200B, r == 0x2060, r == 0x180E, r >= 0x2062 && r <= 0x2064, r == 0xFEFF && i > 0:
			h.ZeroWidth++
		case r == 0x200C || r == 0x200D:
			var prev, next rune
			if i > 0 {
				prev = runes[i-1]
			}
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			if !joinerContext(prev) && !joinerContext(next) {
				h.ZeroWidth++
			}
		}
	}
	flush()
	return h
}

// flagTagSequenceEnd returns the index of the CANCEL TAG that closes a
// well-formed emoji tag sequence starting at i — WAVING BLACK FLAG, two to
// seven tag letters or digits, CANCEL TAG — or 0 when there is none. These are
// how the England, Scotland and Wales flags are spelled, not hidden text.
func flagTagSequenceEnd(runes []rune, i int) int {
	if runes[i] != 0x1F3F4 {
		return 0
	}
	j := i + 1
	for j < len(runes) && j-i-1 < 8 && (runes[j] >= 0xE0061 && runes[j] <= 0xE007A || runes[j] >= 0xE0030 && runes[j] <= 0xE0039) {
		j++
	}
	if n := j - i - 1; n >= 2 && n <= 7 && j < len(runes) && runes[j] == 0xE007F {
		return j
	}
	return 0
}

// joinerContext reports whether a character is one next to which a
// zero-width joiner or non-joiner is ordinary: emoji (and their variation
// selectors), and the Arabic, Persian and Indic scripts that use them.
func joinerContext(r rune) bool {
	switch {
	case r >= 0x1F000, r >= 0x2600 && r <= 0x27BF, r == 0xFE0F, r >= 0x0600 && r <= 0x06FF, r >= 0x0900 && r <= 0x0DFF:
		return true
	}
	return false
}

// hiddenTextFindings turns what findHiddenText found in a file into
// findings.
func hiddenTextFindings(path, text string) []Finding {
	h := findHiddenText(text)
	var out []Finding
	if h.TagCount > 0 {
		out = append(out, Finding{Rule: "ai.hidden_instructions", Severity: SevCritical, Technique: "T1027", Confidence: 85,
			Detail: fmt.Sprintf("%s holds %d invisible Unicode tag characters, which spell out: %q. An AI agent reads them; a person "+
				"reviewing the file sees nothing (ASCII smuggling, a prompt injection hidden in plain sight)",
				path, h.TagCount, excerpt(string(h.Tags), 300))})
	}
	if len(h.Carried) > 0 {
		shown := strings.Map(func(r rune) rune {
			if unicode.IsPrint(r) || r == '\n' {
				return r
			}
			return '.'
		}, string(h.Carried))
		out = append(out, Finding{Rule: "ai.hidden_instructions", Severity: SevCritical, Technique: "T1027", Confidence: 80,
			Detail: fmt.Sprintf("%s hides %d bytes in runs of invisible variation selectors (one byte per selector): %q",
				path, len(h.Carried), excerpt(shown, 300))})
	}
	if h.Bidi > 0 {
		out = append(out, Finding{Rule: "ai.hidden_instructions", Severity: SevSuspect, Technique: "T1027", Confidence: 65,
			Detail: fmt.Sprintf("%s holds %d bidirectional control characters, which make text display in a different order "+
				"from the order an agent reads it (Trojan Source; the rules-file backdoor)", path, h.Bidi)})
	}
	if h.ZeroWidth >= 2 {
		out = append(out, Finding{Rule: "ai.hidden_instructions", Severity: SevSuspect, Technique: "T1027", Confidence: 60,
			Detail: fmt.Sprintf("%s holds %d zero-width characters outside emoji: invisible to a reader, but they split words an "+
				"agent still reads and can hide instructions between visible ones (the rules-file backdoor)", path, h.ZeroWidth)})
	}
	return out
}
