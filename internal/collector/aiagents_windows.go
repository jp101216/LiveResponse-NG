//go:build windows

package collector

import (
	"os"
	"path/filepath"
)

// aiHomes lists the user profile folders to read AI client configuration
// from.
func aiHomes() []string {
	profiles, _ := userProfiles()
	var out []string
	for _, d := range profileDirs(profiles) {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			out = append(out, d)
		}
	}
	return out
}

// aiClientConfigs are where each AI client keeps its MCP servers (and Claude
// Code its hooks) under a Windows profile.
var aiClientConfigs = []aiClientConfig{
	{Client: "Claude Desktop", Path: "AppData/Roaming/Claude/claude_desktop_config.json"},
	{Client: "Claude Code", Path: ".claude.json"},
	{Client: "Claude Code", Path: ".claude/settings.json"},
	{Client: "Cursor", Path: ".cursor/mcp.json"},
	{Client: "Windsurf", Path: ".codeium/windsurf/mcp_config.json"},
	{Client: "VS Code", Path: "AppData/Roaming/Code/User/mcp.json"},
	{Client: "VS Code", Path: "AppData/Roaming/Code/User/settings.json"},
	{Client: "VS Code Insiders", Path: "AppData/Roaming/Code - Insiders/User/mcp.json"},
	{Client: "Cline", Path: "AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"},
	{Client: "Roo Code", Path: "AppData/Roaming/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"},
	{Client: "Gemini CLI", Path: ".gemini/settings.json"},
	{Client: "Codex", Path: ".codex/config.toml", TOML: true},
	{Client: "Zed", Path: "AppData/Roaming/Zed/settings.json"},
}

// aiSystemConfigs are the machine-wide files: Claude Code's managed
// settings and MCP servers, which apply to every user.
var aiSystemConfigs = func() []aiClientConfig {
	dir := filepath.Join(os.Getenv("ProgramData"), "ClaudeCode")
	if os.Getenv("ProgramData") == "" {
		dir = `C:\ProgramData\ClaudeCode`
	}
	return []aiClientConfig{
		{Client: "Claude Code (managed)", Path: filepath.ToSlash(filepath.Join(dir, "managed-settings.json"))},
		{Client: "Claude Code (managed)", Path: filepath.ToSlash(filepath.Join(dir, "managed-mcp.json"))},
	}
}()
