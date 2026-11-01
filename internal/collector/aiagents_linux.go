//go:build linux

package collector

// aiHomes lists the home directories to read AI client configuration from.
func aiHomes() []string { return userHomes() }

// aiClientConfigs are where each AI client keeps its MCP servers (and Claude
// Code its hooks) under a Linux home.
var aiClientConfigs = []aiClientConfig{
	{Client: "Claude Desktop", Path: ".config/Claude/claude_desktop_config.json"},
	{Client: "Claude Code", Path: ".claude.json"},
	{Client: "Claude Code", Path: ".claude/settings.json"},
	{Client: "Cursor", Path: ".cursor/mcp.json"},
	{Client: "Windsurf", Path: ".codeium/windsurf/mcp_config.json"},
	{Client: "VS Code", Path: ".config/Code/User/mcp.json"},
	{Client: "VS Code", Path: ".config/Code/User/settings.json"},
	{Client: "Cline", Path: ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"},
	{Client: "Roo Code", Path: ".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"},
	{Client: "Gemini CLI", Path: ".gemini/settings.json"},
	{Client: "Codex", Path: ".codex/config.toml", TOML: true},
	{Client: "Zed", Path: ".config/zed/settings.json"},
}

// aiSystemConfigs are the machine-wide files: Claude Code's managed
// settings and MCP servers, which apply to every user.
var aiSystemConfigs = []aiClientConfig{
	{Client: "Claude Code (managed)", Path: "/etc/claude-code/managed-settings.json"},
	{Client: "Claude Code (managed)", Path: "/etc/claude-code/managed-mcp.json"},
}
