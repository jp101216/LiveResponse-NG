package collector

import (
	"fmt"
	"sort"
)

// parseAIYAML reads the MCP servers out of a YAML client configuration with
// the package's YAML reader (yamllite.go): the first document only.
func parseAIYAML(client, path string, data []byte) ([]mcpServer, error) {
	docs, err := parseYAMLDocuments(data)
	if err != nil || len(docs) == 0 {
		return nil, err
	}
	return yamlMCPServers(client, path, yamlPlain(docs[0])), nil
}

// yamlMCPServers reads the MCP servers out of a parsed YAML configuration:
// Continue's mcpServers (a list of named entries, or a map by name in a file
// copied from another client) and Goose's extensions (by name, with cmd, args,
// envs and uri; built-in extensions run no command of their own).
func yamlMCPServers(client, path string, root any) []mcpServer {
	m, _ := root.(map[string]any)
	var out []mcpServer
	named := func(name string, entry map[string]any, s mcpServer) {
		s.Client, s.Config, s.Name = client, path, name
		if d, _ := entry["disabled"].(string); d == "true" {
			s.Disabled = true
		}
		if e, _ := entry["enabled"].(string); e == "false" {
			s.Disabled = true
		}
		out = append(out, s)
	}
	switch v := m["mcpServers"].(type) {
	case []any:
		for i, e := range v {
			em, _ := e.(map[string]any)
			if s, ok := mcpServerFrom(em); ok {
				name, _ := em["name"].(string)
				if name == "" {
					name = fmt.Sprintf("#%d", i+1)
				}
				named(name, em, s)
			}
		}
	case map[string]any:
		for _, name := range sortedKeys(v) {
			em, _ := v[name].(map[string]any)
			if s, ok := mcpServerFrom(em); ok {
				named(name, em, s)
			}
		}
	}
	if ext, ok := m["extensions"].(map[string]any); ok {
		for _, name := range sortedKeys(ext) {
			em, _ := ext[name].(map[string]any)
			if t, _ := em["type"].(string); t == "builtin" || t == "platform" {
				continue
			}
			s, ok := mcpServerFrom(map[string]any{"command": em["cmd"], "args": em["args"], "env": em["envs"], "url": em["uri"]})
			if !ok {
				continue
			}
			if keys, ok := em["env_keys"].([]any); ok {
				for _, k := range keys {
					if ks, ok := k.(string); ok {
						s.EnvNames = append(s.EnvNames, ks)
					}
				}
				sort.Strings(s.EnvNames)
			}
			named(name, em, s)
		}
	}
	return out
}

// yamlPlain converts a parsed YAML node into map[string]any, []any and
// string values (nil for null), the shapes mcpServerFrom reads.
func yamlPlain(n *yamlNode) any {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yamlMap:
		m := make(map[string]any, len(n.Map))
		for k, v := range n.Map {
			m[k] = yamlPlain(v)
		}
		return m
	case yamlSeq:
		out := make([]any, len(n.Seq))
		for i, v := range n.Seq {
			out[i] = yamlPlain(v)
		}
		return out
	}
	if n.Null {
		return nil
	}
	return n.Str
}
