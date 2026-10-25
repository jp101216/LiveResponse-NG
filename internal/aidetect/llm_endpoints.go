// Package aidetect holds AI module A: runtime LLM-callout detection.
//
// Classic malware beacons to attacker C2; a growing class of "AI-assisted"
// malware instead calls a commercial LLM API at runtime to generate commands,
// decode data, or decide its next move (LameHug, for example, asked a model
// hosted on Hugging Face for its commands). A connection to LLM inference
// infrastructure from a process that has no business talking to one (a
// script host, a random service binary) is the signal this module surfaces.
//
// This is a heuristic, and the code is honest about its limits: public LLM
// APIs sit behind shared CDNs, their IPs churn, and allowlists are imperfect.
// It is a lead for an analyst, not a verdict.
//
// Module B (embedded prompt artifacts) lives in the Rust sidecar; keep its
// api.endpoint pattern (sidecar-rs/src/prompts.rs) in step with this list.
package aidetect

import "strings"

// llmHostnames are the API endpoints of commercial LLM inference providers.
// They are resolved to IPs at runtime so matching survives IP rotation
// between runs, and matched exactly when a connection's hostname is known.
var llmHostnames = []string{
	"api.openai.com",
	"api.anthropic.com",
	"generativelanguage.googleapis.com", // Google Gemini
	"aiplatform.googleapis.com",         // Google Vertex AI (global endpoint)
	"api.cohere.ai",
	"api.cohere.com",
	"api.mistral.ai",
	"api.groq.com",
	"api.together.xyz",
	"api.perplexity.ai",
	"openrouter.ai",
	"api.deepseek.com",
	"api.x.ai", // Grok
	"api.fireworks.ai",
	"api.replicate.com",
	"api-inference.huggingface.co", // Hugging Face Inference API
	"router.huggingface.co",        // Hugging Face Inference Providers
	"models.inference.ai.azure.com",
	"api.ai21.com",
	"api.deepinfra.com",
	"api.cerebras.ai",
	"api.sambanova.ai",
	"api.moonshot.ai",
	"api.moonshot.cn",
	"dashscope.aliyuncs.com", // Alibaba Qwen
	"dashscope-intl.aliyuncs.com",
	"integrate.api.nvidia.com",
	"api.novita.ai",
	"api.hyperbolic.xyz",
}

// hostPattern matches providers whose endpoints are regional or per-tenant
// and so can't be resolved generically: <anything><Suffix>, optionally
// required to start with Prefix. Used only when a connection's hostname is
// known (DNS-cache correlation), not for raw IP matching.
type hostPattern struct {
	Prefix, Suffix, Label string
}

var hostPatterns = []hostPattern{
	{"", ".openai.azure.com", "Azure OpenAI"},
	{"", ".cognitiveservices.azure.com", "Azure AI services"},
	{"", ".services.ai.azure.com", "Azure AI Foundry"},
	{"", ".models.ai.azure.com", "Azure AI model endpoint"},
	{"bedrock-runtime.", ".amazonaws.com", "AWS Bedrock"}, // bedrock-runtime.<region>.amazonaws.com
	{"bedrock-runtime-fips.", ".amazonaws.com", "AWS Bedrock (FIPS)"},
	{"bedrock-agent-runtime.", ".amazonaws.com", "AWS Bedrock agents"},
	{"", "-aiplatform.googleapis.com", "Google Vertex AI (regional)"}, // us-central1-aiplatform...
}

// MatchHostname reports whether host is LLM inference infrastructure and
// says how it matched. Comparison is case-insensitive and ignores a trailing
// dot.
func MatchHostname(host string) (string, bool) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return "", false
	}
	for _, known := range llmHostnames {
		if h == known {
			return "known hostname " + known, true
		}
	}
	for _, p := range hostPatterns {
		if strings.HasSuffix(h, p.Suffix) && len(h) > len(p.Suffix) &&
			(p.Prefix == "" || (strings.HasPrefix(h, p.Prefix) && len(h) > len(p.Prefix)+len(p.Suffix))) {
			return "hostname pattern " + p.Label, true
		}
	}
	return "", false
}

// ProviderHostnames returns a copy of the resolvable provider list.
func ProviderHostnames() []string { return append([]string(nil), llmHostnames...) }

// defaultAllowlist are process image names (lowercase, no path) that
// legitimately talk to LLM APIs. Deliberately narrow: browsers and known
// first-party AI desktop apps. Script hosts and interpreters are intentionally
// NOT here — that's exactly where a malicious callout hides, so seeing one
// reach an LLM endpoint should raise the finding, not suppress it.
//
// Matching is by name, which a binary can copy; the network collector
// therefore also checks where an allowlisted process runs from (see
// Conn.UnusualPath). On Linux the name is the executable's file name (the
// process's own name can be set at will), which carries no ".exe".
var defaultAllowlist = map[string]bool{
	// Browsers and the WebView2 runtime that embeds web UIs in desktop apps
	"chrome.exe":         true,
	"msedge.exe":         true,
	"msedgewebview2.exe": true,
	"firefox.exe":        true,
	"brave.exe":          true,
	"opera.exe":          true,
	"vivaldi.exe":        true,
	"arc.exe":            true,
	// First-party AI desktop apps
	"claude.exe":    true,
	"chatgpt.exe":   true,
	"ollama.exe":    true,
	"lm studio.exe": true,
	// Developer tools with built-in AI features
	"code.exe":     true,
	"cursor.exe":   true,
	"windsurf.exe": true,
	"zed.exe":      true,
	"devenv.exe":   true, // Visual Studio

	// Linux executables of the same applications.
	"chrome": true, "chromium": true, "chromium-browser": true, "firefox": true,
	"firefox-esr": true, "firefox-bin": true, "brave": true, "msedge": true,
	"opera": true, "vivaldi-bin": true, "ollama": true, "code": true,
	"code-insiders": true, "cursor": true, "windsurf": true, "zed": true,
	"zed-editor": true,
}
