package watch

import (
	"math"
	"net/netip"
	"strings"
)

// sharedSuffixes are suffixes under which every label belongs to someone
// different: dynamic DNS, tunnels and app hosting, all favoured for C2. A
// name under one is registrable one label further down.
var sharedSuffixes = map[string]bool{
	"duckdns.org": true, "no-ip.org": true, "no-ip.biz": true, "ddns.net": true, "hopto.org": true,
	"zapto.org": true, "sytes.net": true, "dynu.net": true, "freedns.afraid.org": true, "dyndns.org": true,
	"ngrok.io": true, "ngrok-free.app": true, "ngrok.app": true, "trycloudflare.com": true, "loca.lt": true,
	"serveo.net": true, "workers.dev": true, "pages.dev": true, "github.io": true, "gitlab.io": true,
	"herokuapp.com": true, "azurewebsites.net": true, "cloudapp.net": true, "cloudfront.net": true,
	"blob.core.windows.net": true, "web.core.windows.net": true, "appspot.com": true, "firebaseapp.com": true,
	"web.app": true, "vercel.app": true, "netlify.app": true, "onrender.com": true, "fly.dev": true,
	"amazonaws.com": true,
	"r2.dev":        true, "glitch.me": true, "repl.co": true, "replit.dev": true, "pythonanywhere.com": true,
}

// secondLevels are second-level labels that country codes register under
// (example.co.uk, example.com.au).
var secondLevels = map[string]bool{
	"co": true, "com": true, "net": true, "org": true, "gov": true, "edu": true, "ac": true,
	"or": true, "ne": true, "go": true, "gob": true, "mil": true, "nic": true, "ltd": true, "plc": true,
}

// Registrable is the name an owner registered: the last two labels, three
// under a country code's second level or one label below a shared suffix.
// It is an approximation of the Public Suffix List, good enough to group a
// beacon's rotating subdomains. An address literal is returned as is.
func Registrable(name string) string {
	name = normName(name)
	if name == "" {
		return ""
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return name
	}
	labels := strings.Split(name, ".")
	n := len(labels)
	for i := 1; i < n; i++ {
		if sharedSuffixes[strings.Join(labels[i:], ".")] {
			return strings.Join(labels[i-1:], ".")
		}
	}
	if n <= 2 {
		return name
	}
	if len(labels[n-1]) == 2 && secondLevels[labels[n-2]] {
		return strings.Join(labels[n-3:], ".")
	}
	return strings.Join(labels[n-2:], ".")
}

// subdomain is the part of name left of its registrable domain.
func subdomain(name, reg string) string {
	if name == reg || !strings.HasSuffix(name, "."+reg) {
		return ""
	}
	return strings.TrimSuffix(name, "."+reg)
}

// entropy is the Shannon entropy of s in bits per character, ignoring dots.
func entropy(s string) float64 {
	s = strings.ReplaceAll(s, ".", "")
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
