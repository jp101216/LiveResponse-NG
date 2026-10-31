# Live Response NG — build, test and release
#
#   make help        list targets
#   make all         agent + sidecar for this machine, side by side in the repo root
#   make release     every Windows and Linux build into dist/<os>-<arch>/ with dist/SHA256SUMS

BINARY           := lrng
SIDECAR          := lrng-sidecar
SIDECAR_MANIFEST := sidecar-rs/Cargo.toml
DIST             := dist

# Version stamping. With a git tag, the tag becomes main.version; otherwise the
# version in cmd/lrng/main.go stands. main.commit is the short commit hash.
# Keep cmd/lrng/main.go and sidecar-rs/Cargo.toml at the same version.
VERSION ?= $(shell git describe --tags --dirty 2>/dev/null)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null)

GOEXE   := $(shell go env GOEXE)
LDFLAGS := -s -w
ifneq ($(VERSION),)
LDFLAGS += -X main.version=$(VERSION)
endif
ifneq ($(COMMIT),)
LDFLAGS += -X main.commit=$(COMMIT)
endif
# CGO_ENABLED=0 is set per build line, not exported globally, so `go test -race`
# (which needs cgo) still works if you want it.
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

# --locked: refuse to build if Cargo.lock would change (Cargo.lock is committed).
CARGO_FLAGS           ?= --release --locked
WIN_RS_TARGET         ?= x86_64-pc-windows-gnu
WIN_RS_TARGET_X86     ?= i686-pc-windows-gnu
LINUX_RS_TARGET       ?= x86_64-unknown-linux-musl
LINUX_RS_TARGET_ARM64 ?= aarch64-unknown-linux-musl
# The Linux sidecars build through cargo-zigbuild: zig is both the C compiler
# (wasmtime compiles a small C helper on Unix targets) and the linker, for any
# target from any host — no musl-tools or aarch64 cross toolchain needed.
ZIGBUILD              ?= cargo zigbuild
# Cargo's output directory for the profile CARGO_FLAGS selects, so the sidecar
# recipes also work with CARGO_FLAGS=--locked (a debug build; CI uses that).
RS_PROFILE := $(if $(findstring --release,$(CARGO_FLAGS)),release,debug)

W64   := $(DIST)/windows-amd64
W32   := $(DIST)/windows-386
WARM  := $(DIST)/windows-arm64
LX64  := $(DIST)/linux-amd64
LXARM := $(DIST)/linux-arm64

.DEFAULT_GOAL := help
.PHONY: help all build sidecar windows windows-x86 windows-arm64 \
        linux linux-arm64 \
        sidecar-windows sidecar-windows-x86 sidecar-linux sidecar-linux-arm64 \
        release release-windows release-linux viewer-dist checksums \
        intelgen intel-data \
        test test-race wine-test vet check-windows-rs fmt-check lint audit check clean

help: ## Show this help
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z0-9_-]+:.*## /{printf "  %-20s %s\n",$$1,$$2}' $(MAKEFILE_LIST)

## ---- Host build -------------------------------------------------------------

all: build sidecar ## Agent + sidecar for this machine (sidecar copied next to the agent)

build: ## Agent for the host OS
	$(GOBUILD) -o $(BINARY)$(GOEXE) ./cmd/lrng

sidecar: ## Sidecar for the host OS, copied next to the agent
	cargo build $(CARGO_FLAGS) --manifest-path $(SIDECAR_MANIFEST)
	cp sidecar-rs/target/$(RS_PROFILE)/$(SIDECAR)$(GOEXE) ./$(SIDECAR)$(GOEXE)

## ---- Windows agents (static, no cgo) ----------------------------------------

windows: ## Agent, Windows x64            -> dist/windows-amd64/lrng.exe
	@mkdir -p $(W64)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(W64)/$(BINARY).exe ./cmd/lrng

windows-x86: ## Agent, 32-bit Windows only -> dist/windows-386/lrng.exe
	@mkdir -p $(W32)
	GOOS=windows GOARCH=386 $(GOBUILD) -o $(W32)/$(BINARY).exe ./cmd/lrng

windows-arm64: ## Agent, Windows on ARM64  -> dist/windows-arm64/lrng.exe
	@mkdir -p $(WARM)
	GOOS=windows GOARCH=arm64 $(GOBUILD) -o $(WARM)/$(BINARY).exe ./cmd/lrng

## ---- Linux agents (static, no cgo) ------------------------------------------

linux: ## Agent, Linux x64            -> dist/linux-amd64/lrng
	@mkdir -p $(LX64)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(LX64)/$(BINARY) ./cmd/lrng

linux-arm64: ## Agent, Linux ARM64     -> dist/linux-arm64/lrng
	@mkdir -p $(LXARM)
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(LXARM)/$(BINARY) ./cmd/lrng

## ---- Windows sidecars (cross-compiled; needs mingw-w64) ---------------------

sidecar-windows: ## Sidecar, Windows x64 (also used under emulation on ARM64)
	@mkdir -p $(W64) $(WARM)
	cargo build $(CARGO_FLAGS) --target $(WIN_RS_TARGET) --manifest-path $(SIDECAR_MANIFEST)
	cp sidecar-rs/target/$(WIN_RS_TARGET)/$(RS_PROFILE)/$(SIDECAR).exe $(W64)/$(SIDECAR).exe
	cp sidecar-rs/target/$(WIN_RS_TARGET)/$(RS_PROFILE)/$(SIDECAR).exe $(WARM)/$(SIDECAR).exe

sidecar-windows-x86: ## Sidecar, Windows x86 (YARA via the Pulley interpreter: no JIT on x86)
	@mkdir -p $(W32)
	cargo build $(CARGO_FLAGS) --features yara-pulley --target $(WIN_RS_TARGET_X86) --manifest-path $(SIDECAR_MANIFEST)
	cp sidecar-rs/target/$(WIN_RS_TARGET_X86)/$(RS_PROFILE)/$(SIDECAR).exe $(W32)/$(SIDECAR).exe

## ---- Linux sidecars (static musl; needs cargo-zigbuild + zig) ---------------
#
# Fully static, so one binary runs on any distro — glibc of any age, or musl
# (Alpine) — for the same reason the Windows sidecar links its C runtime
# statically: triage hosts are whatever they are. One-time build-host setup:
#   rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#   cargo install --locked cargo-zigbuild
#   pip install ziglang          # or put a zig release on PATH
# ARM64 gets a native aarch64 sidecar: unlike Windows on ARM, Linux won't run
# the x64 one under emulation.

sidecar-linux: ## Sidecar, Linux x64 (static musl)    -> dist/linux-amd64/lrng-sidecar
	@mkdir -p $(LX64)
	$(ZIGBUILD) $(CARGO_FLAGS) --target $(LINUX_RS_TARGET) --manifest-path $(SIDECAR_MANIFEST)
	cp sidecar-rs/target/$(LINUX_RS_TARGET)/$(RS_PROFILE)/$(SIDECAR) $(LX64)/$(SIDECAR)

sidecar-linux-arm64: ## Sidecar, Linux ARM64 (static musl) -> dist/linux-arm64/lrng-sidecar
	@mkdir -p $(LXARM)
	$(ZIGBUILD) $(CARGO_FLAGS) --target $(LINUX_RS_TARGET_ARM64) --manifest-path $(SIDECAR_MANIFEST)
	cp sidecar-rs/target/$(LINUX_RS_TARGET_ARM64)/$(RS_PROFILE)/$(SIDECAR) $(LXARM)/$(SIDECAR)

## ---- Endpoint-intelligence dataset ------------------------------------------

intelgen: ## Build the offline dataset generator -> ./intelgen
	$(GOBUILD) -o intelgen$(GOEXE) ./cmd/intelgen

# Regenerate the bundled dataset (internal/intel/data/endpoints.tsv) that lrng
# embeds. Needs network to fetch the two sources first (run on a workstation):
#   curl -LO https://iptoasn.com/data/ip2asn-combined.tsv.gz
#   curl -L  https://check.torproject.org/torbulkexitlist -o torbulkexitlist
# then `make intel-data`, commit the result, and rebuild lrng to embed it.
intel-data: intelgen ## Regenerate the bundled dataset (expects ip2asn-combined.tsv.gz + torbulkexitlist in CWD)
	./intelgen$(GOEXE) -v -ip2asn ip2asn-combined.tsv.gz -tor torbulkexitlist -out internal/intel/data/endpoints.tsv

## ---- Release ----------------------------------------------------------------

WINDOWS_RELEASE := windows windows-x86 windows-arm64 sidecar-windows sidecar-windows-x86
LINUX_RELEASE   := linux linux-arm64 sidecar-linux sidecar-linux-arm64

release: $(WINDOWS_RELEASE) $(LINUX_RELEASE) ## Every Windows + Linux build + dist/SHA256SUMS
	$(MAKE) viewer-dist checksums   # sequenced after the builds, even under make -j

release-windows: $(WINDOWS_RELEASE) ## Windows builds only + dist/SHA256SUMS (needs mingw-w64)
	$(MAKE) viewer-dist checksums

release-linux: $(LINUX_RELEASE) ## Linux builds only + dist/SHA256SUMS (needs cargo-zigbuild)
	$(MAKE) viewer-dist checksums

viewer-dist: ## Put the report viewer beside the agent in every dist/<os>-<arch>/
	for d in $(DIST)/*/; do cp viewer/lrng-viewer.html "$$d"; done

checksums: ## Write dist/SHA256SUMS (record these in your case notes)
	cd $(DIST) && rm -f SHA256SUMS && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS && cat SHA256SUMS

## ---- Quality ----------------------------------------------------------------

test: ## Go + Rust tests (host OS), Rust with and without YARA
	go test ./...
	cargo test --locked --manifest-path $(SIDECAR_MANIFEST)
	cargo test --locked --manifest-path $(SIDECAR_MANIFEST) --no-default-features

test-race: ## Go tests under the race detector (needs cgo)
	go test -race ./...

wine-test: ## Optional Linux dev loop: run the Windows test binary (and a sweep) under Wine
	@mkdir -p $(DIST)/wine
	GOOS=windows GOARCH=amd64 go test -c -o $(DIST)/wine/collector.test.exe ./internal/collector
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(DIST)/wine/lrng.exe ./cmd/lrng
	cd $(DIST)/wine && WINEDEBUG=-all wine collector.test.exe -test.v
	cd $(DIST)/wine && rm -f wine.json wine.json.sha256 && WINEDEBUG=-all wine lrng.exe -no-dns -out wine.json

vet: ## go vet for host, and for Windows on every arch (catches 32/64-bit struct bugs)
	go vet ./...
	GOOS=windows GOARCH=amd64 go vet ./...
	GOOS=windows GOARCH=386   go vet ./...
	GOOS=windows GOARCH=arm64 go vet ./...

check-windows-rs: ## Type-check + clippy the sidecar's Windows memory code from any OS
	CARGO_TARGET_DIR=sidecar-rs/target/typecheck-windows RUSTFLAGS="--cfg lrng_typecheck_windows" \
		cargo clippy --locked --manifest-path $(SIDECAR_MANIFEST) --all-targets -- -D warnings

fmt-check: ## Fail if gofmt or rustfmt would change anything
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	cargo fmt --manifest-path $(SIDECAR_MANIFEST) -- --check

lint: vet ## vet + clippy (with and without YARA) with warnings as errors
	cargo clippy --locked --manifest-path $(SIDECAR_MANIFEST) --all-targets -- -D warnings
	cargo clippy --locked --manifest-path $(SIDECAR_MANIFEST) --no-default-features --all-targets -- -D warnings

audit: ## Known-vuln scan: govulncheck (Go) + cargo-audit (Rust, must be installed)
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	cargo audit --file sidecar-rs/Cargo.lock

check: fmt-check lint check-windows-rs test ## Everything CI should run

clean: ## Remove build outputs
	rm -rf $(DIST) $(BINARY) $(BINARY).exe $(SIDECAR) $(SIDECAR).exe intelgen intelgen.exe
	cargo clean --manifest-path $(SIDECAR_MANIFEST)
