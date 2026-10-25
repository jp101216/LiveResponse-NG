package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const (
	maxResponseBytes = 16 << 20 // one response line; generous for many hits
	maxStderrBytes   = 64 << 10
	waitDelay        = 2 * time.Second
)

// Client drives the Rust sidecar. Each call spawns the sidecar, exchanges one
// request/response pair, and lets it exit — simple and crash-isolated. A
// long-lived streaming client is an easy later optimisation if call volume
// grows.
type Client struct {
	Path string // absolute path to the sidecar binary
}

// DefaultName is the sidecar's file name on this OS.
func DefaultName() string {
	if runtime.GOOS == "windows" {
		return "lrng-sidecar.exe"
	}
	return "lrng-sidecar"
}

// Locate resolves the sidecar binary to an absolute path.
//
// With no path it looks next to the running agent, which is where a release
// ships it. An explicit path is made absolute relative to the working
// directory. A bare name is never searched for on PATH: on a host under
// investigation, PATH is attacker-influenced.
func Locate(path string) (string, error) {
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("sidecar: locate agent executable: %w", err)
		}
		path = filepath.Join(filepath.Dir(exe), DefaultName())
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("sidecar: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("sidecar: %w (pass -sidecar <path>)", err)
	}
	if st.IsDir() {
		return "", fmt.Errorf("sidecar: %s is a directory", abs)
	}
	return abs, nil
}

// New returns a client for the sidecar at path (see Locate).
func New(path string) (*Client, error) {
	abs, err := Locate(path)
	if err != nil {
		return nil, err
	}
	return &Client{Path: abs}, nil
}

// Call runs one operation.
func (c *Client) Call(ctx context.Context, req Request) (*Response, error) {
	line, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("sidecar: marshal request: %w", err)
	}

	cmd := exec.CommandContext(ctx, c.Path)
	cmd.Stdin = bytes.NewReader(append(line, '\n'))
	stdout := &cappedBuffer{max: maxResponseBytes}
	stderr := &cappedBuffer{max: maxStderrBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// If the context kills the sidecar, don't hang waiting on its pipes.
	cmd.WaitDelay = waitDelay

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("sidecar: %w (stderr: %s)", ctx.Err(), stderr.String())
		}
		return nil, fmt.Errorf("sidecar: run %s: %w (stderr: %s)", c.Path, err, stderr.String())
	}
	if stdout.overflow {
		return nil, fmt.Errorf("sidecar: response exceeded %d bytes", maxResponseBytes)
	}

	out := stdout.Bytes()
	if i := bytes.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("sidecar: no response (stderr: %s)", stderr.String())
	}
	var resp Response
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("sidecar: decode response: %w", err)
	}
	return &resp, nil
}

// Stream runs one operation that may answer with several lines (scan_memory
// over several PIDs) and calls fn for each Response as it arrives, so results
// already received survive if ctx expires and the sidecar is killed. It
// returns once the sidecar exits; a non-nil error means the stream ended
// early or abnormally.
func (c *Client) Stream(ctx context.Context, req Request, fn func(*Response)) error {
	line, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("sidecar: marshal request: %w", err)
	}

	cmd := exec.CommandContext(ctx, c.Path)
	cmd.Stdin = bytes.NewReader(append(line, '\n'))
	stderr := &cappedBuffer{max: maxStderrBytes}
	cmd.Stderr = stderr
	cmd.WaitDelay = waitDelay
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("sidecar: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sidecar: start %s: %w", c.Path, err)
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), maxResponseBytes)
	var decodeErr error
	for sc.Scan() {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var resp Response
		if err := json.Unmarshal(b, &resp); err != nil {
			decodeErr = fmt.Errorf("sidecar: decode response: %w", err)
			break
		}
		fn(&resp)
	}
	scanErr := sc.Err()
	if decodeErr != nil || scanErr != nil {
		// Stop reading; make sure the child doesn't linger.
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()

	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("sidecar: %w (stderr: %s)", ctx.Err(), stderr.String())
	case decodeErr != nil:
		return decodeErr
	case scanErr != nil:
		return fmt.Errorf("sidecar: read: %w", scanErr)
	case waitErr != nil:
		return fmt.Errorf("sidecar: %s: %w (stderr: %s)", c.Path, waitErr, stderr.String())
	}
	return nil
}

// Ping checks the sidecar is present and answering.
func (c *Client) Ping(ctx context.Context) (*Response, error) {
	resp, err := c.Call(ctx, Request{Op: OpPing})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return resp, errors.New("sidecar: ping not ok: " + resp.Error)
	}
	return resp, nil
}

// cappedBuffer keeps at most max bytes and silently drops the rest, while
// still reporting full writes so the child never blocks on a full pipe.
type cappedBuffer struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := c.max - c.Len()
	if len(p) > room {
		c.overflow = true
		if room > 0 {
			c.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return c.Buffer.Write(p)
}
