package collector

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

// Opening a path the host supplies is not as harmless as it looks. A FIFO
// planted where a dotfile, an autostart entry or a hashed image is expected
// blocks open() until something writes to it, and the collector with it; a
// device node can have side effects when opened; a huge or sparse file
// exhausts memory when read whole; and on Windows a UNC or WebDAV path makes
// this (often elevated) process authenticate to whatever host the attacker
// named. Every read of a host-supplied path goes through openRegular, which
// refuses all of these before anything is opened.

var (
	errNotRegular = errors.New("not a regular file")
	errRemotePath = errors.New("not read: a network or device path (opening it would reach out from this host)")
)

// checkLocalPath refuses a path that would leave the host (or address a
// device) when opened. It is a no-op except on Windows.
func checkLocalPath(path string) error {
	if remotePath(path) {
		return errRemotePath
	}
	return nil
}

// fileMissing reports whether a local path names nothing at all.
func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// openRegular opens a local regular file for reading without blocking: the
// type is checked before the open (so a device is never opened) and again on
// the open handle (so a file swapped for a FIFO in between is caught too; the
// non-blocking open keeps that race from hanging).
func openRegular(path string) (*os.File, fs.FileInfo, error) {
	if err := checkLocalPath(path); err != nil {
		return nil, nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil, errNotRegular
	}
	f, err := openNoBlock(path)
	if err != nil {
		return nil, nil, err
	}
	if st, err = f.Stat(); err != nil {
		f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, nil, errNotRegular
	}
	return f, st, nil
}

// readRegular reads at most max bytes of a local regular file. truncated is
// true when the file held more; the prefix is still returned. Files under
// /proc and /sys report a size of 0, so the size is never trusted: the read
// itself is bounded.
func readRegular(path string, max int64) (data []byte, truncated bool, err error) {
	f, _, err := openRegular(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err = io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(data)) > max {
		return data[:max], true, err
	}
	return data, false, err
}
