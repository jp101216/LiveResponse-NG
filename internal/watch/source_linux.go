//go:build linux

package watch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
)

// The Linux source: the kernel's process connector reports execs, forks and
// exits; a packet socket with a classic BPF filter (bpf.go) sees connections
// start, datagrams leave and DNS go by; sock_diag and /proc/<pid>/fd name the
// process behind each one (linuxtrack.go). Nothing is loaded into the
// kernel beyond the socket filter, and nothing outlives the process.
const sourceName = "netlink"

const (
	pollInterval = 200 * time.Millisecond
	// packetWake bounds how long the capture loop sleeps in a read, so a
	// finished socket scan is used (and the next one started) promptly.
	packetWake     = 20 * time.Millisecond
	packetRcvBuf   = 16 << 20
	procConnRcvBuf = 8 << 20
	// Full socket scans start as soon as one is needed, paid for from a
	// budget that refills at 5% of wall time up to a quarter second: bursts
	// are answered at once, and a long run stays within 5% of a core.
	scanShare       = 0.05
	scanBurst       = 250 * time.Millisecond
	fastScanBudget  = 2048 // fd links a fast lookup may read
	fastCandidates  = 32
	recentWithin    = time.Minute
	maxKnownSockets = 1 << 18
)

func runSource(ctx context.Context, o RecordOptions, started time.Time, sink func(Event)) (Window, error) {
	w := Window{Source: sourceName, Meta: map[string]any{}}
	pc, err := openProcConnector()
	if err != nil {
		return w, denied("listening to the kernel's process connector", err)
	}
	defer pc.close()
	pk, err := openPacketSocket()
	if err != nil {
		return w, denied("opening a packet socket", err)
	}
	defer syscall.Close(pk)
	diag, err := openDiag()
	if err != nil {
		w.Meta["socket_lookup"] = "procfs"
		w.Errors = append(w.Errors, "sock_diag is unavailable, reading /proc/net instead: "+err.Error())
	} else {
		w.Meta["socket_lookup"] = "sock_diag"
		defer diag.close()
	}

	known := &pidSet{m: map[uint32]bool{}}
	recent := &recentPIDs{}
	if procs, err := collector.RunningProcesses(); err == nil {
		for _, p := range procs {
			known.add(p.PID)
			if p.PID != o.SelfPID {
				sink(Event{Time: started, Kind: ProcSeen, PID: p.PID, Image: p.Path})
			}
		}
	} else {
		w.Errors = append(w.Errors, "listing processes: "+err.Error())
	}

	lp := &linuxProcs{sink: sink, known: known, recent: recent}
	var wg sync.WaitGroup
	var procErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		procErr = lp.run(ctx, pc.fd)
	}()

	own := &linuxOwners{diag: diag, known: known, recent: recent, sockets: map[uint32]sockRef{}}
	tr := newTracker(own, sink, localAddrs())
	cs, capErr := capture(ctx, pk, tr, own)
	wg.Wait()

	for k, v := range cs {
		w.Meta[k] = v
	}
	w.Meta["proc_events"] = lp.events.Load()
	if n := lp.lost.Load(); n > 0 {
		w.Meta["proc_events_lost"] = n
	}
	if n := lp.missed.Load(); n > 0 {
		w.Meta["proc_exec_missed"] = n // exited before its image could be read
	}
	if e := lp.ackErr.Load(); e != 0 {
		w.Errors = append(w.Errors, "process connector: "+syscall.Errno(e).Error())
	}
	if procErr != nil {
		w.Errors = append(w.Errors, "process connector: "+procErr.Error())
	}
	if own.diagErrs > 0 {
		w.Meta["sock_diag_errors"] = own.diagErrs
	}
	return w, capErr
}

func denied(what string, err error) error {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return fmt.Errorf("%s was denied: watch mode needs root on Linux (CAP_NET_ADMIN and CAP_NET_RAW)", what)
	}
	return fmt.Errorf("%s: %w", what, err)
}

func setRecvTimeout(fd int, d time.Duration) error {
	tv := syscall.NsecToTimeval(d.Nanoseconds())
	return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

func setRcvBuf(fd, n int) {
	if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, n) != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, n)
	}
}

func retryable(err error) bool {
	return err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR
}

// localAddrs are this host's addresses, so a resolver listening on one of
// them counts as local.
func localAddrs() []netip.Addr {
	as, _ := net.InterfaceAddrs()
	var out []netip.Addr
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

func procPath(pid uint32, name string) string {
	return "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/" + name
}

func procPPID(pid uint32) uint32 {
	b, err := os.ReadFile(procPath(pid, "stat"))
	if err != nil {
		return 0
	}
	return statPPID(b)
}

// ---- the process connector ----

type procConn struct{ fd int }

func openProcConnector() (*procConn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.NETLINK_CONNECTOR)
	if err != nil {
		return nil, err
	}
	setRcvBuf(fd, procConnRcvBuf)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	c := &procConn{fd: fd}
	if err := setRecvTimeout(fd, pollInterval); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := c.control(procCnMcastListen); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return c, nil
}

func (c *procConn) control(op uint32) error {
	return syscall.Sendto(c.fd, procConnMessage(op), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

// close tells the kernel to stop producing events for this listener.
func (c *procConn) close() {
	_ = c.control(procCnMcastIgnore)
	_ = syscall.Close(c.fd)
}

type linuxProcs struct {
	sink   func(Event)
	known  *pidSet
	recent *recentPIDs
	events atomic.Int64
	lost   atomic.Int64
	missed atomic.Int64
	ackErr atomic.Int64
}

func (lp *linuxProcs) run(ctx context.Context, fd int) error {
	buf := make([]byte, 1<<16)
	for ctx.Err() == nil {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		switch {
		case err == nil:
		case retryable(err):
			continue
		case err == syscall.ENOBUFS:
			lp.lost.Add(1) // the socket overflowed: some events are gone
			continue
		default:
			return err
		}
		now := time.Now().UTC()
		for _, ev := range parseProcEvents(buf[:n]) {
			lp.handle(ev, now)
		}
	}
	return nil
}

func (lp *linuxProcs) handle(ev procEvent, now time.Time) {
	lp.events.Add(1)
	switch ev.what {
	case procEventNone:
		if ev.err != 0 {
			lp.ackErr.Store(int64(ev.err))
		}
	case procEventFork:
		if ev.pid == ev.tgid { // a process, not a thread
			lp.recent.add(ev.tgid, now)
		}
	case procEventExec:
		pid := ev.tgid
		image, err := os.Readlink(procPath(pid, "exe"))
		if err != nil {
			lp.missed.Add(1)
			return
		}
		lp.known.add(pid)
		lp.recent.add(pid, now)
		lp.sink(Event{Time: now, Kind: ProcStart, PID: pid, PPID: procPPID(pid), Image: image,
			CmdLine: collector.ProcessCommandLine(pid)})
	case procEventExit:
		if ev.pid == ev.tgid && lp.known.remove(ev.tgid) {
			lp.sink(Event{Time: now, Kind: ProcStop, PID: ev.tgid})
		}
	}
}

// pidSet is the PIDs the stream has named.
type pidSet struct {
	mu sync.Mutex
	m  map[uint32]bool
}

func (s *pidSet) add(pid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[pid] {
		return false
	}
	s.m[pid] = true
	return true
}

func (s *pidSet) remove(pid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := s.m[pid]
	delete(s.m, pid)
	return ok
}

// recentPIDs are processes started lately, newest last.
type recentPIDs struct {
	mu   sync.Mutex
	ring [64]struct {
		pid uint32
		at  time.Time
	}
	n int
}

func (r *recentPIDs) add(pid uint32, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ring[r.n%len(r.ring)].pid, r.ring[r.n%len(r.ring)].at = pid, at
	r.n++
}

// list returns up to max processes started within d of now, newest first.
func (r *recentPIDs) list(now time.Time, max int, d time.Duration) []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []uint32
	for i := 1; i <= len(r.ring) && i <= r.n && len(out) < max; i++ {
		e := r.ring[(r.n-i)%len(r.ring)]
		if now.Sub(e.at) > d {
			break
		}
		out = append(out, e.pid)
	}
	return out
}

// ---- the packet socket ----

func openPacketSocket() (int, error) {
	// Protocol 0 receives nothing until bind, so no packet arrives unfiltered.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	prog := captureFilter()
	filter := make([]syscall.SockFilter, len(prog))
	for i, in := range prog {
		filter[i] = syscall.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fail := func(err error) (int, error) {
		syscall.Close(fd)
		return -1, err
	}
	if err := syscall.AttachLsf(fd, filter); err != nil { //nolint:staticcheck // the stdlib's own socket filter call
		return fail(fmt.Errorf("attaching the socket filter: %w", err))
	}
	setRcvBuf(fd, packetRcvBuf)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
		return fail(err)
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RXQ_OVFL, 1) // the drop count rides along
	if err := setRecvTimeout(fd, packetWake); err != nil {
		return fail(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL)}); err != nil {
		return fail(err)
	}
	return fd, nil
}

func htons(v uint16) uint16 {
	var b [2]byte
	b[0], b[1] = byte(v>>8), byte(v)
	return ne.Uint16(b[:])
}

type scanResult struct {
	sockets map[uint32]sockRef
	started time.Time
	took    time.Duration
}

// capture reads packets until ctx ends, then settles what is still waiting.
func capture(ctx context.Context, fd int, tr *tracker, own *linuxOwners) (map[string]any, error) {
	buf := make([]byte, snapDNS+256)
	oob := make([]byte, syscall.CmsgSpace(16)+syscall.CmsgSpace(4)+64)
	results := make(chan scanResult, 1)
	scanning := false
	budget := newScanBudget(scanShare, scanBurst, time.Now())
	lastTick := time.Now()
	var drops uint32
	var scans int64
	var scanMax time.Duration
	install := func(r scanResult) {
		scanning = false
		budget.spend(r.took, time.Now())
		scans++
		if r.took > scanMax {
			scanMax = r.took
		}
		own.sockets = r.sockets
		tr.scanned(own.ownerOf, r.started)
	}
	var err error
	wake := packetWake
	for ctx.Err() == nil {
		// Sleep in short reads only while a socket scan is wanted or running.
		want := pollInterval
		if scanning || own.wantScan {
			want = packetWake
		}
		if want != wake {
			_ = setRecvTimeout(fd, want)
			wake = want
		}
		n, oobn, _, from, rerr := syscall.Recvmsg(fd, buf, oob, 0)
		now := time.Now()
		switch {
		case rerr == nil:
			at, d := parseCmsgs(oob[:oobn], now)
			if d > drops {
				drops = d
			}
			out := false
			if sll, ok := from.(*syscall.SockaddrLinklayer); ok {
				out = sll.Pkttype == pktOutgoing
			}
			tr.packet(buf[:n], at.UTC(), out)
		case retryable(rerr):
		default:
			err = fmt.Errorf("reading the packet socket: %w", rerr)
		}
		if err != nil {
			break
		}
		select {
		case r := <-results:
			install(r)
		default:
		}
		if own.wantScan && !scanning && budget.ready(now) {
			own.wantScan, scanning = false, true
			go func() { results <- fullScan() }()
		}
		if now.Sub(lastTick) >= pollInterval {
			tr.tick(now.UTC())
			lastTick = now
		}
	}
	// The window closed: name what still waits if a last scan can.
	if scanning {
		install(<-results)
	}
	if tr.waiting() > 0 {
		install(fullScan())
	}
	tr.flush(time.Now().UTC())
	m := map[string]any{"full_socket_scans": scans}
	if scans > 0 {
		m["full_socket_scan_ms_max"] = scanMax.Milliseconds()
	}
	if drops > 0 {
		m["packets_dropped_by_kernel"] = drops
	}
	st := tr.stats()
	attributed, unattributed := map[string]int64{}, map[string]int64{}
	for k, v := range st {
		switch {
		case k == "unattributed_events":
			m["unattributed_events"] = v
		case len(k) > 11 && k[:11] == "attributed_":
			attributed[k[11:]] = v
		case len(k) > 13 && k[:13] == "unattributed_":
			unattributed[k[13:]] = v
		default:
			m[k] = v
		}
	}
	if len(attributed) > 0 {
		m["attributed_by"] = attributed
	}
	if len(unattributed) > 0 {
		m["unattributed_because"] = unattributed
	}
	if _, ok := m["unattributed_events"]; !ok {
		m["unattributed_events"] = int64(0)
	}
	return m, err
}

// parseCmsgs reads the kernel's receive timestamp and the socket's
// cumulative drop count.
func parseCmsgs(oob []byte, now time.Time) (time.Time, uint32) {
	at, drops := now, uint32(0)
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return at, 0
	}
	for _, m := range msgs {
		if m.Header.Level != syscall.SOL_SOCKET {
			continue
		}
		switch int(m.Header.Type) {
		case syscall.SCM_TIMESTAMPNS:
			switch len(m.Data) {
			case 16:
				at = time.Unix(int64(ne.Uint64(m.Data)), int64(ne.Uint64(m.Data[8:])))
			case 8:
				at = time.Unix(int64(int32(ne.Uint32(m.Data))), int64(int32(ne.Uint32(m.Data[4:]))))
			}
		case syscall.SO_RXQ_OVFL:
			if len(m.Data) >= 4 {
				drops = ne.Uint32(m.Data)
			}
		}
	}
	return at, drops
}

// ---- socket owners ----

type sockRef struct {
	pid uint32
	fd  int32
}

// linuxOwners finds the process holding a socket. It is used by the capture
// goroutine only; known and recent are shared with the process goroutine.
type linuxOwners struct {
	diag     *diagConn // nil: /proc/net instead
	known    *pidSet
	recent   *recentPIDs
	sockets  map[uint32]sockRef // inode -> holder, from scans
	mru      []uint32           // processes that held sockets lately, most recent first
	wantScan bool
	diagErrs int64
}

func (o *linuxOwners) inode(proto uint8, local, remote netip.AddrPort) uint32 {
	if o.diag != nil {
		ino, err := o.diag.lookup(proto, local, remote)
		if err != nil {
			o.diagErrs++
		}
		return ino
	}
	names := []string{"/proc/net/udp", "/proc/net/udp6"}
	if proto == ipProtoTCP {
		names = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	}
	if !local.Addr().Unmap().Is4() {
		names = names[1:]
	}
	for _, n := range names {
		if b, err := os.ReadFile(n); err == nil {
			if ino := procNetInode(b, proto == ipProtoTCP, local, remote); ino != 0 {
				return ino
			}
		}
	}
	return 0
}

func (o *linuxOwners) ownerOf(inode uint32) (uint32, bool) {
	r, ok := o.sockets[inode]
	return r.pid, ok
}

func (o *linuxOwners) fast(inode uint32) (uint32, bool) {
	if r, ok := o.sockets[inode]; ok {
		if l, err := os.Readlink(procPath(r.pid, "fd/"+strconv.Itoa(int(r.fd)))); err == nil {
			if ino, ok := socketInode(l); ok && ino == inode {
				return r.pid, true
			}
		}
		delete(o.sockets, inode)
	}
	budget := fastScanBudget
	seen := map[uint32]bool{}
	cands := append(o.recent.list(time.Now(), fastCandidates, recentWithin), o.mru...)
	for _, pid := range cands {
		if seen[pid] {
			continue
		}
		seen[pid] = true
		found := false
		budget -= scanFDs(pid, func(ino uint32, fd int32) bool {
			if len(o.sockets) < maxKnownSockets {
				o.sockets[ino] = sockRef{pid, fd}
			}
			found = ino == inode
			return found
		})
		if found {
			return pid, true
		}
		if budget <= 0 {
			break
		}
	}
	return 0, false
}

func (o *linuxOwners) learned(pid uint32) {
	if len(o.mru) > 0 && o.mru[0] == pid {
		return
	}
	for i, p := range o.mru {
		if p == pid {
			copy(o.mru[1:i+1], o.mru[:i])
			o.mru[0] = pid
			return
		}
	}
	if len(o.mru) < fastCandidates {
		o.mru = append(o.mru, 0)
	}
	copy(o.mru[1:], o.mru)
	o.mru[0] = pid
}

func (o *linuxOwners) requestScan() { o.wantScan = true }

func (o *linuxOwners) describe(pid uint32, t time.Time) (Event, bool) {
	if !o.known.add(pid) {
		return Event{}, false
	}
	image, err := os.Readlink(procPath(pid, "exe"))
	if err != nil {
		return Event{}, false
	}
	return Event{Time: t, Kind: ProcSeen, PID: pid, PPID: procPPID(pid), Image: image,
		CmdLine: collector.ProcessCommandLine(pid)}, true
}

// scanFDs reads a process's fd links, calling fn for each socket until it
// returns true; it returns how many links it read.
func scanFDs(pid uint32, fn func(inode uint32, fd int32) bool) int {
	dir := procPath(pid, "fd/")
	f, err := os.Open(dir)
	if err != nil {
		return 1
	}
	names, _ := f.Readdirnames(-1)
	f.Close()
	n := 1
	for _, name := range names {
		n++
		l, err := os.Readlink(dir + name)
		if err != nil {
			continue
		}
		ino, ok := socketInode(l)
		if !ok {
			continue
		}
		fd, _ := strconv.Atoi(name)
		if fn(ino, int32(fd)) {
			break
		}
	}
	return n
}

// fullScan maps every process's sockets.
func fullScan() scanResult {
	started := time.Now()
	m := map[uint32]sockRef{}
	if d, err := os.Open("/proc"); err == nil {
		names, _ := d.Readdirnames(-1)
		d.Close()
		for _, name := range names {
			pid, err := strconv.ParseUint(name, 10, 32)
			if err != nil {
				continue
			}
			scanFDs(uint32(pid), func(ino uint32, fd int32) bool {
				if len(m) < maxKnownSockets {
					m[ino] = sockRef{uint32(pid), fd}
				}
				return false
			})
		}
	}
	return scanResult{sockets: m, started: started.UTC(), took: time.Since(started)}
}

// ---- sock_diag ----

type diagConn struct {
	fd  int
	seq uint32
	buf []byte
}

func openDiag() (*diagConn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return nil, err
	}
	d := &diagConn{fd: fd, buf: make([]byte, 1<<15)}
	if err := setRecvTimeout(fd, 100*time.Millisecond); err != nil {
		d.close()
		return nil, err
	}
	// A dump matching no state answers at once where the TCP and UDP
	// handlers are present, and with ENOENT where they aren't.
	for _, p := range []struct {
		proto uint8
		name  string
	}{{ipProtoTCP, "tcp"}, {ipProtoUDP, "udp"}} {
		_, errno, err := d.request(p.proto, netip.AddrPort{}, netip.AddrPort{}, 0, true)
		if err == nil && errno != 0 {
			err = syscall.Errno(errno)
		}
		if err != nil {
			d.close()
			return nil, fmt.Errorf("%s: %w", p.name, err)
		}
	}
	return d, nil
}

func (d *diagConn) close() { _ = syscall.Close(d.fd) }

// lookup finds the inode of the socket at local talking to remote.
func (d *diagConn) lookup(proto uint8, local, remote netip.AddrPort) (uint32, error) {
	try := func(src, dst netip.AddrPort) (uint32, error) {
		ino, errno, err := d.request(proto, src, dst, local.Port(), false)
		if err == nil && errno != 0 && errno != errnoENOENT {
			err = syscall.Errno(errno)
		}
		return ino, err
	}
	if proto == ipProtoUDP {
		// UDP's exact lookup reads the request as a packet arriving: its
		// source is the remote end ("swapped for historical reasons", says
		// the kernel). The reply's local port is checked either way.
		if ino, err := try(remote, local); ino != 0 || err != nil {
			return ino, err
		}
	}
	return try(local, remote)
}

// request sends one sock_diag request and returns the inode found and the
// kernel's errno for it (ENOENT: no such socket).
func (d *diagConn) request(proto uint8, src, dst netip.AddrPort, sport uint16, dump bool) (uint32, int, error) {
	d.seq++
	req := diagRequest(d.seq, proto, src, dst, dump)
	if err := syscall.Sendto(d.fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, 0, err
	}
	for {
		n, _, err := syscall.Recvfrom(d.fd, d.buf, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, 0, err
		}
		ino, done, errno := parseDiagReply(d.buf[:n], d.seq, sport)
		if !done {
			continue // a late reply to an earlier request
		}
		if errno < 0 {
			return 0, 0, errors.New("malformed sock_diag reply")
		}
		return ino, errno, nil
	}
}
