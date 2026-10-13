package logins

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	agentTypes "mosona-manager/agent/types"
)

const (
	utmpOffsetType   = 0
	utmpOffsetLine   = 8
	utmpOffsetUser   = 44
	utmpOffsetHost   = 76
	utmpFieldLineLen = 32
	utmpFieldUserLen = 32
	utmpFieldHostLen = 256

	// USER_PROCESS marks a session started by login/sshd and written to wtmp.
	utmpTypeUserProcess = 7

	// maxSeenKeys bounds the deduplication set; on overflow it is rebuilt,
	// which in the worst case (combined with a wtmp rotation) repeats one
	// round of notifications.
	maxSeenKeys = 4096
)

// glibc's compat32 ABI (including amd64) uses 384-byte records with an
// int32 timeval at 340. Native 64-bit ABIs (including glibc arm64 and musl)
// use 400-byte records with an int64 timeval at 344. A static Go binary can
// run on either libc, so GOARCH alone cannot select the file layout.
type utmpLayout struct {
	recordSize int
	timeOffset int
	addrOffset int
	time64     bool
	order      binary.ByteOrder
}

func utmpLayouts(order binary.ByteOrder) []utmpLayout {
	return []utmpLayout{
		{recordSize: 384, timeOffset: 340, addrOffset: 348, order: order},
		{recordSize: 400, timeOffset: 344, addrOffset: 360, time64: true, order: order},
	}
}

func (l utmpLayout) timeval(buf []byte) (sec, usec int64) {
	if l.time64 {
		return int64(l.order.Uint64(buf[l.timeOffset:])), int64(l.order.Uint64(buf[l.timeOffset+8:]))
	}
	return int64(int32(l.order.Uint32(buf[l.timeOffset:]))), int64(int32(l.order.Uint32(buf[l.timeOffset+4:])))
}

// detectUtmpLayout checks record alignment and timeval widths, including
// non-login entries. File-size divisibility alone is unreliable during an
// append. Ambiguous or incomplete data is retained until another scan.
func detectUtmpLayout(data []byte, order binary.ByteOrder) (utmpLayout, bool) {
	var match utmpLayout
	matches := 0
	bestScore := -1
	for _, layout := range utmpLayouts(order) {
		width := 4
		if layout.time64 {
			width = 8
		}
		valid := true
		score := 0
		for offset := 0; offset+layout.timeOffset+2*width <= len(data); offset += layout.recordSize {
			buf := data[offset:]
			typ := order.Uint16(buf[utmpOffsetType:])
			sec, usec := layout.timeval(buf)
			// Accept years 0001 through 9999, including pre-epoch and post-2038
			// timestamps. The bounds only fence out grossly non-time data
			// (they cannot reject e.g. IPv4 bytes as seconds, which stay far
			// below the upper bound); near-misses are instead resolved by the
			// score tie-break and ambiguity deferral above.
			if typ > 9 || sec < -62135596800 || sec > 253402300799 || usec < 0 || usec >= 1000000 {
				valid = false
				break
			}
			if typ != 0 {
				score++
			}
		}
		if valid {
			// A wrong stride can land in zero-filled fields that resemble
			// EMPTY entries. Prefer the alignment with more non-empty records.
			if score > bestScore {
				match = layout
				bestScore = score
				matches = 1
			} else if score == bestScore {
				matches++
			}
		}
	}
	if len(data) < 360 {
		return utmpLayout{}, false
	}
	return match, matches == 1
}

type record struct {
	user string
	tty  string
	ip   string
	time int64
}

func (r record) event() agentTypes.LoginEvent {
	return agentTypes.LoginEvent{User: r.user, TTY: r.tty, IP: r.ip, Time: r.time}
}

func (r record) key() string {
	return r.user + "|" + r.tty + "|" + r.ip + "|" + strconv.FormatInt(r.time, 10)
}

func trimCField(buf []byte, offset, length int) string {
	field := buf[offset : offset+length]
	end := bytes.IndexByte(field, 0)
	if end < 0 {
		end = length
	}
	return strings.TrimSpace(string(field[:end]))
}

// utmpIP reads the network-order address bytes used by last -i. ut_host may
// contain a resolved hostname, so only use it when it is a numeric fallback.
func utmpIP(buf []byte, layout utmpLayout) string {
	addr := buf[layout.addrOffset : layout.addrOffset+net.IPv6len]
	var zero [net.IPv6len]byte
	if !bytes.Equal(addr, zero[:]) {
		if bytes.Equal(addr[net.IPv4len:], zero[net.IPv4len:]) {
			return net.IP(addr[:net.IPv4len]).String()
		}
		return net.IP(addr).String()
	}
	if ip := net.ParseIP(trimCField(buf, utmpOffsetHost, utmpFieldHostLen)); ip != nil {
		return ip.String()
	}
	return ""
}

// parseUtmpRecord accepts USER_PROCESS entries with a user and a source IP.
func parseUtmpRecord(buf []byte, layout utmpLayout) (record, bool) {
	if len(buf) != layout.recordSize {
		return record{}, false
	}
	if layout.order.Uint16(buf[utmpOffsetType:]) != utmpTypeUserProcess {
		return record{}, false
	}
	sec, _ := layout.timeval(buf)
	rec := record{
		user: trimCField(buf, utmpOffsetUser, utmpFieldUserLen),
		tty:  trimCField(buf, utmpOffsetLine, utmpFieldLineLen),
		ip:   utmpIP(buf, layout),
		time: sec,
	}
	if rec.user == "" || rec.ip == "" {
		return record{}, false
	}
	return rec, true
}

// parseUtmpRecords parses all complete records in data, dropping a trailing
// partial record (a wtmp append in progress is re-read on the next scan).
func parseUtmpRecords(data []byte, layout utmpLayout) []record {
	var records []record
	for len(data) >= layout.recordSize {
		if rec, ok := parseUtmpRecord(data[:layout.recordSize], layout); ok {
			records = append(records, rec)
		}
		data = data[layout.recordSize:]
	}
	return records
}

// scanState deduplicates sessions across scans. The first ingest only seeds
// the baseline: logins that happened before monitoring started are not
// reported (matching the SSH-mode login monitor). The seen set is a bounded
// window: when full, the oldest quarter is evicted, so an evicted session
// may be re-notified once if a wtmp rotation re-reads it.
type scanState struct {
	seen   map[string]struct{}
	order  []string
	head   int
	seeded bool
}

func newScanState() *scanState {
	return &scanState{seen: make(map[string]struct{})}
}

// ingest returns the records that were not seen before.
func (s *scanState) ingest(records []record) []record {
	var fresh []record
	for _, rec := range records {
		key := rec.key()
		if _, dup := s.seen[key]; dup {
			continue
		}
		if len(s.seen) >= maxSeenKeys {
			s.evictOldest()
		}
		s.seen[key] = struct{}{}
		s.order = append(s.order, key)
		if s.seeded {
			fresh = append(fresh, rec)
		}
	}
	if !s.seeded {
		s.seeded = true
	}
	return fresh
}

// evictOldest drops the oldest quarter of the window.
func (s *scanState) evictOldest() {
	n := maxSeenKeys / 4
	for i := 0; i < n; i++ {
		delete(s.seen, s.order[s.head])
		s.head++
	}
	if s.head >= maxSeenKeys {
		s.order = append([]string(nil), s.order[s.head:]...)
		s.head = 0
	}
}
