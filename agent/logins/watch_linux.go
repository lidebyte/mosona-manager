//go:build linux

package logins

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"os"
	"syscall"
	"time"

	agentTypes "mosona-manager/agent/types"
)

const (
	wtmpPath     = "/var/log/wtmp"
	scanInterval = agentTypes.LoginReportInterval
	Supported    = true
)

// Run watches /var/log/wtmp for new SSH login sessions until ctx is done,
// emitting each fresh session once. The first scan only seeds the baseline.
func Run(ctx context.Context, emit func(agentTypes.LoginEvent)) {
	w := &watcher{state: newScanState()}
	defer w.close()
	w.run(ctx, emit)
}

type watcher struct {
	file         *os.File // Pins the inode until the next successful scan.
	startupTime  int64
	minLoginTime int64
	state        *scanState
	offset       int64
	device       uint64
	inode        uint64
	ctim         syscall.Timespec
	layout       utmpLayout
	started      bool
	baselineSize int
	readFailed   bool
}

func (w *watcher) close() {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
}

func (w *watcher) run(ctx context.Context, emit func(agentTypes.LoginEvent)) {
	for {
		if ctx.Err() != nil {
			return
		}
		if !w.scan(emit) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(scanInterval):
		}
	}
}

// scan retries unavailable files, including gaps during log rotation.
func (w *watcher) scan(emit func(agentTypes.LoginEvent)) bool {
	return w.scanPath(wtmpPath, emit)
}

func (w *watcher) scanPath(path string, emit func(agentTypes.LoginEvent)) bool {
	f, err := os.Open(path)
	if err != nil {
		return w.retryRead(path, err)
	}
	defer func() {
		if w.file != f {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return w.retryRead(path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		log.Printf("SSH login monitoring stopped: unexpected stat type for %s", path)
		return false
	}

	// Rotation or truncation restarts from the beginning; the deduplication
	// set suppresses records that were already reported.
	offset := w.offset
	rotated := stat.Dev != w.device || utmpRotated(stat, info.Size(), offset, w.inode, w.ctim)
	if rotated {
		offset = 0
	}
	data, err := readFrom(f, offset)
	if err != nil {
		return w.retryRead(path, err)
	}
	w.readFailed = false
	if rotated {
		w.offset = 0
		w.layout = utmpLayout{}
		w.baselineSize = 0
		if w.started && !w.state.seeded {
			// The original ambiguous bytes no longer describe this file.
			// Preserve the startup boundary by time, not the replacement's
			// size: it can contain both old records and new logins.
			w.minLoginTime = w.startupTime
			w.state.ingest(nil)
		}
	}
	w.close()
	w.file = f
	w.device = stat.Dev
	w.inode = stat.Ino
	w.ctim = stat.Ctim

	if !w.started {
		if w.startupTime == 0 {
			w.startupTime = time.Now().Unix()
		}
		w.baselineSize = len(data)
		w.started = true
	}

	if w.layout.recordSize == 0 {
		layout, ok := detectUtmpLayout(data, binary.NativeEndian)
		if !ok {
			if len(data) == 0 {
				w.state.ingest(nil)
			}
			return true
		}
		w.layout = layout
	}
	// Keep a trailing partial record for the next scan (append in progress).
	complete := len(data) - len(data)%w.layout.recordSize
	w.offset += int64(complete)
	// Layout detection may require a later append. Only records already
	// complete at startup belong to the baseline, even when detection waits.
	if !w.state.seeded {
		baseline := min(w.baselineSize, complete)
		baseline -= baseline % w.layout.recordSize
		w.state.ingest(parseUtmpRecords(data[:baseline], w.layout))
		data = data[baseline:]
		complete -= baseline
	}
	records := parseUtmpRecords(data[:complete], w.layout)
	if w.minLoginTime != 0 {
		fresh := records[:0]
		for _, rec := range records {
			if rec.time >= w.minLoginTime {
				fresh = append(fresh, rec)
			}
		}
		records = fresh
	}
	fresh := w.state.ingest(records)
	if len(fresh) > agentTypes.MaxLoginEventsPerReport {
		log.Printf("SSH login scan found %d new sessions; reporting only the first %d", len(fresh), agentTypes.MaxLoginEventsPerReport)
		fresh = fresh[:agentTypes.MaxLoginEventsPerReport]
	}
	for _, rec := range fresh {
		emit(rec.event())
	}
	return true
}

func (w *watcher) retryRead(path string, err error) bool {
	if !w.readFailed {
		log.Printf("SSH login monitoring cannot read %s; retrying: %v", path, err)
	}
	w.readFailed = true
	return true
}

func readFrom(f *os.File, offset int64) ([]byte, error) {
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// utmpRotated reports whether the wtmp file was replaced or truncated since
// the last successful scan. A different inode catches renames and a shrinking
// file catches truncation. The watcher keeps the previous file open so its
// inode cannot be recycled between scans. A backward ctime is an additional
// reset signal, not a reliable way to detect inode reuse on its own.
func utmpRotated(stat *syscall.Stat_t, size, offset int64, prevIno uint64, prevCtim syscall.Timespec) bool {
	if stat.Ino != prevIno || size < offset {
		return true
	}
	return prevCtim.Sec != 0 && timespecBefore(stat.Ctim, prevCtim)
}

func timespecBefore(a, b syscall.Timespec) bool {
	return a.Sec < b.Sec || a.Sec == b.Sec && a.Nsec < b.Nsec
}
