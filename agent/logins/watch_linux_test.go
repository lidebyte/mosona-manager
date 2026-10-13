//go:build linux

package logins

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	agentTypes "mosona-manager/agent/types"
)

func TestWatcherLayoutsAppendAndRotation(t *testing.T) {
	for _, size := range []int{384, 400} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wtmp")
			baseline := makeABIRecord(size, binary.NativeEndian, 7, "root", "pts/0", "203.0.113.7", 1728360023)
			fresh := makeABIRecord(size, binary.NativeEndian, 7, "deploy", "pts/1", "192.0.2.1", 1728360024)
			writeWtmp(t, path, baseline)
			w := &watcher{state: newScanState()}
			t.Cleanup(w.close)
			var events []agentTypes.LoginEvent
			emit := func(ev agentTypes.LoginEvent) { events = append(events, ev) }
			scan := func() {
				t.Helper()
				if !w.scanPath(path, emit) {
					t.Fatal("scan stopped")
				}
			}
			scan()
			if len(events) != 0 || w.offset != int64(size) {
				t.Fatalf("baseline: events=%v offset=%d", events, w.offset)
			}
			writeWtmp(t, path, joinRecords(baseline, fresh[:383]))
			scan()
			if len(events) != 0 || w.offset != int64(size) {
				t.Fatalf("partial append: events=%v offset=%d", events, w.offset)
			}
			writeWtmp(t, path, joinRecords(baseline, fresh))
			scan()
			scan()
			if len(events) != 1 || events[0].Time != 1728360024 || w.offset != int64(2*size) {
				t.Fatalf("complete append: events=%v offset=%d", events, w.offset)
			}

			// A replacement file can have a different ABI. Re-detect the
			// layout while preserving deduplication across the rotation.
			otherSize := 384
			if size == 384 {
				otherSize = 400
			}
			rotated := path + ".new"
			writeWtmp(t, rotated, joinRecords(
				makeABIRecord(otherSize, binary.NativeEndian, 7, "deploy", "pts/1", "192.0.2.1", 1728360024),
				makeABIRecord(otherSize, binary.NativeEndian, 7, "admin", "pts/2", "192.0.2.2", 1728360025),
			))
			if err := os.Rename(rotated, path); err != nil {
				t.Fatal(err)
			}
			scan()
			if len(events) != 2 || events[1].User != "admin" || w.offset != int64(2*otherSize) {
				t.Fatalf("rotation: events=%v offset=%d", events, w.offset)
			}
			writeWtmp(t, path, makeABIRecord(otherSize, binary.NativeEndian, 7, "last", "pts/3", "192.0.2.3", 1728360026))
			scan()
			if len(events) != 3 || events[2].User != "last" || w.offset != int64(otherSize) {
				t.Fatalf("truncation: events=%v offset=%d", events, w.offset)
			}
		})
	}
}

func TestWatcherDelayedDetectionPreservesStartupBaseline(t *testing.T) {
	for _, size := range []int{384, 400} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wtmp")
			// Zero time/address fields make both layouts possible initially.
			baseline := makeABIRecord(size, binary.NativeEndian, 7, "old", "pts/0", "203.0.113.7", 0)
			clear(baseline[336:])
			writeWtmp(t, path, baseline)
			w := &watcher{state: newScanState()}
			t.Cleanup(w.close)
			var events []agentTypes.LoginEvent
			emit := func(ev agentTypes.LoginEvent) { events = append(events, ev) }
			if !w.scanPath(path, emit) || w.offset != 0 {
				t.Fatal("ambiguous data should be retained")
			}
			fresh := makeABIRecord(size, binary.NativeEndian, 7, "new", "pts/1", "192.0.2.1", 1728360024)
			writeWtmp(t, path, joinRecords(baseline, fresh))
			if !w.scanPath(path, emit) || len(events) != 1 || events[0].User != "new" {
				t.Fatalf("events = %v, want only the new login", events)
			}
		})
	}
}

func TestWatcherEmptyStartupThenFirstLogin(t *testing.T) {
	for _, size := range []int{384, 400} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wtmp")
			writeWtmp(t, path, nil)
			w := &watcher{state: newScanState()}
			t.Cleanup(w.close)
			var events []agentTypes.LoginEvent
			emit := func(ev agentTypes.LoginEvent) { events = append(events, ev) }
			if !w.scanPath(path, emit) {
				t.Fatal("empty scan stopped")
			}
			data := makeABIRecord(size, binary.NativeEndian, 7, "new", "pts/0", "203.0.113.7", 1728360024)
			writeWtmp(t, path, data[:383])
			if !w.scanPath(path, emit) || len(events) != 0 || w.offset != 0 {
				t.Fatalf("partial record: events=%v offset=%d", events, w.offset)
			}
			writeWtmp(t, path, data)
			if !w.scanPath(path, emit) || len(events) != 1 || events[0].Time != 1728360024 {
				t.Fatalf("events = %v, want first login", events)
			}
		})
	}
}

func TestWatcherRetriesRotationGapAndReadFailure(t *testing.T) {
	for _, size := range []int{384, 400} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wtmp")
			baseline := makeABIRecord(size, binary.NativeEndian, 7, "old", "pts/0", "203.0.113.7", 1728360023)
			writeWtmp(t, path, baseline)
			w := &watcher{state: newScanState()}
			t.Cleanup(w.close)
			var events []agentTypes.LoginEvent
			emit := func(ev agentTypes.LoginEvent) { events = append(events, ev) }
			if !w.scanPath(path, emit) {
				t.Fatal("baseline scan stopped")
			}
			if err := os.Rename(path, path+".1"); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if !w.scanPath(path, emit) {
					t.Fatal("missing file stopped the watcher")
				}
			}
			// A directory opens and stats successfully, but cannot be read as wtmp.
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if !w.scanPath(path, emit) || w.offset != int64(size) {
				t.Fatal("read failure stopped the watcher or changed its offset")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			writeWtmp(t, path, joinRecords(baseline,
				makeABIRecord(size, binary.NativeEndian, 7, "new", "pts/1", "192.0.2.1", 1728360024)))
			if !w.scanPath(path, emit) || len(events) != 1 || events[0].User != "new" {
				t.Fatalf("recovery: events=%v", events)
			}
			if w.readFailed {
				t.Fatal("successful read did not clear the failure state")
			}
		})
	}
}

func TestWatcherCapsScanBurstWithoutBackfillingDroppedEvents(t *testing.T) {
	for _, size := range []int{384, 400} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wtmp")
			writeWtmp(t, path, nil)
			w := &watcher{state: newScanState()}
			t.Cleanup(w.close)
			var events []agentTypes.LoginEvent
			emit := func(ev agentTypes.LoginEvent) { events = append(events, ev) }
			w.scanPath(path, emit)
			var burst []byte
			for i := 0; i < agentTypes.MaxLoginEventsPerReport+10; i++ {
				burst = append(burst, makeABIRecord(size, binary.NativeEndian, 7, "root", "pts/0", "203.0.113.7", 1728360023+int64(i))...)
			}
			writeWtmp(t, path, burst)
			w.scanPath(path, emit)
			w.scanPath(path, emit)
			if len(events) != agentTypes.MaxLoginEventsPerReport {
				t.Fatalf("burst emitted %d events, want %d", len(events), agentTypes.MaxLoginEventsPerReport)
			}
			// Re-reading the same records after rotation must not send the excess.
			writeWtmp(t, path+".new", burst)
			if err := os.Rename(path+".new", path); err != nil {
				t.Fatal(err)
			}
			w.scanPath(path, emit)
			if len(events) != agentTypes.MaxLoginEventsPerReport {
				t.Fatalf("rotation backfilled dropped events: %v", events)
			}
			writeWtmp(t, path, append(burst, makeABIRecord(size, binary.NativeEndian, 7, "next", "pts/1", "192.0.2.1", 1728361000)...))
			w.scanPath(path, emit)
			if len(events) != agentTypes.MaxLoginEventsPerReport+1 || events[len(events)-1].User != "next" {
				t.Fatalf("next scan failed to report a fresh login: %v", events)
			}
		})
	}
}

func writeWtmp(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestUtmpRotatedMetadataSignals(t *testing.T) {
	prevCtim := syscall.Timespec{Sec: 1000, Nsec: 500}

	// A backward ctime jump remains an additional reset signal. Inode
	// reuse itself is prevented by retaining the file descriptor.
	recreated := &syscall.Stat_t{Ino: 42, Ctim: syscall.Timespec{Sec: 900, Nsec: 0}}
	if !utmpRotated(recreated, 2*384, 384, 42, prevCtim) {
		t.Fatal("recreated file with reused inode and backward ctime not detected as rotated")
	}

	// Forward ctime movement (a normal append updates ctime) must not rotate,
	// even on coarse-granularity filesystems that keep the same second.
	appended := &syscall.Stat_t{Ino: 42, Ctim: syscall.Timespec{Sec: 1000, Nsec: 501}}
	if utmpRotated(appended, 2*384, 384, 42, prevCtim) {
		t.Fatal("append with forward ctime misdetected as rotation")
	}
	sameSecond := &syscall.Stat_t{Ino: 42, Ctim: syscall.Timespec{Sec: 1000, Nsec: 500}}
	if utmpRotated(sameSecond, 2*384, 384, 42, prevCtim) {
		t.Fatal("same-second append misdetected as rotation")
	}

	// The pre-existing signals keep working.
	truncated := &syscall.Stat_t{Ino: 42, Ctim: syscall.Timespec{Sec: 1001, Nsec: 0}}
	if !utmpRotated(truncated, 100, 384, 42, prevCtim) {
		t.Fatal("truncation not detected as rotation")
	}
	renamed := &syscall.Stat_t{Ino: 43, Ctim: syscall.Timespec{Sec: 1001, Nsec: 0}}
	if !utmpRotated(renamed, 2*384, 384, 42, prevCtim) {
		t.Fatal("inode change not detected as rotation")
	}

	// Without a previous observation a backward ctime alone must not rotate:
	// the first scan is anchored by the inode/size signals instead.
	fresh := &syscall.Stat_t{Ino: 42, Ctim: syscall.Timespec{Sec: 1, Nsec: 0}}
	if utmpRotated(fresh, 384, 0, 42, syscall.Timespec{}) {
		t.Fatal("backward ctime without a previous observation misdetected as rotation")
	}
}

func TestWatcherRotationBeforeDetectionKeepsStartupBoundary(t *testing.T) {
	for _, size := range []int{384, 400} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wtmp")
			// Zero time/address fields make both layouts possible, deferring
			// detection beyond the first scan.
			baseline := makeABIRecord(size, binary.NativeEndian, 7, "old", "pts/0", "203.0.113.7", 0)
			clear(baseline[336:])
			writeWtmp(t, path, baseline)
			w := &watcher{state: newScanState(), startupTime: 1728360020}
			t.Cleanup(w.close)
			var events []agentTypes.LoginEvent
			emit := func(ev agentTypes.LoginEvent) { events = append(events, ev) }
			if !w.scanPath(path, emit) || w.offset != 0 {
				t.Fatal("ambiguous data should be retained")
			}

			// Rotate to a new file holding two complete records before
			// detection lands. Only the first two predate monitoring.
			rotated := path + ".new"
			writeWtmp(t, rotated, joinRecords(
				makeABIRecord(size, binary.NativeEndian, 7, "older", "pts/9", "198.51.100.9", 1728360000),
				makeABIRecord(size, binary.NativeEndian, 7, "pre", "pts/8", "198.51.100.8", 1728360001),
				makeABIRecord(size, binary.NativeEndian, 7, "at-rotation", "pts/2", "192.0.2.2", 1728360021),
			))
			if err := os.Rename(rotated, path); err != nil {
				t.Fatal(err)
			}
			if !w.scanPath(path, emit) {
				t.Fatal("scan stopped")
			}
			if len(events) != 1 || events[0].User != "at-rotation" {
				t.Fatalf("rotation must report only the new login: %v", events)
			}
			if want := int64(3 * size); w.offset != want {
				t.Fatalf("offset = %d, want %d (baseline skipped to end)", w.offset, want)
			}

			// A later append on the rotated file is still reported.
			writeWtmp(t, path, joinRecords(
				makeABIRecord(size, binary.NativeEndian, 7, "older", "pts/9", "198.51.100.9", 1728360000),
				makeABIRecord(size, binary.NativeEndian, 7, "pre", "pts/8", "198.51.100.8", 1728360001),
				makeABIRecord(size, binary.NativeEndian, 7, "at-rotation", "pts/2", "192.0.2.2", 1728360021),
				makeABIRecord(size, binary.NativeEndian, 7, "fresh", "pts/1", "192.0.2.1", 1728360024),
			))
			if !w.scanPath(path, emit) || len(events) != 2 || events[1].User != "fresh" {
				t.Fatalf("append after rotation: events = %v, want only the fresh login", events)
			}
		})
	}
}

func TestWatcherPinsInodeAcrossDeleteAndRecreate(t *testing.T) {
	for _, size := range []int{384, 400} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wtmp")
			writeWtmp(t, path, makeABIRecord(size, binary.NativeEndian, 7, "old", "pts/0", "192.0.2.1", 1728360000))
			w := &watcher{state: newScanState()}
			t.Cleanup(w.close)
			var events []agentTypes.LoginEvent
			emit := func(ev agentTypes.LoginEvent) { events = append(events, ev) }
			w.scanPath(path, emit)
			pinned := w.file
			if pinned == nil {
				t.Fatal("scan must hold the inode open")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			// A missing-file scan must also keep the inode pinned.
			w.scanPath(path, emit)
			info, err := pinned.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if info.Sys().(*syscall.Stat_t).Nlink != 0 {
				t.Fatal("old inode should be unlinked but still open")
			}
			writeWtmp(t, path, joinRecords(
				makeABIRecord(size, binary.NativeEndian, 7, "new-first", "pts/1", "192.0.2.2", 1728360021),
				makeABIRecord(size, binary.NativeEndian, 7, "new-second", "pts/2", "192.0.2.3", 1728360022),
			))
			w.scanPath(path, emit)
			if len(events) != 2 || events[0].User != "new-first" {
				t.Fatalf("replacement skipped events before the old offset: %v", events)
			}
			if _, err := pinned.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("previous descriptor was not released: %v", err)
			}
			w.close()
			if w.file != nil {
				t.Fatal("watcher close retained descriptor")
			}
		})
	}
}
