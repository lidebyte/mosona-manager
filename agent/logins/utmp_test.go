package logins

import (
	"encoding/binary"
	"net"
	"testing"
)

func makeRecord(utType int16, user, tty, host string, sec int64) []byte {
	return makeABIRecord(384, binary.NativeEndian, utType, user, tty, host, sec)
}

// Offsets are independent of the parser constants and follow the libc ABIs.
func makeABIRecord(size int, order binary.ByteOrder, utType int16, user, tty, host string, sec int64) []byte {
	buf := make([]byte, size)
	order.PutUint16(buf[0:2], uint16(utType))
	copy(buf[8:40], tty)
	copy(buf[44:76], user)
	copy(buf[76:332], host)
	addrOffset := 348
	if size == 384 {
		order.PutUint32(buf[340:344], uint32(sec))
		order.PutUint32(buf[344:348], 123456)
	} else {
		order.PutUint64(buf[344:352], uint64(sec))
		order.PutUint64(buf[352:360], 123456)
		addrOffset = 360
	}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			copy(buf[addrOffset:addrOffset+4], ipv4)
		} else {
			copy(buf[addrOffset:addrOffset+16], ip.To16())
		}
	}
	return buf
}

func joinRecords(records ...[]byte) []byte {
	var out []byte
	for _, r := range records {
		out = append(out, r...)
	}
	return out
}

func TestParseUtmpRecordValidLogin(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, layout := range utmpLayouts(order) {
			buf := makeABIRecord(layout.recordSize, order, utmpTypeUserProcess, "root", "pts/0", "203.0.113.7", 1728360023)
			rec, ok := parseUtmpRecord(buf, layout)
			if !ok {
				t.Fatal("valid login record rejected")
			}
			if rec.user != "root" || rec.tty != "pts/0" || rec.ip != "203.0.113.7" || rec.time != 1728360023 {
				t.Fatalf("%s/%d: record = %#v", order, layout.recordSize, rec)
			}
		}
	}
}

func TestParseUtmpRecordSignedTime(t *testing.T) {
	for _, layout := range utmpLayouts(binary.NativeEndian) {
		times := []int64{-1}
		if layout.time64 {
			times = append(times, 2200000000)
		}
		for _, sec := range times {
			buf := makeABIRecord(layout.recordSize, layout.order, 7, "root", "pts/0", "203.0.113.7", sec)
			rec, ok := parseUtmpRecord(buf, layout)
			if !ok || rec.time != sec {
				t.Fatalf("%d: time = %d, want %d (ok=%v)", layout.recordSize, rec.time, sec, ok)
			}
		}
	}
}

func TestParseUtmpRecordSourceAddress(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, layout := range utmpLayouts(order) {
			for _, ip := range []string{"203.0.113.7", "2001:db8::7", "::1", "::ffff:203.0.113.7"} {
				for _, host := range []string{"workstation", "client.example.com", "192.0.2.1", ""} {
					buf := makeABIRecord(layout.recordSize, order, 7, "root", "pts/0", ip, 1728360023)
					clear(buf[76:332])
					copy(buf[76:332], host)
					rec, ok := parseUtmpRecord(buf, layout)
					want := net.ParseIP(ip).String()
					if !ok || rec.ip != want {
						t.Fatalf("%s/%d, host %q: IP = %q, ok=%v; want %q", order, layout.recordSize, host, rec.ip, ok, want)
					}
				}
			}
			for _, host := range []string{"203.0.113.7", "2001:db8::7", "::1", "client.example.com", "workstation", "999.999.999.999", ""} {
				buf := makeABIRecord(layout.recordSize, order, 7, "root", "pts/0", host, 1728360023)
				clear(buf[layout.addrOffset : layout.addrOffset+16])
				rec, ok := parseUtmpRecord(buf, layout)
				ip := net.ParseIP(host)
				if ip == nil {
					if ok {
						t.Fatalf("invalid fallback %q accepted: %+v", host, rec)
					}
				} else if !ok || rec.ip != ip.String() {
					t.Fatalf("numeric fallback %q: record=%+v, ok=%v", host, rec, ok)
				}
			}
		}
	}
}

func TestParseUtmpRecordFilters(t *testing.T) {
	cases := []struct {
		name string
		rec  []byte
	}{
		{"wrong type", makeRecord(8, "root", "pts/0", "203.0.113.7", 1)},
		{"empty user", makeRecord(utmpTypeUserProcess, "", "pts/0", "203.0.113.7", 1)},
		{"hostname not ip", makeRecord(utmpTypeUserProcess, "root", "pts/0", "localhost", 1)},
		{"short buffer", makeRecord(utmpTypeUserProcess, "root", "pts/0", "203.0.113.7", 1)[:100]},
	}
	for _, tc := range cases {
		if _, ok := parseUtmpRecord(tc.rec, utmpLayouts(binary.NativeEndian)[0]); ok {
			t.Fatalf("%s: record accepted", tc.name)
		}
	}
}

func TestParseUtmpRecordsDropsTrailingPartialRecord(t *testing.T) {
	data := joinRecords(
		makeRecord(utmpTypeUserProcess, "root", "pts/0", "203.0.113.7", 1),
		makeRecord(utmpTypeUserProcess, "deploy", "pts/1", "192.0.2.1", 2),
	)
	data = append(data, makeRecord(utmpTypeUserProcess, "partial", "pts/2", "192.0.2.2", 3)[:200]...)

	records := parseUtmpRecords(data, utmpLayouts(binary.NativeEndian)[0])
	if len(records) != 2 || records[1].user != "deploy" {
		t.Fatalf("records = %#v, want 2 complete entries", records)
	}
}

func TestDetectUtmpLayoutAndParseMultipleRecords(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, size := range []int{384, 400} {
			first := makeABIRecord(size, order, 2, "", "~", "", 1728360000)
			second := makeABIRecord(size, order, 7, "root", "pts/0", "203.0.113.7", 1728360023)
			third := makeABIRecord(size, order, 7, "deploy", "pts/1", "192.0.2.1", 1728360024)
			for _, partial := range []int{0, 100, 383} {
				data := joinRecords(first, second, third, third[:partial])
				layout, ok := detectUtmpLayout(data, order)
				if !ok || layout.recordSize != size {
					t.Fatalf("%s/%d, partial %d: layout = %+v, ok = %v", order, size, partial, layout, ok)
				}
				recs := parseUtmpRecords(data, layout)
				if len(recs) != 2 || recs[0].time != 1728360023 || recs[1].user != "deploy" || recs[1].time != 1728360024 {
					t.Fatalf("%s/%d: records = %#v", order, size, recs)
				}
			}
		}
	}
}

func TestDetectUtmpLayoutDefersAmbiguousAndShortData(t *testing.T) {
	for _, n := range []int{0, 100, 384, 400, 800} {
		if layout, ok := detectUtmpLayout(make([]byte, n), binary.NativeEndian); ok {
			t.Fatalf("%d zero bytes: accepted ambiguous layout %+v", n, layout)
		}
	}
}

func TestDetectUtmpLayoutWhenBothRecordSizesDivideFileSize(t *testing.T) {
	for _, size := range []int{384, 400} {
		var data []byte
		for i := 0; i < 9600/size; i++ {
			data = append(data, makeABIRecord(size, binary.NativeEndian, 7, "root", "pts/0", "203.0.113.7", 1728360023+int64(i))...)
		}
		layout, ok := detectUtmpLayout(data, binary.NativeEndian)
		if !ok || layout.recordSize != size {
			t.Fatalf("%d: layout=%+v, ok=%v", size, layout, ok)
		}
		if records := parseUtmpRecords(data, layout); len(records) != 9600/size {
			t.Fatalf("%d: parsed %d records", size, len(records))
		}
	}
}

func TestScanStateSeedsBaselineThenDeduplicates(t *testing.T) {
	state := newScanState()

	first := []record{
		{user: "root", tty: "pts/0", ip: "203.0.113.7", time: 1},
	}
	if fresh := state.ingest(first); len(fresh) != 0 {
		t.Fatalf("baseline ingest emitted %v, want none", fresh)
	}

	repeated := state.ingest([]record{
		{user: "root", tty: "pts/0", ip: "203.0.113.7", time: 1},
		{user: "deploy", tty: "pts/1", ip: "192.0.2.1", time: 2},
	})
	if len(repeated) != 1 || repeated[0].user != "deploy" {
		t.Fatalf("fresh = %#v, want only the deploy session", repeated)
	}
}

func TestScanStateKeyIncludesLoginTime(t *testing.T) {
	state := newScanState()
	state.ingest([]record{{user: "root", tty: "pts/0", ip: "203.0.113.7", time: 1}})

	fresh := state.ingest([]record{{user: "root", tty: "pts/0", ip: "203.0.113.7", time: 2}})
	if len(fresh) != 1 {
		t.Fatalf("same session at a different time must be a new event, got %v", fresh)
	}
}

func TestScanStateEvictsOldestWhenFull(t *testing.T) {
	state := newScanState()
	state.seeded = true
	records := make([]record, 0, maxSeenKeys+1)
	for i := 0; i < maxSeenKeys+1; i++ {
		records = append(records, record{user: "u", tty: "pts/0", ip: "198.51.100.1", time: int64(i)})
	}
	fresh := state.ingest(records)
	if len(fresh) != maxSeenKeys+1 {
		t.Fatalf("fresh = %d, want all %d new sessions", len(fresh), maxSeenKeys+1)
	}
	if len(state.seen) > maxSeenKeys {
		t.Fatalf("seen set has %d entries, want <= %d", len(state.seen), maxSeenKeys)
	}
	if len(state.order)-state.head != len(state.seen) {
		t.Fatalf("window tracking out of sync: order %d, seen %d", len(state.order)-state.head, len(state.seen))
	}
}
