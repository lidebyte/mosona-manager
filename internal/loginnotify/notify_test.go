package loginnotify

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"mosona-manager/internal/servernotify"
	"mosona-manager/internal/utils"
)

type notifyRecorder struct {
	mu       sync.Mutex
	messages []string
	items    []string
}

func (r *notifyRecorder) record(ctx context.Context, teamId, serverId int64, item, message string) servernotify.Delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, message)
	r.items = append(r.items, item)
	return servernotify.Delivery{Attempted: true, Delivered: true}
}

func stubDeps(t *testing.T, ruleEnabled bool, geo utils.IPGeoResponse, geoErr error) *notifyRecorder {
	t.Helper()

	originalQuery := queryLoginAlertOn
	originalGeo := getIPGeoLocation
	originalNotify := notifyServerEvent
	originalLog := addSecurityLog

	recorder := &notifyRecorder{}
	queryLoginAlertOn = func(context.Context, int64) bool { return ruleEnabled }
	getIPGeoLocation = func(ip string) (utils.IPGeoResponse, error) { return geo, geoErr }
	notifyServerEvent = recorder.record
	addSecurityLog = func(int64, int64, string, string, string, string, string) {}

	t.Cleanup(func() {
		queryLoginAlertOn = originalQuery
		getIPGeoLocation = originalGeo
		notifyServerEvent = originalNotify
		addSecurityLog = originalLog
	})
	return recorder
}

func TestReportSkippedWhenRuleDisabled(t *testing.T) {
	recorder := stubDeps(t, false, utils.IPGeoResponse{Country: "China"}, nil)

	Report(context.Background(), 1, 7, []Event{
		{User: "root", TTY: "pts/0", IP: "203.0.113.7"},
	})

	if len(recorder.messages) != 0 {
		t.Fatalf("notifications sent despite disabled rule: %v", recorder.messages)
	}
}

func TestReportEmptySkipsRuleLookup(t *testing.T) {
	stubDeps(t, true, utils.IPGeoResponse{}, nil)
	queryLoginAlertOn = func(context.Context, int64) bool {
		t.Fatal("empty report must not query alert rules")
		return false
	}
	Report(context.Background(), 1, 7, nil)
	Report(context.Background(), 1, 7, []Event{})
}

func TestReportCanceledSkipsRuleLookup(t *testing.T) {
	recorder := stubDeps(t, true, utils.IPGeoResponse{}, nil)
	queryLoginAlertOn = func(context.Context, int64) bool {
		t.Fatal("canceled report must not query alert rules")
		return false
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Report(ctx, 1, 7, []Event{{User: "root", IP: "203.0.113.7"}})
	if len(recorder.messages) != 0 {
		t.Fatal("canceled report sent notifications")
	}
}

func TestReportIncludesUserIPAndCountry(t *testing.T) {
	recorder := stubDeps(t, true, utils.IPGeoResponse{Country: "China"}, nil)

	Report(context.Background(), 1, 7, []Event{
		{User: "root", TTY: "pts/0", IP: "203.0.113.7"},
	})

	if len(recorder.messages) != 1 {
		t.Fatalf("messages = %v", recorder.messages)
	}
	want := "User 'root' logged in via SSH from 203.0.113.7 (China)"
	if recorder.messages[0] != want {
		t.Fatalf("message = %q, want %q", recorder.messages[0], want)
	}
	if recorder.items[0] != "SSH Login" {
		t.Fatalf("item = %q", recorder.items[0])
	}
}

func TestReportFallsBackToUnknownCountry(t *testing.T) {
	recorder := stubDeps(t, true, utils.IPGeoResponse{}, errors.New("geo db unavailable"))

	Report(context.Background(), 1, 7, []Event{
		{User: "root", TTY: "pts/0", IP: "203.0.113.7"},
	})

	if len(recorder.messages) != 1 || !strings.Contains(recorder.messages[0], "(Unknown)") {
		t.Fatalf("messages = %v, want Unknown country fallback", recorder.messages)
	}
}

func TestReportCapPerBatch(t *testing.T) {
	recorder := stubDeps(t, true, utils.IPGeoResponse{Country: "China"}, nil)

	events := make([]Event, 0, MaxEventsPerReport+2)
	for i := 0; i < MaxEventsPerReport+2; i++ {
		events = append(events, Event{User: "root", TTY: "pts/0", IP: "203.0.113.7"})
	}
	Report(context.Background(), 1, 7, events)

	if len(recorder.messages) != MaxEventsPerReport {
		t.Fatalf("notified %d times, want cap %d", len(recorder.messages), MaxEventsPerReport)
	}
}
