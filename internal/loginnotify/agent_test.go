package loginnotify

import (
	"context"
	"sync"
	"testing"
	"time"

	agentTypes "mosona-manager/agent/types"
	"mosona-manager/internal/db"
	"mosona-manager/internal/utils"
	pbTypes "mosona-manager/pkg/types"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/vmihailenco/msgpack/v5"
)

func TestAgentReporterCapsBurstEvenWhenWorkerDrainsQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reports := make(chan Event, MaxEventsPerReport+1)
	r := newAgentReporter(ctx, 91, func(_ context.Context, serverID int64, events []Event) {
		if serverID != 91 {
			t.Errorf("server ID = %d, want 91", serverID)
		}
		for _, event := range events {
			reports <- event
		}
	})
	now := time.Now()
	for i := 0; i < MaxEventsPerReport; i++ {
		if !r.submitAt(Event{Time: int64(i)}, now) {
			t.Fatal("event within the limit was rejected")
		}
		select {
		case event := <-reports:
			if event.Time != int64(i) {
				t.Fatalf("event order changed: %+v", event)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("report worker did not consume an event")
		}
	}
	if r.submitAt(Event{}, now) {
		t.Fatal("sixth event in one scan window was accepted")
	}
	if !r.submitAt(Event{Time: 99}, now.Add(agentTypes.LoginReportInterval)) {
		t.Fatal("new scan window did not reset the limit")
	}
	<-reports
	cancel()
	waitReporter(t, r)
}

func TestAgentReporterSlowDeliveryKeepsQueueBoundedAndDiscardsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var delivered int
	r := newAgentReporter(ctx, 91, func(context.Context, int64, []Event) {
		delivered++
		if delivered == 1 {
			close(started)
		}
		<-release
	})
	now := time.Now()
	r.submitAt(Event{}, now)
	<-started
	submitted := make(chan int, 1)
	go func() {
		accepted := 0
		for i := 1; i < 1000; i++ {
			if r.submitAt(Event{Time: int64(i)}, now) {
				accepted++
			}
		}
		submitted <- accepted
	}()
	select {
	case accepted := <-submitted:
		if accepted != MaxEventsPerReport-1 {
			t.Fatalf("accepted %d queued events, want %d", accepted, MaxEventsPerReport-1)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("submitting events blocked on slow delivery")
	}
	next := now.Add(agentTypes.LoginReportInterval)
	if !r.submitAt(Event{}, next) || r.submitAt(Event{}, next) {
		t.Fatal("queue did not enforce its capacity across scan windows")
	}
	cancel()
	if r.submitAt(Event{}, next.Add(agentTypes.LoginReportInterval)) {
		t.Fatal("canceled reporter accepted an event")
	}
	unblock()
	waitReporter(t, r)
	if delivered != 1 {
		t.Fatalf("delivered %d events; queued events should be discarded on cancellation", delivered)
	}
}

func TestAgentReporterDecodesExistingLoginFrames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reports := make(chan Event, 1)
	r := newAgentReporter(ctx, 91, func(_ context.Context, _ int64, events []Event) {
		for _, event := range events {
			reports <- event
		}
	})
	r.SubmitMsg(pbTypes.Msg{Data: []byte{0xc1}})
	ev := agentTypes.LoginEvent{User: "root", TTY: "pts/0", IP: "203.0.113.7", Time: 1728360023}
	data, err := agentTypes.MarshalMsg(ev)
	if err != nil {
		t.Fatal(err)
	}
	var frame pbTypes.Msg
	if err := msgpack.Unmarshal(data, &frame); err != nil {
		t.Fatal(err)
	}
	r.SubmitMsg(frame)
	select {
	case event := <-reports:
		if event != (Event{User: ev.User, TTY: ev.TTY, IP: ev.IP, Time: ev.Time}) {
			t.Fatalf("decoded event = %+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("valid login frame was not reported")
	}
	cancel()
	waitReporter(t, r)
}

func TestDrainEventsCollectsQueuedBurst(t *testing.T) {
	events := make(chan Event, MaxEventsPerReport)
	for i := 0; i < 3; i++ {
		events <- Event{Time: int64(i)}
	}
	batch := drainEvents(events, Event{Time: 99})
	if len(batch) != 4 || batch[0].Time != 99 || batch[3].Time != 2 {
		t.Fatalf("batch = %+v", batch)
	}
}

func TestReportAgentEventsResolvesTeamOncePerBatch(t *testing.T) {
	recorder := stubDeps(t, true, utils.IPGeoResponse{Country: "China"}, nil)
	database, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	oldDB := db.Db
	db.Db = sqlx.NewDb(database, "sqlmock")
	t.Cleanup(func() {
		_ = database.Close()
		db.Db = oldDB
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
	})
	mock.ExpectQuery("SELECT team_id FROM servers WHERE id = $1").WithArgs(int64(91)).
		WillReturnRows(sqlmock.NewRows([]string{"team_id"}).AddRow(int64(7)))

	events := make([]Event, 0, MaxEventsPerReport)
	for i := 0; i < MaxEventsPerReport; i++ {
		events = append(events, Event{User: "root", TTY: "pts/0", IP: "203.0.113.7"})
	}
	reportAgentEvents(context.Background(), 91, events)

	// sqlmock fails the test on any second team_id query, proving the
	// lookup happens once per batch.
	if len(recorder.messages) != len(events) {
		t.Fatalf("messages = %d, want %d", len(recorder.messages), len(events))
	}
}

func waitReporter(t *testing.T, r *AgentReporter) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(2 * time.Second):
		t.Fatal("reporter did not stop")
	}
}

func TestAgentReportCachesLookupsAcrossSeparateBatchesAndRefreshes(t *testing.T) {
	recorder := stubDeps(t, true, utils.IPGeoResponse{}, nil)
	queryLoginAlertOn = SSHLoginAlertEnabled
	database, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	oldDB := db.Db
	db.Db = sqlx.NewDb(database, "sqlmock")
	t.Cleanup(func() {
		_ = database.Close()
		db.Db = oldDB
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
	})
	expectLookups := func(enabled bool) {
		mock.ExpectQuery("SELECT team_id FROM servers WHERE id = $1").WithArgs(int64(91)).
			WillReturnRows(sqlmock.NewRows([]string{"team_id"}).AddRow(int64(7)))
		mock.ExpectQuery("SELECT EXISTS (SELECT 1 FROM server_alerts WHERE server_id = $1 AND item = $2)").
			WithArgs(int64(91), db.AlertItemSSHLogin).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(enabled))
	}
	now := time.Now()
	report := cachedAgentReport(func() time.Time { return now })
	expectLookups(true)
	for i := 0; i < MaxEventsPerReport; i++ {
		// Wait for each report to finish before sending the next: draining
		// the queue cannot help in this worst-case arrival pattern.
		report(context.Background(), 91, []Event{{User: "root", IP: "192.0.2.1"}})
	}
	if len(recorder.messages) != MaxEventsPerReport {
		t.Fatalf("delivered %d events", len(recorder.messages))
	}
	now = now.Add(agentTypes.LoginReportInterval)
	expectLookups(false)
	for i := 0; i < MaxEventsPerReport; i++ {
		report(context.Background(), 91, []Event{{User: "root", IP: "192.0.2.1"}})
	}
	if len(recorder.messages) != MaxEventsPerReport {
		t.Fatal("disabled rule was not refreshed")
	}
}
