package servernotify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"mosona-manager/internal/_type"
	"mosona-manager/internal/db"
)

func stubDelivery(t *testing.T) *[]string {
	t.Helper()
	var sent []string
	original := SendShoutrrr
	SendShoutrrr = func(_ context.Context, _ string, message string) error {
		sent = append(sent, message)
		return nil
	}
	t.Cleanup(func() { SendShoutrrr = original })
	return &sent
}

func TestDeliverFormatsShoutrrrMessageLikeServerAlerts(t *testing.T) {
	sent := stubDelivery(t)

	delivery := Deliver(
		context.Background(),
		7,
		"web-1",
		[]*_type.TeamNotification{{Module: "shoutrrr", Target: "generic://test"}},
		"SSH Login",
		"User 'root' logged in via SSH from 203.0.113.7 (China)",
	)

	if !delivery.Attempted || !delivery.Delivered {
		t.Fatalf("delivery = %#v, want attempted and delivered", delivery)
	}
	if len(*sent) != 1 {
		t.Fatalf("sent = %v", *sent)
	}
	message := (*sent)[0]
	if !strings.Contains(message, "<b>web-1 – SSH Login</b>") {
		t.Fatalf("message %q missing server/item header", message)
	}
	if !strings.Contains(message, "User 'root' logged in via SSH from 203.0.113.7 (China)") {
		t.Fatalf("message %q missing login details", message)
	}
	if !strings.HasSuffix(message, "/7/monitor") {
		t.Fatalf("message %q missing monitor link", message)
	}
}

func TestDeliverAddsTelegramParseMode(t *testing.T) {
	var target string
	original := SendShoutrrr
	SendShoutrrr = func(_ context.Context, t2 string, _ string) error {
		target = t2
		return nil
	}
	t.Cleanup(func() { SendShoutrrr = original })

	Deliver(context.Background(), 7, "web-1",
		[]*_type.TeamNotification{{Module: "shoutrrr", Target: "telegram://token@channel"}},
		"SSH Login", "msg",
	)

	if !strings.Contains(target, "parsemode=HTML") {
		t.Fatalf("target %q missing parsemode", target)
	}
}

func TestDeliverWithoutChannelsIsNotAttempted(t *testing.T) {
	delivery := Deliver(context.Background(), 7, "web-1", nil, "SSH Login", "msg")
	if delivery.Attempted || delivery.Delivered {
		t.Fatalf("delivery = %#v, want not attempted", delivery)
	}
}

func TestDeliverReportsFailure(t *testing.T) {
	original := SendShoutrrr
	SendShoutrrr = func(context.Context, string, string) error { return errors.New("send failed") }
	t.Cleanup(func() { SendShoutrrr = original })

	delivery := Deliver(context.Background(), 7, "web-1",
		[]*_type.TeamNotification{{Module: "shoutrrr", Target: "generic://test"}},
		"SSH Login", "msg",
	)

	if !delivery.Attempted || delivery.Delivered {
		t.Fatalf("delivery = %#v, want attempted but not delivered", delivery)
	}
}

func TestNotifyServerEventPropagatesCancellation(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	oldDB := db.Db
	db.Db = sqlx.NewDb(database, "sqlmock")
	oldSender := SendShoutrrr
	t.Cleanup(func() {
		SendShoutrrr = oldSender
		db.Db = oldDB
		_ = database.Close()
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
	})
	mock.ExpectQuery("SELECT name FROM servers").WithArgs(int64(7), int64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("web-1"))
	mock.ExpectQuery("SELECT module, target FROM teams_notifications").WithArgs(int64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"module", "target"}).
			AddRow("shoutrrr", "generic://first").AddRow("shoutrrr", "generic://second"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	SendShoutrrr = func(sendCtx context.Context, _, _ string) error {
		calls++
		cancel()
		if sendCtx.Err() != context.Canceled {
			t.Fatal("notification did not receive caller cancellation")
		}
		return sendCtx.Err()
	}
	delivery := NotifyServerEvent(ctx, 2, 7, "SSH Login", "msg")
	if calls != 1 || !delivery.Attempted || delivery.Delivered {
		t.Fatalf("calls = %d, delivery = %#v; want one canceled attempt", calls, delivery)
	}
}

func TestDeliverCanceledContextDoesNotSend(t *testing.T) {
	sent := stubDelivery(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	delivery := Deliver(ctx, 7, "web-1",
		[]*_type.TeamNotification{{Module: "shoutrrr", Target: "generic://test"}},
		"SSH Login", "msg")
	if len(*sent) != 0 || delivery.Attempted || delivery.Delivered {
		t.Fatalf("sent = %v, delivery = %#v; want no attempt", *sent, delivery)
	}
}
