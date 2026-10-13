package agent

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	agentTypes "mosona-manager/agent/types"
	"mosona-manager/internal/db"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/websocket"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v5"
)

func TestPassiveReadLoopContinuesWhileLoginLookupBlocks(t *testing.T) {
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseLookup) }) }
	defer release()
	var startedOnce sync.Once
	matcher := sqlmock.QueryMatcherFunc(func(expected, actual string) error {
		if expected != actual {
			return errors.New("unexpected query: " + actual)
		}
		if strings.HasPrefix(actual, "SELECT team_id") {
			startedOnce.Do(func() { close(lookupStarted) })
			<-releaseLookup
		}
		return nil
	})
	database, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(matcher))
	if err != nil {
		t.Fatal(err)
	}
	oldDB := db.Db
	db.Db = sqlx.NewDb(database, "sqlmock")
	t.Cleanup(func() {
		release()
		_ = database.Close()
		db.Db = oldDB
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
	})
	mock.ExpectQuery("SELECT type = 2 AND allow_monitor FROM servers WHERE id = $1").
		WithArgs(int64(91)).WillReturnRows(sqlmock.NewRows([]string{"enabled"}).AddRow(true))
	mock.ExpectQuery("SELECT team_id FROM servers WHERE id = $1").
		WithArgs(int64(91)).WillReturnError(errors.New("test lookup failure"))

	handlerDone := make(chan error, 1)
	e := echo.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := e.NewContext(r, w)
		c.Set("server_id", int64(91))
		handlerDone <- passiveWS(c)
	}))
	defer func() {
		release()
		server.Close()
	}()
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	frame, err := agentTypes.MarshalMsg(agentTypes.LoginEvent{User: "root", IP: "203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-lookupStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("login report never started")
	}
	for i := 0; i < 100; i++ {
		if err := client.WriteMessage(websocket.BinaryMessage, frame); err != nil {
			t.Fatal(err)
		}
	}
	_ = client.Close()
	select {
	case err := <-handlerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("websocket read loop blocked by login report")
	}
}
