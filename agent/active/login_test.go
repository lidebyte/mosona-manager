package active

import (
	"errors"
	"mosona-manager/agent/config"
	"mosona-manager/agent/logins"
	"mosona-manager/pkg/securews"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestLoginWebSocketNoMonitorDeclinesStream(t *testing.T) {
	testLoginWebSocketDeclinesStream(t, true)
}

func TestLoginWebSocketUnsupportedPlatformDeclinesStream(t *testing.T) {
	if logins.Supported {
		t.Skip("requires an unsupported platform")
	}
	testLoginWebSocketDeclinesStream(t, false)
}

func testLoginWebSocketDeclinesStream(t *testing.T, noMonitor bool) {
	t.Helper()
	oldConfig := config.Current
	config.Current.NoMonitor = noMonitor
	t.Cleanup(func() { config.Current = oldConfig })

	serverDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(serverDone)
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		handleLoginWebSocket(conn, (*secureWS.SessionCrypto)(nil))
	}))
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = conn.ReadMessage()
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) {
		t.Fatalf("read error = %v, want a close frame", err)
	}
	if closeErr.Code != websocket.ClosePolicyViolation {
		t.Fatalf("close code = %d, want policy violation", closeErr.Code)
	}
	if !strings.Contains(closeErr.Text, "login monitoring disabled") {
		t.Fatalf("close text = %q, want the disable reason", closeErr.Text)
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("login WebSocket handler did not return after declining the stream")
	}
}
