package active

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentTypes "mosona-manager/agent/types"
	"mosona-manager/internal/db"
	secureWS "mosona-manager/pkg/securews"
	"mosona-manager/pkg/ws"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/websocket"
	"github.com/jmoiron/sqlx"
)

func TestLoginMonitorRetriesDialAndDisconnectedStreams(t *testing.T) {
	identityPrivate := mustGenerateIdentity(t)
	var attempts atomic.Int32
	nonces := make(chan string, 3)
	handshakes := make(chan error, 2)
	host, port := startFakeAgentServer(t, func(w http.ResponseWriter, r *http.Request) {
		nonces <- r.Header.Get("X-Agent-Nonce")
		if attempts.Add(1) == 1 {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		conn, err := upgradeFakeAgent(w, r)
		if err == nil {
			// The fake agent closes only the login socket after completing
			// authentication, exercising independent stream recovery.
			_, err = serveFakeAgentHandshake(conn, r, identityPrivate, nil, true, nil)
		}
		handshakes <- err
	})
	a := newTestHubAuth(t, host, port, identityPrivate.Public().(ed25519.PublicKey))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.monitorActiveAgentLogins(ctx, 20*time.Millisecond)
	}()
	for i := 0; i < 2; i++ {
		waitFakeAgent(t, handshakes)
	}
	cancel()
	waitLoginMonitor(t, done)
	seen := make(map[string]bool)
	for i := 0; i < 3; i++ {
		nonce := <-nonces
		if nonce == "" || seen[nonce] {
			t.Fatal("each retry must use fresh authentication headers")
		}
		seen[nonce] = true
	}
}

func TestLoginMonitorStopsForUnavailableEndpoint(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var attempts atomic.Int32
			host, port := startFakeAgentServer(t, func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				http.Error(w, "unsupported endpoint", status)
			})
			a := newTestHubAuth(t, host, port, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			a.monitorActiveAgentLogins(ctx, time.Millisecond)
			if ctx.Err() != nil || attempts.Load() != 1 {
				t.Fatalf("unsupported endpoint: attempts=%d, context=%v", attempts.Load(), ctx.Err())
			}
		})
	}
}

func TestLoginMonitorCancellationInterruptsRetryDelay(t *testing.T) {
	dialed := make(chan struct{}, 1)
	var attempts atomic.Int32
	host, port := startFakeAgentServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		dialed <- struct{}{}
	})
	a := newTestHubAuth(t, host, port, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.monitorActiveAgentLogins(ctx, time.Hour)
	}()
	select {
	case <-dialed:
	case <-time.After(2 * time.Second):
		t.Fatal("login monitor never dialed")
	}
	cancel()
	waitLoginMonitor(t, done)
	if attempts.Load() != 1 {
		t.Fatalf("dial attempts = %d, want 1", attempts.Load())
	}
}

func TestLoginStreamCancellationClosesIdleWebSocket(t *testing.T) {
	closed := make(chan struct{})
	host, port := startFakeAgentServer(t, func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgradeFakeAgent(w, r)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, _ = conn.ReadMessage()
		close(closed)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := ws.NewClient()
	client.SetReconnectConfig(0, 0)
	if err := client.Connect(ctx, fmt.Sprintf("ws://%s:%d/api/ws/login", host, port)); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runActiveAgentLoginStream(ctx, 91, client, nil)
	}()
	cancel()
	waitLoginMonitor(t, done)
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation left login socket open")
	}
}

func TestLoginMonitorStopsForIdentityMismatch(t *testing.T) {
	mock := setupIdentityTest(t)
	expectIdentityAuditLookup(mock)
	identityPrivate := mustGenerateIdentity(t)
	host, port, handlerDone := startSingleHandshakeAgent(t, identityPrivate, false)
	expectedPrivate := mustGenerateIdentity(t)
	a := newTestHubAuth(t, host, port, expectedPrivate.Public().(ed25519.PublicKey))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a.monitorActiveAgentLogins(ctx, time.Millisecond)
	waitFakeAgent(t, handlerDone)
	if ctx.Err() != nil {
		t.Fatal("identity mismatch must stop retries")
	}
}

func TestLoginStreamProcessesPongsWhileLoginLookupBlocks(t *testing.T) {
	lookupStarted := make(chan struct{})
	lookupFinished := make(chan struct{})
	releaseLookup := make(chan struct{})
	var once, startedOnce, finishedOnce sync.Once
	release := func() { once.Do(func() { close(releaseLookup) }) }
	defer release()
	matcher := sqlmock.QueryMatcherFunc(func(expected, actual string) error {
		if expected != actual {
			return fmt.Errorf("unexpected query: %s", actual)
		}
		if strings.HasPrefix(actual, "SELECT team_id") {
			startedOnce.Do(func() { close(lookupStarted) })
			<-releaseLookup
			finishedOnce.Do(func() { close(lookupFinished) })
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
	mock.ExpectQuery("SELECT team_id FROM servers WHERE id = $1").WithArgs(int64(91)).
		WillReturnError(errors.New("test lookup failure"))

	curve := ecdh.X25519()
	hubKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hubCrypto, err := secureWS.NewSessionCryptoV2(secureWS.RoleHub, agentKey.PublicKey(), hubKey, []byte("login test"))
	if err != nil {
		t.Fatal(err)
	}
	agentCrypto, err := secureWS.NewSessionCryptoV2(secureWS.RoleAgent, hubKey.PublicKey(), agentKey, []byte("login test"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := agentTypes.MarshalMsg(agentTypes.LoginEvent{User: "root", IP: "203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := agentCrypto.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	handlerDone := make(chan error, 1)
	host, port := startFakeAgentServer(t, func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgradeFakeAgent(w, r)
		if err == nil {
			defer conn.Close()
			err = conn.WriteMessage(websocket.BinaryMessage, frame)
			if err == nil {
				// ReadMessage services pings until the hub sends the closing probe.
				_, _, err = conn.ReadMessage()
			}
		}
		handlerDone <- err
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := ws.NewClient()
	client.SetReconnectConfig(0, 0)
	if err := client.Connect(ctx, fmt.Sprintf("ws://%s:%d/api/ws/login", host, port)); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	const pongWait = 250 * time.Millisecond
	if err := client.SetPongDeadline(pongWait); err != nil {
		t.Fatal(err)
	}
	readErr := make(chan error, 1)
	go func() { readErr <- runActiveAgentLoginStream(ctx, 91, client, hubCrypto) }()
	select {
	case <-lookupStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("login lookup never started")
	}
	ticker := time.NewTicker(pongWait / 5)
	defer ticker.Stop()
	timer := time.NewTimer(3 * pongWait)
	defer timer.Stop()
holdLookup:
	for {
		select {
		case err := <-readErr:
			t.Fatalf("login stream ended during a slow lookup: %v", err)
		case <-ticker.C:
			if err := client.SendMessage(websocket.PingMessage, nil); err != nil {
				t.Fatal(err)
			}
		case <-timer.C:
			break holdLookup
		}
	}
	release()
	<-lookupFinished
	if err := client.SendMessage(websocket.BinaryMessage, []byte("finish")); err != nil {
		t.Fatal(err)
	}
	waitFakeAgent(t, handlerDone)
	select {
	case err := <-readErr:
		if err == nil || strings.Contains(err.Error(), "i/o timeout") {
			t.Fatalf("stream should observe the peer closing after healthy pongs, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("login reader did not observe the peer closing")
	}
}

func waitLoginMonitor(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("login monitor did not stop")
	}
}

func TestLoginMonitorStopsForPolicyClose(t *testing.T) {
	identityPrivate := mustGenerateIdentity(t)
	var attempts atomic.Int32
	handshakeDone := make(chan error, 1)
	host, port := startFakeAgentServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		conn, err := upgradeFakeAgent(w, r)
		if err != nil {
			handshakeDone <- err
			return
		}
		// A NoMonitor agent completes authentication and then declines the
		// login stream with a policy close.
		_, err = serveFakeAgentHandshakeAfter(conn, r, identityPrivate, nil, true, nil, func() error {
			return conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "login monitoring disabled"))
		})
		handshakeDone <- err
	})
	a := newTestHubAuth(t, host, port, identityPrivate.Public().(ed25519.PublicKey))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a.monitorActiveAgentLogins(ctx, time.Millisecond)
	waitFakeAgent(t, handshakeDone)
	if ctx.Err() != nil {
		t.Fatal("policy close must stop retries")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("dial attempts = %d, want 1", got)
	}
}
