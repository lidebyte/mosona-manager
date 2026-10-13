package active

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	agentTypes "mosona-manager/agent/types"
	"mosona-manager/internal/_type"
	"mosona-manager/internal/influx"
	"mosona-manager/internal/loginnotify"
	"mosona-manager/pkg/identity"
	secureWS "mosona-manager/pkg/securews"
	pbTypes "mosona-manager/pkg/types"
	"mosona-manager/pkg/ws"
	"mosona-manager/pkg/wsutil"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/vmihailenco/msgpack/v5"
)

type auth struct {
	serverID        int64
	agentUID        string
	host            string
	port            int
	privKey         *ed25519.PrivateKey
	agentPubKey     ed25519.PublicKey
	protocolVersion int16
	pongWait        time.Duration
}

type stateMessageReader interface {
	ReadMessage() (messageType int, data []byte, err error)
}

func agentDisksToServerDisks(agentDisks []agentTypes.DiskInfo) []_type.DiskInfo {
	if len(agentDisks) == 0 {
		return nil
	}
	disks := make([]_type.DiskInfo, len(agentDisks))
	for i, d := range agentDisks {
		disks[i] = _type.DiskInfo{
			MountPoint: d.MountPoint,
			TotalGB:    d.TotalGB,
			UsedGB:     d.UsedGB,
		}
	}
	return disks
}

func Connect(
	ctx context.Context,
	host string, port int,
	privKey string, agentUid string,
	publicKey string, protocolVersion int16, serverId int64, allowMonitor bool,
) error {
	privateKey, err := identity.ParseEd25519PrivateKeyPEM([]byte(privKey))
	if err != nil {
		return err
	}

	a := &auth{
		serverID:        serverId,
		agentUID:        agentUid,
		host:            host,
		port:            port,
		privKey:         &privateKey,
		protocolVersion: protocolVersion,
	}
	if publicKey != "" {
		a.agentPubKey, err = identity.ParseEd25519PublicKeyPEM([]byte(publicKey))
		if err != nil {
			return err
		}
	}

	useLegacy := false
	if len(a.agentPubKey) == 0 {
		pairClient, _, pairErr := a.connectAgent(ctx, "/api/ws/pair", true)
		if pairErr != nil {
			if errors.Is(pairErr, ErrAgentIdentityMismatch) {
				return pairErr
			}
			if a.protocolVersion != 1 {
				return pairErr
			}
			useLegacy = true
		} else {
			_ = pairClient.Close()
			if err = markActiveAgentPaired(serverId); err != nil {
				return err
			}
		}
	}
	if !allowMonitor {
		if useLegacy {
			legacyClient, _, legacyErr := a.connectAgentLegacy(ctx, "/api/ws/state")
			if legacyErr != nil {
				return legacyErr
			}
			_ = legacyClient.Close()
			if err = markActiveAgentPaired(serverId); err != nil {
				return err
			}
			return ErrLegacyAgentRequiresUpgrade
		}
		return nil
	}
	if err = a.getInformation(ctx); err != nil {
		return err
	}

	var client *ws.Client
	var sc *secureWS.SessionCrypto
	if useLegacy {
		client, sc, err = a.connectAgentLegacy(ctx, "/api/ws/state")
	} else {
		client, sc, err = a.connectAgent(ctx, "/api/ws/state", false)
	}
	if err != nil {
		return err
	}

	// Read loop
	readDone := make(chan struct{})
	readErr := make(chan error, 1)
	go func() {
		defer close(readDone)
		readErr <- readActiveAgentStatuses(ctx, client, sc, serverId)
	}()
	defer func() {
		_ = client.Close()
		<-readDone
	}()

	// The login stream reconnects independently, but belongs to this state
	// connection's lifetime. Every retry performs a fresh authenticated handshake.
	if !useLegacy {
		loginCtx, cancelLogins := context.WithCancel(ctx)
		defer cancelLogins()
		go a.monitorActiveAgentLogins(loginCtx, loginRetryInitialBackoff)
	}

	var ping <-chan time.Time
	var pingTicker *time.Ticker
	if !useLegacy {
		pingTicker = time.NewTicker(wsutil.DefaultPingInterval)
		ping = pingTicker.C
		defer pingTicker.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err = <-readErr:
			return err
		case <-ping:
			if err := client.SendMessage(websocket.PingMessage, nil); err != nil {
				return err
			}
		}
	}
}

const (
	loginRetryInitialBackoff = 5 * time.Second
	loginRetryMaxBackoff     = 5 * time.Minute
)

func (a *auth) monitorActiveAgentLogins(ctx context.Context, initialRetry time.Duration) {
	backoff := initialRetry
	attempts := 0
	capLogged := false
	for ctx.Err() == nil {
		client, sc, err := a.connectAgent(ctx, "/api/ws/login", false)
		streamed := err == nil
		if streamed {
			// A NoMonitor agent declines the stream with a policy close;
			// surface it instead of transparently reconnecting.
			client.SetTerminalCloseCodes(websocket.ClosePolicyViolation)
			err = runActiveAgentLoginStream(ctx, a.serverID, client, sc)
		}
		if ctx.Err() != nil {
			return
		}
		if ws.IsHandshakeStatus(err, http.StatusNotFound, http.StatusMethodNotAllowed) ||
			errors.Is(err, ErrAgentIdentityMismatch) ||
			ws.IsCloseError(err, websocket.ClosePolicyViolation) {
			log.Printf("Active agent login stream unavailable for server %d: %v", a.serverID, err)
			return
		}
		if streamed {
			// The stream was established before breaking; restart the backoff.
			backoff = initialRetry
			capLogged = false
		}
		attempts++
		if backoff < time.Minute || attempts == 1 {
			log.Printf("Active agent login stream for server %d ended; retrying in %s: %v", a.serverID, backoff, err)
		} else if backoff/2 < time.Minute || backoff == loginRetryMaxBackoff && !capLogged {
			// Past the fast-retry regime: log only when the delay crosses a
			// threshold (and once when it reaches the cap) instead of every attempt.
			log.Printf("Active agent login stream for server %d still failing (attempt %d); retrying in %s: %v", a.serverID, attempts, backoff, err)
		}
		if backoff == loginRetryMaxBackoff {
			capLogged = true
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > loginRetryMaxBackoff {
			backoff = loginRetryMaxBackoff
		}
	}
}

// runActiveAgentLoginStream keeps the SSH login event websocket alive with
// pings until the connection context ends or the stream breaks; a broken
// login stream never tears down the state connection.
func runActiveAgentLoginStream(ctx context.Context, serverID int64, client *ws.Client, sc *secureWS.SessionCrypto) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	readDone := make(chan struct{})
	defer func() {
		_ = client.Close()
		<-readDone
	}()
	pingTicker := time.NewTicker(wsutil.DefaultPingInterval)
	defer pingTicker.Stop()

	readErr := make(chan error, 1)
	go func() {
		defer close(readDone)
		readErr <- readActiveAgentLogins(ctx, client, sc, serverID)
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return err
		case <-pingTicker.C:
			if err := client.SendMessage(websocket.PingMessage, nil); err != nil {
				return err
			}
		}
	}
}

// readActiveAgentLogins decrypts login event frames from the agent until the
// connection ends.
func readActiveAgentLogins(ctx context.Context, client stateMessageReader, sc *secureWS.SessionCrypto, serverID int64) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reporter := loginnotify.NewAgentReporter(ctx, serverID)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, originData, err := client.ReadMessage()
		if err != nil {
			return err
		}
		data, err := sc.Decrypt(originData)
		if err != nil {
			// Unlike a malformed frame (skipped below), a decrypt failure
			// means the session crypto is out of sync; only a fresh handshake
			// can recover, so tear the stream down and let the monitor reconnect.
			return fmt.Errorf("decrypt Active Agent login event: %w", err)
		}

		var frame pbTypes.Msg
		if err = msgpack.Unmarshal(data, &frame); err != nil || frame.Code != pbTypes.MsgCodeSSHLogin {
			continue
		}
		reporter.SubmitMsg(frame)
	}
}

func readActiveAgentStatuses(ctx context.Context, client stateMessageReader, sc *secureWS.SessionCrypto, serverID int64) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, originData, err := client.ReadMessage()
		if err != nil {
			return err
		}
		data, err := sc.Decrypt(originData)
		if err != nil {
			return fmt.Errorf("decrypt Active Agent status: %w", err)
		}

		var state agentTypes.Status
		if err = msgpack.Unmarshal(data, &state); err != nil {
			continue
		}

		if err = influx.AddServerStatusContext(ctx, serverID, _type.ServerStatusType{
			CPU:           state.CPU,
			MemTotalMB:    state.MemTotalMB,
			MemUsedMB:     state.MemUsedMB,
			SwapTotalMB:   state.SwapTotalMB,
			SwapUsedMB:    state.SwapUsedMB,
			Disks:         agentDisksToServerDisks(state.Disks),
			DiskReadKibS:  state.DiskReadKibS,
			DiskWriteKibS: state.DiskWriteKibS,
			DiskReadIOPS:  state.DiskReadIOPS,
			DiskWriteIOPS: state.DiskWriteIOPS,
			RxKibS:        state.RxKibS,
			TxKibS:        state.TxKibS,
			RxTotalMB:     state.RxTotalMB,
			TxTotalMB:     state.TxTotalMB,
			TCPTotal:      state.TCPTotal,
			UDPTotal:      state.UDPTotal,
			Time:          time.Now(),
		}); err != nil {
			log.Println("Failed to add server status:", err)
		}
	}
}
