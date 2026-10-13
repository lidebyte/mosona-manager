package active

import (
	"context"
	"log"
	"mosona-manager/agent/config"
	"mosona-manager/agent/logins"
	agentTypes "mosona-manager/agent/types"
	secureWS "mosona-manager/pkg/securews"

	"github.com/gorilla/websocket"
)

// handleLoginWebSocket streams local SSH login events to the hub over an
// encrypted websocket. Events are only collected while the hub is connected;
// they are not backfilled after a disconnect (same semantics as the SSH-mode
// login monitor).
func handleLoginWebSocket(
	conn *websocket.Conn,
	sc *secureWS.SessionCrypto,
) {
	defer func() {
		_ = conn.Close()
	}()
	writer := newWebSocketWriter(conn)

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	if config.Current.NoMonitor || !logins.Supported {
		// Decline the stream: the hub treats the policy close as terminal
		// instead of holding an idle connection that will never carry events.
		// The deferred Close unblocks the read pump below.
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "login monitoring disabled"))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-readDone
		cancel()
	}()

	logins.Run(ctx, func(ev agentTypes.LoginEvent) {
		data, err := agentTypes.MarshalMsg(ev)
		if err != nil {
			log.Println("Failed to marshal SSH login event:", err)
			return
		}
		frame, err := sc.Encrypt(data)
		if err != nil {
			log.Println("Failed to encrypt SSH login event:", err)
			return
		}
		if err := writer.writeMessage(websocket.BinaryMessage, frame); err != nil {
			_ = conn.Close()
		}
	})
	<-readDone
}
