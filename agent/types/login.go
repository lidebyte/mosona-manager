package types

import (
	pbTypes "mosona-manager/pkg/types"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	MaxLoginEventsPerReport = 5
	LoginReportInterval     = 5 * time.Second
)

// LoginEvent is a single SSH login session observed by the agent's local
// wtmp monitor, reported to the hub wrapped in pbTypes.Msg{Code: "ssh_login"}.
type LoginEvent struct {
	User string `msgpack:"user"`
	TTY  string `msgpack:"tty"`
	IP   string `msgpack:"ip"`
	Time int64  `msgpack:"time"` // login time, unix seconds on the monitored host
}

// MarshalMsg packs a login event into a pbTypes.Msg frame for delivery over
// the agent's websocket channel.
func MarshalMsg(ev LoginEvent) ([]byte, error) {
	data, err := msgpack.Marshal(ev)
	if err != nil {
		return nil, err
	}
	return msgpack.Marshal(pbTypes.Msg{Code: pbTypes.MsgCodeSSHLogin, Data: data})
}

// UnmarshalMsg extracts a login event from a pbTypes.Msg frame on the hub.
func UnmarshalMsg(msg pbTypes.Msg) (LoginEvent, error) {
	var ev LoginEvent
	err := msgpack.Unmarshal(msg.Data, &ev)
	return ev, err
}
