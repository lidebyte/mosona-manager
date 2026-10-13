package pbTypes

type Msg struct {
	Code string `msgpack:"code"`
	Data []byte `msgpack:"data"`
}

// MsgCodeTerminal requests the agent to open a terminal session.
const MsgCodeTerminal = "terminal"

// MsgCodeSSHLogin carries an agentTypes.LoginEvent from the agent to the hub.
const MsgCodeSSHLogin = "ssh_login"
