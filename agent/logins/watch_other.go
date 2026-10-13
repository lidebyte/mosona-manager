//go:build !linux

package logins

import (
	"context"
	"log"
	"sync"

	agentTypes "mosona-manager/agent/types"
)

const Supported = false

var unsupportedLogOnce sync.Once

// Run is a no-op outside Linux: wtmp is Linux-specific, so agents on other
// platforms have no local login source to monitor.
func Run(_ context.Context, _ func(agentTypes.LoginEvent)) {
	unsupportedLogOnce.Do(func() {
		log.Println("SSH login monitoring is only supported on Linux agents; disabled")
	})
}
