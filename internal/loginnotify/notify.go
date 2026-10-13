// Package loginnotify turns SSH login session observations — probed over SSH
// or reported by an agent — into security logs and team notifications,
// gated on the server having an ssh_login alert rule configured.
package loginnotify

import (
	"context"
	"fmt"
	"log"
	agentTypes "mosona-manager/agent/types"
	"mosona-manager/internal/db"
	"mosona-manager/internal/influx"
	"mosona-manager/internal/servernotify"
	"mosona-manager/internal/utils"
)

// MaxEventsPerReport caps how many login events are notified from a single
// report burst.
const MaxEventsPerReport = agentTypes.MaxLoginEventsPerReport

// Event is a single observed SSH login session.
type Event struct {
	User string
	TTY  string
	IP   string
	// Time is the login's Unix timestamp on the monitored host, carried by
	// agent reports. Notifications omit it; audit logs use hub receipt time.
	Time int64
}

// Report delivers notifications for login events, gated on the server having
// an ssh_login alert rule configured.
func Report(ctx context.Context, serverId, teamID int64, events []Event) {
	if len(events) == 0 || ctx.Err() != nil || !queryLoginAlertOn(ctx, serverId) {
		return
	}
	reportEnabledEvents(ctx, serverId, teamID, events)
}

func reportEnabledEvents(ctx context.Context, serverId, teamID int64, events []Event) {
	if len(events) > MaxEventsPerReport {
		log.Printf("server %d reported %d new SSH logins at once, notifying only the first %d", serverId, len(events), MaxEventsPerReport)
		events = events[:MaxEventsPerReport]
	}
	for _, event := range events {
		if ctx.Err() != nil {
			return
		}
		country := "Unknown"
		if geo, err := getIPGeoLocation(event.IP); err == nil && geo.Country != "" {
			country = geo.Country
		}
		addSecurityLog(teamID, 0, "security",
			fmt.Sprintf("SSH login: user '%s' from %s (%s)", event.User, event.IP, country),
			event.IP, "ssh login monitor", "medium")
		message := fmt.Sprintf("User '%s' logged in via SSH from %s (%s)", event.User, event.IP, country)
		delivery := notifyServerEvent(ctx, teamID, serverId, "SSH Login", message)
		if delivery.Attempted && !delivery.Delivered {
			log.Printf("failed to deliver SSH login notification for server %d", serverId)
		}
	}
}

// Wiring points kept as variables so tests can stub external dependencies.
var (
	getIPGeoLocation  = utils.GetIPGeoLocation
	addSecurityLog    = influx.LogAdd
	notifyServerEvent = servernotify.NotifyServerEvent
	queryLoginAlertOn = SSHLoginAlertEnabled
)

// SSHLoginAlertEnabled reports whether the server has an ssh_login alert
// rule configured (per-server opt-in, also via team alert fan-out).
func SSHLoginAlertEnabled(ctx context.Context, serverId int64) bool {
	var enabled bool
	if err := db.Db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM server_alerts WHERE server_id = $1 AND item = $2)`,
		serverId, db.AlertItemSSHLogin,
	).Scan(&enabled); err != nil {
		log.Println("failed to check ssh_login alert rule for server", serverId, ":", err)
		return false
	}
	return enabled
}
