package servernotify

import (
	"context"
	"fmt"
	"log"
	"strings"

	"mosona-manager/internal/_type"
	"mosona-manager/internal/config"
	"mosona-manager/internal/db"
	"mosona-manager/internal/email"
	"mosona-manager/internal/notification"
)

// Delivery reports whether notification delivery was attempted and whether at
// least one channel succeeded.
type Delivery struct {
	Attempted bool
	Delivered bool
}

// SendEmail and SendShoutrrr are exposed as variables so tests can stub the
// delivery transports.
var (
	SendEmail    = email.Send
	SendShoutrrr = notification.Send
)

// Deliver sends one event to the given notification channels. serverName and
// notifications are usually preloaded by the caller (e.g. the periodic alert
// evaluation) to avoid per-event queries. Cancellation stops further delivery
// and cancels Shoutrrr requests; an in-flight email send cannot be interrupted.
func Deliver(ctx context.Context, serverId int64, serverName string, notifications []*_type.TeamNotification, item, message string) Delivery {
	var delivery Delivery
	if len(notifications) == 0 || ctx.Err() != nil {
		return delivery
	}

	uri := fmt.Sprintf("%s/%d/monitor", config.ReadDynamicConf().Domain, serverId)
	emailContent, err := email.GetNotificationTemplate(serverName, item, message, uri)
	if err != nil {
		log.Println("failed to get email template:", err)
	}

	for _, n := range notifications {
		if ctx.Err() != nil {
			break
		}
		switch n.Module {
		case "email":
			delivery.Attempted = true
			if emailContent != "" {
				if err := SendEmail(n.Target, fmt.Sprintf("%s: %s - Alert Notification", serverName, item), emailContent); err != nil {
					log.Println("failed to send alert email:", err)
				} else {
					delivery.Delivered = true
				}
			}
		case "shoutrrr":
			delivery.Attempted = true
			target := n.Target
			if strings.Contains(target, "telegram://") && !strings.Contains(target, "parsemode=") {
				if strings.Contains(target, "?") {
					target += "&parsemode=HTML"
				} else {
					target += "?parsemode=HTML"
				}
			}
			if err := SendShoutrrr(ctx, target, fmt.Sprintf("<b>%s – %s</b>\n%s\n\n%s", serverName, item, message, uri)); err != nil {
				log.Println("failed to send alert shoutrrr notification:", err)
			} else {
				delivery.Delivered = true
			}
		}
	}

	return delivery
}

// NotifyServerEvent loads the server display name and the team's notification
// channels, then delivers the event. It is the push-style entry point used
// outside the periodic alert evaluation (e.g. SSH login alerts).
func NotifyServerEvent(ctx context.Context, teamId, serverId int64, item, message string) Delivery {
	serverName, err := serverDisplayName(ctx, serverId, teamId)
	if err != nil {
		log.Printf("failed to load server name for notification (server %d): %v", serverId, err)
		serverName = fmt.Sprintf("Server %d", serverId)
	}

	notifications, err := teamNotifications(ctx, teamId)
	if err != nil {
		log.Printf("failed to load notification targets for team %d: %v", teamId, err)
		notifications = nil
	}

	return Deliver(ctx, serverId, serverName, notifications, item, message)
}

func serverDisplayName(ctx context.Context, serverId, teamId int64) (string, error) {
	var name string
	err := db.Db.QueryRowContext(ctx,
		"SELECT name FROM servers WHERE id = $1 AND team_id = $2",
		serverId, teamId,
	).Scan(&name)
	return name, err
}

func teamNotifications(ctx context.Context, teamId int64) ([]*_type.TeamNotification, error) {
	entries, err := db.GetNotificationsByTeamId(ctx, teamId)
	if err != nil {
		return nil, err
	}

	notifications := make([]*_type.TeamNotification, 0, len(entries))
	for i := range entries {
		notifications = append(notifications, &entries[i])
	}
	return notifications, nil
}
