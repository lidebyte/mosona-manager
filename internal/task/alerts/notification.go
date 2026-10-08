package alerttasks

import (
	"context"
	"fmt"

	"mosona-manager/internal/servernotify"
)

type notificationDelivery struct {
	attempted bool
	delivered bool
}

func (a *alertInstance) notifyAll(serverId int64, item, message string) notificationDelivery {
	if len(a.notifications) == 0 {
		return notificationDelivery{}
	}

	serverName, ok := (*a.serverMap)[serverId]
	if !ok {
		serverName = fmt.Sprintf("Server %d", serverId)
	}

	delivery := servernotify.Deliver(context.Background(), serverId, serverName, a.notifications, item, message)
	return notificationDelivery{
		attempted: delivery.Attempted,
		delivered: delivery.Delivered,
	}
}
