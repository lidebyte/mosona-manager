package loginnotify

import (
	"context"
	"log"
	agentTypes "mosona-manager/agent/types"
	"mosona-manager/internal/db"
	pbTypes "mosona-manager/pkg/types"
	"sync"
	"time"
)

// AgentReporter keeps notification work out of websocket readers. Each
// connection has one worker, a bounded queue and a five-event scan window.
type AgentReporter struct {
	ctx      context.Context
	serverID int64
	events   chan Event
	done     chan struct{}
	mu       sync.Mutex
	window   time.Time
	accepted int
	dropped  bool
}

func NewAgentReporter(ctx context.Context, serverID int64) *AgentReporter {
	return newAgentReporter(ctx, serverID, cachedAgentReport(time.Now))
}

func newAgentReporter(ctx context.Context, serverID int64, report func(context.Context, int64, []Event)) *AgentReporter {
	r := &AgentReporter{
		ctx: ctx, serverID: serverID,
		events: make(chan Event, MaxEventsPerReport), done: make(chan struct{}),
	}
	go func() {
		defer close(r.done)
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-r.events:
				if ctx.Err() != nil {
					return
				}
				report(ctx, serverID, drainEvents(r.events, event))
			}
		}
	}()
	return r
}

// drainEvents returns first plus every event already queued behind it. These
// queued events share a batch. Events arriving later can form separate batches;
// cachedAgentReport bounds their database lookups independently of scheduling.
func drainEvents(events chan Event, first Event) []Event {
	batch := []Event{first}
	for {
		select {
		case event := <-events:
			batch = append(batch, event)
		default:
			return batch
		}
	}
}

func (r *AgentReporter) SubmitMsg(frame pbTypes.Msg) {
	event, err := agentTypes.UnmarshalMsg(frame)
	if err != nil {
		log.Printf("Failed to unmarshal SSH login event from agent server %d: %v", r.serverID, err)
		return
	}
	r.submitAt(Event{User: event.User, TTY: event.TTY, IP: event.IP, Time: event.Time}, time.Now())
}

func (r *AgentReporter) submitAt(event Event, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		return false
	}
	if r.window.IsZero() || now.Sub(r.window) >= agentTypes.LoginReportInterval {
		r.window = now
		r.accepted = 0
		r.dropped = false
	}
	if r.accepted >= MaxEventsPerReport {
		r.logDrop()
		return false
	}
	select {
	case r.events <- event:
		r.accepted++
		return true
	default:
		r.logDrop()
		return false
	}
}

func (r *AgentReporter) logDrop() {
	if !r.dropped {
		log.Printf("SSH login report limit or queue capacity reached for server %d; dropping excess events", r.serverID)
		r.dropped = true
	}
}

func reportAgentEvents(ctx context.Context, serverID int64, events []Event) {
	cachedAgentReport(time.Now)(ctx, serverID, events)
}

// cachedAgentReport belongs to one connection's serial worker. Cache both
// lookups (including failures) for one scan interval so separately arriving
// frames cannot cause one pair of queries per event. Rule/team changes become
// visible on the first report after expiry.
func cachedAgentReport(now func() time.Time) func(context.Context, int64, []Event) {
	var expires time.Time
	var teamID int64
	var enabled bool
	return func(ctx context.Context, serverID int64, events []Event) {
		if len(events) == 0 {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if current := now(); !current.Before(expires) {
			expires = current.Add(agentTypes.LoginReportInterval)
			enabled = false
			var err error
			teamID, err = db.GetServerTeamId(ctx, serverID)
			if err != nil {
				log.Printf("Failed to look up team for SSH login event, server %d: %v", serverID, err)
				return
			}
			enabled = queryLoginAlertOn(ctx, serverID)
		}
		if enabled {
			reportEnabledEvents(ctx, serverID, teamID, events)
		}
	}
}
