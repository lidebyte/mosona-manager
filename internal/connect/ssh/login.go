package ssh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"mosona-manager/internal/connect/ssh/script"
	"mosona-manager/internal/loginnotify"
)

const (
	loginProbeInterval = 30 * time.Second
	loginProbeMaxFail  = 5
	loginProbeTimeout  = 15 * time.Second
	// Re-request a small window on the server clock to cover records written
	// around the previous probe; session keys discard repeated entries.
	loginSinceOverlap = 5 * time.Minute
	loginLastLines    = 50
)

// loginSession is a single login entry reported by linux_logins.sh.
type loginSession struct {
	user string
	tty  string
	ip   string
	date string
}

func (s loginSession) key() string {
	return s.user + "|" + s.tty + "|" + s.ip + "|" + s.date
}

// isMonitorSelf reports whether the session matches Mosona's own monitoring
// connection (same user coming from the manager egress IP as seen by sshd).
// Mosona's exec sessions do not allocate a PTY and are not recorded in wtmp,
// so this is a defense-in-depth filter on top of that.
func (s loginSession) isMonitorSelf(monitorUser, selfIP string) bool {
	return selfIP != "" && s.ip == selfIP && s.user == monitorUser
}

// loginProbe is the parsed output of one linux_logins.sh run.
type loginProbe struct {
	selfIP      string
	serverEpoch int64
	unavailable bool
	sessions    []loginSession
}

func parseLoginProbe(output string) loginProbe {
	probe := loginProbe{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "self_ip="):
			probe.selfIP = strings.TrimSpace(strings.TrimPrefix(line, "self_ip="))
		case strings.HasPrefix(line, "server_epoch="):
			probe.serverEpoch, _ = strconv.ParseInt(strings.TrimPrefix(line, "server_epoch="), 10, 64)
		case line == "logins_unavailable=1":
			probe.unavailable = true
		case strings.HasPrefix(line, "login|"):
			parts := strings.SplitN(line, "|", 5)
			if len(parts) != 5 {
				continue
			}
			session := loginSession{
				user: parts[1],
				tty:  parts[2],
				ip:   parts[3],
				date: parts[4],
			}
			if session.user == "" || session.ip == "" {
				continue
			}
			if !strings.Contains(session.ip, ".") && !strings.Contains(session.ip, ":") {
				continue
			}
			probe.sessions = append(probe.sessions, session)
		}
	}
	return probe
}

// loginProber keeps the script in a shell process for this SSH connection.
// Only numeric poll arguments cross stdin after startup; no script cache is
// written to the server's filesystem. Calls to probe are sequential.
type loginProber struct {
	client     *gossh.Client
	session    *gossh.Session
	stdin      io.WriteCloser
	stdout     *bufio.Reader
	lastPollAt time.Time // server clock, never the manager clock
}

const loginProbeEnd = "mosona_login_probe_end="

func loginProbeCommand(scriptFile string) string {
	// Each invocation runs in a subshell so the probe's exit/traps and shell
	// options do not terminate or modify the persistent request loop.
	program := "login_probe() {\n" + scriptFile + "\n}\n" + `while read -r since lines; do
  [ "$since" = 0 ] && since=''
  ( login_probe "$since" "$lines" )
  result=$?
  printf 'mosona_login_probe_end=%s\n' "$result"
done`
	return "sh -c '" + strings.ReplaceAll(program, "'", "'\"'\"'") + "'"
}

func (p *loginProber) start() error {
	scriptFile, err := script.GetScript("linux_logins.sh")
	if err != nil {
		return err
	}
	session, err := p.client.NewSession()
	if err != nil {
		return err
	}
	p.session = session
	p.stdin, err = session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	p.stdout = bufio.NewReader(stdout)
	session.Stderr = io.Discard
	return session.Start(loginProbeCommand(scriptFile))
}

func (p *loginProber) close() {
	if p.session != nil {
		if p.stdin != nil {
			_ = p.stdin.Close()
		}
		_ = p.session.Close()
		p.session = nil
		p.stdin = nil
		p.stdout = nil
	}
}

// sinceEpoch returns the lower bound for the next incremental window, or 0
// for the baseline poll (full bounded window).
func (p *loginProber) sinceEpoch() int64 {
	if p.lastPollAt.IsZero() {
		return 0
	}
	return p.lastPollAt.Add(-loginSinceOverlap).Unix()
}

// The deadline covers starting the shell, sending arguments and reading a
// complete response. Closing a stuck connection unblocks SSH operations and
// lets the existing monitoring reconnect loop recover it.
func (p *loginProber) probe(ctx context.Context) (loginProbe, error) {
	ctx, cancel := context.WithTimeout(ctx, loginProbeTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return loginProbe{}, err
	}
	type result struct {
		probe loginProbe
		err   error
	}
	done := make(chan result, 1)
	go func() {
		probe, err := p.runProbe()
		done <- result{probe, err}
	}()
	var r result
	select {
	case <-ctx.Done():
		_ = p.client.Close()
		// Join before touching prober fields or starting another probe.
		r = <-done
		r.err = ctx.Err()
	case r = <-done:
		if ctx.Err() != nil {
			r.err = ctx.Err()
		}
	}
	if r.err != nil {
		p.close()
		return loginProbe{}, r.err
	}
	// If the target cannot report its clock, retain bounded full snapshots
	// instead of substituting a potentially skewed manager clock.
	p.lastPollAt = time.Time{}
	if r.probe.serverEpoch > 0 {
		p.lastPollAt = time.Unix(r.probe.serverEpoch, 0)
	}
	return r.probe, nil
}

func (p *loginProber) runProbe() (loginProbe, error) {
	if p.session == nil {
		if err := p.start(); err != nil {
			return loginProbe{}, err
		}
	}
	if _, err := fmt.Fprintf(p.stdin, "%d %d\n", p.sinceEpoch(), loginLastLines); err != nil {
		return loginProbe{}, err
	}
	var output strings.Builder
	for {
		line, err := p.stdout.ReadString('\n')
		if err != nil {
			return loginProbe{}, fmt.Errorf("read login probe: %w", err)
		}
		if strings.HasPrefix(line, loginProbeEnd) {
			status, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, loginProbeEnd)))
			if err != nil || status != 0 {
				return loginProbe{}, fmt.Errorf("login probe failed: %s", strings.TrimSpace(line))
			}
			return parseLoginProbe(output.String()), nil
		}
		output.WriteString(line)
	}
}

// diffLoginSessions returns sessions in current that were not present in the
// previous snapshot (excluding Mosona's own monitoring connection) plus the
// new snapshot. The snapshot is replaced (not merged) because `last` output
// only ever loses entries from its tail, which keeps the state bounded.
func diffLoginSessions(prev map[string]struct{}, current []loginSession, monitorUser, selfIP string) (fresh []loginSession, snapshot map[string]struct{}) {
	snapshot = make(map[string]struct{}, len(current))
	for _, session := range current {
		key := session.key()
		snapshot[key] = struct{}{}
		if prev != nil {
			if _, seen := prev[key]; !seen && !session.isMonitorSelf(monitorUser, selfIP) {
				fresh = append(fresh, session)
			}
		}
	}
	return fresh, snapshot
}

// loginMonitor polls the monitored server for new SSH login sessions until
// ctx is done, probes keep failing, or login detection is unavailable.
// The first poll only seeds the baseline, so logins that happened before
// monitoring started (or while the manager was down) are not reported.
func loginMonitor(ctx context.Context, client *gossh.Client, serverId, teamID int64, monitorUser string) {
	prober := &loginProber{client: client}
	defer prober.close()
	var snapshot map[string]struct{}
	seeded := false
	failures := 0
	for {
		probe, err := prober.probe(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			if failures == 1 {
				log.Printf("SSH login probe for server %d failed: %v", serverId, err)
			}
			if failures >= loginProbeMaxFail {
				log.Printf("SSH login monitor for server %d giving up after %d consecutive failed probes", serverId, failures)
				return
			}
		} else {
			failures = 0
			if probe.unavailable {
				log.Printf("SSH login detection unavailable for server %d (`last` missing or wtmp unreadable); login alerts disabled for this connection", serverId)
				return
			}

			fresh, current := diffLoginSessions(snapshot, probe.sessions, monitorUser, probe.selfIP)
			snapshot = current
			if seeded && len(fresh) > 0 {
				notifyFreshLogins(ctx, serverId, teamID, fresh)
			}
			seeded = true
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(loginProbeInterval):
		}
	}
}

// notifyFreshLogins delivers login notifications for newly seen sessions via
// the shared loginnotify reporter.
func notifyFreshLogins(ctx context.Context, serverId, teamID int64, fresh []loginSession) {
	events := make([]loginnotify.Event, 0, len(fresh))
	for _, session := range fresh {
		events = append(events, loginnotify.Event{
			User: session.user,
			TTY:  session.tty,
			IP:   session.ip,
		})
	}
	loginnotify.Report(ctx, serverId, teamID, events)
}
