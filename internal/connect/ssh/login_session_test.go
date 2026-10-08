package ssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"mosona-manager/internal/connect/ssh/script"
)

func loginTestClient(t *testing.T, handle func(gossh.NewChannel, <-chan struct{})) *gossh.Client {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := &gossh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(newTestSigner(t))
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		conn, channels, requests, err := gossh.NewServerConn(raw, config)
		if err != nil {
			return
		}
		defer conn.Close()
		go gossh.DiscardRequests(requests)
		closed := make(chan struct{})
		go func() { _ = conn.Wait(); close(closed) }()
		for channel := range channels {
			go handle(channel, closed)
		}
	}()
	client, err := gossh.Dial("tcp", listener.Addr().String(), &gossh.ClientConfig{
		User: "test", HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestLoginProbeReusesShellAndRemoteClock(t *testing.T) {
	for _, skew := range []time.Duration{-10 * time.Minute, 10 * time.Minute} {
		t.Run(skew.String(), func(t *testing.T) {
			epoch := time.Now().Add(skew).Unix()
			var starts atomic.Int32
			requests := make(chan string, 4)
			finished := make(chan struct{})
			client := loginTestClient(t, func(next gossh.NewChannel, _ <-chan struct{}) {
				ch, reqs, err := next.Accept()
				if err != nil {
					return
				}
				defer ch.Close()
				for req := range reqs {
					if req.Type != "exec" {
						_ = req.Reply(false, nil)
						continue
					}
					starts.Add(1)
					_ = req.Reply(true, nil)
					scanner := bufio.NewScanner(ch)
					for scanner.Scan() {
						requests <- scanner.Text()
						_, _ = fmt.Fprintf(ch, "server_epoch=%d\nlogin|root|pts/0|192.0.2.1|stable date\n%s0\n", epoch, loginProbeEnd)
					}
					close(finished)
					return
				}
			})
			prober := &loginProber{client: client}
			defer prober.close()
			var snapshot map[string]struct{}
			for i := 0; i < 3; i++ {
				probe, err := prober.probe(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				got := <-requests
				wantSince := int64(0)
				if i > 0 {
					wantSince = epoch - int64(loginSinceOverlap/time.Second)
				}
				if got != fmt.Sprintf("%d %d", wantSince, loginLastLines) {
					t.Fatalf("poll must transmit only server-clock arguments, got %q", got)
				}
				fresh, current := diffLoginSessions(snapshot, probe.sessions, "monitor", "")
				snapshot = current
				if len(fresh) != 0 {
					t.Fatalf("unchanged logins reported again: %v", fresh)
				}
			}
			if starts.Load() != 1 {
				t.Fatalf("uploaded script %d times", starts.Load())
			}
			prober.close()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("closing prober did not terminate remote input loop")
			}
		})
	}
}

func TestLoginProbeShellExecutesMultipleRequests(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"date": "echo 1700000300",
		"last": `printf '%s\n' "$*" >> "$LOGIN_TEST_ARGS"
printf '%s\n' 'root pts/0 192.0.2.1 Mon Jan 5 09:30:00 2026 still logged in'`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	contents, err := script.GetScript("linux_logins.sh")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", loginProbeCommand(contents))
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "LOGIN_TEST_ARGS="+filepath.Join(dir, "args"))
	cmd.Stdin = strings.NewReader("0 50\n1700000000 50\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("persistent shell: %v: %s", err, output)
	}
	if strings.Count(string(output), loginProbeEnd+"0\n") != 2 || strings.Count(string(output), "server_epoch=1700000300") != 2 {
		t.Fatalf("probe exit/traps broke subsequent requests: %s", output)
	}
	args, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	if string(args) != "-F -n 50 -i\n-F -n 50 -i -s @1700000000\n" {
		t.Fatalf("unexpected probe arguments: %s", args)
	}
}

func TestLoginProbeDeadlineUnblocksEveryStage(t *testing.T) {
	for _, stage := range []string{"open", "exec", "response"} {
		t.Run(stage, func(t *testing.T) {
			reached := make(chan struct{})
			client := loginTestClient(t, func(next gossh.NewChannel, closed <-chan struct{}) {
				if stage == "open" {
					close(reached)
					<-closed
					return
				}
				ch, reqs, err := next.Accept()
				if err != nil {
					return
				}
				defer ch.Close()
				for req := range reqs {
					if stage == "exec" {
						close(reached)
						<-closed
						return
					}
					_ = req.Reply(true, nil)
					_, _ = bufio.NewReader(ch).ReadString('\n')
					close(reached)
					<-closed
					return
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			prober := &loginProber{client: client}
			defer prober.close()
			_, err := prober.probe(ctx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error = %v, want deadline exceeded", err)
			}
			select {
			case <-reached:
			default:
				t.Fatalf("probe timed out before reaching %s", stage)
			}
			if _, err := client.NewSession(); err == nil {
				t.Fatal("stalled connection was not closed for reconnect")
			}
		})
	}
}
