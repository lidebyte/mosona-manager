package script

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runLoginsScript(t *testing.T, binDir string, args []string, env ...string) string {
	t.Helper()
	writeTestCommand(t, binDir, "date", "echo 1700000300")
	contents, err := GetScript("linux_logins.sh")
	if err != nil {
		t.Fatal(err)
	}
	argv := append([]string{"sh", "-c", contents, "linux-logins-test"}, args...)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(testCommandEnv(binDir), env...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("linux_logins.sh failed: %v\n%s", err, output)
	}
	return string(output)
}

func readCapturedArgs(t *testing.T, binDir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(binDir, "last.args"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(data))
}

func TestLinuxLoginsParsesLastOutput(t *testing.T) {
	binDir := t.TempDir()
	writeTestCommand(t, binDir, "last", `
if [ "${1:-}" = "-F" ]; then
  printf '%s\n' 'root     pts/0        203.0.113.7     Fri Oct  8 12:00:23 2026   still logged in'
  printf '%s\n' 'deploy   pts/1        2001:db8::1     Fri Oct  8 11:00:00 2026 - Fri Oct  8 11:30:00 2026  (00:30)'
  printf '%s\n' 'admin    tty1                          Fri Oct  8 09:00:00 2026   still logged in'
  printf '%s\n' 'reboot   system boot  6.1.0-amd64     Fri Oct  8 08:00:00 2026   still running'
  printf '%s\n' ''
  printf '%s\n' 'wtmp begins Fri Oct  1 00:00:00 2026'
  exit 0
fi
exit 1
`)

	output := runLoginsScript(t, binDir, nil, "SSH_CONNECTION=198.51.100.7 51234 10.0.0.1 22")

	want := strings.Join([]string{
		"self_ip=198.51.100.7",
		"login|root|pts/0|203.0.113.7|Fri Oct 8 12:00:23 2026",
		"login|deploy|pts/1|2001:db8::1|Fri Oct 8 11:00:00 2026",
		"server_epoch=1700000300",
		"",
	}, "\n")
	if output != want {
		t.Fatalf("linux_logins.sh output = %q, want %q", output, want)
	}
}

func TestLinuxLoginsPassesSinceEpochToLast(t *testing.T) {
	binDir := t.TempDir()
	writeTestCommand(t, binDir, "last", `
cd "$(dirname "$0")"
for arg in "$@"; do
  printf '%s ' "$arg" >> last.args
done
printf '\n' >> last.args
printf '%s\n' 'root     pts/0        203.0.113.7     Fri Oct  8 12:00:23 2026   still logged in'
exit 0
`)

	output := runLoginsScript(t, binDir, []string{"1700000000", "50"}, "SSH_CONNECTION=198.51.100.7 51234 10.0.0.1 22")

	args := readCapturedArgs(t, binDir)
	hasSince := false
	for i, arg := range args {
		if arg == "-s" && i+1 < len(args) && args[i+1] == "@1700000000" {
			hasSince = true
		}
	}
	if !hasSince {
		t.Fatalf("last args = %v, want -s @1700000000", args)
	}
	if !strings.Contains(output, "login|root|pts/0|203.0.113.7|Fri Oct 8 12:00:23 2026") {
		t.Fatalf("linux_logins.sh output missing login record: %q", output)
	}
}

func TestLinuxLoginsFallsBackWhenFullTimesUnsupported(t *testing.T) {
	binDir := t.TempDir()
	writeTestCommand(t, binDir, "last", `
for arg in "$@"; do
  if [ "$arg" = "-s" ] || [ "$arg" = "-F" ]; then
    exit 1
  fi
done
printf '%s\n' 'root     pts/2        192.0.2.9      Mon Jan  5 09:30   still logged in'
exit 0
`)

	output := runLoginsScript(t, binDir, []string{"1700000000", "50"}, "SSH_CONNECTION=198.51.100.7 51234 10.0.0.1 22")

	want := "self_ip=198.51.100.7\nlogin|root|pts/2|192.0.2.9|Mon Jan 5 09:30\nserver_epoch=1700000300\n"
	if output != want {
		t.Fatalf("linux_logins.sh output = %q, want %q (short-format date must not include session status)", output, want)
	}
}

func TestLinuxLoginsIdleSinceWindowIsEmpty(t *testing.T) {
	binDir := t.TempDir()
	writeTestCommand(t, binDir, "last", `
for arg in "$@"; do
  if [ "$arg" = "-s" ]; then
    exit 0
  fi
done
exit 1
`)

	output := runLoginsScript(t, binDir, []string{"1700000000", "50"}, "SSH_CONNECTION=198.51.100.7 51234 10.0.0.1 22")

	if output != "self_ip=198.51.100.7\nserver_epoch=1700000300\n" {
		t.Fatalf("linux_logins.sh output = %q, want only probe metadata", output)
	}
}

func TestLinuxLoginsReportsUnavailableWhenLastFails(t *testing.T) {
	binDir := t.TempDir()
	writeTestCommand(t, binDir, "last", "exit 1")

	output := runLoginsScript(t, binDir, nil, "SSH_CONNECTION=198.51.100.7 51234 10.0.0.1 22")

	want := "self_ip=198.51.100.7\nlogins_unavailable=1\n"
	if output != want {
		t.Fatalf("linux_logins.sh output = %q, want %q", output, want)
	}
}

func TestLinuxLoginsEmptySSHConnection(t *testing.T) {
	binDir := t.TempDir()
	writeTestCommand(t, binDir, "last", "exit 1")

	cmdEnv := testCommandEnv(binDir)
	for i, entry := range cmdEnv {
		if strings.HasPrefix(entry, "SSH_CONNECTION=") {
			cmdEnv[i] = "SSH_CONNECTION="
		}
	}
	contents, err := GetScript("linux_logins.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", contents, "linux-logins-test")
	cmd.Env = cmdEnv
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("linux_logins.sh failed: %v\n%s", err, output)
	}
	if !strings.HasPrefix(string(output), "self_ip=\n") {
		t.Fatalf("linux_logins.sh output should start with empty self_ip: %q", output)
	}
	if !strings.Contains(string(output), "logins_unavailable=1") {
		t.Fatalf("linux_logins.sh output missing logins_unavailable: %q", output)
	}
}

// dash is /bin/sh on Debian/Ubuntu and does not support bashisms such as
// (( ... )); run the idle-window scenario through it so a silently
// misbehaving fallback gate cannot leak full login history into an
// incremental poll again.
func TestLinuxLoginsIdleSinceWindowIsEmptyUnderDash(t *testing.T) {
	dashPath, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not available")
	}

	binDir := t.TempDir()
	writeTestCommand(t, binDir, "last", `
for arg in "$@"; do
  if [ "$arg" = "-s" ]; then
    exit 0
  fi
done
printf '%s\n' 'root     pts/2        192.0.2.9      Mon Jan  5 09:30   still logged in'
exit 0
`)

	contents, err := GetScript("linux_logins.sh")
	if err != nil {
		t.Fatal(err)
	}
	writeTestCommand(t, binDir, "date", "echo 1700000300")
	cmd := exec.Command(dashPath, "-c", contents, "linux-logins-test", "1700000000", "50")
	cmd.Env = append(testCommandEnv(binDir), "SSH_CONNECTION=198.51.100.7 51234 10.0.0.1 22")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("linux_logins.sh under dash failed: %v\n%s", err, output)
	}
	if string(output) != "self_ip=198.51.100.7\nserver_epoch=1700000300\n" {
		t.Fatalf("linux_logins.sh under dash output = %q, want only probe metadata", output)
	}
}

func TestLinuxLoginsSinceFallbackPreservesSessionKeys(t *testing.T) {
	binDir := t.TempDir()
	writeTestCommand(t, binDir, "last", `
full=0
for arg in "$@"; do
  case "$arg" in
    -s) exit 1 ;;
    -F) full=1 ;;
  esac
done
if [ "$full" -eq 1 ]; then
  printf '%s\n' 'root pts/2 192.0.2.9 Mon Jan 5 09:30:00 2026 still logged in'
else
  printf '%s\n' 'root pts/2 192.0.2.9 Mon Jan 5 09:30 still logged in'
fi
`)
	baseline := runLoginsScript(t, binDir, nil)
	incremental := runLoginsScript(t, binDir, []string{"1700000000", "50"})
	if incremental != baseline || !strings.Contains(incremental, "09:30:00 2026") {
		t.Fatalf("same login changed keys: baseline %q, incremental %q", baseline, incremental)
	}
}
