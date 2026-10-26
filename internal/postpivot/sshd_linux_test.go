//go:build linux

package postpivot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// serveSSHTest starts serveSSH on a random loopback port and returns
// the client-facing address. t.Cleanup cancels + waits for shutdown.
func serveSSHTest(t *testing.T, cfg *SSHConfig) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serveSSH(ctx, []net.Listener{ln}, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Log("serveSSH did not exit in 2s")
		}
	})
	return ln.Addr().String()
}

// genClientKey returns an ed25519 client key + its authorized_keys
// serialization.
func genClientKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	return signer, authorized
}

func dialClient(t *testing.T, addr string, auth []ssh.AuthMethod) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "root",
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSSHPublicKeyExec(t *testing.T) {
	signer, authorized := genClientKey(t)
	addr := serveSSHTest(t, &SSHConfig{
		Port:           0,
		AuthorizedKeys: authorized,
	})

	c := dialClient(t, addr, []ssh.AuthMethod{ssh.PublicKeys(signer)})
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	out, err := sess.CombinedOutput("echo hello")
	if err != nil {
		t.Fatalf("run: %v (out=%q)", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "hello" {
		t.Errorf("output = %q, want %q", got, "hello")
	}
}

func TestSSHRejectsAuthorizedKeyOptions(t *testing.T) {
	signer, authorized := genClientKey(t)
	for _, options := range []string{`command="/bin/false"`, `from="192.0.2.1"`, "no-pty", "restrict", `command="/bin/false",no-pty`} {
		t.Run(options, func(t *testing.T) {
			cfg := &SSHConfig{AuthorizedKeys: options + " " + authorized}
			if _, err := buildServerConfig(cfg); err != nil {
				if !strings.Contains(err.Error(), "unsupported authorized_keys options") {
					t.Fatalf("unexpected configuration rejection: %v", err)
				}
				return
			}

			addr := serveSSHTest(t, cfg)
			c := dialClient(t, addr, []ssh.AuthMethod{ssh.PublicKeys(signer)})
			sess, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			out, err := sess.CombinedOutput("echo unrestricted-exec")
			t.Fatalf("unsupported restrictions were accepted: arbitrary exec returned %q, error %v", out, err)
		})
	}
}

func TestSSHCertificateAuthentication(t *testing.T) {
	key, _ := genClientKey(t)
	authority, _ := genClientKey(t)
	for _, tc := range []struct {
		name     string
		after    uint64
		before   uint64
		critical map[string]string
		pty      bool
		host     bool
		tampered bool
		password string
		wantErr  string
	}{
		{name: "permitted", before: ssh.CertTimeInfinity},
		{name: "permitted with PTY", before: ssh.CertTimeInfinity, pty: true},
		{name: "forced command", before: ssh.CertTimeInfinity, critical: map[string]string{"force-command": "/bin/false"}, wantErr: "unsupported SSH certificate critical options"},
		{name: "source address", before: ssh.CertTimeInfinity, critical: map[string]string{"source-address": "192.0.2.1/32"}, wantErr: "unsupported SSH certificate critical options"},
		{name: "restricted with password", before: ssh.CertTimeInfinity, critical: map[string]string{"source-address": "192.0.2.1/32"}, password: "valid-password", wantErr: "unsupported SSH certificate critical options"},
		{name: "expired", before: 1, wantErr: "expired"},
		{name: "future", after: ssh.CertTimeInfinity - 1, before: ssh.CertTimeInfinity, wantErr: "not yet valid"},
		{name: "host certificate", before: ssh.CertTimeInfinity, host: true, wantErr: "not a user certificate"},
		{name: "invalid signature", before: ssh.CertTimeInfinity, tampered: true, wantErr: "signature does not verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &ssh.Certificate{Key: key.PublicKey(), CertType: ssh.UserCert,
				ValidPrincipals: []string{"root"}, ValidAfter: tc.after, ValidBefore: tc.before,
				Permissions: ssh.Permissions{CriticalOptions: tc.critical}}
			if tc.pty {
				cert.Extensions = map[string]string{"permit-pty": ""}
			}
			if tc.host {
				cert.CertType = ssh.HostCert
			}
			if err := cert.SignCert(rand.Reader, authority); err != nil {
				t.Fatal(err)
			}
			if tc.tampered {
				cert.Serial++
			}
			cfg := &SSHConfig{AuthorizedKeys: string(ssh.MarshalAuthorizedKey(cert)), Password: tc.password}
			if _, err := buildServerConfig(cfg); err != nil {
				if tc.wantErr == "" || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("unexpected configuration rejection: %v", err)
				}
				return
			}
			signer, err := ssh.NewCertSigner(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			addr := serveSSHTest(t, cfg)
			c := dialClient(t, addr, []ssh.AuthMethod{ssh.PublicKeys(signer)})
			sess, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			if tc.wantErr != "" {
				out, err := sess.CombinedOutput("echo unrestricted-certificate-exec")
				t.Fatalf("invalid certificate was accepted: arbitrary exec returned %q, error %v", out, err)
			}
			if err := sess.RequestPty("xterm", 24, 80, nil); (err == nil) != tc.pty {
				t.Errorf("PTY request = %v, permit-pty = %v", err, tc.pty)
			}
			out, err := sess.CombinedOutput("echo permitted-certificate-exec")
			if err != nil || strings.TrimSpace(string(out)) != "permitted-certificate-exec" {
				t.Fatalf("permitted certificate exec: %q, %v", out, err)
			}
			other, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
				User: "other", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second,
			})
			if err == nil {
				other.Close()
				t.Error("certificate authorized a principal it does not contain")
			}
		})
	}
}

func TestSSHExitStatusPropagates(t *testing.T) {
	signer, authorized := genClientKey(t)
	addr := serveSSHTest(t, &SSHConfig{AuthorizedKeys: authorized})

	c := dialClient(t, addr, []ssh.AuthMethod{ssh.PublicKeys(signer)})
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	err = sess.Run("exit 42")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 42 {
		t.Errorf("exit status = %v, want ExitError(42)", err)
	}
}

type heldSSHOutput struct {
	ssh.Channel
	written chan struct{}
	release chan struct{}
	once    sync.Once
	status  exitMsg
}

func (ch *heldSSHOutput) Read([]byte) (int, error) { return 0, io.EOF }

func (ch *heldSSHOutput) Write(p []byte) (int, error) {
	ch.once.Do(func() { close(ch.written) })
	<-ch.release
	return len(p), nil
}

func (ch *heldSSHOutput) SendRequest(name string, _ bool, payload []byte) (bool, error) {
	if name != "exit-status" {
		return false, fmt.Errorf("unexpected request %q", name)
	}
	return true, ssh.Unmarshal(payload, &ch.status)
}

func TestSSHExitStatusSurvivesOrphanReaping(t *testing.T) {
	for _, code := range []int{0, 42} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("printf ready; exit %d", code))
			ch := &heldSSHOutput{written: make(chan struct{}), release: make(chan struct{}), status: exitMsg{Status: 255}}
			var release sync.Once
			defer release.Do(func() { close(ch.release) })
			reqs := make(chan *ssh.Request)
			close(reqs)
			done := make(chan struct{})
			go func() {
				runSession(ch, reqs, cmd, "xterm", nil, true, pty.Winsize{Rows: 24, Cols: 80})
				close(done)
			}()
			select {
			case <-ch.written:
			case <-ctx.Done():
				t.Fatal("SSH command did not produce output")
			}

			// Leave the real exit status waitable while PTY output holds cmd.Wait back.
			var info unix.Siginfo
			for {
				err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
				if err == unix.EINTR {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				break
			}
			reapOrphans()

			// A managed zombie must not prevent cleanup of an unowned child.
			orphan := exitingChild(t)
			if err := unix.Waitid(unix.P_PID, orphan, &info, unix.WEXITED|unix.WNOWAIT, nil); err != nil {
				t.Fatal(err)
			}
			reapOrphans()
			if _, err := syscall.Wait4(orphan, nil, syscall.WNOHANG, nil); err != syscall.ECHILD {
				t.Errorf("unowned child was not reaped: %v", err)
			}

			release.Do(func() { close(ch.release) })
			select {
			case <-done:
				if ch.status.Status != uint32(code) {
					t.Errorf("SSH exit status = %d, want %d; process state = %v", ch.status.Status, code, cmd.ProcessState)
				}
			case <-ctx.Done():
				t.Fatal("SSH session did not finish")
			}
		})
	}
}

func TestSSHExitStatusWithIdleSupervisor(t *testing.T) {
	guard := make(chan os.Signal, 4)
	signal.Notify(guard, syscall.SIGTERM)
	defer signal.Stop(guard)
	done := make(chan int, 1)
	go func() { done <- ServeUntilSignal() }()
	defer func() {
		deadline := time.After(5 * time.Second)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			select {
			case code := <-done:
				if code != 0 {
					t.Errorf("idle exit status = %d, want 0", code)
				}
				return
			case <-deadline:
				t.Error("idle supervisor did not stop")
				return
			case <-tick.C:
			}
		}
	}()

	orphan := exitingChild(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", orphan)); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle supervisor did not reap unowned child")
		}
		// SIGCHLD may have arrived before the idle loop registered its handler.
		_ = syscall.Kill(os.Getpid(), syscall.SIGCHLD)
		time.Sleep(time.Millisecond)
	}

	addr := serveSSHTest(t, &SSHConfig{Password: "idle-test-password"})
	c := dialClient(t, addr, []ssh.AuthMethod{ssh.Password("idle-test-password")})
	for _, terminal := range []bool{false, true} {
		for _, code := range []int{0, 42} {
			t.Run(fmt.Sprintf("pty=%t/exit=%d", terminal, code), func(t *testing.T) {
				sess, err := c.NewSession()
				if err != nil {
					t.Fatal(err)
				}
				defer sess.Close()
				if terminal {
					if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
						t.Fatal(err)
					}
				}
				result := make(chan error, 1)
				go func() { result <- sess.Run(fmt.Sprintf("exit %d", code)) }()
				select {
				case err := <-result:
					var ee *ssh.ExitError
					if code == 0 && err != nil || code != 0 && (!errors.As(err, &ee) || ee.ExitStatus() != code) {
						t.Errorf("SSH result = %v, want exit %d", err, code)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("SSH session did not finish")
				}
			})
		}
	}
}

func TestSSHPasswordAuth(t *testing.T) {
	addr := serveSSHTest(t, &SSHConfig{Password: "s3cret"})
	c := dialClient(t, addr, []ssh.AuthMethod{ssh.Password("s3cret")})
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if err := sess.Run("true"); err != nil {
		t.Errorf("run: %v", err)
	}
}

func TestSSHRejectsUnknownKey(t *testing.T) {
	_, authorized := genClientKey(t)  // authorized on server
	otherSigner, _ := genClientKey(t) // client uses a DIFFERENT key
	addr := serveSSHTest(t, &SSHConfig{AuthorizedKeys: authorized})

	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(otherSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected auth failure for unknown key")
	}
}

func TestSSHNoAuthConfiguredRefuses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	err = serveSSH(ctx, []net.Listener{ln}, &SSHConfig{}) // no keys, no password
	if err == nil || !strings.Contains(err.Error(), "no auth method") {
		t.Errorf("serveSSH err = %v, want 'no auth method'", err)
	}
}

func TestParseAuthorizedKeys(t *testing.T) {
	_, authorized := genClientKey(t)
	_, other := genClientKey(t)
	input := "# comment\n\n" + authorized + "\n" + other + "\n"

	keys, err := ParseAuthorizedKeys(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("got %d keys, want 2", len(keys))
	}
}

type fakeTailnet struct{}

func (fakeTailnet) Listen(network, addr string) (net.Listener, error) {
	return net.Listen(network, "127.0.0.1:0")
}

func TestStartSSHServerAddsTailnetListener(t *testing.T) {
	_, authorized := genClientKey(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- StartSSHServer(ctx, &SSHConfig{AuthorizedKeys: authorized}, fakeTailnet{}) }()
	// Give both listeners a moment to bind, then shut down.
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("StartSSHServer: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("StartSSHServer did not exit")
	}
}

func TestParseAuthorizedKeysBadLineReturnsError(t *testing.T) {
	_, err := ParseAuthorizedKeys("this-is-not-a-key")
	if err == nil {
		t.Fatal("expected error for bogus key")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("line 1")) {
		t.Errorf("err = %v, want to mention line number", err)
	}
}

// `ssh host cmd` must return when the command returns, even though the
// client's stdin is still open.
//
// This is the shape every other test in this file misses. x/crypto/ssh's
// Session sends channel EOF immediately when Stdin is nil, so sess.Run("true")
// passes even against a server that deadlocks — and a real client only sends
// EOF when its own stdin does, which for a command run from a terminal or a
// live pipe is never. The server used to set cmd.Stdin = ch, which makes
// os/exec's Wait() block until that copy finishes, i.e. until the client
// closes the channel, i.e. until after the thing it is blocking. Found by the
// VM test in nix/tests/lifecycle.nix, which logs in over a real ssh(1).
func TestSSHExecReturnsWithStdinStillOpen(t *testing.T) {
	addr := serveSSHTest(t, &SSHConfig{Password: "s3cret"})
	c := dialClient(t, addr, []ssh.AuthMethod{ssh.Password("s3cret")})
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	// A stdin that never reaches EOF, the way a terminal behaves. Nothing is
	// ever written to it; the point is only that it stays open.
	pr, pw := io.Pipe()
	defer pw.Close()
	sess.Stdin = pr

	var out bytes.Buffer
	sess.Stdout = &out

	done := make(chan error, 1)
	go func() { done <- sess.Run("echo logged-in") }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if got := strings.TrimSpace(out.String()); got != "logged-in" {
			t.Errorf("stdout = %q, want %q", got, "logged-in")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session never returned; the server is waiting on a stdin the client will not close")
	}
}
