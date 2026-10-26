package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"go.calculon.tech/xmorph/internal/config"
	"go.calculon.tech/xmorph/internal/passphrase"
	"go.calculon.tech/xmorph/internal/postpivot"
	"golang.org/x/crypto/ssh"
)

// The last line of defence before anything destructive happens. A bare shell
// detached from a terminal exits the instant it reads stdin, so pivoting into
// one gives an operator a reboot loop instead of the machine they asked for.
// Catching that here costs nothing: the old root is still mounted and the
// pivot has not started.
//
// go test runs with stdin on /dev/null, which is exactly the detached case
// these tests are about. The converse — a real terminal, where a shell is a
// perfectly sensible entrypoint — cannot be exercised without allocating a
// pty, and is left to the --contain path below.
func TestCheckEntrypointSurvivesDetach(t *testing.T) {
	for _, tc := range []struct {
		name       string
		entrypoint string
		contain    bool
		wantErr    bool
	}{
		{name: "sh", entrypoint: "/bin/sh", wantErr: true},
		{name: "bash", entrypoint: "/bin/bash", wantErr: true},
		{name: "busybox", entrypoint: "/bin/busybox", wantErr: true},
		{name: "absolute path is not what matters", entrypoint: "/usr/local/bin/ash", wantErr: true},
		{name: "a real program is fine", entrypoint: "/usr/local/bin/xmorph"},
		{name: "so is an init", entrypoint: "/sbin/init"},
		// --contain keeps the caller's terminal and never leaves the machine
		// without userspace, so a shell there is the normal case.
		{name: "contain permits a shell", entrypoint: "/bin/sh", contain: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkEntrypointSurvivesDetach(
				&config.Config{Contain: tc.contain}, tc.entrypoint)
			if tc.wantErr != (err != nil) {
				t.Fatalf("checkEntrypointSurvivesDetach(%q, contain=%v) = %v, wantErr %v",
					tc.entrypoint, tc.contain, err, tc.wantErr)
			}
		})
	}
}

// An error that only says no is a support ticket. This one has to name the way
// forward, because the person reading it is usually mid-rescue on a machine
// they cannot walk over to.
func TestEntrypointRefusalNamesTheFix(t *testing.T) {
	err := checkEntrypointSurvivesDetach(&config.Config{}, "/bin/sh")
	if err == nil {
		t.Fatal("want a refusal for a detached shell")
	}
	for _, want := range []string{"--cmd idle", "--command"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
}

// --ssh.enable with no credentials produced a machine that pivoted, stayed up,
// and could not be logged into: sshd logged "no auth method configured" to a
// console nobody was reading and never bound the port. The VM test found it.
// Now the missing credential is invented rather than demanded.
func TestEnsureSSHUsable(t *testing.T) {
	enabled := true
	disabled := false
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert,
		ValidBefore: ssh.CertTimeInfinity,
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"force-command": "/bin/false"}}}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		cfg           config.Config
		wantGenerated bool
		wantPassword  string // "" means "whatever was generated"
		wantErr       string
	}{
		{name: "ssh off", cfg: config.Config{}},
		{name: "ssh explicitly off", cfg: config.Config{SSHEnable: &disabled}},
		{
			name:          "enabled with nothing to authenticate with",
			cfg:           config.Config{SSHEnable: &enabled},
			wantGenerated: true,
		},
		{
			name:         "operator password is left alone",
			cfg:          config.Config{SSHEnable: &enabled, SSHPassword: "hunter2"},
			wantPassword: "hunter2",
		},
		{
			// Keys are enough on their own; generating a password here would
			// weaken a setup that deliberately has no password to guess.
			name: "authorized keys, no password invented",
			cfg:  config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: authorized},
		},
		{
			name:          "comment-only keys generate a usable password",
			cfg:           config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: "# no keys\n"},
			wantGenerated: true,
		},
		{
			name:          "whitespace-only keys generate a usable password",
			cfg:           config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: " \t\n"},
			wantGenerated: true,
		},
		{
			name:         "comment-only keys with a password",
			cfg:          config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: "# no keys\n", SSHPassword: "hunter2"},
			wantPassword: "hunter2",
		},
		{
			name:         "valid keys and password",
			cfg:          config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: authorized, SSHPassword: "hunter2"},
			wantPassword: "hunter2",
		},
		{
			name:    "malformed keys",
			cfg:     config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: "not-a-key"},
			wantErr: "line 1",
		},
		{
			name:    "malformed keys also reject a valid password",
			cfg:     config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: "not-a-key", SSHPassword: "hunter2"},
			wantErr: "line 1",
		},
		{
			name:    "valid key does not hide malformed key",
			cfg:     config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: authorized + "not-a-key"},
			wantErr: "line 2",
		},
		{
			name:    "restricted valid key",
			cfg:     config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: `command="/bin/false" ` + authorized},
			wantErr: "unsupported authorized_keys options",
		},
		{
			name:    "restricted certificate",
			cfg:     config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: string(ssh.MarshalAuthorizedKey(cert))},
			wantErr: "unsupported SSH certificate critical options",
		},
		{
			name:    "restricted certificate with password",
			cfg:     config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: string(ssh.MarshalAuthorizedKey(cert)), SSHPassword: "valid-password"},
			wantErr: "unsupported SSH certificate critical options",
		},
		{
			name:    "plain key and password do not hide restricted key",
			cfg:     config.Config{SSHEnable: &enabled, SSHAuthorizedKeys: authorized + "no-pty " + authorized, SSHPassword: "hunter2"},
			wantErr: "unsupported authorized_keys options",
		},
		// SSHEnabled() is implied by any other ssh.* flag, so this is on too.
		{
			name:         "implied by password alone",
			cfg:          config.Config{SSHPassword: "hunter2"},
			wantPassword: "hunter2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ensureSSHUsable(&tc.cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ensureSSHUsable() error = %v, want %q", err, tc.wantErr)
				}
				if got != "" || tc.cfg.SSHPasswordGenerated {
					t.Fatal("invalid credentials must not generate a fallback password")
				}
				return
			}
			if err != nil {
				t.Fatalf("ensureSSHUsable() error: %v", err)
			}
			if tc.wantGenerated != (got != "") {
				t.Fatalf("ensureSSHUsable() = %q, wantGenerated %v", got, tc.wantGenerated)
			}
			if tc.cfg.SSHPasswordGenerated != tc.wantGenerated {
				t.Errorf("SSHPasswordGenerated = %v, want %v",
					tc.cfg.SSHPasswordGenerated, tc.wantGenerated)
			}
			if !tc.wantGenerated {
				if tc.cfg.SSHPassword != tc.wantPassword {
					t.Errorf("SSHPassword = %q, want %q", tc.cfg.SSHPassword, tc.wantPassword)
				}
				return
			}
			// The generated password has to reach the post-pivot config,
			// which reads it from cfg and not from the return value.
			if tc.cfg.SSHPassword != got {
				t.Errorf("cfg.SSHPassword = %q, generated %q", tc.cfg.SSHPassword, got)
			}
			if n := strings.Count(got, "-") + 1; n != passphrase.DefaultWords {
				t.Errorf("generated %q, want %d hyphenated words", got, passphrase.DefaultWords)
			}
		})
	}
}

func TestSSHPasswordFile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		missing bool
		extra   []string
		want    string
		wantErr string
	}{
		{name: "password with shell characters and trailing newline", content: " secret '$HOME `false`\n", want: " secret '$HOME `false`"},
		{name: "embedded newline preserved", content: "first\nsecond\n\n", want: "first\nsecond"},
		{name: "explicitly disabled ignores missing file", missing: true, extra: []string{"--ssh.enable=false"}},
		{name: "empty", wantErr: "SSH password file is empty"},
		{name: "only newlines", content: "\n\n", wantErr: "SSH password file is empty"},
		{name: "missing", missing: true, wantErr: "read SSH password file"},
		{name: "conflicting inline password", content: "file-password", extra: []string{"--ssh.password=inline"}, wantErr: "cannot combine"},
		{name: "malformed keys still rejected", content: "file-password", extra: []string{"--ssh.authorized-keys=not-a-key"}, wantErr: "invalid SSH authorized_keys"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ssh password")
			if !tc.missing {
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := config.New()
			flags := pflag.NewFlagSet("pivot", pflag.ContinueOnError)
			config.BindPivot(flags, &cfg)
			if err := flags.Parse(append([]string{"--ssh.password-file=" + path}, tc.extra...)); err != nil {
				t.Fatal(err)
			}
			cfg.Normalize(flags, nil, nil)
			generated, err := ensureSSHUsable(&cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			pc := buildPostpivotConfig(&cfg, "/bin/true", nil)
			if !cfg.SSHEnabled() {
				if generated != "" || pc.SSH != nil {
					t.Fatal("disabled SSH acquired credentials")
				}
				return
			}
			if generated != "" || pc.SSH == nil || pc.SSH.PasswordGenerated || pc.SSH.Password != tc.want {
				t.Fatalf("file credential not preserved as an operator password: %+v", pc.SSH)
			}
			root := t.TempDir()
			if err := postpivot.WriteConfig(root, pc); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(filepath.Join(root, postpivot.ConfigPath))
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("private handoff mode: %v, %v", info, err)
			}
		})
	}
}

// The whole point of generating a password is that someone can read it. A
// banner that prints everything except the password would pass every test
// above.
func TestAnnounceSSHPasswordShowsThePassword(t *testing.T) {
	var buf bytes.Buffer
	postpivot.AnnounceSSHPassword(&buf, "swan-pesky-tofu", 2222)
	out := buf.String()
	if !strings.Contains(out, "swan-pesky-tofu") {
		t.Errorf("banner omits the password: %s", out)
	}
	if !strings.Contains(out, "2222") {
		t.Errorf("banner omits the port an operator has to connect to: %s", out)
	}
}

// An operator-supplied password must never be echoed to a console or into the
// persistent log; only one we generated is ours to print.
func TestOperatorPasswordIsNotMarkedGenerated(t *testing.T) {
	enabled := true
	cfg := config.Config{SSHEnable: &enabled, SSHPassword: "reused-elsewhere"}
	if _, err := ensureSSHUsable(&cfg); err != nil {
		t.Fatalf("ensureSSHUsable() error: %v", err)
	}
	pc := buildPostpivotConfig(&cfg, "/bin/true", nil)
	if pc.SSH == nil {
		t.Fatal("post-pivot config has no SSH section")
	}
	if pc.SSH.PasswordGenerated {
		t.Error("an operator-supplied password is flagged as generated; it would be printed")
	}
	if pc.SSH.Password != "reused-elsewhere" {
		t.Errorf("SSH password = %q, want the one the operator gave", pc.SSH.Password)
	}
}

// ...and the generated one must be flagged, or the post-pivot console never
// shows it and the machine is unreachable again for a different reason.
func TestGeneratedPasswordReachesPostPivotConfig(t *testing.T) {
	enabled := true
	cfg := config.Config{SSHEnable: &enabled}
	got, err := ensureSSHUsable(&cfg)
	if err != nil {
		t.Fatalf("ensureSSHUsable() error: %v", err)
	}
	pc := buildPostpivotConfig(&cfg, "/bin/true", nil)
	if pc.SSH == nil {
		t.Fatal("post-pivot config has no SSH section")
	}
	if !pc.SSH.PasswordGenerated {
		t.Error("generated password is not flagged; it would never be printed post-pivot")
	}
	if pc.SSH.Password != got {
		t.Errorf("SSH password = %q, generated %q", pc.SSH.Password, got)
	}
	if pc.SSH.Port != 22 {
		t.Errorf("SSH port = %d, want the default 22", pc.SSH.Port)
	}
}

func TestTailscaleControlURLReachesPostPivotConfig(t *testing.T) {
	cfg := config.Config{
		TailscaleAuthkey: "tskey-auth-test",
		TailscaleServer:  "http://headscale",
	}
	pc := buildPostpivotConfig(&cfg, "/bin/true", nil)
	data, err := json.Marshal(pc.Tailscale)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), cfg.TailscaleServer) {
		t.Fatalf("post-pivot config lost control URL: %s", data)
	}
}

func TestTailscaleHostnameReachesPostPivotConfig(t *testing.T) {
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args string
		want string
	}{
		{name: "default", want: host + "-xmorph"},
		{name: "custom", args: "--hostname=rescue", want: "rescue"},
		{name: "legacy args without hostname", args: "--ssh", want: host + "-xmorph"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{TailscaleAuthkey: "tskey-auth-test", TailscaleArgs: tc.args}
			pc := buildPostpivotConfig(&cfg, "/bin/true", nil)
			data, err := json.Marshal(pc.Tailscale)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Hostname string `json:"hostname"`
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if got.Hostname != tc.want {
				t.Fatalf("post-pivot config hostname = %q, want %q", got.Hostname, tc.want)
			}
		})
	}
}
