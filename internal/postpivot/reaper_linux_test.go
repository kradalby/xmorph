//go:build linux

package postpivot

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReapOrphansWithoutChildLists(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root + CAP_SYS_ADMIN for the isolated procfs fixture")
	}
	mode := os.Getenv("XMORPH_TEST_CHILD_LISTS")
	if mode == "" {
		for _, mode := range []string{"missing", "omitted"} {
			t.Run(mode, func(t *testing.T) {
				exe, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, exe, "-test.run=^TestReapOrphansWithoutChildLists$", "-test.v")
				cmd.Env = append(os.Environ(), "XMORPH_TEST_CHILD_LISTS="+mode)
				cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("isolated reaper test: %v\n%s", err, out)
				}
			})
		}
		return
	}

	runtime.LockOSThread()
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		dir := filepath.Join(fixture, task.Name())
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if mode == "omitted" {
			// Concurrent removal can yield an empty child list despite waitable siblings.
			if err := os.WriteFile(filepath.Join(dir, "children"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := unix.Mount(fixture, "/proc/self/task", "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount("/proc/self/task", unix.MNT_DETACH) })

	orphan := exitingChild(t)
	defer syscall.Wait4(orphan, nil, 0, nil)
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, orphan, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	reapOrphans()
	if _, err := syscall.Wait4(orphan, nil, syscall.WNOHANG, nil); err != syscall.ECHILD {
		t.Fatalf("waitable unowned child survived %s child lists: %v", mode, err)
	}
}
