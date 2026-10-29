//go:build darwin || linux || freebsd || openbsd || netbsd

package durablefile

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCrossProcessLockHonorsCancellationAndRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	unlock, err := Lock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestLockProcessHelper$")
	command.Env = append(os.Environ(), "FIREMON_DURABLE_LOCK="+path)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	release, err := Lock(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}
func TestLockProcessHelper(t *testing.T) {
	path := os.Getenv("FIREMON_DURABLE_LOCK")
	if path == "" {
		t.Skip("helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	release, err := Lock(ctx, path)
	if err == nil {
		release()
		t.Fatal("acquired another process lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
