//go:build desktop && (windows || linux)

package desktop

import (
	"context"
	"testing"
)

func TestOwnedBackendStopsOnceAndAttachedBackendRemainsIndependent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	h := &host{cancel: cancel, backend: Backend{Stop: func() error { calls++; return nil }}}
	h.stop()
	h.stop()
	if calls != 1 || ctx.Err() == nil || !h.quitting.Load() {
		t.Fatal("desktop lifecycle did not stop owned backend exactly once")
	}
	_, attachedCancel := context.WithCancel(context.Background())
	attached := &host{cancel: attachedCancel, backend: Backend{}}
	attached.stop()
	attached.stop()
}
