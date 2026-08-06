package dialer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type lifecycleStartTestDialer struct {
	starts   atomic.Int32
	closes   atomic.Int32
	done     <-chan struct{}
	startErr error
}

func (d *lifecycleStartTestDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, context.Canceled
}

func (d *lifecycleStartTestDialer) Start(ctx context.Context) error {
	d.starts.Add(1)
	d.done = ctx.Done()
	return d.startErr
}

func TestNewDialerContextTreatsLifecycleStartFailureAsBestEffort(t *testing.T) {
	t.Parallel()
	logger := logrus.New()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	underlying := &lifecycleStartTestDialer{startErr: errors.New("warm failed")}
	dialer := NewDialerContext(
		context.Background(),
		underlying,
		&GlobalOption{Log: logger, CheckInterval: 30 * time.Second},
		InstanceOption{},
		&Property{Property: D.Property{Name: "best-effort"}},
	)
	require.Equal(t, int32(1), underlying.starts.Load())
	require.Contains(t, logs.String(), "Failed to start outbound dialer lifecycle")
	require.NoError(t, dialer.Close())
}

func (d *lifecycleStartTestDialer) Close() error {
	d.closes.Add(1)
	return nil
}

func TestNewDialerContextStartsAndClosesUnderlyingLifecycle(t *testing.T) {
	t.Parallel()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	parentCtx, cancel := context.WithCancel(context.Background())
	underlying := &lifecycleStartTestDialer{}
	dialer := NewDialerContext(
		parentCtx,
		underlying,
		&GlobalOption{Log: logger, CheckInterval: 30 * time.Second},
		InstanceOption{},
		&Property{Property: D.Property{Name: "lifecycle"}},
	)
	require.Equal(t, int32(1), underlying.starts.Load())
	cancel()
	select {
	case <-underlying.done:
	case <-time.After(time.Second):
		t.Fatal("underlying lifecycle did not receive parent cancellation")
	}
	require.NoError(t, dialer.Close())
	require.Equal(t, int32(1), underlying.closes.Load())
}
