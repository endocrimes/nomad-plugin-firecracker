package plugin

import (
	"context"
	"sync"
	"time"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/drivers/shared/executor"
	"github.com/hashicorp/nomad/plugins/drivers"
)

type taskHandle struct {
	client *firecracker.Client
	logger hclog.Logger
	exec   executor.Executor
	pid    int

	// stateLock syncs access to all fields below
	stateLock sync.RWMutex

	taskConfig  *drivers.TaskConfig
	procState   drivers.TaskState
	startedAt   time.Time
	completedAt time.Time
	exitResult  *drivers.ExitResult
	waitCh      chan struct{}
}

func (h *taskHandle) TaskStatus() *drivers.TaskStatus {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()

	return &drivers.TaskStatus{
		ID:               h.taskConfig.ID,
		Name:             h.taskConfig.Name,
		State:            h.procState,
		StartedAt:        h.startedAt,
		CompletedAt:      h.completedAt,
		ExitResult:       h.exitResult,
		DriverAttributes: map[string]string{},
	}
}

func (h *taskHandle) IsRunning() bool {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()
	return h.procState == drivers.TaskStateRunning
}

func (h *taskHandle) run() {
	h.stateLock.Lock()
	if h.exitResult == nil {
		h.exitResult = &drivers.ExitResult{}
	}
	h.stateLock.Unlock()

	defer close(h.waitCh)

	ctx := context.Background()
	info := models.InstanceActionInfo{
		ActionType: models.InstanceActionInfoActionTypeInstanceStart,
	}
	if resp, err := h.client.CreateSyncAction(ctx, &info); err != nil {
		h.stateLock.Lock()
		defer h.stateLock.Unlock()

		h.logger.Error("Failed to start machine", "error", err, "resp_err", resp.Error())
		h.procState = drivers.TaskStateExited
		h.completedAt = time.Now()

		return
	}

	_, err := h.exec.Wait(ctx)

	h.logger.Warn("Firecracker exited", "error", err)

	h.stateLock.Lock()
	defer h.stateLock.Unlock()

	h.procState = drivers.TaskStateExited
	h.completedAt = time.Now()
}

type taskStore struct {
	store map[string]*taskHandle
	lock  sync.RWMutex
}

func newTaskStore() *taskStore {
	return &taskStore{store: map[string]*taskHandle{}}
}

func (ts *taskStore) Set(id string, handle *taskHandle) {
	ts.lock.Lock()
	defer ts.lock.Unlock()
	ts.store[id] = handle
}

func (ts *taskStore) Get(id string) (*taskHandle, bool) {
	ts.lock.RLock()
	defer ts.lock.RUnlock()
	t, ok := ts.store[id]
	return t, ok
}

func (ts *taskStore) Delete(id string) {
	ts.lock.Lock()
	defer ts.lock.Unlock()
	delete(ts.store, id)
}
