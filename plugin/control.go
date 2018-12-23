package plugin

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"

	"github.com/kr/pty"
)

type Process struct {
	Pid     int
	buffer  *outputBuffer
	command *exec.Cmd
	Script  []string
	Env     []string

	pty *os.File

	// Running is stored as an int32 so we can use atomic operations to
	// set/get it (it's accessed by multiple goroutines)
	running int32

	mu   sync.Mutex
	done chan struct{}
}

func (p *Process) IsRunning() bool {
	return atomic.LoadInt32(&p.running) != 0
}

func (p *Process) setRunning(r bool) {
	// Use the atomic package to avoid race conditions when setting the
	// `running` value from multiple routines
	if r {
		atomic.StoreInt32(&p.running, 1)
	} else {
		atomic.StoreInt32(&p.running, 0)
	}
}

// Start executes the command and blocks until it finishes
func (p *Process) Start() error {
	if p.IsRunning() {
		return fmt.Errorf("Process is already running")
	}

	p.command = exec.Command(p.Script[0], p.Script[1:]...)

	// Create a channel that we use for signaling when the process is
	// done for Done()
	p.mu.Lock()
	if p.done == nil {
		p.done = make(chan struct{})
	}
	p.mu.Unlock()

	currentEnv := os.Environ()
	p.command.Env = append(currentEnv, p.Env...)

	f, err := pty.Start(p.command)
	if err != nil {
		return err
	}
	p.pty = f

	go func() {
		io.Copy(p.buffer, p.pty)
	}()

	return nil
}

// Output returns the current state of the output buffer and can be called incrementally
func (p *Process) Output() string {
	return p.buffer.String()
}

// outputBuffer is a goroutine safe bytes.Buffer
type outputBuffer struct {
	sync.RWMutex
	buf bytes.Buffer
}

func (ob *outputBuffer) Write(p []byte) (n int, err error) {
	ob.Lock()
	defer ob.Unlock()
	return ob.buf.Write(p)
}

func (ob *outputBuffer) WriteString(s string) (n int, err error) {
	return ob.Write([]byte(s))
}

func (ob *outputBuffer) String() string {
	ob.RLock()
	defer ob.RUnlock()
	return ob.buf.String()
}
