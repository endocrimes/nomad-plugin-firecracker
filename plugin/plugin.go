package plugin

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/drivers/shared/executor"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	pstructs "github.com/hashicorp/nomad/plugins/shared/structs"
	"github.com/sirupsen/logrus"
)

const (
	// pluginName is the name of the plugin
	pluginName = "firecracker"

	// fingerprintPeriod is the interval at which the driver will send fingerprint responses
	fingerprintPeriod = 30 * time.Second

	// executableMask is the mask needed to check whether or not a file's
	// permissions are executable.
	executableMask = 0111

	// taskHandleVersion is the version of task handle which this driver sets
	// and understands how to decode driver state
	taskHandleVersion = 1
)

var (
	// pluginInfo is the response returned for the PluginInfo RPC
	pluginInfo = &base.PluginInfoResponse{
		Type:              base.PluginTypeDriver,
		PluginApiVersions: []string{"0.1.0"},
		PluginVersion:     "0.0.1",
		Name:              pluginName,
	}

	// configSpec is the hcl specification returned by the ConfigSchema RPC
	configSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"firecracker_path": hclspec.NewAttr("firecracker_path", "string", true),

		// Jailer support is currently unimplemented.
		"use_jailer":  hclspec.NewAttr("use_jailer", "bool", false),
		"jailer_path": hclspec.NewAttr("jailer_path", "string", false),
	})

	// taskConfigSpec is the hcl specification for the driver config section of
	// a task within a job. It is returned in the TaskConfigSchema RPC
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"kernel_path": hclspec.NewAttr("kernel_path", "string", true),
		"image_path":  hclspec.NewAttr("image_path", "string", true),

		"kernel_boot_args": hclspec.NewAttr("kernel_boot_args", "string", false),
	})

	// capabilities is returned by the Capabilities RPC and indicates what
	// optional features this driver supports
	capabilities = &drivers.Capabilities{
		SendSignals: false,
		Exec:        false,
		FSIsolation: drivers.FSIsolationImage,
	}
)

type DriverConfig struct {
	FirecrackerPath string `codec:"firecracker_path"`
	UseJailer       bool   `codec:"use_jailer"`
	JailerPath      string `codec:"jailer_path"`
}

type TaskConfig struct {
	KernelPath     string `codec:"kernel_path"`
	ImagePath      string `codec:"image_path"`
	KernelBootArgs string `codec:"kernel_boot_args"`
}

const (
	defaultBootArgs = "ro console=ttyS0 noapic reboot=k panic=1 pci=off nomodules"
)

type Driver struct {
	// logger will log to the plugin output which is usually an 'executor.out'
	// file located in the root of the TaskDir
	logger hclog.Logger

	config *DriverConfig

	// tasks is the in memory datastore mapping taskIDs to driverHandles
	tasks *taskStore

	// nomadConfig is the client config from nomad
	nomadConfig *base.ClientDriverConfig
}

var _ drivers.DriverPlugin = &Driver{}

func NewDriver(logger hclog.Logger) *Driver {
	logger = logger.Named(pluginName)
	return &Driver{
		logger: logger,
		tasks:  newTaskStore(),
	}
}

func (*Driver) PluginInfo() (*base.PluginInfoResponse, error) {
	return pluginInfo, nil
}

func (*Driver) ConfigSchema() (*hclspec.Spec, error) {
	return configSpec, nil
}

func (d *Driver) SetConfig(cfg *base.Config) error {
	var config DriverConfig
	if len(cfg.PluginConfig) != 0 {
		if err := base.MsgPackDecode(cfg.PluginConfig, &config); err != nil {
			return err
		}
	}

	if cfg.AgentConfig != nil {
		d.nomadConfig = cfg.AgentConfig.Driver
	}

	d.config = &config

	return nil
}

func (d *Driver) Shutdown(ctx context.Context) error {
	return nil
}

func (d *Driver) TaskConfigSchema() (*hclspec.Spec, error) {
	return taskConfigSpec, nil
}

func (d *Driver) Capabilities() (*drivers.Capabilities, error) {
	return capabilities, nil
}

func (d *Driver) Fingerprint(ctx context.Context) (<-chan *drivers.Fingerprint, error) {
	ch := make(chan *drivers.Fingerprint, 1)
	ch <- d.buildFingerprint()
	go d.handleFingerprint(ctx, ch)
	return ch, nil
}

func (d *Driver) handleFingerprint(ctx context.Context, ch chan<- *drivers.Fingerprint) {
	defer close(ch)
	ticker := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ch <- d.buildFingerprint()
			ticker.Reset(fingerprintPeriod)
		}
	}
}

func (d *Driver) fingerprintBinary(path string) *drivers.Fingerprint {
	finfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		return &drivers.Fingerprint{
			Health:            drivers.HealthStateUndetected,
			HealthDescription: fmt.Sprintf("Binary, %q, does not exist: %v", path, err),
		}
	}

	if err != nil {
		return &drivers.Fingerprint{
			Health:            drivers.HealthStateUnhealthy,
			HealthDescription: fmt.Sprintf("Failed to stat binary, %q: %v", path, err),
		}
	}

	if finfo.IsDir() {
		return &drivers.Fingerprint{
			Health:            drivers.HealthStateUndetected,
			HealthDescription: fmt.Sprintf("Binary, %q is a directory", path),
		}
	} else if finfo.Mode()&executableMask == 0 {
		return &drivers.Fingerprint{
			Health:            drivers.HealthStateUnhealthy,
			HealthDescription: fmt.Sprintf("Binary, %q, is not executable. Check permissions of binary", path),
		}
	}

	return nil
}

func (d *Driver) buildFingerprint() *drivers.Fingerprint {
	if d.config == nil {
		return &drivers.Fingerprint{
			Health:            drivers.HealthStateUnhealthy,
			HealthDescription: "Waiting for config",
		}
	}

	if f := d.fingerprintBinary(d.config.FirecrackerPath); f != nil {
		return f
	}

	if d.config.UseJailer == true {
		if f := d.fingerprintBinary(d.config.JailerPath); f != nil {
			return f
		}
	}

	health := drivers.HealthStateHealthy
	desc := "ready"
	attrs := map[string]*pstructs.Attribute{"driver.firecracker": pstructs.NewStringAttribute("1")}

	return &drivers.Fingerprint{
		Attributes:        attrs,
		Health:            health,
		HealthDescription: desc,
	}
}

func (d *Driver) RecoverTask(handle *drivers.TaskHandle) error {
	return nil
}

func (d *Driver) StartTask(cfg *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	if _, ok := d.tasks.Get(cfg.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", cfg.ID)
	}

	ctx := context.Background()
	handle := drivers.NewTaskHandle(taskHandleVersion)

	var config TaskConfig
	if err := cfg.DecodeDriverConfig(&config); err != nil {
		return nil, nil, err
	}

	if config.KernelBootArgs == "" {
		config.KernelBootArgs = defaultBootArgs
	}

	cpuCount := int64(math.Max(1, float64(cfg.Resources.NomadResources.Cpu.CpuShares)/1024.0))
	memSize := cfg.Resources.NomadResources.Memory.MemoryMB

	controlSocketPath := filepath.Join(cfg.TaskDir().Dir, fmt.Sprintf("%s-control.sock", cfg.Name))

	// TODO: Support jailer
	cmd := firecracker.VMCommandBuilder{}.
		WithBin(d.config.FirecrackerPath).
		WithSocketPath(controlSocketPath).
		WithStdin(nil).
		WithStdout(os.Stdout).
		WithStderr(os.Stderr).
		Build(ctx)

	pluginLogFile := filepath.Join(cfg.TaskDir().Dir, fmt.Sprintf("%s-executor.out", cfg.Name))
	executorConfig := &executor.ExecutorConfig{
		LogFile:  pluginLogFile,
		LogLevel: "debug",
	}

	execImpl, pluginClient, err := executor.CreateExecutor(
		d.logger.With("task_name", cfg.Name, "alloc_id", cfg.AllocID),
		d.nomadConfig, executorConfig)
	if err != nil {
		return nil, nil, err
	}

	execCmd := &executor.ExecCommand{
		Cmd:        cmd.Path,
		Args:       cmd.Args[1:],
		Env:        append(cfg.EnvList(), cmd.Env...),
		User:       cfg.User,
		TaskDir:    cfg.TaskDir().Dir,
		StdoutPath: cfg.StdoutPath,
		StderrPath: cfg.StderrPath,
		Mounts:     []*drivers.MountConfig{},
	}

	ps, err := execImpl.Launch(execCmd)
	if err != nil {
		pluginClient.Kill()
		return nil, nil, err
	}

	rootDrive := models.Drive{
		DriveID:      firecracker.String("1"),
		PathOnHost:   firecracker.String(config.ImagePath),
		IsRootDevice: firecracker.Bool(true),
		IsReadOnly:   firecracker.Bool(false),
	}

	bsrc := models.BootSource{
		KernelImagePath: &config.KernelPath,
		BootArgs:        config.KernelBootArgs,
	}

	machineCfg := models.MachineConfiguration{
		VcpuCount: cpuCount,
		// TODO: Figure this out
		CPUTemplate: models.CPUTemplate("C3"),
		// TODO:Make this configurable
		HtEnabled:  false,
		MemSizeMib: memSize,
	}

	// TODO: FIXME: Timeout after some reasonable amount of time and log non 404s.
	for {
		if _, err := os.Stat(controlSocketPath); os.IsNotExist(err) {
			continue
		}

		break
	}

	client := firecracker.NewClient(controlSocketPath, logrus.WithField("alloc_id", cfg.AllocID), false)

	if resp, err := client.PutGuestBootSource(ctx, &bsrc); err != nil {
		d.logger.Error("Failed to configure boot source", "resp_error", resp.Error(), "err", err)
		return nil, nil, err
	}

	if resp, err := client.PutMachineConfiguration(ctx, &machineCfg); err != nil {
		d.logger.Error("Failed to configure machine", "resp_error", resp.Error(), "err", err)
		return nil, nil, err
	}

	if resp, err := client.PutGuestDriveByID(ctx, *rootDrive.DriveID, &rootDrive); err != nil {
		d.logger.Error("Failed to configure root drive", "resp_error", resp.Error(), "err", err)
		return nil, nil, err
	}

	h := &taskHandle{
		taskConfig: cfg,
		client:     client,
		pid:        ps.Pid,
		procState:  drivers.TaskStateRunning,
		exec:       execImpl,
		startedAt:  time.Now().Round(time.Millisecond),
		logger:     d.logger,
		waitCh:     make(chan struct{}),
	}

	d.tasks.Set(cfg.ID, h)

	go h.run()

	return handle, nil, nil
}

func (d *Driver) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	ch := make(chan *drivers.ExitResult)
	go func(ch chan *drivers.ExitResult, task *taskHandle) {
		<-task.waitCh
		ch <- task.exitResult
	}(ch, h)

	return ch, nil
}

func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return fmt.Errorf("task with ID %q not found", taskID)
	}

	return h.exec.Shutdown("SIGKILL", 5*time.Second)
}

func (d *Driver) DestroyTask(taskID string, force bool) error {
	d.tasks.Delete(taskID)

	// TODO: Destroy any ephemeral storage and ensure firecracker proc is dead.
	return nil
}

func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	return h.TaskStatus(), nil
}

func (d *Driver) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	return h.exec.Stats(ctx, interval)
}

func (d *Driver) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	return make(chan *drivers.TaskEvent), nil
}

func (d *Driver) SignalTask(taskID string, signal string) error {
	return nil
}

func (d *Driver) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	return nil, nil
}
