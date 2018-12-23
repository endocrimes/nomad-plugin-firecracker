package plugin

import (
	"context"
	"fmt"
	"os"
	"time"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	"github.com/google/uuid"
	hclog "github.com/hashicorp/go-hclog"
	cstructs "github.com/hashicorp/nomad/client/structs"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	"github.com/hashicorp/nomad/plugins/shared/loader"
	pstructs "github.com/hashicorp/nomad/plugins/shared/structs"
)

const (
	// pluginName is the name of the plugin
	pluginName = "firecracker"

	// fingerprintPeriod is the interval at which the driver will send fingerprint responses
	fingerprintPeriod = 30 * time.Second

	// executableMask is the mask needed to check whether or not a file's
	// permissions are executable.
	executableMask = 0111
)

var (
	// PluginID is the exec plugin metadata registered in the plugin
	// catalog.
	PluginID = loader.PluginID{
		Name:       pluginName,
		PluginType: base.PluginTypeDriver,
	}

	// PluginConfig is the exec driver factory function registered in the
	// plugin catalog.
	PluginConfig = &loader.InternalPluginConfig{
		Config:  map[string]interface{}{},
		Factory: func(l hclog.Logger) interface{} { return NewDriver(l) },
	}

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
		"boot_args":   hclspec.NewAttr("boot_args", "string", false),
	})

	// capabilities is returned by the Capabilities RPC and indicates what
	// optional features this driver supports
	capabilities = &drivers.Capabilities{
		SendSignals: false,
		Exec:        false,
		FSIsolation: cstructs.FSIsolationImage,
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

	d.logger.Warn("Set Config", "config", fmt.Sprintf("%#v", config), "raw", cfg.PluginConfig)

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

func newFirecracker(ctx context.Context, binPath, socketPath, kernelImage, kernelArgs, fsPath string) (*firecracker.Machine, error) {
	rootDrive := models.Drive{
		DriveID:      firecracker.String("1"),
		PathOnHost:   firecracker.String(fsPath),
		IsRootDevice: firecracker.Bool(true),
		IsReadOnly:   firecracker.Bool(false),
	}

	fcCfg := firecracker.Config{
		SocketPath:      socketPath,
		KernelImagePath: kernelImage,
		KernelArgs:      kernelArgs,
		Drives:          []models.Drive{rootDrive},
		MachineCfg: models.MachineConfiguration{
			VcpuCount:   1,
			CPUTemplate: models.CPUTemplate("C3"),
			HtEnabled:   false,
			MemSizeMib:  512,
		},
	}

	machineOpts := []firecracker.Opt{}

	// TODO: Support jailer
	cmd := firecracker.VMCommandBuilder{}.
		WithBin(binPath).
		WithSocketPath(socketPath).
		WithStdin(os.Stdin).
		WithStdout(os.Stdout).
		WithStderr(os.Stderr).
		Build(ctx)
	machineOpts = append(machineOpts, firecracker.WithProcessRunner(cmd))

	m, err := firecracker.NewMachine(ctx, fcCfg, machineOpts...)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (d *Driver) StartTask(cfg *drivers.TaskConfig) (*drivers.TaskHandle, *cstructs.DriverNetwork, error) {
	if _, ok := d.tasks.Get(cfg.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", cfg.ID)
	}

	ctx := context.Background()
	handle := drivers.NewTaskHandle(pluginName)

	var config TaskConfig
	if err := cfg.DecodeDriverConfig(&config); err != nil {
		return nil, nil, err
	}

	if config.KernelBootArgs == "" {
		config.KernelBootArgs = defaultBootArgs
	}

	controlUUID, err := uuid.NewRandom()
	if err != nil {
		return nil, nil, err
	}

	controlSocketPath := fmt.Sprintf("/tmp/%s.socket", controlUUID)
	m, err := newFirecracker(ctx, d.config.FirecrackerPath, controlSocketPath, config.KernelPath, config.KernelBootArgs, config.ImagePath)
	if err != nil {
		return nil, nil, err
	}

	h := &taskHandle{
		taskConfig: cfg,
		machine:    m,
		procState:  drivers.TaskStateRunning,
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

	return h.machine.StopVMM()
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

func (d *Driver) TaskStats(taskID string) (*cstructs.TaskResourceUsage, error) {
	_, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	return &cstructs.TaskResourceUsage{
		ResourceUsage: &cstructs.ResourceUsage{
			MemoryStats: &cstructs.MemoryStats{},
			CpuStats:    &cstructs.CpuStats{},
		},
		Pids: make(map[string]*cstructs.ResourceUsage),
	}, nil
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
