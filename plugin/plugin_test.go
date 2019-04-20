package plugin

import (
	"testing"

	"github.com/dantoml/nomad-plugin-firecracker/plugin/testutils"
	dtestutil "github.com/hashicorp/nomad/plugins/drivers/testutils"
	"gotest.tools/assert"
)

func driverHarness(t *testing.T) *dtestutils.DriverHarness {
	testutils.KVMCompatible(t)
	return nil
}

func TestDriver_StartTask(t *testing.T) {
	harness := driverHarness(t)
	assert.NotNil(t, harness)
}
