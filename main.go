package main

import (
	"github.com/dantoml/nomad-plugin-firecracker/plugin"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins"
)

func main() {
	plugins.Serve(factory)
}

func factory(log hclog.Logger) interface{} {
	if log == nil {
		log = hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Trace,
			JSONFormat: true,
		})
	}
	return plugin.NewDriver(log)
}
