// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security
//
// Licensed under the Functional Source License, Version 1.1,
// ALv2 Future License, the terms and conditions of which are
// set forth in the "LICENSE" file included in the root directory
// of this code repository (the "License"); you may not use this
// file except in compliance with the License. You may obtain
// a copy of the License at
//
// https://fsl.software/FSL-1.1-ALv2.template.md
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	gcpcompute "cloud.google.com/go/compute/apiv1"
	"github.com/confidentsecurity/confidentcompute/cloud"
	"github.com/confidentsecurity/confidentcompute/debug"
	"github.com/confidentsecurity/confidentcompute/profiling"
	"github.com/confidentsecurity/confidentcompute/routercom"
	"github.com/confidentsecurity/confidentcompute/routercom/evidence"
	"github.com/openpcc/openpcc/app"
	"github.com/openpcc/openpcc/app/config"
	"github.com/openpcc/openpcc/app/httpapp"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/uuidv7"
)

type Config struct {
	// HTTP is http server related config
	HTTP *httpapp.Config `yaml:"http"`
	// Evidence is config for how router_com gets evidence from compute_boot
	Evidence evidence.ReceiveConfig `yaml:"evidence"`
	// RouterCom is router_com service specific config
	RouterCom *routercom.Config `yaml:"router_com"`
	// RouterAgent is config related to registering with the router
	RouterAgent *agent.Config `yaml:"router_agent"`
	// RouterRIGMDiscovery is config for discovering routers directly from the MIG. (Deprecated, we use the LB by default)
	RouterRIGMDiscovery *cloud.GCPRIGMAddrFinderConfig `yaml:"router_rigm_discovery"`
	// Models is the list of LLMs installed on the system
	Models []string `yaml:"models"`
}

const serviceName = "router_com"

func main() {
	code := run()
	os.Exit(code)
}

func run() int {
	profiling.RouterCom.InitProfilerIfEnabled()

	debug.SetupLog(serviceName)

	shutdown, err := otelutil.Init(context.Background(), serviceName)
	if err != nil {
		slog.Error("failed to init opentelemetry", "error", err)
		return 1
	}
	defer shutdown(context.Background())

	// determine the config file
	configFile, err := config.FilenameFromArgs(os.Args[1:])
	if err != nil {
		slog.Error("Failed to determine config file", "error", err)
		return 1
	}

	// start with default config and override by loading from
	// YAML file and/or environment.
	cfg := &Config{
		HTTP:                httpapp.DefaultStreamingConfig(),
		Evidence:            evidence.DefaultReceiverConfig(),
		RouterCom:           routercom.DefaultConfig(),
		RouterAgent:         agent.DefaultConfig(),
		RouterRIGMDiscovery: nil,
		Models:              []string{},
	}

	err = config.Load(cfg, configFile, nil)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		return 1
	}

	if len(cfg.Models) == 0 {
		slog.Error("Invalid config: no models provided")
	}
	for _, model := range cfg.Models {
		cfg.RouterAgent.Tags = append(cfg.RouterAgent.Tags, "model="+model)
		cfg.RouterCom.Worker.Models = append(cfg.RouterCom.Worker.Models, model)
	}

	// wait until we receive the evidence from compute boot.
	evidenceList, err := evidence.Receive(context.Background(), cfg.Evidence)
	if err != nil {
		slog.Error("failed to get evidence", "error", err)
		return 1
	}

	// setup routercom as an http app
	rtrcom, err := routercom.New(cfg.RouterCom, evidenceList)
	if err != nil {
		slog.Error("failed to create routercom service", "error", err)
		return 1
	}

	defer func() {
		err = errors.Join(err, rtrcom.Close())
	}()

	// setup the router agent
	id, err := uuidv7.New()
	if err != nil {
		slog.Error("failed to generate uuid for routercom", "error", err)
		return 1
	}

	rtragent, err := agent.New(id, cfg.RouterAgent, rtrcom.Evidence())
	if err != nil {
		slog.Error("failed to create new router agent", "error", err)
		return 1
	}

	if cfg.RouterRIGMDiscovery != nil {
		rigmclient, err := gcpcompute.NewRegionInstanceGroupManagersRESTClient(context.Background())
		if err != nil {
			slog.Error("failed to create rigm rest client", "error", err)
			return 1
		}
		defer rigmclient.Close()

		rtragent.RouterFinder(cloud.NewGCPAddrFinder(cfg.RouterRIGMDiscovery, rigmclient))
	}

	a := app.NewMulti(
		httpapp.New(cfg.HTTP, rtrcom),
		rtragent,
	)

	// run the app until it exits or signals received
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	code := app.Run(ctx, a, func() (context.Context, context.CancelFunc) {
		// signals received during graceful shutdown cause immediate exit
		return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	})

	return code
}
