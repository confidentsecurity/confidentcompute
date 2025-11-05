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
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/confidentsecurity/confidentcompute/cmd/compute_worker/exitcodes"
	"github.com/confidentsecurity/confidentcompute/computeworker"
	"github.com/confidentsecurity/confidentcompute/debug"
	"github.com/confidentsecurity/confidentcompute/profiling"
	"github.com/openpcc/openpcc/otel/otelutil"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

const serviceName = "compute_worker"

func main() {
	os.Exit(run())
}

func run() int {
	profiling.ComputeWorker.InitProfilerIfEnabled()

	debug.SetupLog(serviceName)

	slog.Info("Starting compute worker")
	now := time.Now()

	shutdown, err := otelutil.Init(context.Background(), serviceName)
	if err != nil {
		slog.Error("failed to init opentelemetry", "error", err)
		return 1
	}

	slog.Info("otel initialized", "took_ms", time.Since(now).Milliseconds())

	defer func() {
		now := time.Now()
		shutdown(context.Background())
		slog.Info("shutdown otel", "took_ms", time.Since(now).Milliseconds())
	}()

	config, err := computeworker.ParseConfigFromFlags()
	if err != nil {
		slog.Error("failed to parse config from flags", "error", err)
		return 1
	}

	// Create a new context with our trace information.
	ctx := context.Background()
	if v := config.Traceparent; v != "" {
		carrier := propagation.MapCarrier{"traceparent": config.Traceparent}
		ctx = otel.GetTextMapPropagator().Extract(ctx, carrier)
	}

	ctx, _ = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)

	worker, err := computeworker.New(ctx, config, os.Stdin, os.Stdout)
	if err != nil {
		slog.Error("failed to create worker", "error", err)
		return exitcodes.MapErrorToExitCode(err)
	}

	err = worker.Run()
	if err != nil {
		slog.Error("failed to run worker", "error", err)
		return exitcodes.MapErrorToExitCode(err)
	}

	return 0
}
