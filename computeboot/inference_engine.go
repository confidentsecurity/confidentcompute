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

package computeboot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"

	"github.com/openpcc/openpcc/otel/otelutil"
	openai "github.com/sashabaranov/go-openai"
)

type InferenceEngineConfig struct {
	// Type is the type of inference engine (ollama, vllm, etc.)
	Type string `yaml:"type"`
	// Skip skips the inference engine initialization, used in local dev
	Skip bool `yaml:"skip"`
	// Model is the model the inference engine is using
	Models []string `yaml:"models"`
	// URL is the local url for connecting to the inference engine
	URL string `yaml:"url"`
	// LocalDev prevents reloading the inference engine service to search for a GPU as part of the initialization
	LocalDev bool `yaml:"local_dev"`
	// name of the systemd service that the inference engine is running in
	SystemdServiceName string `yaml:"systemd_service_name"`
}

type InferenceEngineInitializer struct {
	httpClient  *http.Client
	engineType  string
	models      []string
	engineURL   string
	serviceName string
}

func NewInferenceEngineInitializerWithConfig(cfg *InferenceEngineConfig) *InferenceEngineInitializer {
	return &InferenceEngineInitializer{
		httpClient: &http.Client{
			Timeout:   10 * time.Minute, // have at least some timeout.
			Transport: otelutil.NewTransport(http.DefaultTransport),
		},
		engineType:  cfg.Type,
		models:      cfg.Models,
		engineURL:   cfg.URL,
		serviceName: cfg.SystemdServiceName,
	}
}

func (eng *InferenceEngineInitializer) ReloadService(ctx context.Context) error {
	slog.InfoContext(ctx, "Reloading inference engine service to find GPU")

	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	reschan := make(chan string)
	_, err = conn.RestartUnitContext(ctx, eng.serviceName, "replace", reschan)
	if err != nil {
		return err
	}

	job := <-reschan
	if job != "done" {
		return fmt.Errorf("failed to restart inference engine service: %s", job)
	}

	return eng.WaitUntilReady(ctx)
}

// WaitUntilReady waits for the inference engine to respond to HTTP requests.
// This is useful after starting or restarting the service, since blocking on
// systemd service status is not enough to guarantee the engine is ready.
func (eng *InferenceEngineInitializer) WaitUntilReady(ctx context.Context) error {
	// The health check endpoint for vllm is /health, but for ollama it's just /
	var url string
	if eng.engineType == "vllm" {
		url = eng.engineURL + "/health"
	} else {
		url = eng.engineURL
	}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}

		resp, err := eng.httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				slog.InfoContext(ctx, "inference engine service is ready")
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			// retry
		}
	}
}

func (eng *InferenceEngineInitializer) PrewarmModel(ctx context.Context, model string) error {
	// Generate a dummy request to load the model into memory
	rawBody, err := json.Marshal(openai.CompletionRequest{
		Model:     model,
		Prompt:    "Ping",
		Stream:    false,
		MaxTokens: 10,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, eng.engineURL+"/v1/completions", bytes.NewBuffer(rawBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	slog.InfoContext(ctx, "Prewarming model", "request", string(rawBody))
	resp, err := eng.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to prewarm model %s: status %d", model, resp.StatusCode)
	}

	slog.InfoContext(ctx, "Successfully prewarmed model", "model", model)
	return nil
}

func (eng *InferenceEngineInitializer) Prewarm(ctx context.Context) error {
	for _, model := range eng.models {
		err := eng.PrewarmModel(ctx, model)
		if err != nil {
			return err
		}
	}
	return nil
}
