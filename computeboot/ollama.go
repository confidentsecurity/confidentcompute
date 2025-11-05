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

	ollama "github.com/ollama/ollama/api"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/otel/otelutil"
)

type OllamaConfig struct {
	// Skip skips the Ollama initialization, used in local dev
	Skip bool `yaml:"skip"`
	// Model is the model Ollama is using
	Models []string `yaml:"models"`
	// URL is the local url for connecting to ollama on
	URL string `yaml:"url"`
	// LocalDev prevents reloading Ollama to search for a GPU as part of Ollama initialization
	LocalDev bool `yaml:"local_dev"`
}

type OllamaInitializer struct {
	httpClient *http.Client
	models     []string
	ollamaURL  string
}

func NewOllamaInitializerWithConfig(cfg *OllamaConfig) *OllamaInitializer {
	return &OllamaInitializer{
		httpClient: &http.Client{
			Timeout:   10 * time.Minute, // have at least some timeout.
			Transport: otelutil.NewTransport(http.DefaultTransport),
		},
		models:    cfg.Models,
		ollamaURL: cfg.URL,
	}
}

func (o *OllamaInitializer) PullModel(ctx context.Context, model string) error {
	stream := false
	ollamaReq := ollama.PullRequest{
		Model:  model,
		Stream: &stream,
	}

	rawBody, err := json.Marshal(ollamaReq)
	if err != nil {
		slog.Error("Failed to marshal request", "error", err)
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.ollamaURL+"/api/pull", bytes.NewBuffer(rawBody))
	if err != nil {
		slog.Error("Failed to create request", "error", err)
		return err
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		slog.Error("Failed to do request", "error", err)
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Failed to get response", "status", resp.Status)
		err = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		return httpfmt.ParseBodyAsError(resp, err)
	}

	ollamaProgressResp := &ollama.ProgressResponse{}
	err = json.NewDecoder(resp.Body).Decode(ollamaProgressResp)
	if err != nil {
		slog.Error("Failed to read response", "error", err)
		return err
	}

	if ollamaProgressResp.Status != "success" {
		slog.Error("Failed to get response", "status", ollamaProgressResp.Status)
		return fmt.Errorf("failed to get response: %s", ollamaProgressResp.Status)
	}

	slog.InfoContext(ctx, "Successfully pulled the model", "model", model)
	return nil
}

func (o *OllamaInitializer) Pull(ctx context.Context) error {
	for _, model := range o.models {
		err := o.PullModel(ctx, model)
		if err != nil {
			return err
		}
	}

	return nil
}

func (o *OllamaInitializer) ReloadService(ctx context.Context) error {
	slog.InfoContext(ctx, "Reloading ollama service to find GPU")

	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	reschan := make(chan string)
	_, err = conn.RestartUnitContext(ctx, "ollama.service", "replace", reschan)
	if err != nil {
		return err
	}

	job := <-reschan
	if job != "done" {
		return fmt.Errorf("failed to restart ollama: %s", job)
	}

	// Wait for Ollama to actually respond to HTTP requests,
	// since blocking on its systemd service status is not enough to guarantee it's ready.
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.ollamaURL, nil)
		if err != nil {
			return err
		}

		resp, err := o.httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				slog.InfoContext(ctx, "Ollama service is ready")
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

func (o *OllamaInitializer) PrewarmModel(ctx context.Context, model string) error {
	// Generate a dummy request to load the model into memory
	stream := false
	generateReq := ollama.GenerateRequest{
		Model:  model,
		Prompt: "Hello",
		Stream: &stream,
		Options: map[string]any{
			"num_predict": 1, // Minimal generation, force a 1 token response
		},
	}

	rawBody, err := json.Marshal(generateReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.ollamaURL+"/api/generate", bytes.NewBuffer(rawBody))
	if err != nil {
		return err
	}

	resp, err := o.httpClient.Do(req)
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

func (o *OllamaInitializer) Prewarm(ctx context.Context) error {
	for _, model := range o.models {
		err := o.PrewarmModel(ctx, model)
		if err != nil {
			return err
		}
	}
	return nil
}
