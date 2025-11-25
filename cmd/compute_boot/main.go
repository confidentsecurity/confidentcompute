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
	"fmt"
	"log/slog"
	"os"

	"github.com/confidentsecurity/confidentcompute/computeboot"
	"github.com/confidentsecurity/confidentcompute/debug"
	"github.com/confidentsecurity/confidentcompute/routercom/evidence"
	"github.com/openpcc/openpcc/app/config"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/otel/otelutil"
)

const serviceName = "compute_boot"

func main() {
	os.Exit(run(context.Background()))
}

// Config is compute_boot service config
type Config struct {
	// InferenceEngine is config for talking to the inference engine (eg. ollama, vllm)
	InferenceEngine *computeboot.InferenceEngineConfig `yaml:"inference_engine"`
	// TPM is config for talking to the TPM
	TPM *computeboot.TPMConfig `yaml:"tpm"`
	// Attestation is config for the attestations compute boot creates
	Attestation *computeboot.AttestationConfig `yaml:"attestation"`
	// Evidence is config for sending the evidence to router_com
	Evidence evidence.SenderConfig `yaml:"evidence"`
	// GPU is config for attesting to a GPU
	GPU *computeboot.GPUConfig `yaml:"gpu"`
	// TransparencyConfig is config for the transparency service
	TransparencyConfig *computeboot.TransparencyConfig `yaml:"transparency"`
}

func run(ctx context.Context) int {
	debug.SetupLog(serviceName)

	shutdown, err := otelutil.Init(context.Background(), serviceName)
	if err != nil {
		slog.Error("failed to init opentelemetry", "error", err)
		return 1
	}
	defer shutdown(context.Background())

	ctx, span := otelutil.Tracer.Start(ctx, "compute_boot")
	defer span.End()

	configFile, err := config.FilenameFromArgs(os.Args[1:])
	if err != nil {
		slog.Error("failed to determine config file", "error", err)
		return 1
	}

	cfg := &Config{
		InferenceEngine:    &computeboot.InferenceEngineConfig{},
		TPM:                &computeboot.TPMConfig{},
		Attestation:        &computeboot.AttestationConfig{},
		Evidence:           evidence.DefaultSenderConfig(),
		GPU:                &computeboot.GPUConfig{},
		TransparencyConfig: &computeboot.TransparencyConfig{},
	}
	err = config.Load(cfg, configFile, nil)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		return 1
	}

	gpuManager, err := computeboot.NewGPUManager(cfg.GPU)
	if err != nil {
		slog.Error("failed to create GPU manager", "error", err)
		return 1
	}

	ctx, verifyGPUStateSpan := otelutil.Tracer.Start(ctx, "compute_boot.verifyGPUState")
	if err := gpuManager.VerifyGPUState(ctx); err != nil {
		slog.Error("GPU configuration failed", "error", err)
		verifyGPUStateSpan.RecordError(err)
		return 1
	}
	verifyGPUStateSpan.End()

	tpmOperator, err := computeboot.NewTPMOperatorWithConfig(cfg.TPM)
	if err != nil {
		slog.Error("failed to create TPM operator", "error", err)
		return 1
	}

	if err := setupTPM(ctx, tpmOperator); err != nil {
		slog.Error("TPM setup failed", "error", err)
		return 1
	}
	defer func() {
		err = errors.Join(err, tpmOperator.Close())
	}()

	slog.InfoContext(ctx, "Preparing attestation evidence")

	evidenceList, err := attestNode(tpmOperator, gpuManager, cfg)
	if err != nil {
		slog.Error("failed to attest", "error", err)
		return 1
	}
	slog.InfoContext(ctx, "Attestation evidence prepared successfully", "evidence", evidenceList)

	// if gpu is present, mark it as ready for computing, after successful attestation
	if err := gpuManager.EnableConfidentialCompute(); err != nil {
		slog.Error("failed to enable confidential compute", "error", err)
		return 1
	}

	// initialize inference engine after GPU is ready
	slog.InfoContext(ctx, "Initializing inference engine", "engine", cfg.InferenceEngine.Type)
	if err := initializeInferenceEngine(ctx, cfg.InferenceEngine); err != nil {
		slog.Error("inference engine initialization failed", "error", err)
		return 1
	}

	if err := evidence.Send(ctx, cfg.Evidence, evidenceList); err != nil {
		slog.Error("failed to send attestation evidence to routercom", "error", err)
		return 1
	}

	return 0
}

func setupTPM(ctx context.Context, tpmOperator *computeboot.TPMOperator) error {
	err := tpmOperator.LogTPMState()

	if err != nil {
		return fmt.Errorf("failed to log tpm startup state %w", err)
	}

	err = tpmOperator.SetupAttestationKey()

	if err != nil {
		return fmt.Errorf("failed to setup attestation key on TPM: %w", err)
	}

	err = tpmOperator.SetupEncryptionKeys()

	if err != nil {
		return fmt.Errorf("failed to setup encryption keys on TPM: %w", err)
	}

	slog.InfoContext(ctx, "TPM encryption keys configured successfully")
	return nil
}

func initializeInferenceEngine(ctx context.Context, engineConfig *computeboot.InferenceEngineConfig) error {
	ctx, span := otelutil.Tracer.Start(ctx, "compute_boot.initializeInferenceEngine")
	defer span.End()

	if engineConfig.Skip {
		slog.WarnContext(ctx, "skipping inference engine initialization")
		return nil
	}

	engine := computeboot.NewInferenceEngineInitializerWithConfig(engineConfig)

	// the reload uses a linux command
	if !engineConfig.LocalDev {
		if engineConfig.Type == "vllm" {
			if err := engine.WaitUntilReady(ctx); err != nil {
				return fmt.Errorf("inference engine %s did not become ready: %w", engineConfig.Type, err)
			}
		} else {
			if err := engine.ReloadService(ctx); err != nil {
				return fmt.Errorf("failed to reload %s service: %w", engineConfig.SystemdServiceName, err)
			}
		}
	}

	// Prewarm models to load them into memory and warm any disk caches.
	if err := engine.Prewarm(ctx); err != nil {
		return fmt.Errorf("failed to prewarm models: %w", err)
	}

	slog.InfoContext(ctx, "inference engine initialized successfully")
	return nil
}

func attestNode(tpmOperator *computeboot.TPMOperator, gpuManager computeboot.GPUManager, cfg *Config) (ev.SignedEvidenceList, error) {
	evidenceList, err := computeboot.PrepareAttestationPackage(tpmOperator.GetDevice(), gpuManager, cfg.TPM, cfg.Attestation, cfg.TransparencyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare attestation package: %w", err)
	}

	return evidenceList, nil
}
