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
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonscq"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nras"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nvswitch"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openpcc/openpcc/attestation/attest"
	ev "github.com/openpcc/openpcc/attestation/evidence"
)

type RemoteVerifier interface {
	AttestGPU(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error)
	AttestSwitch(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error)
	VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error)
}

type SwitchAdmin interface {
	CollectEvidence(nonce []byte) ([]nvswitch.SwitchDevice, error)
	Shutdown() error
}

type SwitchAdminProvider interface {
	BuildSwitchAdmin() (SwitchAdmin, error)
}

type NvidiaManager struct {
	GPUAdmin                        GPUAdmin
	Verifier                        RemoteVerifier
	NVSwitchAdminProvider           SwitchAdminProvider
	NonceGenerator                  func() []byte
	IntermediateCertificateProvider attest.CertificateProvider
}

type ConfidentialComputeState struct {
	PersistenceModeEnabled        bool
	ConfidentialComputeReadyState bool
}

func (c *ConfidentialComputeState) preparedForAttestation() bool {
	isPrepared := c.PersistenceModeEnabled && !c.ConfidentialComputeReadyState
	if !isPrepared {
		slog.Error("GPU is not in a valid state for confidential computing",
			"persistence_mode_enabled", c.PersistenceModeEnabled,
			"confidential_compute_ready_state", c.ConfidentialComputeReadyState,
		)
	}
	return isPrepared
}

// defaultNonceGenerator generates a 32-byte random nonce
func defaultNonceGenerator() []byte {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		slog.Error("failed to generate nonce", "error", err)
		return make([]byte, 32) // Return zero-filled nonce on error
	}
	return nonce
}

// nscqSwitchAdminProvider is the default provider for NVSwitch admin
type nscqSwitchAdminProvider struct{}

func (*nscqSwitchAdminProvider) BuildSwitchAdmin() (SwitchAdmin, error) {
	handler, err := gonscq.NewHandler()
	if err != nil {
		return nil, fmt.Errorf("failed to create nvswitch handler: %w", err)
	}
	admin, err := nvswitch.NewNscqSwitchAdmin(handler)
	if err != nil {
		return nil, fmt.Errorf("failed to create nvswitch admin: %w", err)
	}
	return admin, nil
}

func NewNvidiaManager() (*NvidiaManager, error) {
	gpuAdmin, err := gpu.NewNvmlGPUAdmin(nil)
	if err != nil {
		return nil, err
	}
	return &NvidiaManager{
		GPUAdmin:                        gpuAdmin,
		Verifier:                        nras.NewNRASClient(http.DefaultClient),
		NVSwitchAdminProvider:           &nscqSwitchAdminProvider{},
		NonceGenerator:                  defaultNonceGenerator,
		IntermediateCertificateProvider: nil, // Will use default NRAS provider
	}, nil
}

func (n *NvidiaManager) VerifyGPUState(ctx context.Context) error {
	slog.InfoContext(ctx, "Verifying GPU for confidential computing")

	state, err := n.getConfidentialComputeState()
	if err != nil {
		return fmt.Errorf("failed to get confidential compute state: %w", err)
	}

	if !state.preparedForAttestation() {
		return errors.New("GPU is not in a valid state for confidential computing")
	}

	return nil
}

func (n *NvidiaManager) getConfidentialComputeState() (ConfidentialComputeState, error) {
	persistenceModeEnabled, err := n.GPUAdmin.AllGPUInPersistenceMode()
	if err != nil {
		return ConfidentialComputeState{}, fmt.Errorf("failed to check if GPU is in persistence mode: %w", err)
	}

	confComputeReadyState, err := n.GPUAdmin.IsGPUReadyStateEnabled()
	if err != nil {
		return ConfidentialComputeState{}, fmt.Errorf("failed to check if confidential compute is ready: %w", err)
	}

	return ConfidentialComputeState{
		PersistenceModeEnabled:        persistenceModeEnabled,
		ConfidentialComputeReadyState: confComputeReadyState,
	}, nil
}

func (n *NvidiaManager) EnableConfidentialCompute() error {
	slog.Info("setting confidential compute mode for GPU")

	err := n.GPUAdmin.EnableGPUReadyState()
	if err != nil {
		slog.Error("failed to enable GPU ready state", "error", err)
		return fmt.Errorf("failed to enable GPU ready state: %w", err)
	}

	return nil
}

func (n *NvidiaManager) GetAttestationEvidenceList(ctx context.Context) (ev.SignedEvidenceList, error) {
	result := ev.SignedEvidenceList{}
	nonce := n.NonceGenerator()

	gpuAttester, err := attest.NewNVidiaAttestor(
		gonvtrust.NewRemoteAttester(n.GPUAdmin, n.Verifier),
		ev.NvidiaETA,
		nonce,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nvidia CC attestor: %w", err)
	}

	gpuSignedEvidence, err := gpuAttester.CreateSignedEvidence(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nvidia CC signed evidence: %w", err)
	}
	result = append(result, gpuSignedEvidence)

	nvidiaCCIntermediateCertificateSignedEvidence, err := n.createIntermediateCertificateEvidence(ctx, gpuSignedEvidence.ToJWT(), ev.NvidiaCCIntermediateCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nvidia CC intermediate certificate signed evidence: %w", err)
	}
	result = append(result, nvidiaCCIntermediateCertificateSignedEvidence)

	// If there are multiple GPUs, that means the system is in protected PCIE mode
	// and we need to attest nvswitches as well.
	if len(gpuAttester.AttestationResult.DevicesTokens) > 1 {
		nvSwitchAdmin, err := n.NVSwitchAdminProvider.BuildSwitchAdmin()
		if err != nil {
			return nil, err
		}
		defer func() {
			err := nvSwitchAdmin.Shutdown()
			if err != nil {
				slog.Error("failed to shutdown nvswitch admin", "error", err)
			}
		}()

		switchNonce := n.NonceGenerator()
		nvSwitchAttester := gonvtrust.NewRemoteAttester(nvSwitchAdmin, n.Verifier)

		switchAttester, err := attest.NewNVidiaAttestor(nvSwitchAttester, ev.NvidiaSwitchETA, switchNonce)
		if err != nil {
			return nil, fmt.Errorf("failed to create nvswitch attestor: %w", err)
		}
		switchSignedEvidence, err := switchAttester.CreateSignedEvidence(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create nvswitch signed evidence: %w", err)
		}
		result = append(result, switchSignedEvidence)
		nvidiaSwitchIntermediateCertificateSignedEvidence, err := n.createIntermediateCertificateEvidence(ctx, switchSignedEvidence.ToJWT(), ev.NvidiaSwitchIntermediateCertificate)
		if err != nil {
			return nil, fmt.Errorf("failed to create Nvidia CC intermediate certificate signed evidence: %w", err)
		}
		result = append(result, nvidiaSwitchIntermediateCertificateSignedEvidence)
	}

	return result, nil
}

func (n *NvidiaManager) createIntermediateCertificateEvidence(ctx context.Context, jwtToken string, evidenceType ev.EvidenceType) (*ev.SignedEvidencePiece, error) {
	if n.IntermediateCertificateProvider != nil {
		// Use injected provider for testing
		intermediateCert, err := n.IntermediateCertificateProvider.GetCertificate(ctx, jwtToken)
		if err != nil {
			return nil, fmt.Errorf("failed to get intermediate certificate: %w", err)
		}
		return &ev.SignedEvidencePiece{
			Type:      evidenceType,
			Data:      intermediateCert.Raw,
			Signature: intermediateCert.Signature,
		}, nil
	}

	// Use default NRAS provider
	attestor := attest.NewNvidiaCCIntermediateCertificateAttestor(jwtToken, evidenceType)
	return attestor.CreateSignedEvidence(ctx)
}
