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

//go:build include_fake_attestation

package computeboot_test

import (
	"context"
	"errors"
	"testing"

	"github.com/confidentsecurity/confidentcompute/computeboot"
	"github.com/google/go-tpm/tpm2/transport"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	"github.com/stretchr/testify/require"
)

// MockTPMDevice implements TPMDevice interface for testing.
type MockTPMDevice struct {
	OpenDeviceFunc func() (transport.TPMCloser, error)
	CloseFunc      func() error
}

func (m *MockTPMDevice) OpenDevice() (transport.TPMCloser, error) {
	if m.OpenDeviceFunc != nil {
		return m.OpenDeviceFunc()
	}
	return nil, errors.New("mock error")
}

func (m *MockTPMDevice) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

// MockGPUManager implements GPUManager interface for testing.
type MockGPUManager struct {
	VerifyGPUStateFunc             func(ctx context.Context) error
	EnableConfidentialComputeFunc  func() error
	GetAttestationEvidenceListFunc func(ctx context.Context) (ev.SignedEvidenceList, error)
}

func (m *MockGPUManager) VerifyGPUState(ctx context.Context) error {
	if m.VerifyGPUStateFunc != nil {
		return m.VerifyGPUStateFunc(ctx)
	}
	return nil
}

func (m *MockGPUManager) EnableConfidentialCompute() error {
	if m.EnableConfidentialComputeFunc != nil {
		return m.EnableConfidentialComputeFunc()
	}
	return nil
}

func (m *MockGPUManager) GetAttestationEvidenceList(ctx context.Context) (ev.SignedEvidenceList, error) {
	if m.GetAttestationEvidenceListFunc != nil {
		return m.GetAttestationEvidenceListFunc(ctx)
	}
	return ev.SignedEvidenceList{}, nil
}

func TestPrepareAttestationPackage_FailedToOpenDevice(t *testing.T) {
	tpmConfig := &computeboot.TPMConfig{
		ChildKeyHandle:          0x81000000,
		PrimaryKeyHandle:        0x81010001,
		REKCreationTicketHandle: 0x01c0000A,
		REKCreationHashHandle:   0x01c0000B,
		TPMType:                 computeboot.InMemorySimulator,
	}
	attestConfig := &computeboot.AttestationConfig{
		FakeSecret: "fake",
	}

	mockDevice := &MockTPMDevice{
		OpenDeviceFunc: func() (transport.TPMCloser, error) {
			return nil, errors.New("could not connect to TPM")
		},
	}

	mockGPUManager := &MockGPUManager{}
	transparencyConfig := &computeboot.TransparencyConfig{}

	evidence, err := computeboot.PrepareAttestationPackage(mockDevice, mockGPUManager, tpmConfig, attestConfig, transparencyConfig)

	require.Error(t, err)
	require.Contains(t, err.Error(), "could not connect to TPM")
	require.Nil(t, evidence)
}

func TestPrepareAttestationPackage_Success(t *testing.T) {
	tpmCfg := &computeboot.TPMConfig{
		PrimaryKeyHandle:        0x81000001,
		ChildKeyHandle:          0x81000002,
		REKCreationTicketHandle: 0x01c0000A,
		REKCreationHashHandle:   0x01c0000B,
		AttestationKeyHandle:    0x81000003,
		TPMType:                 computeboot.InMemorySimulator,
	}
	operator, err := computeboot.NewTPMOperatorWithConfig(tpmCfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, operator.Close())
	})

	err = operator.SetupAttestationKey()
	require.NoError(t, err)

	err = operator.SetupEncryptionKeys()
	require.NoError(t, err)

	attestationCfg := &computeboot.AttestationConfig{
		FakeSecret: "fake",
	}
	transparencyCfg := &computeboot.TransparencyConfig{}

	evidence, err := computeboot.PrepareAttestationPackage(operator.GetDevice(), &MockGPUManager{}, tpmCfg, attestationCfg, transparencyCfg)
	require.NoError(t, err)
	require.NotNil(t, evidence)
	require.Len(t, evidence, 5)

	v := verify.NewFakeVerifier([]byte(attestationCfg.FakeSecret))
	_, err = v.VerifyComputeNode(t.Context(), evidence)
	require.NoError(t, err)
}
