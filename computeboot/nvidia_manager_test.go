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
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonscq"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/certs"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nras"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nvswitch"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed mockCert.txt
var ValidCertChainData []byte

type MockGPUAdmin struct {
	AllGPUInPersistenceModeFunc      func() (bool, error)
	IsConfidentialComputeEnabledFunc func() (bool, error)
	IsGPUReadyStateEnabledFunc       func() (bool, error)
	EnableGPUReadyStateFunc          func() error
	CollectEvidenceFunc              func(nonce []byte) ([]gpu.GPUDevice, error)
}

func (m *MockGPUAdmin) CollectEvidence(nonce []byte) ([]gpu.GPUDevice, error) {
	return m.CollectEvidenceFunc(nonce)
}

func (m *MockGPUAdmin) AllGPUInPersistenceMode() (bool, error) {
	return m.AllGPUInPersistenceModeFunc()
}

func (m *MockGPUAdmin) IsConfidentialComputeEnabled() (bool, error) {
	return m.IsConfidentialComputeEnabledFunc()
}

func (m *MockGPUAdmin) IsGPUReadyStateEnabled() (bool, error) {
	return m.IsGPUReadyStateEnabledFunc()
}

func (m *MockGPUAdmin) EnableGPUReadyState() error {
	return m.EnableGPUReadyStateFunc()
}

type MockRemoteVerifier struct {
	AttestGPUFunc    func(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error)
	AttestSwitchFunc func(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error)
	VerifyJWTFunc    func(ctx context.Context, signedToken string) (*jwt.Token, error)
}

func (m *MockRemoteVerifier) AttestGPU(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error) {
	if m.AttestGPUFunc != nil {
		return m.AttestGPUFunc(ctx, request)
	}
	// Return a default successful response with proper JWT data
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"x-nvidia-overall-att-result": true,
	})
	// Add kid header for intermediate certificate attestor
	token.Header["kid"] = "test-key-id"
	tokenString, _ := token.SignedString([]byte("test-secret"))

	// Create device JWTs based on the number of evidence items in the request
	deviceJWTs := make(map[string]string)
	for i := range request.EvidenceList {
		deviceJWTs[fmt.Sprintf("GPU-%d", i)] = tokenString
	}

	return &nras.AttestationResponse{
		JWTData:    []string{"unused-header", tokenString},
		DeviceJWTs: deviceJWTs,
	}, nil
}

func (m *MockRemoteVerifier) AttestSwitch(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error) {
	if m.AttestSwitchFunc != nil {
		return m.AttestSwitchFunc(ctx, request)
	}
	// Return a default successful response with proper JWT data
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"x-nvidia-overall-att-result": true,
	})
	// Add kid header for intermediate certificate attestor
	token.Header["kid"] = "test-key-id"
	tokenString, _ := token.SignedString([]byte("test-secret"))
	return &nras.AttestationResponse{
		JWTData:    []string{"unused-header", tokenString},
		DeviceJWTs: map[string]string{},
	}, nil
}

func (m *MockRemoteVerifier) VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error) {
	if m.VerifyJWTFunc != nil {
		return m.VerifyJWTFunc(ctx, signedToken)
	}
	// Parse the token and return it (without signature verification for tests)
	token, _, err := jwt.NewParser().ParseUnverified(signedToken, jwt.MapClaims{})
	return token, err
}

type MockSwitchAdminProvider struct {
	BuildSwitchAdminFunc func() (SwitchAdmin, error)
}

func (m *MockSwitchAdminProvider) BuildSwitchAdmin() (SwitchAdmin, error) {
	return m.BuildSwitchAdminFunc()
}

type MockSwitchAdmin struct {
	ShutdownFunc        func() error
	CollectEvidenceFunc func(nonce []byte) ([]nvswitch.SwitchDevice, error)
}

func (m *MockSwitchAdmin) Shutdown() error {
	return m.ShutdownFunc()
}

func (m *MockSwitchAdmin) CollectEvidence(nonce []byte) ([]nvswitch.SwitchDevice, error) {
	return m.CollectEvidenceFunc(nonce)
}

type MockCertificateProvider struct {
	GetCertificateFunc func(jwtToken string) (*x509.Certificate, error)
}

func (m *MockCertificateProvider) GetCertificate(_ context.Context, jwtToken string) (*x509.Certificate, error) {
	if m.GetCertificateFunc != nil {
		return m.GetCertificateFunc(jwtToken)
	}
	// Parse the first certificate from the cert chain data
	block, _ := pem.Decode(ValidCertChainData)
	if block == nil {
		return nil, errors.New("failed to decode PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func TestVerifyGPUState(t *testing.T) {
	testCases := []struct {
		name             string
		persistenceMode  bool
		readyState       bool
		persistenceErr   error
		readyStateErr    error
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:            "Valid state for attestation",
			persistenceMode: true,
			readyState:      false,
			expectedError:   false,
		},
		{
			name:             "Invalid state - persistence mode off",
			persistenceMode:  false,
			readyState:       false,
			expectedError:    true,
			expectedErrorMsg: "GPU is not in a valid state for confidential computing",
		},
		{
			name:             "Invalid state - ready state on",
			persistenceMode:  true,
			readyState:       true,
			expectedError:    true,
			expectedErrorMsg: "GPU is not in a valid state for confidential computing",
		},
		{
			name:             "Error checking persistence mode",
			persistenceErr:   errors.New("persistence mode error"),
			expectedError:    true,
			expectedErrorMsg: "failed to get confidential compute state: failed to check if GPU is in persistence mode: persistence mode error",
		},
		{
			name:             "Error checking ready state",
			persistenceMode:  true,
			readyStateErr:    errors.New("ready state error"),
			expectedError:    true,
			expectedErrorMsg: "failed to get confidential compute state: failed to check if confidential compute is ready: ready state error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockGPUAdmin := &MockGPUAdmin{
				AllGPUInPersistenceModeFunc: func() (bool, error) {
					return tc.persistenceMode, tc.persistenceErr
				},
				IsGPUReadyStateEnabledFunc: func() (bool, error) {
					return tc.readyState, tc.readyStateErr
				},
			}

			manager := &NvidiaManager{
				GPUAdmin: mockGPUAdmin,
			}

			err := manager.VerifyGPUState(t.Context())

			if tc.expectedError {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedErrorMsg, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEnableConfidentialCompute(t *testing.T) {
	testCases := []struct {
		name             string
		enableError      error
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:          "Successfully enabled confidential compute",
			expectedError: false,
		},
		{
			name:             "Failed to enable GPU ready state",
			enableError:      errors.New("enable error"),
			expectedError:    true,
			expectedErrorMsg: "failed to enable GPU ready state: enable error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockGPUAdmin := &MockGPUAdmin{
				EnableGPUReadyStateFunc: func() error {
					return tc.enableError
				},
			}

			manager := &NvidiaManager{
				GPUAdmin: mockGPUAdmin,
			}

			err := manager.EnableConfidentialCompute()

			if tc.expectedError {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedErrorMsg, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPreparedForAttestation(t *testing.T) {
	testCases := []struct {
		name                   string
		persistenceModeEnabled bool
		readyStateEnabled      bool
		expectedResult         bool
	}{
		{
			name:                   "Valid state for attestation",
			persistenceModeEnabled: true,
			readyStateEnabled:      false,
			expectedResult:         true,
		},
		{
			name:                   "Invalid - persistence mode off",
			persistenceModeEnabled: false,
			readyStateEnabled:      false,
			expectedResult:         false,
		},
		{
			name:                   "Invalid - ready state on",
			persistenceModeEnabled: true,
			readyStateEnabled:      true,
			expectedResult:         false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := ConfidentialComputeState{
				PersistenceModeEnabled:        tc.persistenceModeEnabled,
				ConfidentialComputeReadyState: tc.readyStateEnabled,
			}

			result := state.preparedForAttestation()
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestGetAttestationEvidenceList_SingleGPU(t *testing.T) {
	ctx := context.Background()

	mockGPUAdmin := &MockGPUAdmin{
		AllGPUInPersistenceModeFunc: func() (bool, error) {
			return true, nil
		},
		IsGPUReadyStateEnabledFunc: func() (bool, error) {
			return false, nil
		},
		CollectEvidenceFunc: func(nonce []byte) ([]gpu.GPUDevice, error) {
			// Return a proper GPUDevice with cert chain from mockCert.txt
			certChain := certs.NewCertChainFromData(ValidCertChainData)
			device := gpu.NewGPUDevice(nvml.DEVICE_ARCH_HOPPER, []byte("mock-attestation-report"), certChain)
			return []gpu.GPUDevice{device}, nil
		},
	}

	mockVerifier := &MockRemoteVerifier{}

	mockSwitchProvider := &MockSwitchAdminProvider{}

	mockCertProvider := &MockCertificateProvider{}

	manager := &NvidiaManager{
		GPUAdmin:                        mockGPUAdmin,
		Verifier:                        mockVerifier,
		NVSwitchAdminProvider:           mockSwitchProvider,
		IntermediateCertificateProvider: mockCertProvider,
		NonceGenerator: func() []byte {
			return make([]byte, 32)
		},
	}

	evidenceList, err := manager.GetAttestationEvidenceList(ctx)
	require.NoError(t, err)
	require.NotNil(t, evidenceList)

	// With single GPU, should only have 2 evidence pieces:
	// 1. GPU attestation
	// 2. GPU intermediate certificate
	assert.Len(t, evidenceList, 2)
}

func TestGetAttestationEvidenceList_MultiGPU(t *testing.T) {
	ctx := context.Background()

	mockGPUAdmin := &MockGPUAdmin{
		AllGPUInPersistenceModeFunc: func() (bool, error) {
			return true, nil
		},
		IsGPUReadyStateEnabledFunc: func() (bool, error) {
			return false, nil
		},
		CollectEvidenceFunc: func(nonce []byte) ([]gpu.GPUDevice, error) {
			// Return two devices to trigger multi-GPU path (protected PCIE mode)
			certChain := certs.NewCertChainFromData(ValidCertChainData)
			device1 := gpu.NewGPUDevice(nvml.DEVICE_ARCH_HOPPER, []byte("mock-attestation-report-1"), certChain)
			device2 := gpu.NewGPUDevice(nvml.DEVICE_ARCH_HOPPER, []byte("mock-attestation-report-2"), certChain)
			return []gpu.GPUDevice{device1, device2}, nil
		},
	}

	mockVerifier := &MockRemoteVerifier{}

	shutdownCalled := false
	mockSwitchAdmin := &MockSwitchAdmin{
		CollectEvidenceFunc: func(nonce []byte) ([]nvswitch.SwitchDevice, error) {
			// Return a proper SwitchDevice with cert chain
			certChain := certs.NewCertChainFromData(ValidCertChainData)
			device := nvswitch.NewSwitchDevice("switch-uuid-1", gonscq.ArchLS10, []byte("mock-switch-attestation-report"), certChain)
			return []nvswitch.SwitchDevice{device}, nil
		},
		ShutdownFunc: func() error {
			shutdownCalled = true
			return nil
		},
	}

	mockSwitchProvider := &MockSwitchAdminProvider{
		BuildSwitchAdminFunc: func() (SwitchAdmin, error) {
			return mockSwitchAdmin, nil
		},
	}

	mockCertProvider := &MockCertificateProvider{}

	manager := &NvidiaManager{
		GPUAdmin:                        mockGPUAdmin,
		Verifier:                        mockVerifier,
		NVSwitchAdminProvider:           mockSwitchProvider,
		IntermediateCertificateProvider: mockCertProvider,
		NonceGenerator: func() []byte {
			return make([]byte, 32)
		},
	}

	evidenceList, err := manager.GetAttestationEvidenceList(ctx)
	require.NoError(t, err)
	require.NotNil(t, evidenceList)

	// With multi-GPU (protected PCIE mode), should have 4 evidence pieces:
	// 1. GPU attestation
	// 2. GPU intermediate certificate
	// 3. NVSwitch attestation
	// 4. NVSwitch intermediate certificate
	assert.Len(t, evidenceList, 4)
	assert.True(t, shutdownCalled, "NVSwitch admin should be shutdown")
}
