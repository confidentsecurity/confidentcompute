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

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"
	ev "github.com/openpcc/openpcc/attestation/evidence"
)

type GPUConfig struct {
	// Required is a bool that indicates whether the GPU is going to be present or simulated. True means a real NVIDIA GPU
	Required bool `yaml:"required"`
}

type GPUManager interface {
	VerifyGPUState(ctx context.Context) error
	EnableConfidentialCompute() error
	GetAttestationEvidenceList(ctx context.Context) (ev.SignedEvidenceList, error)
}

type GPUAdmin interface {
	CollectEvidence(nonce []byte) ([]gpu.GPUDevice, error)
	AllGPUInPersistenceMode() (bool, error)
	IsConfidentialComputeEnabled() (bool, error)
	IsGPUReadyStateEnabled() (bool, error)
	EnableGPUReadyState() error
}
