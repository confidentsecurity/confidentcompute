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
	"fmt"

	ev "github.com/openpcc/openpcc/attestation/evidence"
)

type AttestationConfig struct {
	// FakeSecret triggers and configures fake attestation. Only used when
	// computeboot is built with the `include_fake_attestation` build tag.
	FakeSecret string `yaml:"fake_secret"`
	// AttestGPU indicates whether to attest the GPU
	AttestGPU bool `yaml:"attest_gpu"`
}

func PrepareAttestationPackage(tpmDevice TPMDevice, gpuManager GPUManager, tpmCfg *TPMConfig, attestationCfg *AttestationConfig, tlogCfg *TransparencyConfig) (ev.SignedEvidenceList, error) {
	// collectEvidence is implemented differently depending on build tags.
	evidence, err := collectEvidence(attestationCfg, tpmCfg, tpmDevice, gpuManager, tlogCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create evidence handler: %w", err)
	}

	return evidence, nil
}
