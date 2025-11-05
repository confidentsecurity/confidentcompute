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

package routercom

import (
	"time"
)

const (
	defaultTPMDevice = "/dev/tpmrm0"
)

type Config struct {
	// TPM is tpm related config
	TPM *TPM `yaml:"tpm"`
	// Worker is compute_worker related config
	Worker *WorkerConfig `yaml:"worker"`
}

type TPM struct {
	// Simulate indicates whether the TPM is simulated. Only true during local dev
	Simulate bool `yaml:"simulate"`
	// Device is the filesystem device where the TPM lives
	Device string `yaml:"device"`
	// REKHandle is the TPM handle for the Request Encryption Key
	REKHandle uint32 `yaml:"rek_handle"`
	// SimulatorCmdAddress is the address to reach out to the simulator's command. Leave blank for default
	SimulatorCmdAddress string `yaml:"simulator_cmd_address"`
	// SimulatorPlatformAddress is the address to reach out to the simulator's command. Leave blank for default
	SimulatorPlatformAddress string `yaml:"simulator_platform_address"`
}

// WorkerConfig is config for talking to compute_worker
type WorkerConfig struct {
	// BinaryPath is where the compute_worker binary lives on the machine
	BinaryPath string `yaml:"binary_path"`
	// LLMBaseURL is the local url for talking to an LLM on the system
	LLMBaseURL string `yaml:"llm_base_url"`
	// Timeout is how long to wait for the compute_worker to work
	Timeout time.Duration `yaml:"timeout"`
	// BadgePublicKey is the public key counterpart to the ed25519 private key that the auth server uses to sign badges
	BadgePublicKey string `yaml:"badge_public_key"`
	// Models is the list of LLMs installed on the system
	Models []string `yaml:"models"`
}

func DefaultConfig() *Config {
	return &Config{
		TPM: &TPM{
			Simulate:  false,
			Device:    defaultTPMDevice,
			REKHandle: 0,
		},
		Worker: &WorkerConfig{
			BinaryPath: "",
			// Zero values mean we use the defaults from the computeworker flags.
			LLMBaseURL: "",
			// Set the compute worker process timeout to 5 minutes,
			// to match our default 5 minute inference timeout in the client, and the gateway.
			Timeout:        5 * time.Minute,
			BadgePublicKey: "",
			Models:         []string{},
		},
	}
}
