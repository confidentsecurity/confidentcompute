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

package computeworker

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/openpcc/openpcc/attestation/evidence"
)

// The maximum time a worker process can remain idle before it's terminated.
// This timeout helps prevent an accumulation of idle worker processes. A suitable value
// should be determined based on the typical workload and the desired responsiveness of the system.
const DefaultTimeout = 10 * time.Second

var keyHandlePtr *uint
var tpmDevicePtr *string
var base64PublicKeyPtr *string
var base64PublicKeyNamePtr *string
var base64PCRValuesPtr *string
var simulatePtr *bool
var simulatorCmdAddressPtr *string
var simulatorPlatformAddressPtr *string
var llmBaseURLPtr *string
var timeoutPtr *string
var traceparentPtr *string
var requestMediaType *string
var requestEncapsulatedKeyPtr *string
var requestCreditAmountPtr *int64
var badgePublicKeyPtr *string
var modelsList FlagValueList

func init() {
	keyHandlePtr = flag.Uint("tpm_key_handle", 0, "key handle to use for encryption")
	tpmDevicePtr = flag.String("tpm_device", "", "path to the TPM device")
	base64PublicKeyPtr = flag.String("tpm_base64_public_key", "", "base64 encoded public key")
	base64PublicKeyNamePtr = flag.String("tpm_base64_public_key_name", "", "base64 encoded public key name")
	base64PCRValuesPtr = flag.String("tpm_base64_pcr_values", "", "base64 encoded protobuf containing pcr values")
	simulatePtr = flag.Bool("tpm_simulate", false, "simulate the TPM")
	simulatorCmdAddressPtr = flag.String("tpm_simulator_cmd_addr", "", "Address for talking to the simulator cmd, leave blank for defaults")
	simulatorPlatformAddressPtr = flag.String("tpm_simulator_platform_addr", "", "Address for talking to the simulator platform, leave blank for defaults")
	llmBaseURLPtr = flag.String("llm_base_url", "http://localhost:11434", "url to send LLM requests to")
	timeoutPtr = flag.String("service_timeout", DefaultTimeout.String(), "timeout of the worker process")
	traceparentPtr = flag.String("traceparent", "", "trace context")
	requestMediaType = flag.String("request_media_type", "", "the media type of the request as claimed by the client")
	requestEncapsulatedKeyPtr = flag.String("request_encapsulated_key", "", "encapsulated key used to decrypt the request, should be base 64 encoded")
	requestCreditAmountPtr = flag.Int64("request_credit_amount", 0, "the amount of credits that can be spent on this request")
	badgePublicKeyPtr = flag.String("badge_public_key", "", "the PEM-encoded public key counterpart to the ed25519 private key that the auth server uses to sign badges")
	// Since modelsList is of type FlagValueList, the flag '--model <some-val>' can be specified multiple
	// times in the invocation, which will cause <some-val> to be appended to modelsList
	flag.Var(&modelsList, "model", "an LLM model that the node is running")
}

type Config struct {
	TPM         TPMConfig
	LLMBaseURL  string
	Timeout     time.Duration
	Traceparent string
	// RequestParams are the parameters used to handle the request.
	RequestParams  RequestParams
	BadgePublicKey []byte
	Models         []string
}

type TPMConfig struct {
	KeyHandle                uint
	Device                   string
	Simulate                 bool
	SimulatorCmdAddress      string
	SimulatorPlatformAddress string
	PublicKeyBytes           []byte
	PublicKeyNameBytes       []byte
	PCRValues                map[uint32][]byte
}

type RequestParams struct {
	MediaType       string
	EncapsulatedKey []byte
	CreditAmount    int64
}

func DecodeBadgeKey(badgePK string) (ed25519.PublicKey, error) {
	badgeKeyBytes, err := base64.StdEncoding.DecodeString(badgePK)
	if err != nil {
		return nil, fmt.Errorf("failed to parse badge public key: %w", err)
	}
	block, _ := pem.Decode(badgeKeyBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	pubKeyed25519, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("failed to convert parsed publickey into an ed25519 public key")
	}
	return pubKeyed25519, nil
}

func ParseConfigFromFlags() (*Config, error) {
	flag.Parse()

	timeout, err := time.ParseDuration(*timeoutPtr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timeout: %w", err)
	}

	if len(*requestMediaType) == 0 {
		return nil, errors.New("missing request media type")
	}

	encapKeyB, err := base64.StdEncoding.DecodeString(*requestEncapsulatedKeyPtr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request encapsulated key: %w", err)
	}

	badgeKey, err := DecodeBadgeKey(*badgePublicKeyPtr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse badge public key: %w", err)
	}

	// Even though the credit amount is validated upstream when we construct it, we want to make 100% sure
	// that it's a positive number specifically in this context, when we accessing the Ollama API.
	// The credit amount <=0 will translate into `{"options:{"num_predict": <=0}"}` sent to Ollama,
	// which it will happily accept and treat as "num_predict" = "unlimited".
	if *requestCreditAmountPtr < 0 {
		return nil, fmt.Errorf("invalid request credit amount: %d", *requestCreditAmountPtr)
	}

	pubKeyB, err := base64.StdEncoding.DecodeString(*base64PublicKeyPtr)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode public key: %w", err)
	}

	pubKeyNameB, err := base64.StdEncoding.DecodeString(*base64PublicKeyNamePtr)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode public key name: %w", err)
	}

	pcrValB, err := base64.StdEncoding.DecodeString(*base64PCRValuesPtr)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode pcr values: %w", err)
	}

	pcrVals := &evidence.PCRValues{}
	err = pcrVals.UnmarshalBinary(pcrValB)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal pcr values: %w", err)
	}

	return &Config{
		TPM: TPMConfig{
			KeyHandle:                *keyHandlePtr,
			Device:                   *tpmDevicePtr,
			Simulate:                 *simulatePtr,
			SimulatorCmdAddress:      *simulatorCmdAddressPtr,
			SimulatorPlatformAddress: *simulatorPlatformAddressPtr,
			PublicKeyBytes:           pubKeyB,
			PublicKeyNameBytes:       pubKeyNameB,
			PCRValues:                pcrVals.Values,
		},
		LLMBaseURL:  *llmBaseURLPtr,
		Timeout:     timeout,
		Traceparent: *traceparentPtr,
		RequestParams: RequestParams{
			MediaType:       *requestMediaType,
			EncapsulatedKey: encapKeyB,
			CreditAmount:    *requestCreditAmountPtr,
		},
		BadgePublicKey: badgeKey,
		Models:         modelsList,
	}, nil
}

// implements the flag.Value interface
type FlagValueList []string

func (l *FlagValueList) String() string {
	return strings.Join(*l, ", ")
}

// Set is called once every time a flag is listed, so if you pass in
// --model mymodel1 --model mymodel2, then Set will be called twice
func (l *FlagValueList) Set(s string) error {
	*l = append(*l, s)

	return nil
}
