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
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/go-tpm/tpmutil/mssim"
	"github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
	"gopkg.in/yaml.v3"
)

const HandlesToRetrieve = 64

//revive:disable:exported
type TPMType int

//revive:enable:exported
const (
	GCE TPMType = iota
	Azure
	Simulator
	InMemorySimulator
	QEMU
)

func (t TPMType) IsSimulator() bool {
	return t == Simulator || t == InMemorySimulator || t == QEMU
}

func (t TPMType) String() string {
	return [...]string{"GCE", "Azure", "Simulator", "InMemorySimulator", "QEMU"}[t]
}

func (t TPMType) MarshalYAML() (any, error) {
	return t.String(), nil
}

func (t *TPMType) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}

	switch s {
	case "GCE":
		*t = GCE
	case "Azure":
		*t = Azure
	case "Simulator":
		*t = Simulator
	case "InMemorySimulator":
		*t = InMemorySimulator
	case "QEMU":
		*t = QEMU
	default:
		return fmt.Errorf("unknown TPMType: %s", s)
	}

	return nil
}

type TPMConfig struct {
	// PrimaryKeyHandle is the handle in the TPM for the primary key
	PrimaryKeyHandle uint32 `yaml:"primary_key_handle"`
	// ChildKeyHandle is the handle in the TPM for the child key
	ChildKeyHandle uint32 `yaml:"child_key_handle"`
	// REKCreationTicketHandle is the NV index where the
	// request encryption key creation ticket is saved.
	REKCreationTicketHandle uint32 `yaml:"rek_creation_ticket_handle"`
	// REKCreationHashHandle is the NV index where the
	// request encryption key creation has is saved.
	REKCreationHashHandle uint32 `yaml:"rek_creation_hash_handle"`
	// AttestationKeyHandle is the handle where the OEM attestation key
	// is persisted
	AttestationKeyHandle uint32 `yaml:"attestation_key_handle"`
	// TPMType is GCE, Azure, or Simulator. Unknown how this conflicts with the Simulate config
	TPMType TPMType `yaml:"tpm_type"`
	// Path to TCG Event log
	EventLogPath string `yaml:"event_log_path"`
	// SimulatorCmdAddress is the address to reach out to the simulator's command. Leave blank for default
	SimulatorCmdAddress string `yaml:"simulator_cmd_address"`
	// SimulatorPlatformAddress is the address to reach out to the simulator's command. Leave blank for default
	SimulatorPlatformAddress string `yaml:"simulator_platform_address"`
}

func NewTPMOperatorWithConfig(cfg *TPMConfig) (*TPMOperator, error) {
	o := &TPMOperator{
		primaryKeyHandle:        tpmutil.Handle(cfg.PrimaryKeyHandle),
		childKeyHandle:          tpmutil.Handle(cfg.ChildKeyHandle),
		rekCreationTicketHandle: tpmutil.Handle(cfg.REKCreationTicketHandle),
		rekCreationHashHandle:   tpmutil.Handle(cfg.REKCreationHashHandle),
		attestationKeyHandle:    tpmutil.Handle(cfg.AttestationKeyHandle),
		tpmType:                 cfg.TPMType,
	}
	switch o.tpmType {
	case Simulator:
		o.device = NewTPMSimulator(cfg.SimulatorCmdAddress, cfg.SimulatorPlatformAddress)
	case InMemorySimulator:
		o.device = NewTPMInMemorySimulator()
	case GCE, Azure, QEMU:
		o.device = NewTPMRealDevice()
	default:
		return nil, fmt.Errorf("invalid tpm type: %v", o.tpmType)
	}

	return o, nil
}

type TPMOperator struct {
	device                  TPMDevice
	primaryKeyHandle        tpmutil.Handle
	childKeyHandle          tpmutil.Handle
	rekCreationTicketHandle tpmutil.Handle
	rekCreationHashHandle   tpmutil.Handle
	attestationKeyHandle    tpmutil.Handle
	tpmType                 TPMType
}

func (t *TPMOperator) GetDevice() TPMDevice {
	return t.device
}

func (t *TPMOperator) SetupAttestationKey() error {
	thetpm, err := t.device.OpenDevice()
	if err != nil {
		return fmt.Errorf("could not connect to TPM: %w", err)
	}

	if t.tpmType == GCE {
		err = MoveGCEAKToHandle(thetpm, tpm2.TPMHandle(t.attestationKeyHandle))
		if err != nil {
			return fmt.Errorf("could not move GCE AK to handle: %w", err)
		}
	}

	if t.tpmType.IsSimulator() {
		// can only be used with fake attestation as this key won't trace back to a trusted party.
		err = setupSimulatorAttestationKey(thetpm, t.attestationKeyHandle)
		if err != nil {
			return fmt.Errorf("could not setup simulator AK for handle: %w", err)
		}
	}

	return nil
}

// Log the current state of all persisted objects in the TPM
// for debugging purposes.
func (t *TPMOperator) LogTPMState() error {
	thetpm, err := t.device.OpenDevice()
	if err != nil {
		return fmt.Errorf("could not connect to TPM: %w", err)
	}

	err = cstpm.LogTPMInfo(thetpm)
	if err != nil {
		return fmt.Errorf("could not get information from TPM: %w", err)
	}
	return nil
}

// SetupEncryptionKeys creates a primary key and a child key in the TPM.
// This method returns the CreateResponse object, see Table 12.1.2 - Table 20 — TPM2_Create Response
// in the TPM 2.0 specification (https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf).
// The create response object contains the TPMT_TK_CREATION structure, which is
// necessary for proving the provenance of this key.
// This structure cannot be retrieved after key creation and
// so must be returned from this method and persisted somewhere until CertifyCreation is called.
func (t *TPMOperator) SetupEncryptionKeys() error {
	thetpm, err := t.device.OpenDevice()

	if err != nil {
		return fmt.Errorf("could not connect to TPM: %w", err)
	}

	createPrimaryKeyResponse, err := cstpm.CreateECCPrimaryKey(thetpm)

	if err != nil {
		return fmt.Errorf("could not create primary key: %w", err)
	}

	flushPrimaryContext := tpm2.FlushContext{FlushHandle: createPrimaryKeyResponse.ObjectHandle}

	defer func() {
		if _, err := flushPrimaryContext.Execute(thetpm); err != nil {
			slog.Error("Failed to flush context", "err", err)
		}
	}()

	err = cstpm.MaybeClearPersistentHandle(thetpm, t.primaryKeyHandle)

	if err != nil {
		return fmt.Errorf("error clearing handle 0x%x: %w", t.primaryKeyHandle, err)
	}

	err = cstpm.PersistObject(
		thetpm,
		tpmutil.Handle(createPrimaryKeyResponse.ObjectHandle),
		t.primaryKeyHandle)

	if err != nil {
		return fmt.Errorf("could not persist primary key to 0x%x: %w", t.primaryKeyHandle, err)
	}

	// The golden PCR values are going to be whatever the state of the machine is at this point
	goldenPcrValues, err := cstpm.PCRRead(thetpm, evidence.AttestPCRSelection)

	if err != nil {
		return err
	}

	authorizationPolicyDigest, err := cstpm.GetTPMPCRPolicyDigest(
		thetpm,
		goldenPcrValues,
	)

	if err != nil {
		return fmt.Errorf("could not get desired policy digest: %w", err)
	}

	creationResponse, loadResponse, err := cstpm.CreateECCEncryptionKey(
		thetpm,
		createPrimaryKeyResponse.ObjectHandle,
		*authorizationPolicyDigest,
	)

	if err != nil {
		return fmt.Errorf("could not create primary key: %w", err)
	}

	flushChildContext := tpm2.FlushContext{FlushHandle: loadResponse.ObjectHandle}

	defer func() {
		if _, err := flushChildContext.Execute(thetpm); err != nil {
			slog.Error("Failed to flush context", "err", err)
		}
	}()

	err = cstpm.MaybeClearPersistentHandle(thetpm, t.childKeyHandle)

	if err != nil {
		return fmt.Errorf("error clearing handle 0x%x: %w", t.childKeyHandle, err)
	}

	err = cstpm.PersistObject(
		thetpm,
		tpmutil.Handle(loadResponse.ObjectHandle),
		t.childKeyHandle)

	if err != nil {
		return fmt.Errorf("could not persist child key to 0x%x: %w", t.childKeyHandle, err)
	}

	slog.Info("Child key handle:", "handle", fmt.Sprintf("0x%x", t.childKeyHandle))

	err = cstpm.MaybeClearNVIndex(thetpm, t.rekCreationTicketHandle)
	if err != nil {
		return fmt.Errorf("error clearing nv index 0x%x: %w", t.rekCreationTicketHandle, err)
	}

	err = cstpm.WriteToNVRamNoAuth(thetpm,
		t.rekCreationTicketHandle,
		tpm2.Marshal(creationResponse.CreationTicket))

	if err != nil {
		return fmt.Errorf("could not write creation ticket to NVRAM: %w", err)
	}

	err = cstpm.MaybeClearNVIndex(thetpm, t.rekCreationHashHandle)
	if err != nil {
		return fmt.Errorf("error clearing nv index 0x%x: %w", t.rekCreationHashHandle, err)
	}

	err = cstpm.WriteToNVRamNoAuth(thetpm,
		t.rekCreationHashHandle,
		tpm2.Marshal(creationResponse.CreationHash))

	if err != nil {
		return fmt.Errorf("could not write creation hash to NVRAM: %w", err)
	}

	return nil
}

func (t *TPMOperator) Close() error {
	if t.device != nil {
		return t.device.Close()
	}
	return nil
}

type TPMSimulator struct {
	tpmHandle               *transport.TPMCloser
	commandAddressOverride  string
	platformAddressOverride string
}

// NewTPMSimulator creates a new TPM simulator, you can override the defaults of commandAddress and platformAddress
func NewTPMSimulator(commandAddress string, platformAddress string) *TPMSimulator {
	return &TPMSimulator{
		commandAddressOverride:  commandAddress,
		platformAddressOverride: platformAddress,
	}
}

func (t *TPMSimulator) OpenDevice() (transport.TPMCloser, error) {
	if t.tpmHandle != nil {
		return *t.tpmHandle, nil
	}

	tpmDevice, err := mssim.Open(mssim.Config{
		CommandAddress:  t.commandAddressOverride,
		PlatformAddress: t.platformAddressOverride,
	})

	if err != nil {
		return nil, err
	}
	slog.Info("Using simulated TPM")
	tpm := transport.FromReadWriteCloser(tpmDevice)

	slog.Info("executing startup command TPM simulator")
	_, err = tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(tpm)
	slog.Info("startup command TPM simulator done")

	if err != nil {
		return nil, err
	}

	t.tpmHandle = &tpm

	return tpm, nil
}

func (t *TPMSimulator) Close() error {
	if t.tpmHandle != nil {
		return (*t.tpmHandle).Close()
	}
	return nil
}

type TPMInMemorySimulator struct {
	tpmHandle *transport.TPMCloser
}

func NewTPMInMemorySimulator() *TPMInMemorySimulator {
	return &TPMInMemorySimulator{}
}

func (t *TPMInMemorySimulator) OpenDevice() (transport.TPMCloser, error) {
	if t.tpmHandle != nil {
		return *t.tpmHandle, nil
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		return nil, err
	}
	slog.Info("Using TPM simulator")

	t.tpmHandle = &tpm

	return tpm, nil
}

func (t *TPMInMemorySimulator) Close() error {
	if t.tpmHandle != nil {
		return (*t.tpmHandle).Close()
	}
	return nil
}

type TPMRealDevice struct {
	tpmHandle *transport.TPMCloser
}

func NewTPMRealDevice() *TPMRealDevice {
	return &TPMRealDevice{}
}

func (t *TPMRealDevice) OpenDevice() (transport.TPMCloser, error) {
	if t.tpmHandle != nil {
		return *t.tpmHandle, nil
	}

	rwc, err := tpmutil.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return nil, err
	}
	slog.Info("Using real TPM")
	tpm := transport.FromReadWriteCloser(rwc)

	t.tpmHandle = &tpm

	return tpm, nil
}

func (t *TPMRealDevice) Close() error {
	if t.tpmHandle != nil {
		return (*t.tpmHandle).Close()
	}
	return nil
}

type TPMDevice interface {
	OpenDevice() (transport.TPMCloser, error)
	Close() error
}
