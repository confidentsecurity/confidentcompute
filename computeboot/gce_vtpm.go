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
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	cstpm "github.com/openpcc/openpcc/tpm"
)

// GCE Attestation Key NV Indices
// Sources for these constants:
// https://github.com/google/go-tpm/blob/364d5f2f78b95ba23e321373466a4d881181b85d/legacy/tpm2/tpm2.go#L1429
// github.com/google/go-tpm-tools@v0.4.4/client/handles.go
// [go-tpm-tools/client](https://pkg.go.dev/github.com/google/go-tpm-tools/client#pkg-constants)
const (
	// RSA 2048 AK.
	GceAKCertNVIndexRSA     uint32 = 0x01c10000
	GceAKTemplateNVIndexRSA uint32 = 0x01c10001
	// ECC P256 AK.
	GceAKCertNVIndexECC     uint32 = 0x01c10002
	GceAKTemplateNVIndexECC uint32 = 0x01c10003

	// RSA 2048 EK Cert.
	EKCertNVIndexRSA uint32 = 0x01c00002
	// ECC P256 EK Cert.
	EKCertNVIndexECC uint32 = 0x01c0000a
)

// When a GCE Shielded VM boots, the GCE Attestation Key (AK) does not actually exist anywhere in the TPM.
// Instead, a template for the AK is stored in an NV Index.
// In TPM2.0 key generation is a deterministic function of the template and the heirarchy seed;
// because of this property, GCE has already computed a certificate ahead of time
// for the AK that will be generated from the template.
// This certificate is available from the getSheildedInstanceIdentity API, and is additionally also stored in NVRam.
// In order to actually use the AK for anything useful, we need to create it and store it in a persistent handle.
// This function does this, it is intended to be run once on startup of the GCE Shielded VM Instance.
func MoveGCEAKToHandle(tpm transport.TPM, handle tpm2.TPMHandle) error {
	akTemplatebytes, err := cstpm.NVReadEXNoAuthorization(tpm, tpmutil.Handle(GceAKTemplateNVIndexRSA))
	if err != nil {
		return err
	}

	tb := tpm2.BytesAs2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](akTemplatebytes)

	createPrimaryCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tb,
	}

	createGCEAKResponse, err := createPrimaryCommand.Execute(tpm)
	if err != nil {
		return err
	}

	evictControlCommand := tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: createGCEAKResponse.ObjectHandle,
			Name:   createGCEAKResponse.Name,
		},
		PersistentHandle: handle,
	}

	_, err = evictControlCommand.Execute(tpm)
	if err != nil {
		return err
	}

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: createGCEAKResponse.ObjectHandle,
	}

	_, err = flushContextCmd.Execute(tpm)
	if err != nil {
		return err
	}

	return nil
}
