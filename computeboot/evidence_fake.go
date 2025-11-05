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

package computeboot

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/attestation/attest"
	ev "github.com/openpcc/openpcc/attestation/evidence"
)

// collectEvidence collects fake evidence. It only uses some of the TPM evidence.
func collectEvidence(cfg *AttestationConfig, tpmCfg *TPMConfig, tpmDevice TPMDevice, _ GPUManager, _ *TransparencyConfig) (ev.SignedEvidenceList, error) {
	// collect fake evidence if configured for it.
	slog.Info("INSECURE WARNING: using fake attestation, not for production use!")

	result := ev.SignedEvidenceList{}

	tpm, err := tpmDevice.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to open tpm device: %w", err)
	}

	// Piece 1: TPMTPublic of the AK.
	akTPMPT := attest.NewTPMTPublicAttestor(tpm, tpmutil.Handle(tpmCfg.AttestationKeyHandle))
	akTPMPTEvidence, err := akTPMPT.CreateSignedEvidence(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to attest ak: %w", err)
	}
	// make unspecified so it doesn't accidentally get interpreted as the REK.
	akTPMPTEvidence.Type = ev.EvidenceTypeUnspecified
	result = append(result, akTPMPTEvidence)

	// Piece 2: REK Creation.
	certifyREKAttestor := attest.NewCertifyREKCreationAttestor(
		tpm,
		tpmutil.Handle(tpmCfg.AttestationKeyHandle),
		tpmutil.Handle(tpmCfg.ChildKeyHandle),
		tpmutil.Handle(tpmCfg.REKCreationTicketHandle),
		tpmutil.Handle(tpmCfg.REKCreationHashHandle),
	)

	certifyREKSignedEvidence, err := certifyREKAttestor.CreateSignedEvidence(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to certify rek: %w", err)
	}
	result = append(result, certifyREKSignedEvidence)

	// Piece 3: TPM Quote.
	tpmQuoteAttestor := attest.NewTPMQuoteAttestor(tpm, tpmutil.Handle(tpmCfg.AttestationKeyHandle))
	tpmQuoteEvidence, err := tpmQuoteAttestor.CreateSignedEvidence(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to attest tpmquote: %w", err)
	}
	result = append(result, tpmQuoteEvidence)

	// Piece 4: TPMTPublic of the REK.
	rekTMPT := attest.NewTPMTPublicAttestor(tpm, tpmutil.Handle(tpmCfg.ChildKeyHandle))
	rekTPMPTEvidence, err := rekTMPT.CreateSignedEvidence(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to attest rek: %w", err)
	}
	result = append(result, rekTPMPTEvidence)

	// Piece 5: Fake attestation.
	fakeAttestor := attest.NewFakeAttestor([]byte(cfg.FakeSecret))
	fakeEvidence, err := fakeAttestor.CreateSignedEvidence(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create fake evidence: %w", err)
	}
	result = append(result, fakeEvidence)

	return result, nil
}
