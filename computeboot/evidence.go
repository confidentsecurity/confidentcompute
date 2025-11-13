//go:build !include_fake_attestation

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
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/openpcc/openpcc/attestation/attest"
	ev "github.com/openpcc/openpcc/attestation/evidence"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/verify/trust"
	"github.com/google/go-tpm/tpmutil"
)

func collectEvidence(_ *AttestationConfig, tpmCfg *TPMConfig, tpmDevice TPMDevice, gpuManager GPUManager, tlogCfg *TransparencyConfig) (ev.SignedEvidenceList, error) {
	result := ev.SignedEvidenceList{}
	var teeType ev.TEEType

	teeType, err := attest.GetTEEType()
	if err != nil {
		return nil, err
	}

	tpm, err := tpmDevice.OpenDevice()
	if err != nil {
		return nil, err
	}

	switch teeType {
	case ev.Tdx:
		switch tpmCfg.TPMType {
		case GCE:
			teeAttestor, err := attest.NewTDXTEEAttestor(
				make([]byte, 64),
			)

			if err != nil {
				return nil, err
			}

			teeEvidencePiece, err := teeAttestor.CreateSignedEvidence(context.Background())
			if err != nil {
				return nil, fmt.Errorf("gce tdx create evidence failed: %w", err)
			}
			result = append(result, teeEvidencePiece)

			collateralEvidence, err := getTDXCollateral(teeEvidencePiece)

			if err != nil {
				return nil, fmt.Errorf("gce tdx collateral failed: %w", err)
			}

			result = append(result, collateralEvidence)
		case Azure:
			teeAttestor := attest.NewAzureTDXTEEAttestorWithQuoteService(
				tpm,
				make([]byte, 64),
				&attest.HTTPMetadataQuoteService{},
			)

			teeEvidencePiece, err := teeAttestor.CreateSignedEvidence(context.Background())

			if err != nil {
				return nil, fmt.Errorf("azure tdx create evidence failed: %w", err)
			}

			result = append(result, teeEvidencePiece)

			collateralEvidence, err := getTDXCollateral(teeEvidencePiece)

			if err != nil {
				return nil, fmt.Errorf("azure tdx collateral failed: %w", err)
			}

			result = append(result, collateralEvidence)
		case Simulator, InMemorySimulator, QEMU:
			// these do nothing, but we have to have this comment for revive:useless-fallthrough
			fallthrough
		default:
			return nil, fmt.Errorf("unsupported TPM type for procedure: %s", tpmCfg.TPMType)
		}
	case ev.SevSnp:
		switch tpmCfg.TPMType {
		case GCE:
			teeAttestor, err := attest.NewSEVSNPTEEAttestor(
				make([]byte, 64),
			)

			if err != nil {
				return nil, err
			}

			teeEvidencePiece, err := teeAttestor.CreateSignedEvidence(context.Background())

			if err != nil {
				return nil, fmt.Errorf("gce sevsnp create evidence failed: %w", err)
			}
			result = append(result, teeEvidencePiece)
		case Azure:
			teeAttestor := attest.NewAzureSEVSNPTEEAttestor(
				tpm,
				make([]byte, 64),
			)

			teeEvidencePiece, err := teeAttestor.CreateSignedEvidence(context.Background())

			if err != nil {
				return nil, fmt.Errorf("azure sevsnp create evidence failed: %w", err)
			}

			result = append(result, teeEvidencePiece)
		case QEMU:
			teeAttestor, err := attest.NewBareMetalSEVSNPTEEAttestor(make([]byte, 64))
			if err != nil {
				return nil, err
			}

			teeEvidencePiece, err := teeAttestor.CreateSignedEvidence(context.Background())

			if err != nil {
				return nil, fmt.Errorf("qemu sevsnp create evidence failed: %w", err)
			}

			result = append(result, teeEvidencePiece)
		case Simulator, InMemorySimulator:
			// these two do nothing, but we have to have this comment for revive:useless-fallthrough
			fallthrough
		default:
			return nil, fmt.Errorf("unsupported TPM type for procedure: %s", tpmCfg.TPMType)
		}
	case ev.NoTEE:
		return nil, errors.New("not running in a TEE")
	default:
		return nil, fmt.Errorf("unsupported TEE type: %d", teeType)
	}

	switch tpmCfg.TPMType {
	case GCE:
		certifyAKAttestor := attest.NewGceAkCertificateAttestor(tpm)

		akCertificateSignedEvidence, err := certifyAKAttestor.CreateSignedEvidence(context.Background())
		if err != nil {
			return nil, fmt.Errorf("gce ak certificate failed: %w", err)
		}

		akCert, err := x509.ParseCertificate(akCertificateSignedEvidence.Data)

		if err != nil {
			return nil, fmt.Errorf("parse ak certificate failed: %w", err)
		}

		certifyAKIntermediateAttestor := attest.NewGceAkIntermediateCertificateAttestor(*akCert)

		intermediateAKCertificateSignedEvidence, err := certifyAKIntermediateAttestor.CreateSignedEvidence(context.Background())

		if err != nil {
			return nil, fmt.Errorf("certify ak certificate failed: %w", err)
		}

		result = append(result, akCertificateSignedEvidence)
		result = append(result, intermediateAKCertificateSignedEvidence)
	case Azure:
		certifyAKAttestor := attest.NewAzureAkCertificateAttestor(tpm)
		akCertificateSignedEvidence, err := certifyAKAttestor.CreateSignedEvidence(context.Background())
		if err != nil {
			return nil, fmt.Errorf("azure ak certificate evidence failed: %w", err)
		}
		result = append(result, akCertificateSignedEvidence)
	case QEMU:
		// instead of attesting the AK certificate, we include the AK TPMT public area in the evidence,
		// and verify that it matches the vTPM TPMT public area in the SEV-SNP services manifest
		tpmtAttestor := attest.NewTPMTPublicAttestor(tpm, tpmutil.Handle(tpmCfg.AttestationKeyHandle), ev.AkTPMTPublic)
		akTPMPTEvidence, err := tpmtAttestor.CreateSignedEvidence(context.Background())
		if err != nil {
			return nil, fmt.Errorf("tpmt create signed evidence failed: %w", err)
		}
		result = append(result, akTPMPTEvidence)
	case Simulator, InMemorySimulator:
		// these two do nothing, but we have to have this comment for revive:useless-fallthrough
		fallthrough
	default:
		return nil, fmt.Errorf("unsupported TPM type for procedure: %s", tpmCfg.TPMType)
	}

	nvidiaEvidence, err := gpuManager.GetAttestationEvidenceList(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation evidence: %w", err)
	}

	certifyREKAttestor := attest.NewCertifyREKCreationAttestor(
		tpm,
		tpmutil.Handle(tpmCfg.AttestationKeyHandle),
		tpmutil.Handle(tpmCfg.ChildKeyHandle),
		tpmutil.Handle(tpmCfg.REKCreationTicketHandle),
		tpmutil.Handle(tpmCfg.REKCreationHashHandle),
	)

	certifyREKSignedEvidence, err := certifyREKAttestor.CreateSignedEvidence(context.Background())
	if err != nil {
		return nil, fmt.Errorf("certify REK failed: %w", err)
	}
	result = append(result, certifyREKSignedEvidence)

	tpmtAttestor := attest.NewTPMTPublicAttestor(tpm, tpmutil.Handle(tpmCfg.ChildKeyHandle), ev.TpmtPublic)
	tpmtSignedEvidence, err := tpmtAttestor.CreateSignedEvidence(context.Background())
	if err != nil {
		return nil, fmt.Errorf("tpmt create signed evidence failed: %w", err)
	}
	result = append(result, tpmtSignedEvidence)

	if len(nvidiaEvidence) > 0 {
		result = append(result, nvidiaEvidence...)
	}

	if tlogCfg == nil || tlogCfg.ImageSigstoreBundle == "" {
		return nil, errors.New("no image sigstore bundle provided")
	}

	decodedBundle, err := base64.StdEncoding.DecodeString(tlogCfg.ImageSigstoreBundle)

	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode image sigstore bundle: %w", err)
	}

	sigstoreBundle := &ev.SignedEvidencePiece{
		Type:      ev.ImageSigstoreBundle,
		Data:      decodedBundle,
		Signature: []byte{},
	}
	result = append(result, sigstoreBundle)

	tpmQuoteAttestor := attest.NewTPMQuoteAttestor(tpm, tpmutil.Handle(tpmCfg.AttestationKeyHandle))

	tpmQuoteEvidence, err := tpmQuoteAttestor.CreateSignedEvidence(context.Background())
	if err != nil {
		return nil, fmt.Errorf("tpm quote failed: %w", err)
	}

	tpmQuoteProto := ev.TPMQuoteAttestation{}

	err = tpmQuoteProto.UnmarshalBinary(tpmQuoteEvidence.Data)

	if err != nil {
		return nil, fmt.Errorf("unmarshalling tpm quote failed: %w", err)
	}

	file, err := os.Open(tpmCfg.EventLogPath)
	if err != nil {
		return nil, fmt.Errorf("error opening event log: %s", tpmCfg.EventLogPath)
	}
	defer file.Close()

	eventLogAttestor, err := attest.NewEventLogAttestor(file, tpmQuoteProto.PCRValues.ToMRs())
	if err != nil {
		return nil, fmt.Errorf("event log attestator construction failed: %w", err)
	}

	eventLogEvidence, err := eventLogAttestor.CreateSignedEvidence(context.Background())
	if err != nil {
		return nil, fmt.Errorf("event log attestator create signed evidence failed: %w", err)
	}
	result = append(result, eventLogEvidence)

	result = append(result, tpmQuoteEvidence)
	return result, nil
}

func getTDXCollateral(teeEvidencePiece *ev.SignedEvidencePiece) (*ev.SignedEvidencePiece, error) {
	quote, err := abi.QuoteToProto(teeEvidencePiece.Data)

	if err != nil {
		return nil, err
	}

	quoteV4, ok := quote.(*pb.QuoteV4)

	if !ok {
		return nil, errors.New("failed to cast quote")
	}

	chain, err := attest.ExtractChainFromQuoteV4(quoteV4)
	if err != nil {
		return nil, err
	}

	collateralAttestor, err := attest.NewTDXCollateralAttestor(
		&trust.SimpleHTTPSGetter{},
		chain.PCKCertificate,
	)
	if err != nil {
		return nil, fmt.Errorf("tdx create collateral failed: %w", err)
	}

	collateralEvidence, err := collateralAttestor.CreateSignedEvidence(context.Background())

	if err != nil {
		return nil, fmt.Errorf("tdx create collateral failed: %w", err)
	}

	return collateralEvidence, nil
}
