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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/confidentsecurity/twoway"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/go-tpm/tpmutil/mssim"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/otel/otelutil"
	cstpm "github.com/openpcc/openpcc/tpm"
	tpmhpke "github.com/openpcc/openpcc/tpm/hpke"
	"go.opentelemetry.io/otel/codes"
)

func newTPMHPKEReceiver(ctx context.Context, config TPMConfig, info []byte) (*tpmhpke.Receiver, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "computeworker.newTPMHPKEReceiver")
	defer span.End()

	kemID, _, _ := tpmhpke.SuiteParams()
	nodePubKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(config.PublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	if config.KeyHandle > math.MaxUint32 {
		return nil, otelutil.Errorf(span, "key handle value %d exceeds maximum value for TPM handle", config.KeyHandle)
	}

	goldenPCRValues := map[uint32][]byte{}
	for _, pcr := range evidence.AttestPCRSelection {
		if pcr > math.MaxUint32 {
			return nil, fmt.Errorf("unexpected pcr value %d, does not fit in uint32", pcr)
		}

		val, ok := config.PCRValues[uint32(pcr)]
		if !ok {
			return nil, fmt.Errorf("config is missing pcr value %d", pcr)
		}
		goldenPCRValues[uint32(pcr)] = val
	}

	slog.Info("Creating TPM receiver with golden PCR values", "goldenPcrValues", goldenPCRValues)

	// Because the compute worker only requires a single ECDZGen operation, we try to minimize
	// the time spent using the TPM. We do the following once the receiver makes the ECDZGen call:
	// 1. Open TPM connection.
	// 2. Create a session.
	// 3. Call the operation.
	// 4. Cleanup.
	ecdhZGenFunc := func(keyInfo *tpmhpke.ECDHZGenKeyInfo, pubPoint tpm2.TPM2BECCPoint) ([]byte, error) {
		// 1. Open TPM connection.
		tpm, err := openTPM(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("failed to open tpm: %w", err)
		}
		defer func() {
			_, span := otelutil.Tracer.Start(ctx, "computeworker.TPMHPKE.closeTPM")
			defer span.End()
			err = errors.Join(err, tpm.Close())
		}()

		// 2. Begin TPM session.
		_, sessionSpan := otelutil.Tracer.Start(ctx, "computeworker.TPMHPKE.beginSession")
		sess, cleanup, err := cstpm.PCRPolicySession(tpm, goldenPCRValues)
		if err != nil {
			sessionSpan.End()
			return nil, fmt.Errorf("failed to create tpm session: %w", err)
		}
		sessionSpan.End()

		defer func() {
			_, span := otelutil.Tracer.Start(ctx, "computeworker.TPMHPKE.cleanupSession")
			defer span.End()
			err = errors.Join(err, cleanup())
		}()

		// 3. ECDHZgen
		_, ecdhZGenSpan := otelutil.Tracer.Start(ctx, "computeworker.TPMHPKE.ecdhZGen")
		b, err := tpmhpke.ECDHZGen(tpm, sess, keyInfo, pubPoint)
		ecdhZGenSpan.End()
		return b, err
	}

	span.SetStatus(codes.Ok, "")

	return tpmhpke.NewReceiver(
		nodePubKey,
		info,
		&tpmhpke.ECDHZGenKeyInfo{
			PrivKeyHandle: tpmutil.Handle(config.KeyHandle),
			PublicName: tpm2.TPM2BName{
				Buffer: config.PublicKeyNameBytes,
			},
		},
		ecdhZGenFunc,
	), nil
}

func openTPM(ctx context.Context, config TPMConfig) (transport.TPMCloser, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "computeworker.TPMHPKE.openTPM")
	defer span.End()
	if config.Simulate {
		tpmDevice, err := mssim.Open(mssim.Config{
			CommandAddress:  config.SimulatorCmdAddress,
			PlatformAddress: config.SimulatorPlatformAddress,
		})
		if err != nil {
			return nil, otelutil.Errorf(span, "open tpm device: %w", err)
		}

		slog.InfoContext(ctx, "Using simulated TPM")
		tpm := transport.FromReadWriteCloser(tpmDevice)

		slog.InfoContext(ctx, "executing startup command TPM simulator")
		if _, err := (tpm2.Startup{StartupType: tpm2.TPMSUClear}.Execute(tpm)); err != nil {
			// This initialization error can occur under heavy load and indicates
			// that the TPM is already initialized so we can ignore it and use the TPM.
			if !strings.Contains(err.Error(), "TPM_RC_INITIALIZE") {
				return nil, otelutil.Errorf(span, "tpm startup: %w", err)
			}
			slog.Warn("tpm startup error", "err", err)
		}
		slog.InfoContext(ctx, "startup command TPM simulator done", "err", err)
		return tpm, nil
	}

	slog.InfoContext(ctx, "Opening Real TPM")
	rwc, err := tpmutil.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return nil, fmt.Errorf("failed to open tpm: %w", err)
	}
	slog.InfoContext(ctx, "Using real TPM", "err", err)
	return transport.FromReadWriteCloser(rwc), nil
}

// tpmSuiteAdapter implements twoway.HPKESuite so we can inject our TPM based HPKE receiver
// into twoway.
type tpmSuiteAdapter struct {
	ctx    context.Context
	config TPMConfig
	kemID  hpke.KEM
	kdfID  hpke.KDF
	aeadID hpke.AEAD
}

func (*tpmSuiteAdapter) NewSender(_ kem.PublicKey, _ []byte) (twoway.HPKESender, error) {
	panic("not implemented")
}

func (s *tpmSuiteAdapter) NewReceiver(_ kem.PrivateKey, info []byte) (twoway.HPKEReceiver, error) {
	receiver, err := newTPMHPKEReceiver(s.ctx, s.config, info)
	if err != nil {
		return nil, err
	}
	return &tpmReceiverAdapter{
		receiver: receiver,
	}, nil
}

func (s *tpmSuiteAdapter) Params() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return s.kemID, s.kdfID, s.aeadID
}

// tpmReceiverAdapter implements twoway.HPKEReceiver so we can inject our TPM based HPKE Receiver
// into twoway.
type tpmReceiverAdapter struct {
	receiver *tpmhpke.Receiver
}

func (r *tpmReceiverAdapter) Setup(enc []byte) (twoway.HPKEOpener, error) {
	return r.receiver.Setup(enc)
}
