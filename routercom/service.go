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
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-tpm/tpm2"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/otel/otelutil"
	tpmhpke "github.com/openpcc/openpcc/tpm/hpke"
)

type Service struct {
	config   *Config
	handler  http.Handler
	evidence ev.SignedEvidenceList

	commandsWG       *sync.WaitGroup
	base64PubKey     string
	base64PubKeyName string
	base64PCRValues  string
}

func New(cfg *Config, evidence ev.SignedEvidenceList) (*Service, error) {
	s := &Service{
		config:     cfg,
		evidence:   evidence,
		commandsWG: &sync.WaitGroup{},
	}

	// extract data required by the compute worker from the evidence.
	for _, item := range s.evidence {
		switch item.Type { //nolint:exhaustive
		case ev.TpmtPublic:
			b, err := tpmptToPubKeyBytes(item)
			if err != nil {
				return nil, fmt.Errorf("failed to extract rek public key from evidence: %w", err)
			}

			s.base64PubKey = base64.StdEncoding.EncodeToString(b)
			s.base64PubKeyName = base64.StdEncoding.EncodeToString(item.Signature)
			continue
		case ev.TpmQuote:
			quotePB := ev.TPMQuoteAttestation{}
			err := quotePB.UnmarshalBinary(item.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal tpm quote to protobuf: %w", err)
			}

			b, err := quotePB.PCRValues.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marhsal pcr values to binary: %w", err)
			}

			s.base64PCRValues = base64.StdEncoding.EncodeToString(b)
			continue
		case ev.NvidiaCCIntermediateCertificate, ev.NvidiaSwitchIntermediateCertificate:
			// Extract the intermediate certificate to identify its expiry date.
			cert, err := x509.ParseCertificate(item.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse nvidia intermediate certificate: %w", err)
			}

			slog.Info("Nvidia intermediate certificate provided in evidence",
				"subject", cert.Subject.String(),
				"not_before", cert.NotBefore,
				"not_after", cert.NotAfter)

			// Schedule router_com to shutdown when the certificate expires.
			// Until we have more data around JWT expirations, we will force compute
			// nodes to be recreated when the intermediate certificate expires
			// (since that breaks the attestation package provided to the client).
			go func() {
				// Shut down 1 minute before the certificate expires.
				// This gives the node time to notify the router that it is shutting down,
				// and finish serving any in-flight requests.
				expirationTime := cert.NotAfter.Add(-1 * time.Minute)
				slog.Info("Waiting until certificate expiry to force a shutdown",
					"not_after", cert.NotAfter,
					"expiration_time", expirationTime)

				time.Sleep(time.Until(expirationTime))
				pid := os.Getpid()
				// Send SIGTERM to ourselves to trigger a graceful shutdown.
				err := syscall.Kill(pid, syscall.SIGTERM)
				if err != nil {
					// This really shouldnt happen...
					panic("failed to kill router_com: " + err.Error())
				}
			}()
		default:
		}
	}

	if len(s.base64PubKey) == 0 {
		return nil, errors.New("failed to find public key in evidence")
	}

	if len(s.base64PubKeyName) == 0 {
		return nil, errors.New("failed to find public key name in evidence")
	}

	if len(s.base64PCRValues) == 0 {
		return nil, errors.New("failed to find pcr values in evidence")
	}

	setupHandlers(s)

	return s, nil
}

func setupHandlers(s *Service) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /_health", s.healthHandler)
	otelutil.ServeMuxHandleFunc(mux, "POST /", s.generateHandler)

	s.handler = mux
}

func (s *Service) Evidence() ev.SignedEvidenceList {
	return s.evidence
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Confsec-Ping") == "routercom" {
		_, err := w.Write([]byte("routercom"))
		if err != nil {
			slog.Error("failed to write ping response", "err", err)
		}
		return
	}

	s.handler.ServeHTTP(w, r)
}

func (s *Service) Close() error {
	s.commandsWG.Wait()
	return nil
}

func tpmptToPubKeyBytes(evidence *ev.SignedEvidencePiece) ([]byte, error) {
	tpmtPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](evidence.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tpmpt public key: %w", err)
	}

	kemPub, err := tpmhpke.Pub(tpmtPub)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tpmpt public key to hpke public key: %w", err)
	}

	b, err := kemPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to bytes: %w", err)
	}

	return b, nil
}
