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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/stretchr/testify/require"
)

func TestMoveGCEAKToHande_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	/*
		Example of what the AK template looks like on a real GCE TPM:
			$ sudo tpm2_nvread 0x01c10001 > AK_TPMT.bin
			$ tpm2_print -t TPMT_PUBLIC AK_TPMT.bin
				name-alg:
				  value: sha256
				  raw: 0xb
				attributes:
				  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign
				  raw: 0x50072
				type:
				  value: rsa
				  raw: 0x1
				exponent: 65537
				bits: 2048
				scheme:
				  value: rsassa
				  raw: 0x14
				scheme-halg:
				  value: sha256
				  raw: 0xb
				sym-alg:
				  value: null
				  raw: 0x10
				sym-mode:
				  value: (null)
				  raw: 0x0
				sym-keybits: 0
				rsa: ... bits of RSA pubkey ...
	*/
	// Make a test RSA Key.
	testRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Generating RSA key: %v", err)
	}

	fakeAKTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			// Note: We set this to false so that we can actually test signing something.
			// This being set to true restricts using the key to sign arbitrary data.
			Restricted:  false,
			SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgNull,
				},
				KeyBits:  2048,
				Exponent: 65537,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: testRSAKey.N.Bytes(),
			},
		),
	}

	fakeAKTemplateBytes := tpm2.Marshal(fakeAKTemplate)

	def := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte(""),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: tpm2.TPMHandle(GceAKTemplateNVIndexRSA),
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
				},
				DataSize: uint16(len(fakeAKTemplateBytes)),
			}),
	}
	if _, err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	pub, err := def.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	nvName, err := tpm2.NVName(pub)
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	prewrite := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: tpm2.Marshal(fakeAKTemplate),
		},
		Offset: 0,
	}
	_, err = prewrite.Execute(thetpm)

	if err != nil {
		t.Fatalf("Writing template to NV index: %v", err)
	}

	testPersistentHandle := tpm2.TPMHandle(0x81000000)

	err = MoveGCEAKToHandle(thetpm, testPersistentHandle)
	require.NoError(t, err)

	readPublic := tpm2.ReadPublic{
		ObjectHandle: testPersistentHandle,
	}

	readPublicResponse, err := readPublic.Execute(thetpm)
	require.NoError(t, err)

	// Check that the AK is now in the persistent handle by signing some data.
	digest := sha256.Sum256([]byte("confidentsecurity"))

	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: testPersistentHandle,
			Name:   readPublicResponse.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	// Success, we can sign something
	_, err = sign.Execute(thetpm)
	require.NoError(t, err)
}
