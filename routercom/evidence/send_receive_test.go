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

package evidence_test

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/confidentsecurity/confidentcompute/routercom/evidence"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/stretchr/testify/require"
)

func TestSendReceiveTest(t *testing.T) {
	t.Skip("FLAKE")
	// GitHub test failure unrelated to changes:
	// --- FAIL: TestSendReceiveTest (0.00s)
	// --- FAIL: TestSendReceiveTest/ok,_empty_evidence (0.00s)
	//     send_receive_test.go:126:
	//         	Error Trace:	/home/runner/work/T/T/domain/routercom/evidence/send_receive_test.go:126
	//         	            				/opt/hostedtoolcache/go/1.24.2/x64/src/runtime/asm_amd64.s:1700
	//         	Error:      	Received unexpected error:
	//         	            	failed to send evidence data: write unix @->/tmp/TestSendReceiveTestok,_empty_evidence3993294250/001/test.sock: write: broken pipe
	//         	Test:       	TestSendReceiveTest/ok,_empty_evidence
	tests := map[string]struct {
		evidence      ev.SignedEvidenceList
		receiverSleep time.Duration
		senderSleep   time.Duration
	}{
		"ok, empty evidence": {
			evidence: ev.SignedEvidenceList{},
		},
		"ok, single piece": {
			evidence: ev.SignedEvidenceList{
				&ev.SignedEvidencePiece{
					Type:      ev.SevSnpReport,
					Data:      []byte("test-data"),
					Signature: []byte("test-signature"),
				},
			},
		},
		"ok, multiple pieces": {
			evidence: ev.SignedEvidenceList{
				&ev.SignedEvidencePiece{
					Type:      ev.SevSnpReport,
					Data:      []byte("test-data-1"),
					Signature: []byte("test-signature-1"),
				},
				&ev.SignedEvidencePiece{
					Type:      ev.SevSnpReport,
					Data:      []byte("test-data-2"),
					Signature: []byte("test-signature-2"),
				},
				&ev.SignedEvidencePiece{
					Type:      ev.SevSnpReport,
					Data:      []byte("test-data-3"),
					Signature: []byte("test-signature-3"),
				},
			},
		},
		"ok, sender available first": {
			evidence: ev.SignedEvidenceList{
				&ev.SignedEvidencePiece{
					Type:      ev.SevSnpReport,
					Data:      []byte("test-data"),
					Signature: []byte("test-signature"),
				},
			},
			receiverSleep: time.Millisecond * 30,
		},
		"ok, receiver available first": {
			evidence: ev.SignedEvidenceList{
				&ev.SignedEvidencePiece{
					Type:      ev.SevSnpReport,
					Data:      []byte("test-data"),
					Signature: []byte("test-signature"),
				},
			},
			senderSleep: time.Millisecond * 30,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			socket := newSocketPath(t)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()

				cfg := evidence.DefaultReceiverConfig()
				cfg.Socket = socket
				cfg.Timeout = time.Second

				time.Sleep(tc.receiverSleep)

				got, err := evidence.Receive(t.Context(), cfg)
				require.NoError(t, err)
				require.Equal(t, tc.evidence, got)
			}()

			go func() {
				defer wg.Done()

				cfg := evidence.DefaultSenderConfig()
				cfg.Socket = socket
				cfg.MaxRetries = 10
				cfg.RetryInterval = time.Millisecond * 10

				time.Sleep(tc.senderSleep)

				err := evidence.Send(t.Context(), cfg, tc.evidence)
				require.NoError(t, err)
			}()

			wg.Wait()
		})
	}
}

func TestSend(t *testing.T) {
	t.Run("fail, times out", func(t *testing.T) {
		t.Parallel()

		socket := newSocketPath(t)

		cfg := evidence.DefaultSenderConfig()
		cfg.Socket = socket
		cfg.MaxRetries = 10
		cfg.RetryInterval = time.Millisecond * 10

		err := evidence.Send(t.Context(), cfg, ev.SignedEvidenceList{})
		require.Error(t, err)
	})

	t.Run("fail, context cancelled", func(t *testing.T) {
		t.Parallel()

		socket := newSocketPath(t)

		cfg := evidence.DefaultSenderConfig()
		cfg.Socket = socket
		cfg.MaxRetries = 10
		cfg.RetryInterval = time.Millisecond * 10

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		err := evidence.Send(ctx, cfg, ev.SignedEvidenceList{})
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestReceive(t *testing.T) {
	t.Run("fail, times out", func(t *testing.T) {
		t.Parallel()

		socket := newSocketPath(t)

		cfg := evidence.DefaultReceiverConfig()
		cfg.Socket = socket
		cfg.Timeout = time.Second

		_, err := evidence.Receive(t.Context(), cfg)
		require.Error(t, err)
	})

	t.Run("fail, context cancelled", func(t *testing.T) {
		t.Parallel()

		socket := newSocketPath(t)

		cfg := evidence.DefaultReceiverConfig()
		cfg.Socket = socket
		cfg.Timeout = time.Second

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := evidence.Receive(ctx, cfg)
		require.ErrorIs(t, err, context.Canceled)
	})

	invalidDataTests := map[string]func([]byte) []byte{
		"fail, invalid payload length": func(b []byte) []byte {
			return b[:3]
		},
		"fail, excessive max length": func(b []byte) []byte {
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, (1024*1024)+1)
			copy(b[:4], lenBuf)
			return b
		},
		"fail, non protobuf payload": func(b []byte) []byte {
			data := []byte("abcdefg")
			copy(b[4:], data)
			return b
		},
		"fail, payload length shorter than message length": func(b []byte) []byte {
			return b[:len(b)-1]
		},
	}

	for name, tc := range invalidDataTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			socket := newSocketPath(t)

			sel := ev.SignedEvidenceList{
				&ev.SignedEvidencePiece{
					Type:      ev.SevSnpReport,
					Data:      []byte("test-data"),
					Signature: []byte("test-signature"),
				},
			}
			payload, err := sel.MarshalBinary()
			require.NoError(t, err)

			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
			data := append(lenBuf, payload...)
			data = tc(data)

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()

				cfg := evidence.DefaultReceiverConfig()
				cfg.Socket = socket
				cfg.Timeout = time.Second

				_, err := evidence.Receive(t.Context(), cfg)
				require.Error(t, err)
			}()

			go func() {
				defer wg.Done()

				// wait for receiver to be up.
				time.Sleep(10 * time.Millisecond)

				// write message
				conn, err := net.Dial("unix", socket)
				require.NoError(t, err)
				_, err = conn.Write(data)
				require.NoError(t, err)

				defer conn.Close()
			}()

			wg.Wait()
		})
	}
}

func newSocketPath(t *testing.T) string {
	// Use /tmp directly to avoid macOS socket path length limits (104 chars)
	// t.TempDir() creates paths like /var/folders/.../T/TestName.../... which are too long
	tmpDir, err := os.MkdirTemp("/tmp", "test-sock-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		err := os.RemoveAll(tmpDir)
		require.NoError(t, err)
	})

	return filepath.Join(tmpDir, "test.sock")
}
