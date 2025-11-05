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

package evidence

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	ev "github.com/openpcc/openpcc/attestation/evidence"
)

const (
	DefaultSocket = "/tmp/router.sock"
	maxPayloadLen = 1024 * 1024 // 1MB
)

// ReceiveConfig is config for how router com gets evidence from compute_boot
type ReceiveConfig struct {
	// Socket is the socket to receive evidence on
	Socket string `yaml:"socket"`
	// Timeout is how long to wait for evidence
	Timeout time.Duration `yaml:"timeout"`
}

func DefaultReceiverConfig() ReceiveConfig {
	return ReceiveConfig{
		Socket:  DefaultSocket,
		Timeout: 60 * time.Second,
	}
}

func Receive(ctx context.Context, cfg ReceiveConfig) (ev.SignedEvidenceList, error) {
	if cfg.Socket == "" {
		return nil, errors.New("missing socket")
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	// Create and listen on Unix socket
	if err := os.RemoveAll(cfg.Socket); err != nil {
		return nil, fmt.Errorf("failed to remove existing socket: %w", err)
	}

	listener, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on socket: %w", err)
	}
	// not deferring the listener.Close() as this will be triggered via defer cancel().

	go func() {
		// close the listener when the context is done.
		<-ctx.Done()
		if err := listener.Close(); err != nil {
			slog.ErrorContext(ctx, "failed to close listener", "error", err)
		}
	}()

	conn, err := listener.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) && ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return ev.SignedEvidenceList{}, fmt.Errorf("failed to accept connection: %w", err)
	}
	defer conn.Close()

	// Read message length (4 bytes)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return ev.SignedEvidenceList{}, fmt.Errorf("failed to read message length: %w", err)
	}

	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > maxPayloadLen {
		return ev.SignedEvidenceList{}, fmt.Errorf("payload length %d over maximum %d", payloadLen, maxPayloadLen)
	}

	data := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return ev.SignedEvidenceList{}, fmt.Errorf("failed to read message: %w", err)
	}

	// Unmarshal protobuf message
	var evidence ev.SignedEvidenceList
	err = evidence.UnmarshalBinary(data)
	if err != nil {
		return ev.SignedEvidenceList{}, fmt.Errorf("failed to unmarshal signed evidence list: %w", err)
	}

	return evidence, nil
}
