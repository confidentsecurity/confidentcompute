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
	"fmt"
	"math"
	"net"
	"time"

	"github.com/cenkalti/backoff/v4"
	ev "github.com/openpcc/openpcc/attestation/evidence"
)

type SenderConfig struct {
	// Socket is the socket to send the attestation data over on
	Socket string `yaml:"socket"`
	// MaxRetries are how many times to try and send the data over to router_com
	MaxRetries int `yaml:"max_retries"`
	// RetryInterval is how long to wait between retries
	RetryInterval time.Duration `yaml:"retry_interval"`
}

func DefaultSenderConfig() SenderConfig {
	return SenderConfig{
		Socket:        DefaultSocket,
		MaxRetries:    60,
		RetryInterval: time.Second * 1,
	}
}

func Send(ctx context.Context, cfg SenderConfig, evidence ev.SignedEvidenceList) error {
	data, err := evidence.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal evidence to binary: %w", err)
	}

	conn, err := connect(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	dataLen := len(data)

	// fixes the following linter error
	// G115: integer overflow conversion int -> uint32 (gosec)
	if dataLen > int(math.MaxUint32) {
		return fmt.Errorf("data length exceeds maximum uint32 value: %d", dataLen)
	}

	lenBuf := make([]byte, 4)

	binary.BigEndian.PutUint32(lenBuf, uint32(dataLen))

	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to send message length: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to send evidence data: %w", err)
	}

	return nil
}

func connect(ctx context.Context, cfg SenderConfig) (net.Conn, error) {
	var conn net.Conn
	if cfg.MaxRetries < 0 {
		return nil, fmt.Errorf("invalid max retries: %d", cfg.MaxRetries)
	}
	backoffCfg := backoff.WithContext(backoff.WithMaxRetries(backoff.NewConstantBackOff(cfg.RetryInterval), uint64(cfg.MaxRetries)), ctx)
	err := backoff.Retry(func() error {
		c, dialErr := net.Dial("unix", cfg.Socket)
		if dialErr != nil {
			return dialErr
		}
		conn = c
		return nil
	}, backoffCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to receiver after %d attempts: %w", cfg.MaxRetries, err)
	}

	return conn, nil
}
