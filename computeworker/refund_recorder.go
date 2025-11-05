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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/openpcc/openpcc/anonpay/currency"
)

type refundRecorder interface {
	Read(p []byte) (int, error)
	Close() error
	Refund(creditAmount int64) (currency.Value, error)
}

func newRefundRecorder(path string, rc io.ReadCloser) refundRecorder {
	switch path {
	case OpenAICompletionsPath, OpenAIChatPath:
		return &openAIRefundRecorder{
			line:     nil,
			i:        0,
			lastJSON: nil,
			eof:      false,
			r:        bufio.NewReader(rc),
			c:        rc,
		}
	default:
		// Default to Ollama format for /api/generate, /api/chat, etc.
		return &ollamaRefundRecorder{
			line: nil,
			i:    0,
			eof:  false,
			r:    bufio.NewReader(rc),
			c:    rc,
		}
	}
}

// ollamaRefundRecorder tracks the last line of an ollama response to be able
// to record a refund.
type ollamaRefundRecorder struct {
	line []byte
	i    int
	eof  bool
	r    *bufio.Reader
	c    io.Closer
}

func (r *ollamaRefundRecorder) Read(p []byte) (int, error) {
	if r.i >= len(r.line) {
		if r.eof {
			return 0, io.EOF
		}

		// read the next line from the reader
		line, err := r.r.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				return len(line), err
			}
			r.eof = true
			if len(line) == 0 {
				return 0, io.EOF
			}
		}
		r.line = line
		r.i = 0
	}

	n := copy(p, r.line[r.i:])
	r.i += n
	return n, nil
}

func (r *ollamaRefundRecorder) Close() error {
	return r.c.Close()
}

func (r *ollamaRefundRecorder) Refund(creditAmount int64) (currency.Value, error) {
	var responseData map[string]any
	if err := json.Unmarshal(r.line, &responseData); err != nil {
		return currency.Zero, fmt.Errorf("failed to parse last line of JSON response: %w", err)
	}

	numInputTokens, ok := responseData["prompt_eval_count"].(float64)
	if !ok {
		return currency.Zero, fmt.Errorf("failed to get prompt_eval_count from JSON response: %w", errNoRefundAvailable)
	}
	numOutputTokens, ok := responseData["eval_count"].(float64)
	if !ok {
		return currency.Zero, fmt.Errorf("failed to get eval_count from JSON response: %w", errNoRefundAvailable)
	}

	refund, err := calculateRefund(numInputTokens, numOutputTokens, creditAmount)
	if err != nil {
		return currency.Zero, err
	}

	return refund, nil
}

// openAIRefundRecorder tracks the last line of an openAI response to be able
// to record a refund.
type openAIRefundRecorder struct {
	line     []byte // Current line being read
	i        int    // Position in current line
	lastJSON []byte // Last valid JSON for refund calculation
	eof      bool
	r        *bufio.Reader
	c        io.Closer
}

func (r *openAIRefundRecorder) Read(p []byte) (int, error) {
	if r.i >= len(r.line) {
		if r.eof {
			return 0, io.EOF
		}

		// read the next line from the reader
		line, err := r.r.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				return len(line), err
			}
			r.eof = true
			if len(line) == 0 {
				return 0, io.EOF
			}
		}
		r.line = line
		r.i = 0

		// Extract JSON for refund calculation (like the original logic)
		trimmedLine := bytes.TrimSpace(line)
		trimmedLine = bytes.TrimPrefix(trimmedLine, []byte("data: "))
		if len(trimmedLine) > 0 && !bytes.Equal(trimmedLine, []byte("[DONE]")) &&
			bytes.HasPrefix(trimmedLine, []byte("{")) && bytes.HasSuffix(trimmedLine, []byte("}")) {
			// Store the JSON part for later refund calculation
			r.lastJSON = make([]byte, len(trimmedLine))
			copy(r.lastJSON, trimmedLine)
		}
	}

	n := copy(p, r.line[r.i:])
	r.i += n
	return n, nil
}

func (r *openAIRefundRecorder) Close() error {
	return r.c.Close()
}

func (r *openAIRefundRecorder) Refund(creditAmount int64) (currency.Value, error) {
	var responseData map[string]any
	if err := json.Unmarshal(r.lastJSON, &responseData); err != nil {
		return currency.Zero, fmt.Errorf("failed to parse last line of JSON response: %w", err)
	}

	usage, ok := responseData["usage"].(map[string]any)
	if !ok {
		return currency.Zero, fmt.Errorf("failed to get usage from JSON response: %w", errNoRefundAvailable)
	}
	numInputTokens, ok := usage["prompt_tokens"].(float64)
	if !ok {
		return currency.Zero, fmt.Errorf("failed to get prompt_tokens from JSON response: %w", errNoRefundAvailable)
	}
	numOutputTokens, ok := usage["completion_tokens"].(float64)
	if !ok {
		return currency.Zero, fmt.Errorf("failed to get completion_tokens from JSON response: %w", errNoRefundAvailable)
	}

	refund, err := calculateRefund(numInputTokens, numOutputTokens, creditAmount)
	if err != nil {
		return currency.Zero, err
	}

	return refund, nil
}
