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
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/stretchr/testify/require"
)

func TestOllamaRefundRecorderRead(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedOutput string
	}{
		{
			name: "single_line_response",
			input: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello","done":true,"eval_count":5}
`,
			expectedOutput: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello","done":true,"eval_count":5}
`,
		},
		{
			name: "multi_line_response",
			input: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello","done":false}
{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":" world","done":false}
{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"","done":true,"eval_count":10}
`,
			expectedOutput: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello","done":false}
{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":" world","done":false}
{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"","done":true,"eval_count":10}
`,
		},
		{
			name:           "empty_input",
			input:          "",
			expectedOutput: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rc := io.NopCloser(strings.NewReader(tc.input))
			recorder := newRefundRecorder("/api/generate", rc).(*ollamaRefundRecorder)

			output, err := io.ReadAll(recorder)
			require.NoError(t, err)
			require.Equal(t, tc.expectedOutput, string(output))

			err = recorder.Close()
			require.NoError(t, err)
		})
	}
}

func TestOllamaRefundRecorderRefund(t *testing.T) {
	testCases := []struct {
		name         string
		input        string
		creditAmount int64
		wantErr      bool
		errContains  string
	}{
		{
			name: "valid_single_line_with_eval_count",
			input: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello world","done":true,"prompt_eval_count":10,"eval_count":5}
`,
			creditAmount: 1000,
			wantErr:      false,
		},
		{
			name: "valid_multi_line_last_has_eval_count",
			input: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello","done":false}
{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":" world","done":false}
{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"","done":true,"prompt_eval_count":15,"eval_count":8}
`,
			creditAmount: 1000,
			wantErr:      false,
		},
		{
			name: "invalid_json_last_line",
			input: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello","done":false}
invalid json line
`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "failed to parse last line of JSON response",
		},
		{
			name: "missing_eval_count",
			input: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello","done":true}
`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "no refund available",
		},
		{
			name: "eval_count_wrong_type",
			input: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello","done":true,"prompt_eval_count":10,"eval_count":"not_a_number"}
`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "no refund available",
		},
		{
			name: "missing_prompt_eval_count",
			input: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello","done":true,"eval_count":5}
`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "no refund available",
		},
		{
			name: "prompt_eval_count_wrong_type",
			input: `{"model":"llama3.2:1b","created_at":"2025-01-23T10:30:00Z","response":"Hello","done":true,"prompt_eval_count":"not_a_number","eval_count":5}
`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "no refund available",
		},
		{
			name:         "empty_input",
			input:        "",
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "failed to parse last line of JSON response",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rc := io.NopCloser(strings.NewReader(tc.input))
			recorder := newRefundRecorder("/api/generate", rc).(*ollamaRefundRecorder)

			// Read all data to populate the last line
			_, err := io.ReadAll(recorder)
			require.NoError(t, err)

			refund, err := recorder.Refund(tc.creditAmount)

			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
				require.Equal(t, currency.Zero, refund)
			} else {
				require.NoError(t, err)
				// Just verify that we got a valid refund (non-error), not checking exact amount
				// since calculateRefund involves randomness
			}

			err = recorder.Close()
			require.NoError(t, err)
		})
	}
}

func TestOpenAIRefundRecorderRead(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedOutput string
	}{
		{
			name: "sse_response_with_usage",
			input: `data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{"content":"Hello"},"index":0}]}

data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{"content":" world"},"index":0}]}

data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{},"index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}

data: [DONE]

`,
			expectedOutput: `data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{"content":"Hello"},"index":0}]}

data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{"content":" world"},"index":0}]}

data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{},"index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}

data: [DONE]

`,
		},
		{
			name: "sse_response_with_empty_lines",
			input: `data: {"id":"chatcmpl-123","choices":[{"delta":{"content":"Hello"}}]}

data: {"id":"chatcmpl-123","choices":[{"delta":{"content":" world"}}]}


data: [DONE]

`,
			expectedOutput: `data: {"id":"chatcmpl-123","choices":[{"delta":{"content":"Hello"}}]}

data: {"id":"chatcmpl-123","choices":[{"delta":{"content":" world"}}]}


data: [DONE]

`,
		},
		{
			name:           "empty_input",
			input:          "",
			expectedOutput: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rc := io.NopCloser(strings.NewReader(tc.input))
			recorder := &openAIRefundRecorder{
				r: bufio.NewReader(rc),
				c: rc,
			}

			output, err := io.ReadAll(recorder)
			require.NoError(t, err)
			require.Equal(t, tc.expectedOutput, string(output))

			err = recorder.Close()
			require.NoError(t, err)
		})
	}
}

func TestOpenAIRefundRecorderRefund(t *testing.T) {
	testCases := []struct {
		name         string
		input        string
		creditAmount int64
		wantErr      bool
		errContains  string
	}{
		{
			name: "valid_sse_with_usage",
			input: `data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{"content":"Hello"},"index":0}]}

data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{"content":" world"},"index":0}]}

data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{},"index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}

data: [DONE]

`,
			creditAmount: 1000,
			wantErr:      false,
		},
		{
			name: "sse_without_usage",
			input: `data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{"content":"Hello"},"index":0}]}

data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1677652288,"model":"gpt-3.5-turbo","choices":[{"delta":{},"index":0,"finish_reason":"stop"}]}

data: [DONE]

`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "no refund available",
		},
		{
			name: "invalid_json_in_sse",
			input: `data: {"id":"chatcmpl-123","invalid json

data: [DONE]

`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "failed to parse last line of JSON response",
		},
		{
			name: "completion_tokens_wrong_type",
			input: `data: {"id":"chatcmpl-123","usage":{"prompt_tokens":10,"completion_tokens":"not_a_number","total_tokens":15}}

data: [DONE]

`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "no refund available",
		},
		{
			name: "missing_completion_tokens",
			input: `data: {"id":"chatcmpl-123","usage":{"prompt_tokens":10,"total_tokens":15}}

data: [DONE]

`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "no refund available",
		},
		{
			name: "missing_prompt_tokens",
			input: `data: {"id":"chatcmpl-123","usage":{"completion_tokens":5,"total_tokens":15}}

data: [DONE]

`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "no refund available",
		},
		{
			name: "prompt_tokens_wrong_type",
			input: `data: {"id":"chatcmpl-123","usage":{"prompt_tokens":"not_a_number","completion_tokens":5,"total_tokens":15}}

data: [DONE]

`,
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "no refund available",
		},
		{
			name:         "empty_input",
			input:        "",
			creditAmount: 1000,
			wantErr:      true,
			errContains:  "failed to parse last line of JSON response",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rc := io.NopCloser(strings.NewReader(tc.input))
			recorder := &openAIRefundRecorder{
				r: bufio.NewReader(rc),
				c: rc,
			}

			// Read all data to populate the last valid JSON line
			_, err := io.ReadAll(recorder)
			require.NoError(t, err)

			refund, err := recorder.Refund(tc.creditAmount)

			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
				require.Equal(t, currency.Zero, refund)
			} else {
				require.NoError(t, err)
				// Just verify that we got a valid refund (non-error), not checking exact amount
				// since calculateRefund involves randomness
			}

			err = recorder.Close()
			require.NoError(t, err)
		})
	}
}

func TestNewRefundRecorder(t *testing.T) {
	testCases := []struct {
		name         string
		path         string
		expectedType string
	}{
		{
			name:         "ollama_generate_path",
			path:         "/api/generate",
			expectedType: "*computeworker.ollamaRefundRecorder",
		},
		{
			name:         "ollama_chat_path",
			path:         "/api/chat",
			expectedType: "*computeworker.ollamaRefundRecorder",
		},
		{
			name:         "openai_completions_path",
			path:         "/v1/completions",
			expectedType: "*computeworker.openAIRefundRecorder",
		},
		{
			name:         "openai_chat_path",
			path:         "/v1/chat/completions",
			expectedType: "*computeworker.openAIRefundRecorder",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rc := io.NopCloser(strings.NewReader("test"))
			recorder := newRefundRecorder(tc.path, rc)

			require.NotNil(t, recorder)
			require.Implements(t, (*refundRecorder)(nil), recorder)

			// Check the concrete type
			switch tc.expectedType {
			case "*computeworker.ollamaRefundRecorder":
				_, ok := recorder.(*ollamaRefundRecorder)
				require.True(t, ok, "Expected ollamaRefundRecorder but got %T", recorder)
			case "*computeworker.openAIRefundRecorder":
				_, ok := recorder.(*openAIRefundRecorder)
				require.True(t, ok, "Expected openAIRefundRecorder but got %T", recorder)
			}

			err := recorder.Close()
			require.NoError(t, err)
		})
	}
}

func TestRefundRecorderReadInChunks(t *testing.T) {
	t.Run("ollama_recorder_small_buffer", func(t *testing.T) {
		input := `{"model":"llama3.2:1b","response":"Hello world","done":true,"prompt_eval_count":10,"eval_count":5}
`
		rc := io.NopCloser(strings.NewReader(input))
		recorder := newRefundRecorder("/api/generate", rc)

		// Read in small chunks to test buffer handling
		var output []byte
		buf := make([]byte, 10)
		for {
			n, err := recorder.Read(buf)
			if n > 0 {
				output = append(output, buf[:n]...)
			}
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
		}

		require.Equal(t, input, string(output))
		err := recorder.Close()
		require.NoError(t, err)
	})

	t.Run("openai_recorder_small_buffer", func(t *testing.T) {
		input := `data: {"id":"chatcmpl-123","choices":[{"delta":{"content":"Hello"}}]}

data: [DONE]

`
		rc := io.NopCloser(strings.NewReader(input))
		recorder := &openAIRefundRecorder{
			r: bufio.NewReader(rc),
			c: rc,
		}

		// Read in small chunks to test buffer handling
		var output []byte
		buf := make([]byte, 15)
		for {
			n, err := recorder.Read(buf)
			if n > 0 {
				output = append(output, buf[:n]...)
			}
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
		}

		require.Equal(t, input, string(output))
		err := recorder.Close()
		require.NoError(t, err)
	})
}
