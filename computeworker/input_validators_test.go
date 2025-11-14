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
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/openpcc/openpcc/auth/credentialing"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/stretchr/testify/require"
)

func assertError(t *testing.T, err error, wantErr bool, wantCode ValidationErrorCode) {
	t.Helper()

	if !wantErr {
		require.NoError(t, err)
	} else {
		require.Error(t, err)

		var validErr ValidationError
		require.ErrorAs(t, err, &validErr)
		require.Equal(t, wantCode, validErr.Code,
			"expected code %d (%v), got %d (%v)",
			wantCode, wantCode,
			validErr.Code, validErr.Code)
	}
}

var defaultTestModels = []string{"llama3.2:1b", "qwen2:1.5b-instruct", "deepseek-r1:7b", "gemma3:1b"}

func getTestBadge(t *testing.T, keyProvider credentialing.BadgeKeyProvider) credentialing.Badge {
	badgeSK, err := keyProvider.PrivateKey()
	require.NoError(t, err)

	badge := credentialing.Badge{}
	badge.Credentials = credentialing.Credentials{Models: defaultTestModels}
	credBytes, err := badge.Credentials.MarshalBinary()
	require.NoError(t, err)

	sig := ed25519.Sign(badgeSK, credBytes)
	badge.Signature = sig
	return badge
}

func getTestBadgeInvalidSignature(t *testing.T, keyProvider credentialing.BadgeKeyProvider) credentialing.Badge {
	badgeSK, err := keyProvider.PrivateKey()
	require.NoError(t, err)

	badge := credentialing.Badge{}
	badge.Credentials = credentialing.Credentials{Models: []string{"llama3.2:1b", "qwen2:1.5b-instruct", "gemma3:1b"}}
	credBytes, err := badge.Credentials.MarshalBinary()
	require.NoError(t, err)

	credBytes = append(credBytes, []byte("some extra data")...)
	sig := ed25519.Sign(badgeSK, credBytes)
	badge.Signature = sig
	return badge
}

func TestEndpointValidator(t *testing.T) {
	t.Run("basic validations", func(t *testing.T) {
		allowedEndpoints := map[string][]string{
			"/v1/chat/completions": {"POST"},
			"/api/embed":           {"POST"},
		}
		testCases := []struct {
			name       string
			path       string
			requestURI string
			method     string
			wantErr    bool
			wantCode   ValidationErrorCode
		}{
			{
				name:       "allowed_route",
				path:       "/v1/chat/completions",
				requestURI: "/v1/chat/completions",
				method:     "POST",
				wantErr:    false,
			},
			{
				name:       "disallowed_path",
				path:       "/api/pull",
				requestURI: "/api/pull",
				method:     "POST",
				wantErr:    true,
				wantCode:   ErrUnsupportedPath,
			},
			{
				name:       "allowed_path_disallowed_method",
				path:       "/v1/chat/completions",
				requestURI: "/v1/chat/completions",
				method:     "PUT",
				wantErr:    true,
				wantCode:   ErrUnsupportedMethod,
			},
			{
				name:       "allowed_path_with_query_params",
				path:       "/v1/chat/completions?user=admin",
				requestURI: "/v1/chat/completions?user=admin",
				method:     "POST",
				wantErr:    true,
				wantCode:   ErrQueryParamsNotAllowed,
			},
			{
				name:       "url_path_differs_from_request_uri",
				path:       "/v1/chat/completions",
				requestURI: "/v1/chat/completions/.../admin",
				method:     "POST",
				wantErr:    true,
				wantCode:   ErrInvalidRequestURI,
			},
		}

		for _, tc := range testCases {
			validator := EndpointValidator{
				Allowed: allowedEndpoints,
			}
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(tc.method, tc.path, nil)
				req.RequestURI = tc.requestURI

				err := validator.Validate(req)
				assertError(t, err, tc.wantErr, tc.wantCode)
			})
		}
	})
}

func TestHeaderValidator(t *testing.T) {
	blockedHeaders := []string{
		"Content-Encoding",
		"Authorization",
		"Cookie",
	}
	maxHeaderSize := 1024

	badgeKeyProvider := test.NewTestBadgeKeyProvider()
	badgeHeader := "X-Confsec-Badge"
	badge := getTestBadge(t, badgeKeyProvider)
	serializedBadge, err := badge.Serialize()
	require.NoError(t, err)

	testCases := []struct {
		name     string
		headers  map[string]string
		wantErr  bool
		wantCode ValidationErrorCode
	}{
		{
			name: "valid_headers",
			headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
				badgeHeader:    serializedBadge,
			},
			wantErr: false,
		},
		{
			name: "blocked_headers",
			headers: map[string]string{
				"Content-Type":     "application/json",
				"Content-Encoding": "gzip",
				badgeHeader:        serializedBadge,
			},
			wantErr:  true,
			wantCode: ErrHeaderNotAllowed,
		},
		{
			name: "blocked_headers_lowercase",
			headers: map[string]string{
				"Content-Type":     "application/json",
				"content-encoding": "gzip",
				badgeHeader:        serializedBadge,
			},
			wantErr:  true,
			wantCode: ErrHeaderNotAllowed,
		},
		{
			name: "blocked_headers_mixed_case",
			headers: map[string]string{
				"Content-Type":  "application/json",
				"AUTHorization": "######",
				badgeHeader:     serializedBadge,
			},
			wantErr:  true,
			wantCode: ErrHeaderNotAllowed,
		},
		{
			name: "chunked_encoding_not_allowed",
			headers: map[string]string{
				"Content-Type":      "application/json",
				"Transfer-Encoding": "chunked",
				badgeHeader:         serializedBadge,
			},
			wantErr:  true,
			wantCode: ErrTransferEncodingNotAllowed,
		},
		{
			name: "header_value_too_large",
			headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       strings.Repeat("a", maxHeaderSize+1),
				badgeHeader:    serializedBadge,
			},
			wantErr:  true,
			wantCode: ErrHeaderTooLarge,
		},
		{
			name: "header_value_at_size_limit",
			headers: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   strings.Repeat("a", maxHeaderSize),
				badgeHeader:    serializedBadge,
			},
			wantErr: false,
		},
		{
			name: "content_type_not_set",
			headers: map[string]string{
				"Accept":    "application/json",
				badgeHeader: serializedBadge,
			},
			wantErr:  true,
			wantCode: ErrContentTypeNotAllowed,
		},
		{
			name: "unsupported_content_type",
			headers: map[string]string{
				"Content-Type": "text/plain",
				badgeHeader:    serializedBadge,
			},
			wantErr:  true,
			wantCode: ErrContentTypeNotAllowed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := HeaderValidator{
				MaxHeaderSize: maxHeaderSize,
				Blocked:       blockedHeaders,
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			err := validator.Validate(req)
			assertError(t, err, tc.wantErr, tc.wantCode)
		})
	}
	t.Run("combined header value too large", func(t *testing.T) {
		validator := HeaderValidator{
			MaxHeaderSize: maxHeaderSize,
			Blocked:       blockedHeaders,
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Add("Content-Type", "application/json")

		v := "application/json"
		for i := 0; i < maxHeaderSize/len(v)+1; i++ {
			req.Header.Add("Accept", v)
		}

		err := validator.Validate(req)
		assertError(t, err, true, ErrHeaderTooLarge)
	})
}

func TestRequestAuthorizer(t *testing.T) {
	badgeKeyProvider := test.NewTestBadgeKeyProvider()
	badgeSK, err := badgeKeyProvider.PrivateKey()
	require.NoError(t, err)
	badgePK, ok := badgeSK.Public().(ed25519.PublicKey)
	require.True(t, ok)

	badgeHeader := "X-Confsec-Badge"
	badge := getTestBadge(t, badgeKeyProvider)
	serializedBadge, err := badge.Serialize()
	require.NoError(t, err)
	invalidBadge := getTestBadgeInvalidSignature(t, badgeKeyProvider)
	serializedInvalidBadge, err := invalidBadge.Serialize()
	require.NoError(t, err)

	testCases := []struct {
		name       string
		headers    map[string]string
		wantErr    bool
		wantCode   ValidationErrorCode
		wantModels []string
	}{
		{
			name: "valid_badge",
			headers: map[string]string{
				"Content-Type": "application/json",
				badgeHeader:    serializedBadge,
			},
			wantErr:    false,
			wantModels: defaultTestModels,
		},
		{
			name: "invalid_badge_signature",
			headers: map[string]string{
				"Content-Type": "application/json",
				badgeHeader:    serializedInvalidBadge,
			},
			wantErr:  true,
			wantCode: ErrBadgeInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := RequestAuthorizer{
				BadgePublicKey: badgePK,
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			badge, err := authorizer.Authorize(req)
			assertError(t, err, tc.wantErr, tc.wantCode)
			if !tc.wantErr {
				sort.Strings(tc.wantModels)
				require.Equal(t, badge.Credentials.Models, tc.wantModels)
			}
		})
	}
}

func TestBodyValidator(t *testing.T) {
	maxBodySize := 1 * 1024 * 1024
	validator := BodyValidator{
		MaxSize: maxBodySize,
		RouteBodyTypes: map[string]func() RequestBody{
			OllamaGeneratePath:    func() RequestBody { return &OllamaRequestBodyGenerate{} },
			OllamaChatPath:        func() RequestBody { return &OllamaRequestBodyChat{} },
			OpenAICompletionsPath: func() RequestBody { return &OpenAIRequestBodyCompletions{} },
			OpenAIChatPath:        func() RequestBody { return &OpenAIRequestBodyChat{} },
		},
		SupportedModels: []string{"llama3.2:1b", "qwen2:1.5b-instruct", "private-model1:5b", "gemma3:1b"},
	}

	badgeKeyProvider := test.NewTestBadgeKeyProvider()
	badge := getTestBadge(t, badgeKeyProvider)

	t.Run("size validation", func(t *testing.T) {

		createValidPayload := func(targetSize int) string {
			if targetSize == 0 {
				return ""
			}

			basePayload := `{
				"model":"llama3.2:1b",
				"messages": [
					{"role":"system","content":"you are a helpful assistant"},
					{"role":"user","content":"%s"}
				],
				"stream":false
			}`

			baseSize := len(fmt.Sprintf(basePayload, ""))
			fillerSize := targetSize - baseSize

			if fillerSize <= 0 {
				return fmt.Sprintf(basePayload, "x")
			} else {
				return fmt.Sprintf(basePayload, strings.Repeat("x", fillerSize))
			}
		}

		testCases := []struct {
			name           string
			bodySize       int
			setContentSize bool
			contentSize    int
			wantErr        bool
			wantCode       ValidationErrorCode
		}{
			{
				name:     "within_limit",
				bodySize: maxBodySize / 2,
				wantErr:  false,
			},
			{
				name:     "at_limit",
				bodySize: maxBodySize,
				wantErr:  false,
			},
			{
				name:     "empty_body",
				bodySize: 0,
				wantErr:  true,
				wantCode: ErrEmptyBody,
			},
			{
				name:           "actual_size_exceeds_limit",
				bodySize:       maxBodySize * 2,
				setContentSize: true,
				contentSize:    maxBodySize,
				wantErr:        true,
				wantCode:       ErrBodyTooLarge,
			},
			{
				name:           "actual_size_slightly_exceeds_limit",
				bodySize:       maxBodySize + 1,
				setContentSize: true,
				contentSize:    maxBodySize,
				wantErr:        true,
				wantCode:       ErrBodyTooLarge,
			},
			{
				name:           "content_length_exceeds_max_size",
				bodySize:       maxBodySize / 2,
				setContentSize: true,
				contentSize:    maxBodySize + 1,
				wantErr:        true,
				wantCode:       ErrBodyTooLarge,
			},
			{
				name:           "content_length_does_not_actual_body_size",
				bodySize:       10,
				setContentSize: true,
				contentSize:    11,
				wantErr:        true,
				wantCode:       ErrContentLengthMismatch,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				body := createValidPayload(tc.bodySize)
				req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
				if tc.setContentSize && tc.contentSize > 0 {
					req.ContentLength = int64(tc.contentSize)
				}

				err := validator.ValidateWithBadge(req, &badge)
				assertError(t, err, tc.wantErr, tc.wantCode)
			})
		}
	})

	t.Run("payload validation, /api/generate", func(t *testing.T) {
		testCases := []struct {
			name     string
			payload  string
			wantErr  bool
			wantCode ValidationErrorCode
		}{
			{
				name:    "minimal_valid_payload",
				payload: `{"model":"llama3.2:1b","prompt":"Why is the sky blue?","stream":false}`,
				wantErr: false,
			},
			{
				name:    "valid_payload_with_system_and_options",
				payload: `{"model":"llama3.2:1b","prompt":"Write python func to forecast weather","system":"You are a coding assistant.","options":{"temperature":0.7,"top_p":0.9},"stream":true}`,
				wantErr: false,
			},
			{
				name:     "malformed_json",
				payload:  `{"model":"llama3.2:1b","prompt":"Hello"`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "not_an_object",
				payload:  `"just a string"`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "array_instead_of_object",
				payload:  `[{"model":"llama3.2:1b","prompt":"Hello"}]`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "unknown_field",
				payload:  `{"model":"llama3.2:1b","prompt":"Hello","unknown_field":"value"}`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "invalid_property_type",
				payload:  `{"model":"llama3.2:1b","prompt":{"nested":"value"}}`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "array_prompt",
				payload:  `{"model":"llama3.2:1b","prompt":["item1","item2"]}`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "multiple_json_objects",
				payload:  `{"model":"llama3.2:1b","prompt":"Hello"}{"sneaky":"payload","with":"malicious content"}`,
				wantErr:  true,
				wantCode: ErrMultipleJSONObjects,
			},
			{
				name:     "null_value",
				payload:  `null`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "missing_model",
				payload:  `{"prompt":"Why is the sky blue?"}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "empty_model",
				payload:  `{"model":"","prompt":"Why is the sky blue?"}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "missing_prompt",
				payload:  `{"model":"llama3.2:1b"}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "empty_prompt",
				payload:  `{"model":"llama3.2:1b","prompt":""}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "unsupported_model",
				payload:  `{"model":"deepseek-r1:7b","prompt":"Why is the sky blue?"}`,
				wantErr:  true,
				wantCode: ErrUnsupportedModel,
			},
			{
				name:     "model_not_in_badge_credentials",
				payload:  `{"model":"private-model1:5b","prompt":"Why is the sky blue?"}`,
				wantErr:  true,
				wantCode: ErrUnsupportedModel,
			},
			// TODO[Val]:
			// - Unicode in payload
			// - Fuzzy testing
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, "/api/generate", strings.NewReader(tc.payload))
				req.Header.Set("Content-Type", "application/json")
				req.ContentLength = int64(len(tc.payload))

				err := validator.ValidateWithBadge(req, &badge)
				assertError(t, err, tc.wantErr, tc.wantCode)
			})
		}
	})

	t.Run("payload validation, /api/chat", func(t *testing.T) {
		testCases := []struct {
			name     string
			payload  string
			wantErr  bool
			wantCode ValidationErrorCode
		}{
			{
				name:    "minimal_valid_payload",
				payload: `{"model":"llama3.2:1b","messages":[],"stream":false}`,
				wantErr: false,
			},
			{
				name:    "valid_payload_with_messages",
				payload: `{"model":"qwen2:1.5b-instruct","messages":[{"role": "user","content": "why is the sky blue?"}]}`,
				wantErr: false,
			},
			{
				name: "valid_payload_with_format_and_options",
				payload: `{
  "model": "qwen2:1.5b-instruct",
  "messages": [{"role": "user", "content": "Ollama is 22 years old and busy saving the world. Return a JSON object with the age and availability."}],
  "stream": false,
  "format": {
    "type": "object",
    "properties": {
      "age": {
        "type": "integer"
      },
      "available": {
        "type": "boolean"
      }
    },
    "required": [
      "age",
      "available"
    ]
  },
  "options": {
    "temperature": 0
  }
}
				`,
				wantErr: false,
			},
			{
				name:     "malformed_json",
				payload:  `{"model":"llama3.2:1b","messages":[{"role":"system","content":"check"}]`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "not_an_object",
				payload:  `"just a string"`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "array_instead_of_object",
				payload:  `[{"model":"llama3.2:1b","messages":[]}]`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "unknown_field",
				payload:  `{"model":"llama3.2:1b","messages":[],"unknown_field":"value"}`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "invalid_property_type",
				payload:  `{"model":"llama3.2:1b","messages":{"as":"object"}}`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "multiple_json_objects",
				payload:  `{"model":"qwen2:1.5b-instruct","messages":[{"role":"user","content":"ping"}]}{"sneaky":"payload","with":"malicious content"}`,
				wantErr:  true,
				wantCode: ErrMultipleJSONObjects,
			},
			{
				name:     "null_value",
				payload:  `null`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "missing_model",
				payload:  `{"messages":[{"role":"user","content":"ping"}]}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "empty_model",
				payload:  `{"model":"","messages":[{"role":"user","content":"ping"}]}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "missing_messages",
				payload:  `{"model":"llama3.2:1b"}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(tc.payload))
				req.Header.Set("Content-Type", "application/json")
				req.ContentLength = int64(len(tc.payload))

				err := validator.ValidateWithBadge(req, &badge)
				assertError(t, err, tc.wantErr, tc.wantCode)
			})
		}
	})

	t.Run("payload validation, /v1/completions", func(t *testing.T) {
		testCases := []struct {
			name     string
			payload  string
			wantErr  bool
			wantCode ValidationErrorCode
		}{
			{
				name:    "minimal_valid_payload",
				payload: `{"model":"llama3.2:1b","prompt":"Why is the sky blue?"}`,
				wantErr: false,
			},
			{
				name:    "valid_payload_with_options",
				payload: `{"model":"qwen2:1.5b-instruct","prompt":"Write a function","temperature":1,"max_tokens":100,"stream":false}`,
				wantErr: false,
			},
			{
				name:    "stream_without_stream_options",
				payload: `{"model":"llama3.2:1b","prompt":"Hello","stream":true}`,
				wantErr: false,
			},
			{
				name:    "stream_with_stream_options_include_usage_false",
				payload: `{"model":"llama3.2:1b","prompt":"Hello","stream":true,"stream_options":{"include_usage":false}}`,
				wantErr: false,
			},
			{
				name:    "stream_with_stream_options_include_usage_true",
				payload: `{"model":"llama3.2:1b","prompt":"Hello","stream":true,"stream_options":{"include_usage":true}}`,
				wantErr: false,
			},
			{
				name:     "malformed_json",
				payload:  `{"model":"llama3.2:1b","prompt":"Hello"`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "not_an_object",
				payload:  `"just a string"`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "array_instead_of_object",
				payload:  `[{"model":"llama3.2:1b","prompt":"Hello"}]`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "unknown_field",
				payload:  `{"model":"llama3.2:1b","prompt":"Hello","unknown_field":"value"}`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "invalid_property_type",
				payload:  `{"model":"llama3.2:1b","prompt":{"nested":"value"}}`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "multiple_json_objects",
				payload:  `{"model":"llama3.2:1b","prompt":"Hello"}{"sneaky":"payload"}`,
				wantErr:  true,
				wantCode: ErrMultipleJSONObjects,
			},
			{
				name:     "null_value",
				payload:  `null`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "missing_model",
				payload:  `{"prompt":"Why is the sky blue?"}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "empty_model",
				payload:  `{"model":"","prompt":"Why is the sky blue?"}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "missing_prompt",
				payload:  `{"model":"llama3.2:1b"}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "empty_prompt",
				payload:  `{"model":"llama3.2:1b","prompt":""}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "unsupported_model",
				payload:  `{"model":"unsupported-model","prompt":"Why is the sky blue?"}`,
				wantErr:  true,
				wantCode: ErrUnsupportedModel,
			},
			{
				name:     "model_not_in_badge_credentials",
				payload:  `{"model":"private-model1:5b","prompt":"Why is the sky blue?"}`,
				wantErr:  true,
				wantCode: ErrUnsupportedModel,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, "/v1/completions", strings.NewReader(tc.payload))
				req.Header.Set("Content-Type", "application/json")
				req.ContentLength = int64(len(tc.payload))

				err := validator.ValidateWithBadge(req, &badge)
				assertError(t, err, tc.wantErr, tc.wantCode)
			})
		}
	})

	t.Run("payload validation, /v1/chat/completions", func(t *testing.T) {
		testCases := []struct {
			name     string
			payload  string
			wantErr  bool
			wantCode ValidationErrorCode
		}{
			{
				name:    "minimal_valid_payload",
				payload: `{"model":"llama3.2:1b","messages":[{"role":"user","content":"Hello"}]}`,
				wantErr: false,
			},
			{
				name:    "valid_payload_with_options",
				payload: `{"model":"qwen2:1.5b-instruct","messages":[{"role":"user","content":"Hello"}],"temperature":1,"max_completion_tokens":100,"stream":false}`,
				wantErr: false,
			},
			{
				name:    "stream_without_stream_options",
				payload: `{"model":"llama3.2:1b","messages":[{"role":"user","content":"Hello"}],"stream":true}`,
				wantErr: false,
			},
			{
				name:    "stream_with_stream_options_include_usage_false",
				payload: `{"model":"llama3.2:1b","messages":[{"role":"user","content":"Hello"}],"stream":true,"stream_options":{"include_usage":false}}`,
				wantErr: false,
			},
			{
				name:    "stream_with_stream_options_include_usage_true",
				payload: `{"model":"llama3.2:1b","messages":[{"role":"user","content":"Hello"}],"stream":true,"stream_options":{"include_usage":true}}`,
				wantErr: false,
			},
			{
				name:    "valid_payload_with_tools",
				payload: `{"model":"qwen2:1.5b-instruct","messages":[{"role":"user","content":"What's the weather?"}],"tools":[{"type":"function","function":{"name":"get_weather","description":"Get weather info"}}]}`,
				wantErr: false,
			},
			{
				name:     "malformed_json",
				payload:  `{"model":"llama3.2:1b","messages":[{"role":"user","content":"Hello"}]`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "not_an_object",
				payload:  `"just a string"`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "array_instead_of_object",
				payload:  `[{"model":"llama3.2:1b","messages":[]}]`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "unknown_field",
				payload:  `{"model":"llama3.2:1b","messages":[],"unknown_field":"value"}`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "invalid_property_type",
				payload:  `{"model":"llama3.2:1b","messages":"not_an_array"}`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "multiple_json_objects",
				payload:  `{"model":"llama3.2:1b","messages":[]}{"sneaky":"payload"}`,
				wantErr:  true,
				wantCode: ErrMultipleJSONObjects,
			},
			{
				name:     "null_value",
				payload:  `null`,
				wantErr:  true,
				wantCode: ErrInvalidJSON,
			},
			{
				name:     "missing_model",
				payload:  `{"messages":[{"role":"user","content":"Hello"}]}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "empty_model",
				payload:  `{"model":"","messages":[{"role":"user","content":"Hello"}]}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "missing_messages",
				payload:  `{"model":"llama3.2:1b"}`,
				wantErr:  true,
				wantCode: ErrMissingRequiredField,
			},
			{
				name:     "unsupported_model",
				payload:  `{"model":"unsupported-model","messages":[{"role":"user","content":"Hello"}]}`,
				wantErr:  true,
				wantCode: ErrUnsupportedModel,
			},
			{
				name:     "model_not_in_badge_credentials",
				payload:  `{"model":"private-model1:5b","messages":[{"role":"user","content":"Hello"}]}`,
				wantErr:  true,
				wantCode: ErrUnsupportedModel,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(tc.payload))
				req.Header.Set("Content-Type", "application/json")
				req.ContentLength = int64(len(tc.payload))

				err := validator.ValidateWithBadge(req, &badge)
				assertError(t, err, tc.wantErr, tc.wantCode)
			})
		}
	})

	t.Run("body mutation for stream options", func(t *testing.T) {
		testCases := []struct {
			name        string
			path        string
			payload     string
			expectDirty bool
			wantErr     bool
		}{
			{
				name:        "openai_completions_stream_without_stream_options_should_be_mutated",
				path:        "/v1/completions",
				payload:     `{"model":"llama3.2:1b","prompt":"Hello","stream":true}`,
				expectDirty: true,
				wantErr:     false,
			},
			{
				name:        "openai_completions_stream_with_include_usage_false_should_be_mutated",
				path:        "/v1/completions",
				payload:     `{"model":"llama3.2:1b","prompt":"Hello","stream":true,"stream_options":{"include_usage":false}}`,
				expectDirty: true,
				wantErr:     false,
			},
			{
				name:        "openai_completions_stream_with_include_usage_true_should_not_be_mutated",
				path:        "/v1/completions",
				payload:     `{"model":"llama3.2:1b","prompt":"Hello","stream":true,"stream_options":{"include_usage":true}}`,
				expectDirty: false,
				wantErr:     false,
			},
			{
				name:        "openai_chat_stream_without_stream_options_should_be_mutated",
				path:        "/v1/chat/completions",
				payload:     `{"model":"llama3.2:1b","messages":[{"role":"user","content":"Hello"}],"stream":true}`,
				expectDirty: true,
				wantErr:     false,
			},
			{
				name:        "openai_chat_stream_with_include_usage_false_should_be_mutated",
				path:        "/v1/chat/completions",
				payload:     `{"model":"llama3.2:1b","messages":[{"role":"user","content":"Hello"}],"stream":true,"stream_options":{"include_usage":false}}`,
				expectDirty: true,
				wantErr:     false,
			},
			{
				name:        "openai_chat_stream_with_include_usage_true_should_not_be_mutated",
				path:        "/v1/chat/completions",
				payload:     `{"model":"llama3.2:1b","messages":[{"role":"user","content":"Hello"}],"stream":true,"stream_options":{"include_usage":true}}`,
				expectDirty: false,
				wantErr:     false,
			},
			{
				name:        "ollama_generate_should_never_be_mutated",
				path:        "/api/generate",
				payload:     `{"model":"llama3.2:1b","prompt":"Hello","stream":true}`,
				expectDirty: false,
				wantErr:     false,
			},
			{
				name:        "ollama_chat_should_never_be_mutated",
				path:        "/api/chat",
				payload:     `{"model":"llama3.2:1b","messages":[],"stream":true}`,
				expectDirty: false,
				wantErr:     false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				bodyBuilder, found := validator.RouteBodyTypes[tc.path]
				require.True(t, found, "Route %s should be supported", tc.path)

				requestBody := bodyBuilder()

				err := json.Unmarshal([]byte(tc.payload), &requestBody)
				require.NoError(t, err, "Should be able to unmarshal test payload")

				_, dirty, err := requestBody.Validate(validator.SupportedModels)

				if tc.wantErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					require.Equal(t, tc.expectDirty, dirty, "Dirty flag should match expectation")
				}
			})
		}
	})
}

func TestHostnameValidator(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		wantErr  bool
		wantCode ValidationErrorCode
	}{
		{
			name:    "allowed_hostname",
			url:     "http://confsec.invalid/v1/chat/completions",
			wantErr: false,
		},
		{
			name:     "empty_hostname",
			url:      "http:///v1/chat/completions",
			wantErr:  true,
			wantCode: ErrUnknownHostname,
		},
		{
			name:     "disallowed_hostname",
			url:      "http://example.com/v1/chat/completions",
			wantErr:  true,
			wantCode: ErrUnknownHostname,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.url, nil)
			validator := &HostnameValidator{}
			err := validator.Validate(req)
			assertError(t, err, tc.wantErr, tc.wantCode)
		})
	}
}

func TestRequestValidator(t *testing.T) {
	blockedHeaders := []string{
		"Content-Encoding",
		"Authorization",
		"Cookie",
	}
	maxHeaderSize := 1024
	maxBodySize := 1 * 1024 * 1024

	badgeKeyProvider := test.NewTestBadgeKeyProvider()
	badgeSK, err := badgeKeyProvider.PrivateKey()
	require.NoError(t, err)
	badgePK, ok := badgeSK.Public().(ed25519.PublicKey)
	require.True(t, ok)

	badgeHeader := "X-Confsec-Badge"
	badge := getTestBadge(t, badgeKeyProvider)
	serializedBadge, err := badge.Serialize()
	require.NoError(t, err)

	testCases := []struct {
		name     string
		headers  map[string]string
		payload  string
		wantErr  bool
		wantCode ValidationErrorCode
	}{
		{
			name: "unauthorized_model_in_body_json",
			headers: map[string]string{
				"Content-Type": "application/json",
				badgeHeader:    serializedBadge,
			},
			payload:  `{"model":"privatemodel1.0","messages":[{"role":"user","content":"Hello"}],"stream":true,"stream_options":{"include_usage":true}}`,
			wantErr:  true,
			wantCode: ErrUnsupportedModel,
		},
	}

	validator := RequestValidator{
		preAuthValidators: []Validator{
			HeaderValidator{
				MaxHeaderSize: maxHeaderSize,
				Blocked:       blockedHeaders,
			},
			EndpointValidator{
				Allowed: map[string][]string{
					"/v1/chat/completions": {"POST"},
					"/api/embed":           {"POST"},
					"/v1/completions":      {"POST"},
				},
			},
		},
		requestAuthorizer: RequestAuthorizer{
			BadgePublicKey: badgePK,
		},
		postAuthValidators: []PostAuthValidator{
			BodyValidator{
				MaxSize: maxBodySize,
				RouteBodyTypes: map[string]func() RequestBody{
					"/v1/chat/completions": func() RequestBody { return &OpenAIRequestBodyChat{} },
					"/v1/completions":      func() RequestBody { return &OpenAIRequestBodyCompletions{} },
				},
				SupportedModels: []string{"llama3.2:1b", "privatemodel1.0", "qwen2:1.5b-instruct", "gemma3:1b"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(tc.payload))
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}
			err := validator.Validate(req)
			assertError(t, err, tc.wantErr, tc.wantCode)
		})
	}
}
