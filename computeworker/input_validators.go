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
	"io"
	"log/slog"
	"net/http"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/openpcc/openpcc/auth/credentialing"
	"github.com/openpcc/openpcc/messages"
	"github.com/openpcc/openpcc/otel/otelutil"
)

type ValidationErrorCode int

const (
	// if adding a new error code, insert it at the end of the const to avoid
	// shifting the value of existing error codes
	ErrGeneric ValidationErrorCode = iota
	// Endpoint validation errors
	ErrQueryParamsNotAllowed
	ErrInvalidRequestURI
	ErrUnsupportedPath
	ErrUnsupportedMethod
	// Header validation errors
	ErrTransferEncodingNotAllowed
	ErrHeaderNotAllowed
	ErrHeaderTooLarge
	// Body validation errors
	ErrBodyTooLarge
	ErrEmptyBody
	ErrReadingBody
	ErrContentLengthMismatch
	ErrInvalidJSON
	ErrMultipleJSONObjects
	ErrMissingRequiredField
	// Hostname validation errors
	ErrUnknownHostname

	ErrContentTypeNotAllowed
	ErrBadgeInvalid
	ErrUnsupportedModel
)

func (c ValidationErrorCode) String() string {
	switch c {
	case ErrGeneric:
		return "ErrGeneric"
	case ErrQueryParamsNotAllowed:
		return "ErrQueryParamsNotAllowed"
	case ErrInvalidRequestURI:
		return "ErrInvalidRequestURI"
	case ErrUnsupportedPath:
		return "ErrUnsupportedPath"
	case ErrUnsupportedMethod:
		return "ErrUnsupportedMethod"
	case ErrTransferEncodingNotAllowed:
		return "ErrTransferEncodingNotAllowed"
	case ErrHeaderNotAllowed:
		return "ErrHeaderNotAllowed"
	case ErrContentTypeNotAllowed:
		return "ErrContentTypeNotAllowed"
	case ErrHeaderTooLarge:
		return "ErrHeaderTooLarge"
	case ErrBodyTooLarge:
		return "ErrBodyTooLarge"
	case ErrEmptyBody:
		return "ErrEmptyBody"
	case ErrReadingBody:
		return "ErrReadingBody"
	case ErrContentLengthMismatch:
		return "ErrContentLengthMismatch"
	case ErrInvalidJSON:
		return "ErrInvalidJSON"
	case ErrMultipleJSONObjects:
		return "ErrMultipleJSONObjects"
	case ErrMissingRequiredField:
		return "ErrMissingRequiredField"
	case ErrUnknownHostname:
		return "ErrUnknownHostname"
	case ErrBadgeInvalid:
		return "ErrBadgeInvalid"
	case ErrUnsupportedModel:
		return "ErrUnsupportedModel"
	default:
		return "Unknown"
	}
}

type ValidationError struct {
	Code    ValidationErrorCode
	Message string
}

func (e ValidationError) Error() string {
	return e.Message
}

func newValidationError(code ValidationErrorCode, message string) ValidationError {
	return ValidationError{
		Code:    code,
		Message: message,
	}
}

const (
	OllamaGeneratePath    = "/api/generate"
	OllamaChatPath        = "/api/chat"
	OpenAICompletionsPath = "/v1/completions"
	OpenAIChatPath        = "/v1/chat/completions"
)

type Validator interface {
	Validate(r *http.Request) error
}

// PostAuthValidators are Validators that require information about the requestor's credentials
// to properly validate the request
type PostAuthValidator interface {
	ValidateWithBadge(r *http.Request, b *credentialing.Badge) error
}

// The RequestAuthorizer is responsible for validating the badge in the request header
type RequestAuthorizer struct {
	BadgePublicKey ed25519.PublicKey
}

func DefaultValidator(badgePublicKey []byte, models []string) Validator {
	return RequestValidator{
		preAuthValidators: []Validator{
			EndpointValidator{
				Allowed: map[string][]string{
					OllamaGeneratePath:    {"POST"}, // Used by the local demo.
					OllamaChatPath:        {"POST"}, // Used by the WASM demo.
					OpenAICompletionsPath: {"POST"}, // Used by the SDKs
					OpenAIChatPath:        {"POST"}, // Used by the SDKs
				},
			},
			HeaderValidator{
				MaxHeaderSize: 1024,
				Blocked: []string{
					// * "Transfer-Encoding=chunked" - not needed and not supported for client requests.
					//   A hole for request smuggling and other exploits related to body size ambiguities.
					// * "Transfer-Encoding", compression options - We should not see this in the unpacked
					//   user request as it's added and removed by proxies, on hop-by-hop basis.
					"Transfer-Encoding",
					// Mitigates "compression bomb" attacks and has many other merits (e.g., no need to handle
					// de-compression and ambiguities with calculating the body size, actual credit amount, etc.)
					"Content-Encoding",
				},
			},
			HostnameValidator{},
		},
		requestAuthorizer: RequestAuthorizer{
			BadgePublicKey: badgePublicKey,
		},
		postAuthValidators: []PostAuthValidator{
			BodyValidator{
				MaxSize: 1 * 1024 * 1024,
				RouteBodyTypes: map[string]func() RequestBody{
					OllamaGeneratePath:    func() RequestBody { return &OllamaRequestBodyGenerate{} },
					OllamaChatPath:        func() RequestBody { return &OllamaRequestBodyChat{} },
					OpenAICompletionsPath: func() RequestBody { return &OpenAIRequestBodyCompletions{} },
					OpenAIChatPath:        func() RequestBody { return &OpenAIRequestBodyChat{} },
				},
				SupportedModels: models,
			},
		},
	}
}

type MultiValidator []Validator

func (mv MultiValidator) Validate(r *http.Request) error {
	_, span := otelutil.Tracer.Start(r.Context(), "MultiValidator.Validate")
	defer span.End()
	for _, v := range mv {
		err := v.Validate(r)
		if err != nil {
			return otelutil.RecordError(span, err)
		}
	}

	return nil
}

// RequestValidator enforces an expected order for running the validators
type RequestValidator struct {
	preAuthValidators  []Validator
	requestAuthorizer  RequestAuthorizer
	postAuthValidators []PostAuthValidator
}

func (rv RequestValidator) Validate(r *http.Request) error {
	for _, v := range rv.preAuthValidators {
		err := v.Validate(r)
		if err != nil {
			return err
		}
	}

	badge, err := rv.requestAuthorizer.Authorize(r)
	if err != nil {
		return err
	}

	for _, v := range rv.postAuthValidators {
		err := v.ValidateWithBadge(r, &badge)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *RequestAuthorizer) Authorize(r *http.Request) (credentialing.Badge, error) {
	serializedBadge := r.Header.Get("X-Confsec-Badge")
	if serializedBadge == "" {
		return credentialing.Badge{}, newValidationError(ErrBadgeInvalid, "badge is not provided")
	}
	badge := credentialing.Badge{}
	err := badge.Deserialize(serializedBadge)

	if err != nil {
		return credentialing.Badge{}, newValidationError(ErrBadgeInvalid, "failed to parse badge")
	}

	if len(badge.Signature) == 0 {
		return credentialing.Badge{}, newValidationError(ErrBadgeInvalid, "invalid badge: signature not provided")
	}

	credBytes, err := badge.Credentials.MarshalBinary()
	if err != nil {
		return credentialing.Badge{}, newValidationError(ErrBadgeInvalid, "failed to marshal badge credentials")
	}
	isValid := ed25519.Verify(a.BadgePublicKey, credBytes, badge.Signature)
	if !isValid {
		return credentialing.Badge{}, newValidationError(ErrBadgeInvalid, "invalid signature")
	}

	return badge, nil
}

type EndpointValidator struct {
	Allowed map[string][]string
}

func (v EndpointValidator) Validate(r *http.Request) error {
	// The presence of query parameters is a deviation from the expected request format.
	// It's safer to assume that unexpected input is an attempt to exploit the system and
	// discard the request entirely.
	if r.URL.RawQuery != "" {
		return newValidationError(ErrQueryParamsNotAllowed, "not supported: query params")
	}

	// Require the request path to be a clean URL path.
	// While non-normalized paths like "/api/%67enerate" or "/api/generate/../admin" are technically
	// valid, they open a door for various path shenanigans.
	//
	// Go's `http.ServeMux` correctly implements [RFC-3986](https://www.rfc-editor.org/rfc/rfc3986),
	// which means that a path like "/api/generate/../admin" becomes "/api/admin" after normalization.
	// The default `http.ServeMux` behavior will also be to respond with "301 Moved Permanently", which
	// is aligned with the best SEO practices like content de-duplication.
	//
	// In our case, we don't care about SEO optimization but we want to be as conservative as possible, and
	// leak the minimum of information, so any suspicious path is simply rejected.
	if r.RequestURI != filepath.FromSlash(path.Clean("/"+strings.Trim(r.URL.Path, "/"))) {
		return newValidationError(ErrInvalidRequestURI, "suspicious path: "+r.RequestURI)
	}

	p := r.URL.Path
	methods, ok := v.Allowed[p]
	if !ok {
		return newValidationError(ErrUnsupportedPath, "not supported: "+p)
	}
	if !slices.Contains(methods, r.Method) {
		return newValidationError(ErrUnsupportedMethod, "not supported: "+r.Method+" "+p)
	}

	return nil
}

type HeaderValidator struct {
	MaxHeaderSize  int
	Blocked        []string
	BadgePublicKey ed25519.PublicKey
}

func (v HeaderValidator) Validate(r *http.Request) error {
	if r.Header.Get("Transfer-Encoding") == "chunked" {
		// Potential request smuggling attempt.
		// (see https://book.hacktricks.wiki/en/pentesting-web/http-request-smuggling/index.html#theory)
		if r.Header.Get("Content-Length") != "" {
			slog.Warn(
				"possible request smuggling attempt",
				"content-length", r.Header.Get("Content-Length"),
				"transfer-encoding", r.Header.Get("Transfer-Encoding"),
			)
		}

		return newValidationError(ErrTransferEncodingNotAllowed, "transfer-encoding=chunked not allowed")
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		return newValidationError(ErrContentTypeNotAllowed, "Content-Type header must be set to application/json")
	}

	for header, values := range r.Header {
		if slices.Contains(v.Blocked, header) {
			return newValidationError(ErrHeaderNotAllowed, "header not allowed: "+header)
		}

		totalSize := 0
		for _, value := range values {
			totalSize += len(value)
		}
		if totalSize > v.MaxHeaderSize {
			return newValidationError(ErrHeaderTooLarge, "header size exceeds max size: "+header)
		}
	}

	serializedBadge := r.Header.Get("X-Confsec-Badge")
	if serializedBadge == "" {
		return newValidationError(ErrBadgeInvalid, "badge is not provided")
	}

	return nil
}

type BodyValidator struct {
	MaxSize         int
	RouteBodyTypes  map[string]func() RequestBody
	SupportedModels []string
}

type RequestBody interface {
	// Validate validates the request body, returning the model name and a bool indicating
	// whether the request body was mutated in the process of validation.
	Validate(supportedModels []string) (string, bool, error)
}

// https://github.com/ollama/ollama/blob/main/docs/api.md#generate-a-completion
type OllamaRequestBodyGenerate struct {
	Model    string         `json:"model"`
	Options  map[string]any `json:"options,omitempty"`
	Prompt   string         `json:"prompt"`
	Stream   bool           `json:"stream,omitempty"`
	System   string         `json:"system,omitempty"`
	Suffix   string         `json:"suffix,omitempty"`
	Template string         `json:"template,omitempty"`
	// "keep_alive" can be a number of seconds or a duration string. TODO[Val]: Implement custom type and JSON Marshaller.
	KeepAlive any `json:"keep_alive,omitempty"`
	// TODO[Val]: Add more fields as needed
	// Images [][]byte							 `json:"images,omitempty"` // Assess carefully (binary exploitation possibility)
	// Format // JSON schema for structured output generation
	// More: https://github.com/ollama/ollama/blob/main/docs/api.md#generate-a-completion
}

func (b *OllamaRequestBodyGenerate) Validate(supportedModels []string) (string, bool, error) {
	if b.Model == "" {
		return "", false, newValidationError(ErrMissingRequiredField, "missing required field: model")
	}
	if !slices.Contains(supportedModels, b.Model) {
		return "", false, newValidationError(ErrUnsupportedModel, "unsupported model: "+b.Model)
	}

	if b.Prompt == "" {
		return "", false, newValidationError(ErrMissingRequiredField, "missing required field: prompt")
	}

	return b.Model, false, nil
}

// https://github.com/ollama/ollama/blob/main/docs/api.md#generate-a-chat-completion
type OllamaRequestBodyChat struct {
	Model     string           `json:"model"`
	Messages  []map[string]any `json:"messages"`
	Tools     []map[string]any `json:"tools,omitempty"`
	Format    map[string]any   `json:"format,omitempty"`
	Options   map[string]any   `json:"options,omitempty"`
	Stream    bool             `json:"stream,omitempty"`
	KeepAlive any              `json:"keep_alive,omitempty"`
}

func (b *OllamaRequestBodyChat) Validate(supportedModels []string) (string, bool, error) {
	if b.Model == "" {
		return "", false, newValidationError(ErrMissingRequiredField, "missing required field: model")
	}
	if !slices.Contains(supportedModels, b.Model) {
		return "", false, newValidationError(ErrUnsupportedModel, "unsupported model: "+b.Model)
	}

	if b.Messages == nil {
		return "", false, newValidationError(ErrMissingRequiredField, "missing required field: messages")
	}

	return b.Model, false, nil
}

// https://platform.openai.com/docs/api-reference/completions/create
type OpenAIRequestBodyStreamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

type OpenAIRequestBodyCompletions struct {
	Model            string         `json:"model"`
	Prompt           string         `json:"prompt"`
	BestOf           int            `json:"best_of,omitempty"`
	Echo             bool           `json:"echo,omitempty"`
	FrequencyPenalty int            `json:"frequency_penalty,omitempty"`
	LogitBias        map[string]any `json:"logit_bias,omitempty"`
	Logprobs         int            `json:"logprobs,omitempty"`
	MaxTokens        int            `json:"max_tokens,omitempty"`
	N                int            `json:"n,omitempty"`
	PresencePenalty  int            `json:"presence_penalty,omitempty"`
	Seed             int            `json:"seed,omitempty"`
	// https://platform.openai.com/docs/api-reference/completions/create#completions-create-stop)
	Stop          any                             `json:"stop,omitempty"` // string / array / null
	Stream        bool                            `json:"stream,omitempty"`
	StreamOptions *OpenAIRequestBodyStreamOptions `json:"stream_options,omitempty"`
	Suffix        string                          `json:"suffix,omitempty"`
	Temperature   int                             `json:"temperature,omitempty"`
	TopP          int                             `json:"top_p,omitempty"`
	User          string                          `json:"user,omitempty"`
	// [TBD]: vLLM has exra params that aren't a part of OpenAI spec, e.g:
	// MinTokens int `json:"min_tokens"`
	//   (https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html#id5)
	// We probably should not support this and stick to the core OpenAI spec to not commit
	// to the specific workload implementation, and also to not disclose it.
	// Additionally, at least this "min_tokens" parameters was plain buggy in my tests.
}

func (b *OpenAIRequestBodyCompletions) Validate(supportedModels []string) (string, bool, error) {
	if b.Model == "" {
		return "", false, newValidationError(ErrMissingRequiredField, "missing required field: model")
	}

	if !slices.Contains(supportedModels, b.Model) {
		return "", false, newValidationError(ErrUnsupportedModel, "unsupported model: "+b.Model)
	}

	if b.Prompt == "" {
		return "", false, newValidationError(ErrMissingRequiredField, "missing required field: prompt")
	}

	// In order to correctly process refunds we need to ensure that usage is always
	// included in the response, even if the request has explicitly disabled it.
	dirty := false
	if b.Stream && (b.StreamOptions == nil || !b.StreamOptions.IncludeUsage) {
		b.StreamOptions = &OpenAIRequestBodyStreamOptions{IncludeUsage: true}
		dirty = true
	}

	return b.Model, dirty, nil
}

// https://platform.openai.com/docs/api-reference/chat/create
type OpenAIRequestBodyChatMessage struct {
	Content string `json:"content"`
	Role    string `json:"role"`
	Name    string `json:"name,omitempty"`
	// Assistant is the only role that can have audio and tool calls.
	// https://platform.openai.com/docs/api-reference/chat/create#chat-create-messages
	Audio     any    `json:"audio,omitempty"`
	Refusal   string `json:"refusal,omitempty"`
	ToolCalls []any  `json:"tool_calls,omitempty"`
}

type OpenAIRequestBodyChat struct {
	Messages            []OpenAIRequestBodyChatMessage  `json:"messages"`
	Model               string                          `json:"model"`
	FrequencyPenalty    int                             `json:"frequency_penalty,omitempty"`
	FunctionCall        any                             `json:"function_call,omitempty"` // Deprecated in favor of `tool_choice`
	Functions           []any                           `json:"functions,omitempty"`     // Deprecated in favor of `tools`
	LogitBias           map[string]any                  `json:"logit_bias,omitempty"`
	Logprobs            int                             `json:"logprobs,omitempty"`
	MaxCompletionTokens int                             `json:"max_completion_tokens"`
	MaxTokens           int                             `json:"max_tokens,omitempty"` // Deprecated in favor of `max_completion_tokens`
	Metadata            map[string]any                  `json:"metadata,omitempty"`
	N                   int                             `json:"n,omitempty"`
	ParallelToolCalls   bool                            `json:"parallel_tool_calls,omitempty"`
	Prediction          any                             `json:"prediction,omitempty"`
	PresencePenalty     int                             `json:"presence_penalty,omitempty"`
	ResponseFormat      any                             `json:"response_format,omitempty"`
	Seed                int                             `json:"seed,omitempty"`
	Stop                any                             `json:"stop,omitempty"` // string / array / null
	Stream              bool                            `json:"stream,omitempty"`
	StreamOptions       *OpenAIRequestBodyStreamOptions `json:"stream_options,omitempty"`
	Temperature         int                             `json:"temperature,omitempty"`
	ToolChoice          any                             `json:"tool_choice,omitempty"` // string / object / null
	Tools               []any                           `json:"tools,omitempty"`       // array / null
	TopLogProbs         int                             `json:"top_logprobs,omitempty"`
	TopP                int                             `json:"top_p,omitempty"`
	User                string                          `json:"user,omitempty"`
	// Not included but present in the OpenAI spec:
	// * audio (https://platform.openai.com/docs/api-reference/chat/create#chat-create-audio)
	// * modalities (https://platform.openai.com/docs/api-reference/chat/create#chat-create-modalities)
	// * reasoning_effort (o-series models only)
	// * service_tier (Likely N/A outside of the  OpenAI platform)
	// * store (Likely N/A outside of the  OpenAI platform)
	// * web_search_options
	//
	// vLLM exra params: https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html#id7
}

func (b *OpenAIRequestBodyChat) Validate(supportedModels []string) (string, bool, error) {
	if b.Model == "" {
		return "", false, newValidationError(ErrMissingRequiredField, "missing required field: model")
	}

	if !slices.Contains(supportedModels, b.Model) {
		return "", false, newValidationError(ErrUnsupportedModel, "unsupported model: "+b.Model)
	}

	if b.Messages == nil {
		return "", false, newValidationError(ErrMissingRequiredField, "missing required field: messages")
	}

	// In order to correctly process refunds we need to ensure that usage is always
	// included in the response, even if the request has explicitly disabled it.
	dirty := false
	if b.Stream && (b.StreamOptions == nil || !b.StreamOptions.IncludeUsage) {
		b.StreamOptions = &OpenAIRequestBodyStreamOptions{IncludeUsage: true}
		dirty = true
	}

	return b.Model, dirty, nil
}

func (v BodyValidator) ValidateWithBadge(r *http.Request, b *credentialing.Badge) error {
	if r.ContentLength > int64(v.MaxSize) {
		return newValidationError(ErrBodyTooLarge, "content-length exceeds max size")
	}

	// TODO[Val]: Should be route-aware (e.g., this is not suitable for Ollama's `GET /api/tags`).
	if r.Body == nil {
		return newValidationError(ErrEmptyBody, "empty body")
	}

	// This is better than using `http.MaxBytesReader` because it gives us more control of what is
	// written to a response (e.g., in addition to a `reader` instance, `MaxBytesReader` also requires
	// `w http.ResponseWriter` as its argument, which it uses to set some internal flags).
	limitedReader := &io.LimitedReader{R: r.Body, N: int64(v.MaxSize + 1)} // +1 to check if the body exceeds the limit.
	body, err := io.ReadAll(limitedReader)

	if err != nil {
		return newValidationError(ErrReadingBody, "error reading body: "+err.Error())
	}
	if len(body) == 0 {
		return newValidationError(ErrEmptyBody, "empty body")
	}
	if limitedReader.N <= 0 {
		return newValidationError(ErrBodyTooLarge, "body exceeds max size")
	}
	// Potential tampering attempt
	if r.ContentLength != int64(len(body)) {
		return newValidationError(ErrContentLengthMismatch, "content-length does not match body size")
	}

	r.Body = io.NopCloser(bytes.NewReader(body))

	route := r.URL.Path
	bodyBuilder, found := v.RouteBodyTypes[route]
	if !found {
		return fmt.Errorf("internal configuration error: no body builder defined for route %s", route)
	}
	requestBody := bodyBuilder()

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&requestBody); err != nil {
		return newValidationError(ErrInvalidJSON, "failed to decode request body: "+err.Error())
	}

	if requestBody == nil {
		return newValidationError(ErrInvalidJSON, "null request body")
	}

	// Ensure there are no additional JSON objects appended.
	if decoder.More() {
		return newValidationError(ErrMultipleJSONObjects, "multiple JSON objects in request body")
	}

	// Route-specific validation for strictly required fields.
	modelRequested, dirty, err := requestBody.Validate(v.SupportedModels)
	if err != nil {
		return err
	}

	if !slices.Contains(b.Credentials.Models, modelRequested) {
		return newValidationError(ErrUnsupportedModel, "unsupported model: "+modelRequested)
	}

	// If the deserialized request body was mutated, we should re-serialize it and
	// replace the original request body with the mutated one.
	if dirty {
		body, err = json.Marshal(requestBody)
		if err != nil {
			return newValidationError(ErrInvalidJSON, "failed to encode request body: "+err.Error())
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	return nil
}

type HostnameValidator struct{}

func (HostnameValidator) Validate(r *http.Request) error {
	if r.Host != messages.UnroutableHostname {
		return newValidationError(ErrUnknownHostname, "unknown hostname")
	}
	return nil
}
