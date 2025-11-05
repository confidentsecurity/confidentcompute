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
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/confidentcompute/computeworker/output"
	"github.com/confidentsecurity/twoway"
	ollama "github.com/ollama/ollama/api"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/chunk"
	"github.com/openpcc/openpcc/messages"
	"github.com/openpcc/openpcc/models"
	"github.com/openpcc/openpcc/otel/otelutil"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var errNoRefundAvailable = errors.New("no refund available")

type ValidationErrorMessage struct {
	Code    string `json:"code"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

func validationErrorMessageBody(err error) ([]byte, error) {
	var code string
	// if this is a validation error, use the string there
	var valErr ValidationError
	if errors.As(err, &valErr) {
		code = valErr.Code.String()
	} else {
		code = "ErrValidationUnknown"
	}

	errorMessage := ValidationErrorMessage{
		Code:    code,
		Error:   "Request Validation Error",
		Message: err.Error(),
	}
	return json.Marshal(errorMessage)
}

func validationErrorMessageCode(err error) int {
	// if this is a validation error, use the string there
	var valErr ValidationError
	if errors.As(err, &valErr) && valErr.Code == ErrUnsupportedPath {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// RequestDecapsulationError indicates thet request decapsulation failed.
type RequestDecapsulationError struct {
	Err error
}

func (e *RequestDecapsulationError) Error() string {
	return "request decapsulation error: " + e.Err.Error()
}

type Worker struct {
	config      *Config
	ctx         context.Context
	httpClient  *http.Client
	receiver    *twoway.MultiRequestReceiver
	validator   Validator
	reader      io.Reader
	writer      io.Writer
	diagnostics map[string]string
}

func NewWithDependencies(
	ctx context.Context,
	config *Config,
	httpClient *http.Client,
	receiver *twoway.MultiRequestReceiver,
	reader io.Reader,
	writer io.Writer,
	diagnostics map[string]string,
) *Worker {
	ctx, span := otelutil.Tracer.Start(ctx, "computeworker.NewWithDependencies")
	defer span.End()
	span.SetStatus(codes.Ok, "")

	return &Worker{
		ctx:         ctx,
		config:      config,
		httpClient:  httpClient,
		receiver:    receiver,
		validator:   DefaultValidator(config.BadgePublicKey, config.Models),
		reader:      reader,
		writer:      writer,
		diagnostics: diagnostics,
	}
}

func New(ctx context.Context, config *Config, reader io.Reader, writer io.Writer) (*Worker, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "computeworker.New")
	defer span.End()

	_, err := url.Parse(config.LLMBaseURL)
	if err != nil {
		return nil, otelutil.Errorf(span, "invalid LLMBaseURL: %w", err)
	}

	tpmSuite := &tpmSuiteAdapter{
		ctx:    ctx,
		config: config.TPM,
		kemID:  hpke.KEM_P256_HKDF_SHA256,
		kdfID:  hpke.KDF_HKDF_SHA256,
		aeadID: hpke.AEAD_AES128GCM,
	}

	receiver, err := twoway.NewMultiRequestReceiverWithCustomSuite(tpmSuite, 0, nil, rand.Reader)
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to create multi request receiver: %w", err)
	}

	httpClient := &http.Client{
		Timeout:   config.Timeout,
		Transport: otelutil.NewTransport(chunk.NewHTTPTransport(chunk.DefaultDialTimeout)),
	}

	diagnostics, err := LoadDiagnosticResponseBodies()
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to load diagnostics response bodies: %w", err)
	}

	span.SetStatus(codes.Ok, "")
	return NewWithDependencies(ctx, config, httpClient, receiver, reader, writer, diagnostics), nil
}

type StatusRecorderWriter struct {
	http.ResponseWriter
	StatusCode int
}

func (sr *StatusRecorderWriter) WriteHeader(code int) {
	sr.StatusCode = code
	sr.ResponseWriter.WriteHeader(code)
}

func (s *Worker) Run() error {
	ctx, span := otelutil.Tracer.Start(s.ctx, "computeworker.Run")
	defer span.End()

	decapCtx, decapSpan := otelutil.Tracer.Start(ctx, "computeworker.Run.Decapsulate")
	req, opener, err := messages.DecapsulateRequest(decapCtx, s.receiver, s.config.RequestParams.EncapsulatedKey, s.config.RequestParams.MediaType, s.reader)
	if err != nil {
		decapSpan.End()
		err = &RequestDecapsulationError{Err: err}
		return otelutil.RecordError(span, err)
	}
	decapSpan.End()

	req = req.WithContext(ctx)

	var resp *http.Response

	// Validate the request.
	if err = s.validator.Validate(req); err != nil {
		slog.InfoContext(s.ctx, "Request Validation Error", "err", err)

		errorBytes, valErr := validationErrorMessageBody(err)
		if valErr != nil {
			slog.ErrorContext(s.ctx, "Failed to marshal validation error message", "err", valErr)
			return valErr
		}

		resp = &http.Response{
			StatusCode: validationErrorMessageCode(err),
			Status:     http.StatusText(http.StatusBadRequest),
			Header:     http.Header{},
			Body:       io.NopCloser(bytes.NewReader(errorBytes)),
		}
		resp.Header.Add("Content-Type", "application/json")
	} else {
		slog.DebugContext(s.ctx, "Handling Confidential Request")

		resp, err = s.handle(req)
		if err != nil {
			return otelutil.Errorf(span, "failed to handle request: %w", err)
		}
	}

	refundRecorder := newRefundRecorder(req.URL.Path, resp.Body)
	resp.Body = refundRecorder

	defer func() {
		closeErr := resp.Body.Close()
		// The outer func returns err directly, so safe to set it here.
		err = errors.Join(err, closeErr)
	}()

	_, encapSpan := otelutil.Tracer.Start(ctx, "computeworker.Run.Encapsulate")
	sealer, respMediaType, err := messages.EncapsulateResponse(opener, resp)
	if err != nil {
		encapSpan.End()
		return otelutil.Errorf(span, "failed to encapsulate response: %w", err)
	}
	encapSpan.End()

	ctChunkLen, chunked := sealer.MaxCiphertextChunkLen()
	if !chunked {
		ctChunkLen = 0
	}

	// encode the output
	encoder, err := output.NewEncoder(output.Header{
		MediaType:   respMediaType,
		MaxChunkLen: ctChunkLen,
	}, s.writer)
	if err != nil {
		return otelutil.Errorf(span, "failed to create output encoder: %w", err)
	}

	// write the ciphertext
	_, writeSpan := otelutil.Tracer.Start(ctx, "computeworker.Run.WriteCiphertext")
	if chunked {
		buf := make([]byte, ctChunkLen)
		_, err = io.CopyBuffer(encoder, sealer, buf)
		if err != nil {
			writeSpan.End()
			return otelutil.Errorf(span, "failed to write chunked ciphertext: %w", err)
		}
	} else {
		_, err = io.Copy(encoder, sealer)
		if err != nil {
			writeSpan.End()
			return otelutil.Errorf(span, "failed to write ciphertext: %w", err)
		}
	}
	writeSpan.End()

	// note: nil refund indicates no refund.
	refund, hasRefund, err := s.newRefund(resp.StatusCode, refundRecorder)
	if err != nil {
		return otelutil.Errorf(span, "failed to determine refund: %w", err)
	}

	footer := output.Footer{}
	if hasRefund {
		footer.Refund = &refund
	}
	err = encoder.Close(footer)
	if err != nil {
		return otelutil.Errorf(span, "failed to close output encoder: %w", err)
	}

	span.SetStatus(codes.Ok, "")
	// Important we return err here instead of nil to catch any errors during deferred cleanup.
	return err
}

func (s *Worker) newRefund(code int, refundRecorder refundRecorder) (currency.Value, bool, error) {
	// Refund credits:
	// * For 2xx responses: Calculate a refund based on recorded usage.
	// * For 4xx responses: Do a full refund. This is our goodwill for now, see CS-607.
	// * For 5xx responses: Do a full refund. This is likely our fault we shouldn't charge for it
	var (
		refund currency.Value
		err    error
	)
	switch {
	case code >= 200 && code < 300:
		refund, err = refundRecorder.Refund(s.config.RequestParams.CreditAmount)
	case code >= 400:
		refund, err = currency.Exact(s.config.RequestParams.CreditAmount)
	default:
		return currency.Zero, false, fmt.Errorf("unexpected status code: %d", code)
	}
	if err != nil {
		if errors.Is(err, errNoRefundAvailable) {
			slog.WarnContext(s.ctx, "no refund available")
			// nothing to write.
			return currency.Zero, false, nil
		}
		return currency.Zero, false, fmt.Errorf("failed to create refund: %w", err)
	}

	return refund, true, nil
}

func (s *Worker) handle(req *http.Request) (*http.Response, error) {
	ctx, span := otelutil.Tracer.Start(req.Context(), "computeworker.handle")
	defer span.End()

	origHeader := req.Header
	// recreate the request but point it to the local LLM instance.
	endpointURL, err := url.Parse(s.config.LLMBaseURL)
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to create LLM request. URL parsing error: %w", err)
	}
	endpointURL.Path = req.URL.Path

	req, err = http.NewRequestWithContext(ctx, req.Method, endpointURL.String(), req.Body)
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to create LLM request: %w", err)
	}

	// Headers we forward to the LLM. We set them from scratch and don't use the headers from req.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept", "application/x-ndjson")

	exec := origHeader.Get("X-Confsec-Exec")
	switch {
	case exec == "noop":
		recordConfsecExecHeaderInTrace(ctx, exec)
		return s.recordNoopResponse()
	case exec == "simulated":
		recordConfsecExecHeaderInTrace(ctx, exec)
		return s.recordSimulatedResponse()
	case strings.HasPrefix(exec, "diagnostic-"):
		recordConfsecExecHeaderInTrace(ctx, exec)
		scenario, _ := strings.CutPrefix(exec, "diagnostic-")
		return s.recordDiagnosticResponse(ctx, scenario), nil
	default:
		ctx, span := otelutil.Tracer.Start(ctx, "computeworker.handle.Do")
		defer span.End()
		resp, err := s.httpClient.Do(req.WithContext(ctx))
		if err != nil {
			return nil, otelutil.Errorf(span, "request to the llm failed: %w", err)
		}
		return resp, nil
	}
}

func recordConfsecExecHeaderInTrace(ctx context.Context, exec string) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("confsec.exec", exec))
}

// recordNoopResponse returns a minimal Ollama response without performing any inference.
// The response consists of 2 lines that are technically streamed back to the client.
// Intended for load and e2e testing. Note that this response will include necessary fields for refunds to work.
func (*Worker) recordNoopResponse() (*http.Response, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(ollama.GenerateResponse{
		Model:     "none",
		CreatedAt: time.Now(),
		Response:  "noop",
	}); err != nil {
		return nil, fmt.Errorf("failed to encode response: %w", err)
	}
	if err := enc.Encode(ollama.GenerateResponse{
		Model:      "none",
		CreatedAt:  time.Now(),
		Done:       true,
		DoneReason: "stop",
		Metrics: ollama.Metrics{
			PromptEvalCount: 1, // Struct field has `omitempty` tag, so we need to set it to a non-zero value.
			EvalCount:       4, // "noop" has 4 characters.
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to encode done response: %w", err)
	}

	return &http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type": []string{"application/x-ndjson"},
			"Date":         []string{time.Now().Format(http.TimeFormat)},
		},
		TransferEncoding: []string{"chunked"},
		Body:             io.NopCloser(&buf),
	}, nil
}

// recordSimulatedResponse returns a representative Ollama-like streaming response without performing inference.
// These responses are intended to mask traffic (which implies that they work with refunds).
func (s *Worker) recordSimulatedResponse() (*http.Response, error) {
	const avgTokenDelay = 4 * time.Microsecond
	maxTokenN := s.config.RequestParams.CreditAmount / models.OutputTokenCreditMultiplier

	bigTokenN, err := rand.Int(rand.Reader, big.NewInt(maxTokenN))
	if err != nil {
		return nil, fmt.Errorf("failed to generate token count: %w", err)
	}

	tokenN := bigTokenN.Int64()

	// Have 10% of requests hit the token limit and issue no refund.
	if n, err := rand.Int(rand.Reader, big.NewInt(100)); err != nil {
		return nil, fmt.Errorf("failed to generate random number: %w", err)
	} else if n.Int64() <= 10 {
		tokenN = maxTokenN
	}

	r, w := io.Pipe()
	go s.writeSimulatedStreamingBody(w, tokenN, avgTokenDelay)

	return &http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type": []string{"application/x-ndjson"},
			"Date":         []string{time.Now().Format(http.TimeFormat)},
		},
		TransferEncoding: []string{"chunked"},
		Body:             r,
	}, nil
}

func (*Worker) writeSimulatedStreamingBody(w io.WriteCloser, tokenN int64, avgTokenDelay time.Duration) {
	defer func() {
		err := w.Close()
		if err != nil {
			slog.Error("failed to close fake body writer", "error", err)
		}
	}()

	startTime := time.Now()
	enc := json.NewEncoder(w)
	for i := int64(0); i < tokenN; i++ {
		// Generate a variable length between 0-2 and we'll add that to a base
		// length below of 3 to have tokens between 3-5 characters.
		tokenLen, err := rand.Int(rand.Reader, big.NewInt(int64(3)))
		if err != nil {
			slog.Error("failed to generate token len", "error", err)
			return
		}

		// Write out a random tokens in the Ollama format.
		token := randText(3 + int(tokenLen.Int64()))
		if err := enc.Encode(ollama.GenerateResponse{Model: "simulated", CreatedAt: time.Now(), Response: token}); err != nil {
			slog.Error("failed to encode response", "error", err)
			return
		}

		// Simulate delay in between tokens.
		jitter, err := rand.Int(rand.Reader, big.NewInt(int64(avgTokenDelay)))
		if err != nil {
			slog.Error("failed to generate refund amount", "error", err)
			return
		}
		time.Sleep(avgTokenDelay/2 + time.Duration(jitter.Int64()+1))
	}

	elapsed := time.Since(startTime)

	// Mark the response as complete.
	if err := enc.Encode(ollama.GenerateResponse{
		Model:      "simulated",
		CreatedAt:  time.Now(),
		Done:       true,
		DoneReason: "stop",
		Context: []int{ // context simply pads to a typical size
			12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345,
			12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345,
			12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345,
			12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345, 12345,
		},
		Metrics: ollama.Metrics{ // these values are simply to pad; not necessarily accurate
			TotalDuration:      elapsed,
			LoadDuration:       elapsed,
			PromptEvalCount:    int(tokenN),
			PromptEvalDuration: elapsed,
			EvalCount:          int(tokenN),
			EvalDuration:       elapsed,
		},
	}); err != nil {
		slog.Error("failed to encode done response", "error", err)
		return
	}
}

// recordDiagnosticResponse records ollama-like hardcoded responses without performing interference.
// Mainly useful for end-to-end tests or debugging issues.
func (s *Worker) recordDiagnosticResponse(ctx context.Context, diagnostic string) *http.Response {
	body, ok := s.diagnostics[diagnostic]
	if !ok {
		// We support the following additional diagnostic headers, whose responses are
		// NOT checked in (and are NOT valid ollama responses) due to size constraints:
		//
		// - no-stream-extra-large-json
		// - stream-extra-large-json
		//
		// Both of these diagnostics return a simple json response body that is exactly 1 MiB in size.
		switch diagnostic {
		case "no-stream-extra-long":
			// Craft a valid Ollama response that is exactly 1 MiB with refund fields
			baseResponse := `{"model":"none","created_at":"2025-01-01T00:00:00Z","response":"`
			suffix := `","done":true,"done_reason":"stop","prompt_eval_count":10,"eval_count":1000}`
			contentSize := 1024*1024 - len(baseResponse) - len(suffix)
			content := strings.Repeat("a", contentSize)
			body = baseResponse + content + suffix
		case "stream-extra-long":
			// The goal here is to stream 1 MiB of data total, with each line containing 90 bytes of data,
			// to match a typical LLM response (which usually contain ~1 token, or 5 characters in this case, of data).
			finalLine := `{"model":"diagnostic","created_at":"2025-01-01T00:00:00Z","response":"","done":true,"done_reason":"stop","prompt_eval_count":1,"eval_count":1000}`
			// Hard code "hello" response to ensure line is exactly 90 bytes.
			streamLine := `{"model":"diagnostic","created_at":"2025-01-01T00:00:00Z","response":"hello","done":false}`
			// Subtract 1 for the final line.
			linesToStream := (1024*1024)/90 - 1

			body = strings.Repeat(streamLine+"\n", linesToStream) + finalLine + "\n"
		default:
			// Unknown diagnostic, return a general bad request response.
			// NB: This can be used to simulate a "zero byte" response (by sending a bunk diagnostic header).
			resp := &http.Response{
				StatusCode: http.StatusBadRequest,
				Status:     http.StatusText(http.StatusBadRequest),
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewReader([]byte{})),
			}
			resp.Header.Add("Content-Type", "text/plain; charset=utf-8")
			return resp
		}
	}

	// create the diagnostic response
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     http.StatusText(http.StatusOK),
		Header:     http.Header{},
	}

	switch {
	case diagnostic == "error":
		// error responses are always known length.
		resp.StatusCode = http.StatusNotFound
		resp.Status = http.StatusText(http.StatusNotFound)
		resp.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp.ContentLength = int64(len(body))
		resp.Body = io.NopCloser(strings.NewReader(body))
	case strings.Contains(diagnostic, "no-stream"):
		// no-stream responses are known length.
		resp.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp.ContentLength = int64(len(body))
		resp.Body = io.NopCloser(strings.NewReader(body))
	default:
		// streaming response, unknown-length.
		resp.Header.Set("Content-Type", "application/x-ndjson")
		resp.ContentLength = -1
		// How long to wait between streaming chunks, to simulate a real LLM response.
		// Note that this is critical for benchmarking our system, since LLMs in streaming
		// mode won't dump all the response data at once.
		streamChunkDelay := 15 * time.Millisecond
		resp.Body = newStreamingBody(ctx, []byte(body), streamChunkDelay)
	}

	return resp
}

func newStreamingBody(ctx context.Context, body []byte, chunkPause time.Duration) io.ReadCloser {
	// chunks are lines + their newline.
	chunks := bytes.Split(body, []byte("\n"))
	// add back the newlines to all but the last chunk.
	for i := range chunks {
		if i != len(chunks)-1 {
			chunks[i] = append(chunks[i], '\n')
		}
	}

	r, w := io.Pipe()
	go func() {
		defer w.Close()
		for _, line := range chunks {
			select {
			case <-ctx.Done():
				w.CloseWithError(ctx.Err())
				return
			case <-time.After(chunkPause):
				// Continue with write
			}

			_, err := w.Write(line)
			if err != nil {
				w.CloseWithError(err)
				return
			}
		}
	}()

	return r
}

func calculateRefund(numInputTokens, numOutputTokens float64, creditAmount int64) (currency.Value, error) {
	creditUsed := (numInputTokens * models.InputTokenCreditMultiplier) + (numOutputTokens * models.OutputTokenCreditMultiplier)

	refund := float64(creditAmount) - creditUsed

	if refund > 0 {
		roundingFactor, err := currency.RandFloat64()
		if err != nil {
			slog.Error("failed to generate random float for rounding", "error", err)
			return currency.Zero, fmt.Errorf("failed to generate random float for rounding: %w", err)
		}
		refundAmount, err := currency.Rounded(refund, roundingFactor)
		if err != nil {
			slog.Error("failed to round refund amount", "error", err, "refund", refund)
			return currency.Zero, fmt.Errorf("failed to round refund: %w", err)
		}
		debugAmount, err := refundAmount.Amount()
		if err != nil {
			slog.Error("failed to get refund amount", "error", err)
			return currency.Zero, fmt.Errorf("failed to get refund amount: %w", err)
		}
		slog.Debug("refund calculations", "creditAmount", creditAmount, "creditUsed", creditUsed, "refund", refund, "roundedRefund", debugAmount)
		return refundAmount, nil
	}

	return currency.Zero, errNoRefundAvailable
}

// Mostly copied from crypto/rand. Not available until Go 1.24.
func randText(n int) string {
	b := make([]byte, 0, n)
	for len(b) < n {
		b = append(b, []byte(rand.Text())...)
	}

	return string(b[:n])
}
