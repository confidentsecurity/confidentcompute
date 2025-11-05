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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/confidentsecurity/confidentcompute/cmd/compute_worker/exitcodes"
	"github.com/confidentsecurity/confidentcompute/computeworker"
	"github.com/confidentsecurity/confidentcompute/computeworker/output"
	"github.com/openpcc/openpcc/ahttp"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/messages"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/router/api"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/protobuf/proto"
)

func (s *Service) generateHandler(w http.ResponseWriter, r *http.Request) {
	ctx, span := otelutil.Tracer.Start(r.Context(), "routercom.generateHandler")
	defer span.End()

	r = r.WithContext(ctx)

	requestParams, err := s.requestParams(r)
	if err != nil {
		otelutil.RecordError2(span, fmt.Errorf("failed to parse request params: %w", err))
		httpfmt.BinaryBadRequest(w, r, err.Error())
		return
	}

	stdout, closeFunc, err := s.runWorker(ctx, r.Body, requestParams)
	if err != nil {
		slog.ErrorContext(ctx, "failed to run worker", "error", err)
		otelutil.RecordError2(span, fmt.Errorf("failed to run worker: %w", err))
		if closeFunc != nil {
			code := closeFunc(ctx)
			writeResponseForExitCode(w, r, code)
		} else {
			httpfmt.BinaryServerError(w, r)
		}
		return
	}

	_, decoderSpan := otelutil.Tracer.Start(ctx, "routercom.generateHandler.newDecoder")
	decoder, err := output.NewDecoder(stdout)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create output decoder", "error", err)
		otelutil.RecordError2(span, fmt.Errorf("failed to create output decoder: %w", err))
		code := closeFunc(ctx)
		writeResponseForExitCode(w, r, code)
		decoderSpan.End()
		return
	}
	decoderSpan.End()

	defer func(ctx context.Context) {
		// We'll do clean up in a separate goroutine so the handler can return
		// once it has read everything it needs from stdout.
		s.commandsWG.Add(1)
		go func() {
			closeFunc(ctx)
			s.commandsWG.Done()
		}()
	}(ctx)

	header := decoder.Header()

	// We're writing an encrypted response. Always attempt to add the refund trailer.
	w.Header().Add("Trailer", ahttp.NodeRefundAmountHeader)
	w.Header().Set("Content-Type", header.MediaType)

	ctx, copyBodySpan := otelutil.Tracer.Start(ctx, "routercom.generateHandler.copyBody")
	if header.IsChunked() {
		// should already be implied since we're setting a trailer header, but just to be sure.
		w.Header().Set("Transfer-Encoding", "chunked")
	}
	_, err = decoder.WriteTo(w)
	if err != nil {
		copyBodySpan.End()
		slog.ErrorContext(ctx, "failed to write response body", "error", err)
		otelutil.RecordError2(span, fmt.Errorf("failed to write response body: %w", err))
		return
	}
	copyBodySpan.End()

	s.handleRefundTrailer(ctx, w, decoder)

	span.SetStatus(codes.Ok, "")
}

// requestParams extracts the compute worker request parameters from the request and returns
// an error if these are invalid. The error is safe to return to the user and contains no technical
// information.
func (*Service) requestParams(r *http.Request) (computeworker.RequestParams, error) {
	// check if media type looks right.
	mediaType := r.Header.Get("Content-Type")
	if !messages.IsRequestMediaType(mediaType) {
		return computeworker.RequestParams{}, errors.New("invalid media type")
	}

	// check if encapsulated key looks right.
	b64EncapKey := r.Header.Get(api.EncapsulatedKeyHeader)
	if len(b64EncapKey) == 0 || len(b64EncapKey) > 512 {
		return computeworker.RequestParams{}, errors.New("invalid encapsulated key")
	}

	encapKey, err := base64.StdEncoding.DecodeString(b64EncapKey)
	if err != nil {
		return computeworker.RequestParams{}, errors.New("invalid encapsulated key")
	}

	// check if credit amount and encap key looks right.
	creditAmount, err := strconv.ParseInt(r.Header.Get(ahttp.NodeCreditAmountHeader), 10, 64)
	if err != nil {
		return computeworker.RequestParams{}, errors.New("invalid credit amount")
	}

	if creditAmount <= 0 {
		return computeworker.RequestParams{}, errors.New("credit amount must be greater than 0")
	}

	return computeworker.RequestParams{
		MediaType:       mediaType,
		EncapsulatedKey: encapKey,
		CreditAmount:    creditAmount,
	}, nil
}

type closeFunc func(ctx context.Context) int

func (s *Service) runWorker(ctx context.Context, ciphertext io.ReadCloser, p computeworker.RequestParams) (io.Reader, closeFunc, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "routercom.runWorker")
	defer span.End()

	commandPath, err := filepath.Abs(s.config.Worker.BinaryPath)
	if err != nil {
		return nil, nil, otelutil.Errorf(span, "failed to get absolute path: %w", err)
	}
	slog.DebugContext(ctx, "Running command", "path", commandPath)
	args := []string{
		"-tpm_key_handle", strconv.FormatUint(uint64(s.config.TPM.REKHandle), 10),
		"-tpm_base64_public_key", s.base64PubKey,
		"-tpm_base64_public_key_name", s.base64PubKeyName,
		"-tpm_base64_pcr_values", s.base64PCRValues,
		"-tpm_simulator_cmd_addr", s.config.TPM.SimulatorCmdAddress,
		"-tpm_simulator_platform_addr", s.config.TPM.SimulatorPlatformAddress,
		"-request_media_type", p.MediaType,
		"-request_credit_amount", strconv.FormatInt(p.CreditAmount, 10),
		"-request_encapsulated_key", base64.StdEncoding.EncodeToString(p.EncapsulatedKey),
	}
	if s.config.TPM.Device != "" {
		args = append(args, "-tpm_device", s.config.TPM.Device)
	}

	if s.config.TPM.Simulate {
		args = append(args, "-tpm_simulate")
	}

	if s.config.Worker.LLMBaseURL != "" {
		args = append(args, "-llm_base_url", s.config.Worker.LLMBaseURL)
	}

	if s.config.Worker.Timeout != 0 {
		args = append(args, "-service_timeout", s.config.Worker.Timeout.String())
	}

	if s.config.Worker.BadgePublicKey != "" {
		args = append(args, "-badge_public_key", s.config.Worker.BadgePublicKey)
	}

	for _, model := range s.config.Worker.Models {
		args = append(args, "-model", model)
	}

	// Pass trace context to worker.
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	args = append(args, "-traceparent", carrier["traceparent"])

	// SemGrep: it's ok, b/c commandPath is startup config, user cannot change command path
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(
		ctx,
		commandPath,
		args...,
	)
	// send sigterm signal for the command when the context is cancelled to trigger graceful shutdown and free vTPM session. Killing
	// the process does not allow our computeworker to clean up properly. Kill the process if SIGTERM fails.
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				slog.WarnContext(ctx, "failed to send SIGTERM to compute worker", "error", err)
				return cmd.Process.Kill()
			}
		}
		return nil
	}
	cmd.Stdin = ciphertext
	cmd.Stderr = os.Stderr
	// Explicitly set wait delay to 0 (no timeout), so the above I/O pipes are not closed during Wait calls.
	// This should be the default value, but it never hurts to be explicit.
	cmd.WaitDelay = 0 * time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, otelutil.Errorf(span, "failed to get stdout pipe: %w", err)
	}

	slog.DebugContext(ctx, "Starting the compute worker process")
	if err := cmd.Start(); err != nil {
		return nil, nil, otelutil.Errorf(span, "failed to start command: %w", err)
	}

	// Return a closer function so the caller can control the duration of the process.
	closeFunc := func(ctx context.Context) int {
		ctx, span := otelutil.Tracer.Start(ctx, "routercom.runWorker.close")
		defer span.End()

		slog.InfoContext(ctx, "Waiting for compute worker to exit", "pid", cmd.Process.Pid)
		err = cmd.Wait()
		if err != nil {
			// If err is due to context cancel, then we don't need to log an error.
			if !errors.Is(err, context.Canceled) {
				slog.ErrorContext(ctx, "failed to wait for command", "error", err)
			}
		}
		// If cmd.Wait has returned, we know the process has exited, so we don't need to kill it.

		slog.InfoContext(ctx, "Compute worker exited", "pid", cmd.Process.Pid, "exit_code", cmd.ProcessState.ExitCode())

		span.SetStatus(codes.Ok, "")
		return cmd.ProcessState.ExitCode()
	}

	span.SetStatus(codes.Ok, "")
	return stdout, closeFunc, nil
}

func writeResponseForExitCode(w http.ResponseWriter, r *http.Request, exitCode int) {
	switch exitCode {
	case exitcodes.RequestDecapsulationCode:
		httpfmt.BinaryBadRequest(w, r, "failed to decapsulate encrypted request")
	default:
		httpfmt.BinaryServerError(w, r)
	}
}

func (*Service) handleRefundTrailer(ctx context.Context, w http.ResponseWriter, decoder *output.Decoder) {
	ctx, span := otelutil.Tracer.Start(ctx, "routercom.handleRefundTrailer")
	defer span.End()

	footer, hasFooter := decoder.Footer()
	if !hasFooter {
		slog.ErrorContext(ctx, "output from worker is missing footer")
		return
	}

	if !footer.HasRefund() {
		return
	}

	currencyProto, err := footer.Refund.MarshalProto()
	if err != nil {
		slog.Error("failed to marshal refund to proto", "error", err)
		return
	}
	b, err := proto.Marshal(currencyProto)
	if err != nil {
		slog.Error("failed to marshal refund proto to binary", "error", err)
		return
	}

	w.Header().Set(ahttp.NodeRefundAmountHeader, base64.StdEncoding.EncodeToString(b))
}
