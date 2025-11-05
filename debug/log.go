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

package debug

import (
	"log/slog"
	"os"
	"strings"
	"time"

	slogenv "github.com/cbrewster/slog-env"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"github.com/openpcc/openpcc/otel/otelutil"
)

// SetupLog sets up the logger for the service, falling back to the INFO
// level if the environment variable GO_LOG is not set.
func SetupLog(cmdID string, globalAttrs ...any) {
	setupLogHelper(cmdID, slog.LevelInfo, "json", true, globalAttrs...)
}

// SetupLogForCLI sets up the logger for any user-facing CLIs, falling back to the
// specified level if the environment variable GO_LOG is not set.
func SetupLogForCLI(cmdID string, defaultLevel slog.Level, globalAttrs ...any) {
	setupLogHelper(cmdID, defaultLevel, "text", false, globalAttrs...)
}

// setupLogHelper is the internal helper that does the actual work, and is intentionally not exported.
func setupLogHelper(cmdID string, defaultLogLevel slog.Level, defaultLogFormat string, defaultLogSource bool, globalAttrs ...any) {
	replacer := func(_ []string, a slog.Attr) slog.Attr {
		const prefix = "/T/"
		if a.Key == slog.SourceKey {
			if source, ok := a.Value.Any().(*slog.Source); ok {
				// Split the file path on the module name, and keep the last half
				// This is to make the logs more readable
				parts := strings.Split(source.File, prefix)
				if len(parts) == 2 {
					source.File = parts[1]
				}
			}
		}
		if err, ok := a.Value.Any().(error); ok {
			aErr := tint.Err(err)
			aErr.Key = a.Key
			return aErr
		}
		return a
	}
	format := strings.ToLower(os.Getenv("LOG_FORMAT"))
	if format == "" {
		format = defaultLogFormat
	}

	addSource := defaultLogSource
	addSourceEnv := strings.ToLower(os.Getenv("LOG_SOURCE"))
	if addSourceEnv == "true" || addSourceEnv == "1" {
		addSource = true
	}

	var handler slog.Handler
	handlerOptions := slog.HandlerOptions{AddSource: addSource, ReplaceAttr: replacer}

	// Explicitly configure the default log level, instead of falling back to the slogenv
	// library's default of INFO. This default will be used if the GO_LOG environment variable is not set.
	slogenvOptions := []slogenv.Opt{slogenv.WithDefaultLevel(defaultLogLevel)}

	switch format {
	case "text":
		handler = slogenv.NewHandler(tint.NewHandler(os.Stderr, &tint.Options{
			TimeFormat:  time.TimeOnly,
			ReplaceAttr: handlerOptions.ReplaceAttr,
			AddSource:   handlerOptions.AddSource,
			NoColor:     !isatty.IsTerminal(os.Stderr.Fd()),
		}), slogenvOptions...)
	case "json":
		handler = slogenv.NewHandler(slog.NewJSONHandler(os.Stderr, &handlerOptions), slogenvOptions...)
	default:
		handler = slogenv.NewHandler(slog.NewTextHandler(os.Stderr, &handlerOptions), slogenvOptions...)
	}

	var logLevel string
	if le, ok := os.LookupEnv("GO_LOG"); ok {
		logLevel = le
	} else {
		// Note that we can't just call string(defaultLogLeveler) here because it's a slog.Level (enum) type.
		// Instead, we have to use slog's Level.String() method.
		logLevel = defaultLogLevel.String()
	}

	handler = otelutil.NewSlogHandler(handler)

	logger := slog.New(handler).With("cmd_id", cmdID).With(globalAttrs...)
	slog.SetDefault(logger)
	slog.Debug("setting up log", "format", format, "level", logLevel)
}
