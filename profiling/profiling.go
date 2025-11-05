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

package profiling

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // #nosec G108 -- Profiling endpoints intentionally exposed for debugging
	"os"
	"time"

	"github.com/felixge/fgprof"
)

type Service string

const (
	Auth          Service = "auth"
	OHTTPRelay    Service = "ohttp_relay"
	Gateway       Service = "gateway"
	Bank          Service = "bank"
	CreditHole    Service = "credit_hole"
	Router        Service = "router"
	RouterCom     Service = "router_com"
	ComputeWorker Service = "compute_worker"
	Confsec       Service = "confsec"
)

// ServePort is the port on which the profiler UI will be served.
const ServePort = "6059"

// ServiceFromString returns the Service for the given string.
func ServiceFromString(s string) (Service, error) {
	switch s {
	case string(Auth):
		return Auth, nil
	case string(OHTTPRelay):
		return OHTTPRelay, nil
	case string(Gateway):
		return Gateway, nil
	case string(Bank):
		return Bank, nil
	case string(CreditHole):
		return CreditHole, nil
	case string(Router):
		return Router, nil
	case string(RouterCom):
		return RouterCom, nil
	case string(ComputeWorker):
		return ComputeWorker, nil
	case string(Confsec):
		return Confsec, nil
	default:
		return "", fmt.Errorf("unknown service: %s", s)
	}
}

// ProfilerConfig contains the profiler configuration for a given service.
type ProfilerConfig struct {
	// EnvVar is the name of the environment variable that must be set to true/1 for
	// profiling to be enabled for a given service.
	EnvVar string

	// Port is the port on which the profiler will listen.
	Port string
}

// GetProfilerConfig returns the profiler configuration for the given service.
func (s Service) GetProfilerConfig() ProfilerConfig {
	switch s {
	case Auth:
		return ProfilerConfig{
			EnvVar: "PROFILE_AUTH",
			Port:   "6060",
		}
	case OHTTPRelay:
		return ProfilerConfig{
			EnvVar: "PROFILE_OHTTP_RELAY",
			Port:   "6061",
		}
	case Gateway:
		return ProfilerConfig{
			EnvVar: "PROFILE_GATEWAY",
			Port:   "6062",
		}
	case Bank:
		return ProfilerConfig{
			EnvVar: "PROFILE_BANK",
			Port:   "6063",
		}
	case CreditHole:
		return ProfilerConfig{
			EnvVar: "PROFILE_CREDIT_HOLE",
			Port:   "6064",
		}
	case Router:
		return ProfilerConfig{
			EnvVar: "PROFILE_ROUTER",
			Port:   "6065",
		}
	case RouterCom:
		return ProfilerConfig{
			EnvVar: "PROFILE_ROUTER_COM",
			Port:   "6066",
		}
	case ComputeWorker:
		return ProfilerConfig{
			EnvVar: "PROFILE_COMPUTE_WORKER",
			Port:   "6067",
		}
	case Confsec:
		return ProfilerConfig{
			EnvVar: "PROFILE_CONFSEC",
			Port:   "6068",
		}
	default:
		return ProfilerConfig{}
	}
}

// InitProfilerIfEnabled initializes the profiler for the given service, if profiling
// is enabled via the corresponding environment variable.
func (s Service) InitProfilerIfEnabled() {
	config := s.GetProfilerConfig()
	enabledStr := os.Getenv(config.EnvVar)
	enabled := enabledStr == "1" || enabledStr == "true"
	if !enabled {
		return
	}
	http.DefaultServeMux.Handle("/debug/fgprof", fgprof.Handler())
	go func() {
		server := &http.Server{
			Addr:         "localhost:" + config.Port,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		log.Println(server.ListenAndServe())
	}()
}
