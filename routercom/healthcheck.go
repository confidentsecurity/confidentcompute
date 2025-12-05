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
	"net/http"

	"github.com/openpcc/openpcc/httpfmt"
)

// healthHandler returns a health check response compatible with Azure Application Health Extension v2.
// Azure expects: {"ApplicationHealthState": "Healthy"}
// GCP health checks only look at HTTP status code, so this is compatible with both.
// xref https://learn.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-health-extension?tabs=rest-api#rich-health-states
// TODO (CS-1277): We may want to adjust our router_com health check to start sooner and return unhealthy if attestation fails.
func (*Service) healthHandler(w http.ResponseWriter, r *http.Request) {
	type body struct {
		ApplicationHealthState string `json:"ApplicationHealthState"`
	}

	httpfmt.JSON(w, r, body{ApplicationHealthState: "Healthy"}, http.StatusOK)
}
