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
	"fmt"
	"log/slog"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

const (
	computeBootServiceName = "compute_boot.service"
	pollInterval           = 100 * time.Millisecond
	defaultExitTimeout     = 30 * time.Second
)

// WaitForComputeBootExit waits for the compute_boot systemd service to reach
// the "exited" state, which indicates that ExecStartPost has completed and
// any temporary compute_boot firewall rules have been cleaned up.
func WaitForComputeBootExit(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, defaultExitTimeout)
	defer cancel()

	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to systemd: %w", err)
	}
	defer conn.Close()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	slog.Info("waiting for compute_boot service to exit", "timeout", defaultExitTimeout)

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for %s to exit: %w", computeBootServiceName, ctx.Err())
		case <-ticker.C:
			// Check ActiveState
			activeStateProp, err := conn.GetUnitPropertyContext(ctx, computeBootServiceName, "ActiveState")
			if err != nil {
				return fmt.Errorf("failed to get ActiveState for %s: %w", computeBootServiceName, err)
			}

			activeState, ok := activeStateProp.Value.Value().(string)
			if !ok {
				return fmt.Errorf("ActiveState is not a string: %v", activeStateProp.Value.Value())
			}

			// Check SubState
			subStateProp, err := conn.GetUnitPropertyContext(ctx, computeBootServiceName, "SubState")
			if err != nil {
				return fmt.Errorf("failed to get SubState for %s: %w", computeBootServiceName, err)
			}

			subState, ok := subStateProp.Value.Value().(string)
			if !ok {
				return fmt.Errorf("SubState is not a string: %v", subStateProp.Value.Value())
			}

			slog.Info("checking compute_boot service state",
				"active_state", activeState,
				"sub_state", subState)

			// Check for failure states first
			if activeState == "failed" {
				return fmt.Errorf("compute_boot service failed: ActiveState=%s, SubState=%s", activeState, subState)
			}

			// For Type=oneshot with RemainAfterExit=true, we expect:
			// ActiveState=active, SubState=exited when successfully completed (including ExecStartPost)
			if activeState == "active" && subState == "exited" {
				slog.Info("compute_boot service has exited successfully")
				return nil
			}
		}
	}
}
