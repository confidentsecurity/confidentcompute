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

package cloud

import (
	"context"
	"errors"
	"fmt"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
)

type GCPRIGMAddrFinderConfig struct {
	// Project is the GCP project the MIG is in
	Project string `yaml:"project"`
	// Region is the GCP region the MIG is in
	Region string `yaml:"region"`
	// InstanceGroupManager is the ID of the instance group manager to be queried
	InstanceGroupManager string `yaml:"instance_group_manager"`
}

func (c *GCPRIGMAddrFinderConfig) Empty() bool {
	return c.Project == "" && c.Region == "" && c.InstanceGroupManager == ""
}

// GCPRIGMAddrFinder finds addresses of nodes in an region instance group manager.
type GCPRIGMAddrFinder struct {
	cfg        *GCPRIGMAddrFinderConfig
	client     *compute.RegionInstanceGroupManagersClient
	filterFunc func(s string) bool
}

func NewGCPAddrFinder(cfg *GCPRIGMAddrFinderConfig, client *compute.RegionInstanceGroupManagersClient) *GCPRIGMAddrFinder {
	return &GCPRIGMAddrFinder{
		cfg:    cfg,
		client: client,
	}
}

// FilterFunc can optionally be provided to filter returned addresses. Only addresses for which filterFunc
// returns true are kept.
func (f *GCPRIGMAddrFinder) FilterFunc(filterFunc func(s string) bool) {
	f.filterFunc = filterFunc
}

func (f *GCPRIGMAddrFinder) FindAddrs(ctx context.Context) ([]string, error) {
	req := &computepb.ListManagedInstancesRegionInstanceGroupManagersRequest{
		Project:              f.cfg.Project,
		Region:               f.cfg.Region,
		InstanceGroupManager: f.cfg.InstanceGroupManager,
	}

	var addrs []string
	it := f.client.ListManagedInstances(ctx, req)
	for {
		instance, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to retrieve next instance: %w", err)
		}

		if !isHealthy(instance) {
			continue
		}

		name := instance.GetName()
		zone, zoneOk := parseZone(instance.GetInstance())
		if !zoneOk {
			continue
		}

		addr := fmt.Sprintf("%s.%s.c.%s.internal", name, zone, f.cfg.Project)
		if f.filterFunc != nil && !f.filterFunc(addr) {
			continue
		}

		addrs = append(addrs, addr)
	}

	return addrs, nil
}

func parseZone(instanceURL string) (string, bool) {
	parts := strings.Split(instanceURL, "/")
	// Find the "zones" part and get the next element
	for i, part := range parts {
		if part == "zones" && i+1 < len(parts) {
			return parts[i+1], true
		}
	}

	return "", false
}

func isHealthy(instance *computepb.ManagedInstance) bool {
	// Should be running.
	if instance.GetInstanceStatus() != computepb.ManagedInstance_RUNNING.String() {
		return false
	}

	// Should have no action being applied on them.
	if instance.GetCurrentAction() != computepb.ManagedInstance_NONE.String() {
		return false
	}

	// All healthchecks for this instance should be healthy.
	for _, check := range instance.GetInstanceHealth() {
		if check.GetDetailedHealthState() != computepb.ManagedInstanceInstanceHealth_HEALTHY.String() {
			return false
		}
	}

	return true
}
