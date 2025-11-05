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

package computeboot_test

import (
	"testing"

	"github.com/confidentsecurity/confidentcompute/computeboot"
	"github.com/stretchr/testify/require"
)

func TestSetupEncryptionKeys_Success(t *testing.T) {
	operator, err := computeboot.NewTPMOperatorWithConfig(&computeboot.TPMConfig{
		PrimaryKeyHandle:        0x81000001,
		ChildKeyHandle:          0x81000002,
		REKCreationTicketHandle: 0x01c0000A,
		REKCreationHashHandle:   0x01c0000B,
		AttestationKeyHandle:    0x81000003,
		TPMType:                 computeboot.InMemorySimulator,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := operator.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	err = operator.SetupEncryptionKeys()

	require.NoError(t, err)
}
