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

package output

import (
	"fmt"
	"math"

	pb "github.com/openpcc/openpcc/gen/protos/computeworker"
	"google.golang.org/protobuf/proto"
)

type Header struct {
	MediaType   string
	MaxChunkLen int
}

func (h Header) IsChunked() bool {
	return h.MaxChunkLen > 0
}

func (h Header) MarshalBinary() ([]byte, error) {
	if h.MaxChunkLen > math.MaxInt32 {
		return nil, fmt.Errorf("max chunk len is expected to fit in a int32, got %d", h.MaxChunkLen)
	}

	pbh := &pb.OutputHeader{}
	pbh.SetMediaType(h.MediaType)
	pbh.SetMaxChunkLen(int32(h.MaxChunkLen)) // nolint: gosec
	b, err := proto.Marshal(pbh)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal output header to binary: %w", err)
	}

	return b, nil
}

func (h *Header) UnmarshalBinary(b []byte) error {
	pbh := &pb.OutputHeader{}
	err := proto.Unmarshal(b, pbh)
	if err != nil {
		return fmt.Errorf("failed to unmarshal output header from protobuf: %w", err)
	}

	h.MediaType = pbh.GetMediaType()
	h.MaxChunkLen = int(pbh.GetMaxChunkLen())

	return nil
}
