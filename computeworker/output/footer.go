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

	"github.com/openpcc/openpcc/anonpay/currency"
	pb "github.com/openpcc/openpcc/gen/protos/computeworker"
	"google.golang.org/protobuf/proto"
)

type Footer struct {
	// Refund is the refund for this request. Note: a nil refund indicates no refund.
	Refund *currency.Value
}

func (f Footer) HasRefund() bool {
	return f.Refund != nil
}

func (f Footer) MarshalBinary() ([]byte, error) {
	pbf := &pb.OutputFooter{}

	if f.HasRefund() {
		refundPB, err := f.Refund.MarshalProto()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal refund to protobuf: %w", err)
		}
		pbf.SetRefund(refundPB)
	}

	b, err := proto.Marshal(pbf)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal output footer to binary: %w", err)
	}

	return b, nil
}

func (f *Footer) UnmarshalBinary(b []byte) error {
	pbf := &pb.OutputFooter{}
	err := proto.Unmarshal(b, pbf)
	if err != nil {
		return fmt.Errorf("failed to unmarshal output footer from protobuf: %w", err)
	}

	if pbf.HasRefund() {
		refund := &currency.Value{}
		err = refund.UnmarshalProto(pbf.GetRefund())
		if err != nil {
			return fmt.Errorf("failed to unmarshal refund from protobuf: %w", err)
		}

		f.Refund = refund
	}

	return nil
}
