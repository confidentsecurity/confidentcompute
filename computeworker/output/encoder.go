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
	"io"

	"github.com/quic-go/quic-go/quicvarint"
)

// Encoder encodes chunks of data sandwiched between a header and a footer.
// - Header and footer are unencrypted and intended to be used by routercom.
// - The header chunk is the 0th chunk.
// - Each non-footer chunk is prefixed with a quicencoded integer indicating it's length.
// - The footer chunk is indicated with a zero length, followed by its actual length.
type Encoder struct {
	header Header
	w      io.Writer
}

func NewEncoder(h Header, w io.Writer) (*Encoder, error) {
	b, err := h.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header to binary: %w", err)
	}

	enc := &Encoder{
		header: h,
		w:      w,
	}

	// write the header as a length prefixed chunk.
	_, err = enc.Write(b)
	if err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	return enc, nil
}

func (e *Encoder) Write(b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		chunkLen := min(len(b), maxBufferLen)

		lenBytes := quicvarint.Append(nil, uint64(chunkLen)) // #nosec G115 -- len and maxbuffer are always non-negative
		_, err := e.w.Write(lenBytes)

		if err != nil {
			return written, fmt.Errorf("failed to write chunk length: %w", err)
		}

		n, err := e.w.Write(b[:chunkLen])
		if err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}

	return written, nil
}

func (e *Encoder) Close(f Footer) error {
	b, err := f.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal footer to binary: %w", err)
	}

	// write zero length to indicate this is a footer chunk.
	footerBytes := quicvarint.Append(nil, 0)
	_, err = e.w.Write(footerBytes)
	if err != nil {
		return fmt.Errorf("failed to encode zero length indicating footer chunk: %w", err)
	}

	// write the actual footer chunk length.
	lengthBytes := quicvarint.Append(nil, uint64(len(b)))
	_, err = e.w.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("failed to write length of the footer chunk: %w", err)
	}

	// write the footer chunk data.
	_, err = e.w.Write(b)
	if err != nil {
		return fmt.Errorf("failed to write footer payload: %w", err)
	}

	return nil
}
