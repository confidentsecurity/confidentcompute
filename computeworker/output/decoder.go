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
	"net/http"

	"github.com/quic-go/quic-go/quicvarint"
)

const maxBufferLen = 32 * 1024 // 32kb

type Decoder struct {
	r      quicvarint.Reader
	buf    []byte
	header Header
	footer *Footer
}

func NewDecoder(r io.Reader) (*Decoder, error) {
	quicReader := quicvarint.NewReader(r)
	dec := &Decoder{
		r:   quicReader,
		buf: nil,
	}

	err := dec.readHeader()
	if err != nil {
		return nil, err
	}

	return dec, nil
}

func (d *Decoder) Header() Header {
	return d.header
}

func (d *Decoder) Footer() (Footer, bool) {
	if d.footer == nil {
		return Footer{}, false
	}
	return *d.footer, true
}

func (d *Decoder) readChunk() error {
	chunkLen, err := quicvarint.Read(d.r)
	if err != nil {
		return fmt.Errorf("failed to decode length: %w", err)
	}
	// prevent excessive buffer allocations in case something goes wrong.
	if chunkLen > maxBufferLen {
		return fmt.Errorf("received length %d over max buffer len %d", chunkLen, maxBufferLen)
	}

	if uint64(cap(d.buf)) < chunkLen {
		d.buf = make([]byte, chunkLen)
	}

	// resize buffer to fit header data.
	d.buf = d.buf[:chunkLen]

	_, err = io.ReadFull(d.r, d.buf)
	if err != nil {
		return fmt.Errorf("failed to read header chunk: %w", err)
	}

	return nil
}

func (d *Decoder) readHeader() error {
	err := d.readChunk()
	if err != nil {
		return err
	}

	err = d.header.UnmarshalBinary(d.buf)
	if err != nil {
		return fmt.Errorf("failed to unmarshal header: %w", err)
	}

	return nil
}

func (d *Decoder) readFooter() error {
	err := d.readChunk()
	if err != nil {
		return err
	}

	d.footer = &Footer{}
	err = d.footer.UnmarshalBinary(d.buf)
	if err != nil {
		return fmt.Errorf("failed to unmarshal footer: %w", err)
	}

	return nil
}

func (d *Decoder) WriteTo(w io.Writer) (int64, error) {
	flusher, isFlusher := w.(http.Flusher)

	written := int64(0)
	for {
		err := d.readChunk()
		if err != nil {
			return written, err
		}

		// zero chunk length indicates the footer.
		if len(d.buf) == 0 {
			err = d.readFooter()
			if err != nil {
				return written, fmt.Errorf("failed to decode footer: %w", err)
			}
			return written, nil
		}

		// d.buf now contains the chunk data.
		n, err := w.Write(d.buf)
		if err != nil {
			return written, fmt.Errorf("failed to write chunk: %w", err)
		}
		written += int64(n)

		if isFlusher {
			flusher.Flush()
		}
	}
}
