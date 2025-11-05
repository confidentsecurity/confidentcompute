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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"github.com/openpcc/openpcc/cserrors"
	"google.golang.org/api/iterator"
)

type GCPBucketStore struct {
	bucket *storage.BucketHandle
}

func NewGCPBucketStore(bucket string, client *storage.Client) *GCPBucketStore {
	return &GCPBucketStore{
		bucket: client.Bucket(bucket),
	}
}

func (s *GCPBucketStore) FindByKey(ctx context.Context, key string) ([]byte, error) {
	obj := s.bucket.Object(key)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, cserrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to create object reader: %w", err)
	}
	defer func() {
		closeErr := reader.Close()
		if err == nil {
			err = closeErr
		}
	}()

	bundle, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle data: %w", err)
	}

	return bundle, nil
}

func (s *GCPBucketStore) Insert(ctx context.Context, key string, bundle []byte) error {
	obj := s.bucket.Object(key)
	writer := obj.NewWriter(ctx)
	_, err := io.Copy(writer, bytes.NewReader(bundle))
	if err != nil {
		return fmt.Errorf("failed to copy bundle to object: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close the object: %w", err)
	}

	return nil
}

func (s *GCPBucketStore) FindByGlob(ctx context.Context, glob string) ([][]byte, error) {
	q := &storage.Query{
		MatchGlob: glob,
	}
	err := q.SetAttrSelection([]string{"Name"})
	if err != nil {
		return nil, fmt.Errorf("failed to set attr selection: %w", err)
	}

	it := s.bucket.Objects(ctx, q)

	var out [][]byte
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get next object: %w", err)
		}
		data, err := s.FindByKey(ctx, attrs.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get data for %s: %w", attrs.Name, err)
		}
		out = append(out, data)
	}

	return out, nil
}
