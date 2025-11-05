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

package computeworker

import (
	"embed"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/txtar"
)

//go:embed diagnostics/*
var diagnosticsArchive embed.FS

func LoadDiagnosticResponseBodies() (map[string]string, error) {
	// collect all response.json files in diagnostics/*.txtar files.
	files, err := diagnosticsArchive.ReadDir("diagnostics")
	if err != nil {
		return nil, fmt.Errorf("failed to read diagnostic directory: %w", err)
	}

	result := make(map[string]string, len(files))
	for _, file := range files {
		data, err := diagnosticsArchive.ReadFile(filepath.Join("diagnostics", file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read diagnostic file %v: %w", file.Name(), err)
		}

		archive := txtar.Parse(data)
		i := slices.IndexFunc(archive.Files, func(archiveFile txtar.File) bool {
			return archiveFile.Name == "response.json"
		})
		if i == -1 {
			return nil, fmt.Errorf("file %s does not contain a response.json", file.Name())
		}

		key, found := strings.CutSuffix(file.Name(), ".txtar")
		if !found {
			return nil, fmt.Errorf("expected a .txtar extension got filename: %v", file.Name())
		}
		result[key] = string(archive.Files[i].Data)
	}

	return result, nil
}
