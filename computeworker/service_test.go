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

package computeworker_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/confidentsecurity/confidentcompute/computeworker"
	"github.com/confidentsecurity/confidentcompute/computeworker/output"
	"github.com/openpcc/openpcc/auth/credentialing"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/messages"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireErrorMessageInBody(t *testing.T, body io.Reader, code string, message string) {
	var errMsg computeworker.ValidationErrorMessage
	require.NoError(t, json.NewDecoder(body).Decode(&errMsg))
	require.Equal(t, code, errMsg.Code)
	require.Equal(t, "Request Validation Error", errMsg.Error)
	require.Equal(t, message, errMsg.Message)
}

func TestServiceRun(t *testing.T) {
	readTestDataResponse := func(t *testing.T, name string) []byte {
		return test.ReadFile(t, test.TextArchiveFS(t, "testdata/"+name), "response.json")
	}

	badgeKeyProvider := test.NewTestBadgeKeyProvider()
	badgeSK, err := badgeKeyProvider.PrivateKey()
	require.NoError(t, err)
	badgePK, ok := badgeSK.Public().(ed25519.PublicKey)
	require.True(t, ok)

	getTestBadge := func(t *testing.T, keyProvider credentialing.BadgeKeyProvider) credentialing.Badge {
		badgeSK, err := keyProvider.PrivateKey()
		require.NoError(t, err)

		badge := credentialing.Badge{}
		badge.Credentials = credentialing.Credentials{Models: []string{"llama3.2:1b", "qwen2:1.5b-instruct", "gemma3:1b"}}
		credBytes, err := badge.Credentials.MarshalBinary()
		require.NoError(t, err)

		sig := ed25519.Sign(badgeSK, credBytes)
		badge.Signature = sig
		return badge
	}

	newJSONRequest := func(t *testing.T, url string, body io.Reader) *http.Request {
		req, err := http.NewRequest(http.MethodPost, url, body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		badge := getTestBadge(t, badgeKeyProvider)
		serializedBadge, err := badge.Serialize()
		require.NoError(t, err)
		req.Header.Set("X-Confsec-Badge", serializedBadge)
		return req
	}

	tests := map[string]struct {
		creditAmount   int64
		reqFunc        func(t *testing.T) *http.Request
		handler        func(t *testing.T, w http.ResponseWriter, r *http.Request)
		verifyRespFunc func(t *testing.T, resp *http.Response)
		verifyFooter   func(t *testing.T, f output.Footer)
		modConfig      func(t *testing.T, cfg *computeworker.Config)
		verifyErr      func(t *testing.T, err error)
	}{
		"ok, /api/generate no streaming, valid empty response from llm, full refund": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":false}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				data := readTestDataResponse(t, "generate-no-stream-empty.txt")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{"280"},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				data := readTestDataResponse(t, "generate-no-stream-empty.txt")
				test.RequireReadAll(t, data, resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				// Credit used = (29 * 0.5) + (0 * 2) = 14.5, so refund should be ~185
				require.GreaterOrEqual(t, amount, int64(180))
			},
		},
		"ok, /api/generate no streaming, valid response from llm, missing eval_count, no refund": {
			creditAmount: 100,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":false}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				data := readTestDataResponse(t, "generate-no-stream-missing-eval-count.txt")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{"856"},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				data := readTestDataResponse(t, "generate-no-stream-missing-eval-count.txt")
				test.RequireReadAll(t, data, resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.Nil(t, f.Refund)
			},
		},
		"ok, /api/generate no streaming, valid response from llm, used some credits": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":false}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				data := readTestDataResponse(t, "generate-no-stream.txt")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{"872"},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				data := readTestDataResponse(t, "generate-no-stream.txt")
				test.RequireReadAll(t, data, resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				// Credit used = (29 * 0.5) + (54 * 2) = 122.5, so refund should be ~77
				require.GreaterOrEqual(t, amount, int64(70))
				require.LessOrEqual(t, amount, int64(85))
			},
		},
		"ok, /api/generate no streaming, valid response from llm, used all credits": {
			creditAmount: 4,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":false}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				data := readTestDataResponse(t, "generate-no-stream.txt")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{"872"},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				data := readTestDataResponse(t, "generate-no-stream.txt")
				test.RequireReadAll(t, data, resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.Nil(t, f.Refund)
			},
		},
		"ok, /api/generate streaming, valid empty response from llm, full refund": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":true}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				data := readTestDataResponse(t, "generate-stream-empty.txt")
				w.Header().Set("Transfer-Encoding", "chunked")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				data := readTestDataResponse(t, "generate-stream-empty.txt")
				test.RequireReadAll(t, data, resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				// Credit used = (29 * 0.5) + (0 * 2) = 14.5, so refund should be ~185
				require.GreaterOrEqual(t, amount, int64(180))
			},
		},
		"ok, /api/generate streaming, valid response from llm, missing eval_count, no refund": {
			creditAmount: 100,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":true}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				data := readTestDataResponse(t, "generate-stream-missing-eval-count.txt")
				w.Header().Set("Transfer-Encoding", "chunked")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				data := readTestDataResponse(t, "generate-stream-missing-eval-count.txt")
				test.RequireReadAll(t, data, resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.Nil(t, f.Refund)
			},
		},
		"ok, /api/generate streaming, valid response from llm, used some credits": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":true}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				data := readTestDataResponse(t, "generate-stream.txt")
				w.Header().Set("Transfer-Encoding", "chunked")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				data := readTestDataResponse(t, "generate-stream.txt")
				test.RequireReadAll(t, data, resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				// Credit used = (29 * 0.5) + (54 * 2) = 122.5, so refund should be ~77
				require.GreaterOrEqual(t, amount, int64(70))
				require.LessOrEqual(t, amount, int64(85))
			},
		},
		"ok, /api/generate streaming, valid response from llm, used all credits": {
			creditAmount: 4,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":true}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				data := readTestDataResponse(t, "generate-stream.txt")
				w.Header().Set("Transfer-Encoding", "chunked")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				data := readTestDataResponse(t, "generate-stream.txt")
				test.RequireReadAll(t, data, resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.Nil(t, f.Refund)
			},
		},
		"ok, /api/chat no streaming, valid response from llm, used some credits": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":false}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				data := readTestDataResponse(t, "chat-no-stream.txt")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{"503"},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				data := readTestDataResponse(t, "chat-no-stream.txt")
				test.RequireReadAll(t, data, resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				// Credit used = (29 * 0.5) + (55 * 2) = 124.5, so refund should be ~75
				require.GreaterOrEqual(t, amount, int64(70))
				require.LessOrEqual(t, amount, int64(82))
			},
		},
		"ok, /api/chat streaming, valid response from llm, used some credits": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","messages":[{"role":"user","content":"Ping"}],"stream":true}`)
				return newJSONRequest(t, "https://confsec.invalid/api/chat", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				data := readTestDataResponse(t, "chat-stream.txt")
				w.Header().Set("Transfer-Encoding", "chunked")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				data := readTestDataResponse(t, "chat-stream.txt")
				test.RequireReadAll(t, data, resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				// Credit used = (29 * 0.5) + (54 * 2) = 122.5, so refund should be ~77
				require.GreaterOrEqual(t, amount, int64(70))
				require.LessOrEqual(t, amount, int64(85))
			},
		},
		"ok, valid request, 5xx response from llm, full refund": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":false}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"data": "failed"}`))
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{"18"},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				test.RequireReadAll(t, []byte(`{"data": "failed"}`), resp.Body)
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				require.Equal(t, int64(200), amount)
			},
		},
		"ok, noop request does not call handler and looks okay": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":true}`)
				req := newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
				req.Header.Set("X-Confsec-Exec", "noop")
				return req
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				panic("should not be called")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Type": []string{"application/x-ndjson"},
					"Date":         []string{resp.Header.Get("Date")},
				}, resp.Header)
				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.Greater(t, len(data), 0) // require some data
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				require.GreaterOrEqual(t, amount, int64(0))
			},
		},
		"ok, simulated request does not call handler and looks okay": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":true}`)
				req := newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
				req.Header.Set("X-Confsec-Exec", "simulated")
				return req
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				panic("should not be called")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Type": []string{"application/x-ndjson"},
					"Date":         []string{resp.Header.Get("Date")},
				}, resp.Header)
				data, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.Greater(t, len(data), 0) // require some data
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				// either have no refund or have more than zero.
				if f.Refund == nil {
					return
				}
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				require.GreaterOrEqual(t, amount, int64(0))
			},
		},
		"ok, unknown headers are stripped": {
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":true}`)
				req := newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
				req.Header.Set("X-Unknown-Header", "test")
				return req
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.Header{
					"Accept":          []string{"application/json", "application/x-ndjson"},
					"Accept-Encoding": []string{"gzip"},
					"Content-Type":    []string{"application/json"},
					"User-Agent":      []string{"Go-http-client/1.1"},
					// Note: No X-Unknown-Header
				}, r.Header)
				data := readTestDataResponse(t, "generate-no-stream.txt")
				w.Write(data)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {},
			verifyFooter:   func(t *testing.T, f output.Footer) {},
		},
		"ok, invalid request, blocked header": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":true}`)
				req := newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
				req.Header.Set("Content-Encoding", "gzip")
				return req
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				panic("should not be called")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Type": []string{"application/json"},
				}, resp.Header)

				requireErrorMessageInBody(t, resp.Body, "ErrHeaderNotAllowed", "header not allowed: Content-Encoding")
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				require.Equal(t, int64(200), amount)
			},
		},
		"ok, invalid request, invalid endpoint": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b"}`)
				req := newJSONRequest(t, "https://confsec.invalid/api/pull", bdy)
				return req
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				panic("should not be called")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusNotFound, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Type": []string{"application/json"},
				}, resp.Header)

				requireErrorMessageInBody(t, resp.Body, "ErrUnsupportedPath", "not supported: /api/pull")
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				require.Equal(t, int64(200), amount)
			},
		},
		"ok, invalid request, body too long": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				tmpl := `{"model":"llama:3.2:1b","prompt":"%s","stream":false}`
				// +2 to account for `%s` in template (it counts toward the `tmpl` length), +1 to exceed the max size (1 MB)
				promptLen := 1*1024*1024 - len(tmpl) + 2 + 1
				bdy := strings.NewReader(fmt.Sprintf(tmpl, strings.Repeat("a", promptLen)))
				req := newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
				return req
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				panic("should not be called")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Type": []string{"application/json"},
				}, resp.Header)

				requireErrorMessageInBody(t, resp.Body, "ErrBodyTooLarge", "content-length exceeds max size")
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				require.Equal(t, int64(200), amount)
			},
		},
		"ok, invalid request, unknown hostname": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":true}`)
				req := newJSONRequest(t, "https://example.com/api/generate", bdy)
				return req
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				panic("should not be called")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Type": []string{"application/json"},
				}, resp.Header)

				requireErrorMessageInBody(t, resp.Body, "ErrUnknownHostname", "unknown hostname")
				require.NoError(t, resp.Body.Close())
			},
			verifyFooter: func(t *testing.T, f output.Footer) {
				require.NotNil(t, f.Refund)
				amount, err := f.Refund.Amount()
				require.NoError(t, err)
				require.Equal(t, int64(200), amount)
			},
		},
		"fail, media-type mismatch": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":false}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Fail(t, "unexpected handler call")
			},
			modConfig: func(t *testing.T, cfg *computeworker.Config) {
				cfg.RequestParams.MediaType = cfg.RequestParams.MediaType + "a"
			},
			verifyErr: func(t *testing.T, err error) {
				require.Error(t, err)
				inputErr := &computeworker.RequestDecapsulationError{}
				require.ErrorAs(t, err, &inputErr)
			},
		},
		"fail, encap key tampered with": {
			creditAmount: 200,
			reqFunc: func(t *testing.T) *http.Request {
				bdy := strings.NewReader(`{"model":"llama3.2:1b","prompt":"Ping","stream":false}`)
				return newJSONRequest(t, "https://confsec.invalid/api/generate", bdy)
			},
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Fail(t, "unexpected handler call")
			},
			modConfig: func(t *testing.T, cfg *computeworker.Config) {
				cfg.RequestParams.EncapsulatedKey[0]++
			},
			verifyErr: func(t *testing.T, err error) {
				require.Error(t, err)
				inputErr := &computeworker.RequestDecapsulationError{}
				require.ErrorAs(t, err, &inputErr)
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// create node compute data and run a fake llm.
			receiver, computeData := test.NewComputeNodeReceiver(t)
			sender := test.NewClientSender(t, computeData)
			pubKey, err := computeData.UnmarshalPublicKey()
			require.NoError(t, err)

			llmURL := test.RunHandlerWhile(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.handler(t, w, r)
			}))

			// set up the request
			req := tt.reqFunc(t)

			// encode and encrypt the request
			ct, mediaType, err := messages.EncapsulateRequest(sender, req)
			require.NoError(t, err)

			encapKey, openerFunc, err := ct.EncapsulateKey(0, pubKey)
			require.NoError(t, err)

			cfg := &computeworker.Config{
				LLMBaseURL: llmURL,
				Timeout:    1 * time.Second,
				RequestParams: computeworker.RequestParams{
					MediaType:       mediaType,
					EncapsulatedKey: encapKey,
					CreditAmount:    tt.creditAmount,
				},
				BadgePublicKey: badgePK,
				Models:         []string{"llama3.2:1b"},
			}

			if tt.modConfig != nil {
				tt.modConfig(t, cfg)
			}

			buf := &bytes.Buffer{}
			worker := computeworker.NewWithDependencies(t.Context(), cfg, http.DefaultClient, receiver, ct, buf, nil)

			// Run the worker.
			err = worker.Run()
			if tt.verifyErr != nil {
				tt.verifyErr(t, err)
				return
			}

			require.NoError(t, err)

			dec, err := output.NewDecoder(buf)
			require.NoError(t, err)

			h := dec.Header()
			// max chunk len should either be zero or messages.MaxChunkLen
			require.Contains(t, []int{0, messages.EncapsulatedChunkLen()}, h.MaxChunkLen)

			content := &bytes.Buffer{}
			_, err = dec.WriteTo(content)
			require.NoError(t, err)

			resp, err := messages.DecapsulateResponse(t.Context(), openerFunc, h.MediaType, content)
			require.NoError(t, err)

			// Verify the response.
			tt.verifyRespFunc(t, resp)

			// Verify the footer (contains the refund).
			footer, ok := dec.Footer()
			require.True(t, ok)
			tt.verifyFooter(t, footer)
		})
	}
}
