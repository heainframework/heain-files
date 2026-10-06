// Package api serves heain-files over the heain-sdk direct-endpoint server
// (mTLS between apps, formal audit of every call in heain-core). The
// calling app -- from its certificate, heain.Caller -- owns what it
// uploads; other apps read a file only when its owner shares it.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-files/internal/backend"
	"github.com/heainframework/heain-files/internal/store"
)

// API ties the store to the endpoints.
type API struct {
	Store *store.Store
	Logf  func(string, ...any)
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	reply(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg, "retryable": status >= 500}})
}

func failErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, backend.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such file (or not shared with this app)")
	case errors.Is(err, store.ErrForbidden):
		fail(w, http.StatusForbidden, "forbidden", "only the owning app may change or delete this file")
	case errors.Is(err, store.ErrConflict):
		fail(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, store.ErrInvalid):
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		fail(w, http.StatusInternalServerError, "internal", err.Error())
	}
}

// callerApp is the calling app id: the CN is <app-id>.<instance-id>.
func callerApp(r *http.Request) string {
	c := heain.Caller(r.Context())
	if i := strings.IndexByte(c, '.'); i > 0 {
		return c[:i]
	}
	return c
}

func (a *API) app(w http.ResponseWriter, r *http.Request) (string, bool) {
	app := callerApp(r)
	if app == "" {
		fail(w, http.StatusForbidden, "forbidden", "no calling app identity")
		return "", false
	}
	return app, true
}

// Register adds every endpoint of the manifest to s.
func (a *API) Register(s *heain.Server) error {
	h := map[string]http.HandlerFunc{
		"POST /v1/files":                a.create,
		"GET /v1/files":                 a.list,
		"GET /v1/files/{id}":            a.get,
		"PUT /v1/files/{id}/chunks/{n}": a.putChunk,
		"GET /v1/files/{id}/chunks/{n}": a.getChunk,
		"POST /v1/files/{id}/commit":    a.commit,
		"GET /v1/files/{id}/content":    a.content,
		"PUT /v1/files/{id}/sharing":    a.share,
		"DELETE /v1/files/{id}":         a.delete,
	}
	for p, f := range h {
		if err := s.HandleFunc(p, f); err != nil {
			return err
		}
	}
	return nil
}

func decode(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	app, ok := a.app(w, r)
	if !ok {
		return
	}
	var spec store.CreateSpec
	if !decode(w, r, 64<<10, &spec) {
		return
	}
	f, err := a.Store.Create(r.Context(), app, spec)
	if err != nil {
		failErr(w, err)
		return
	}
	reply(w, http.StatusOK, f)
}

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	app, ok := a.app(w, r)
	if !ok {
		return
	}
	var (
		fs  []*store.File
		err error
	)
	if name := r.URL.Query().Get("name"); name != "" {
		fs, err = a.Store.Versions(app, name)
	} else {
		fs, err = a.Store.List(app)
	}
	if err != nil {
		failErr(w, err)
		return
	}
	if fs == nil {
		fs = []*store.File{}
	}
	reply(w, http.StatusOK, map[string]any{"files": fs})
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	app, ok := a.app(w, r)
	if !ok {
		return
	}
	f, err := a.Store.Get(app, r.PathValue("id"))
	if err != nil {
		failErr(w, err)
		return
	}
	reply(w, http.StatusOK, f)
}

func chunkNo(w http.ResponseWriter, r *http.Request) (int, bool) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 0 {
		fail(w, http.StatusBadRequest, "bad_request", "chunk number")
		return 0, false
	}
	return n, true
}

// putChunk takes the chunk as the raw body (Content-Type
// application/octet-stream) or as JSON {"data_b64": ...} -- what heain-sdk
// App.Call sends -- or {"data": "<text>"} for small text content.
func (a *API) putChunk(w http.ResponseWriter, r *http.Request) {
	app, ok := a.app(w, r)
	if !ok {
		return
	}
	n, ok := chunkNo(w, r)
	if !ok {
		return
	}
	var data []byte
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "application/octet-stream" {
		var err error
		data, err = io.ReadAll(http.MaxBytesReader(w, r.Body, store.MaxChunkSize))
		if err != nil {
			fail(w, http.StatusRequestEntityTooLarge, "too_large", err.Error())
			return
		}
	} else {
		var in struct {
			DataB64 []byte  `json:"data_b64"`
			Data    *string `json:"data"`
		}
		if !decode(w, r, store.MaxChunkSize/3*4+4096, &in) {
			return
		}
		data = in.DataB64
		if in.Data != nil {
			data = []byte(*in.Data)
		}
	}
	c, err := a.Store.PutChunk(r.Context(), app, r.PathValue("id"), n, data)
	if err != nil {
		failErr(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"n": n, "size": c.Size, "sha256": c.SHA256})
}

// getChunk answers JSON {"n", "size", "sha256", "data_b64"} -- or the raw
// bytes when the caller sends Accept: application/octet-stream.
func (a *API) getChunk(w http.ResponseWriter, r *http.Request) {
	app, ok := a.app(w, r)
	if !ok {
		return
	}
	n, ok := chunkNo(w, r)
	if !ok {
		return
	}
	b, f, err := a.Store.ReadChunk(r.Context(), app, r.PathValue("id"), n)
	if err != nil {
		failErr(w, err)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "application/octet-stream") {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Heain-Chunk-Sha256", f.Chunks[n].SHA256)
		_, _ = w.Write(b)
		return
	}
	reply(w, http.StatusOK, map[string]any{"n": n, "size": len(b), "sha256": f.Chunks[n].SHA256, "last": n == len(f.Chunks)-1,
		"data_b64": base64.StdEncoding.EncodeToString(b)})
}

func (a *API) commit(w http.ResponseWriter, r *http.Request) {
	app, ok := a.app(w, r)
	if !ok {
		return
	}
	var in struct {
		SHA256 string `json:"sha256"`
	}
	if r.ContentLength != 0 && !decode(w, r, 4096, &in) {
		return
	}
	f, err := a.Store.Commit(r.Context(), app, r.PathValue("id"), in.SHA256)
	if err != nil {
		failErr(w, err)
		return
	}
	reply(w, http.StatusOK, f)
}

// content streams a committed file's whole content.
func (a *API) content(w http.ResponseWriter, r *http.Request) {
	app, ok := a.app(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	f, err := a.Store.Get(app, id)
	if err != nil {
		failErr(w, err)
		return
	}
	if f.State != store.StateCommitted {
		failErr(w, store.ErrConflict)
		return
	}
	ct := f.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
	w.Header().Set("X-Heain-File-Sha256", f.SHA256)
	for i := range f.Chunks {
		b, _, err := a.Store.ReadChunk(r.Context(), app, id, i)
		if err != nil {
			if i == 0 {
				w.Header().Del("Content-Length")
				failErr(w, err)
			}
			a.logf("heain-files: content %s chunk %d: %v", id, i, err)
			return // a short body tells the client something went wrong
		}
		if _, err := w.Write(b); err != nil {
			return
		}
	}
}

func (a *API) share(w http.ResponseWriter, r *http.Request) {
	app, ok := a.app(w, r)
	if !ok {
		return
	}
	var in struct {
		SharedWith []string `json:"shared_with"`
	}
	if !decode(w, r, 64<<10, &in) {
		return
	}
	f, err := a.Store.Share(app, r.PathValue("id"), in.SharedWith)
	if err != nil {
		failErr(w, err)
		return
	}
	reply(w, http.StatusOK, f)
}

func (a *API) delete(w http.ResponseWriter, r *http.Request) {
	app, ok := a.app(w, r)
	if !ok {
		return
	}
	if err := a.Store.Delete(r.Context(), app, r.PathValue("id")); err != nil {
		failErr(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"deleted": true, "crypto_shredded": true})
}

// Sweep removes expired files and abandoned uploads every interval.
func (a *API) Sweep(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n, err := a.Store.Sweep(ctx); err != nil {
			a.logf("heain-files: sweep: %v", err)
		} else if n > 0 {
			a.logf("heain-files: sweep removed %d expired file(s)", n)
		}
	}
}

func (a *API) logf(f string, v ...any) {
	if a.Logf != nil {
		a.Logf(f, v...)
	}
}
