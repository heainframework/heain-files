// Package client is how other heain apps (Go) use heain-files: upload a
// file in chunks, read it back chunk by chunk or whole. Calls go through
// heain-sdk App.Call, so the app must declare in its manifest
//
//	uses:
//	  - {app: heain-files, capability: files.write, version: 1}
//	  - {app: heain-files, capability: files.read, version: 1}
//
// Chunks are what travels inside heain-job payloads between nodes
// (decision 2026-10-06): a module job carries {file_id, n} or the chunk's
// bytes; the result is stored back with Upload on the node that owns it.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"

	"github.com/heainframework/heain-sdk/heain"
)

// App is the heain-files app id.
const App = "heain-files"

// File is heain-files' file record.
type File struct {
	ID          string            `json:"id"`
	Owner       string            `json:"owner"`
	Name        string            `json:"name"`
	Version     int               `json:"version"`
	ContentType string            `json:"content_type,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	State       string            `json:"state"`
	ChunkSize   int               `json:"chunk_size"`
	Chunks      []struct {
		Size   int    `json:"size"`
		SHA256 string `json:"sha256"`
	} `json:"chunks"`
	Size       int64    `json:"size"`
	SHA256     string   `json:"sha256,omitempty"`
	SharedWith []string `json:"shared_with,omitempty"`
	// Instance is the heain-files instance that holds the file.
	Instance string `json:"instance,omitempty"`
}

// Ref returns the file's reference.
func (f *File) Ref() Ref { return Ref{Instance: f.Instance, ID: f.ID} }

// Spec describes a new file.
type Spec struct {
	ID          string            `json:"id,omitempty"` // optional, makes a retried upload resume
	Name        string            `json:"name"`
	ContentType string            `json:"content_type,omitempty"`
	ChunkSize   int               `json:"chunk_size,omitempty"` // default 8 MiB, at most 32 MiB
	Labels      map[string]string `json:"labels,omitempty"`
	SharedWith  []string          `json:"shared_with,omitempty"`
	ExpiresInS  int64             `json:"expires_in_s,omitempty"`
}

func call(ctx context.Context, a *heain.App, capability, method, path string, body, out any) error {
	_, err := a.Call(ctx, heain.CallSpec{App: App, Capability: capability, Method: method, Path: path, Body: body, Out: out})
	return err
}

// Upload stores r as a new file (or the next version of spec.Name).
func Upload(ctx context.Context, a *heain.App, spec Spec, r io.Reader) (*File, error) {
	var f File
	if err := call(ctx, a, "files.write", "POST", "/v1/files", spec, &f); err != nil {
		return nil, err
	}
	h := sha256.New()
	buf := make([]byte, f.ChunkSize)
	for n := 0; ; n++ {
		k, err := io.ReadFull(r, buf)
		if k > 0 {
			h.Write(buf[:k])
			if err := PutChunk(ctx, a, f.ID, n, buf[:k]); err != nil {
				return nil, err
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return Commit(ctx, a, f.ID, hex.EncodeToString(h.Sum(nil)))
}

// PutChunk stores chunk n of an upload.
func PutChunk(ctx context.Context, a *heain.App, id string, n int, data []byte) error {
	return call(ctx, a, "files.write", "PUT", fmt.Sprintf("/v1/files/%s/chunks/%d", url.PathEscape(id), n),
		map[string]any{"data_b64": data}, nil)
}

// Commit finishes an upload; sha256 (hex, optional) is checked.
func Commit(ctx context.Context, a *heain.App, id, sha string) (*File, error) {
	var f File
	return &f, call(ctx, a, "files.write", "POST", "/v1/files/"+url.PathEscape(id)+"/commit", map[string]any{"sha256": sha}, &f)
}

// Stat returns a file's record.
func Stat(ctx context.Context, a *heain.App, id string) (*File, error) {
	var f File
	return &f, call(ctx, a, "files.read", "GET", "/v1/files/"+url.PathEscape(id), nil, &f)
}

// Chunk reads chunk n, checking its hash.
func Chunk(ctx context.Context, a *heain.App, id string, n int) ([]byte, error) {
	var out struct {
		Data   []byte `json:"data_b64"`
		SHA256 string `json:"sha256"`
	}
	if err := call(ctx, a, "files.read", "GET", fmt.Sprintf("/v1/files/%s/chunks/%d", url.PathEscape(id), n), nil, &out); err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(out.Data); hex.EncodeToString(sum[:]) != out.SHA256 {
		return nil, fmt.Errorf("heain-files: chunk %d of %s: hash mismatch", n, id)
	}
	return out.Data, nil
}

// Download writes a whole file to w, chunk by chunk, and checks its hash.
func Download(ctx context.Context, a *heain.App, id string, w io.Writer) (*File, error) {
	f, err := Stat(ctx, a, id)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	for n := range f.Chunks {
		b, err := Chunk(ctx, a, id, n)
		if err != nil {
			return nil, err
		}
		h.Write(b)
		if _, err := io.Copy(w, bytes.NewReader(b)); err != nil {
			return nil, err
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return nil, fmt.Errorf("heain-files: %s: content hash mismatch", id)
	}
	return f, nil
}

// Share replaces the apps the file is shared with.
func Share(ctx context.Context, a *heain.App, id string, apps []string) error {
	return call(ctx, a, "files.write", "PUT", "/v1/files/"+url.PathEscape(id)+"/sharing", map[string]any{"shared_with": apps}, nil)
}

// Delete crypto-shreds a file.
func Delete(ctx context.Context, a *heain.App, id string) error {
	return call(ctx, a, "files.write", "DELETE", "/v1/files/"+url.PathEscape(id), nil, nil)
}
