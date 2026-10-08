package client

// Data by reference (Stage B-1e, author decisions 2026-10-08): a job's
// payload names a file -- the heain-files instance that holds it and the
// file id -- instead of carrying its bytes. An app on any node of the zone
// reads the range it needs from that instance over mTLS (heain-sdk zone
// discovery) and writes its output back there, as a stream.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/heainframework/heain-sdk/heain"
)

// Ref names a file on one heain-files instance of the zone.
type Ref struct {
	Instance string `json:"instance"`
	ID       string `json:"file_id"`
}

// String is "heain-files:<instance>/<id>".
func (r Ref) String() string { return "heain-files:" + r.Instance + "/" + r.ID }

// spec is the call spec for capability on instance (any instance on this
// node when instance is ""): this node's instance when it is here,
// otherwise the zone's.
func spec(ctx context.Context, a *heain.App, capability, instance string) heain.CallSpec {
	cs := heain.CallSpec{App: App, Capability: capability, Instance: instance}
	if instance == "" {
		return cs
	}
	if insts, err := a.Discover(ctx, capability, 0); err == nil {
		for _, in := range insts {
			if in.AppID == App && in.InstanceID == instance {
				return cs
			}
		}
	}
	cs.Scope = heain.ScopeZone
	return cs
}

func callAt(ctx context.Context, a *heain.App, instance, capability, method, path string, body, out any) error {
	cs := spec(ctx, a, capability, instance)
	cs.Method, cs.Path, cs.Body, cs.Out = method, path, body, out
	_, err := a.Call(ctx, cs)
	return err
}

func notFound(err error) bool {
	var ce *heain.CallError
	return errors.As(err, &ce) && ce.Status == http.StatusNotFound || errors.Is(err, heain.ErrNoInstance)
}

// StatRef returns the record of the file r names.
func StatRef(ctx context.Context, a *heain.App, r Ref) (*File, error) {
	var f File
	if err := callAt(ctx, a, r.Instance, "files.read", "GET", "/v1/files/"+url.PathEscape(r.ID), nil, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// Locate finds file id: on this node's heain-files first, then on every
// heain-files of the zone. The record's Instance says where it is.
func Locate(ctx context.Context, a *heain.App, id string) (*File, error) {
	f, err := Stat(ctx, a, id)
	if err == nil || !notFound(err) {
		return f, err
	}
	zi, _, zerr := a.DiscoverZone(ctx, "files.read", 0)
	if zerr != nil {
		return nil, err
	}
	for _, z := range zi {
		if z.AppID != App {
			continue
		}
		if f, e := StatRef(ctx, a, Ref{Instance: z.InstanceID, ID: id}); e == nil {
			return f, nil
		} else if !notFound(e) {
			err = e
		}
	}
	return nil, err
}

// OpenRange reads n bytes of r from offset off (n < 0: to the end) as a
// stream; the caller closes it. Only the chunks the range covers are read.
func OpenRange(ctx context.Context, a *heain.App, r Ref, off, n int64, header http.Header) (*heain.Stream, error) {
	cs := spec(ctx, a, "files.read", r.Instance)
	cs.Method, cs.Path = "GET", "/v1/files/"+url.PathEscape(r.ID)+"/content"
	h := http.Header{}
	for k, v := range header {
		h[k] = v
	}
	if h.Get("Range") == "" && (off > 0 || n >= 0) {
		if n >= 0 {
			if n == 0 {
				return nil, fmt.Errorf("heain-files: empty range")
			}
			h.Set("Range", "bytes="+strconv.FormatInt(off, 10)+"-"+strconv.FormatInt(off+n-1, 10))
		} else {
			h.Set("Range", "bytes="+strconv.FormatInt(off, 10)+"-")
		}
	}
	return a.Stream(ctx, cs, h, nil)
}

// UploadTo stores r on the heain-files instance named (this node's when
// ""), chunk by chunk as r is read (raw chunks, no base64), and commits it
// with the content hash; it never holds more than one chunk.
func UploadTo(ctx context.Context, a *heain.App, instance string, sp Spec, r io.Reader) (*File, error) {
	var f File
	if err := callAt(ctx, a, instance, "files.write", "POST", "/v1/files", sp, &f); err != nil {
		return nil, err
	}
	if f.Instance != "" {
		instance = f.Instance
	}
	h := sha256.New()
	buf := make([]byte, f.ChunkSize)
	defer wipe(buf)
	for n := 0; ; n++ {
		k, err := io.ReadFull(r, buf)
		if k > 0 || n == 0 {
			h.Write(buf[:k])
			cs := spec(ctx, a, "files.write", instance)
			cs.Method, cs.Path = "PUT", fmt.Sprintf("/v1/files/%s/chunks/%d", url.PathEscape(f.ID), n)
			st, perr := a.Stream(ctx, cs, nil, bytesReader(buf[:k]))
			if perr != nil {
				return nil, perr
			}
			_, _ = io.Copy(io.Discard, st.Body)
			st.Close()
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	var out File
	if err := callAt(ctx, a, instance, "files.write", "POST", "/v1/files/"+url.PathEscape(f.ID)+"/commit",
		map[string]any{"sha256": hex.EncodeToString(h.Sum(nil))}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteRef crypto-shreds the file r names.
func DeleteRef(ctx context.Context, a *heain.App, r Ref) error {
	return callAt(ctx, a, r.Instance, "files.write", "DELETE", "/v1/files/"+url.PathEscape(r.ID), nil, nil)
}

// ShareRef replaces the apps the file r names is shared with.
func ShareRef(ctx context.Context, a *heain.App, r Ref, apps []string) error {
	return callAt(ctx, a, r.Instance, "files.write", "PUT", "/v1/files/"+url.PathEscape(r.ID)+"/sharing", map[string]any{"shared_with": apps}, nil)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
