package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/heainframework/heain-sdk/heain"
)

// Loopback lets a tool that reads URLs (ffmpeg, ffprobe) read a heain-files
// file by range without a local copy: URL gives an http://127.0.0.1 address
// for one file, behind an unguessable token, and each request the tool makes
// (Range: bytes=...) becomes a range read on the heain-files instance that
// holds the file, over mTLS. The address answers only while the file is
// registered (until release is called) and only on the loopback interface.
type Loopback struct {
	App *heain.App

	once sync.Once
	err  error
	base string
	mu   sync.Mutex
	refs map[string]Ref
}

func (l *Loopback) start() error {
	l.once.Do(func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			l.err = err
			return
		}
		l.base = "http://" + ln.Addr().String()
		l.refs = map[string]Ref{}
		go func() { _ = http.Serve(ln, http.HandlerFunc(l.serve)) }()
	})
	return l.err
}

// URL registers r and returns its address; name (a file name) only sets
// the extension tools see. release unregisters it.
func (l *Loopback) URL(r Ref, name string) (string, func(), error) {
	if err := l.start(); err != nil {
		return "", nil, err
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	tok := hex.EncodeToString(b)
	l.mu.Lock()
	l.refs[tok] = r
	l.mu.Unlock()
	base := path.Base(name)
	if base == "." || base == "/" || base == "" {
		base = "file"
	}
	return l.base + "/" + tok + "/" + url.PathEscape(base), func() {
		l.mu.Lock()
		delete(l.refs, tok)
		l.mu.Unlock()
	}, nil
}

func (l *Loopback) serve(w http.ResponseWriter, r *http.Request) {
	tok, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	l.mu.Lock()
	ref, ok := l.refs[tok]
	l.mu.Unlock()
	if !ok || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	h := http.Header{}
	if v := r.Header.Get("Range"); v != "" {
		h.Set("Range", v)
	}
	if r.Method == http.MethodHead {
		f, err := StatRef(r.Context(), l.App, ref)
		if err != nil {
			http.Error(w, "unavailable", http.StatusBadGateway)
			return
		}
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", itoa(f.Size))
		return
	}
	st, err := OpenRange(context.WithoutCancel(r.Context()), l.App, ref, 0, -1, h)
	if err != nil {
		var ce *heain.CallError
		if asCallError(err, &ce) && ce.Status == http.StatusRequestedRangeNotSatisfiable {
			http.Error(w, "range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		http.Error(w, "unavailable", http.StatusBadGateway)
		return
	}
	defer st.Close()
	go func() { <-r.Context().Done(); st.Close() }()
	for _, k := range []string{"Content-Length", "Content-Range", "Accept-Ranges", "Content-Type"} {
		if v := st.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(st.StatusCode)
	_, _ = io.Copy(w, st.Body)
}
