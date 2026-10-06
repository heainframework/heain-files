package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-files/internal/backend"
)

// fakeKMS stands in for heain-core's /v1/app/keys.
type fakeKMS struct {
	mu   sync.Mutex
	keys map[string][]byte
}

func (k *fakeKMS) sealer(_ context.Context, name string) (*heain.Sealer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.keys == nil {
		k.keys = map[string][]byte{}
	}
	if _, ok := k.keys[name]; !ok {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		k.keys[name] = b
	}
	return heain.NewSealer(k.keys[name])
}

func (k *fakeKMS) destroy(_ context.Context, name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.keys, name)
	return nil
}

func open(t *testing.T) (*Store, *fakeKMS, string) {
	dir := t.TempDir()
	kms := &fakeKMS{}
	inside := make([]byte, 32)
	_, _ = rand.Read(inside)
	s, err := Open(filepath.Join(dir, "files.db"), inside, backend.Disk{Root: filepath.Join(dir, "blobs")}, Keys{Sealer: kms.sealer, Destroy: kms.destroy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, kms, dir
}

func upload(t *testing.T, s *Store, owner, name string, data []byte, chunk int) *File {
	ctx := context.Background()
	f, err := s.Create(ctx, owner, CreateSpec{Name: name, ChunkSize: chunk})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i*chunk < len(data); i++ {
		end := min((i+1)*chunk, len(data))
		if _, err := s.PutChunk(ctx, owner, f.ID, i, data[i*chunk:end]); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256(data)
	f, err = s.Commit(ctx, owner, f.ID, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRoundTripVersionsShareShred(t *testing.T) {
	s, kms, dir := open(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte("secret-frame-"), 15000) // ~195 KB, 3 chunks of 64 KiB + rest
	f := upload(t, s, "heain-image", "masters/reel1.exr", data, MinChunkSize)
	if f.Version != 1 || f.Size != int64(len(data)) || len(f.Chunks) != 3 {
		t.Fatalf("file %+v", f)
	}
	var got []byte
	for i := range f.Chunks {
		b, _, err := s.ReadChunk(ctx, "heain-image", f.ID, i)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, b...)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content")
	}
	// nothing plaintext on disk: neither content nor name
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte("secret-frame-")) || bytes.Contains(b, []byte("reel1")) {
				t.Errorf("plaintext in %s", p)
			}
		}
		return nil
	})
	// immutable once committed
	if _, err := s.PutChunk(ctx, "heain-image", f.ID, 0, []byte("x")); !errors.Is(err, ErrConflict) {
		t.Fatalf("immutable: %v", err)
	}
	// another app cannot see it until shared
	if _, err := s.Get("heain-qc", f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("hidden")
	}
	if _, err := s.Share("heain-qc", f.ID, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("only owner shares")
	}
	if _, err := s.Share("heain-image", f.ID, []string{"heain-qc"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadChunk(ctx, "heain-qc", f.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "heain-qc", f.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("reader cannot delete")
	}
	// second version of the same name
	f2 := upload(t, s, "heain-image", "masters/reel1.exr", []byte("v2"), MinChunkSize)
	if f2.Version != 2 {
		t.Fatalf("version %d", f2.Version)
	}
	vs, _ := s.Versions("heain-image", "masters/reel1.exr")
	if len(vs) != 2 || vs[1].ID != f2.ID {
		t.Fatal("versions")
	}
	if vs, _ := s.Versions("heain-qc", "masters/reel1.exr"); len(vs) != 0 {
		t.Fatal("names are per owner")
	}
	// crypto-shred
	if err := s.Delete(ctx, "heain-image", f.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := kms.keys["file-"+f.ID]; ok {
		t.Fatal("key not destroyed")
	}
	if _, err := s.Get("heain-image", f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted")
	}
	if vs, _ := s.Versions("heain-image", "masters/reel1.exr"); len(vs) != 1 {
		t.Fatal("version list after delete")
	}
	if l, _ := s.List("heain-image"); len(l) != 1 {
		t.Fatalf("list %d", len(l))
	}
}

func TestCommitChecks(t *testing.T) {
	s, _, _ := open(t)
	ctx := context.Background()
	f, err := s.Create(ctx, "a", CreateSpec{ID: "job-0001-out", Name: "out.wav", ChunkSize: MinChunkSize})
	if err != nil {
		t.Fatal(err)
	}
	// idempotent create by the same owner; conflict for another
	if g, err := s.Create(ctx, "a", CreateSpec{ID: "job-0001-out", Name: "out.wav", ChunkSize: MinChunkSize}); err != nil || g.ID != f.ID {
		t.Fatal("idempotent create")
	}
	if _, err := s.Create(ctx, "b", CreateSpec{ID: "job-0001-out", Name: "out.wav"}); !errors.Is(err, ErrConflict) {
		t.Fatal("id owned by another app")
	}
	if _, err := s.Commit(ctx, "a", f.ID, ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty")
	}
	_, _ = s.PutChunk(ctx, "a", f.ID, 1, []byte("tail"))
	if _, err := s.Commit(ctx, "a", f.ID, ""); err == nil || !strings.Contains(err.Error(), "chunk 0 is missing") {
		t.Fatalf("gap: %v", err)
	}
	_, _ = s.PutChunk(ctx, "a", f.ID, 0, []byte("short"))
	if _, err := s.Commit(ctx, "a", f.ID, ""); err == nil || !strings.Contains(err.Error(), "all but the last") {
		t.Fatalf("short: %v", err)
	}
	_, _ = s.PutChunk(ctx, "a", f.ID, 0, bytes.Repeat([]byte{1}, MinChunkSize))
	if _, err := s.Commit(ctx, "a", f.ID, strings.Repeat("0", 64)); !errors.Is(err, ErrConflict) {
		t.Fatal("sha mismatch")
	}
	if _, err := s.PutChunk(ctx, "a", f.ID, 2, make([]byte, MinChunkSize+1)); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversize chunk")
	}
	if _, err := s.Commit(ctx, "a", f.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, "a", CreateSpec{Name: "x", ChunkSize: MaxChunkSize + 1}); !errors.Is(err, ErrInvalid) {
		t.Fatal("chunk size")
	}
	if _, err := s.Create(ctx, "a", CreateSpec{ID: "BAD", Name: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatal("id")
	}
}

func TestSweep(t *testing.T) {
	s, kms, _ := open(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	keep := upload(t, s, "a", "keep", []byte("k"), MinChunkSize)
	f, _ := s.Create(ctx, "a", CreateSpec{Name: "tmp", ExpiresInS: 60})
	_, _ = s.PutChunk(ctx, "a", f.ID, 0, []byte("t"))
	_, _ = s.Commit(ctx, "a", f.ID, "")
	abandoned, _ := s.Create(ctx, "a", CreateSpec{Name: "half"})
	if n, _ := s.Sweep(ctx); n != 0 {
		t.Fatal("nothing due yet")
	}
	now = now.Add(2 * time.Minute)
	if n, _ := s.Sweep(ctx); n != 1 {
		t.Fatalf("expired: %d", n)
	}
	now = now.Add(25 * time.Hour)
	if n, _ := s.Sweep(ctx); n != 1 {
		t.Fatalf("abandoned: %d", n)
	}
	if _, err := s.Get("a", abandoned.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("abandoned upload swept")
	}
	if _, err := s.Get("a", keep.ID); err != nil {
		t.Fatal("kept")
	}
	if _, ok := kms.keys["file-"+keep.ID]; !ok || len(kms.keys) != 1 {
		t.Fatalf("keys %d", len(kms.keys))
	}
}
