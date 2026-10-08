// Package store keeps heain-files' file records and chunks.
//
// Every file has its own data key in heain-core's KMS ("file-<id>"), so a
// delete is a crypto-shred of just that file. Chunks are sealed under it
// (AES-256-GCM, additional data "<id>/chunk/<n>") before they reach the
// backend, under opaque names derived from a blinded id. The records --
// owner, name, size, hashes, sharing -- are sealed under the app's "inside"
// key in a BoltDB file, and names are found through HMAC indexes, so no
// plaintext name or content rests on disk or in the object store.
package store

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-files/internal/backend"
)

// Limits.
const (
	DefaultChunkSize = 8 << 20
	MinChunkSize     = 64 << 10
	// MaxChunkSize keeps one chunk inside a heain-job payload (decision
	// 2026-10-06: chunks travel with the job, about 32 MiB at most).
	MaxChunkSize = 32 << 20
	MaxChunks    = 1 << 20
)

// Errors the API maps to status codes.
var (
	ErrNotFound  = errors.New("not found")
	ErrForbidden = errors.New("forbidden")
	ErrConflict  = errors.New("conflict")
	ErrInvalid   = errors.New("invalid")
)

// IDPattern is what a caller-chosen file id must look like (so the core
// key name "file-<id>" stays valid).
var IDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{7,47}$`)

var appPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// States of a file.
const (
	StateUploading = "uploading"
	StateCommitted = "committed"
)

// Chunk is one stored chunk.
type Chunk struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

// File is a file record.
type File struct {
	ID          string            `json:"id"`
	Owner       string            `json:"owner"`
	Name        string            `json:"name"`
	Version     int               `json:"version"`
	ContentType string            `json:"content_type,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	State       string            `json:"state"`
	ChunkSize   int               `json:"chunk_size"`
	Chunks      []Chunk           `json:"chunks"` // index = chunk number; Size 0 = not yet uploaded
	Size        int64             `json:"size"`
	SHA256      string            `json:"sha256,omitempty"`
	SharedWith  []string          `json:"shared_with,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	CommittedAt *time.Time        `json:"committed_at,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	Backend     string            `json:"backend"`
	// Instance is set on answers only (the heain-files instance that holds
	// the file), never stored.
	Instance string `json:"instance,omitempty"`
}

// CanRead: the owner and the apps the file is shared with.
func (f *File) CanRead(app string) bool {
	if app == f.Owner {
		return true
	}
	for _, a := range f.SharedWith {
		if a == app {
			return true
		}
	}
	return false
}

// Keys is what the store needs from heain-core's KMS.
type Keys struct {
	Sealer  func(ctx context.Context, name string) (*heain.Sealer, error)
	Destroy func(ctx context.Context, name string) error
}

// Store is the file store.
type Store struct {
	db        *bolt.DB
	inside    *heain.Sealer
	mac       []byte
	be        backend.Backend
	keys      Keys
	now       func() time.Time
	mu        sync.Mutex // serialises chunk writes per store (records are read-modify-write)
	UploadTTL time.Duration
}

var (
	bFiles  = []byte("files")  // id -> sealed File
	bNames  = []byte("names")  // HMAC(owner,name) -> sealed []id (versions, oldest first)
	bOwners = []byte("owners") // HMAC(owner) || id -> nil
	bExpiry = []byte("expiry") // be64(unix) || id -> nil
)

// Open opens (or creates) the record database at path.
func Open(path string, insideKey []byte, be backend.Backend, keys Keys) (*Store, error) {
	s, err := heain.NewSealer(insideKey)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bFiles, bNames, bOwners, bExpiry} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	m := hmac.New(sha256.New, insideKey)
	m.Write([]byte("heain-files/index/v1"))
	return &Store{db: db, inside: s, mac: m.Sum(nil), be: be, keys: keys, now: time.Now, UploadTTL: 24 * time.Hour}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Backend is the chunk backend's kind.
func (s *Store) Backend() string { return s.be.Kind() }

func (s *Store) index(parts ...string) []byte {
	m := hmac.New(sha256.New, s.mac)
	m.Write([]byte(strings.Join(parts, "\x00")))
	return m.Sum(nil)
}

func (s *Store) objectName(id string, n int) string {
	h := hex.EncodeToString(s.index("object", id))
	return h[:2] + "/" + h[2:40] + "/" + fmt.Sprint(n)
}

func keyName(id string) string { return "file-" + id }

func chunkAAD(id string, n int) []byte { return []byte(fmt.Sprintf("%s/chunk/%d", id, n)) }

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Store) get(tx *bolt.Tx, id string) (*File, error) {
	raw := tx.Bucket(bFiles).Get([]byte(id))
	if raw == nil {
		return nil, ErrNotFound
	}
	pt, err := s.inside.Open(raw, []byte("file/"+id))
	if err != nil {
		return nil, err
	}
	var f File
	return &f, json.Unmarshal(pt, &f)
}

func (s *Store) put(tx *bolt.Tx, f *File) error {
	c := *f
	c.Instance = ""
	raw, _ := json.Marshal(&c)
	return tx.Bucket(bFiles).Put([]byte(f.ID), s.inside.Seal(raw, []byte("file/"+f.ID)))
}

func (s *Store) versions(tx *bolt.Tx, owner, name string) ([]string, error) {
	k := s.index("name", owner, name)
	raw := tx.Bucket(bNames).Get(k)
	if raw == nil {
		return nil, nil
	}
	pt, err := s.inside.Open(raw, append([]byte("names/"), k...))
	if err != nil {
		return nil, err
	}
	var ids []string
	return ids, json.Unmarshal(pt, &ids)
}

func (s *Store) setVersions(tx *bolt.Tx, owner, name string, ids []string) error {
	k := s.index("name", owner, name)
	if len(ids) == 0 {
		return tx.Bucket(bNames).Delete(k)
	}
	raw, _ := json.Marshal(ids)
	return tx.Bucket(bNames).Put(k, s.inside.Seal(raw, append([]byte("names/"), k...)))
}

func expiryKey(t time.Time, id string) []byte {
	k := make([]byte, 8, 8+len(id))
	binary.BigEndian.PutUint64(k, uint64(t.Unix()))
	return append(k, id...)
}

// CreateSpec is a new upload.
type CreateSpec struct {
	ID          string            `json:"id,omitempty"` // optional caller-chosen id (idempotent create)
	Name        string            `json:"name"`
	ContentType string            `json:"content_type,omitempty"`
	ChunkSize   int               `json:"chunk_size,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	SharedWith  []string          `json:"shared_with,omitempty"`
	ExpiresInS  int64             `json:"expires_in_s,omitempty"`
}

func validApps(apps []string) error {
	for _, a := range apps {
		if !appPattern.MatchString(a) {
			return fmt.Errorf("%w: shared_with %q is not an app id", ErrInvalid, a)
		}
	}
	return nil
}

// Create starts an upload owned by owner. Creating again with the same
// caller-chosen id by the same owner returns the existing record (so a
// retried job can resume its upload).
func (s *Store) Create(ctx context.Context, owner string, spec CreateSpec) (*File, error) {
	if spec.Name == "" || len(spec.Name) > 1024 {
		return nil, fmt.Errorf("%w: name is required (at most 1024 bytes)", ErrInvalid)
	}
	if spec.ChunkSize == 0 {
		spec.ChunkSize = DefaultChunkSize
	}
	if spec.ChunkSize < MinChunkSize || spec.ChunkSize > MaxChunkSize {
		return nil, fmt.Errorf("%w: chunk_size must be %d..%d bytes", ErrInvalid, MinChunkSize, MaxChunkSize)
	}
	if err := validApps(spec.SharedWith); err != nil {
		return nil, err
	}
	if spec.ExpiresInS < 0 {
		return nil, fmt.Errorf("%w: expires_in_s", ErrInvalid)
	}
	id := spec.ID
	if id == "" {
		id = newID()
	} else if !IDPattern.MatchString(id) {
		return nil, fmt.Errorf("%w: id must match %s", ErrInvalid, IDPattern)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out *File
	err := s.db.Update(func(tx *bolt.Tx) error {
		if f, err := s.get(tx, id); err == nil {
			if f.Owner != owner {
				return ErrConflict
			}
			if f.Name != spec.Name {
				return fmt.Errorf("%w: id %s already names another file", ErrConflict, id)
			}
			out = f
			return nil
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		now := s.now().UTC()
		f := &File{ID: id, Owner: owner, Name: spec.Name, ContentType: spec.ContentType, Labels: spec.Labels,
			State: StateUploading, ChunkSize: spec.ChunkSize, SharedWith: spec.SharedWith, CreatedAt: now, Backend: s.be.Kind()}
		if spec.ExpiresInS > 0 {
			t := now.Add(time.Duration(spec.ExpiresInS) * time.Second)
			f.ExpiresAt = &t
		}
		// an unfinished upload expires after UploadTTL unless committed
		exp := now.Add(s.UploadTTL)
		if err := tx.Bucket(bExpiry).Put(expiryKey(exp, id), nil); err != nil {
			return err
		}
		if err := tx.Bucket(bOwners).Put(append(s.index("owner", owner), id...), nil); err != nil {
			return err
		}
		out = f
		return s.put(tx, f)
	})
	if err != nil {
		return nil, err
	}
	// make sure the file's key exists in core before any chunk arrives
	if _, err := s.keys.Sealer(ctx, keyName(id)); err != nil {
		return nil, err
	}
	return out, nil
}

// Get returns a file record the caller may read.
func (s *Store) Get(app, id string) (*File, error) {
	var f *File
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		f, err = s.get(tx, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !f.CanRead(app) {
		return nil, ErrNotFound // do not reveal other apps' files
	}
	return f, nil
}

// PutChunk stores chunk n of an upload owned by owner.
func (s *Store) PutChunk(ctx context.Context, owner, id string, n int, data []byte) (*Chunk, error) {
	f, err := s.Get(owner, id)
	if err != nil {
		return nil, err
	}
	if f.Owner != owner {
		return nil, ErrForbidden
	}
	if f.State != StateUploading {
		return nil, fmt.Errorf("%w: file is committed (files are immutable; upload a new version)", ErrConflict)
	}
	if n < 0 || n >= MaxChunks {
		return nil, fmt.Errorf("%w: chunk number", ErrInvalid)
	}
	if len(data) == 0 || len(data) > f.ChunkSize {
		return nil, fmt.Errorf("%w: chunk must be 1..%d bytes", ErrInvalid, f.ChunkSize)
	}
	sl, err := s.keys.Sealer(ctx, keyName(id))
	if err != nil {
		return nil, err
	}
	if err := s.be.Put(ctx, s.objectName(id, n), sl.Seal(data, chunkAAD(id, n))); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	c := Chunk{Size: len(data), SHA256: hex.EncodeToString(sum[:])}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.db.Update(func(tx *bolt.Tx) error {
		f, err := s.get(tx, id)
		if err != nil {
			return err
		}
		if f.State != StateUploading {
			return ErrConflict
		}
		for len(f.Chunks) <= n {
			f.Chunks = append(f.Chunks, Chunk{})
		}
		f.Chunks[n] = c
		return s.put(tx, f)
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Commit seals an upload: every chunk 0..k-1 present, all but the last
// full-size. If wantSHA is set the whole content must hash to it. The file
// becomes immutable and the newest version of its name.
func (s *Store) Commit(ctx context.Context, owner, id, wantSHA string) (*File, error) {
	f, err := s.Get(owner, id)
	if err != nil {
		return nil, err
	}
	if f.Owner != owner {
		return nil, ErrForbidden
	}
	if f.State == StateCommitted {
		if wantSHA != "" && wantSHA != f.SHA256 {
			return nil, fmt.Errorf("%w: sha256 does not match the committed file", ErrConflict)
		}
		return f, nil
	}
	if len(f.Chunks) == 0 {
		return nil, fmt.Errorf("%w: no chunks uploaded", ErrInvalid)
	}
	var size int64
	for i, c := range f.Chunks {
		if c.Size == 0 {
			return nil, fmt.Errorf("%w: chunk %d is missing", ErrInvalid, i)
		}
		if i < len(f.Chunks)-1 && c.Size != f.ChunkSize {
			return nil, fmt.Errorf("%w: chunk %d is %d bytes; all but the last must be %d", ErrInvalid, i, c.Size, f.ChunkSize)
		}
		size += int64(c.Size)
	}
	// hash the whole content from the stored ciphertext (proves it is readable)
	h := sha256.New()
	for i := range f.Chunks {
		b, err := s.readChunk(ctx, f, i)
		if err != nil {
			return nil, err
		}
		h.Write(b)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if wantSHA != "" && !strings.EqualFold(wantSHA, sum) {
		return nil, fmt.Errorf("%w: content sha256 is %s, not %s", ErrConflict, sum, wantSHA)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out *File
	err = s.db.Update(func(tx *bolt.Tx) error {
		f, err := s.get(tx, id)
		if err != nil {
			return err
		}
		if f.State == StateCommitted {
			out = f
			return nil
		}
		vs, err := s.versions(tx, owner, f.Name)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		f.State, f.Size, f.SHA256, f.CommittedAt, f.Version = StateCommitted, size, sum, &now, len(vs)+1
		if len(vs) > 0 {
			if last, err := s.get(tx, vs[len(vs)-1]); err == nil {
				f.Version = last.Version + 1
			}
		}
		if err := s.setVersions(tx, owner, f.Name, append(vs, id)); err != nil {
			return err
		}
		// swap the upload deadline for the file's own expiry (if any)
		if err := s.dropExpiry(tx, id); err != nil {
			return err
		}
		if f.ExpiresAt != nil {
			if err := tx.Bucket(bExpiry).Put(expiryKey(*f.ExpiresAt, id), nil); err != nil {
				return err
			}
		}
		out = f
		return s.put(tx, f)
	})
	return out, err
}

func (s *Store) dropExpiry(tx *bolt.Tx, id string) error {
	c := tx.Bucket(bExpiry).Cursor()
	var dead [][]byte
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		if len(k) > 8 && string(k[8:]) == id {
			dead = append(dead, append([]byte(nil), k...))
		}
	}
	for _, k := range dead {
		if err := tx.Bucket(bExpiry).Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) readChunk(ctx context.Context, f *File, n int) ([]byte, error) {
	sl, err := s.keys.Sealer(ctx, keyName(f.ID))
	if err != nil {
		return nil, err
	}
	raw, err := s.be.Get(ctx, s.objectName(f.ID, n))
	if err != nil {
		return nil, err
	}
	pt, err := sl.Open(raw, chunkAAD(f.ID, n))
	if err != nil {
		return nil, fmt.Errorf("chunk %d of %s: %w", n, f.ID, err)
	}
	if want := f.Chunks[n].SHA256; want != "" {
		if sum := sha256.Sum256(pt); hex.EncodeToString(sum[:]) != want {
			return nil, fmt.Errorf("chunk %d of %s: hash mismatch", n, f.ID)
		}
	}
	return pt, nil
}

// ReadChunk returns chunk n of a committed file the caller may read.
func (s *Store) ReadChunk(ctx context.Context, app, id string, n int) ([]byte, *File, error) {
	f, err := s.Get(app, id)
	if err != nil {
		return nil, nil, err
	}
	if f.State != StateCommitted {
		return nil, nil, fmt.Errorf("%w: file is not committed", ErrConflict)
	}
	if n < 0 || n >= len(f.Chunks) {
		return nil, nil, ErrNotFound
	}
	b, err := s.readChunk(ctx, f, n)
	return b, f, err
}

// Versions lists the committed versions of owner's name, oldest first.
func (s *Store) Versions(owner, name string) ([]*File, error) {
	var out []*File
	err := s.db.View(func(tx *bolt.Tx) error {
		ids, err := s.versions(tx, owner, name)
		if err != nil {
			return err
		}
		for _, id := range ids {
			f, err := s.get(tx, id)
			if err != nil {
				return err
			}
			out = append(out, f)
		}
		return nil
	})
	return out, err
}

// List returns the files owned by owner (newest first).
func (s *Store) List(owner string) ([]*File, error) {
	var out []*File
	err := s.db.View(func(tx *bolt.Tx) error {
		p := s.index("owner", owner)
		c := tx.Bucket(bOwners).Cursor()
		for k, _ := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, _ = c.Next() {
			f, err := s.get(tx, string(k[len(p):]))
			if err != nil {
				return err
			}
			out = append(out, f)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, err
}

// Share replaces the apps a file is shared with (owner only).
func (s *Store) Share(owner, id string, apps []string) (*File, error) {
	if err := validApps(apps); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out *File
	err := s.db.Update(func(tx *bolt.Tx) error {
		f, err := s.get(tx, id)
		if err != nil {
			return err
		}
		if f.Owner != owner {
			if f.CanRead(owner) {
				return ErrForbidden
			}
			return ErrNotFound
		}
		f.SharedWith = apps
		out = f
		return s.put(tx, f)
	})
	return out, err
}

// Delete crypto-shreds a file (owner only): its key is destroyed in core
// first, then its chunks and record are removed.
func (s *Store) Delete(ctx context.Context, owner, id string) error {
	f, err := s.Get(owner, id)
	if err != nil {
		return err
	}
	if f.Owner != owner {
		return ErrForbidden
	}
	return s.remove(ctx, f)
}

func (s *Store) remove(ctx context.Context, f *File) error {
	if err := s.keys.Destroy(ctx, keyName(f.ID)); err != nil {
		return err
	}
	for i := range f.Chunks {
		_ = s.be.Delete(ctx, s.objectName(f.ID, i)) // already unreadable; best effort
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		if f.State == StateCommitted {
			vs, err := s.versions(tx, f.Owner, f.Name)
			if err != nil {
				return err
			}
			keep := vs[:0]
			for _, v := range vs {
				if v != f.ID {
					keep = append(keep, v)
				}
			}
			if err := s.setVersions(tx, f.Owner, f.Name, keep); err != nil {
				return err
			}
		}
		if err := s.dropExpiry(tx, f.ID); err != nil {
			return err
		}
		if err := tx.Bucket(bOwners).Delete(append(s.index("owner", f.Owner), f.ID...)); err != nil {
			return err
		}
		return tx.Bucket(bFiles).Delete([]byte(f.ID))
	})
}

// Sweep removes expired files and abandoned uploads; it returns how many.
func (s *Store) Sweep(ctx context.Context) (int, error) {
	now := s.now().UTC()
	var due []string
	_ = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bExpiry).Cursor()
		for k, _ := c.First(); k != nil && len(k) > 8; k, _ = c.Next() {
			if int64(binary.BigEndian.Uint64(k[:8])) > now.Unix() {
				break
			}
			due = append(due, string(k[8:]))
		}
		return nil
	})
	n := 0
	for _, id := range due {
		var f *File
		_ = s.db.View(func(tx *bolt.Tx) error { f, _ = s.get(tx, id); return nil })
		if f == nil {
			_ = s.db.Update(func(tx *bolt.Tx) error { return s.dropExpiry(tx, id) })
			continue
		}
		if err := s.remove(ctx, f); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
