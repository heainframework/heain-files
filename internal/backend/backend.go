// Package backend is where heain-files puts its (already encrypted) chunks:
// the local disk by default, or any S3-compatible object store (author
// decision 2026-10-06: pluggable, disk default). A backend only ever sees
// ciphertext under opaque names.
package backend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotFound: no object under that name.
var ErrNotFound = errors.New("backend: not found")

// Backend stores opaque objects.
type Backend interface {
	Put(ctx context.Context, name string, data []byte) error
	Get(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	Kind() string
}

// Disk stores objects as files under Root (mode 0600, written atomically).
type Disk struct{ Root string }

func (d Disk) path(name string) (string, error) {
	if name == "" || strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("backend: bad object name %q", name)
	}
	return filepath.Join(d.Root, filepath.FromSlash(name)), nil
}

// Kind names the backend.
func (Disk) Kind() string { return "disk" }

// Put writes name atomically.
func (d Disk) Put(_ context.Context, name string, data []byte) error {
	p, err := d.path(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Get reads name.
func (d Disk) Get(_ context.Context, name string) ([]byte, error) {
	p, err := d.path(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

// Delete removes name (idempotent).
func (d Disk) Delete(_ context.Context, name string) error {
	p, err := d.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(filepath.Dir(p)) // drop the file's directory once empty
	return nil
}
