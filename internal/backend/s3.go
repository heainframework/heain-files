package backend

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// S3 stores objects in an S3-compatible bucket (AWS S3, MinIO, Ceph RGW,
// ...) with path-style requests signed with AWS Signature Version 4. No SDK
// dependency: PUT, GET and DELETE of single objects is all heain-files needs.
type S3 struct {
	Endpoint  string // e.g. https://minio.local:9000
	Region    string // e.g. us-east-1
	Bucket    string
	Prefix    string // optional key prefix
	AccessKey string
	SecretKey string
	HTTP      *http.Client
	now       func() time.Time
}

// Kind names the backend.
func (S3) Kind() string { return "s3" }

func (s S3) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func hmacSHA(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// uriEncode is SigV4's path encoding (each segment, '/' kept).
func uriEncode(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = strings.ReplaceAll(url.PathEscape(s), "+", "%2B")
	}
	return strings.Join(parts, "/")
}

func (s S3) do(ctx context.Context, method, name string, body []byte) (*http.Response, error) {
	u, err := url.Parse(strings.TrimSuffix(s.Endpoint, "/"))
	if err != nil {
		return nil, err
	}
	key := strings.TrimPrefix(s.Prefix+name, "/")
	path := "/" + s.Bucket + "/" + key
	u.Path, u.RawPath = path, uriEncode(path)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if s.now != nil {
		now = s.now().UTC()
	}
	amzDate, day := now.Format("20060102T150405Z"), now.Format("20060102")
	payloadHash := sha256Hex(body)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	host := u.Host
	canonHeaders := "host:" + host + "\nx-amz-content-sha256:" + payloadHash + "\nx-amz-date:" + amzDate + "\n"
	signed := "host;x-amz-content-sha256;x-amz-date"
	canon := strings.Join([]string{method, uriEncode(path), "", canonHeaders, signed, payloadHash}, "\n")
	scope := day + "/" + s.Region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canon))
	k := hmacSHA([]byte("AWS4"+s.SecretKey), day)
	k = hmacSHA(k, s.Region)
	k = hmacSHA(k, "s3")
	k = hmacSHA(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA(k, toSign))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", s.AccessKey, scope, signed, sig))
	return s.client().Do(req)
}

// Put uploads name.
func (s S3) Put(ctx context.Context, name string, data []byte) error {
	resp, err := s.do(ctx, http.MethodPut, name, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("backend s3: PUT %s: %d %s", name, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// Get downloads name.
func (s S3) Get(ctx context.Context, name string) ([]byte, error) {
	resp, err := s.do(ctx, http.MethodGet, name, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("backend s3: GET %s: %d", name, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// Delete removes name (S3 DELETE is idempotent).
func (s S3) Delete(ctx context.Context, name string) error {
	resp, err := s.do(ctx, http.MethodDelete, name, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("backend s3: DELETE %s: %d", name, resp.StatusCode)
	}
	return nil
}
