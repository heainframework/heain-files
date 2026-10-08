# heain-files

The file base app of the heain framework (Step 4e, 2026-10-06): large files — masters, footage,
audio stems, scans — stored for other heain apps in chunks, **each file under its own data key in
heain-core's KMS**, on the local disk by default or in any S3-compatible object store.

Built on [heain-sdk](https://github.com/heainframework/heain-sdk) v1; passes the heain conformance
suite. Runs however you like: a plain process, a service unit, or a container (Docker is not required).

## What it does

- **Chunked, immutable files.** `POST /v1/files` starts an upload (chunk size 64 KiB – 32 MiB,
  default 8 MiB); chunks go to `PUT /v1/files/{id}/chunks/{n}`; `POST /v1/files/{id}/commit`
  checks that every chunk is there (all but the last full-size) and, if given, the whole-file
  sha256. A committed file never changes; uploading the same name again makes version 2, 3, …
- **Per-file keys, crypto-shred.** Each file's chunks are sealed (AES-256-GCM, bound to
  `<id>/chunk/<n>`) under the key `file-<id>` from heain-core. `DELETE /v1/files/{id}` destroys that
  key first, so the content is unreadable everywhere — including backups and object-store copies.
- **Nothing plaintext at rest.** Records (owner, name, sizes, hashes, sharing) are sealed under the
  app's `inside` key; names are found through HMAC indexes; backend objects have opaque names.
- **Ownership by certificate.** The calling app (from its mTLS certificate) owns what it uploads.
  Another app sees a file only when the owner shares it (`PUT /v1/files/{id}/sharing`), and only
  the owner can change or delete it.
- **Resumable uploads.** A caller may choose the file id (`[a-z0-9][a-z0-9-]{7,47}`); creating again
  with the same id resumes the upload — useful for a heain-job module job that is retried.
- **Expiry.** `expires_in_s` removes a file (and its key) when due; an upload not committed within
  24 hours is removed too.
- Every call is a formal record in heain-core's audit (`files.write`, `files.read`).

## Across nodes

Files stay on the node that owns them. When work runs on another node, **the chunks travel inside
heain-job payloads** (core-encrypted, ≤ 32 MiB each): the job carries the chunk (`data_b64` from
`GET /v1/files/{id}/chunks/{n}`), and the result is stored back in heain-files on the origin node.
No core change is needed for this.

## Endpoints

| Method | Path | Capability |
|---|---|---|
| POST | `/v1/files` | files.write — `{id?, name, content_type?, chunk_size?, labels?, shared_with?, expires_in_s?}` |
| PUT | `/v1/files/{id}/chunks/{n}` | files.write — raw body (`application/octet-stream`) or JSON `{data_b64}` / `{data}` |
| POST | `/v1/files/{id}/commit` | files.write — `{sha256?}` |
| PUT | `/v1/files/{id}/sharing` | files.write — `{shared_with: [app ids]}` |
| DELETE | `/v1/files/{id}` | files.write — crypto-shred |
| GET | `/v1/files` | files.read — the caller's files; `?name=` lists that name's versions |
| GET | `/v1/files/{id}` | files.read — the record |
| GET | `/v1/files/{id}/chunks/{n}` | files.read — JSON `{n, size, sha256, last, data_b64}`, or raw with `Accept: application/octet-stream` |
| GET | `/v1/files/{id}/content` | files.read — the whole file |

Go apps can use the `client` package (`client.Upload`, `client.Download`, `client.Chunk`, …),
which calls through heain-sdk `App.Call`; declare `uses: heain-files files.write / files.read`.

## Running

```
heain-files [-backend disk|s3] [-disk-root DIR] [-sweep 1m]
```

Port 19490 (`HEAIN_LISTEN`). The disk backend writes to `<HEAIN_STATE_DIR>/blobs` unless
`-disk-root` / `HEAIN_FILES_DISK_ROOT` says otherwise. The S3-compatible backend (AWS S3, MinIO,
Ceph RGW, …; path-style, SigV4) takes its settings from the environment only:
`HEAIN_FILES_S3_ENDPOINT`, `HEAIN_FILES_S3_REGION` (default us-east-1), `HEAIN_FILES_S3_BUCKET`,
`HEAIN_FILES_S3_PREFIX`, `HEAIN_FILES_S3_ACCESS_KEY`, `HEAIN_FILES_S3_SECRET_KEY`. Either way the
backend only ever holds ciphertext.

## Tests

- `go test ./...` — backends (disk; S3 against a signature-checking fake), store (round trip,
  versions, sharing, immutability, commit checks, crypto-shred, expiry sweep, no plaintext on disk).
- `bash scripts/live_4e.sh` — against a real heain-core node (needs `~/heain-core`, `~/heain-sdk`).
- Conformance: `heain-conformance run --app . --core ~/heain-core`.

Not yet: a live run against a real S3-compatible store; range reads of the whole content.

## Stage B-1e: range reads and data by reference (1.1, 2026-10-08)

The author decided (2026-10-08) that large data travels by reference: a job names a heain-files file (and the part it needs) instead of carrying its bytes, and whoever processes it reads that range from heain-files and writes its result back as a stream. This closes "range reads of the whole content" above.

- **Range reads.** `GET /v1/files/{id}/content` honours one `Range: bytes=a-b` / `a-` / `-n` (206 with `Content-Range`; 416 outside the file; no or several ranges: the whole file). Only the chunks the range covers are read and opened, and the answer is streamed: its formal audit event is written before the first byte (`streamed: true`), not after the whole file was buffered.
- **Which instance.** Every file record carries `instance`, the heain-files instance that holds it, so an app on another node can name it.
- **Across the zone.** The data class `file` is now `zone-local`: a file stays on the node that stored it, and apps on other nodes of the same zone read it there by range over mTLS (ownership and sharing unchanged); nothing goes past the zone (P7).
- **Go client** (`client`): `Ref`; `Locate` (this node first, then every heain-files of the zone); `OpenRange` (a range as a stream); `UploadTo` (raw chunks as they are read, on a named instance); `DeleteRef`, `ShareRef`; `Loopback`, an `http://127.0.0.1` address behind an unguessable token for tools that read URLs by range (ffmpeg, ffprobe), answering only while the file is registered.
- **Not yet:** a live run against a real S3-compatible store.
