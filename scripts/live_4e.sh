#!/usr/bin/env bash
# heain-files live test 4e: heain-files v1 on heain-sdk v1 against a real heain-core node.
#  - a file uploaded in chunks (raw bytes or JSON data_b64), committed with its sha256, read back
#    whole and chunk by chunk; caller-chosen ids make a retried upload resume; names keep versions;
#  - each file has its own data key in core's KMS; nothing plaintext at rest or in core's audit;
#  - the calling app owns its files; another app reads only after the owner shares, and cannot delete;
#  - data survives a restart; delete destroys the file's key in core (crypto-shred); expiry sweeps.
# Disk backend (the default). The S3-compatible backend is covered by unit tests against a fake.
# Needs ~/heain-core, ~/heain-sdk. ~1 min.  Run from ~/heain-files:  bash scripts/live_4e.sh
set -uo pipefail
FS=$(cd "$(dirname "$0")/.." && pwd)
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/files-4e
URL=https://127.0.0.1:18000
FURL=https://127.0.0.1:19490
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
cl() { local who=$1; shift; curl -sk --noproxy '*' --cert "$W/$who.pem" --key "$W/$who.key" --cacert "$C/ca.pem" "$@"; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; }
runapp() { # <instance> <manifest> <port> <state> <binary> [args...]
  local inst=$1 man=$2 port=$3 st=$4; shift 4; mkdir -p "$st"
  HEAIN_MANIFEST=$man HEAIN_INSTANCE=$inst HEAIN_CORE_URL=$URL HEAIN_CORE_ID=G HEAIN_CA=$C/ca.pem HEAIN_CHAIN=$W/prov.pem \
  HEAIN_STATE_DIR=$st HEAIN_ENROLL_TOKEN=$W/$inst.tok HEAIN_ENDPOINT_BASE=https://127.0.0.1:$port HEAIN_LISTEN=127.0.0.1:$port \
    nohup "$@" >> "$W/$inst.log" 2>&1 &
  echo $! > "$P/$inst.pid"; }
pending() { as approver-1 $URL/v1/admin/policy/pending | j "' '.join(x['ID'] for x in d['actions'] if x['Type']=='$1')"; }
until_ok() { for i in $(seq 1 ${2:-20}); do eval "$1" && return 0; sleep 1; done; return 1; }
audit() { as admin "$URL/v1/admin/audit?limit=1000&from=${1:-1}"; }
client() { # <label> : a client certificate from core's provisioning
  as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$1.json"
  python3 - "$W" "$1" <<'PY'
import json,sys; w,l=sys.argv[1],sys.argv[2]; d=json.load(open(f"{w}/{l}.json"))
open(f"{w}/{l}.boot.pem","w").write(d["bootstrap_cert_pem"]+open(w+"/prov.pem").read()); open(f"{w}/{l}.boot.key","w").write(d["bootstrap_key_pem"]); open(f"{w}/{l}.token","w").write(d["token"])
PY
  openssl genrsa -out "$W/$1.key" 2048 >/dev/null 2>&1; openssl req -new -key "$W/$1.key" -subj "/CN=$1" -out "$W/$1.csr" >/dev/null 2>&1
  python3 -c "import json;print(json.dumps({'token':open('$W/$1.token').read(),'csr_pem':open('$W/$1.csr').read()}))" > "$W/$1.req"
  curl -sk --noproxy '*' --cert "$W/$1.boot.pem" --key "$W/$1.boot.key" --cacert "$C/ca.pem" -X POST -H 'Content-Type: application/json' -d @"$W/$1.req" $URL/provision/csr \
    | python3 -c "import json,sys;open('$W/$1.pem','w').write(json.load(sys.stdin)['cert_pem']+open('$W/prov.pem').read())"; }

echo "== 0. core node G; build heain-files"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
: > "$L/G.log"
nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -approval-store-path="$T/data-G/approvals.db" -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 6
( cd "$FS" && GOFLAGS= GOWORK=${SDK_GOWORK:-} go build -o "$W/heain-files" ./cmd/heain-files ) && ok "heain-files builds" || { bad "build"; exit 1; }
for k in $(seq 1 15); do [ "$(code admin -X POST -H 'Content-Type: application/json' -d '{"label":"probe.x"}' $URL/provision/token)" = 200 ] && break; sleep 1; done
client mediaapp.c1; client reader.c2

echo "== 1. heain-files starts and is admitted"
as admin -X POST -H 'Content-Type: application/json' -d '{"label":"heain-files.f1"}' $URL/provision/token > "$W/f1.tok"
runapp f1 "$FS/heain-app.yaml" 19490 "$W/state-f1" "$W/heain-files" -sweep 1s
for k in $(seq 1 40); do for a in $(pending app.register); do code approver-1 -X POST $URL/v1/admin/policy/$a/approve >/dev/null; done
  grep -q "heain-files: active" "$W/f1.log" && break; sleep 1; done
grep -q "heain-files: active" "$W/f1.log" && ok "admitted (P5 app.register) and serving ($(grep -o 'backend: [a-z0-9]*' "$W/f1.log" | head -1))" || { bad "start: $(tail -3 "$W/f1.log")"; $H stop-all >/dev/null 2>&1; exit 1; }

echo "== 2. chunked upload, commit with sha256, read back"
python3 - "$W/src.bin" <<'PY'
import sys,os; open(sys.argv[1],"wb").write(b"SECRET-MASTER-REEL-" * 9000 + os.urandom(5000))   # ~176 KB = 3 chunks of 64 KiB
PY
SHA=$(sha256sum "$W/src.bin" | cut -d' ' -f1); split -b 65536 -d -a 2 "$W/src.bin" "$W/part."
r=$(cl mediaapp.c1 -X POST -d '{"name":"masters/SECRET-reel-1.mov","content_type":"video/quicktime","chunk_size":65536}' $FURL/v1/files)
ID=$(echo "$r" | j "d['id']"); [ -n "$ID" ] && [ "$(echo "$r" | j "d['state']")" = uploading ] && ok "upload created (id ${ID:0:8}…, chunk 64 KiB)" || bad "create: $r"
n=0; for p in "$W"/part.*; do cl mediaapp.c1 -o /dev/null -X PUT -H 'Content-Type: application/octet-stream' --data-binary @"$p" $FURL/v1/files/$ID/chunks/$n; n=$((n+1)); done
[ "$(cl mediaapp.c1 -o /dev/null -w '%{http_code}' -X POST -d "{\"sha256\":\"$(printf '0%.0s' $(seq 64))\"}" $FURL/v1/files/$ID/commit)" = 409 ] && ok "commit with a wrong sha256 is refused (409)" || bad "bad sha"
r=$(cl mediaapp.c1 -X POST -d "{\"sha256\":\"$SHA\"}" $FURL/v1/files/$ID/commit)
[ "$(echo "$r" | j "d['state'], len(d['chunks']), d['version']")" = "committed 3 1" ] && ok "committed: 3 chunks, version 1, sha256 checked" || bad "commit: $r"
[ "$(cl mediaapp.c1 -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/octet-stream' --data-binary x $FURL/v1/files/$ID/chunks/0)" = 409 ] && ok "a committed file is immutable (409)" || bad "immutable"
cl mediaapp.c1 $FURL/v1/files/$ID/content -o "$W/back.bin"
cmp -s "$W/src.bin" "$W/back.bin" && ok "whole content reads back identical ($(stat -c %s "$W/back.bin") bytes)" || bad "content"
[ "$(cl mediaapp.c1 $FURL/v1/files/$ID/chunks/1 | python3 -c "import json,sys,base64,hashlib;d=json.load(sys.stdin);b=base64.b64decode(d['data_b64']);print(hashlib.sha256(b).hexdigest()==d['sha256'] and b==open('$W/part.01','rb').read())")" = True ] \
  && ok "chunk 1 as JSON data_b64 (what heain-sdk App.Call and module jobs carry) matches, hash included" || bad "chunk json"
r=$(cl mediaapp.c1 -X POST -d '{"id":"job-7f3a-out-0001","name":"masters/SECRET-reel-1.mov","chunk_size":65536}' $FURL/v1/files)
cl mediaapp.c1 -o /dev/null -X PUT -d "{\"data_b64\":\"$(printf 'second version' | base64 -w0)\"}" $FURL/v1/files/job-7f3a-out-0001/chunks/0
[ "$(cl mediaapp.c1 -X POST -d '{"id":"job-7f3a-out-0001","name":"masters/SECRET-reel-1.mov","chunk_size":65536}' $FURL/v1/files | j "d['id'], d['state']")" = "job-7f3a-out-0001 uploading" ] \
  && ok "create again with the same caller-chosen id resumes the upload (a retried job)" || bad "idempotent"
cl mediaapp.c1 -o /dev/null -X POST $FURL/v1/files/job-7f3a-out-0001/commit
[ "$(cl mediaapp.c1 "$FURL/v1/files?name=masters/SECRET-reel-1.mov" | j "[f['version'] for f in d['files']]")" = "[1, 2]" ] && ok "the name keeps both versions (1, 2)" || bad "versions"

echo "== 3. ownership and sharing"
[ "$(cl reader.c2 -o /dev/null -w '%{http_code}' $FURL/v1/files/$ID)" = 404 ] && [ "$(cl reader.c2 $FURL/v1/files | j "len(d['files'])")" = 0 ] && ok "another app does not see the file (404, empty list)" || bad "hidden"
[ "$(cl reader.c2 -o /dev/null -w '%{http_code}' -X PUT -d '{"shared_with":["reader"]}' $FURL/v1/files/$ID/sharing)" = 404 ] && ok "another app cannot share it to itself" || bad "self-share"
cl mediaapp.c1 -o /dev/null -X PUT -d '{"shared_with":["reader"]}' $FURL/v1/files/$ID/sharing
cl reader.c2 $FURL/v1/files/$ID/content -o "$W/shared.bin"; cmp -s "$W/src.bin" "$W/shared.bin" && ok "shared with app 'reader': it reads the content" || bad "shared read"
[ "$(cl reader.c2 -o /dev/null -w '%{http_code}' -X DELETE $FURL/v1/files/$ID)" = 403 ] && ok "a reader cannot delete (403)" || bad "reader delete"
[ "$(audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Actor'].startswith('heain-files.') and x['event']['Detail'].get('capability') in ('files.write','files.read'))")" -ge 10 ] \
  && ok "every call is a formal record in core's audit (files.write / files.read)" || bad "audit records"

echo "== 4. nothing plaintext at rest; restart"
! grep -rqaF -e SECRET-MASTER-REEL -e SECRET-reel -e "second version" "$W/state-f1" && ok "state dir (records and blobs) holds no content and no file name" || bad "plaintext at rest"
! audit | grep -q -e SECRET-MASTER-REEL -e SECRET-reel && ok "no content or file name in core's audit" || bad "audit leak"
[ "$(audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.key_created' and x['event']['Detail']['key_id'].startswith('file-'))")" -ge 2 ] && ok "each file got its own data key in core's KMS (file-<id>)" || bad "per-file keys"
kill -TERM "$(cat "$P/f1.pid")"; sleep 2; runapp f1 "$FS/heain-app.yaml" 19490 "$W/state-f1" "$W/heain-files" -sweep 1s
until_ok '[ "$(grep -c "heain-files: active" "$W/f1.log")" -ge 2 ]' 30
cl mediaapp.c1 $FURL/v1/files/$ID/content -o "$W/after.bin"; cmp -s "$W/src.bin" "$W/after.bin" && ok "after a restart the file reads back (keys from core)" || bad "restart"

echo "== 5. delete = crypto-shred; expiry"
B0=$(find "$W/state-f1/blobs" -type f | wc -l)
[ "$(cl mediaapp.c1 -X DELETE $FURL/v1/files/$ID | j "d['crypto_shredded']")" = True ] && [ "$(cl mediaapp.c1 -o /dev/null -w '%{http_code}' $FURL/v1/files/$ID)" = 404 ] \
  && [ "$(audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.key_destroyed' and x['event']['Detail']['key_id']=='file-$ID')")" = 1 ] \
  && ok "deleted: key file-${ID:0:8}… destroyed in core, record gone (404)" || bad "delete"
[ "$(find "$W/state-f1/blobs" -type f | wc -l)" = $((B0-3)) ] && ok "its 3 chunk objects removed from the backend" || bad "chunks left ($B0 -> $(find "$W/state-f1/blobs" -type f | wc -l))"
E=$(cl mediaapp.c1 -X POST -d '{"name":"tmp/preview.jpg","expires_in_s":2}' $FURL/v1/files | j "d['id']")
cl mediaapp.c1 -o /dev/null -X PUT -d '{"data":"short-lived preview"}' $FURL/v1/files/$E/chunks/0; cl mediaapp.c1 -o /dev/null -X POST $FURL/v1/files/$E/commit
until_ok '[ "$(cl mediaapp.c1 -o /dev/null -w "%{http_code}" $FURL/v1/files/$E)" = 404 ]' 15 && ok "a file past expires_in_s is swept (key destroyed)" || bad "expiry"
[ "$(as admin "$URL/v1/admin/audit/verify" | j "d['ok']")" = True ] && ok "core audit chain verifies" || bad "audit verify"

echo "== cleanup"
kill -TERM "$(cat "$P/f1.pid")" 2>/dev/null; sleep 2
$H stop-all >/dev/null 2>&1
echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
