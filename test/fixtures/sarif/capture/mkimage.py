# builds a minimal docker-archive tarball (alpine 3.10.2 with an old musl and a fake secret) without docker
import hashlib, io, json, sys, tarfile
out = sys.argv[1]
def add(t, name, data, mode=0o644):
    ti = tarfile.TarInfo(name); ti.size = len(data); ti.mode = mode; ti.mtime = 0
    t.addfile(ti, io.BytesIO(data))
layer = io.BytesIO()
with tarfile.open(fileobj=layer, mode='w') as t:
    add(t, 'etc/os-release', b'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.10.2\nPRETTY_NAME="Alpine Linux v3.10"\n')
    add(t, 'etc/alpine-release', b'3.10.2\n')
    add(t, 'lib/apk/db/installed', b'C:Q1' + b'A' * 27 + b'=\nP:musl\nV:1.1.22-r3\nA:x86_64\nS:1\nI:1\nT:the musl c library\nU:https://musl.libc.org/\nL:MIT\no:musl\n\nC:Q1' + b'B' * 27 + b'=\nP:busybox\nV:1.30.1-r2\nA:x86_64\nS:1\nI:1\nT:busybox\nU:https://busybox.net/\nL:GPL-2.0-only\no:busybox\n\n')
    tok = 'gh' + 'p_' + hashlib.sha256(b'image-one').hexdigest()[:18].upper() + hashlib.sha256(b'image-one').hexdigest()[:18]
    add(t, 'app/.env', ('GITHUB_' + 'TOK' + 'EN=' + tok + '\n').encode())
layer_bytes = layer.getvalue()
diff_id = 'sha256:' + hashlib.sha256(layer_bytes).hexdigest()
cfg = {'architecture': 'amd64', 'os': 'linux', 'config': {'Cmd': ['/bin/sh']}, 'rootfs': {'type': 'layers', 'diff_ids': [diff_id]},
       'history': [{'created': '2019-08-20T00:00:00Z', 'created_by': '/bin/sh -c #(nop) ADD file in /'}]}
cfg_bytes = json.dumps(cfg).encode()
manifest = json.dumps([{'Config': 'config.json', 'RepoTags': ['fixture:latest'], 'Layers': ['layer.tar']}]).encode()
with tarfile.open(out, 'w') as t:
    add(t, 'manifest.json', manifest); add(t, 'config.json', cfg_bytes); add(t, 'layer.tar', layer_bytes)
