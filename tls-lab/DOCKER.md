# Chạy lab bằng Docker

## 1. Kiến trúc (3 container trên mạng `lab`)

```
client ──(TLS)──► mitm:4434 ──(proxy: strip/mangle)──► server:443  (nginx, TLS1.2+1.3, ECDHE-RSA)
   └─────────────────(TLS trực tiếp)──────────────────► server:443
```

| Service | Ảnh nền | Vai trò |
|---|---|---|
| `server` | `nginx:stable` | hostname `lab.local`, nghe 443, bật TLS 1.2 + 1.3, cipher ECDHE-RSA (xem `server/nginx.conf`) |
| `mitm`   | `python:3.12-slim` | proxy nghe `0.0.0.0:4434`, chuyển tiếp tới `server:443`; xóa `supported_versions` (và tùy chọn xóa sentinel) |
| `client` | `debian:stable-slim` + openssl/tcpdump | có sẵn `/etc/ssl/lab/ca.crt`; chạy `sleep infinity` để `docker compose exec` vào chạy `openssl s_client` |

**Cấu hình MITM qua biến môi trường** (đặt trong `docker-compose.yml`). Script
`mitm_strip_versions.py` đọc `LISTEN_HOST/LISTEN_PORT/TARGET_HOST/TARGET_PORT`
(mặc định là localhost cho bare-metal; Docker override thành `0.0.0.0` và `server:443`)
và `MANGLE_SENTINEL` (0 = chỉ strip `supported_versions`; 1 = strip + zero 8 byte
cuối `server_random` để xóa sentinel).

## 2. Build & khởi động

```bash
cd tls-lab
docker compose up -d --build
docker compose ps       
```

PKI (`ca.crt`, `server.crt/key`, `mitm.crt/key`) phải sinh **trước** bằng
`bash scripts/00_make_ca.sh`.

## 3. Chạy từng kịch bản

### S1 — baseline, nối thẳng server, kỳ vọng TLS 1.3

```bash
docker compose exec client sh -c 'echo | openssl s_client -connect server:443 \
  -servername lab.local -CAfile /etc/ssl/lab/ca.crt \
  -verify_return_error -verify_hostname lab.local \
  -min_protocol TLSv1.2 -max_protocol TLSv1.3 2>&1 | grep -E "Protocol|Cipher|Verify"'
# → Protocol: TLSv1.3
```

### S2 — qua MITM (strip `supported_versions`), kỳ vọng abort

MITM mặc định `MANGLE_SENTINEL=0`. Client nối vào `mitm:4434`:

```bash
docker compose exec client sh -c 'echo | openssl s_client -connect mitm:4434 \
  -servername lab.local -CAfile /etc/ssl/lab/ca.crt \
  -verify_return_error -verify_hostname lab.local \
  -min_protocol TLSv1.2 -max_protocol TLSv1.3 2>&1 | grep -Ei "inappropriate|error|Protocol"'
# → ssl_choose_client_version:inappropriate fallback   (client bắt sentinel → hủy)
```

### S3 — MITM xóa luôn sentinel, server ECDHE, kỳ vọng `decrypt_error`

```bash
MANGLE_SENTINEL=1 docker compose up -d --force-recreate mitm   # bật mangle sentinel
docker compose exec client sh -c 'echo | openssl s_client -connect mitm:4434 \
  -servername lab.local -CAfile /etc/ssl/lab/ca.crt \
  -verify_return_error -verify_hostname lab.local \
  -min_protocol TLSv1.2 -max_protocol TLSv1.3 2>&1 | grep -Ei "bad signature|decrypt|Protocol"'
# → tls_process_key_exchange:bad signature   (Alert decrypt_error 51)

docker compose up -d --force-recreate mitm                     # tắt lại mangle (về hành vi S2)
```

### S4 — static RSA (cần sửa nginx)

Docker dùng nginx làm server, nên để demo static RSA key transport phải đổi cipher:

```bash
# trong server/nginx.conf: đổi dòng ssl_ciphers thành cipher kRSA
docker compose up -d --force-recreate server
MANGLE_SENTINEL=1 docker compose up -d --force-recreate mitm
docker compose exec client sh -c 'echo | openssl s_client -connect mitm:4434 \
  -servername lab.local -CAfile /etc/ssl/lab/ca.crt \
  -verify_return_error -verify_hostname lab.local \
  -cipher AES128-GCM-SHA256 -max_protocol TLSv1.2 2>&1 | grep -Ei "bad record mac|Protocol"'
# → bad record mac (Alert 20): server_random không được ký nhưng là đầu vào master_secret
```

### S5 / S5b — client tự fallback (không cần MITM)

```bash
# S5: client tự hạ trần xuống 1.2 → downgrade "thành công" (server thật vẫn hỗ trợ 1.2)
docker compose exec client sh -c 'echo | openssl s_client -connect server:443 \
  -servername lab.local -CAfile /etc/ssl/lab/ca.crt \
  -verify_return_error -verify_hostname lab.local \
  -max_protocol TLSv1.2 2>&1 | grep -E "Protocol|Cipher"'
# → Protocol: TLSv1.2

# S5b: thêm -fallback_scsv → server chặn
docker compose exec client sh -c 'echo | openssl s_client -connect server:443 \
  -servername lab.local -CAfile /etc/ssl/lab/ca.crt \
  -verify_return_error -verify_hostname lab.local \
  -max_protocol TLSv1.2 -fallback_scsv 2>&1 | grep -Ei "inappropriate|86|Protocol"'
# → alert number 86 (inappropriate_fallback)
```

### S6 — cert giả

## 4. Bắt pcap trong Docker

```bash
# chạy tcpdump nền trong client, rồi chạy kịch bản ở lệnh khác
docker compose exec -d client sh -c \
  'tcpdump -i eth0 -w /tmp/s2.pcap "tcp port 443 or tcp port 4434"'
# ... chạy S2 ...
docker compose exec client sh -c 'pkill tcpdump; tcpdump -n -X -r /tmp/s2.pcap | head -40'
docker compose cp client:/tmp/s2.pcap ./pcap/s2_docker.pcap    # lấy file ra host
```

## 6. Dọn dẹp

```bash
docker compose down    
```
