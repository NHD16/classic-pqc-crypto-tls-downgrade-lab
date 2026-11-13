# Mật mã cổ điển, Hậu lượng tử (PQC) và lab hạ phiên bản TLS 1.3 → 1.2

Bài báo cáo nghiên cứu gồm hai phần:

1. **Lý thuyết:** các thuật toán mật mã cổ điển (AES, Diffie–Hellman/ECDHE, RSA-PSS…), mật mã hậu lượng tử theo chuẩn NIST (ML-KEM, ML-DSA…), giao thức TLS 1.2 và TLS 1.3.
2. **Thực hành:** một lab tái hiện tấn công **hạ phiên bản (downgrade)** từ TLS 1.3 xuống TLS 1.2 bằng một proxy MITM, kèm log, pcap và ảnh chụp làm bằng chứng.

## Câu hỏi nghiên cứu

> Khi client và server đều hỗ trợ TLS 1.2 và TLS 1.3, kẻ tấn công đứng giữa (MITM) có ép được hai bên xuống TLS 1.2 không?

**Kết luận: KHÔNG**, nếu hai bên cấu hình đúng RFC 8446 và client xác thực chứng chỉ nghiêm ngặt. Server nhúng sentinel `DOWNGRD\x01` vào `server_random`, và giá trị này được bảo vệ bởi chữ ký của server (ECDHE) hoặc bởi `Finished` (RSA key transport). Vì vậy mọi can thiệp đều bị phát hiện, và kẻ tấn công chỉ gây được gián đoạn (DoS).

Kết luận **đảo thành CÓ** chỉ khi có điều kiện ngoài chuẩn: client tự fallback xuống 1.2 mà không gửi `TLS_FALLBACK_SCSV`, client không xác thực chứng chỉ, client bỏ qua sentinel, hoặc lộ khóa riêng của server.

## Kết quả lab

| Kịch bản | Mô tả | Kết quả |
|---|---|---|
| **S1** | Nối thẳng, không can thiệp | `TLSv1.3`, `TLS_AES_256_GCM_SHA384` |
| **S2** | MITM xóa `supported_versions` khỏi ClientHello | Client hủy: `inappropriate fallback` |
| **S2b** | Quan sát `ServerHello.random` khi thương lượng 1.2 | Tận cùng `44 4f 57 4e 47 52 44 01` = `DOWNGRD\x01` |
| **S3** | S2 + xóa sentinel, server dùng ECDHE | Chữ ký sai: `bad signature` → alert `decrypt_error` (51) |
| **S4** | S2 + xóa sentinel, static RSA | Khóa phiên lệch: `bad record mac` (alert 20) |
| **S5** | Client tự fallback xuống 1.2, không SCSV | **Hạ cấp thành công**: `TLSv1.2` |
| **S5b** | Fallback có `TLS_FALLBACK_SCSV` | Server chặn: `inappropriate_fallback` (alert 86) |
| **S6** | MITM tự đóng vai server bằng cert giả | Verify bật: bị từ chối; verify tắt: **hạ cấp thành công** |

Chi tiết từng kịch bản, phân tích và biện pháp phòng chống nằm trong [report.md](report.md).

## Cấu trúc thư mục

```
.
├── report.md            Báo cáo đầy đủ (lý thuyết, câu hỏi nghiên cứu, lab, phụ lục, tài liệu tham khảo)
├── slide.pdf            Slide thuyết trình
├── tls_lab_demo.mp4     Video demo lab
├── lab.sh               Mở tmux 4 ô (server / client / mitm / pcap) để demo
├── images/              Hình minh họa cho phần lý thuyết (AES, DH, RSA-PSS, handshake TLS)
└── tls-lab/
    ├── scripts/
    │   ├── 00_make_ca.sh    Dựng PKI: CA nội bộ, cert server, cert giả cho S6
    │   └── run_all.sh       Chạy lại toàn bộ S1–S6 trên localhost, ghi log vào logs/
    ├── ca/                  CA nội bộ của lab
    ├── server/              Cert/khóa server, nginx.conf, Dockerfile
    ├── client/              ca.crt (neo tin cậy), Dockerfile
    ├── mitm/                mitm_strip_versions.py, cert giả, Dockerfile
    ├── logs/                Log từng kịch bản (sX_client.log, sX_mitm.log)
    ├── pcap/                Gói tin bắt được (.pcap) và bản đọc lại (.txt)
    ├── certinfo/            Nội dung cert/CSR dạng văn bản
    ├── screenshots/         Ảnh chụp kết quả các kịch bản
    ├── docker-compose.yml   Lab chạy bằng Docker (server / mitm / client)
    └── DOCKER.md            Hướng dẫn chạy lab bằng Docker
```

## Chạy lab

Yêu cầu: OpenSSL 3.x, Python 3, tcpdump (tùy chọn). Lab đã kiểm tra với OpenSSL 3.5.5, Python 3.14 trên Ubuntu 26.04 (WSL2).

**Chạy trực tiếp trên máy (localhost):**

```bash
cd tls-lab
bash scripts/00_make_ca.sh   # chỉ cần khi muốn sinh lại PKI
bash scripts/run_all.sh      # chạy S1–S6, kết quả ghi vào logs/
```

**Chạy bằng Docker:**

```bash
cd tls-lab
docker compose up -d --build
docker compose exec client sh -c 'echo | openssl s_client -connect server:443 \
  -servername lab.local -CAfile /etc/ssl/lab/ca.crt \
  -verify_return_error -verify_hostname lab.local'
```

Lệnh cho từng kịch bản và cách bắt pcap trong container có trong [tls-lab/DOCKER.md](tls-lab/DOCKER.md).

**Thành phần MITM:** [mitm_strip_versions.py](tls-lab/mitm/mitm_strip_versions.py) là một proxy TCP xóa extension `supported_versions` khỏi ClientHello. Khi đặt `MANGLE_SENTINEL=1`, nó còn ghi đè 8 byte cuối của `server_random` để xóa sentinel.

## Lưu ý

- Các khóa riêng trong repo (`ca/ca.key`, `server/server.key`, `mitm/mitm.key`) **chỉ dùng cho lab**, tự ký và không có giá trị ngoài môi trường này. Không dùng lại cho hệ thống thật.
- Lab chỉ phục vụ mục đích học tập và nghiên cứu, chạy trong mạng cục bộ hoặc Docker. Không dùng các công cụ này với hệ thống mà bạn không được phép kiểm thử.
