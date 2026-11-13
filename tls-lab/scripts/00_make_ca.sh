#!/usr/bin/env bash
# Dựng PKI cho lab. Mỗi vai giữ file của mình trong thư mục riêng:
#   ca/      khóa riêng CA (BÍ MẬT) + cert công khai CA (bên phát hành)
#   server/  khóa + CSR + cert server do CA ký
#   client/  CHỈ ca.crt (neo tin cậy công khai) -- client "nhận" file này
#   mitm/    cert giả tự ký cho S6 (kẻ tấn công)
# Chạy một lần từ gốc repo: bash scripts/00_make_ca.sh
set -e
cd "$(dirname "$0")/.."
mkdir -p ca server client mitm pcap logs

# (1) CA nội bộ (tự ký). ca/ca.key là BÍ MẬT, không bao giờ rời khỏi ca/.
openssl req -x509 -newkey rsa:2048 -keyout ca/ca.key -out ca/ca.crt -days 365 -nodes \
  -subj "/C=VN/O=TLS-Lab/CN=TLS-Lab Internal CA"

# (2) Khóa + yêu cầu ký (CSR) cho server
openssl req -newkey rsa:2048 -keyout server/server.key -out server/server.csr -nodes \
  -subj "/C=VN/O=TLS-Lab/CN=lab.local"

# (3) CA ký CSR, nhúng SAN (client hiện đại chỉ khớp hostname trong SAN)
printf 'subjectAltName=DNS:lab.local,DNS:localhost,IP:127.0.0.1\n' > server/san.cnf
openssl x509 -req -in server/server.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
  -out server/server.crt -days 365 -extfile server/san.cnf

# (4) Phân phối cert CÔNG KHAI của CA cho client (chỉ ca.crt, KHÔNG bao giờ ca.key).
#     Đây là bước "client nhận cert của CA" -- neo tin cậy trước mọi handshake.
cp ca/ca.crt client/ca.crt

# (5) Cert giả cho S6: tự ký, CN/SAN = lab.local nhưng KHÔNG do CA lab ký.
#     SAN khớp hostname có chủ đích, nên thứ duy nhất client nghiêm ngặt từ chối
#     là "nhà phát hành không tin cậy".
openssl req -x509 -newkey rsa:2048 -keyout mitm/mitm.key -out mitm/mitm.crt -days 365 -nodes \
  -subj "/C=VN/O=Evil-MITM/CN=lab.local" \
  -addext "subjectAltName=DNS:lab.local,DNS:localhost,IP:127.0.0.1"

echo "PKI sẵn sàng: ca/ (phát hành), server/ (cert), client/ca.crt (neo tin cậy), mitm/ (cert giả)."
