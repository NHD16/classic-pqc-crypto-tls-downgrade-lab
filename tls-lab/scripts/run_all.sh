#!/usr/bin/env bash
# Tái hiện S1,S2,S2b,S3,S4,S5,S5b,S6 trên localhost. Bằng chứng -> logs/.
# Log tách theo VAI để khỏi lẫn: sX_client.log (đầu ra client) và sX_mitm.log (stderr MITM).
# Mỗi vai chạy lệnh TRONG thư mục của nó (subshell `cd`): server/ , client/ , mitm/.
#   server: openssl s_server trong server/  (dùng server.crt, server.key)
#   client: openssl s_client trong client/  (dùng ca.crt = neo tin cậy)
#   mitm  : mitm_strip_versions.py trong mitm/ (và cert giả mitm.crt cho S6)
# Bắt gói (tùy chọn) ghi vào pcap/, ví dụ chạy nền trước mỗi kịch bản:
#   sudo tcpdump -i loopback0 -Z $USER -w pcap/s2.pcap 'tcp port 4433 or tcp port 4434' &
# Đọc lại trong WSL: tcpdump -n -X -r pcap/sX.pcap
set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
LOGS="$ROOT/logs"
mkdir -p "$LOGS" "$ROOT/pcap"

# server chạy trong server/, trả PID của openssl (nhờ exec) để kill sau.
start_srv(){   # $1 = cờ server thêm
  ( cd "$ROOT/server" && exec openssl s_server -accept 4433 -cert server.crt -key server.key \
      -www -quiet $1 >/dev/null 2>&1 ) & echo $!; sleep 0.6;
}
# client chạy trong client/, dùng ca.crt tại chỗ. $1=cổng $2=cờ thêm
cli(){ ( cd "$ROOT/client" && echo | openssl s_client -connect 127.0.0.1:$1 -servername lab.local \
      -CAfile ca.crt -verify_return_error -verify_hostname lab.local $2 ) ; }

echo "== S1 baseline ==" | tee "$LOGS/s1_client.log"
P=$(start_srv "-min_protocol TLSv1.2 -max_protocol TLSv1.3")
cli 4433 "" 2>/dev/null | grep -E "Protocol|Cipher " | tee -a "$LOGS/s1_client.log"
kill $P 2>/dev/null; wait 2>/dev/null

echo "== S2 MITM strip supported_versions (expect abort) ==" | tee "$LOGS/s2_client.log"
P=$(start_srv "-min_protocol TLSv1.2 -max_protocol TLSv1.3")
( cd "$ROOT/mitm" && exec python3 -I mitm_strip_versions.py ) 2>"$LOGS/s2_mitm.log" & M=$!; sleep 0.5
cli 4434 "-min_protocol TLSv1.2 -max_protocol TLSv1.3" 2>&1 \
  | grep -iE "inappropriate fallback|alert|protocol" | tee -a "$LOGS/s2_client.log"
kill $P $M 2>/dev/null; wait 2>/dev/null

echo "== S2b evidence: ServerHello.random sentinel ==" | tee "$LOGS/s2b_client.log"
P=$(start_srv "-min_protocol TLSv1.2 -max_protocol TLSv1.3")
cli 4433 "-min_protocol TLSv1.2 -max_protocol TLSv1.2 -msg" 2>/dev/null \
  | sed -n '/ServerHello/,+5p' | tee -a "$LOGS/s2b_client.log"
kill $P 2>/dev/null; wait 2>/dev/null

echo "== S3 MITM strip + erase sentinel, ECDHE (signature catches it) ==" | tee "$LOGS/s3_client.log"
P=$(start_srv "-min_protocol TLSv1.2 -max_protocol TLSv1.3")
( cd "$ROOT/mitm" && export MANGLE_SENTINEL=1 && exec python3 -I mitm_strip_versions.py ) 2>"$LOGS/s3_mitm.log" & M=$!; sleep 0.5
cli 4434 "-min_protocol TLSv1.2 -max_protocol TLSv1.3" 2>&1 \
  | grep -iE "bad signature|decrypt error|sslv3 alert|alert|protocol" | tee -a "$LOGS/s3_client.log"
kill $P $M 2>/dev/null; wait 2>/dev/null

echo "== S4 MITM strip + erase sentinel, static RSA (Finished catches it) ==" | tee "$LOGS/s4_client.log"
P=$(start_srv "-min_protocol TLSv1.2 -max_protocol TLSv1.3 -cipher AES128-GCM-SHA256")
( cd "$ROOT/mitm" && export MANGLE_SENTINEL=1 && exec python3 -I mitm_strip_versions.py ) 2>"$LOGS/s4_mitm.log" & M=$!; sleep 0.5
cli 4434 "-min_protocol TLSv1.2 -max_protocol TLSv1.2 -cipher AES128-GCM-SHA256" 2>&1 \
  | grep -iE "bad record mac|decrypt|sslv3 alert|alert|protocol" | tee -a "$LOGS/s4_client.log"
kill $P $M 2>/dev/null; wait 2>/dev/null

echo "== S5 client fallback to 1.2 (downgrade succeeds) ==" | tee "$LOGS/s5_client.log"
P=$(start_srv "-min_protocol TLSv1.2 -max_protocol TLSv1.3")
cli 4433 "-min_protocol TLSv1.2 -max_protocol TLSv1.2" 2>/dev/null \
  | grep -E "Protocol|Cipher " | tee -a "$LOGS/s5_client.log"
kill $P 2>/dev/null; wait 2>/dev/null

echo "== S5b fallback + TLS_FALLBACK_SCSV (server rejects) ==" | tee "$LOGS/s5b_client.log"
P=$(start_srv "-min_protocol TLSv1.2 -max_protocol TLSv1.3")
cli 4433 "-min_protocol TLSv1.2 -max_protocol TLSv1.2 -fallback_scsv" 2>&1 \
  | grep -iE "inappropriate fallback|alert number 86" | tee -a "$LOGS/s5b_client.log"
kill $P 2>/dev/null; wait 2>/dev/null

echo "== S6 MITM terminates TLS with rogue cert, max 1.2 ==" | tee "$LOGS/s6_client.log"
if [ -f "$ROOT/mitm/mitm.crt" ]; then
  ( cd "$ROOT/mitm" && exec openssl s_server -accept 4435 -cert mitm.crt -key mitm.key -www -quiet \
      -min_protocol TLSv1.2 -max_protocol TLSv1.2 >/dev/null 2>&1 ) & Pm=$!; sleep 0.6
  echo "-- S6a strict client (verify on) -> expect reject --" | tee -a "$LOGS/s6_client.log"
  cli 4435 "" 2>&1 \
    | grep -iE "verify error|unknown ca|certificate verify failed|alert|protocol" | tee -a "$LOGS/s6_client.log"
  echo "-- S6b client WITHOUT verification -> downgrade succeeds --" | tee -a "$LOGS/s6_client.log"
  ( cd "$ROOT/client" && echo | openssl s_client -connect 127.0.0.1:4435 -servername lab.local 2>/dev/null ) \
    | grep -E "Protocol|Cipher " | tee -a "$LOGS/s6_client.log"
  kill $Pm 2>/dev/null; wait 2>/dev/null
else
  echo "mitm/mitm.crt missing - run scripts/00_make_ca.sh first" | tee -a "$LOGS/s6_client.log"
fi

echo "ALL DONE -> xem logs/  (sX_client.log = đầu ra client; sX_mitm.log = log MITM cho S2/S3/S4)"
