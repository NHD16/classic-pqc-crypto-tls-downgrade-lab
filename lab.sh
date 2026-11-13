#!/usr/bin/env bash
# Tạo session tmux "lab" với 4 ô ở 4 góc:
#   ┌──── server ────┬──── client ────┐
#   ├───── mitm ─────┼───── pcap ─────┤
#   └────────────────┴────────────────┘

SESSION="${1:-lab}"
BASE="/vist_test/tls-lab"

# Nếu session đã tồn tại thì vào luôn
if tmux has-session -t "$SESSION" 2>/dev/null; then
  exec tmux attach -t "$SESSION"
fi

# 1. Tạo session chạy nền, ô đầu tiên (server) mở ở thư mục server
tmux new-session -d -s "$SESSION" -c "$BASE/server"

# 2. Chia trái / phải, ô bên phải (client) mở ở thư mục client
tmux split-window -h -t "$SESSION:0.0" -c "$BASE/client"

# 3. Chia cột trái thành trên / dưới, ô dưới trái (mitm) mở ở thư mục mitm
#    -> 0: trên trái, 1: dưới trái, 2: phải
tmux split-window -v -t "$SESSION:0.0" -c "$BASE/mitm"

# 4. Chia cột phải thành trên / dưới, ô dưới phải (pcap) mở ở thư mục pcap
#    -> 2: trên phải, 3: dưới phải
tmux split-window -v -t "$SESSION:0.2" -c "$BASE/pcap"

# 5. Đặt tên từng ô
tmux select-pane -t "$SESSION:0.0" -T server
tmux select-pane -t "$SESSION:0.2" -T client
tmux select-pane -t "$SESSION:0.1" -T mitm
tmux select-pane -t "$SESSION:0.3" -T pcap

# 6. Hiện tên ở viền trên mỗi ô
tmux set -t "$SESSION" pane-border-status top
tmux set -t "$SESSION" pane-border-format " #{pane_title} "

# Không cho chương trình tự đổi tên ô (tmux >= 3.4, bỏ qua nếu bản cũ)
tmux set -t "$SESSION" allow-set-title off 2>/dev/null

# 7. Chọn ô server rồi vào session
tmux select-pane -t "$SESSION:0.0"
exec tmux attach -t "$SESSION"
