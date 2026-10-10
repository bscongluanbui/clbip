# Một VPS giám sát nhiều server, mỗi người một bot

Mỗi server có một receiver riêng: cổng Tailscale, token heartbeat ngẫu nhiên,
bot/chat ID, thư mục dữ liệu và hàng đợi Telegram riêng. Một bot bị lỗi không
chặn sender của node khác. Receiver chỉ nhận heartbeat; người dùng không nhận
quyền RPC quản trị proxy. Đây là các dịch vụ riêng do quản trị viên VPS quản lý,
không phải cổng đăng ký tự phục vụ hay tách tài khoản Unix cho từng tenant.

## Phụ thuộc trên Ubuntu

Trên **VPS và từng server chạy agent host**, cài Python và Requests trước khi
kiểm tra/chạy dịch vụ:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-requests
python3 -c 'import requests; print("REQUESTS=OK")'
```

Các lệnh bên dưới dùng tài khoản `ubuntu`, thư mục `/home/ubuntu` và Tailscale
VPS `100.76.59.88`. Đổi user/group, đường dẫn và IP theo máy thực tế; mỗi server
phải dùng đúng cổng và token của node đã cấp cho mình.

## Tạo node trên VPS

Đặt `create_watchdog_node.py` cùng thư mục với `external_watchdog.py`,
`alerts.py`, `telegram_notify.py` và `heartbeat.py` đã triển khai.

```bash
python3 /home/ubuntu/clbip-watchdog/create_watchdog_node.py \
  --name friend-one --bind 100.76.59.88 --port 8089
nano /home/ubuntu/clbip-watchdog/nodes/friend-one/watchdog.env
```

Chỉ điền `TELEGRAM_BOT_TOKEN` và `TELEGRAM_CHAT_ID` của người đó; giữ token
heartbeat đã tạo. File có quyền `600`, thư mục `700`. Tên node, cổng và config
đã tồn tại không bị ghi đè. Node hiện tại tại cổng `8088` vẫn giữ nguyên.

Sau khi điền, cài unit được tạo; systemd đọc EnvironmentFile như dữ liệu,
không `source` file thành lệnh shell:

```bash
sudo install -m 0644 /home/ubuntu/clbip-watchdog/nodes/friend-one/node.service \
  /etc/systemd/system/clbip-watchdog-friend-one.service
sudo systemctl daemon-reload
sudo systemctl enable --now clbip-watchdog-friend-one.service
systemctl is-active clbip-watchdog-friend-one.service
```

`ExecStartPre --check` ngăn khởi động nếu Telegram/token cấu hình thiếu. Chọn
cổng khác cho người tiếp theo, ví dụ `8090`, tên `friend-two`. Người nhận cần
cho phép bot nhắn tới chat/group. Bot chỉ gửi `sendMessage`, không polling,
không chia sẻ bot token với server được giám sát.

## Heartbeat từ từng server

Các server cần kết nối được tới Tailscale VPS theo ACL được quản trị viên cấu
hình. Không dùng HTTP token này qua địa chỉ public. Với node ví dụ:

Nếu VPS dùng firewalld, cho phép riêng IP Tailscale của server đó tới đúng cổng
receiver. Ví dụ dưới đây dùng node nhà chính; thay **cả IP nguồn và cổng** cho
mỗi người mới. Không đổi toàn bộ zone sang `trusted`, không mở dải cổng public:

```bash
RULE='rule family="ipv4" source address="100.96.122.62/32" destination address="100.76.59.88/32" port port="8088" protocol="tcp" accept'
sudo firewall-cmd --zone=public --add-rich-rule="$RULE"
sudo firewall-cmd --permanent --zone=public --add-rich-rule="$RULE"
```

Không cần `--reload`: lệnh đầu áp dụng runtime, lệnh sau lưu qua reboot.
Tailscale ACL vẫn phải cho phép đường kết nối tương ứng.

```dotenv
HEARTBEAT_URL=http://100.76.59.88:8089/heartbeat
HEARTBEAT_ALLOW_HTTP=1
HEARTBEAT_TOKEN_FILE=/home/ubuntu/clbip-heartbeat/heartbeat_token
HEARTBEAT_INTERVAL=60
HEARTBEAT_TIMEOUT=5
LOCAL_DASHBOARD_URL=http://127.0.0.1:7070/heartbeatz
```

Chuyển riêng token `WATCHDOG_SHARED_TOKEN` của đúng node sang file
`heartbeat_token` quyền `600` trên server đó. Không gửi token vào log, URL hoặc
repo. Không dùng token/cổng node nhà chính cho các server khác: heartbeat từ
một server khác có thể che outage nếu dùng chung node.

Có hai cách gửi, **chỉ bật một cách cho mỗi node**:

1. Worker của bản có hỗ trợ `HEARTBEAT_*`: dùng override
   `docker-compose.heartbeat.yml` như [hướng dẫn](TELEGRAM_ALERTS.md).
2. Agent host: đặt `scripts/host_heartbeat.py` và `heartbeat.py` **cùng phiên bản**
   trong cùng thư mục, chạy bằng systemd với EnvironmentFile. Agent mới đọc
   `/heartbeatz` của dashboard mới, không cần Docker socket, mật khẩu dashboard
   hoặc service token; không restart container hay thay pool. Bản dashboard cũ
   chưa có endpoint này cần giữ URL `/readyz` và hành vi readiness cũ cho đến khi
   image mới đã được triển khai.

Agent host mới chứng minh dashboard và worker/reconciler còn sống, có progress
còn mới tại lần kiểm tra `/heartbeatz`; pool/readiness tạm lỗi được báo riêng,
không làm heartbeat mất dấu server chỉ vì pool đang rebuild. Agent yêu cầu cả
ba boolean `alive`, `worker_alive`, `progress_fresh` bằng `true`, không dùng
`/livez` hay kết quả cũ làm fallback. Đây không chứng minh mọi proxy/website đều
thông. Cảnh báo IPv6 riêng vẫn phụ thuộc health/reconciler của worker. Tránh
chạy hai sender vào cùng node; khi chuyển sang heartbeat trong worker, dừng
agent host trước.

### Cài agent host bằng systemd

Thực hiện trên **server được giám sát**, bằng user `ubuntu`. Từ thư mục checkout
repo có source mới, chép hai module; agent không cần `alerts.py` hoặc bot token:

```bash
install -d -m 0700 /home/ubuntu/clbip-heartbeat
install -m 0644 scripts/host_heartbeat.py heartbeat.py /home/ubuntu/clbip-heartbeat/
test -e /home/ubuntu/clbip-heartbeat/heartbeat.env || \
  install -m 0600 /dev/null /home/ubuntu/clbip-heartbeat/heartbeat.env
test -e /home/ubuntu/clbip-heartbeat/heartbeat_token || \
  install -m 0600 /dev/null /home/ubuntu/clbip-heartbeat/heartbeat_token
nano /home/ubuntu/clbip-heartbeat/heartbeat.env
nano /home/ubuntu/clbip-heartbeat/heartbeat_token
```

Điền các biến mẫu ở trên vào `heartbeat.env`. Điền **chỉ giá trị token chung của
đúng node** vào `heartbeat_token`, không thêm tên biến hoặc dấu nháy. Chuyển token
qua kênh SSH/SFTP riêng; không đưa giá trị vào command line, chat, repo hoặc log.
Các lệnh tạo file chỉ chạy khi file chưa tồn tại, không xóa cấu hình đang dùng.

Kiểm tra quyền và owner, không in nội dung hai file:

```bash
chmod 0700 /home/ubuntu/clbip-heartbeat
chmod 0600 /home/ubuntu/clbip-heartbeat/heartbeat.env \
  /home/ubuntu/clbip-heartbeat/heartbeat_token
stat -c '%a %U:%G %n' /home/ubuntu/clbip-heartbeat \
  /home/ubuntu/clbip-heartbeat/heartbeat.env \
  /home/ubuntu/clbip-heartbeat/heartbeat_token
```

Kết quả cần có thư mục `700 ubuntu:ubuntu`, hai file `600 ubuntu:ubuntu`.
Tạo unit không chứa giá trị secret:

```bash
cat > /home/ubuntu/clbip-heartbeat/clbip-heartbeat.service <<'EOF'
[Unit]
Description=CLB IPv6 read-only host heartbeat
Wants=network-online.target
After=network-online.target tailscaled.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/clbip-heartbeat
EnvironmentFile=/home/ubuntu/clbip-heartbeat/heartbeat.env
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStartPre=/usr/bin/python3 /home/ubuntu/clbip-heartbeat/host_heartbeat.py --check
ExecStart=/usr/bin/python3 -u /home/ubuntu/clbip-heartbeat/host_heartbeat.py
Restart=on-failure
RestartSec=10
TimeoutStopSec=10
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
TasksMax=16

[Install]
WantedBy=multi-user.target
EOF
```

Kiểm tra offline bằng EnvironmentFile do systemd đọc. Không `source` file và
không dùng `export $(cat ...)`:

```bash
sudo systemd-run --unit=clbip-heartbeat-config-check --wait --pipe --collect \
  --property=User=ubuntu --property=Group=ubuntu \
  --property=WorkingDirectory=/home/ubuntu/clbip-heartbeat \
  --property=EnvironmentFile=/home/ubuntu/clbip-heartbeat/heartbeat.env \
  /usr/bin/python3 /home/ubuntu/clbip-heartbeat/host_heartbeat.py --check
```

Kết quả agent phải là `HOST_HEARTBEAT_CONFIG=OK NETWORK=NONE`, exit `0`.
Kiểm tra này không gọi dashboard/VPS/Telegram, nên chưa chứng minh heartbeat đã
được nhận. Sau khi receiver đúng node đã chạy, cài và bật agent:

```bash
sudo install -o root -g root -m 0644 \
  /home/ubuntu/clbip-heartbeat/clbip-heartbeat.service \
  /etc/systemd/system/clbip-heartbeat.service
sudo systemctl daemon-reload
sudo systemctl enable --now clbip-heartbeat.service
systemctl is-enabled clbip-heartbeat.service
systemctl is-active clbip-heartbeat.service
journalctl -u clbip-heartbeat.service -n 30 --no-pager
```

Trạng thái mong đợi là `enabled` và `active`; vẫn cần kiểm tra VPS nhận heartbeat
mới. Khi sửa file cấu hình, chạy lại lệnh kiểm tra offline rồi
`sudo systemctl restart clbip-heartbeat.service`. Agent chỉ GET `/heartbeatz`
(hoặc `/readyz` nếu chọn legacy rõ ràng) và POST
heartbeat rỗng; không gọi Docker socket, không sửa mạng, không restart container
và không đổi pool proxy. Mỗi probe dashboard có timeout socket `(2, 5)` giây,
giới hạn body 4 KB và thời hạn quan sát 8 giây; probe lỗi/quá hạn không dùng lại
success cũ để tiếp tục gửi heartbeat. Ngưỡng progress phía worker là 330 giây,
độc lập `HEARTBEAT_STALE_AFTER` phía sender; tăng biến sender không che được
progress stale. Agent dùng cùng retry/cadence với module `heartbeat.py`:
tối đa 3 lần, backoff 1/2 giây, allowance danh nghĩa 25 giây (không phải hard
DNS/header deadline); xem [chi tiết](TELEGRAM_ALERTS.md#cấu-hình-worker-tại-nhà).

### Nâng cấp agent host từ `/readyz`

Đây là migration riêng cho **agent Python/systemd trên server được giám sát**.
`docker compose pull` chỉ tải image; không thay các module agent ở
`/home/ubuntu/clbip-heartbeat/`. Thực hiện theo thứ tự:

1. Chỉ sau khi image mới đã được triển khai, xác nhận endpoint local trả HTTP
   `200` với ba cờ boolean bằng `true`. Dùng IP/dashboard port thực tế:

   ```bash
   curl --noproxy '*' --fail --silent --show-error --max-time 8 \
     http://127.0.0.1:7070/heartbeatz
   ```

   Khi worker đã dừng hoặc progress stale, response lỗi không phải bằng chứng
   để bỏ qua kiểm tra; xử lý worker trước. Nếu image cũ trả `404`, giữ agent/URL
   cũ cho đến lúc nâng dashboard. Không fallback tự động sang `/livez`.

2. Từ checkout source **cùng release với image mới**, sao lưu và cập nhật cả
   hai module. Không ghi đè file env/token hoặc dữ liệu VPS:

   ```bash
   APP=/home/ubuntu/clbip-heartbeat
   BACKUP=$(mktemp -d "$APP/code-backup.XXXXXX")
   cp -p "$APP/host_heartbeat.py" "$APP/heartbeat.py" "$BACKUP/"
   printf 'AGENT_BACKUP=%s\n' "$BACKUP"
   python3 -B -c 'import scripts.host_heartbeat, heartbeat; print("IMPORTS=OK")'
   install -m 0644 scripts/host_heartbeat.py heartbeat.py "$APP/"
   nano "$APP/heartbeat.env"
   ```

   Giữ mọi biến khác; thay `LOCAL_DASHBOARD_URL` thành
   `http://127.0.0.1:7070/heartbeatz`. File env đã ghi `/readyz` không tự đổi khi
   cập nhật source. Chọn explicit `/readyz` vẫn yêu cầu `200` và `ready=true`.

3. Chạy lại lệnh `systemd-run ... --check` ở phần cài agent, rồi restart riêng
   `sudo systemctl restart clbip-heartbeat.service`. Không cần sửa/restart node
   receiver VPS vì path/token heartbeat phía VPS không đổi. Kiểm tra journal
   agent và VPS xác nhận **heartbeat mới**; `--check` chỉ kiểm tra offline.

Nếu cần rollback agent, chép lại **cả hai** module từ thư mục `AGENT_BACKUP`,
đổi URL về `/readyz` khi dashboard chạy bản cũ, rồi restart dịch vụ agent.
Giữ nguyên secret, database và queue. Nâng cấp source agent không tự recreate
container hoặc thay pool proxy; kế hoạch nâng image phải được thực hiện riêng.

## Kiểm chứng và bảo trì

Mất heartbeat quá 180 giây phát cảnh báo; nhận heartbeat mới phát phục hồi.
Mỗi node giữ outage, retry và queue riêng qua restart. Dừng receiver của node
tương ứng trong lúc bảo trì chỉ tạm dừng nhận heartbeat và gửi Telegram; thao
tác này **không phải maintenance mode hoàn chỉnh**. Deadline và queue cũ vẫn
được lưu bền. Khi receiver chạy lại, nếu heartbeat cuối đã quá hạn, receiver có
thể phát cảnh báo trước khi heartbeat mới tới; tin đã xếp hàng cũng có thể được
gửi lại. Heartbeat mới xác thực sẽ cập nhật trạng thái và xếp tin phục hồi nếu
trước đó có incident. Không xóa database hay sửa timestamp để giả lập trạng
thái khỏe. Nếu VPS cũng mất mạng/điện, tin sẽ chờ trong outbox, không được bảo
đảm gửi ngay.

Acceptance nhiều node dùng HTTP loopback thật và Telegram giả:

```bash
docker run --rm --network none --read-only --cap-drop ALL \
  --tmpfs /tmp:rw,nosuid,size=32m \
  --mount type=bind,src="$(pwd)/tests",dst=/tests,readonly \
  --entrypoint python clbip:telegram-alerts-local \
  /tests/integration_watchdog_nodes.py --run
```

Test xác nhận token A gọi node B bị `401`, queue bot lỗi không chặn bot khác,
restart giữ trạng thái và thông báo không chứa credentials.

Nguồn API: [Telegram sendMessage](https://core.telegram.org/bots/api#sendmessage).
