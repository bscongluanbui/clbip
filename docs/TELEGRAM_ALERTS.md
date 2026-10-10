# Telegram và phát hiện mất toàn bộ mạng

## Hai lớp cảnh báo riêng

1. **Worker tại nhà:** ghi incident vào `DATA_DIR/alerts.sqlite3`. Worker gửi
   Telegram ở luồng riêng, giữ thông báo chưa gửi khi Telegram/mạng lỗi, gửi lại
   khi đường truyền trở lại. Lỗi lặp cùng incident được gộp và nhắc định kỳ;
   incident chuyển về bình thường có thông báo phục hồi. Gửi lại là **at least
   once**: crash sau khi Telegram nhận nhưng trước khi lưu ACK có thể tạo bản
   trùng. Hàng đợi có giới hạn; đây không phải bảo đảm mọi packet/lỗi client của
   mọi website đều được ghi nhận.
2. **VPS độc lập:** nhận heartbeat từ worker. Khi không nhận trong ngưỡng, VPS
   dùng Internet và bot Telegram của VPS để báo. Mất điện/router/Internet tại nhà
   không ngăn VPS gửi tin. Heartbeat chỉ xác định **mất dấu mạng/server/worker**,
   không tự chứng minh lỗi do nhà mạng IPv6. Nếu chính VPS hoặc Telegram cũng mất
   mạng, outbox VPS giữ tin và thử lại khi kết nối trở lại.

Một server đã mất tất cả đường truyền không thể tự gửi tin ra Telegram ngay.
Muốn cảnh báo trong lúc đó, bộ theo dõi phải chạy **ngoài mạng đang bị theo dõi**,
hoặc server phải có một đường truyền khác độc lập. VPS 24/7 phù hợp cho lớp này.

Worker còn giám sát dashboard bằng GET `/livez` mỗi 30 giây, sau grace khởi động
30 giây, timeout socket connect/read 2/3 giây. HTTP lỗi, timeout, JSON lỗi hoặc
thiếu `alive=true` tạo incident `runtime.dashboard`; probe thành công xác nhận
phục hồi và heartbeat không chứng nhận khỏe khi dashboard đang lỗi. Có thể tắt
riêng kiểm tra bằng `DASHBOARD_MONITOR_ENABLED=0`. `/livez` chỉ chứng minh web app
còn đáp ứng; health của reconciler/pool do worker theo dõi riêng. Các lỗi browser
ở từng website/tab, hoặc HTTP business error không làm app chết, không tự được
phát hiện từ liveness này.

## Watchdog tự host trên VPS (ưu tiên)

`scripts/external_watchdog.py` là receiver độc lập; không chạy worker/3proxy,
không nhận cấu hình pool hay lệnh điều khiển. Receiver chỉ nhận:

```http
POST /heartbeat
Authorization: Bearer <shared-token>
Content-Length: 0
```

Token chung dùng tối thiểu 32 ký tự ngẫu nhiên và chỉ dành cho heartbeat. Quy
tắc này **không áp dụng cho mật khẩu dashboard**. Có thể tạo token bằng:

```sh
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Lưu token/bot token/chat ID trong file secret riêng, không commit hoặc đưa vào
URL/query string. VPS chỉ cần bot token và chat ID để **gửi**; không chạy
`getUpdates`, không thay Telegram webhook. Vì vậy VPS có thể dùng cùng bot đang
có với dashboard mà không tranh polling. Chat/group phải cho phép bot gửi tin.

Biến cấu hình receiver:

| Biến | Mặc định / ý nghĩa |
|---|---|
| `WATCHDOG_SHARED_TOKEN` hoặc `_FILE` | Token chung, bắt buộc |
| `TELEGRAM_BOT_TOKEN` hoặc `_FILE` | Bot gửi cảnh báo VPS, bắt buộc |
| `TELEGRAM_CHAT_ID` hoặc `_FILE` | Chat/group nhận cảnh báo, bắt buộc |
| `WATCHDOG_NODE_NAME` | `home-server`; tên node trong tin nhắn |
| `WATCHDOG_BIND` | `127.0.0.1`; thay bằng bind trong container theo Compose mẫu |
| `WATCHDOG_PORT` | `8088` |
| `WATCHDOG_TIMEOUT` | `180` giây kể từ heartbeat cuối |
| `WATCHDOG_CHECK_INTERVAL` | `5` giây |
| `DATA_DIR` | `/app/watchdog-data`; volume phải ghi được, giữ qua recreate |

File `_FILE` được ưu tiên nếu cấu hình cả file và giá trị môi trường. Receiver
đọc secret lúc khởi động; sau khi xoay secret, recreate receiver và worker.

Receiver HTTP cần một trong hai đường triển khai:

- **HTTPS:** reverse proxy TLS trên VPS, ví dụ domain
  `https://monitor.example.com/heartbeat`, chuyển tiếp riêng tới receiver
  `127.0.0.1:8088`. Không public cổng HTTP receiver. Proxy phải chuyển tiếp
  Authorization, không log header/token và chỉ nhận đúng path heartbeat.
- **Tailscale:** bind/publish cổng receiver vào địa chỉ Tailscale của VPS;
  worker gửi đến `http://100.x.y.z:8088/heartbeat`. Tailscale cung cấp đường
  truyền overlay mã hóa, nhưng mất toàn bộ Internet tại nhà vẫn làm heartbeat
  ngừng. Receiver không nên bind/publish HTTP ra địa chỉ public. Client cần
  `HEARTBEAT_ALLOW_HTTP=1`; code chỉ chấp nhận HTTP cho `100.64.0.0/10`,
  `fd7a:115c:a1e0::/48` hoặc hostname `.ts.net` khi bật tùy chọn này.

Compose triển khai receiver riêng: `docker-compose.watchdog.yml`. Trên VPS, tạo
đủ secret theo đường dẫn trong file mẫu và khởi chạy:

```sh
docker compose -f docker-compose.watchdog.yml config --quiet
docker compose -f docker-compose.watchdog.yml build
docker compose -f docker-compose.watchdog.yml up -d
```

Mẫu mặc định build source hiện tại thành image local. Nếu dùng image registry,
chọn tag/digest release đã xuất bản chứa `APP_ROLE=watchdog`; `latest` cũ trước
khi publish tính năng chưa có role mới.

Kiểm tra offline từ source/image (không gọi Telegram/không gọi server):

```sh
python3 scripts/external_watchdog.py --check
python3 scripts/external_watchdog.py --once
```

`--check` chỉ xác thực biến môi trường. `--once` cập nhật deadline/queue trong
volume rồi thoát, không mở HTTP và không gửi Telegram. Receiver lưu heartbeat,
deadline khởi tạo, trạng thái lỗi trong `watchdog.sqlite3`; queue nằm riêng trong
`alerts.sqlite3`. Restart không xóa outage hay tạo lại grace vô hạn. Đồng hồ VPS
lùi quá 5 giây hoặc timestamp lưu nằm trong tương lai làm trạng thái thiếu tin
cậy; heartbeat mới xác thực sẽ xác nhận lại trạng thái.

## Cấu hình worker tại nhà

Thêm biến vào **worker**, không phải dashboard:

```dotenv
HEARTBEAT_URL=https://monitor.example.com/heartbeat
HEARTBEAT_TOKEN_FILE=/run/secrets/heartbeat_token
HEARTBEAT_INTERVAL=60
HEARTBEAT_TIMEOUT=5
HEARTBEAT_STALE_AFTER=330
```

Mount file `heartbeat_token` vào đúng path và dùng cùng token với VPS. Có thể
dùng `HEARTBEAT_URL_FILE` thay URL môi trường, hoặc `HEARTBEAT_TOKEN` thay file
token. Nếu dùng HTTP trên Tailscale, cấu hình ví dụ:

```dotenv
HEARTBEAT_URL=http://100.x.y.z:8088/heartbeat
HEARTBEAT_ALLOW_HTTP=1
```

Repo có override `docker-compose.heartbeat.yml` để mount secret này. Đặt token
chung vào `secrets/heartbeat_token` (quyền `600`), lưu URL/ALLOW_HTTP trong `.env`,
và lưu selector `COMPOSE_FILE=docker-compose.yml:docker-compose.heartbeat.yml`
để những lần `docker compose up -d` sau vẫn dùng override. Không ghi token vào
`.env` hoặc chat/log. Chỉ recreate worker sau khi receiver VPS đã được cấu hình.

Worker mặc định **tắt heartbeat** khi không có URL; không có request ngoại mạng.
Luồng heartbeat chỉ gửi POST body rỗng khi snapshot worker khỏe và timestamp
reconciler/progress còn mới. Lỗi hiện tại, dữ liệu stale, lỗi provider hoặc
worker/reconciler bị treo không được chứng nhận khỏe bằng success cũ. Stop proxy
chủ động vẫn là worker khỏe nếu không có incident khác. Khi bảo trì/tắt worker,
tạm dừng receiver/monitor nếu muốn tránh cảnh báo thiếu heartbeat dự kiến.

Mặc định timestamp stale sau `max(2 × interval, 330)` giây để bao phủ backoff
reconciler tối đa 300 giây. Lỗi health rõ ràng dừng beat ngay; treo không có lỗi
rõ ràng có thể cần hết stale rồi đến deadline VPS. Đặt stale thấp hơn cần kiểm
thử build lớn/backoff, nếu không sẽ tạo cảnh báo giả.

Timeout request là timeout socket của Requests; DNS resolver hệ điều hành có
thể mất lâu hơn. Heartbeat chạy một luồng daemon riêng, không khóa hay cản
reconciler. Không follow redirect, không dùng proxy môi trường, không gửi/log
URL token, prefix, địa chỉ pool hay credentials. VPS/monitor vẫn phát hiện thiếu
beat nếu chính request heartbeat bị treo.

Với interval 60 giây và deadline VPS 180 giây, cảnh báo thiếu beat xuất hiện
xấp xỉ **120–180 giây sau mất kết nối**, cộng tối đa chu kỳ kiểm tra 5 giây và
thời gian Telegram. Thời gian thực tế còn phụ thuộc kết nối VPS/Telegram. Nếu
worker treo nhưng heartbeat vẫn mới vài phút, thời gian phát hiện còn cộng
stale limit. Đây không phải cảnh báo tức thời hoặc cam kết không mất tin.

## Healthchecks.io (tùy chọn thay receiver VPS)

Worker cũng có thể POST body rỗng đến Ping URL HTTPS của một check
Healthchecks.io; để `HEARTBEAT_TOKEN` trống trong trường hợp này. Mỗi server
dùng check riêng. Chọn Simple Schedule: Period 1 phút, Grace Time 2 phút; monitor
sẽ báo thiếu ping sau khoảng 3 phút từ ping cuối. Cấu hình period/grace phải
phù hợp interval worker. [Cấu hình check chính thức](https://healthchecks.io/docs/configuring_checks/)

Để kết nối Telegram, mở chat `HealthchecksBot` (hoặc thêm bot vào group), gửi
`/start`, xác nhận liên kết bot trả về, chọn project và Connect Telegram; gán
integration vào check. Đây là bot của Healthchecks, độc lập với bot riêng đang
dùng trong repo. [Hướng dẫn Telegram chính thức](https://healthchecks.io/integrations/telegram/)

Healthchecks theo dõi ping tới đúng hạn rồi gửi cảnh báo khi check chuyển Down.
Một ping thành công mới xác nhận lại Up. Không gửi ping từ một cron khác hoặc
hai worker khác cùng check: chúng có thể che mất outage của worker thật.
[Mô hình heartbeat chính thức](https://healthchecks.io/docs/)

## Kiểm chứng outage mà không tắt mạng production

1. Chạy receiver/worker test riêng và nhận heartbeat bình thường.
2. Dừng **chỉ worker test**; giữ receiver/VPS và mạng production hoạt động.
3. Chờ hết deadline; xác nhận một tin `mất heartbeat`, không khẳng định ISP lỗi.
4. Bật worker test; xác nhận heartbeat mới và một tin phục hồi.
5. Kiểm tra outage/recovery vẫn giữ qua restart receiver và mất kết nối Telegram.

Chạy unit tests với HTTP/Telegram giả trước; chỉ test gửi thật với bot/chat test
đã cấu hình. Test queue không đồng nghĩa VPS đã được triển khai hoặc tin Telegram
đã được giao thật.
