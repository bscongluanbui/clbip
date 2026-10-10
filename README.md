# IPv6 Proxy Manager — Linux LAN / routed-prefix

Dashboard quản lý HTTP/SOCKS5 proxy với 3proxy. Địa chỉ được chọn **trong prefix IPv6 thực sự có đường đi từ nhà mạng/router**; phần mềm không cấp thêm prefix và không biến một IPv6 bất kỳ thành địa chỉ truy cập Internet được.

## Kiến trúc

- **dashboard**: Gunicorn 1 worker / 8 threads, user `10001:10001`, không capability, root filesystem read-only; mặc định chỉ nghe `127.0.0.1:7070`.
- **worker**: duy nhất quản lý state, IPv6 và 3proxy; `NET_ADMIN`, không `privileged`; persistent named volume `proxy-data`.
- Dashboard ↔ worker: Unix socket mode `0660`, group `10001`, xác thực `SERVICE_TOKEN`; dashboard mount socket directory và volume mật khẩu dashboard read-only, không mount database. Worker ghi mật khẩu vào volume `dashboard-credentials` riêng.
- Một reconciler theo **desired state**; lệnh Stop được giữ qua reconcile/restart. Entrypoint chỉ giám sát vòng đời process, không đổi sysctl, không có watchdog thứ hai, không `pkill` process host.

## Triển khai

**Môi trường mục tiêu:** Docker Engine + Compose trên Linux có NIC kết nối trực tiếp router và IPv6 hoạt động. Docker Desktop host-network chỉ cung cấp một số chức năng L4; không đồng nghĩa với quyền quản lý NIC/L2 của Windows/macOS host. Xem [Docker host-network limitations](https://docs.docker.com/engine/network/drivers/host/#limitations).

Cần có **Git, Bash, Python 3, Docker Engine đang chạy và Docker Compose v2** (`docker compose version`). Installer kiểm tra Linux/Python/Docker/Compose, không tự cài Docker/Python hoặc thay đổi mạng host. Chạy trên máy Linux mục tiêu:

```bash
git clone https://github.com/bscongluanbui/clbip.git /home/ubuntu/clbip
cd /home/ubuntu/clbip
bash scripts/install.sh
```

Nếu đã clone vào `/home/ubuntu/clbip`, chỉ `cd /home/ubuntu/clbip` rồi chạy installer; không clone lồng thêm thư mục `clbip`. Nếu Docker báo `permission denied` khi truy cập daemon, hoặc checkout đã thuộc root nên ghi `.env`/`secrets` bị từ chối, chạy lại **cùng tham số** với `sudo bash scripts/install.sh`.

Installer tạo **chỉ những secrets còn thiếu**, giữ nguyên secrets đã có, kiểm tra Compose/bind/port, pull image rồi khởi động hai container và đợi healthcheck. Cài mới mặc định không đặt mật khẩu dashboard; có thể đặt mật khẩu trong UI. Nếu muốn bootstrap bằng mật khẩu ngẫu nhiên, chạy `python3 scripts/init_secrets.py` trước installer. Không cần chạy `cp .env.example .env`: installer lưu cấu hình cần thiết trong `.env`, giữ nguyên các mục cấu hình khác.

### Cài trên LAN / lỗi pull GHCR

Mặc định dashboard chỉ nghe loopback. Để dashboard nghe trên **mọi địa chỉ IPv4 của server** (`0.0.0.0:7070`) và truy cập tại **`http://192.168.1.3:7070`**:

```bash
cd /home/ubuntu/clbip
sudo bash scripts/install.sh --bind 0.0.0.0 --port 7070
```

Nếu GHCR báo `denied`, `unauthorized`, image/tag chưa publish hoặc `no matching manifest`, installer dừng và báo lỗi; **không tự âm thầm chuyển sang build local**. Kiểm tra quyền pull/tag/kiến trúc theo tài liệu registry bên dưới, hoặc chủ động build từ checkout hiện tại:

```bash
sudo bash scripts/install.sh --build --bind 0.0.0.0 --port 7070
```

`--build` cần truy cập Internet cho base image, dependencies và source 3proxy; nó bỏ bước pull image ứng dụng từ GHCR, không thay thế Docker Engine/Compose.

| Tham số installer | Ý nghĩa |
|---|---|
| `--check` | Kiểm tra điều kiện cài đặt/cấu hình; không ghi `.env`/secrets, không pull/build/start/stop container |
| `--build` | Build image `ipv6-proxy-manager:local` và lưu chế độ build cho lần chạy sau |
| `--bind IP` | Lưu `GUI_BIND`; IP phải thuộc host, hoặc địa chỉ wildcard; mặc định `127.0.0.1` |
| `--port PORT` | Lưu `GUI_PORT`, số nguyên `1024..65535`; mặc định `7070` |
| `--wait-timeout SECONDS` | Giới hạn thời gian đợi dịch vụ sẵn sàng sau `compose up`, `1..3600` giây; mặc định `120` |
| `--host-controller` | Sau khi dịch vụ sẵn sàng, cài controller chỉnh trần thread trên Linux cgroup v2; bước này dùng sudo khi cần |

Kiểm tra trước khi cài, không thay đổi deployment:

```bash
sudo bash scripts/install.sh --check --bind 0.0.0.0 --port 7070
```

Compose mặc định dùng **`ghcr.io/bscongluanbui/clbip:latest`**. GitHub Actions được thiết kế để build/test cả **Linux amd64, arm64 và arm/v7**, rồi ghép một tag đa kiến trúc sau khi cả ba job đạt gate. Docker chọn kiến trúc khi pull; Armbian `aarch64` dùng `linux/arm64`, không cần sửa Compose sang tag riêng. Chỉ dùng tag sau khi workflow publish thành công và package GHCR có quyền pull phù hợp; repository Public không tự làm package Public. Xem [hướng dẫn Armbian/registry](docs/CONTAINER_RELEASE.md#armbian-và-chọn-kiến-trúc).

Lần cập nhật tiếp theo chạy trong **cùng checkout**:

```bash
cd /home/ubuntu/clbip
git pull --ff-only
bash scripts/install.sh
python3 scripts/doctor.py
```

Installer giữ project name `ipv6-proxy-manager`, ba named volumes, thư mục `secrets` và cấu hình `.env`; không dùng `down --volumes` hoặc xóa dữ liệu. Chế độ build local đã lưu cũng được giữ: lần chạy installer tiếp theo rebuild source hiện tại, không quay lại pull GHCR. Container có thể được recreate khi cập nhật nên listener có thể gián đoạn ngắn; cơ chế phục hồi/tạo lại pool vẫn theo settings đã lưu. Không ghi đè `.env` bằng `.env.example` trên deployment đã có. Xem [container release, build local và rollback](docs/CONTAINER_RELEASE.md) để pin tag/digest hoặc cập nhật file Compose khi có thay đổi cấu hình triển khai.

Lệnh doctor mặc định chọn Compose base; **khi dùng build local**, chọn cả hai file để báo cáo đúng cấu hình (installer cũng in lệnh chẩn đoán tương ứng):

```bash
python3 scripts/doctor.py --compose-file docker-compose.yml --compose-file docker-compose.build.yml
```

Truy cập qua SSH tunnel:

```bash
ssh -N -L 7070:127.0.0.1:7070 ubuntu@192.168.1.3
```

Mở `http://127.0.0.1:7070`. Dashboard mở trực tiếp nếu không đặt mật khẩu; nếu đã đặt, đăng nhập bằng mật khẩu đó. Mật khẩu tùy chọn, không ép độ dài hay ký tự đặc biệt; có thể đổi hoặc để trống để tắt đăng nhập trong dashboard. Volume credential đã khởi tạo sẽ giữ mật khẩu qua các lần update; thay bootstrap secret không ghi đè volume này. File secrets không được đưa vào Git/image/build context; trên Linux thư mục host `secrets` có mode `0700`. File-backed Compose secrets giữ quyền file host; script tạo file `0444` để user dashboard non-root đọc được trong container. Giữ nguyên `secret_key` và `service_token` qua các lần cập nhật.

### Build local / phát triển

```bash
bash scripts/install.sh --build
# Installer lưu COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml
# và IPV6_MANAGER_IMAGE=ipv6-proxy-manager:local trong .env.
docker compose config --quiet
```

`docker compose` chạy từ checkout này sẽ dùng override build đã lưu; giữ `.env` để không mất chế độ build khi cập nhật. Nếu chỉ muốn chạy thủ công với override mà không lưu chế độ trong `.env`:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml build
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --no-build
```

Override có chủ đích dùng image `ipv6-proxy-manager:local` và không pull GHCR. Muốn quay lại image registry, sửa `.env`: đặt `COMPOSE_FILE=docker-compose.yml` và `IPV6_MANAGER_IMAGE` thành tag/digest đã publish, rồi chạy installer không có `--build`. Không chỉ đổi image trong khi vẫn giữ override build vì override vẫn chọn image local.

### Lưu settings và trần thread

- Lưu cùng giá trị trả `changed=false`; không ghi lại config hoặc restart proxy.
- Telegram, probe, lịch rotation, startup và các mặc định cho lần tạo tiếp theo được lưu mà không ngắt các listener hiện tại. Thay DNS, bind, auth/ACL, maxconn hoặc timeout vẫn áp dụng giao dịch engine/rollback.
- Dashboard hiển thị thread đang dùng/trần cgroup thực tế, setting được yêu cầu, số lần chạm trần mới, ESTABLISHED/CLOSE-WAIT, FD và RAM. Snapshot tài nguyên cache 5 giây; thông tin thiếu hiện là chưa quan sát. Cảnh báo 80%/90% chỉ là cảnh báo, không tự restart hoặc tạo lại pool.
- Setting `thread_limit` mặc định **4096**, khoảng **256..16384**. Khi host controller đã cài, nút riêng áp dụng ngay bằng Docker update, không restart engine/container. Giảm trần cần còn ít nhất 64 task dự phòng theo tải hiện tại.
- Host controller chỉ nhận `status`, `set_limit`, rollback giới hạn cho worker cố định; chạy trên host qua systemd và Unix socket trong volume runtime sẵn có. Dashboard/container không nhận Docker socket. Giới hạn mới được lưu vào `WORKER_THREAD_LIMIT` trong `.env`; Compose dùng `${WORKER_THREAD_LIMIT:-4096}` để giữ trần qua lần recreate sau.
- Với deployment đã có: cập nhật checkout/Compose rồi chạy `bash scripts/install.sh --host-controller` để cập nhật dịch vụ theo chế độ image/build đã lưu và cài lại controller. Pull image không tự cập nhật Compose hay script host. Installer giữ nguyên secrets và dữ liệu; phần `compose up` có thể tái tạo container nên thực hiện ở thời điểm chấp nhận ngắt kết nối ngắn.
- Kiểm tra controller: `sudo systemctl status clbip-host-controller --no-pager`. Chế độ chỉnh trần trực tiếp hiện dùng Linux cgroup v2; telemetry cũng đọc được cgroup v1. CLOSE-WAIT riêng lẻ không xác nhận leak; theo dõi vòng đời và áp lực tài nguyên trước khi thay timeout.

### Cấu hình mạng trước khi tạo proxy

1. Kiểm tra `ip -6 addr`, `ip -6 route`, DNS AAAA và truy cập HTTPS IPv6 trên host.
2. Chọn đúng NIC và topology: **lan** = prefix on-link router quảng bá; **routed** = prefix router đã route đến host, nhập `routed_prefix` được cấp thực tế.
3. Chọn prefix, listener IPv4, ACL nguồn IPv4/CIDR và username/password. Mặc định proxy chỉ nghe loopback; để truy cập LAN, nhập đúng IPv4 LAN của host và ACL client.
4. Chọn HTTPS probe trả source IPv6 plain text; endpoint phải public. Worker kiểm tra DAD/address readiness + source-bound egress trước commit.
5. Tạo ít proxy trước; chạy acceptance/benchmark ở [docs/LINUX_ACCEPTANCE.md](docs/LINUX_ACCEPTANCE.md), rồi tăng số lượng có kiểm soát.

Để trống **cả username và mật khẩu** trên form tạo proxy sẽ tự chọn không yêu cầu tài khoản; không dùng lại account đã lưu của pool trước. Nhập một ô thì cần nhập cả hai. Chế độ IP Whitelist vẫn dùng ACL nguồn; no-auth giữ ACL đích nhưng không dùng IP whitelist. API bỏ qua cả hai trường credential vẫn giữ cấu hình xác thực hiện tại để tương thích tự phục hồi khi khởi động.

**Khởi Tạo Lại Proxy Cũ** mặc định bật: tạo thành công sẽ thay pool bằng đúng số lượng mới và dọn alias cũ do tool quản lý. Bỏ chọn để chủ động thêm vào pool hiện tại. Nếu kiểm tra pool mới thất bại, transaction giữ pool cũ thay vì xóa pool đang hoạt động.

Phần thông tin interface chỉ hiển thị IPv6 hệ thống đủ điều kiện làm nguồn (tối đa 3 địa chỉ) và số IPv6 do tool quản lý; không liệt kê alias pool ở mục IPv6 nguồn. Danh sách chẩn đoán toàn bộ IPv6 vẫn giữ địa chỉ hệ thống, pool và alias chờ xác minh với nhãn riêng. “Nguồn ứng viên” là quan sát cục bộ, không tự khẳng định đã có Internet.

Speedtest dashboard hiển thị timing của curl qua proxy và tốc độ tải **mẫu response** bằng KiB/s + Mbps; đây không phải băng thông tối đa của đường truyền. `time_namelookup` là phân giải **địa chỉ proxy**, không đo DNS đích bên trong 3proxy; CONNECT/TLS là thời gian tích lũy đến khi tunnel/TLS hoàn tất. “Peer proxy” là địa chỉ listener mà curl kết nối, không phải IP đích hay bằng chứng IPv6 đầu ra. Field API cũ `speed_kbps` giữ giá trị KiB/s; field mới `speed_bytes_per_second` và `speed_mbps` ghi đơn vị rõ ràng.

### Timeout DNS và Diagnostic

- **Settings → Timeout DNS**: `timeout_dns` là số nguyên **1..30 giây**, mặc định **15**. Cấu hình cũ giữ 15 giây; không tự giảm timeout khi update image. Thay giá trị kích hoạt giao dịch cấu hình 3proxy và phục hồi giá trị cũ nếu activation lỗi; không tạo lại IPv6 pool. 3proxy thử DNS kế tiếp khi resolver trước timeout, nên tổng thời gian có thể gồm nhiều lần chờ. Có thể thử 3–5 giây sau khi kiểm tra resolver thực tế.
- **Speed Test → Chẩn Đoán DNS & Kết Nối**: chủ động đo AAAA của hostname đã chọn qua tối đa ba DNS trong Settings, hai vòng/resolver, tối đa ba thread, mỗi vòng có budget `min(timeout_dns, 3)` giây. UDP bị truncate chuyển TCP trong **cùng deadline**. Panel hiển thị RCODE, AAAA/TTL, latency và p50/p95/p99; hai vòng nhanh không phải bằng chứng cache hit hay Internet hoạt động.
- Lịch sử **200 Speed Test gần nhất** ở RAM hiển thị percentile, nhóm port/domain và lỗi CONNECT/auth/DNS/TLS/timeout/HTTP. Không thu thập request của Edge/profile; restart worker xóa lịch sử. History chỉ lưu hostname, không lưu URL path/query hay credentials. DNS percentile chỉ tính query thành công; history percentile tính tất cả probe có timing và ghi rõ phạm vi.
- CPU đọc từ cgroup worker; 100% tương đương một core. NIC Mbps/drop/error và TCP listen-drop/retransmission là delta của network namespace dùng chung host, không quy riêng cho proxy hay suy ra packet loss Internet. Snapshot cache 5 giây, lần đầu/counter reset/thiếu dữ liệu hiển thị chưa có số đo. Diagnostic không đổi NIC, sysctl, cache DNS, trần thread hay pool và không tự polling DNS.

Kiểm chứng resolver im lặng → DNS phụ, cache và thu hồi thread/FD chạy trong namespace cô lập bằng `tests/integration_dns_failover.py`; CI kiểm thử cả amd64/arm64/arm/v7. Hướng dẫn và phạm vi phép đo: [DNS & Diagnostic](docs/DNS_DIAGNOSTICS.md).

Mỗi proxy có IPv6 riêng và port riêng. Dual dùng một HTTP port + một SOCKS5 port (offset mặc định `10000`), tính là **2 dịch vụ**. Giới hạn mặc định **1024 dịch vụ**; `max_connections=64` áp dụng **cho từng dịch vụ/listener**, không phải toàn instance. Validation giới hạn tổng ngân sách `số dịch vụ × max_connections` ở **65536** để tránh cấu hình vượt tài nguyên ngay từ đầu; đây không phải bảo đảm throughput hay số kết nối khả dụng trên mọi host. Outgoing proxy ép IPv6; destination chỉ IPv4 sẽ thất bại.

Bản nâng cấp Linux/Docker: [cải tiến batch, dashboard và vận hành](docs/UPGRADE_20261008.md). Cấu hình đã lưu được giữ nguyên; để áp dụng đúng `maxconn 64` cho deployment hiện có, chạy `docker compose exec -T worker python -c "from rpc import WorkerClient; print(WorkerClient().call('save_settings', {'max_connections': 64}))"`. Settings được kiểm tra và kích hoạt bằng transaction hiện có, không chỉnh tay file 3proxy.

## Cấu hình triển khai

Các biến dưới đây được Compose đọc từ `.env` hoặc môi trường shell. Khi chạy `docker compose` trực tiếp, môi trường shell có ưu tiên cao hơn `.env`. Riêng installer ưu tiên tham số rõ ràng (`--bind`, `--port`, `--build`), rồi các selector đã lưu trong `.env` (`GUI_BIND`, `GUI_PORT`, `IPV6_MANAGER_IMAGE`), rồi môi trường shell hoặc mặc định; `COMPOSE_FILE` luôn lấy từ lựa chọn build hoặc `.env`/file base, không lấy từ shell. [.env.example](.env.example) là mẫu tham khảo, không chứa secrets. Installer lưu bind/port và lựa chọn build khi được yêu cầu; không ghi đè các giá trị khác.

| Biến | Mặc định / nghĩa |
|---|---|
| `IPV6_MANAGER_IMAGE` | `ghcr.io/bscongluanbui/clbip:latest`; có thể pin tag hoặc digest trong `.env` |
| `COMPOSE_FILE` | Không đặt thì Compose tìm `docker-compose.yml`; `--build` lưu `docker-compose.yml:docker-compose.build.yml` trên Linux |
| `GUI_BIND` | `127.0.0.1`; mở LAN chỉ khi đã có ACL/firewall/TLS phù hợp |
| `GUI_PORT` | `7070`; healthcheck và bot dùng cùng port |
| `WORKER_THREAD_LIMIT` | `4096`; trần task của worker, được host controller lưu sau khi thay đổi |
| `TELEGRAM_ENABLED` | `0`; đặt `1` rồi cấu hình bot token/chat ID/user IDs |
| `TELEGRAM_ALLOWED_USER_IDS` | Override allowlist bằng danh sách số, cách dấu phẩy |
| `DNS_CACHE_ENABLED` | `0`; optional DNS cache loopback port `5353` trên worker |
| `SESSION_COOKIE_SECURE` | `0` cho localhost HTTP; đặt `1` khi truy cập HTTPS |

Các đường dẫn runtime `ADMIN_PASSWORD_FILE=/run/secrets/admin_password`, `SECRET_KEY_FILE=/run/secrets/secret_key`, `SERVICE_TOKEN_FILE=/run/secrets/service_token` và `WORKER_SOCKET=/run/ipv6-manager/worker.sock` được cố định trong Compose, không phải biến override qua `.env`. Secrets thực tế nằm trong thư mục `secrets` trên host và được mount vào container; không đưa giá trị password/token/secret key vào `.env.example` hoặc Git.

DNS cache tùy chọn: bật `DNS_CACHE_ENABLED=1`, kiểm tra `127.0.0.1:5353` không xung đột, sau đó đặt DNS Primary trong dashboard thành `127.0.0.1:5353`. Không ghi `/etc/dnsmasq.conf`, không chiếm port `53`, không đổi host resolver.

## Telegram

Bot gọi management API với Bearer service token, không dựa vào bypass localhost. Quyền điều khiển yêu cầu đồng thời **chat ID + user ID allowlist**; anonymous/group/channel identity và forwarded commands bị bỏ qua. `/create`, `/clear`, `/restart`, `/reset200` cần `/confirm <nonce>` trong 60 giây, cùng user/chat; nonce dùng một lần. Config/token được đọc lại giữa các vòng polling. `/reset200` sử dụng một generation transaction `recreate=true`, không delete trước rồi create sau.

Settings API chỉ trả `telegram_bot_token_configured`; users API không trả password. Export credentials là thao tác riêng; không gửi export vào log/báo cáo.

## Kiểm tra và vận hành

### Phục hồi sau mất điện

Dashboard **Công cụ → Tạo lại proxy khi khởi động** cho phép đặt số proxy mới. Worker tự chờ IPv6 gốc có egress xác minh, cập nhật prefix, dọn toàn bộ alias do tool tạo rồi tạo mới đúng số lượng. Hai IPv6 gốc cũ/mới được kiểm tra từng nguồn, không lấy phần tử đầu tiên. Stop thủ công vẫn được giữ qua restart. Xem [hướng dẫn phục hồi](docs/REBOOT_RECOVERY.md).

```bash
node tests/test_frontend.js
python3 -m unittest discover -s tests -v
bash -n start.sh
bash -n scripts/install.sh
docker compose config --quiet
docker compose logs --tail=100 worker dashboard
```

### Chẩn đoán sau khi clone / dashboard không mở

Chạy tại checkout trên server; thêm `sudo` trước các lệnh cần truy cập Docker nếu tài khoản chưa có quyền dùng daemon:

```bash
cd /home/ubuntu/clbip
bash scripts/install.sh --check
docker compose ps --all
docker compose logs --tail=100 worker dashboard
python3 scripts/doctor.py
sudo ss -ltnp 'sport = :7070'
```

Nếu deployment dùng `--build`, thay lệnh doctor trong khối trên bằng `python3 scripts/doctor.py --compose-file docker-compose.yml --compose-file docker-compose.build.yml`. Installer đọc chế độ build đã lưu, còn doctor cần chọn override rõ ràng khi chạy riêng.

- **Chỉ clone chưa chạy dịch vụ:** installer sẽ tạo secrets thiếu và chạy Compose; không chạy trực tiếp `python app.py` trên host.
- **Docker daemon/Compose thiếu hoặc permission denied:** kiểm tra `docker info` và `docker compose version`; dùng `sudo bash scripts/install.sh` nếu daemon cần quyền sudo.
- **Pull GHCR lỗi:** kiểm tra tag, quyền package và kiến trúc; `--build` là lựa chọn chủ động như hướng dẫn trên, không xóa secrets/volumes để sửa lỗi pull.
- **Bind/port không đúng:** dashboard mặc định chỉ nghe loopback; dùng tunnel nếu giữ mặc định, hoặc chạy `sudo bash scripts/install.sh --bind 0.0.0.0 --port 7070` để nghe mọi địa chỉ IPv4 của server và mở `http://192.168.1.3:7070` từ LAN. Nếu port đã thuộc process khác, xem chủ listener bằng `ss`; chọn port còn trống thay vì dừng process đó.
- **Compose báo unhealthy nhưng trang còn mở:** phân biệt endpoint bên dưới; xem worker RPC, permissions, recovery/IPv6 và lỗi trong báo cáo doctor. Nếu router/prefix chưa phục hồi, dashboard login/status vẫn có thể dùng được.

Với bind LAN ở ví dụ trên:

```bash
curl --noproxy '*' -i http://192.168.1.3:7070/livez
curl --noproxy '*' -i http://192.168.1.3:7070/readyz
```

Nếu giữ bind mặc định, thay host URL bằng `127.0.0.1` và chạy trên server hoặc qua SSH tunnel. **`/livez` trả HTTP 200 với `{"alive":true}`** khi dashboard đáp ứng; kết quả này chưa chứng minh worker/proxy hoạt động. **`/readyz` trả HTTP 200 với `{"ready":true}`** chỉ khi dashboard có secrets cần thiết, gọi được RPC worker và health worker ready; HTTP 503 với `{"ready":false}` biểu thị chưa sẵn sàng. Docker healthcheck dùng `/readyz`, nên worker đang recovery, RPC lỗi hoặc IPv6/listener chưa ready có thể làm dashboard unhealthy dù `/livez` vẫn đạt. Installer đợi health trong thời gian giới hạn; lỗi/timeout không được báo là cài thành công.

[Linux acceptance / benchmark](docs/LINUX_ACCEPTANCE.md) · [Build provenance / SBOM](docs/BUILD_PROVENANCE.md) · [Operational checklist](docs/OPERATIONS.md)

Benchmark hỗ trợ listener HTTP và SOCKS5 (`socks5h://`, DNS qua proxy), matrix mặc định **25/50/100/200** hoặc `--counts` tùy chọn, một giới hạn concurrency chung. Report chứa source mismatch/error, p50/p95 và snapshot RSS/FD/NDP qua `/api/proxy/health` được xác thực. Matrix chỉ chọn các listener đã tồn tại; để đo capacity theo số proxy thực sự triển khai, chạy riêng từng mức và đối chiếu tổng deployed trong health. Kết quả unit test không phải số đo throughput/router thật.

CI build/test từng kiến trúc, tạo **SBOM toàn image** (Debian + Python + binary 3proxy có SHA256), rồi Grype scan SBOM với database được cập nhật. Actions được pin commit SHA, Syft/Grype được pin version. Gate chỉ chặn **High/Critical có bản vá**; full scan JSON vẫn giữ cả CVE chưa có bản vá. Evidence SBOM/image ID/scan/gate được lưu theo kiến trúc. Job manifest chỉ ghép digest của đủ ba image đã kiểm thử, không rebuild hoặc cập nhật `latest` khi một job thất bại. SBOM dependency trong repository là metadata nguồn; chỉ artifact của một CI run cụ thể mới chứng minh image tương ứng đã được scan.

Nguồn kỹ thuật chính: [RFC 4861 — Neighbor Discovery](https://www.rfc-editor.org/rfc/rfc4861), [RFC 4862 — SLAAC/DAD](https://www.rfc-editor.org/rfc/rfc4862), [RFC 8201 — IPv6 PMTUD](https://www.rfc-editor.org/rfc/rfc8201), [3proxy documentation](https://3proxy.org/doc/), [Docker capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities), [Docker host networking](https://docs.docker.com/engine/network/drivers/host/).
