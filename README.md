# IPv6 Proxy Manager — Linux LAN / routed-prefix

Dashboard quản lý HTTP/SOCKS5 proxy với 3proxy. Địa chỉ được chọn **trong prefix IPv6 thực sự có đường đi từ nhà mạng/router**; phần mềm không cấp thêm prefix và không biến một IPv6 bất kỳ thành địa chỉ truy cập Internet được.

## Kiến trúc

- **dashboard**: Gunicorn 1 worker / 8 threads, user `10001:10001`, không capability, root filesystem read-only; mặc định chỉ nghe `127.0.0.1:7070`.
- **worker**: duy nhất quản lý state, IPv6 và 3proxy; `NET_ADMIN`, không `privileged`; persistent named volume `proxy-data`.
- Dashboard ↔ worker: Unix socket mode `0660`, group `10001`, xác thực `SERVICE_TOKEN`; dashboard mount socket directory và volume mật khẩu dashboard read-only, không mount database. Worker ghi mật khẩu vào volume `dashboard-credentials` riêng.
- Một reconciler theo **desired state**; lệnh Stop được giữ qua reconcile/restart. Entrypoint chỉ giám sát vòng đời process, không đổi sysctl, không có watchdog thứ hai, không `pkill` process host.

## Triển khai

**Môi trường mục tiêu:** Docker Engine + Compose trên Linux có NIC kết nối trực tiếp router và IPv6 hoạt động. Docker Desktop host-network chỉ cung cấp một số chức năng L4; không đồng nghĩa với quyền quản lý NIC/L2 của Windows/macOS host. Xem [Docker host-network limitations](https://docs.docker.com/engine/network/drivers/host/#limitations).

```bash
git clone https://github.com/bscongluanbui/clbip.git
cd clbip
python3 scripts/init_secrets.py --no-dashboard-password
# Bỏ --no-dashboard-password nếu muốn tạo mật khẩu đăng nhập ban đầu.
# Script giữ nguyên tất cả secrets đã tồn tại.
docker compose config --quiet
docker compose pull
docker compose up -d --no-build
```

Compose mặc định dùng **`ghcr.io/bscongluanbui/clbip:latest`**. GitHub Actions được thiết kế để build/test cả **Linux amd64, arm64 và arm/v7**, rồi ghép một tag đa kiến trúc sau khi cả ba job đạt gate. Docker chọn kiến trúc khi pull; Armbian `aarch64` dùng `linux/arm64`, không cần sửa Compose sang tag riêng. Chỉ dùng tag sau khi workflow publish thành công và package GHCR có quyền pull phù hợp; repository Public không tự làm package Public. Xem [hướng dẫn Armbian/registry](docs/CONTAINER_RELEASE.md#armbian-và-chọn-kiến-trúc).

Lần cập nhật tiếp theo dùng:

```bash
docker compose pull
docker compose up -d --no-build
python3 scripts/doctor.py
```

Giữ project name `ipv6-proxy-manager`, ba named volumes và thư mục `secrets`; cập nhật container không xóa settings, proxy pool đã lưu hoặc mật khẩu dashboard. Xem [container release, build local và rollback](docs/CONTAINER_RELEASE.md) để pin tag/digest hoặc cập nhật file Compose khi có thay đổi cấu hình triển khai.

Truy cập qua SSH tunnel:

```bash
ssh -L 7070:127.0.0.1:7070 ACCOUNT@LINUX_HOST
```

Mở `http://127.0.0.1:7070`. Dashboard mở trực tiếp nếu không đặt mật khẩu; nếu đã đặt, đăng nhập bằng mật khẩu đó. Mật khẩu tùy chọn, không ép độ dài hay ký tự đặc biệt; có thể đổi hoặc để trống để tắt đăng nhập trong dashboard. Volume credential đã khởi tạo sẽ giữ mật khẩu qua các lần update; thay bootstrap secret không ghi đè volume này. File secrets không được đưa vào Git/image/build context; trên Linux thư mục host `secrets` có mode `0700`. File-backed Compose secrets giữ quyền file host; script tạo file `0444` để user dashboard non-root đọc được trong container. Giữ nguyên `secret_key` và `service_token` qua các lần cập nhật.

### Build local / phát triển

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml build
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --no-build
```

Override có chủ đích dùng image `ipv6-proxy-manager:local` và không pull GHCR; không tự áp dụng vào deployment production.

### Cấu hình mạng trước khi tạo proxy

1. Kiểm tra `ip -6 addr`, `ip -6 route`, DNS AAAA và truy cập HTTPS IPv6 trên host.
2. Chọn đúng NIC và topology: **lan** = prefix on-link router quảng bá; **routed** = prefix router đã route đến host, nhập `routed_prefix` được cấp thực tế.
3. Chọn prefix, listener IPv4, ACL nguồn IPv4/CIDR và username/password. Mặc định proxy chỉ nghe loopback; để truy cập LAN, nhập đúng IPv4 LAN của host và ACL client.
4. Chọn HTTPS probe trả source IPv6 plain text; endpoint phải public. Worker kiểm tra DAD/address readiness + source-bound egress trước commit.
5. Tạo ít proxy trước; chạy acceptance/benchmark ở [docs/LINUX_ACCEPTANCE.md](docs/LINUX_ACCEPTANCE.md), rồi tăng số lượng có kiểm soát.

Để trống **cả username và mật khẩu** trên form tạo proxy sẽ tự chọn không yêu cầu tài khoản; không dùng lại account đã lưu của pool trước. Nhập một ô thì cần nhập cả hai. Chế độ IP Whitelist vẫn dùng ACL nguồn; no-auth giữ ACL đích nhưng không dùng IP whitelist. API bỏ qua cả hai trường credential vẫn giữ cấu hình xác thực hiện tại để tương thích tự phục hồi khi khởi động.

**Khởi Tạo Lại Proxy Cũ** mặc định bật: tạo thành công sẽ thay pool bằng đúng số lượng mới và dọn alias cũ do tool quản lý. Bỏ chọn để chủ động thêm vào pool hiện tại. Nếu kiểm tra pool mới thất bại, transaction giữ pool cũ thay vì xóa pool đang hoạt động.

Mỗi proxy có IPv6 riêng và port riêng. Dual dùng một HTTP port + một SOCKS5 port (offset mặc định `10000`), tính là **2 dịch vụ**. Giới hạn mặc định **1024 dịch vụ**; `max_connections=64` áp dụng **cho từng dịch vụ/listener**, không phải toàn instance. Validation giới hạn tổng ngân sách `số dịch vụ × max_connections` ở **65536** để tránh cấu hình vượt tài nguyên ngay từ đầu; đây không phải bảo đảm throughput hay số kết nối khả dụng trên mọi host. Outgoing proxy ép IPv6; destination chỉ IPv4 sẽ thất bại.

Bản nâng cấp Linux/Docker: [cải tiến batch, dashboard và vận hành](docs/UPGRADE_20261008.md). Cấu hình đã lưu được giữ nguyên; để áp dụng đúng `maxconn 64` cho deployment hiện có, chạy `docker compose exec -T worker python -c "from rpc import WorkerClient; print(WorkerClient().call('save_settings', {'max_connections': 64}))"`. Settings được kiểm tra và kích hoạt bằng transaction hiện có, không chỉnh tay file 3proxy.

## Cấu hình triển khai

| Biến | Mặc định / nghĩa |
|---|---|
| `IPV6_MANAGER_IMAGE` | `ghcr.io/bscongluanbui/clbip:latest`; có thể pin tag hoặc digest trong `.env` |
| `GUI_BIND` | `127.0.0.1`; mở LAN chỉ khi đã có ACL/firewall/TLS phù hợp |
| `GUI_PORT` | `7070`; healthcheck và bot dùng cùng port |
| `ADMIN_PASSWORD_FILE` | `/run/secrets/admin_password` |
| `SECRET_KEY_FILE` | `/run/secrets/secret_key`, persistent |
| `SERVICE_TOKEN_FILE` | `/run/secrets/service_token`, cả dashboard/worker |
| `WORKER_SOCKET` | `/run/ipv6-manager/worker.sock` |
| `TELEGRAM_ENABLED` | `0`; đặt `1` rồi cấu hình bot token/chat ID/user IDs |
| `TELEGRAM_ALLOWED_USER_IDS` | Override allowlist bằng danh sách số, cách dấu phẩy |
| `DNS_CACHE_ENABLED` | `0`; optional DNS cache loopback port `5353` trên worker |
| `SESSION_COOKIE_SECURE` | `0` cho localhost HTTP; đặt `1` khi truy cập HTTPS |

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
docker compose config --quiet
docker compose logs --tail=100 worker dashboard
```

[Linux acceptance / benchmark](docs/LINUX_ACCEPTANCE.md) · [Build provenance / SBOM](docs/BUILD_PROVENANCE.md) · [Operational checklist](docs/OPERATIONS.md)

Benchmark hỗ trợ listener HTTP và SOCKS5 (`socks5h://`, DNS qua proxy), matrix mặc định **25/50/100/200** hoặc `--counts` tùy chọn, một giới hạn concurrency chung. Report chứa source mismatch/error, p50/p95 và snapshot RSS/FD/NDP qua `/api/proxy/health` được xác thực. Matrix chỉ chọn các listener đã tồn tại; để đo capacity theo số proxy thực sự triển khai, chạy riêng từng mức và đối chiếu tổng deployed trong health. Kết quả unit test không phải số đo throughput/router thật.

CI build/test từng kiến trúc, tạo **SBOM toàn image** (Debian + Python + binary 3proxy có SHA256), rồi Grype scan SBOM với database được cập nhật. Actions được pin commit SHA, Syft/Grype được pin version. Gate chỉ chặn **High/Critical có bản vá**; full scan JSON vẫn giữ cả CVE chưa có bản vá. Evidence SBOM/image ID/scan/gate được lưu theo kiến trúc. Job manifest chỉ ghép digest của đủ ba image đã kiểm thử, không rebuild hoặc cập nhật `latest` khi một job thất bại. SBOM dependency trong repository là metadata nguồn; chỉ artifact của một CI run cụ thể mới chứng minh image tương ứng đã được scan.

Nguồn kỹ thuật chính: [RFC 4861 — Neighbor Discovery](https://www.rfc-editor.org/rfc/rfc4861), [RFC 4862 — SLAAC/DAD](https://www.rfc-editor.org/rfc/rfc4862), [RFC 8201 — IPv6 PMTUD](https://www.rfc-editor.org/rfc/rfc8201), [3proxy documentation](https://3proxy.org/doc/), [Docker capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities), [Docker host networking](https://docs.docker.com/engine/network/drivers/host/).
