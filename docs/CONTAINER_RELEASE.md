# Container release và cập nhật bằng Compose

## Image và topology

- Repository nguồn: <https://github.com/bscongluanbui/clbip>.
- Compose production dùng `ghcr.io/bscongluanbui/clbip:latest`; `IPV6_MANAGER_IMAGE` trong `.env` hoặc môi trường có thể chọn tag/digest khác.
- Worker và dashboard dùng cùng image; `APP_ROLE` xác định tiến trình từng container.
- Workflow được thiết kế để tạo một manifest chung cho **`linux/amd64`, `linux/arm64`, `linux/arm/v7`**. `amd64` và `arm64` chạy trên runner native; `arm/v7` dùng QEMU trên runner amd64. Mỗi kiến trúc phải qua unit/integration/scan trước khi được ghép vào release; cấu hình workflow không tự chứng minh một tag đã publish thành công.
- Deployment cần Docker Engine + Compose trên Linux và NIC/prefix IPv6 hoạt động. Image Docker này không phải backend native macOS của bản fork.
- Workflow publish giữ image theo commit/tag để chọn đúng phiên bản khi update hoặc rollback. Lấy digest thật từ kết quả workflow hoặc registry; không dùng một digest ví dụ làm release đã xác minh.

Để pull ẩn danh, package GHCR `clbip` phải được đặt **Public** trong package settings. Public repository không tự động chứng minh package mới cũng Public. Nếu chủ repo giữ package private, đăng nhập registry bằng credential có quyền `read:packages` trước khi pull. Hướng dẫn: [GHCR authentication và package visibility](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

### Armbian và chọn kiến trúc

Một tag đa kiến trúc dùng chung cho cả ba nền tảng. Docker tự chọn manifest phù hợp khi pull; không đặt `platform: linux/amd64` trong Compose trên máy ARM. Xem [Docker multi-platform images](https://docs.docker.com/build/building/multi-platform/).

| `uname -m` / hệ điều hành | Manifest |
|---|---|
| `x86_64`, Linux 64-bit | `linux/amd64` |
| `aarch64`, Linux ARM 64-bit | `linux/arm64` |
| `armv7l`, Linux ARM 32-bit | `linux/arm/v7` |

Đối chiếu cả kiến trúc Docker daemon nếu kernel 64-bit nhưng userland/Docker là 32-bit:

```bash
uname -m
docker info --format '{{.OSType}}/{{.Architecture}}'
docker buildx imagetools inspect ghcr.io/bscongluanbui/clbip:latest
```

Lỗi `denied` xảy ra ở bước truy cập registry; nó chưa chứng minh image thiếu ARM. Kiểm tra workflow đã publish tag và package visibility trước. Sau khi có quyền pull, nếu manifest thiếu kiến trúc thì Docker thường báo `no matching manifest`. Trên package Public, có thể kiểm tra pull không dùng credential cũ bằng một Docker config tạm:

```bash
pull_config="$(mktemp -d)"
DOCKER_CONFIG="$pull_config" docker pull ghcr.io/bscongluanbui/clbip:latest
rm -rf "$pull_config"
```

Không ghi PAT vào `.env`, Compose hoặc repository. Nếu package Private, dùng `docker login ghcr.io --username GITHUB_ACCOUNT --password-stdin` với credential đọc package.

## Cài lần đầu

```bash
git clone https://github.com/bscongluanbui/clbip.git
cd clbip
python3 scripts/init_secrets.py --no-dashboard-password
docker compose config --quiet
docker compose pull
docker compose up -d --no-build
python3 scripts/doctor.py
```

`--no-dashboard-password` tạo bootstrap password rỗng; dashboard không cần đăng nhập. Bỏ flag này nếu muốn mật khẩu khởi tạo ngẫu nhiên. Sau đó có thể đổi sang bất kỳ mật khẩu UTF-8 hoặc tắt đăng nhập trong UI, không ép độ dài/ký tự đặc biệt. Script chỉ tạo file chưa tồn tại, không thay secrets cũ.

Mặc định dashboard nghe `127.0.0.1:7070`. Để truy cập qua SSH tunnel:

```bash
ssh -L 7070:127.0.0.1:7070 ubuntu@LINUX_HOST
```

## Cập nhật image

Chạy trong cùng thư mục deployment với cùng Compose project:

```bash
docker compose pull
docker compose up -d --no-build
python3 scripts/doctor.py
docker compose logs --tail=100 worker dashboard
```

`pull` tải image, `up` mới thay container. Pull đơn lẻ chưa chạy bản mới. Nếu release thay Compose/scripts, cập nhật repository trước (`git pull --ff-only`), kiểm tra `docker compose config --quiet`, rồi chạy hai lệnh trên. Mặc định chỉ cần pull image khi cấu hình triển khai chưa đổi.

Compose giữ `name: ipv6-proxy-manager` và các named volumes:

| Volume | Nội dung / mount |
|---|---|
| `proxy-data` | SQLite, settings, ownership journal và pool; chỉ worker RW |
| `worker-runtime` | IPC socket; worker RW, dashboard RO |
| `dashboard-credentials` | Mật khẩu dashboard đã cập nhật; worker RW, dashboard RO |

Không đổi project name, không chạy `down --volumes` khi cập nhật. Giữ thư mục `secrets` và `.env`. Image không chứa secrets hoặc database của máy chủ. Thay image không ghi đè mật khẩu đã lưu trong credential volume; `ADMIN_PASSWORD_FILE` chỉ bootstrap khi volume chưa có credential.

Việc worker restart vẫn thực hiện cơ chế desired state/recovery của ứng dụng. Nếu đã bật tạo lại pool sau boot, worker có thể tái tạo pool theo cài đặt; bảo toàn volume không đồng nghĩa ép giữ từng IPv6 runtime qua restart.

## Pin tag hoặc digest

Trong `.env`, thêm hoặc sửa đúng **một** dòng `IPV6_MANAGER_IMAGE`. Ví dụ cú pháp tag theo commit:

```dotenv
IPV6_MANAGER_IMAGE=ghcr.io/bscongluanbui/clbip:sha-COMMIT
```

Thay `COMMIT` bằng tag đã publish thực tế. Nếu dùng digest, giá trị có dạng `ghcr.io/bscongluanbui/clbip@sha256:DIGEST`, với `DIGEST` lấy từ registry/workflow của bản muốn chạy. Digest pin đúng nội dung image, còn `latest` có thể thay đổi.

Sau khi chọn ref thật:

```bash
docker compose config --quiet
docker compose pull
docker compose up -d --no-build
```

Kiểm tra image của container đang chạy và digest registry tương ứng:

```bash
container_id="$(docker compose ps -q worker)"
image_id="$(docker inspect "$container_id" --format '{{.Image}}')"
docker image inspect "$image_id" --format '{{json .RepoDigests}}'
```

## Rollback image mà giữ dữ liệu

Trước khi update, ghi lại tag commit/digest hiện tại. Có thể giữ thêm tag local cho đúng image worker đang chạy:

```bash
container_id="$(docker compose ps -q worker)"
image_id="$(docker inspect "$container_id" --format '{{.Image}}')"
rollback_tag="clbip:rollback-$(date -u +%Y%m%dT%H%M%SZ)"
docker image tag "$image_id" "$rollback_tag"
printf '%s\n' "$rollback_tag" > .clbip-rollback-image
```

Rollback về registry tag/digest cũ: đặt `IPV6_MANAGER_IMAGE` trong `.env` về ref cũ, rồi `pull` và `up -d --no-build`. Cả worker lẫn dashboard phải về cùng ref.

Rollback về image local đã giữ:

```bash
IPV6_MANAGER_IMAGE="$(cat .clbip-rollback-image)" docker compose up -d --no-build --pull never
python3 scripts/doctor.py
```

Lệnh override môi trường chỉ áp dụng cho lần chạy đó; nếu muốn giữ rollback qua những lần Compose tiếp theo, cập nhật `IPV6_MANAGER_IMAGE` trong `.env` về cùng tag. Giữ image rollback local, không prune/xóa nó trước khi hết nhu cầu. Rollback image không tự phục hồi database về thời điểm cũ; nếu release thay schema không tương thích, dùng backup dữ liệu riêng đã kiểm tra trước khi nâng cấp.

## Build local và chạy CI integration

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.build.yml build
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --no-build
```

File `docker-compose.build.yml` chọn `ipv6-proxy-manager:local`, thêm build context và `pull_policy: never`. Compose production chỉ có image GHCR, không build trên home server. Không dùng tên `compose.override.yml` cho file build này, nhằm tránh Compose tự nạp override trong production.

Khi chẩn đoán hoặc đổi cổng deployment local build, truyền cùng hai Compose files cho helpers:

```bash
python3 scripts/doctor.py --compose-file docker-compose.yml --compose-file docker-compose.build.yml
python3 scripts/change_dashboard_port.py 7071 --compose-file docker-compose.yml --compose-file docker-compose.build.yml
```

Các lệnh isolated integration của CI chỉ kiểm tra namespace Docker riêng, không thay cho acceptance router/ISP thật. Xem [Linux acceptance](LINUX_ACCEPTANCE.md) và [build provenance](BUILD_PROVENANCE.md).

## Thiết kế pipeline release đa kiến trúc

1. Matrix ba kiến trúc build image local với `docker build --platform` và cùng `GITHUB_SHA`; từng job chạy unit/frontend, 3proxy trong namespace riêng và kiểm thử worker/dashboard/IPC trên chính image đó. `amd64`/`arm64` kiểm thử production engine trên runner native. `arm/v7` dùng probe riêng dưới QEMU để kiểm tra parser, authentication, source binding, listener và vòng đời binary; kiểm thử worker/dashboard và mật khẩu vẫn chạy trên image ARM đó. Probe QEMU không xác minh ownership production qua `/proc/PID/exe`, vì tiến trình host có thể hiện emulator; acceptance native ARMv7 trên thiết bị thật vẫn là bước riêng.
2. Từng job tạo SBOM đầy đủ và báo cáo Grype JSON **không bỏ CVE chưa có bản vá**. Gate riêng chỉ chặn mức **High/Critical có bản vá được scanner ghi nhận**, theo cấu hình đã chọn; các finding chưa có bản vá vẫn hiện trong artifact để theo dõi.
3. Chỉ image đã qua gate mới được push vào tag theo commit/kiến trúc (`sha-COMMIT-amd64`, `sha-COMMIT-arm64`, `sha-COMMIT-armv7`). Từng job kiểm tra pull/import và lưu release record gồm commit, platform, image ID và digest registry.
4. Job publish phụ thuộc thành công của **toàn bộ matrix**. Nó tải và xác minh đủ ba record cùng commit, platform và digest, rồi dùng `docker buildx imagetools create` ghép các digest đã kiểm thử; nó không rebuild image hoặc publish `latest` thiếu một kiến trúc. Tag chung gồm `sha-COMMIT` và tag phiên bản nếu workflow chạy từ tag hợp lệ. `latest` chỉ cập nhật từ nhánh `main` hoặc tag ổn định `vMAJOR.MINOR.PATCH`; tag prerelease không thay `latest`.
5. Manifest cuối được kiểm tra đủ ba platform và pull theo từng platform. Các job kiến trúc đã kiểm tra import/maxconn trên từng digest trước khi ghép manifest. Chỉ kết quả workflow và registry của một commit cụ thể mới là bằng chứng release, không phải các bước thiết kế trong tài liệu này.

Đổi gate không đồng nghĩa báo cáo sạch mọi CVE. Evidence giữ nguyên full SBOM, full vulnerability report và kết quả gate riêng cho từng kiến trúc.
