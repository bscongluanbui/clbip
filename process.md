# Quy trình triển khai hiện tại

Tài liệu vận hành chính: [README](README.md), [Operations](docs/OPERATIONS.md), [Linux acceptance](docs/LINUX_ACCEPTANCE.md).

1. Kiểm tra Linux host nhận IPv6 global, default route, và prefix on-link trên cổng LAN.
2. Phân biệt LAN on-link /64 với delegated/routed prefix. Routed mode yêu cầu route upstream về host.
3. Tạo secrets bằng `python scripts/init_secrets.py`, giữ các file giữa các lần deploy.
4. Build/deploy theo README. Worker là thành phần duy nhất có NET_ADMIN; dashboard dùng user không đặc quyền.
5. Xác minh readiness, rồi generate với credential/allowlist. Alias mới dùng /128, DAD và source-egress probe trước commit.
6. Chạy Linux acceptance và benchmark, ghi kết quả thực tế. Quy mô phụ thuộc host/router/ISP.
7. Stop ghi trạng thái bền vững. Reset/generate là transaction, không xóa toàn bộ địa chỉ kernel trước khi kiểm tra input.

Các hướng dẫn cũ về privileged container, forwarding=1, source bind-mount, admin mặc định và xóa toàn bộ địa chỉ global đã được thay thế.
