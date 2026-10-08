# Tự phục hồi IPv6 sau mất điện / restart

## Bật tính năng

Trong dashboard, phần **Công cụ**:

1. Chọn đúng NIC kết nối LAN router, topology **LAN**; cấu hình protocol, port bắt đầu và tài khoản proxy như bình thường.
2. Bật **Tạo lại proxy khi khởi động**, nhập **Số proxy tạo mới** (1–1024, mặc định 25), rồi lưu.
3. Thiết lập có hiệu lực khi worker/container khởi động lại. Nút **Restart** cũng đưa vào chu trình tạo lại khi tính năng này bật.
4. Nếu trước đó đã nhấn **Stop**, nhấn **Start** để tiếp tục. Mất điện hoặc restart không đảo ngược Stop thủ công.

Settings API:

```json
{"startup_rebuild_enabled": true, "startup_proxy_count": 100}
```

Đây là cấu hình một đích NIC/protocol/port: chu trình này dọn **toàn bộ địa chỉ thuộc ledger của tool, kể cả các nhóm cũ trên NIC khác**, rồi tạo đúng số proxy mới trên NIC trong settings. Không lưu lại các nhóm/proxy ID cũ. Username/password đã lưu được giữ nguyên; HTTP/SOCKS/dual lấy từ settings (dual dùng offset 10000 như Generate mặc định).

## Chu trình sau boot

- Worker giữ một journal SQLite bền vững trong volume `proxy-data`; không dựa vào danh sách địa chỉ NIC cũ.
- Worker xác thực count/port/auth/resource budget, dừng listener do mình quản lý, chờ IPv6 gốc global còn preferred, hết DAD và có default/on-link route.
- Worker loại địa chỉ do tool tạo và IPv6 tentative/dadfailed/deprecated/hết lifetime. Worker thử HTTPS bằng từng IPv6 nguồn và kiểm tra nguồn đầu ra khớp chính xác, sau đó đọc lại NIC/routes.
- Nếu NIC còn IPv6 cũ và mới, tool thử nguồn còn dùng được; không chọn theo thứ tự danh sách hoặc báo lỗi chỉ vì có hai IPv6. Nếu cả hai còn hoạt động, live reconcile ưu tiên pool đang hoạt động, trừ khi router chỉ định nguồn ưu tiên khác. Lifetime chỉ là tín hiệu xếp hạng, không chứng minh thời điểm cấp địa chỉ.
- Khi nguồn đã xác minh, worker cập nhật subnet/prefix và ghi phase `cleaning` với proxy list rỗng + ledger inactive **trước** khi xóa alias cũ. Worker xóa từng alias thuộc ledger, xác nhận không còn, rồi tạo mới. Xóa lỗi vẫn giữ ledger; chưa tạo mới cho đến khi dọn xong.
- Mỗi alias mới phải add độc quyền, DAD ready và probe source thành công. Trạng thái `ready` commit cùng snapshot proxy mới. Nếu tạo lỗi/mất điện, rollback về cấu hình rỗng, retry; không bật lại IP/listener cũ đã xóa.
- Router/DNS/Internet chưa sẵn sàng: giữ trạng thái chờ, tự retry với backoff tối đa 30 giây trong phục hồi khởi động. Không tự đổi host sysctl, default route hay xóa IPv6 gốc của OS.
- Những địa chỉ chưa rõ kết quả add trước crash được tự bỏ intent chỉ khi strict snapshot xác nhận **không còn địa chỉ trên NIC**. Địa chỉ unknown còn tồn tại được giữ nguyên để xác minh ownership, không adopt/xóa.

`status`/`health` đọc snapshot không chờ mutation lock khi đang phục hồi; dashboard vẫn khởi động dù worker chưa ready. `proxy_running=null` trong giai đoạn này nghĩa là không thực hiện quan sát process ở snapshot nhẹ, không phải xác nhận số process bằng 0.

Tắt chức năng giữ startup restore truyền thống. Tắt trong khi đang chờ phục hồi đưa desired state về stopped; dùng Start khi muốn chạy tiếp.

## Điều kiện vận hành và nghiệm thu

- Cần Docker Engine trên Linux với NIC LAN thật, IPv6 nhà mạng usable và volume `proxy-data` bền vững. Docker daemon phải tự khởi động cùng host; compose đã có `restart: unless-stopped`. Container bị dừng thủ công bằng Docker vẫn giữ chính sách dừng của Docker.
- Tính năng không cấp prefix từ ISP và không triển khai DHCPv6-PD. Hệ điều hành/router vẫn chịu trách nhiệm nhận RA/DHCPv6 và route.
- Khởi động thử 3–5 proxy, sau đó tăng số lượng. Sequential DAD/source probes có tổng deadline `MAX_OPERATION_SECONDS` mặc định 240 (10–600); số lượng lớn/probe chậm phải đo trên mạng thật và chọn count/budget phù hợp. Chưa có kết luận capacity 1024.
- Thử: host boot trước router; router trở lại sau vài phút; hai prefix cùng tồn tại chỉ một egress được; restart worker hai lần; mất điện giữa cleanup/generation; Stop khi đang tạo; địa chỉ system/manual khác không bị xóa; port/user giữ đúng settings.
- Kiểm tra `startup_recovery.state=ready`, count đúng, source IPv6 đúng, HTTP/SOCKS hoạt động. Sau Stop, restart host phải vẫn stopped.

Nguồn nền tảng: [RFC 4862 — SLAAC, DAD và preferred/deprecated lifetime](https://www.rfc-editor.org/rfc/rfc4862), [Docker restart policy](https://docs.docker.com/engine/containers/start-containers-automatically/). Các kiểm thử giả lập không thay thế nghiệm thu LAN/ISP thật.
