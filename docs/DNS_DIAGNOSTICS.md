# Timeout DNS và Diagnostic

## Cách dùng

1. Update image khi sẵn sàng chuyển bản; chỉ pull image không thay container đang chạy.
2. Trong Settings, giữ `Timeout DNS = 15` để không thay hành vi cũ. Nếu DNS hay mất phản hồi, có thể thử 5 giây, rồi 3 giây sau khi đo. Phạm vi chấp nhận là số nguyên 1..30 giây; các timeout TCP/HTTP khác không đổi.
3. Trong Speed Test, chọn hostname HTTPS, ví dụ `https://www.bing.com`, và bấm **Chẩn Đoán DNS & Kết Nối**. Probe AAAA chạy trực tiếp qua DNS numeric trong Settings, không dùng system resolver. Mỗi resolver có hai vòng, mỗi vòng tối đa `min(timeout_dns, 3)` giây; ba resolver đo song song, không tạo thêm proxy hay thay cấu hình.
4. Chạy Speed Test trên port cần kiểm tra để bổ sung history. Diagnostic không quan sát traffic Edge; history trống nếu chưa chạy Speed Test hoặc worker vừa restart.

Thay `timeout_dns` là thay cấu hình engine, có thể ngắt kết nối ngắn khi kích hoạt. Transaction giữ nguyên IPv6/port của pool; activation thất bại phục hồi cấu hình và setting cũ. Lưu cùng giá trị không restart. Chỉ bấm Diagnostic không kích hoạt engine.

## Đọc đúng kết quả

- **AAAA/TTL/RCODE**: có AAAA không chứng minh TCP/TLS tới website hoạt động. Query lặp nhanh không xác nhận cache hit; phép đo độc lập không tái hiện chính xác cache/process/source IPv6 của từng shard 3proxy.
- **DNS p50/p95/p99**: chỉ query thành công, tính nearest-rank. Hai mẫu/resolver quá ít để đánh giá thống kê dài hạn; lỗi và số mẫu hiển thị riêng. Không có AAAA là kết quả riêng, không coi là latency thành công.
- **History**: tối đa 200 probe ở RAM, các tổng/nhóm port/domain chỉ phản ánh window này. Timing thất bại vẫn được tính nếu có `total_time`; lỗi không có timing không được tạo timing giả. Mất history qua restart là chủ đích. URL path/query, username/password và raw error text không được lưu vào history.
- **Curl qua proxy**: `time_namelookup` đo phân giải địa chỉ proxy, không đo DNS website bên trong 3proxy. `time_connect` là TCP đến proxy; `time_appconnect` tích lũy đến khi CONNECT/TLS hoàn tất, bao gồm chờ upstream DNS/TCP. HTTP CONNECT `407` là auth; `403` là từ chối proxy; `502` là lỗi CONNECT. Không gọi mọi `curl 56` là lỗi website.
- **CPU**: worker cgroup; 100% là một core, có thể vượt 100% khi nhiều core chạy. Delta throttling khác tổng lifetime.
- **NIC/TCP**: host network namespace dùng chung nên gồm cả ứng dụng khác. ListenDrops/Overflows lifetime khác delta trong khoảng đo. NIC drop/error không đo packet loss end-to-end. Speed Mbps là tốc độ link đọc được, không phải throughput Internet.
- **Chưa có dữ liệu**: sample đầu, counter reset, đổi cgroup/interface hoặc thiếu counter trả `null`, không giả thành zero. Snapshot passive cache 5 giây; DNS chỉ chạy khi bấm nút, tối đa một Diagnostic đang chạy.

## API và kiểm thử

`POST /api/proxy/diagnostics` nhận duy nhất `{"target_url":"https://www.bing.com"}`; dùng auth/CSRF hiện có. Đây là POST đọc dữ liệu, không dùng mutation journal/idempotency operation và không giữ khóa giao dịch thay đổi pool. Response gồm `dns`, `history`, `resources`, `runtime_changed=false`.

Các regression offline dùng resolver/socket/NIC/engine fixtures, bao gồm packet DNS không hợp lệ, TCP fallback cùng deadline, auth/CSRF, concurrency, reset counter và rollback cấu hình. Kiểm thử engine thật dùng image được build trong namespace `--network none`; resolver chính cố tình im lặng, resolver phụ và HTTP target nằm trong namespace. Với DNS 3/5 giây, test xác nhận failover HTTP 200 gần mức đặt, cache lượt sau không thêm query, thread/FD trở về baseline. Test không gọi Internet hay đổi NIC host. CI chạy cả ba kiến trúc trước khi publish `latest`.

## Nguồn kỹ thuật

- [3proxy config: timeouts và nserver](https://3proxy.org/doc/man3/3proxy.cfg.3.html).
- [3proxy 0.9.6 resolver implementation](https://github.com/3proxy/3proxy/blob/0.9.6/src/auth.c).
- [curl NAMELOOKUP_TIME](https://curl.se/libcurl/c/CURLINFO_NAMELOOKUP_TIME.html), [CONNECT_TIME](https://curl.se/libcurl/c/CURLINFO_CONNECT_TIME.html), [APPCONNECT_TIME](https://curl.se/libcurl/c/CURLINFO_APPCONNECT_TIME.html), [HTTP_CONNECTCODE](https://curl.se/libcurl/c/CURLINFO_HTTP_CONNECTCODE.html).
- [Linux cgroup v2 CPU counters](https://docs.kernel.org/admin-guide/cgroup-v2.html#cpu), [Linux network counters](https://docs.kernel.org/networking/statistics.html).
