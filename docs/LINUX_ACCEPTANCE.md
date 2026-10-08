# Linux acceptance: direct-LAN and routed-prefix

Các bước dưới đây là runbook kiểm chứng trên host Linux/NIC thật hoặc Linux network lab riêng. Unit tests/mock không xác nhận prefix nhà mạng, router NDP, DAD, RA lifetime hay egress thật. Tạo state backup và dùng số lượng nhỏ trước.

## 1. Baseline (read-only)

```bash
ip -j -6 addr show > baseline-ipv6.json
ip -j -6 route show > baseline-routes.json
ip -6 neigh show
getent ahosts api64.ipify.org
curl --ipv6 --fail --max-time 15 https://api64.ipify.org
```

Ghi NIC, IPv4 LAN, IPv6 SLAAC/system, default gateway link-local, prefix/lifetime, MTU, DNS và port đang dùng (`ss -ltn`). Có IPv6 trên NIC chưa đủ chứng minh router cho phép thêm nhiều source IPv6.

## 2. Topology

### LAN trực tiếp router

- Router/ISP quảng bá prefix on-link trên NIC này. Dùng prefix đang preferred, chưa deprecated, đủ valid lifetime.
- Worker gắn địa chỉ proxy theo `/128`; connected route/default route của host vẫn đến từ network manager/router, không được tự đổi bởi ứng dụng.
- DAD phải hết `tentative`, không có `dadfailed`; router phải resolve NDP và return traffic cho IPv6 mới.
- Nếu router/ISP chỉ chấp nhận một source/MAC hoặc giới hạn neighbor table, thêm địa chỉ đúng cú pháp vẫn có thể thất bại egress.

### Routed prefix

- Router phải có route prefix được cấp **qua host**; `routed_prefix` phải chính xác, không phải giả định cả `/48` là on-link trên LAN.
- Host phải có đường default qua upstream và reverse routing đúng. Không bật forwarding trên toàn host chỉ vì proxy là ứng dụng local.
- Chỉ cấu hình RA/forwarding/prefix delegation trong hệ thống mạng khi topology thực sự yêu cầu; nếu host cần nhận RA trong chế độ forwarding, đánh giá `accept_ra=2` cho đúng NIC, không sửa toàn cục.

Nền tảng: [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861), [RFC 4862](https://www.rfc-editor.org/rfc/rfc4862), [Linux IPv6 sysctl](https://docs.kernel.org/networking/ip-sysctl.html).

## 3. Acceptance matrix

| Case | Thao tác trong lab | Kết quả đạt |
|---|---|---|
| Generation | 1 HTTP, 1 SOCKS5, 1 dual; đúng NIC/prefix | IP ready; tất cả listeners ready; source probe đúng IPv6; JSON/state/config nhất quán |
| ACL | Client allowed và denied; username sai/đúng | Denied source/credentials bị từ chối; đúng source+credential được thông |
| Credential revoke | Xóa user hoặc thay password qua API/UI | Kết nối mới dùng credentials cũ bị từ chối ngay sau success; không chỉ đổi file |
| Conflict | Port đã bị process khác listen, thiếu quyền NIC | Operation fail; old state/listeners/IP giữ nguyên; process host không bị kill |
| Address failure | DAD fail/tentative quá hạn, DNS fail, route fail | Không commit proxy active mới; rollback owned addresses/config |
| Manual Stop | Stop, chờ >60s, restart containers | Desired stopped giữ nguyên; không tự bật lại vì watchdog |
| Unexpected crash | Kill riêng child PID do worker quản lý | Desired running tự phục hồi bounded; tất cả instances sẵn sàng mới báo ready |
| Restart | Restart dashboard/worker, stable secrets | Session policy ổn định; owned address recovery theo desired state; không nhận nhầm PID |
| Rotate / recreate | Một proxy và toàn bộ nhóm | Add-ready-probe trước remove old; thất bại phục hồi state cũ |
| Prefix renewal | Lab đổi RA/prefix/lifetime, drop LAN | Không dùng IPv6 deprecated; báo trạng thái lỗi rõ ràng; cấu hình prefix mới + reprobe trước bật |
| Cleanup | Tạo IPv6 system/manual không thuộc ledger | Cleanup không xóa địa chỉ không do app sở hữu, kể cả `/128` |
| Address ownership race | Trong lab, process khác thêm đúng IP giữa snapshot và thao tác add của worker | Exclusive add fail; worker không adopt/xóa IP của process khác |
| Ambiguous crash boundary | Trong lab, interrupt worker sau kernel add nhưng trước xác nhận journal | Address uncertainty được giữ riêng; không tự adopt/xóa; ready bị chặn đến khi operator review/ack |
| Multiple groups | Nhóm LAN NIC A + nhóm routed NIC B; đổi RA nhóm A | Record giữ topology/NIC/prefix riêng; nhóm routed B không bị đổi prefix theo A |
| API security | Không login/Bearer; thiếu CSRF; key duplicate | 401/403; duplicate request không tạo thêm proxy; same key khác input bị reject |
| XSS/secrets | Username/field có HTML; GET users/settings | Text escaped/rejected; không password/token trong responses/logs |
| IPC | Dashboard nonroot/cap-drop, wrong service token | Dashboard thao tác được qua socket; sai token bị reject; dashboard không mở được data volume |
| PMTU | HTTPS response lớn qua đường IPv6 MTU thấp | Không blackhole; ICMPv6 Packet Too Big không bị firewall chặn |

PMTU: [RFC 8201](https://www.rfc-editor.org/rfc/rfc8201); đừng chặn toàn bộ ICMPv6.

## 4. Source-bound independent verification

Đặt `SOURCE_IPV6` từ record proxy và IPv4/port listener thật; không copy password vào log.

```bash
ip -6 route get 2606:4700:4700::1111 from "$SOURCE_IPV6"
curl --interface "$SOURCE_IPV6" --ipv6 --fail --max-time 15 https://api64.ipify.org
# So sánh kết quả API egress với IPv6 của từng record, không chỉ HTTP status 200.
```

Lệnh direct source-bound kiểm tra routing NIC; phép thử qua HTTP/SOCKS5 listener vẫn cần chạy riêng để xác nhận 3proxy source binding/auth.

## 5. Benchmark bounded

Tạo file JSON owner-only, ví dụ (giá trị demo):

```json
[{"url":"http://USER:PASSWORD@127.0.0.1:10000","expected_ipv6":"2001:db8::1"}]
```

```bash
chmod 600 benchmark-proxies.json
python3 scripts/benchmark.py --proxies benchmark-proxies.json --counts 1 --rounds 10 --concurrency 4 --output benchmark-result.json
```

Với một record demo, `--counts 1` chọn đúng một listener thay vì matrix mặc định.

HTTP dùng `http://USER:PASSWORD@127.0.0.1:10000`; SOCKS5 dùng `socks5h://USER:PASSWORD@127.0.0.1:20000` để hostname được resolve qua proxy (không cần PySocks). Một dual proxy có hai listener: đo từng protocol riêng hoặc ghi hai listener records với cùng expected IPv6, rồi ghi rõ số services khác với số IPv6/proxies.

Với ≥200 listener records đã tạo và verified, chạy matrix **participating listeners** 25/50/100/200:

```bash
python3 scripts/benchmark.py --proxies benchmark-proxies.json --counts 25,50,100,200 \
  --rounds 10 --concurrency 4 \
  --health-url http://127.0.0.1:7070/api/proxy/health \
  --token-file secrets/service_token --output benchmark-matrix.json
```

Tool không generate/delete proxy. Mỗi stage chọn N records đầu của cùng pool; nếu host đã chạy 200 proxy thì stage25 vẫn có tổng200 deployed. **Không gọi đó là capacity25.** Để acceptance theo số proxy thực sự triển khai, tạo riêng25 →50 →100 →200 proxy, xuất đúng pool tương ứng, chạy riêng `--counts 25`, `--counts 50`, `--counts 100`, `--counts 200`; đối chiếu `health_before/after.active_proxy_count` và `active_service_count`. Chọn thứ tự input cân bằng NIC/prefix/protocol, giữ nguyên môi trường giữa các lần.

Một pool concurrency chung giới hạn **tổng request qua tất cả listener ≤32**, rounds1..100, tối đa100000samples. Mỗi sample mở kết nối mới/curl riêng, HTTPS certificate verification bật, không follow redirect, connect timeout5s/total15s/subprocess20s; credential chỉ đi qua stdin, không command arguments hay report. Stage ghi tổng/error/source mismatch count, error rate, p50 (median)/p95 (nearest rank), latency samples và kết quả từng endpoint. Mặc định lỗi source/request dừng các stage sau; `--continue-on-error` chỉ để thu thập lỗi trong lab. Exit0=source checks đạt; exit1=source/request/readiness fail; exit2=input lỗi hoặc metrics được yêu cầu nhưng chưa đầy đủ. Report không chứa credentials; service token chỉ gửi tới literal loopback health URL, không hostname hoặc remote URL.

Health được lấy trước/sau mỗi stage; report ghi `metrics.worker` (RSS bytes/FD), `metrics.proxy_children` (RSS/FD/process count) và `metrics.ndp` (neighbor count/states theo NIC). Phép đo thất bại giữ `null`, không thay bằng0. Đây là **snapshot, không phải peak/high-water mark**; ghi CPU, RSS/FD peaks và router neighbor table bằng monitoring riêng nếu cần stress capacity. NDP được đo trên host, không tự suy ra số entries/giới hạn NDP của router.

Đây **không phải bandwidth test** (response rất nhỏ). Đo bandwidth riêng với HTTPS endpoint/file do bạn quản lý, connection reuse/payload cố định; ghi NIC speed, MTU, router/firmware, CPU/RSS/FD, logging/cache mode và tỷ lệ lỗi. Chạy concurrency1 →4 →16 →32 cho từng count; chỉ tăng sau khi source matching=100%, error=0, ready ổn định và không FD exhaustion. Endpoint probe phải cho phép tần suất dự kiến; rate-limit upstream có thể làm sai kết luận về proxy. So sánh logging bật/tắt, DNS cache bật/tắt trong cùng môi trường, không suy luận mọi hệ thống cần13proxy/process. Hành vi curl dựa trên [curl manual](https://curl.se/docs/manpage.html).

## 6. Crash ownership review

Nếu health trả `uncertain_addresses`, worker giữ NIC nguyên trạng và chặn ready. Hoàn tất pending-operation recovery trước; operator đối chiếu operation ID, address, interface với `ip -j -6 addr show`, journal/state backup và cấu hình mạng hệ thống. Kernel không lưu bằng chứng tác giả tạo alias; chỉ trạng thái address hiện tại không chứng minh ownership. Khi xác nhận record không được ứng dụng tiếp tục nhận sở hữu, gửi authenticated `POST /api/ownership/resolve` với:

```json
{"operation_id":"OPERATION_ID","address":"2001:db8::1","interface":"eth0","acknowledge_unmanaged":true}
```

Thao tác chỉ clear uncertainty record tương ứng, không đổi/xóa NIC address. Operator xử lý alias còn lại bằng quy trình mạng riêng sau khi xác minh; không chèn address vào owned ledger để bỏ qua review. Kiểm tra lại health, source probe và cleanup ledger trước resume generation/rotation.

## 7. Real-engine CI smoke test

CI runs `tests/integration_linux.py --run` in a fresh Docker container with `--network none`, only loopback NIC, `NET_ADMIN` and an explicit isolated-test opt-in. The script rejects a namespace containing any NIC other than lo. It tests the compiled 3proxy binary's multiple instances, HTTP/SOCKS5 source binding, credentials/revocation, destination ACL, observed process ownership/readiness/RSS/FD, and zero-config orphan shutdown. Test traffic remains inside that container; it does not prove router/ISP RA/NDP/routing behavior. Real LAN acceptance above remains separate.

The supported lifecycle is the supervised worker container. An abrupt worker exit causes the entrypoint/container to terminate its private PID namespace; do not run worker.py standalone under an unrelated supervisor and assume the same crash ownership guarantees. The creation-to-process-ledger boundary needs the enclosing container lifecycle and Linux fault acceptance.
