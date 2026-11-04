# TÀI LIỆU TOÀN TẬP VỀ HỆ THỐNG CLEAR NDR & CẤU HÌNH IPS CHẶN SLIVER C2

> **Mục đích tài liệu:** Cung cấp đầy đủ ngữ cảnh (context), kiến trúc hệ thống, quy trình hoạt động của các bộ rule, phân tích nguyên nhân lỗi và giải pháp đã triển khai để toàn đội ngũ nắm bắt và tiếp tục demo/vận hành.

---

## 1. TỔNG QUAN KIẾN TRÚC MẠNG & HỆ THỐNG (SYSTEM TOPOLOGY)

### 1.1. Hạ tầng mạng & Phân vùng (Network Segmentation)
Máy chủ trung tâm là máy **Clear NDR Gateway** (tên máy: `Nhom1`, hệ điều hành Debian 12 / Kernel 6.1), đứng ở giữa làm nhiệm vụ định tuyến (Router/Gateway) kiêm giám sát/ngăn chặn (NDR/IPS):

* **Card mạng nội bộ (`ens36`)**:
  * IP Gateway: `192.168.60.1/24`
  * Nối tới phân vùng máy **Victim (Ubuntu demo)** có IP: `192.168.60.20` (hoặc dải `192.168.60.0/24`). Máy victim trỏ Default Gateway về `192.168.60.1`.
* **Card mạng ngoại vi (`ens33`)**:
  * IP: `192.168.240.129/24`
  * Nối ra mạng ngoài/Internet qua default gateway `192.168.240.2`.
* **Cơ chế chuyển tiếp gói tin**:
  * Linux Kernel bật tính năng định tuyến: `net.ipv4.ip_forward = 1`.

```
+------------------------------------+           +---------------------------------------+           +-----------------------------+
|               VICTIM               |           |           CLEAR NDR GATEWAY           |           |          ATTACKER           |
|         (192.168.60.20)            |           |         (Debian - Suricata 8)         |           |       (Internet / C2)       |
|                                    |           |                                       |           |                             |
|  [Sliver Implant: implant_ubuntu]  | <=======> |  [ens36: .60.1] === [ens33: .240.129] | <=======> |  [Sliver Server / Pinggy]   |
+------------------------------------+  Traffic  +-------------------+-------------------+  Traffic  +-----------------------------+
                                                                     |
                                                           [NFQUEUE num 0]
                                                                     |
                                                        [Suricata IPS Engine]
                                                        (Kiểm tra Rule & DROP)
```

### 1.2. Nền tảng Clear NDR Community Edition
Hệ thống phòng thủ sử dụng bộ giải pháp **Clear NDR Community** (phát triển bởi Stamus Networks trên nền tảng SELKS/Suricata), toàn bộ chạy dưới dạng cụm Docker Compose đặt tại `/root/config/`:
* **Suricata 8.0** (`config-suricata-ZzsclHp2yQONZzoy`): Engine cốt lõi làm nhiệm vụ phân tích gói tin mạng (Deep Packet Inspection), phát hiện và hủy gói tin vi phạm. Chạy với `network_mode: host` và quyền `NET_ADMIN`.
* **Scirius Community 1.1.2** (`config-scirius-ZzsclHp2yQONZzoy`): Web UI Django quản lý tập trung toàn bộ Source, Ruleset, Sensor Suricata, tài khoản và chính sách.
* **EveBox 0.21.1** (`config-evebox-ZzsclHp2yQONZzoy`): Giao diện trực quan hóa chuyên sâu để săn tìm mối đe dọa (Threat Hunting), xem trực tiếp các sự kiện Flow, DNS, TLS và Alert.
* **OpenSearch 3.3.1 & Dashboards**: Lưu trữ dữ liệu log sự kiện và bảng biểu thống kê.
* **Celery & RabbitMQ**: Điều phối các tác vụ ngầm (Build ruleset, test cú pháp, push xuống sensor).

### 1.3. Các đường dẫn truy cập (Access Endpoints)
* **Web Dashboard**: `https://footage-temple-meets-fighters.trycloudflare.com`
  * Username: `clearndr`
  * Password: `clearndr`
* **SSH Quản trị từ xa**:
  ```bash
  ssh -o "ProxyCommand=cloudflared access ssh --hostname %h" root@bite-maria-constraint-detroit.trycloudflare.com
  # Password: 12345678
  ```

---

## 2. CƠ CHẾ QUẢN LÝ RULE TRÊN GIAO DIỆN SCIRIUS / CLEAR NDR

Để hiểu cách quản trị Clear NDR, cần nắm rõ cấu trúc 3 tầng:

$$\text{Source (Nguồn cấp)} \longrightarrow \text{Ruleset (Bộ chính sách)} \longrightarrow \text{Suricata Sensor (Bộ máy thực thi)}$$

1. **Source (`/rules/source/`)**:
   * Nơi chứa các tệp rule thô (`.rules`).
   * Hệ thống hiện có: `c2mal` (nguồn chứa các signature săn Sliver), `ETOpen`, `Malware`, `Web-Attack-Detect`...
2. **Ruleset (`/rules/ruleset/`)**:
   * Nơi gom các danh mục (Categories) từ các Source lại với nhau thành một chính sách áp dụng.
   * Ruleset `C2` (ID 4) hiện tại chứa Category `c2mal Sigs` (gồm 11 rule hoạt động).
   * **Action Transformation**: Tại đây ta quy định hành động đối với các rule trong Category:
     * `Default`: Giữ nguyên hành động gốc trong file rule (thường là `alert`).
     * `Drop`: Tự động chuyển đổi tất cả rule từ `alert` sang `drop` (dùng khi chạy IPS để chặn thực tế).
3. **Suricata Sensor (`/suricata/`)**:
   * Đại diện cho tiến trình Suricata đang chạy trên máy chủ.
   * **Quy tắc vàng của Scirius**: Khi bạn sửa rule hoặc đổi ruleset trong trang Edit, **Suricata chưa áp dụng ngay**. Bạn **bắt buộc** phải vào mục **Ruleset actions** (`/suricata/update/`), tích chọn cả hai ô:
     * `[x] Push` (biên dịch file `scirius.rules` đẩy vào thư mục Suricata)
     * `[x] Reload` (gửi tín hiệu socket yêu cầu Suricata nạp lại rule)
     * Bấm **Apply**.

---

## 3. CHI TIẾT BỘ RULE BẮT SLIVER C2 (`c2mal Sigs`)

Toàn bộ các rule săn bắt Sliver C2 hiện tại nằm trong Source `c2mal` $\rightarrow$ Category `c2mal Sigs` (gồm các SID từ `9000100` đến `9000111`):

| SID | Tên Signature (Msg) | Giao thức / Port | Mục tiêu & Cơ chế phát hiện |
| :--- | :--- | :--- | :--- |
| **9000100** | `HUNT Sliver C2 - Suspicious JA3 Client Fingerprint` | TLS (any) | Khớp mã hash JA3: `72a589da586844d7f0818ce684948eea`. Bắt các client TLS dùng cấu hình mật mã đặc trưng của Sliver Go client. |
| **9000101** | `HUNT Sliver - TLS Client Certificate Authentication (mTLS)` | TLS (any) | Kiểm tra `tls.cert_subject` có trường `CN=`. Bắt quá trình trao đổi chứng chỉ client trong chế độ mTLS của Sliver. |
| **9000102** | `HUNT Sliver - Self-Signed Certificate (Chain Length 1)` | TLS (any) | Kiểm tra `tls.cert_chain_len: 1`. Bắt chứng chỉ tự ký (Self-signed) không có CA trung gian do Sliver server tự sinh. |
| **9000103** | `HUNT Sliver - Age and Minisign Key Material in TCP Stream` | TCP (any) | Quét payload TCP tìm khóa mã hóa `age1` và header `untrusted comment:`. Bắt giao thức mã hóa WireGuard/Age của Sliver. |
| **9000104** | `HUNT Sliver - Beaconing Pattern (Fixed Interval)` | TCP (any) | Ngưỡng `threshold: count 5, seconds 300`. Bắt tín hiệu heartbeat/beacon gửi định kỳ cách nhau khoảng thời gian cố định (đếm đủ 5 lần trong 5 phút). |
| **9000105** | `HUNT Sliver - Repeated Connections to External Host` | TCP (any) | Ngưỡng `threshold: count 10, seconds 300`. Bắt hành vi máy victim liên tục tạo kết nối lặp lại ra một IP ngoại vi trong 5 phút. |
| **9000106** | `HUNT Sliver - Go HTTP Client User-Agent` | HTTP (any) | Bắt header `User-Agent: Go-http-client`. *(Lưu ý: Chỉ bắt được khi chạy HTTP không mã hóa).* |
| **9000107** | `HUNT Sliver - Suspicious HTTP C2 Polling URI` | HTTP (any) | Bắt pattern URI dạng regex `/\/([a-z0-9]{8,16})\.(woff\|js\|php)$/i` trong request POST checkin của Sliver. |
| **9000108** | `HUNT Sliver - Default Sliver C2 Port 31337` | TCP (31337) | Bắt traffic kết nối tới port C2 mặc định của Sliver (`31337`). |
| **9000109** | `HUNT Sliver - Common Sliver C2 Port 8888` | TCP (8888) | Bắt traffic kết nối tới port mTLS phổ biến (`8888`). |
| **9000110** | `HUNT Pinggy Tunnel - Suspicious SNI` | TLS (any) | Quét `tls.sni` chứa chuỗi `pinggy`. **Cực kỳ quan trọng**: Bắt chính xác luồng tunnel `*.run.pinggy-free.link` ngay tại gói TLS Client Hello đầu tiên! |
| **9000111** | `HUNT Pinggy Tunnel - Suspicious Host Header` | HTTP | *(Đã bị Disable)*: Do cú pháp sticky buffer `http.host` gây lỗi phân tích cú pháp với phiên bản engine hiện tại. |

---

## 4. CÁC NGUYÊN NHÂN LỖI TRƯỚC ĐÂY (VÌ SAO KHÔNG LOG & KHÔNG DROP ĐƯỢC)

Trước khi được sửa, bài lab gặp phải 3 rào cản kỹ thuật cốt lõi:

### Lỗi 1: Cú pháp Rule bị sai làm vô hiệu hóa toàn bộ Ruleset
* **Hiện tượng**: Trên giao diện, Ruleset `C2` báo trạng thái đỏ `All rules operational: False`.
* **Nguyên nhân**: Ban đầu rule `1000208` dùng từ khóa `dns.rrtype` (không tồn tại trong Suricata), sau đó rule `9000111` dùng `http.host; content:...` dạng sticky buffer bị parser Suricata từ chối.
* **Hậu quả**: Khi 1 ruleset có dù chỉ 1 rule sai cú pháp, Suricata từ chối nạp toàn bộ bộ rule, khiến ruleset bị coi là hỏng và không thể build/push.
* **Đã khắc phục**: Đã disable các rule lỗi cú pháp, đưa ruleset C2 về trạng thái chuẩn: `All rules operational: True (11 rules)`.

### Lỗi 2: Suricata đang chạy ở chế độ IDS (Passive Sniffer), không phải IPS
* **Hiện tượng**: Khi rule match và hiển thị `Action: blocked` trên Evebox, terminal Sliver bên ngoài vẫn điều khiển máy victim hoàn toàn bình thường.
* **Nguyên nhân**:
  * Kiểm tra qua lệnh `suricatasc -c capture-mode`: trả về `AF_PACKET_DEV`.
  * Metadata của gói tin ghi nhận `"pkt_src": "wire/pcap"`.
  * Đây là chế độ **Passive Sniffer (nghe lén bản sao gói tin trên switch/card mạng)**. Chữ `blocked` trên log chỉ mang tính chất mô phỏng giả định (*"nếu ở chế độ inline thì gói này sẽ bị drop"*). Gói tin vật lý thực tế giữa victim và attacker không đi qua Suricata mà đi thẳng qua routing stack của Linux, nên kết nối C2 không hề bị ảnh hưởng.

### Lỗi 3: Linux Kernel Forward độc lập, "vượt mặt" Suricata
* Máy chủ `Nhom1` có `ip_forward = 1` và bảng `iptables` FORWARD đang đặt:
  ```text
  chain FORWARD {
      iifname "ens36" oifname "ens33" ip saddr 192.168.60.0/24 accept
      iifname "ens33" oifname "ens36" ip daddr 192.168.60.0/24 ct state related,established accept
  }
  ```
  $\rightarrow$ Linux Kernel tự động `accept` và chuyển tiếp 100% traffic giữa victim và internet ở tầng Layer 3. Suricata chỉ đứng ngoài quan sát như khán giả chứ không có quyền can thiệp vào dòng chảy gói tin.

---

## 5. GIẢI PHÁP ĐÃ TRIỂN KHAI: KÍCH HOẠT CHẾ ĐỘ IPS BẰNG NFQUEUE

Chúng ta đã chuyển đổi thành công mô hình hoạt động từ **Passive IDS** sang **Active IPS Inline (via Netfilter Queue)**:

### 5.1. Cơ chế hoạt động của NFQUEUE:
1. Khi máy victim (`ens36`) gửi gói tin đi ra ngoài qua gateway (`ens33`), thay vì để Kernel tự chuyển tiếp (`accept`), rule iptables sẽ bắt giữ gói tin và chuyển vào hàng đợi đặc biệt: **`NFQUEUE num 0`**.
2. Container Suricata (chạy tham số `-q 0`) liên kết trực tiếp với queue này. Suricata phân tích gói tin dựa trên bộ rule C2:
   * **Nếu gói tin bình thường (hợp lệ)**: Suricata gửi tín hiệu `NF_ACCEPT` $\rightarrow$ Kernel cho phép gói tin đi tiếp ra internet.
   * **Nếu gói tin vi phạm rule C2 (ví dụ SNI chứa `pinggy`)**: Suricata gửi tín hiệu `NF_DROP` $\rightarrow$ Kernel Linux **tiêu hủy (drop) gói tin ngay lập tức**! Gói tin không bao giờ rời khỏi card mạng.

### 5.2. Các file và lệnh đã thay đổi trên máy chủ:
* **File cấu hình Compose** (`/root/config/suricata/suricata.compose.yaml`):
  Đổi từ `--af-packet` sang `-q 0`:
  ```yaml
  environment:
      - SURICATA_OPTIONS= -q 0 -vvv --set sensor-name=suricata
  ```
* **Quy tắc iptables FORWARD trên máy chủ**:
  ```bash
  iptables -I FORWARD 1 -i ens36 -o ens33 -j NFQUEUE --queue-num 0 --queue-bypass
  iptables -I FORWARD 2 -i ens33 -o ens36 -m conntrack --ctstate RELATED,ESTABLISHED -j NFQUEUE --queue-num 0 --queue-bypass
  ```
  *(Cờ `--queue-bypass` đảm bảo nếu Suricata đang restart hoặc reload thì mạng của victim vẫn thông suốt, không bị đứt mạng đột ngột).*

### 5.3. Trạng thái xác nhận thành công hiện tại:
* Chế độ capture của Suricata:
  ```json
  {"message": "NFQ", "return": "OK"}
  ```
* Số lượng rule đang hoạt động:
  ```json
  {"id": 0, "rules_loaded": 11, "rules_failed": 0, "rules_skipped": 0}
  ```
* Hàng đợi iptables NFQUEUE đang hoạt động và bắt trực tiếp lưu lượng mạng thực tế.

---

## 6. HƯỚNG DẪN DEMO CHO CẢ NHÓM (KỊCH BẢN KIỂM THỬ)

### Kịch bản 1: Demo Tính Năng Chặn Đứng Kết Nối (IPS Drop)
1. **Chuẩn bị**:
   * Kiểm tra Ruleset C2 trên Web (`/rules/ruleset/4/`): đảm bảo Category `c2mal Sigs` đang để **`Action: Drop`**.
   * Đảm bảo Suricata đã được Push & Reload (`Ruleset: C2`).
2. **Thực hiện tấn công**:
   * Trên máy victim (`192.168.60.20`), chạy file implant: `./implant_ubuntu`.
3. **Hiện tượng quan sát**:
   * **Bên Terminal Sliver Server**: Không nhận được bất kỳ tín hiệu check-in nào, **hoàn toàn KHÔNG hiện session mới** (gói khởi tạo TLS/Pinggy bị drop ngay tại gateway).
   * **Bên Web Clear NDR / Evebox (`/evebox/`)**: Xuất hiện alert `HUNT Pinggy Tunnel - Suspicious SNI` (SID 9000110) với trường **`Action: blocked`**.

---

### Kịch bản 2: Demo Tính Năng Cảnh Báo Thụ Động (Chỉ Alert, Không Chặn)
Nếu giáo viên hoặc bài thuyết trình yêu cầu demo xem khi bị tấn công thì log cảnh báo như thế nào mà không ngắt session:
1. Vào **Rulesets** $\rightarrow$ chọn **C2** $\rightarrow$ chọn category **`c2mal Sigs`**.
2. Nhấn vào mục đổi Action Transformation $\rightarrow$ chọn **`Default`** (hoặc `Alert`).
3. Vào menu **Suricata** $\rightarrow$ **Ruleset actions** (`/suricata/update/`) $\rightarrow$ tích **Push** + **Reload** $\rightarrow$ bấm **Apply**.
4. **Hiện tượng**:
   * Chạy `./implant_ubuntu` trên victim $\rightarrow$ Session trên Sliver Server **mở thành công**.
   * Terminal gõ lệnh bình thường.
   * Trên Evebox xuất hiện liên tục các alert `HUNT Sliver - Beaconing Pattern` (SID 9000104) hoặc `Repeated Connections` (SID 9000105) với trạng thái `Action: allowed`.

---

## 7. CÁC LỆNH KIỂM TRA NHANH KHI CẦN DEBUG

Mở SSH vào máy chủ NDR và sử dụng các lệnh sau:

* **Kiểm tra Suricata có đang ở chế độ IPS (NFQ) hay không**:
  ```bash
  docker exec config-suricata-ZzsclHp2yQONZzoy suricatasc -c capture-mode
  # Kết quả chuẩn: {"message":"NFQ","return":"OK"}
  ```
* **Kiểm tra số lượng rule C2 đã nạp vào RAM của Suricata**:
  ```bash
  docker exec config-suricata-ZzsclHp2yQONZzoy suricatasc -c ruleset-stats
  # Kết quả chuẩn: {"rules_loaded":11,"rules_failed":0,"rules_skipped":0}
  ```
* **Xem gói tin có đang chạy qua hàng đợi NFQUEUE hay không**:
  ```bash
  iptables -L FORWARD -n -v --line-numbers
  # Nhìn cột pkts và bytes của dòng 1 và 2 xem số có tăng lên không
  ```
* **Xem log Suricata trực tiếp**:
  ```bash
  tail -f /root/config/containers-data/suricata/logs/suricata.log
  ```
* **Khởi động lại Suricata an toàn khi cần thiết**:
  ```bash
  cd /root/config
  docker compose -f compose.yml -p clearndr up -d --no-deps suricata
  ```
