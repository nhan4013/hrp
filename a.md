# HTTP Record & Replay Proxy — Kế hoạch dự án

> Side project Go #1 — mục tiêu: học Go qua một tool thật sự dùng được, không phải toy project.

---

## 1. Bối cảnh & vấn đề

Trong môi trường core banking / fintech, service của mình gọi ra rất nhiều bên thứ ba: payment gateway, KYC provider, credit bureau, SMS/OTP, tỷ giá. Khi dev local hoặc chạy CI, mấy dependency này gây ra:

| Vấn đề | Hệ quả |
|---|---|
| Sandbox của vendor chập chờn | Test đỏ nhưng code không sai → mất niềm tin vào CI |
| Rate limit trên sandbox | Không chạy song song được, CI chậm |
| Data sandbox bị reset / thay đổi | Assertion hôm nay pass mai fail |
| Không tái tạo được edge case | Không test được timeout, 5xx, response méo |
| Mock viết tay trong code | Mock lệch với API thật, phát hiện khi lên prod |

**Cách tiếp cận hiện tại và điểm yếu của nó:**

- Mock ở tầng code (monkeypatch, DI fake client) → nhanh nhưng không test được tầng HTTP client thật (retry, timeout, serialization, header).
- WireMock / MockServer → mạnh nhưng nặng (JVM), phải viết stub tay, không tự sinh từ traffic thật.
- VCR-style library (`vcrpy`, `betamax`) → đúng ý tưởng nhưng gắn chặt vào một ngôn ngữ/HTTP client cụ thể.

**Chỗ trống mình lấp:** một binary độc lập, ngôn ngữ-agnostic, đứng ở tầng network. Service nào cũng dùng được (Python, Go, Node), CI dùng được, không cần sửa code ứng dụng.

---

## 2. Tool làm gì

```
┌─────────────┐         ┌──────────────────┐         ┌──────────────┐
│  App của    │  HTTP   │   hrp (proxy)    │  HTTP   │  API bên     │
│  mình       │────────>│                  │────────>│  thứ ba      │
│  (Python/Go)│         │  record | replay │  (chỉ   │              │
└─────────────┘         └────────┬─────────┘  record)└──────────────┘
                                 │
                                 v
                        ┌──────────────────┐
                        │  cassettes/*.yaml│
                        │  (git-committed) │
                        └──────────────────┘
```

### Ba chế độ

| Mode | Hành vi |
|---|---|
| `record` | Forward request thật ra ngoài, ghi lại cặp request/response vào cassette |
| `replay` | Không ra internet. Match request với interaction đã ghi, trả response từ cassette. Không match được → trả 599 kèm diff giải thích tại sao |
| `auto` | Match được thì replay, không match được thì gọi thật rồi ghi thêm vào cassette (chế độ dùng hằng ngày khi dev) |

### Tính năng cốt lõi

1. **Record/Replay** — ghi và phát lại HTTP interaction
2. **Matching engine** — cấu hình được: match theo method + path, có/không query, có/không body, ignore header nào
3. **Redaction** — che field nhạy cảm (token, số thẻ, CCCD, số điện thoại) trước khi ghi xuống disk. Bắt buộc, vì cassette sẽ commit vào git
4. **Fault injection** — ép trả 500, ép timeout, thêm latency giả, để test retry/circuit breaker của app
5. **Cassette là plain YAML** — đọc được bằng mắt, sửa tay được, diff được trong PR

---

## 3. Tech stack

| Thành phần | Lựa chọn | Lý do |
|---|---|---|
| Ngôn ngữ | Go 1.22+ | Mục tiêu học; ship 1 binary |
| HTTP proxy | `net/http` + `net/http/httputil` | Stdlib đủ mạnh, không cần framework |
| CLI | `spf13/cobra` | Chuẩn de-facto, sinh sẵn help/completion |
| Config | `spf13/viper` hoặc chỉ `gopkg.in/yaml.v3` | Bắt đầu bằng yaml.v3 cho gọn |
| Serialization cassette | `gopkg.in/yaml.v3` | Human-readable, diff đẹp |
| MITM TLS | `crypto/tls`, `crypto/x509` | Tự sinh CA + leaf cert |
| Logging | `log/slog` (stdlib 1.21+) | Structured log, không cần lib ngoài |
| Test | `net/http/httptest` + stdlib `testing` | Không cần testify, tập làm quen table-driven test |
| Build/release | `goreleaser` | Cross-compile ra binary macOS/Linux |

**Nguyên tắc:** dependency càng ít càng tốt. Mục tiêu là hiểu stdlib Go, không phải học framework.

---

## 4. Kiến trúc

### 4.1 Hai kiểu proxy — chọn đường đi

| | Reverse proxy | Forward proxy + MITM |
|---|---|---|
| Cấu hình phía app | Đổi base URL sang `localhost:8080` | Set `HTTP_PROXY` / `HTTPS_PROXY` env |
| HTTPS | Không cần xử lý (app gọi http tới proxy) | Cần MITM: tự sinh cert, app phải trust CA |
| Độ khó | Thấp | Cao hơn (CONNECT, TLS handshake) |

**Quyết định:** làm reverse proxy trước (Phase 1–3), MITM forward proxy để Phase 5. Như vậy có thứ chạy được sớm, và phần TLS thành một milestone học tập riêng chứ không chặn tiến độ.

### 4.2 Luồng xử lý một request

```
Request đến
    │
    ├─> [1] Normalize: đọc body ra []byte, giữ lại để re-inject
    │        (http.Request.Body là io.ReadCloser — đọc 1 lần là hết)
    │
    ├─> [2] Redact: apply rule lên header + body
    │
    ├─> [3] Fingerprint: sinh key match từ request đã normalize
    │
    ├─> [4] Cassette lookup
    │        ├─ HIT  ──> [5a] Fault injection check ──> trả response từ cassette
    │        └─ MISS ──> tuỳ mode:
    │                    replay  -> trả 599 + diff report
    │                    record  -> [5b] forward thật
    │                    auto    -> [5b] forward thật
    │
    ├─> [5b] Forward qua ReverseProxy ──> nhận response
    │
    ├─> [6] Redact response ──> append vào cassette (in-memory)
    │
    └─> [7] Trả response cho client

Khi shutdown (SIGINT/SIGTERM) hoặc mỗi N giây: flush cassette xuống disk
```

### 4.3 Cấu trúc thư mục

```
hrp/
├── cmd/
│   └── hrp/
│       └── main.go              # entrypoint, gọi cmd.Execute()
├── internal/
│   ├── cli/
│   │   ├── root.go              # cobra root command, global flags
│   │   ├── record.go            # hrp record
│   │   ├── replay.go            # hrp replay
│   │   └── inspect.go           # hrp inspect <cassette>
│   ├── cassette/
│   │   ├── cassette.go          # struct Cassette, Interaction
│   │   ├── store.go             # load/save, thread-safe access
│   │   └── format.go            # (de)serialize yaml
│   ├── matcher/
│   │   ├── matcher.go           # interface Matcher
│   │   ├── rules.go             # MethodMatcher, PathMatcher, BodyMatcher...
│   │   └── diff.go              # giải thích tại sao không match
│   ├── redact/
│   │   ├── redact.go            # apply rule
│   │   └── rules.go             # built-in rule: authorization, card number...
│   ├── proxy/
│   │   ├── server.go            # http.Server, graceful shutdown
│   │   ├── handler.go           # ServeHTTP — luồng ở 4.2
│   │   └── forward.go           # httputil.ReverseProxy wrapper
│   ├── fault/
│   │   └── injector.go          # latency, error rate, timeout
│   └── config/
│       └── config.go            # parse hrp.yaml
├── testdata/
│   └── cassettes/               # fixture cho test
├── examples/
│   ├── python-client/           # demo dùng với requests
│   └── docker-compose.yml       # demo chạy trong CI
├── hrp.yaml                     # config mẫu
├── Makefile
├── .goreleaser.yaml
├── go.mod
└── README.md
```

Ghi chú: đặt hết dưới `internal/` để Go compiler chặn import từ ngoài — đây là thói quen tốt, ép mình thiết kế API rõ ràng nếu sau này muốn tách package ra `pkg/`.

---

## 5. Thiết kế dữ liệu

### 5.1 Cassette format

```yaml
version: 1
name: payment-gateway
recorded_at: 2026-07-30T10:15:00+07:00
upstream: https://sandbox.payment-vendor.com

interactions:
  - id: 01J8K...            # ULID, dùng để replay/inspect từng cái
    request:
      method: POST
      scheme: https           # chỉ có khi ghi qua MITM forward proxy (omitempty)
      host: api.vendor.com    # chỉ có khi ghi qua MITM forward proxy (omitempty)
      path: /v1/charges
      query:
        currency: [VND]
      headers:
        content-type: [application/json]
        authorization: ["<REDACTED>"]
      body: |
        {"amount":1500000,"card":"<REDACTED>"}
      body_hash: sha256:9f2a...
    response:
      status: 201
      headers:
        content-type: [application/json]
      body: |
        {"id":"ch_123","status":"succeeded"}
      duration_ms: 342
    meta:
      hit_count: 0
      recorded_at: 2026-07-30T10:15:02+07:00
```

### 5.2 Struct chính

```go
type Cassette struct {
    Version      int           `yaml:"version"`
    Name         string        `yaml:"name"`
    RecordedAt   time.Time     `yaml:"recorded_at"`
    Upstream     string        `yaml:"upstream"`
    Interactions []Interaction `yaml:"interactions"`
}

type Interaction struct {
    ID       string   `yaml:"id"`
    Request  Request  `yaml:"request"`
    Response Response `yaml:"response"`
    Meta     Meta     `yaml:"meta"`
}

type Request struct {
    Method   string              `yaml:"method"`
    Path     string              `yaml:"path"`
    Query    map[string][]string `yaml:"query,omitempty"`
    Headers  map[string][]string `yaml:"headers,omitempty"`
    Body     string              `yaml:"body,omitempty"`
    BodyHash string              `yaml:"body_hash,omitempty"`
}
```

### 5.3 Config file (`hrp.yaml`)

```yaml
listen: :8080
upstream: https://sandbox.payment-vendor.com
cassette: ./cassettes/payment.yaml
mode: auto                      # record | replay | auto

match:
  on: [method, path, query, body]
  ignore_headers: [user-agent, x-request-id, date, traceparent]
  ignore_query: [timestamp, nonce, _]

redact:
  headers: [authorization, x-api-key, cookie, set-cookie]
  json_fields: [card.number, cvv, password, id_number, phone]
  patterns:
    - name: card_number
      regex: '\b\d{13,19}\b'

fault:
  enabled: false
  latency: 200ms
  error_rate: 0.1
  error_status: 503
```

---

## 6. Những chỗ khó (và là chỗ học được nhiều nhất)

### 6.1 `http.Request.Body` chỉ đọc được một lần

Đây là bẫy đầu tiên mọi người dính. `Body` là `io.ReadCloser` kiểu stream. Đọc để hash xong là proxy không còn gì để forward.

```go
bodyBytes, err := io.ReadAll(r.Body)
if err != nil {
    return fmt.Errorf("read request body: %w", err)
}
r.Body.Close()
// nạp lại để ReverseProxy đọc được
r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
```

Với response cũng vậy, làm trong `ReverseProxy.ModifyResponse`.

Nhớ giới hạn size: `io.LimitReader(r.Body, maxBodySize)` để một request 2GB không giết proxy.

### 6.2 Concurrency trên cassette store

Nhiều request vào song song, cùng đọc (replay) và cùng ghi (record) vào một cassette.

- Đọc nhiều, ghi ít → dùng `sync.RWMutex`, không dùng `sync.Mutex`
- Không flush xuống disk trong mỗi request (I/O chặn) → gom trong memory, flush theo ticker hoặc lúc shutdown
- `hit_count` tăng bằng `atomic.Int64` hoặc nằm trong vùng khoá của mutex — nhất quán một kiểu, đừng trộn

```go
type Store struct {
    mu       sync.RWMutex
    cassette *Cassette
    dirty    bool
}

func (s *Store) Find(req *Request, m matcher.Matcher) (*Interaction, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    // ...
}
```

Chạy test với `go test -race` — đây là công cụ Python không có tương đương, dùng nó ngay từ đầu.

### 6.3 Graceful shutdown

Cassette đang nằm trong memory. Ctrl-C mà mất data thì tool vô dụng.

```go
ctx, stop := signal.NotifyContext(context.Background(),
    os.Interrupt, syscall.SIGTERM)
defer stop()

go func() {
    if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
        slog.Error("server error", "err", err)
    }
}()

<-ctx.Done()
shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

if err := srv.Shutdown(shutdownCtx); err != nil {
    slog.Error("shutdown", "err", err)
}
if err := store.Flush(); err != nil {   // quan trọng: flush SAU khi server dừng
    slog.Error("flush cassette", "err", err)
}
```

### 6.4 Matching phải giải thích được khi fail

Trải nghiệm tệ nhất của loại tool này là "no match found" rồi hết. Phải in ra được:

```
✗ No match for POST /v1/charges

  Closest candidate: interaction 01J8K... (POST /v1/charges)
  Differs on: body

  - recorded: {"amount":1500000,"currency":"VND"}
  + incoming: {"amount":2000000,"currency":"VND"}
                         ^^^^^^^
```

Cách làm: matcher trả về `(score float64, reasons []string)` thay vì chỉ `bool`. Chọn candidate điểm cao nhất để hiển thị diff. Đây là phần khiến tool từ "chạy được" thành "dùng thật".

### 6.5 Redaction phải chạy trước khi ghi, không phải lúc đọc

Cassette sẽ commit vào git. Một lần lộ token là lộ vĩnh viễn trong history. Nguyên tắc:

- Redact ở đường ghi (write path), không bao giờ ở đường đọc
- Default deny cho header nhạy cảm: `authorization`, `cookie`, `x-api-key` redact mặc định, không cần cấu hình
- Có lệnh `hrp scan <cassette>` quét cassette tìm thứ trông giống secret, chạy được trong pre-commit hook

### 6.6 Determinism

Response có `Date`, `X-Request-Id`, timestamp trong body → mỗi lần record ra cassette khác nhau, PR diff đầy nhiễu. Cần:

- Normalize header trước khi ghi (loại bỏ hoặc chuẩn hoá header trong danh sách ignore)
- Sort key khi serialize (yaml.v3 với map thì thứ tự không đảm bảo → dùng slice của struct, không dùng `map[string]interface{}`)

---

## 7. Roadmap

Ước lượng theo nhịp ~8–10h/tuần ngoài giờ. Mỗi phase phải kết thúc bằng một thứ **chạy được**, không để dở dang.

### Phase 0 — Nền (2–3 ngày)

- [ ] `go mod init github.com/nhan4013/hrp`
- [ ] Đi qua Tour of Go, tập trung: slice vs array, interface, `error` wrapping, struct embedding
- [ ] Dựng Makefile: `build`, `test`, `lint`, `run`
- [ ] Cài `golangci-lint`, bật `errcheck`, `govet`, `staticcheck`
- [ ] Viết một HTTP server hello-world với graceful shutdown

**Kiến thức Go:** package layout, `go.mod`, tooling.

### Phase 1 — Reverse proxy trần (1 tuần)

- [ ] `hrp proxy --listen :8080 --upstream https://httpbin.org` forward được request
- [ ] Đọc + re-inject body cả hai chiều
- [ ] Structured logging mọi request: method, path, status, duration
- [ ] Graceful shutdown

**Deliverable:** `curl localhost:8080/get` trả về đúng như gọi httpbin trực tiếp.

**Kiến thức Go:** `net/http`, `httputil.ReverseProxy`, `io.Reader`/`Writer`, `context`, `log/slog`.

### Phase 2 — Record (1 tuần)

- [ ] Define struct `Cassette` / `Interaction`
- [ ] Serialize/deserialize YAML
- [ ] Ghi interaction vào memory store (có `RWMutex`)
- [ ] Flush xuống disk lúc shutdown + theo ticker 5s
- [ ] `hrp record --cassette ./c.yaml`
- [ ] Test với `-race`

**Deliverable:** chạy app Python gọi qua proxy → sinh ra file cassette đọc được bằng mắt.

**Kiến thức Go:** struct tags, `sync.RWMutex`, `time.Ticker`, `os.Signal`, table-driven test.

### Phase 3 — Replay + matching (1–1.5 tuần)

- [ ] Interface `Matcher`, các implement: method, path, query, body-hash
- [ ] Composite matcher đọc từ config
- [ ] `hrp replay` — không ra internet, trả 599 + diff khi miss
- [ ] Mode `auto`
- [ ] Diff report dễ đọc khi không match
- [ ] `hrp inspect <cassette>` — liệt kê interaction dạng bảng

**Deliverable:** rút mạng, app vẫn chạy pass toàn bộ test.

**Kiến thức Go:** interface composition, functional options, `strings.Builder`, error wrapping với `%w`.

### Phase 4 — Redaction + fault injection (1 tuần)

- [ ] Redact header theo danh sách
- [ ] Redact JSON field theo path (`card.number`) — tự viết bằng `encoding/json` với `map[string]any`, hoặc dùng `tidwall/sjson`
- [ ] Redact theo regex
- [ ] `hrp scan` phát hiện secret sót
- [ ] Fault injection: latency, error rate, ép timeout
- [ ] Config file `hrp.yaml` đầy đủ

**Deliverable:** cassette commit vào git an toàn; test được retry logic của app bằng cách bật `error_rate: 0.5`.

**Kiến thức Go:** `regexp`, `encoding/json` với dynamic structure, `math/rand`, `time.Sleep` trong handler.

### Phase 5 — MITM forward proxy (1–1.5 tuần) *(optional nhưng đáng)*

- [x] Xử lý `CONNECT` method
- [x] Sinh CA cert bằng `crypto/x509`
- [x] Sinh leaf cert on-the-fly theo SNI, cache lại
- [x] `hrp ca install` — hướng dẫn trust CA trên máy dev
- [x] Hoạt động với `HTTPS_PROXY=localhost:8080`

**Deliverable:** không cần đổi base URL trong app nữa, chỉ set env var.

**Kiến thức Go:** `crypto/tls`, `crypto/x509`, `crypto/rsa`, hijack connection từ `http.ResponseWriter`.

### Phase 6 — Đóng gói (3–4 ngày)

- [ ] README có GIF demo (`vhs` hoặc `asciinema`)
- [ ] `goreleaser` build binary cho darwin/linux, amd64/arm64
- [ ] Dockerfile multi-stage (final image `scratch`, vài MB)
- [ ] GitHub Actions: test + lint + release on tag
- [ ] Ví dụ tích hợp: docker-compose chạy proxy + service trong CI
- [ ] Viết bài trên blog.lucaspham.org về những gì học được

---

## 8. Chiến lược test

| Loại | Cách làm |
|---|---|
| Unit | Matcher, redact, cassette serialization — table-driven test thuần |
| Integration | `httptest.NewServer` giả upstream, chạy proxy thật, assert cassette sinh ra |
| Race | `go test -race ./...` trong CI, bắn 100 goroutine song song vào proxy |
| Golden file | So cassette sinh ra với file mẫu trong `testdata/`, có flag `-update` để regen |

Ví dụ table-driven test — pattern nên quen ngay từ đầu:

```go
func TestBodyMatcher(t *testing.T) {
    tests := []struct {
        name     string
        recorded string
        incoming string
        want     bool
    }{
        {"identical", `{"a":1}`, `{"a":1}`, true},
        {"key order", `{"a":1,"b":2}`, `{"b":2,"a":1}`, true},
        {"different value", `{"a":1}`, `{"a":2}`, false},
        {"empty both", ``, ``, true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := NewBodyMatcher().Match(tt.recorded, tt.incoming)
            if got != tt.want {
                t.Errorf("got %v, want %v", got, tt.want)
            }
        })
    }
}
```

---

## 9. Tiêu chí "xong"

MVP coi là hoàn thành khi:

1. Một service Python dùng `requests` chạy qua proxy ở mode `record` sinh được cassette
2. Rút mạng, chạy lại ở mode `replay`, service hoạt động y hệt
3. Cassette không chứa secret nào — `hrp scan` sạch
4. `go test -race ./...` xanh
5. `go build` ra một binary duy nhất, copy sang máy khác chạy được không cần cài gì

---

## 10. Ý tưởng mở rộng (sau MVP)

- **Web UI** — trang HTML tĩnh xem cassette, filter, diff giữa hai lần record
- **Sequence matching** — cùng một request lặp lại nhiều lần trả response khác nhau theo thứ tự (mô phỏng state machine: `pending` → `processing` → `succeeded`)
- **OpenAPI validation** — nạp spec của vendor, cảnh báo khi response thật lệch khỏi spec
- **Contract drift detection** — chạy `record` định kỳ trên CI, so với cassette cũ, báo khi vendor đổi API
- **gRPC support** — cùng ý tưởng, khác protocol
- **Library mode** — tách `internal/` ra `pkg/` để import trực tiếp vào Go test

---

## 11. Tài nguyên tham khảo

| Chủ đề | Nguồn |
|---|---|
| Nền tảng Go | Tour of Go, Effective Go |
| Layout project | golang-standards/project-layout (tham khảo, đừng theo mù quáng) |
| HTTP trong Go | Doc của `net/http`, `net/http/httputil` |
| Ý tưởng gốc | vcrpy (Python), go-vcr, WireMock — đọc để lấy ý, đừng copy design |
| MITM proxy | Source của mitmproxy (concept), `elazarl/goproxy` (Go) |
| Concurrency | "Go Concurrency Patterns" — talk của Rob Pike |

---

## 12. Ghi chú về việc chuyển từ Python sang Go

Mấy điểm sẽ thấy khó chịu lúc đầu, ghi ra để đỡ bất ngờ:

- **Không có exception.** Mỗi lần gọi hàm là một `if err != nil`. Đừng chống lại nó — dùng `fmt.Errorf("...: %w", err)` để wrap và `errors.Is`/`errors.As` để kiểm tra.
- **Không có generic collection helper quen thuộc.** Không có list comprehension, `map`/`filter` phải viết vòng lặp. Go 1.18+ có generics nhưng cộng đồng dùng dè dặt.
- **Interface là implicit.** Không `implements`. Một struct thoả interface là tự động thoả. Định nghĩa interface ở nơi *dùng*, không phải nơi *implement* — ngược với thói quen Java/Python.
- **Zero value có ý nghĩa.** `var mu sync.Mutex` là dùng được ngay, không cần khởi tạo. Thiết kế struct sao cho zero value hữu ích.
- **Không có `__init__`.** Dùng constructor function `NewXxx()` trả về `*Xxx`.
- **`go test -race`, `go vet`, `pprof` là built-in.** Dùng ngay từ đầu, đây là thứ Python phải cài thêm hoặc không có.