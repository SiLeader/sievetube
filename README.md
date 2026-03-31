# Sieve Tube 開発仕様書 (MVP)

## 1. システム概要
Sieve Tubeは、NATやファイアウォールの内側にある非公開サーバー（ローカル環境など）のアプリケーションを、安全にインターネット上へ公開するためのリバーストンネリング・システムです。Cloudflare Tunnelのような使用感を、セルフホスト可能なOSSとして実現することを目的とします。

### 1.1 設計思想
* **シンプルさと堅牢性:** 内部トラフィックの転送（エッジ間ルーティング）を行わず、アーキテクチャをシンプルに保つ。
* **高パフォーマンス:** RustとQUICを採用し、低遅延かつ高スループットなトンネルを実現する。
* **Unix哲学:** Sieve Tubeは「トンネルの確立とトラフィックの転送」に特化し、DNSの解決やDDoS防御は外部のインフラ（CDNやLB）に委譲する。

---

## 2. 技術スタック
| コンポーネント | 採用技術 | 役割・選定理由 |
| :--- | :--- | :--- |
| **開発言語** | Rust | 高いパフォーマンスとメモリ安全性。非同期ランタイムには `tokio` を使用。 |
| **トンネル通信** | QUIC (`quinn`) | TCPのHead-of-Line Blockingを回避し、ストリーム多重化とデータグラム（UDP用）をサポートするため。 |
| **TLSバックエンド** | `rustls` | QUICのバックエンド、および公開サーバーでのTLSターミネーション用。 |
| **状態管理** | Valkey / Redis | テナント管理、エンドポイントの重複チェック等のコントロールプレーンとして利用（※トラフィック転送には不使用）。 |
| **設定フォーマット** | TOML (`serde`) | 人間にとって読み書きしやすく、Rustの構造体へのマッピングが容易なため。 |
| **可観測性** | `tracing`, OpenTelemetry | 分散トレース、構造化ログ出力、Prometheusメトリクスの公開。 |

---

## 3. システムアーキテクチャ

システムは大きく分けて「公開サーバー（Edge）」「非公開サーバー（Connector）」「コントロールプレーン（Valkey）」の3要素で構成されます。

### 3.1 ネットワークトポロジ（アプローチA: フルメッシュ接続）
* 非公開サーバー（Connector）は、設定ファイルに記述された **全ての公開サーバー（Edge）に対して同時にQUICコネクションを確立** します。
* ユーザーからのリクエストが到達した公開サーバーは、自身に張られているコネクションを直接使って非公開サーバーへトラフィックを流します。公開サーバー間でのトラフィック転送は行いません。

### 3.2 コンポーネントの責務
#### ① 公開サーバー (Edge)
* インターネットからのリクエスト（HTTP, HTTPS, TCP, UDP）を受信する。
* BYOC（Bring Your Own Certificate）方式でTLSをターミネーションする。
* リクエストのホスト名（SNIやHostヘッダ）またはポート番号をもとに、接続済みのConnectorのQUICストリーム/データグラムへトラフィックを中継する。
* ValkeyにConnectorの接続状態を登録・更新する。

#### ② 非公開サーバー (Connector)
* 起動時に設定ファイル（`config.toml`）を読み込む。
* 公開サーバー群に対してQUICコネクションを張り、JWTによる認証を行う。
* 切断時は独立した非同期タスクで再接続ループ（バックオフリトライ）を実行する。
* 公開サーバーから流れてきたトラフィックを、設定されたローカルのアプリケーション（ターゲット）へ中継する。

#### ③ コントロールプレーン (Valkey)
* トラフィックのデータプレーンには関与しない。
* 「どのドメイン（エンドポイント）がどのJWTによって所有されているか」の権限管理。
* 「現在どのConnectorがどのEdgeに接続しているか」のステータス可視化用途。

---

## 4. セキュリティと認証

### 4.1 コネクション認証 (JWT)
* ConnectorはEdgeへのQUICコネクション確立時、設定ファイルに記載されたJWTを送信します。
* EdgeはJWTの署名検証のみで接続を許可（ステートレス認証）し、レイテンシを最小化します。

### 4.2 TLSターミネーション (BYOC)
* MVPではユーザーが手動で用意した証明書を利用します。
* Edge起動時に証明書（`.pem`等）をロードし、`rustls`の `ResolvesServerCert` トレイトを用いて、リクエストのSNI情報から動的に正しい証明書を選択して応答します。

---

## 5. 設定ファイル仕様 (Connector側)
`config.toml` に認証情報、接続先、ルーティングルールを定義します。上から順に評価され、最初にマッチしたルールが適用されます。

```toml
# Sieve Tube Connector Configuration

[auth]
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." # JWTトークン

[network]
# 接続先の公開サーバー群
public_servers = [
    "pub1.sieve-tube.example.com:443",
    "pub2.sieve-tube.example.com:443"
]

# トラフィック転送ルール (Ingress)
[[ingress]]
hostname = "web.example.com"
protocol = "http"
target = "127.0.0.1:8080"

[[ingress]]
hostname = "ssh.example.com"
protocol = "tcp"
target = "127.0.0.1:22"

[[ingress]]
hostname = "game.example.com"
protocol = "udp"
target = "127.0.0.1:19132"

[[ingress]]
# キャッチオール（デフォルトルーター）
target = "http_status:404"
```

---

## 6. 可観測性 (Observability)
運用時のトラブルシューティングのため、以下の機能を実装します。

### 6.1 構造化ログ (JSON)
`tracing` および `tracing-subscriber` を使用し、標準出力にJSON形式でログを出力します。以下のフィールドを必須コンテキストとして含めます。
* `trace_id` / `span_id`
* `tunnel_id` (テナントを識別)
* `target_hostname`
* `client_ip`

### 6.2 メトリクス (Prometheus)
`opentelemetry-prometheus` を使用し、Edge/Connector共に `/metrics` エンドポイントを公開します。
* **主要メトリクス:**
  * `sievetube_bytes_transferred_total` (カウンタ)
  * `sievetube_active_quic_connections` (ゲージ)
  * `sievetube_tunnel_latency_seconds` (ヒストグラム)

---

## 7. MVPスコープ外（今後の拡張要素）
以下の機能は今回のMVP実装から除外します。これらはユーザーのインフラストラクチャ（WAF、CDN、LBなど）で対応、または将来のアップデートで対応するものとします。
* Let's Encrypt等を用いたACMEによる証明書の自動更新機能
* リクエストのRate LimitingやIPブロック機能（WasmやTowerミドルウェアによる将来のプラグイン化を想定）
* DNSレコードの自動登録・更新
* 公開サーバー間でのトラフィック内部転送メッシュ網の構築
