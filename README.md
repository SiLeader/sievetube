# Sieve Tube 開発仕様書 (MVP)

## 1. システム概要
Sieve Tubeは、NATやファイアウォールの内側にある非公開サーバー（ローカル環境など）のアプリケーションを、安全にインターネット上へ公開するためのリバーストンネリング・システムです。Cloudflare Tunnelのような使用感を、セルフホスト可能なOSSとして実現することを目的とします。

### 1.1 設計思想
* **明示的な管理:** 自動化の対象（証明書・DNSレコード・転送経路）は管理者が明示したものだけに限る。未知のSNIやConnectorの接続を契機に証明書を発行したり、管理外のDNSレコードを書き換えたりしない。
* **高パフォーマンス:** RustとQUICを採用し、低遅延かつ高スループットなトンネルを実現する。
* **Edge間転送:** 公開サーバー（Edge）は、自身にConnectorが接続していないホスト名への通信を、1ホップだけ他のEdgeへ転送する。Connectorが全Edgeへ接続する従来構成も互換モードとして選択できる。
* **Unix哲学:** Sieve Tubeは「トンネルの確立とトラフィックの転送」に特化し、DDoS防御やCDNは外部のインフラに委譲する。DNSの権威サーバー運用も外部のままとし、プロバイダーAPIによるレコード管理だけを行う。

---

## 2. 技術スタック
| コンポーネント | 採用技術 | 役割・選定理由 |
| :--- | :--- | :--- |
| **開発言語** | Rust | 高いパフォーマンスとメモリ安全性。非同期ランタイムには `tokio` を使用。 |
| **トンネル通信** | QUIC (`quinn`) | TCPのHead-of-Line Blockingを回避し、ストリーム多重化とデータグラム（UDP用）をサポートするため。 |
| **TLSバックエンド** | `rustls` | QUICのバックエンド、および公開サーバーでのTLSターミネーション用。 |
| **状態管理** | Valkey / Redis | ホスト名の所有権、リース、Edge間の経路広告と生存情報を扱うコントロールプレーン（※データプレーンには不使用）。 |
| **証明書自動化** | `instant-acme` | ACMEによる証明書の発行・更新（HTTP-01 / DNS-01）。 |
| **DNS管理** | Cloudflare API / `aws-sdk-route53` | 管理者が指定したレコードのみを維持。 |
| **プラグイン** | `wasmtime` | リクエストポリシーのWebAssemblyプラグイン（メモリ・燃料・時間制限付き）。 |
| **設定フォーマット** | TOML (`serde`) | 人間にとって読み書きしやすく、Rustの構造体へのマッピングが容易なため。 |
| **可観測性** | `tracing`, OpenTelemetry | 分散トレース、構造化ログ出力、Prometheusメトリクスの公開。 |

---

## 3. システムアーキテクチャ

システムは大きく分けて「公開サーバー（Edge）」「非公開サーバー（Connector）」「コントロールプレーン（Valkey）」の3要素で構成されます。

### 3.1 ネットワークトポロジ

標準構成は `routing.mode = "mesh"`（`config_version = 2` の既定値）です。

* 非公開サーバー（Connector）は、冗長性のために選んだ **一部の公開サーバー（Edge）へQUICコネクションを確立** します。
* リクエストが到達したEdgeは、自身にConnectorが接続していればそのまま転送し、接続していなければ経路情報をもとに該当するEdgeへ **1ホップだけ** 転送します（入口Edge → Connector接続先Edge → Connector）。受信側のEdgeは自身のConnectorへのみ中継し、再転送はしません。
* Edge間は専用CAの証明書と専用ALPN（`sievetube-mesh/1`）でmTLS相互認証し、受信側Edgeは「そのホスト名が要求元の名乗るテナントのものか」を再検証します。
* 経路情報（ホスト名・プロトコル・テナント・Edge・接続世代）はValkeyへTTL付きで広告されます。期限切れの経路は使用せず、Valkeyが停止している間も既存のローカル転送は継続します。

互換構成 `routing.mode = "direct"` ではEdge間転送を行いません。公開したい全てのEdgeへConnectorを接続する必要があります。単一Edge構成もこのモードを使います。

### 3.2 コンポーネントの責務
#### ① 公開サーバー (Edge)
* インターネットからのリクエスト（HTTP, HTTPS, TCP, UDP）を受信する。
* HTTP/HTTPSはリクエスト単位で処理し、ホスト名の正規化・経路・ポリシーを評価してからConnectorへ転送する（HTTP/1.1・HTTP/2、WebSocket Upgradeに対応）。
* TLSをターミネーションする。証明書はBYOC（Bring Your Own Certificate）に加え、ACME（HTTP-01 / DNS-01）による自動発行・更新に対応する。
* Rate Limiting・IPブロック・Wasmプラグインによるリクエストポリシーを適用する。
* 管理者が明示したDNSレコードをプロバイダーAPI（Cloudflare / Route 53）経由で維持する。
* ValkeyにConnectorの接続状態とホスト名の所有権、Edge間の経路情報を登録・更新する。
* 他のEdgeからの転送要求を受け付け、自身に接続しているConnectorへのみ中継する。

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

## 7. 拡張機能

MVP以降、[plan/](plan/)の計画に沿って以下を実装しています。設定例は[config/edge.example.toml](config/edge.example.toml)、有効化と運用の手順は[docs/operations.md](docs/operations.md)を参照してください。

* **ACMEによる証明書の自動発行・更新** — HTTP-01を基本とし、ワイルドカードにはDNS-01を使用。複数Edge構成ではリースで発行担当を1台に絞り、HTTP-01の応答を全Edgeへ配布してから検証を要求する。
* **Rate Limiting・IPブロック・プラグイン** — Edgeごとのローカルな上限。監視モードから段階導入でき、Wasmプラグインは許可／拒否のみを返す。
* **DNSレコードの自動登録・更新** — Cloudflare・Route 53。管理対象として明示したレコードだけを扱い、外部で変更されていれば競合として停止する。
* **公開サーバー間のトラフィック内部転送メッシュ** — 1ホップの転送。標準構成はmesh、従来構成はdirectとして選択可能。

### 7.1 現在のスコープ外
* クラスタ全体で厳密な流量制限（現在の制限は各Edgeごとで、Edgeを増やすと許容量も増える）
* 2ホップ以上の経路探索による多段メッシュ
* テナントが任意のWasmプラグインをアップロードするAPI
* Alias・加重ルーティングなどプロバイダー固有のDNS設定の取り込み
