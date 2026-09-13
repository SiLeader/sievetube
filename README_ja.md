# Sieve Tube

[English](README.md)

Sieve Tubeは、非公開ネットワークで動作するサービスを外部公開するためのセルフホスト型リバーストンネルです。Cloudflare Tunnelと同様に、インターネットから到達できるサーバーで**Edge**を、非公開サービスの近くで**Connector**を動かします。ConnectorからEdgeへ外向きのQUIC接続を確立し、Edgeが受けた公開トラフィックをその接続経由で転送するため、非公開ネットワーク側で受信用ポートを開ける必要はありません。

> [!IMPORTANT]
> Sieve Tubeの現在のバージョンは`0.1.0`です。本番トラフィックに使用する前に、設定とセキュリティモデルを十分に確認してください。

## 仕組み

```text
 インターネット利用者              公開サーバー                    非公開ネットワーク
┌───────────────┐  HTTP(S)/TCP  ┌────────────────┐     QUIC      ┌─────────────────┐
│ ブラウザー/App │ ─────────────▶│ Sieve Tube Edge│◀─────────────│ Sieve Tube      │
└───────────────┘      UDP      └────────────────┘  外向き接続   │ Connector       │
                                               トンネル           └────────┬────────┘
                                                                        │
                                                                        ▼
                                                               ┌─────────────────┐
                                                               │ ローカルサービス │
                                                               │ 127.0.0.1:8080  │
                                                               └─────────────────┘
```

- **Edge（`sievetube-edge`）**は公開HTTP、HTTPS、TCP、UDPトラフィックを受け付け、ConnectorからのQUICセッションを待ち受けます。
- **Connector（`sievetube-connector`）**は1台以上のEdgeへ外向きに接続し、ルールに一致した通信をローカルの転送先へ配信します。
- 署名付きJWTによってテナントを識別し、Connectorが公開できるホスト名を制限します。
- Ingressルールは上から順に評価され、ホスト名とプロトコルが最初に一致したルールが使用されます。

## 主な機能

- 公開側のHTTP/1.1・HTTP/2に対応したHTTP/HTTPSリバースプロキシ
- Raw TCPおよびリクエスト・レスポンス型UDP転送
- 非公開ネットワークから外向きに確立するQUICトンネル
- ホスト名の許可リストを含むHMAC-SHA256 JWT認証
- 持ち込み証明書またはACME（`http-01`、`dns-01`）による公開HTTPS
- mTLSのEdge間メッシュとValkey/Redis連携による複数Edgeルーティング
- CIDRブロック、レート制限、サンドボックス化されたWebAssemblyポリシープラグイン
- CloudflareまたはAmazon Route 53を利用したDNSレコード管理
- JSON構造化ログ、ヘルスチェック、Readiness、Prometheusメトリクス
- Graceful Shutdownと安全な設定・証明書リロード

## 必要なもの

- Cargoを含む新しい安定版Rustツールチェーン
- インターネットから到達できるEdge用ホスト
- ConnectorからEdgeのUDP `4433`（または`server.quic_listen`で指定したポート）への到達性
- クライアントから公開リスナーポートへの到達性（通常はTCP `80`/`443`と、設定したRaw TCP・UDPポート）
- 各公開ホスト名をEdgeへ向けるDNSレコード

単一Edgeをdirectモードで使う場合、Valkey/Redisは任意です。複数Edgeのメッシュや一部の分散協調機能では必要です。

## クイックスタート

以下では、非公開サーバーの`127.0.0.1:8080`で動作するHTTPサービスを`app.example.com`として公開します。

### 1. バイナリをビルドする

```sh
git clone <repository-url> sievetube
cd sievetube
cargo build --release
```

生成されるバイナリは次のとおりです。

- `target/release/sievetube-edge`
- `target/release/sievetube-connector`

### 2. Edgeを設定・起動する

公開サーバーで次を実行します。

```sh
cp config/edge.example.toml edge.toml
```

最低限、`edge.toml`の次の項目を編集します。

- `auth.jwt_secret`を十分に長いランダムな秘密値へ変更します。
- `server.quic_listen`、`server.http_listen`、`server.https_listen`で指定したポートへ到達できることを確認します。
- 単一Edge構成では`routing.mode = "direct"`のままにします。
- `tls.cert_dir`を公開HTTPS証明書の配置先にします。公開証明書を用意する前でもHTTPの疎通確認は可能です。

Edgeを起動します。

```sh
RUST_LOG=info ./target/release/sievetube-edge edge.toml
```

1024未満のポートをbindするには、systemdなどでのCapability付与または昇格した権限が必要な場合があります。本番環境では、必要最小限の権限を与えたサービスマネージャー配下で実行してください。

### 3. Connector用トークンを発行する

`auth.jwt_secret`に設定したものと同じ秘密値を使用します。

```sh
./target/release/sievetube-edge issue-token \
  --secret 'replace-with-your-secret' \
  --sub tenant-1 \
  --hostname app.example.com \
  --exp-hours 8760
```

署名済みJWTが標準出力に表示されます。このトークンを持つ利用者は、有効期限まで許可されたホスト名を登録できるため、秘密情報として扱ってください。

### 4. Connectorを設定・起動する

非公開サーバーで次を実行します。

```sh
cp config/connector.example.toml connector.toml
```

`connector.toml`に発行したトークン、公開Edgeのアドレス、ローカルサービスを設定します。

```toml
[auth]
token = "<generated-jwt>"

[network]
public_servers = ["edge.example.net:4433"]

# 本番環境ではいずれかを設定します。詳細は「セキュリティ」を参照してください。
# edge_ca_cert = "/etc/sievetube/edge-ca.pem"
# edge_cert_sha256 = ["<sha256-certificate-fingerprint>"]

[[ingress]]
hostname = "app.example.com"
protocol = "http"
target = "127.0.0.1:8080"

[[ingress]]
target = "http_status:404"
```

ローカルサービスを動かした状態でConnectorを起動します。

```sh
RUST_LOG=info ./target/release/sievetube-connector connector.toml
```

### 5. Edgeへトラフィックを向ける

`app.example.com`の`A`/`AAAA`レコードを公開Edgeへ向け、HTTPを確認します。

```sh
curl http://app.example.com/
```

`app.example.com`用の証明書を`tls.cert_dir`へ配置するか、ACMEで取得するとHTTPSも利用できます。

## 設定

すべての設定項目とコメントは次のファイルにあります。

- [`config/edge.example.toml`](config/edge.example.toml) — リスナー、認証、公開TLS、ACME、ポリシー、DNS、Valkey、Edgeメッシュ
- [`config/connector.example.toml`](config/connector.example.toml) — Edge接続、証明書検証、Ingressルール、Heartbeatによる状態表示

### Connectorの配置と冗長化

1台のEdgeが保持するConnector接続は、テナント（JWTの`sub`クレーム）ごとに1本です。同じテナントの新しい接続が来ると、そのEdge上の古い接続は置き換えられます。複数のConnectorで同じトークンを共有する場合、それぞれを異なるEdgeへ割り当て、同じEdgeを各Connectorに指定しないでください。directルーティングではトラフィックを処理するすべてのEdgeへConnectorを接続する必要があります。meshルーティングではEdge間で転送できるため、冗長な一部のEdgeへの接続で運用できます。

### Raw TCPとUDP

Raw TCPとUDPにはHTTPの`Host`ヘッダーがないため、Edge設定で公開リスナーごとにホスト名を割り当てます。ConnectorのIngressルールにも、同じホスト名とプロトコルを設定します。

```toml
# edge.toml
[[server.tcp_listen]]
addr = "0.0.0.0:2222"
hostname = "ssh.example.com"

[[server.udp_listen]]
addr = "0.0.0.0:19132"
hostname = "game.example.com"
```

```toml
# connector.toml
[[ingress]]
hostname = "ssh.example.com"
protocol = "tcp"
target = "127.0.0.1:22"

[[ingress]]
hostname = "game.example.com"
protocol = "udp"
target = "127.0.0.1:19132"
```

## セキュリティ

- デプロイ前にサンプルの秘密値をすべて変更し、ConnectorのJWTと秘密鍵へのアクセスを制限してください。
- すべてのConnectorで`network.edge_ca_cert`または`network.edge_cert_sha256`を設定してください。どちらもない場合、EdgeのQUIC証明書は**検証されません**。この状態は初期移行またはテスト用途に限ってください。
- 公開HTTPSには、`tls.cert_dir`へ`<hostname>.crt`と`<hostname>.key`を配置するか、明示的なドメイン許可リストを設定してACMEを有効化します。
- ヘルスチェック・メトリクス用リスナーは、別途保護しない限り非公開インターフェースだけで待ち受けてください。
- トラフィックポリシーは`monitor`モードから開始し、判定を確認してから`enforce`へ切り替えてください。
- 転送されたクライアントアドレスは、`policy.trusted_proxies`に列挙したネットワークからのものだけを信頼してください。

## 運用と監視

Edgeは`server.health_listen`（既定値`127.0.0.1:9090`）で次のエンドポイントを公開します。

| エンドポイント | 用途 |
| --- | --- |
| `/healthz` | 生存確認と接続中のConnector数 |
| `/readyz` | 証明書やValkeyを含む準備状態 |
| `/metrics` | Prometheusメトリクス |

Connectorのヘルスチェックとメトリクスは、既定で`127.0.0.1:9091`に公開されます。`SIEVETUBE_HEALTH_ADDR`で変更できます。

ログはJSON形式で、`RUST_LOG`によってフィルタリングできます。証明書のライフサイクル、ACME、ポリシー導入、DNS同期、複数Edgeメッシュ、監視、Graceful Shutdown、切り戻しについては[`docs/operations.md`](docs/operations.md)を参照してください。

## 開発

ワークスペース全体のテストを実行します。

```sh
cargo test --workspace
```

ワークスペースの構成は次のとおりです。

- `sievetube-edge` — 公開Ingressとトンネルサーバー
- `sievetube-connector` — 非公開ネットワーク側のエージェントとローカル転送
- `sievetube-common` — プロトコル、認証、設定、メトリクスの共通型
- `tests/integration` — End-to-Endテスト

本プロジェクトはAI支援型コーディングツールを使用して開発されました。
