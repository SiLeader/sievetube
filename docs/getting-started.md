# スタートガイド

このガイドでは、非公開ホストの `127.0.0.1:8080` で動く HTTP サービスを、1 台の Edge から `app.example.com` として公開します。最初は HTTP で疎通を確認し、その後に TLS を設定します。

## 1. 前提条件

- 新しい安定版 Rust ツールチェーンと Cargo
- インターネットから到達できる Edge 用ホスト
- Connector から Edge の QUIC ポートへ到達できること（例: UDP `4433`）
- 利用者から Edge の公開ポートへ到達できること（例: TCP `80`、`443`）
- `app.example.com` の A/AAAA レコードを Edge のアドレスへ設定できること

ファイアウォールでは通信方向と TCP/UDP を区別してください。

| 送信元 | 宛先 | 既定ポート | 用途 |
| --- | --- | --- | --- |
| Connector | Edge | UDP `4433` | QUIC トンネル |
| 利用者 | Edge | TCP `80` | HTTP、ACME HTTP-01 |
| 利用者 | Edge | TCP `443` | HTTPS |
| 監視システム | Edge | TCP `9090` | Health / Metrics。既定は loopback のみ |
| 監視システム | Connector | TCP `9091` | Health / Metrics。既定は loopback のみ |

## 2. ビルド

リポジトリのルートで実行します。

```sh
cargo build --release
```

次のバイナリが生成されます。

- `target/release/sievetube-edge`
- `target/release/sievetube-connector`

## 3. Edge の設定

公開ホスト上でサンプルをコピーします。

```sh
install -m 600 config/edge.example.toml edge.toml
```

最初の疎通確認では、少なくとも次を確認・変更します。

```toml
config_version = 2

[server]
quic_listen = "0.0.0.0:4433"
http_listen = "0.0.0.0:80"
https_listen = "0.0.0.0:443"
health_listen = "127.0.0.1:9090"

[auth]
jwt_secret = "十分に長いランダムな値へ必ず変更する"

[tls]
cert_dir = "/etc/sievetube/certs"

[routing]
mode = "direct"
```

`config_version = 2` で `routing.mode` を省略すると既定は `mesh` になり、`[mesh]` が必要です。単一 Edge では `direct` を明記してください。

Edge を起動します。

```sh
RUST_LOG=info ./target/release/sievetube-edge edge.toml
```

引数を省略した場合、Edge はカレントディレクトリの `edge.toml` を読みます。80/443 のような 1024 未満のポートを一般ユーザーで bind するには、サービスマネージャーで必要最小限の Capability を付与するか、公開ロードバランサーから非特権ポートへ転送してください。

## 4. Connector 用 JWT の発行

Edge の `auth.jwt_secret` と同じ秘密値を改行なしのファイルへ保存し、権限を制限します。次のコマンドでトークンを発行します。

```sh
./target/release/sievetube-edge issue-token \
  --secret-file /run/secrets/sievetube-jwt \
  --sub tenant-1 \
  --hostname app.example.com \
  --exp-hours 8760
```

複数のホスト名を許可するときは `--hostname` を繰り返します。`--secret-file` の代わりに `SIEVETUBE_JWT_SECRET` も利用できます。コマンドラインの `--secret` はプロセス一覧やシェル履歴へ残る可能性があるため、本番では避けてください。

JWT の `sub` はテナント識別子です。同じ Edge に同じ `sub` の Connector が接続すると、新しい接続が古い接続を置き換えます。出力された JWT は、その許可ホスト名を有効期限まで登録できる秘密情報として扱います。

## 5. Connector の設定

非公開ホスト上でサンプルをコピーします。

```sh
install -m 600 config/connector.example.toml connector.toml
```

生成した JWT、Edge のアドレス、ローカルサービスを設定します。

```toml
[auth]
token = "<生成した JWT>"

[network]
public_servers = ["edge.example.net:4433"]

[[ingress]]
hostname = "app.example.com"
protocol = "http"
target = "127.0.0.1:8080"

[[ingress]]
target = "http_status:404"
```

Ingress は上から評価され、最初に一致したルールが使われます。Catch-all は最後に置いてください。

> [!WARNING]
> `edge_ca_cert` と `edge_cert_sha256` のどちらも設定しない場合、Connector は Edge の QUIC 証明書を検証しません。これは初回のローカル検証に限り、本番では Edge に `server.quic_cert` / `server.quic_key` を設定したうえで、Connector に CA バンドルまたは証明書ピンを設定してください。

CA で検証する構成例です。

```toml
[network]
public_servers = ["edge.example.net:4433"]
edge_ca_cert = "/etc/sievetube/edge-ca.pem"
# IP アドレスで接続し、証明書の SAN は DNS 名の場合に指定する
# edge_server_name = "edge.example.net"
```

Connector を起動します。

```sh
RUST_LOG=info ./target/release/sievetube-connector connector.toml
```

引数を省略した場合、Connector はカレントディレクトリの `config.toml` を読みます。

## 6. 疎通確認

まず各プロセスの状態を確認します。

```sh
curl --fail http://127.0.0.1:9090/healthz
curl --fail http://127.0.0.1:9091/readyz
```

Connector の `/readyz` が 200 なら、少なくとも 1 台の Edge へ認証済みで接続しています。DNS を Edge へ向けた後、外部から確認します。

```sh
curl -v http://app.example.com/
```

DNS の反映前は、Edge の IP を指定しつつ Host ヘッダーを送って確認できます。

```sh
curl -v -H 'Host: app.example.com' http://203.0.113.10/
```

## 7. HTTPS の有効化

公開 HTTPS の証明書は、Connector と Edge 間の QUIC 証明書とは別です。次のいずれかを使います。

- BYOC: `tls.cert_dir` に `app.example.com.crt` と `app.example.com.key` を配置する
- ACME: `[tls.acme]` を有効にし、`domains = ["app.example.com"]` を明示する

証明書の更新、ACME の段階導入、切り戻しは [運用手順](operations.md#3-証明書) を参照してください。

## 次に読む

- TCP/UDP、Ingress、設定バージョン: [設定ガイド](configuration.md)
- 通信経路と認証境界: [アーキテクチャ](architecture.md)
- 疎通しない場合: [トラブルシューティング](troubleshooting.md)
