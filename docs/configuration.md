# 設定ガイド

Edge と Connector は TOML ファイルを読み込みます。未知のキーはエラーになるため、タイプミスした設定が黙って無視されることはありません。起動時にアドレス、範囲、ファイルの存在、機能間の依存関係も検証されます。

このページは設定の選び方を説明します。全フィールドと既定値は、実装と同時に更新されるコメント付きサンプルを参照してください。

- [`config/edge.example.toml`](../config/edge.example.toml)
- [`config/connector.example.toml`](../config/connector.example.toml)

## 設定ファイルの指定

```sh
sievetube-edge /etc/sievetube/edge.toml
sievetube-connector /etc/sievetube/connector.toml
```

引数を省略すると Edge は `edge.toml`、Connector は `config.toml` をカレントディレクトリから読みます。

## Edge

### `config_version` とルーティング

新しい設定では `config_version = 2` を指定します。バージョンによって `routing.mode` 省略時の意味が異なります。

| `config_version` | `routing.mode` 省略時 |
| --- | --- |
| 省略または `1` | `direct` |
| `2` | `mesh` |

既存構成のバイナリ更新だけで通信経路が変わらないよう、バージョンなしは direct として扱われます。単一 Edge の新規構成では、意図を明確にするため `config_version = 2` と `routing.mode = "direct"` を併記してください。

### 主なセクション

| セクション | 役割 | 注意点 |
| --- | --- | --- |
| `[server]` | QUIC、HTTP(S)、TCP/UDP、監視のリスナー | QUIC は UDP。公開側 HTTP(S) は TCP |
| `[auth]` | Connector JWT の署名鍵 | `jwt_secret` は必ず変更し、設定ファイルの権限を制限する |
| `[http]` | HTTP 接続数、ヘッダー、タイムアウト | HTTP と HTTPS で接続数上限を共有する |
| `[tls]` | 公開 HTTPS の BYOC 証明書 | QUIC 用証明書とは別物 |
| `[tls.acme]` | 公開証明書の自動取得 | 明示した `domains` だけを発行する |
| `[valkey]` | 所有権、リース、経路、存在情報 | mesh と複数 writer の協調で必要 |
| `[policy]` | CIDR、Rate Limit、Wasm ポリシー | 最初は `monitor` が安全 |
| `[dns]` | Cloudflare / Route 53 のレコード管理 | 最初は `dry_run = true` で差分確認 |
| `[routing]`, `[mesh]` | Edge 間転送 | peer を持つ mesh では Valkey と mTLS が必要 |

### リスナー

```toml
[server]
quic_listen = "0.0.0.0:4433"
quic_cert = "/etc/sievetube/quic/edge.crt"
quic_key = "/etc/sievetube/quic/edge.key"
http_listen = "0.0.0.0:80"
https_listen = "0.0.0.0:443"
health_listen = "127.0.0.1:9090"
```

`quic_cert` と `quic_key` は両方を指定するか、両方を省略します。省略時は自己署名証明書が生成されますが、Connector は CA 検証できません。固定証明書を設定し、Connector 側で検証する構成を本番の基準にしてください。

Health/Metrics は認証を持たないため、既定の loopback または管理ネットワークだけで待ち受けます。

### Raw TCP / UDP リスナー

```toml
[[server.tcp_listen]]
addr = "0.0.0.0:2222"
hostname = "ssh.example.com"

[[server.udp_listen]]
addr = "0.0.0.0:19132"
hostname = "game.example.com"
```

各 `addr` は同じプロトコル内で一意である必要があります。ここでの `hostname` は DNS の自動設定ではなく、経路選択用の論理名です。Connector の Ingress と JWT の許可ホスト名に同じ値を含めます。

### JWT のローテーション

```toml
[auth]
jwt_secret = "new-secret"
jwt_previous_secrets = ["old-secret"]
```

Edge は新旧どちらで署名されたトークンも検証し、新規トークンは `jwt_secret` だけで発行します。

1. 新しい鍵を `jwt_secret`、旧鍵を `jwt_previous_secrets` に設定して Edge を再起動します。
2. 新しい鍵で全 Connector の JWT を再発行・配布します。
3. 旧 JWT が使われていないことを確認します。
4. 有効期限経過後に旧鍵を削除して再起動します。

`SIGHUP` の対象はポリシーと BYOC 証明書だけなので、JWT 鍵の変更には再起動が必要です。

### 公開 TLS と QUIC TLS

混同しやすい 2 つの TLS 設定があります。

- `server.quic_cert` / `server.quic_key`: Connector が接続する Edge の身元を示す
- `tls.cert_dir` / `tls.acme`: 公開 HTTPS 利用者にホスト名の証明書を提示する

BYOC は `tls.cert_dir/<hostname>.crt` と `<hostname>.key` の組で配置します。ワイルドカードはファイル名も `*.example.com.crt` / `*.example.com.key` です。定期的に再読込され、`SIGHUP` でも即時再読込します。

## Connector

### ネットワークと Edge 検証

```toml
[network]
public_servers = ["edge-a.example.net:4433", "edge-b.example.net:4433"]
edge_ca_cert = "/etc/sievetube/edge-ca.pem"
drain_timeout_secs = 10
max_concurrent_streams = 256
target_connect_timeout_secs = 10
```

`edge_ca_cert` と `edge_cert_sha256` は同時に指定できません。

- CA 検証: 証明書を通常どおり更新できるため、継続運用に向きます。接続先のホスト名は証明書の SAN と一致させます。
- SHA-256 ピン: 自己署名証明書などを特定の証明書に固定します。更新前に新旧のピンを並べることで段階移行できます。
- どちらもなし: 暗号化はされますが接続相手を認証しません。テストまたは移行用途だけにします。

`max_concurrent_streams` は全 Edge 接続で共有されます。Connector のファイルディスクリプター数とローカルサービスの同時接続上限より小さく設計してください。

### Ingress

```toml
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
target = "http_status:404"
```

ルールは上から順に評価し、最初の一致で停止します。

| フィールド | 省略時 | 意味 |
| --- | --- | --- |
| `hostname` | 全ホスト名 | 完全一致するホスト名 |
| `protocol` | 全プロトコル | `http`、`tcp`、`udp` |
| `target` | 省略不可 | IP リテラルとポート、または `http_status:<100..599>` |

ターゲットは `127.0.0.1:8080` や `[::1]:8080` のようなソケットアドレスで指定します。`localhost:8080` のような名前は利用できません。`http_status` は HTTP 専用で、TCP/UDP ルールには指定できません。

JWT の `hostnames` と Ingress の関係は次のとおりです。

```text
JWT で許可されたホスト名 ∩ Ingress が対応するホスト名/プロトコル = Edge に広告するサービス
```

Catch-all は未一致時の動作を Connector 内で定義しますが、JWT にない任意のホスト名を新たに公開する権限は与えません。

### Connector の Health リスナー

Connector の監視アドレスは TOML ではなく環境変数で変更します。

```sh
SIEVETUBE_HEALTH_ADDR=127.0.0.1:9191 sievetube-connector /etc/sievetube/connector.toml
```

## 反映方法

| 変更 | 反映方法 |
| --- | --- |
| Edge の `[policy]`（Wasm を含む） | `SIGHUP` |
| Edge の BYOC 証明書 | 定期再読込または `SIGHUP` |
| 上記以外の Edge 設定 | Edge の再起動 |
| Connector の全設定 | Connector の再起動 |

再起動が必要な変更では `/readyz` を使ってロードバランサーから外し、`SIGTERM` で Graceful Shutdown させてください。詳しくは [運用手順](operations.md) を参照してください。

