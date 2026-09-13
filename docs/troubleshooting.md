# トラブルシューティング

問題は「プロセス起動」「Connector と Edge の接続」「Edge の経路選択」「Connector からローカルサービスへの接続」の順に切り分けると効率的です。

## 最初に収集する情報

Edge と Connector の両方で JSON ログを確認し、Health/Readiness を取得します。

```sh
curl -sS http://127.0.0.1:9090/healthz
curl -sS -i http://127.0.0.1:9090/readyz
curl -sS http://127.0.0.1:9091/healthz
curl -sS -i http://127.0.0.1:9091/readyz
```

必要な時間だけログを詳しくする場合は、起動時の `RUST_LOG` を調整します。

```sh
RUST_LOG=sievetube_edge=debug,sievetube_common=debug sievetube-edge /etc/sievetube/edge.toml
RUST_LOG=sievetube_connector=debug,sievetube_common=debug sievetube-connector /etc/sievetube/connector.toml
```

JWT、署名鍵、秘密鍵、Cloudflare トークンは調査記録へ貼り付けないでください。

## Edge が起動しない

### `address already in use` または `permission denied`

- `server.quic_listen` は UDP、`http_listen` / `https_listen` は TCP として競合を確認します。
- 80/443 など 1024 未満のポートには bind 権限が必要です。
- 同一アドレスを Raw TCP または UDP の同じプロトコル内で重複指定していないか確認します。

切り分けのために一時的に `127.0.0.1:8080` / `127.0.0.1:8443` のような非特権ポートへ変更できます。ただし外部公開時はファイアウォールやロードバランサーの転送先も合わせます。

### 設定ファイルの parse / unknown field エラー

設定は未知のキーを拒否します。エラーに示されたセクションとキーを、コメント付きサンプルと比較してください。

- [`config/edge.example.toml`](../config/edge.example.toml)
- [`config/connector.example.toml`](../config/connector.example.toml)

`config_version = 2` で `routing.mode` を省略すると mesh になるため、単一 Edge では `mode = "direct"` を明記します。

### 証明書ファイルのエラー

- `server.quic_cert` と `server.quic_key` は必ず対で指定します。
- BYOC は `<hostname>.crt` と `<hostname>.key` の名前を一致させます。
- PEM 形式、証明書と秘密鍵の対応、SAN、有効期限、ファイルの読取権限を確認します。
- ACME と BYOC で同じホスト名を同時に管理できません。

## Connector の `/readyz` が 503

Connector の `/healthz` 本文には、設定した Edge ごとの `status`、`last_error`、状態変更時刻が含まれます。次の順で確認します。

1. `public_servers` の名前解決が Connector ホストで成功するか。
2. Connector から Edge のポートへ UDP が許可されているか。TCP 4433 を開けても QUIC は通りません。
3. Edge が `server.quic_listen` で待ち受けているか。
4. Edge 証明書の SAN と接続先名または `edge_server_name` が一致するか。
5. CA バンドルまたは証明書ピンが現在の Edge 証明書と一致するか。
6. JWT の署名鍵、有効期限、許可ホスト名が正しいか。

同じ `sub` の Connector が同じ Edge へ複数接続していると、接続を互いに置き換えます。ログで replacement の警告が繰り返される場合、Connector ごとに別の Edge を割り当てるか、テナント設計を見直してください。

## HTTP が 404 / 502 / 504

### 404

Sieve Tube 自身が通常の未登録ホストへ 404 を返すわけではありません。Connector の `http_status:404` ルール、または転送先アプリケーションが応答しています。意図しない 404 なら、Ingress は上から評価されるため、対象ルールより前の Catch-all に吸収されていないか確認します。

- リクエストの Host が対象の `ingress.hostname` と一致するか確認します。
- Connector の `protocol = "http"` を確認します。
- 転送先アプリケーションへ直接リクエストし、アプリケーション由来の 404 か確認します。
- DNS 反映前は Host を明示して Edge を直接試します。

```sh
curl -v -H 'Host: app.example.com' http://203.0.113.10/
```

### 502

経路がない、または経路は見つかったものの転送を開始できない場合に返ります。

- リクエストの Host が JWT の `hostnames` にあり、対応する HTTP Ingress が Edge に広告されているか確認します。
- Connector と同じホスト・ユーザーの実行環境からターゲットへ接続できるか確認します。
- `target` は DNS 名ではなく IP リテラルとポートで指定します。
- ローカルサービスが loopback の IPv4 と IPv6 のどちらで待ち受けているか確認します。
- mesh では `sievetube_mesh_peers`、`sievetube_mesh_routes` と peer 側ログも確認します。

### 504

Edge が `http.backend_open_timeout_secs` 内にトンネルを確保できない場合などに発生します。Connector の `max_concurrent_streams`、Edge/mesh のストリーム上限、ローカルサービスの負荷、QUIC 経路の遅延・損失を確認します。単にタイムアウトを延ばす前に、上限到達やパケット損失をメトリクスとログで確認してください。

## HTTPS だけ失敗する

HTTP が成功するならトンネル経路ではなく、公開 TLS を確認します。

- クライアントが送る SNI と証明書ファイル名または ACME の `domains` が一致しているか。
- 証明書チェーンと秘密鍵が正しいか。
- `/readyz` に期限切れまたは ACME 証明書不在の理由が出ていないか。
- ACME HTTP-01 では CA から TCP 80 に到達できるか。
- ワイルドカードに HTTP-01 を使っていないか。ワイルドカードは DNS-01 が必要です。

QUIC 用の `server.quic_cert` を設定しても、公開 HTTPS の証明書にはなりません。

## Raw TCP / UDP が届かない

- Edge リスナーの `hostname`、JWT の許可ホスト名、Connector Ingress の `hostname` を完全に一致させます。
- Edge と Connector の `protocol` を TCP/UDP で取り違えていないか確認します。
- TCP/UDP それぞれの公開ファイアウォールを確認します。
- UDP は 1 要求・1 応答モデルです。ストリーミング、複数応答、長時間の疑似セッションを必要とするプロトコルには適合しない場合があります。
- UDP の破棄は `sievetube_udp_dropped_total{reason=...}` で確認します。

## Edge の `/readyz` が 503

レスポンスの `reasons` を先に確認します。代表的な原因は次のとおりです。

- BYOC 証明書の期限切れ
- 有効な ACME 証明書がまだ存在しない
- 構成した Valkey に接続できない

`/healthz` が 200 でも `/readyz` が 503 になるのは意図した動作です。前者はプロセスが生きているか、後者はトラフィックを受ける準備ができているかを表します。

## 設定変更が反映されない

`SIGHUP` で反映されるのは Edge の `[policy]`（Wasm を含む）と BYOC 証明書だけです。リスナー、JWT 鍵、ACME、DNS、routing、mesh などは再起動が必要です。Connector はすべての設定変更で再起動が必要です。

再起動は `SIGTERM` を使い、drain timeout 内で処理中通信を終了させます。強制終了すると進行中の接続は直ちに切断されます。

## DNS 管理が変更を適用しない

まず dry-run の計画を確認します。

```sh
sievetube-edge dns-plan /etc/sievetube/edge.toml
```

- `[dns] enabled = true` と `dry_run` の値を確認します。
- `allowed_zones`、provider の zone、record の name が整合するか確認します。
- Valkey がない単一 writer 構成では `single_writer = true` が必要です。
- 既存レコードを取り込むときだけ `import = true` を使います。
- 削除は設定から行を消さず `state = "absent"` を指定します。
- Cloudflare トークンまたは AWS 権限を確認します。

安全な導入と切り戻しは [運用手順の DNS レコード](operations.md#5-dnsレコード) を参照してください。
