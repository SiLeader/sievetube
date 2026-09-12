# 運用手順

Edge/Connectorの設定項目は[config/edge.example.toml](../config/edge.example.toml)と[config/connector.example.toml](../config/connector.example.toml)に一覧があります。ここでは有効化の順序、監視、切り戻しをまとめます。

## 1. 基本

* 設定はEdgeの起動時に検証されます。値が不正な場合は起動しません（黙って既定値へ戻したり、機能を無効化したりしません）。
* `SIGHUP` で設定ファイルを読み直します。反映されるのは `[policy]`（プラグインを含む）とBYOC証明書です。読み込みや検証に失敗した場合は、稼働中の設定をそのまま維持します。それ以外の項目は再起動が必要です。
* `SIGTERM` / `Ctrl-C` で新規受付を停止し、`server.drain_timeout_secs` の間だけ処理中の接続を待ってから終了します。
* 機能はすべて既定で無効です。`[policy]`・`[tls.acme]`・`[dns]` は `enabled = true`、Edge間転送は `routing.mode = "mesh"` で有効になります。

## 2. 監視

`server.health_listen` で次を公開します。

| パス | 用途 |
| --- | --- |
| `/healthz` | 生存確認。接続中のConnector数を含む |
| `/readyz` | 準備状態。期限切れ証明書、ACME証明書の不在、Valkey未接続があると503 |
| `/metrics` | Prometheus形式 |

主なメトリクス（ホスト名・IP・request_idはラベルにしません。詳細は構造化ログを参照してください）:

* `sievetube_bytes_transferred_total`, `sievetube_active_quic_connections`, `sievetube_tunnel_latency_seconds`
* `sievetube_tls_certificates{source,state}`, `sievetube_tls_certificate_min_remaining_seconds{source}`
* `sievetube_acme_orders_total{result}`, `sievetube_acme_next_attempt_timestamp_seconds`
* `sievetube_policy_decisions_total{protocol,decision,reason,mode}`, `sievetube_policy_buckets{table}`, `sievetube_policy_plugin_failures_total{plugin,failure}`
* `sievetube_dns_records{status}`, `sievetube_dns_changes_total{provider_type,result}`, `sievetube_dns_last_reconcile_timestamp_seconds`
* `sievetube_mesh_forwarded_total{protocol,stage}`, `sievetube_mesh_rejected_total{reason}`, `sievetube_mesh_routes`, `sievetube_mesh_peers`
* `sievetube_udp_dropped_total{reason}`

## 3. 証明書

### 3.1 BYOC

`tls.cert_dir` に `<hostname>.crt` と `<hostname>.key` を置きます。ワイルドカードはファイル名を `*.example.com.crt` とします。`tls.reload_interval_secs` ごと、および `SIGHUP` で再読み込みします。

* 更新が壊れている場合（鍵と証明書の不一致、期限切れ、SAN不一致）は、そのホスト名の直前の証明書を保持します。他のホスト名は通常どおり更新されます。
* 期限切れの証明書は `/readyz` を劣化させます。

### 3.2 ACME

1. まず `directory_url` をステージング（`https://acme-staging-v02.api.letsencrypt.org/directory`）にして検証します。`terms_of_service_agreed = true` が必要です。
2. HTTP-01の場合、CAから **80番ポート** に到達できる必要があります。`domains` に挙げた名前だけが対象です。同じ名前のファイルが `tls.cert_dir` にあると起動時にエラーになります。
3. ワイルドカードはDNS-01が必要です。`challenge = "dns-01"` とし、`[dns]` のプロバイダーが `_acme-challenge.<domain>` を含むゾーンを持つように設定します。
4. 本番へ切り替えるときは `directory_url` を変更します。アカウントと証明書はディレクトリURLごとに別ディレクトリへ保存されるため、ステージングの証明書が本番で使われることはありません。切り替え直後は証明書が無い状態になるため、発行完了まで該当ホストのHTTPSは失敗します。

複数Edgeで運用する場合は `coordination = "valkey"` を設定し、`state_dir` を全Edgeで共有（共有ボリューム）します。発行はドメイン単位のリースを取得した1台だけが行い、HTTP-01の応答は各Edgeへ配布して、応答を返せることを確認してから検証を要求します。確認の対象はACMEを有効にしている生存Edge（チャレンジ応答を担当すると申告したEdge）です。Edgeは自身の `domains` に無いドメインでも、配布された応答がある間だけそのチャレンジパスに応答します。ACMEを無効にしたEdgeがLB/DNSの配下にいる場合はCAがそのEdgeに到達すると検証が失敗するため、警告をログに出します。この構成ではDNS-01を使用してください。

切り戻し: `[tls.acme] enabled = false` にして再起動します。発行済みの証明書やDNSレコードは削除されません。`state_dir` には直前の世代が残っているため、必要なら `certs/<domain>/current` を以前の世代番号に書き換えてEdgeを再起動します。BYOCへ戻す場合は `tls.cert_dir` にファイルを置いてからACMEを無効化します。

## 4. トラフィックポリシー

1. `[policy] enabled = true`、`mode = "monitor"` で開始します。判定はメトリクスとログにだけ現れ、通信は拒否されません。
2. `sievetube_policy_decisions_total` を確認し、想定どおりであればドメイン単位（`[[policy.domains]]`）またはグローバルに `mode = "enforce"` へ切り替えます。
3. ロードバランサの背後にいる場合は `trusted_proxies` を設定します。設定しない限り `X-Forwarded-For` は信用せず、接続元アドレスで判定します。

上限はEdgeごとです。複数Edgeへ分散すると全体の許容量は台数倍になります。

Wasmプラグインは `sha256` が一致するモジュールだけを読み込み、インポートを持つモジュールは拒否します。実行はメモリ・燃料・時間・同時実行数で制限され、trapやタイムアウトは該当リクエストのみ503になります。読み込みに失敗した場合は直前のプラグイン構成を維持するため、`SIGHUP` による切り戻しは高速です。

## 5. DNSレコード

1. `[dns] enabled = true`、`dry_run = true` から始め、`sievetube-edge dns-plan /etc/sievetube/edge.toml` で差分を確認します（出力に秘密情報は含まれません）。
2. 問題がなければ `dry_run = false` にします。既存レコードを引き継ぐ場合のみ `import = true` を指定します。指定がなければ競合として停止し、既存のレコードには触れません。
3. レコードの削除は設定から消すのではなく `state = "absent"` を指定します。管理下の値と現在値が一致する場合のみ削除します。
4. 認証情報はTOMLに書かず、Cloudflareは `api_token_env` / `api_token_file`、Route 53はAWS標準の認証情報取得（環境変数・プロファイル・ロール）を使います。必要なIAM権限は `route53:ListResourceRecordSets`, `route53:ChangeResourceRecordSets`, `route53:GetChange` です。
5. 複数Edgeではゾーン単位のリースで書き込みを1台に絞ります。Valkeyが無い場合は `single_writer = true` を明示した1台だけが書き込めます。

切り戻し: `[dns] enabled = false`（または `dry_run = true`）にします。レコードは削除されません。以前の値は `state_dir/<provider>.json` の `previous` に保存されているので、設定の `values` をその値に戻して再適用します。外部で変更されている場合は競合として停止するため、先に現在値を確認してください。

## 6. Edge間転送メッシュ

### 6.1 証明書の作成

```sh
sievetube-edge mesh-ca   /etc/sievetube/mesh              # ca.pem, ca.key
sievetube-edge mesh-cert /etc/sievetube/mesh edge-a       # edge-a.pem, edge-a.key
sievetube-edge mesh-cert /etc/sievetube/mesh edge-b
```

`ca.key` はEdgeに配布しません。各Edgeには `ca.pem` と自分の証明書・鍵だけを配置します。Edge IDは証明書に埋め込まれ、接続のたびに照合されます。

### 6.2 段階的な移行

1. **Edgeを先に更新する。** 各Edgeに `[mesh]` を設定し、`routing.mode = "direct"` のまま起動します。この時点では転送は行われませんが、設定の妥当性は検証されます。
2. **peer接続と経路広告を確認する。** `routing.mode = "mesh"` に切り替え、`sievetube_mesh_peers` と `sievetube_mesh_routes` が期待値になることを確認します。Connectorは全Edgeへ接続したままにします。
3. **一部ドメインで遠隔転送を検証する。** 該当ドメインのConnectorの接続先を一部のEdgeに絞り、他のEdge経由でも到達できることを確認します。
4. **Connectorの接続先を縮小する。** 単一障害点にならないよう、必ず複数のEdgeを接続先に残します。
5. 旧バージョンのEdgeが混在する間は、そのEdgeへの直接接続を維持します。

切り戻し: まずConnectorを全Edgeへ再接続し、ローカル経路が揃ったことを `/healthz` の接続数で確認してから、Edgeの `routing.mode` を `direct` に戻します。

### 6.3 要件と障害時の挙動

* 複数Edgeのmesh構成では、Valkey・固定のEdge ID・相互認証用の証明書・到達可能な `advertise` アドレスが必須です。不足している場合は設定エラーとして起動しません（暗黙にdirectへ切り替わることはありません）。
* Valkeyが停止すると、新しい経路広告と新規のホスト名所有権取得は止まります。既存の経路はTTLが切れるまで使え、ローカルConnectorへの転送は影響を受けません。
* 転送先Edgeが停止すると、その経路はTTL後に消え、失敗したpeerは一定時間候補から外れます。応答開始前の失敗は502、トンネル確保のタイムアウトは504になります。
* 既存のストリームは障害時に引き継げません。新規接続は経路が回復した時点で成功します。
* UDPは「1要求1応答」のみを転送します。サイズ超過のデータグラムは破棄して `sievetube_udp_dropped_total{reason="oversize"}` に計上します。
* UDPの転送は受信ループの外で行うため、リスナーごとの同時転送数（1024）を超えた分は `reason="forward_backlog"` として破棄します。応答は転送先のpeerからのみ受け付け、他のpeerからの応答は `reason="reply_peer_mismatch"` に計上します。

## 7. 秘密情報

* JWT署名鍵、Cloudflareトークン、ACMEアカウント鍵、mesh CAの鍵、証明書の秘密鍵はログに出力しません。
* ACMEの `state_dir` とmeshの鍵は所有者のみ読める権限で保存されます（作成時に0700/0600）。
* Cloudflareトークンは環境変数またはファイルから読み込みます。設定ファイルに直接書くことはできません。

## 8. テストの実行

```sh
cargo build -p sievetube-edge -p sievetube-connector     # 統合テストはビルド済みバイナリを起動する
cargo test --workspace --all-targets
```

外部依存が必要なテストは、環境変数が設定されていない場合はスキップされます。

| 環境変数 | 対象 |
| --- | --- |
| `SIEVETUBE_TEST_VALKEY_URL` | Valkeyを使う所有権・リース・メッシュ経路のテスト |
| `SIEVETUBE_PEBBLE_BIN`, `SIEVETUBE_CHALLTESTSRV_BIN`, `SIEVETUBE_PEBBLE_DIR` | ACMEテストサーバー（Pebble）を使う発行・更新のテスト |

例:

```sh
docker run -d --rm -p 127.0.0.1:6379:6379 valkey/valkey:8-alpine
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest

SIEVETUBE_TEST_VALKEY_URL=redis://127.0.0.1:6379 \
SIEVETUBE_PEBBLE_BIN=$(go env GOPATH)/bin/pebble \
SIEVETUBE_CHALLTESTSRV_BIN=$(go env GOPATH)/bin/pebble-challtestsrv \
SIEVETUBE_PEBBLE_DIR=$(go env GOPATH)/pkg/mod/github.com/letsencrypt/pebble/v2@v2.10.1 \
cargo test --workspace --all-targets
```
