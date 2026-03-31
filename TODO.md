# TODO — MVPスコープ内の未実装・未接続項目

## 高優先度（動作に直接影響）

### 1. ~~UDP双方向転送が未完成~~ ✅ 実装済み
- Edge: `UdpReplyMap`(request_id → client_addr + socket)でリプライルーティングを実装
- Edge: `udp_reply_loop()`がConnectorからのQUICデータグラムを受信してクライアントへ返送
- Connector: `serve_streams()`を`tokio::select!`に再構築し、`read_datagram()`分岐を追加

### 2. ~~TCP/UDPリスナーがEdge main.rsに接続されていない~~ ✅ 実装済み
- `ServerConfig`の`tcp_listen`/`udp_listen`を`Vec<PortHostMapping>`に変更（addr + hostname）
- `main.rs`で設定をイテレートして`serve_raw_tcp()`/`serve_udp()`をspawn

### 3. ~~ConnectorのValkey接続・ハートビートが未接続~~ ✅ 実装済み
- Connector設定に`[valkey]`セクション（任意）を追加
- `main.rs`でValkey URLが設定されていれば接続し、`heartbeat_loop()`をspawn

### 4. ~~ホスト名の所有権チェックが未接続~~ ✅ 実装済み
- `handle_connector()`内でJWT検証後に各ホスト名についてValkeyでオーナー確認
- 異なるテナントが所有している場合は認証拒否

---

## 中優先度（品質・運用）

### 5. ~~`metrics::global()` の `catch_unwind` を解消~~ ✅ 実装済み
- `forward_tcp()`内の`catch_unwind`を削除し、`metrics::global()`を直接呼ぶよう変更

### 6. ~~グレースフルシャットダウン（コネクション drain）~~ ✅ 実装済み
- Edge: `endpoint.close(GOING_AWAY, ...)`→`endpoint.wait_idle().await`
- Connector: `tokio::sync::watch`チャネルでシャットダウン信号を伝播し、`serve_streams()`で`GOING_AWAY`を送信

### 7. ~~E2E統合テストが未実装~~ ✅ 実装済み
- `tests/integration/` に4テストを実装（全パス）
  - `e2e_http.rs`: `http_tunnel_basic`（HTTP転送）、`auth_rejection_returns_502`（認証拒否）
  - `e2e_tcp.rs`: `tcp_echo_tunnel`（TCPエコー）、`multi_tenant_coexistence`（マルチテナント）
  - `helpers/mod.rs`: テストハーネス（バイナリ起動、ヘルスチェック、JWTトークン生成）

### 8. ~~JWTトークン生成ツールが存在しない~~ ✅ 実装済み
- `sievetube-edge issue-token --secret <secret> --sub <tenant_id> --hostname <hostname> [--exp-hours <hours>]`

---

## 低優先度（MVPスコープ内だが影響小）

### 9. ~~ConnectorRegistry::len() が未使用~~ ✅ 実装済み
- `/healthz` レスポンスに`active_connectors`フィールドを追加（統合テストでも使用）

### 10. ~~Connectorのハートビート間隔が設定不可~~ ✅ 実装済み
- TODO #3 の実装時に`heartbeat_interval_secs`フィールドを追加（デフォルト15秒）

---

## MVPスコープ外（README Section 7 より）

以下は今回の実装対象外。将来のアップデートで対応予定。

- ACME (Let's Encrypt) による TLS 証明書自動更新
- Rate Limiting / IP ブロック機能（Tower ミドルウェア / Wasm プラグイン想定）
- DNS レコードの自動登録・更新
- 公開サーバー（Edge）間でのトラフィック内部転送メッシュ
