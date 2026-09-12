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

## 拡張機能（[plan/](plan/)の計画）— 実装済み

設定例は[config/edge.example.toml](config/edge.example.toml)、有効化と切り戻しの手順は[docs/operations.md](docs/operations.md)を参照。

### P0: 共通基盤 ✅
- ホスト名の正規化（`sievetube-common/src/hostname.rs`）を全経路の検索キーに使用
- Valkeyでのホスト名所有権の原子的な取得（Luaスクリプト）。確認できない場合は新規登録を拒否
- Connector登録に接続世代IDを導入し、旧接続の切断で新接続の経路が消えないようにした
- 設定検証、グレースフルシャットダウン（drain）、`SIGHUP`での再読み込み

### A: ACME ✅
- A1: 証明書ストア（世代ディレクトリ＋原子的な切り替え）、無停止反映、壊れた更新時は直前の証明書を保持
- A2: 単一EdgeのHTTP-01。証明書の有効期間から更新を予約し、失敗は上限付き指数バックオフ（再起動後も保持）
- A3: 複数Edgeでの協調（ドメイン単位リースとフェンシング世代、HTTP-01応答の全Edge配布、共有ストレージからの取り込み）

### B: ポリシー ✅
- B1: HyperによるHTTP/1.1・HTTP/2のリクエスト単位処理（WebSocket Upgrade、ストリーミング本文、hop-by-hopヘッダー処理）
- B2: CIDRブロックとトークンバケット、信頼プロキシ、監視モード、検証してから切り替える再読み込み
- B3: TCPの接続レート・同時接続数、UDPのパケット／バイト制限、UDP返信マップのTTLと上限
- B4: Wasmプラグイン（ハッシュ確認、インポート禁止、メモリ・燃料・時間・同時実行数の制限、失敗は503）

### D: DNS ✅
- D1: 望ましい状態とプロバイダー境界、dry-run（`sievetube-edge dns-plan`）、競合時は停止
- D2: Cloudflare・Route 53アダプターと共通の契約テスト、ゾーン単位リース、部分適用からの復旧
- D3: DNS-01用のTXT操作（自分が追加した値だけを削除、伝播確認、再起動後の回収）

### M: Edge間転送メッシュ ✅
- M1: 専用ALPNとmTLSによる相互認証、転送要求の検証（テナント・ホップ数・バージョン）
- M2: TTL付きの経路広告とローカルキャッシュ、`Local / Remote / Unavailable` の経路判定
- M3: HTTP/HTTPS・TCPの1ホップ転送（受入確認前のみ再試行）
- M4: UDP転送（入口Edge単位の応答振り分け、サイズ超過の破棄）
- M5: `config_version` と `routing.mode` による標準構成への移行（旧設定はdirectのまま）

## 今後の課題

- クラスタ全体での厳密な流量制限（現在の制限はEdgeごと）
- 2ホップ以上の経路探索
- テナントによるWasmプラグインのアップロードAPI
- Alias・加重ルーティングなどプロバイダー固有のDNS設定の取り込み
- 性能基準の測定（機能無効時との比較でp50/p95/p99、スループット、CPU、メモリ）
