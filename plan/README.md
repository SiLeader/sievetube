# 今後の拡張要素の実装計画

作成日: 2026-09-11。対象は[README第7節](../README.md)の4項目。現行ソースを確認して作成した計画であり、機能の実装や依存ライブラリの追加は行わない。

## 計画一覧

| 対象 | 詳細 | 初期到達点 |
| --- | --- | --- |
| ACME証明書自動更新 | [01-acme.md](01-acme.md) | 単一Edgeでの発行・更新・無停止反映 |
| Rate Limiting・IPブロック | [02-traffic-policy.md](02-traffic-policy.md) | HTTP/HTTPSのリクエスト単位制限とCIDRブロック |
| DNS自動登録・更新 | [03-dns.md](03-dns.md) | Cloudflare・Route 53での明示的な公開レコード管理 |
| Edge間内部転送メッシュ | [04-edge-mesh.md](04-edge-mesh.md) | 1ホップのHTTP/TCP中継から段階導入し、将来の標準構成へ移行 |

## 確定した方針

Q1〜Q3はすべてユーザー回答により確定。以下を実装計画の前提とする。実際の利用ゾーン・認証情報は導入時の設定とし、計画作成や共通実装の着手条件にはしない。

| ID | 確認事項 | 決定と影響 |
| --- | --- | --- |
| Q1 | Edge間メッシュを任意機能にするか、将来の標準構成にするか | **確定: 将来の標準構成としてEdge間転送へ移行する。** READMEの設計思想・トポロジを改訂し、段階導入後に新規構成の既定を切り替える。既存構成には明示的な移行手順を提供する |
| Q2 | DNSプロバイダーとACME検証方式 | **確定: HTTP-01を基本とし、Cloudflare・Route 53の両アダプターを実装する。** 実際の利用先は未定。DNS共通層と両アダプターの完成後にDNS-01を追加する |
| Q3 | 制限機能の初期対象 | **確定: HTTP/HTTPSを先行し、TCP/UDP・Wasmを段階的に追加する。** |

## 現状と共通の前提作業

- [listener.rs](../sievetube-edge/src/listener.rs)はHTTPを最大4096バイトの一度のpeekでHost抽出し、その後は接続全体を転送する。HTTPSはSNIで振り分け、ALPNにHTTP/1.1とh2を設定する。リクエスト単位ポリシーのためにHTTP処理を導入する必要がある。
- [tls.rs](../sievetube-edge/src/tls.rs)はArcSwapによる再読み込みを持つが、[main.rs](../sievetube-edge/src/main.rs)に更新トリガーがない。証明書ディレクトリがない場合、HTTPSリスナー自体を起動しない。
- [valkey.rs](../sievetube-edge/src/valkey.rs)の所有権確認と登録は別処理で、登録はSETによる上書き。接続先Edge集合にはTTL・到達アドレスがない。[quic_server.rs](../sievetube-edge/src/quic_server.rs)ではValkeyエラー時にも登録を許す。自動管理・メッシュでは、この状態をそのまま認可や経路の根拠にしない。
- [connector_registry.rs](../sievetube-edge/src/connector_registry.rs)はテナント単位で削除する。旧接続終了が新接続を消さないよう接続世代IDを追加し、登録・削除の競合を解消する。
- [router.rs](../sievetube-edge/src/router.rs)はローカルのhostname検索のみでprotocol引数を使用していない。将来の経路ではhostname・protocol・テナントの認可情報を一貫して扱う。
- QUICのConnector用証明書は自己署名で、[quic_client.rs](../sievetube-connector/src/quic_client.rs)はサーバー証明書を検証しない。新設するEdge間接続には流用せず、相互認証を必須にする。Connector側の検証導入もメッシュ移行前の関連改善として扱う。

共通作業P0として、ホスト名の正規化、所有権の原子的な取得、接続世代を考慮した削除、設定検証を実装する。自動発行・DNS変更・遠隔経路広告は管理者が許可したドメインだけを対象とし、制御状態を確認できなければ新規変更を停止する。既存転送を継続できるかは機能ごとの障害方針に従う。

## 実施順序と依存関係

1. **P0: 共通基盤** — 上記の所有権・世代管理、段階導入用の機能設定、既存動作の回帰テストを整備する。メッシュは移行期間中のみ既定無効とし、M5で標準構成へ切り替える。
2. **P1: HTTP処理・証明書ストア** — 02のB1と01のA1を実装する。A2のHTTP-01もB1のHTTP処理を再利用する。
3. **P2: 運用機能の初期版** — A2（単一Edge ACME）、B2（組み込み制限）、D1〜D2（DNS共通層・Cloudflare・Route 53）をそれぞれ独立した変更として実装する。
4. **P3: 複数Edgeへの対応** — D3（DNS-01）、A3（発行協調・配布）、B3（TCP/UDP）、B4（Wasm）を段階導入する。HTTP-01の基本対応を先行し、DNS-01はCloudflare・Route 53の両方で追加検証する。
5. **P4: メッシュの標準化** — M1〜M3、続いてUDPのM4、標準構成への移行M5を実施する。ACME・DNSの完成はメッシュの必須条件ではないが、P0と相互認証・経路リースは必須。

各IDは詳細文書の実装単位。期間は人員・DNS環境・対応範囲が未確定のため固定しない。まず各初期到達点をPRへ分割し、PoCで難度を確かめて見積もる。

## 共通の完了条件・導入方法

- 既存の設定例で起動でき、機能無効時に既存HTTP/TCPのE2Eが通る。変更機能の正常系、競合、タイムアウト、再起動、外部依存停止をテストする。
- 設定例と運用手順に有効化、秘密情報の渡し方、監視、ロールバックを記載する。新規モジュール名・設定名は提案であり、現行APIとして説明しない。
- 高カーディナリティなIP・任意ホスト名・request_idをメトリクスラベルにせず、詳細は構造化ログへ記録する。秘密鍵・JWT・DNSトークンはログから除外する。
- 単一Edgeの検証環境から一部ドメインへ展開し、複数Edge・障害注入を通して対象を増やす。ACME/DNSの無効化で証明書や公開レコードを自動削除しない。
- 性能は同一環境の機能無効時と比較し、p50/p95/p99遅延、スループット、CPU、メモリを記録する。合格閾値はPoCで基準値を得て初期版の実装前に設定する。

実装時の基本チェック（今回の文書作成では未実行）:

```sh
cargo fmt --all -- --check
cargo build -p sievetube-edge -p sievetube-connector
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

統合テストはビルド済みバイナリを起動するため、先にbuildする。現行E2EはHTTP/TCPを中心とするため、HTTPS・UDP・Valkey・複数Edgeのハーネスを追加する。ACME/DNSは通常CIではローカルテストサーバー／モックを使い、実サービス検証は分離する。
