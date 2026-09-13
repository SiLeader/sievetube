# アーキテクチャ

## コンポーネント

```text
                               ┌─────────────────────────────┐
 Internet ── HTTP(S)/TCP/UDP ─▶│ Edge                        │
                               │ ・公開 TLS の終端            │
                               │ ・認証済み経路の選択          │
                               │ ・ポリシー、DNS、監視         │
                               └──────────────┬──────────────┘
                                              │ QUIC / UDP
                                              │ Connector から開始
                               ┌──────────────▼──────────────┐
 Private network               │ Connector                   │
                               │ ・JWT 認証                   │
                               │ ・Ingress の照合             │
                               │ ・ローカル接続の確立          │
                               └──────────────┬──────────────┘
                                              │ TCP または UDP
                               ┌──────────────▼──────────────┐
                               │ Local service               │
                               └─────────────────────────────┘
```

- `sievetube-edge` は公開リスナー、Connector 用 QUIC リスナー、Health/Metrics リスナーを持ちます。
- `sievetube-connector` は設定された各 Edge に外向きで接続し、Edge が開いたストリームをローカルターゲットへ中継します。
- `sievetube-common` は JWT、設定、ホスト名、トンネルのワイヤープロトコルを共有します。
- Valkey/Redis は単一 Edge の direct 構成には必須ではありません。ホスト名所有権、Edge の存在、メッシュ経路、分散リースなどの制御プレーンに使います。

## 接続の確立

1. Connector が `network.public_servers` の各 Edge へ QUIC 接続を開始します。
2. Connector は JWT と、Ingress から生成した「ホスト名ごとの対応プロトコル」を送ります。
3. Edge は JWT の HMAC-SHA256 署名と有効期限を検証し、`sub` をテナント ID、`hostnames` を公開可能な名前の上限として扱います。
4. Edge は認証済み Connector を登録します。同じ Edge 上では 1 テナントにつき 1 接続で、新しい接続が古い接続を置き換えます。
5. 停止時、Connector は Going Away を通知します。Edge はその接続へ新しい通信を割り当てず、処理中のストリームだけを drain します。

QUIC の ALPN は `sievetube/1` です。制御フレームには認証、接続要求、停止通知があり、アプリケーションデータは接続要求に続く双方向ストリーム上で転送されます。

## リクエストの経路

### HTTP / HTTPS

1. Edge が HTTP リクエストを受け取ります。HTTPS は SNI に対応する公開証明書で TLS を終端します。
2. 正規化したホスト名と `http` プロトコルで経路を検索します。
3. 経路があれば Connector への QUIC ストリームを開き、HTTP を転送します。
4. Connector は Ingress を上から評価し、最初に一致したローカルアドレスへ TCP 接続するか、`http_status:<code>` を返します。

Edge の `http.forwarded_headers = true` では `X-Forwarded-For` と `X-Forwarded-Proto` を設定します。ポリシーが既存の `X-Forwarded-For` を信用するのは、直前の接続元が `policy.trusted_proxies` に含まれる場合だけです。

### Raw TCP

TCP には Host ヘッダーがないため、Edge の `[[server.tcp_listen]]` でリスナーに論理ホスト名を割り当てます。Connector 側には、同じ `hostname` と `protocol = "tcp"` の Ingress が必要です。接続ごとに 1 本の QUIC ストリームを使います。

### UDP

UDP も `[[server.udp_listen]]` の論理ホスト名で経路を決めます。転送モデルは 1 要求・1 応答で、継続的な UDP セッションや複数応答を前提にしていません。応答待ち状態には時間と件数の上限があります。

## ルーティングモード

### direct

Edge に直接つながっている Connector だけを利用します。構成が単純で Valkey は任意ですが、複数 Edge のすべてから同じサービスを公開するなら Connector は各 Edge に接続する必要があります。

### mesh

ローカル Connector がない場合、Valkey 上の有効な経路広告を使って、Connector を保持する peer Edge へ転送します。ローカル経路が常に優先されます。peer 間は専用 CA の mTLS で相互認証し、Edge ID と証明書の ID を照合します。

```text
Client ─▶ Edge A ── mTLS/QUIC ─▶ Edge B ◀── QUIC ── Connector ─▶ Service
            │                     │
            └──── Valkey 上の経路広告・リース ────┘
```

peer が要求を受理する前の失敗だけが別候補で再試行されるため、受理済みリクエストが二重配送されることはありません。進行中のストリームは Edge 障害時に引き継がれません。

## セキュリティ境界

Sieve Tube には用途の異なる 3 種類の資格情報があります。

| 境界 | 資格情報 | 役割 |
| --- | --- | --- |
| Connector → Edge | JWT と Edge の QUIC 証明書 | Connector の権限確認、接続先 Edge の確認 |
| 利用者 → Edge | 公開 HTTPS 証明書 | 公開ホスト名の TLS 終端 |
| Edge ↔ Edge | mesh CA が署名したクライアント/サーバー証明書 | peer の相互認証と Edge ID の確認 |

JWT は「どのホスト名を広告できるか」を制限します。Connector の Ingress は「その中のどのプロトコルをどこへ転送するか」を制御します。どちらか片方だけでは公開経路は成立しません。

Connector が Edge 証明書を検証しない構成では、JWT と転送データを偽の Edge に送る中間者攻撃を防げません。本番では CA 検証または SHA-256 証明書ピンを必ず設定してください。

## 障害時の性質

- Connector が切断されると、その Edge のローカル経路は利用できなくなります。Connector は再接続を試みます。
- direct では別 Edge に Connector が接続していても自動転送されません。
- mesh では Valkey 障害後も既存広告は TTL まで使えますが、新しい広告やホスト名所有権の取得は止まります。
- Edge または Connector の停止時は新規受付を止め、設定された drain timeout まで処理中通信を待ちます。
- `/healthz` はプロセスの生存、`/readyz` はトラフィックを受けられる状態の判定に使います。ロードバランサーから外す判定には通常 `/readyz` を使います。

