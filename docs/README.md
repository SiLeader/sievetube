# Sieve Tube ドキュメント

Sieve Tube は、非公開ネットワーク内のサービスを、インターネットから到達可能な Edge 経由で公開するセルフホスト型リバーストンネルです。非公開側の Connector から Edge へ QUIC 接続を開始するため、サービス側ネットワークに受信用ポートを開けずに HTTP、HTTPS、TCP、UDP を転送できます。

> [!IMPORTANT]
> 現在のバージョンは `0.1.0` です。本番導入前に、特に Connector と Edge 間の証明書検証、JWT の保管、公開ポート、監視方法を確認してください。

## 読み方

| 目的 | ドキュメント |
| --- | --- |
| まず 1 台の Edge で動かす | [スタートガイド](getting-started.md) |
| コンポーネントと通信経路を理解する | [アーキテクチャ](architecture.md) |
| Edge / Connector の設定を確認する | [設定ガイド](configuration.md) |
| 証明書、監視、DNS、メッシュを運用する | [運用手順](operations.md) |
| 起動や疎通の問題を切り分ける | [トラブルシューティング](troubleshooting.md) |

全設定項目の正確な一覧は、コメント付きの [`config/edge.example.toml`](../config/edge.example.toml) と [`config/connector.example.toml`](../config/connector.example.toml) を参照してください。

## 最小構成

```text
利用者 ── HTTP(S) / TCP / UDP ──▶ Edge ◀── QUIC (UDP) ── Connector ──▶ ローカルサービス
                                       非公開側から開始
```

- Edge は公開トラフィックと Connector 接続を受け付けます。
- Connector は JWT で認証し、許可されたホスト名と対応プロトコルを Edge に通知します。
- HTTP/HTTPS はリクエストのホスト名、Raw TCP/UDP は Edge のリスナーに割り当てたホスト名で転送先を決めます。
- 単一 Edge では `routing.mode = "direct"` を使います。複数 Edge 間で転送する場合は Valkey と mTLS を構成して `mesh` を使います。

## 関連ファイル

- [`README_ja.md`](../README_ja.md): 機能概要と短いクイックスタート
- [`README.md`](../README.md): 英語版 README
- [`config/`](../config): 実行可能な設定例
- [`tests/integration/`](../tests/integration): プロトコル別の End-to-End テスト

