# SeCute

自分の環境に関係するセキュリティ情報だけを追い、検査し、記録するための個人用ツールセット。

- **Tracker**：脆弱性情報（CISA KEV / OSV など）を取り込み、資産インベントリと突き合わせて「要対応」だけを追う Web アプリ
- **Harness**：リポジトリやイメージを、使い捨ての Docker サンドボックスで安全に検査する CLI
- **Reports / Articles**：蓄積した記録から、報告書（正式な記録）とカジュアルな解説記事（読み物）を同じデータで作る

設計の全体像は [docs/design-2026-11-06.md](docs/design-2026-11-06.md) を参照。

## クイックスタート（Tracker）

```bash
docker compose up -d --build
# 資産の初期登録（例）
curl -X POST localhost:8080/api/ingest/seed -H 'Content-Type: application/json' \
  -d @tracker/config/assets.example.json
# 脆弱性情報の取り込み
curl -X POST localhost:8080/api/ingest
# ダッシュボード
open http://localhost:8080/
```

Tracker は個人用の前提。compose はポートを localhost にだけ bind する。公開ネットワークには出さず、リバースプロキシやアクセス制御の内側で使うこと。`SECUTE_API_TOKEN` を設定すると、書き込み系 API（資産登録・取り込み・項目更新）に `X-API-Token` ヘッダーが必須になる。

取り込みまわりの性質：

- ソース（KEV / OSV）は独立に取り込まれ、片方が失敗しても他方は進む。実行結果は `GET /api/ingest/runs` で確認できる
- 脆弱性データはソースごとに保持され、表示用の統合ビューはそこから再構築される。再取り込みで他ソースの情報が消えることはない
- 資産にバージョンがあり OSV が影響範囲を公開している場合、範囲で照合する（範囲外は項目化しない）。照合方法と根拠は項目の `match_method` / `match_reason` に残る
- 自動照合で生まれた項目は `unconfirmed` から始まる。確定は人が status を進めて行う

## Harness（サンドボックス検査）

```bash
# スキャナイメージのビルド（初回のみ）
docker build -f harness/Dockerfile.scanner -t secute-scanner harness

# リポジトリを検査（ネットワーク遮断、対象は読み取り専用マウント）
python3 harness/seccheck.py run --target /path/to/repo --profile repo --out results/
```

結果は `results/<日時>/report.json`（正規化済み）と各ツールの生出力。詳しくは [harness/README.md](harness/README.md)。

## テスト

```bash
pip install -r tests/requirements.txt
python -m pytest            # ユニットテスト（Docker 不要）
python -m pytest -m docker  # ハーネスの隔離を実コンテナで確認（Docker が必要）
```

Tracker の DB・取り込み・API と、Harness のチェック別ステータスや検査証跡（ツール版数・対象 commit・生出力のハッシュ）を検証する。Docker 統合テストは Docker のない環境では自動でスキップされる。

## 構成

| パス | 内容 |
|---|---|
| `docs/` | 設計書 |
| `tracker/` | 脆弱性トラッカー（FastAPI + SQLite） |
| `harness/` | サンドボックス検査ハーネス（Docker + gitleaks / osv-scanner / trivy） |
| `tests/` | pytest によるテスト一式 |
| `templates/` | 報告書・記事のテンプレート |
| `skills/secute/` | 運用手順をまとめたエージェント向け SKILL |

## 進捗

- Phase 1（トラッカー読み取り専用版）：KEV / OSV 取り込み、資産登録、一覧・詳細 API、ダッシュボード
- Phase 2（ハーネス最小版）：repo プロファイル（gitleaks + osv-scanner）をサンドボックスで実行し JSON を出力
- Phase 3（統合）：状態管理の運用、報告書・記事の生成、日次ダイジェスト連携
