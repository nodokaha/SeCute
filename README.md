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

Tracker は個人用の前提で、認証を持たない。公開ネットワークには出さず、リバースプロキシやアクセス制御の内側で使うこと。

## Harness（サンドボックス検査）

```bash
# スキャナイメージのビルド（初回のみ）
docker build -f harness/Dockerfile.scanner -t secute-scanner harness

# リポジトリを検査（ネットワーク遮断、対象は読み取り専用マウント）
python3 harness/seccheck.py run --target /path/to/repo --profile repo --out results/
```

結果は `results/<日時>/report.json`（正規化済み）と各ツールの生出力。詳しくは [harness/README.md](harness/README.md)。

## 構成

| パス | 内容 |
|---|---|
| `docs/` | 設計書 |
| `tracker/` | 脆弱性トラッカー（FastAPI + SQLite） |
| `harness/` | サンドボックス検査ハーネス（Docker + gitleaks / osv-scanner / trivy） |
| `templates/` | 報告書・記事のテンプレート |
| `skills/secute/` | 運用手順をまとめたエージェント向け SKILL |

## 進捗

- Phase 1（トラッカー読み取り専用版）：KEV / OSV 取り込み、資産登録、一覧・詳細 API、ダッシュボード
- Phase 2（ハーネス最小版）：repo プロファイル（gitleaks + osv-scanner）をサンドボックスで実行し JSON を出力
- Phase 3（統合）：状態管理の運用、報告書・記事の生成、日次ダイジェスト連携
