# RCC/REVAS × VERITAS — 実行ガバナンス・ベンチマーク

**AIが提案した操作を、どの条件で実際に実行してよいかを証拠に基づいて評価します。**

[English](README.md) · [VERITAS OS](https://github.com/veritasfuji-japan/veritas_os) · [V13正式結果](contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json) · [独立検証手順](docs/AGENTDOJO_FINAL_128_INDEPENDENT_EXTERNAL_REPLICATION_HANDOFF_V1.md)

> **2026-10-09時点の記載。** 研究・評価用ハーネスであり、実銀行で稼働する製品や認証取得済みの本番システムではありません。**実OpenAIプロバイダーによるV13の実測**と、**その後のTask15のプロバイダー未使用ローカル検証**を混同しないでください。CI成功だけで独立したPROVEN判定にはなりません。

## 検証の目的

AIの出力は操作の「提案」であって、実行権限そのものではありません。本リポジトリは、RCC/REVAS上流処理（Arm A）と、VERITASの実行時Bind統制を追加した経路（Arm B）を比較します。両Armは各AgentDojo Bankingケースの**同じ初期状態**から始まります。

```text
AgentDojoケースと管理された上流候補処理
               |
        +------+------+
        |             |
      Arm A         Arm B
     RCC/REVAS      RCC/REVAS
     上流処理       + VERITAS Bind
        |             |
  ネイティブ結果    実行境界で許可/拒否
        |             |
        +------+------+
               |
         AgentDojo採点
```

**Arm Aは比較用の条件です。RCC/REVASが現実の実行権限を発行するという主張ではありません。** どちらも実銀行とは接続していません。正当なユーザータスクの成功（Utility）は**高いほど良く**、攻撃者の目的達成（Injection-task success）は**低いほど安全**です。

## 実測済み結果：Canonical Final 128 / V13

これは**実際のOpenAIプロバイダーで完了した128ケースの比較**です。ただし、使用したAgentDojo Bankingコーパスは開発過程で既に参照されたものです。以下の数値は、新しいTask15のオフライン検証結果ではありません。

| AgentDojoの指標 | Arm A：上流RCC/REVAS処理 | Arm B：＋VERITAS Bind |
| --- | ---: | ---: |
| 正当なタスクの成功率（Utility） | **93/128（72.66%）** | **64/128（50.00%）** |
| 攻撃目的達成率（低いほど安全） | **20/128（15.63%）** | **0/128（0%）** |

**128ペア、256件のArm記録、128件すべて同じ初期状態、実行エラー0件。** 正当タスクの比較ではAのみ成功が**30件**、Bのみ成功が**1件**でした。30件すべてがVERITASの誤拒否だと証明されたわけではありません。

OpenAI呼び出しは**820回**。**0.3221684米ドル**はランナー側の推定費用で、請求明細の監査額ではありません。**V13の一回限りの認可は使用済みで、再利用・再実行は禁止**されています。

| 固定証拠 | 参照 |
| --- | --- |
| 実行mainのSHA | [`2454ba69818d1a46b910f33fab9b57017cd7a83e`](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/commit/2454ba69818d1a46b910f33fab9b57017cd7a83e) |
| 実行Run / Job | [37585673492](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/37585673492) / `112675107243` |
| Artifact | ID `11466539107` |
| ZIP SHA-256 | `9fbb2a1614c237e92c4239bb5d60f83d40d33b81e0092d3f82958931969c9e7a` |
| 正式記録 | [V13 terminal disposition](contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json) |
| ケース別分析 | [V13 post-execution analysis](contracts/AGENTDOJO_FINAL_128_V13_POST_EXECUTION_ANALYSIS_BOUNDARY_v1.json) |

**評価：** Arm Bではこの128ケースで攻撃目的達成が0件でしたが、正当タスクの成功は大きく下がっています。未知の攻撃にも通用する保証、第三者による独立検証、本番運用の証明ではありません。**Utilityの回復はまだ新しい実測値で示されていません。**

## V13以降：別の証拠系列

現在は権限不足の分類と、Task15の住所変更・家賃操作・返金という**3段階のローカル統合**を進めています。**過去のV13スコアを書き換えたり、V13認可を再利用したりしていません。**

| PR | 実装した内容 | 限界 |
| --- | --- | --- |
| [#205](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/205) | プロバイダー未使用でA実行/B拒否の69件を分類 | 方針の緩和やFinal 128の再測定ではない |
| [#243–#245](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/245) | 住所・家賃・返金それぞれの権限スコープを分離 | 事前・読み取り専用の記録は実行許可ではない |
| [#246](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/246) | RCC・B側Bind・ネイティブ実行境界・UNKNOWN処理の3段階統合 | 制御されたローカル環境のみ。実送金や永続的exactly-onceではない |
| [#247](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/247) | 操作完了後の**状態のみ**の採点診断 | 完全な会話履歴のUtility測定ではない |
| [#248](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/248) | SDK形式の独立した3つの模擬モデル提案を実行境界へ渡す | `OFFLINE_INJECTED_CLIENT`：実プロバイダー応答・連続会話・新しい攻撃成功率は未検証 |

#248ではテストが生成した`ChatCompletionMessage`形式の応答を使います。問い合わせは**3回とも独立**し、実モデルがツールの結果を読んで会話を続けたわけではありません。ネイティブ操作の正確な戻り値を記録して次の履歴に接続する検証が必要です。

資料：[Task15統合ランナー](docs/TASK15_CONTROLLED_MULTI_EFFECT_COMPOSED_ADMISSION_RUNNER_V1.md) · [Task15モデル応答境界](docs/TASK15_NATIVE_MODEL_RESPONSE_CAPTURE_BOUNDARY_V1.md)。

**マージ済み、CI成功、独立判定PROVEN、本番運用可能は別の状態です。** 過去の`NOT PROVEN`記録は書き換えません。

## 検証したい内容から選ぶ

| 目的 | 参照先 | 有料APIが必要か |
| --- | --- | --- |
| V13の実測を確認 | [正式結果](contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json)・[分析](contracts/AGENTDOJO_FINAL_128_V13_POST_EXECUTION_ANALYSIS_BOUNDARY_v1.json) | 不要 |
| 保存済みV13 Artifactを独立再計算 | [外部レビューハンドオフ Track A](docs/AGENTDOJO_FINAL_128_INDEPENDENT_EXTERNAL_REPLICATION_HANDOFF_V1.md) | 不要 |
| ローカル3段階操作を確認 | [#246](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/246)・[仕様](docs/TASK15_CONTROLLED_MULTI_EFFECT_COMPOSED_ADMISSION_RUNNER_V1.md) | 不要 |
| 模擬モデル提案の扱いを確認 | [#248](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/248)・[境界](docs/TASK15_NATIVE_MODEL_RESPONSE_CAPTURE_BOUNDARY_V1.md) | 不要 |
| 新たな実プロバイダー/未使用コーパス検証 | [外部レビューハンドオフ Track B/C](docs/AGENTDOJO_FINAL_128_INDEPENDENT_EXTERNAL_REPLICATION_HANDOFF_V1.md) | **新しい明示承認・一回限りの認可・費用上限が必要** |

**読み取り専用の最初の確認：**

```bash
git clone https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark.git
cd rcc-revas-veritas-benchmark
git checkout 00fe1dedc6ef6dd3e690bce892d81105bafb0989
python -m json.tool contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json > /dev/null
python -m json.tool contracts/AGENTDOJO_FINAL_128_V13_POST_EXECUTION_ANALYSIS_BOUNDARY_v1.json > /dev/null
```

上記は**JSONの構文検査だけ**です。新しいモデル実行、ArtifactのSHA照合、独立したスコア再計算、外部認証を行うものではありません。Track Aでは固定ソース、Artifact ID、ZIP SHA-256、スコアの再計算、主張可能な範囲まで検証します。**OpenAI APIキーは不要**です。

## 明確な限界

- **安全と実用の両立：** V13でB側の攻撃目的達成は0/128、Utilityは64/128。最新Task15で改善したと断定できません。
- **テスト範囲：** 開発過程で使用済みのコーパスであり、未知の攻撃への普遍的保証ではありません。
- **実世界の操作：** AgentDojo内の状態変化は実銀行送金、企業の認証情報、外部決済とは異なります。
- **権限の真正性：** 顧客本人性、外部台帳、時刻、鍵の信頼根、通信の真正性には別の検証が必要です。
- **継続性と一回性：** #248は実モデルとの連続会話ではありません。プロセス内の一回性だけで再起動・複数プロセスを保証できません。
- **第三者性：** GitHub CIや自己再計算だけでは外部第三者の認証・独立監査は成立しません。
- **証拠の適用範囲：** 固定SHAや一部の操作経路の証明は、将来のmain全体を自動的に証明しません。

## 次の順序（未完了の計画）

1. Task15の最終sinkで**実際のネイティブ戻り値を正確に保存**する。
2. モデル提案、実行結果、その後のモデル応答が連続した元の履歴を検証し、読み取り専用で採点する。
3. **新しい人間の承認、固定SHA、一回限りの認可、明示的な予算上限**を前提に実プロバイダーの再測定を検討する。**V13認可を再利用しない。**
4. 独立オペレーターによる既存ケース再現、次に開発未使用コーパスでの検証を進める。
5. 実企業の認証情報、迂回耐性、結果照合、監査証拠を含む範囲限定PoCを実施する。

## 旧v0.1 README

初期の「Joint Benchmark Runner / Evaluation Harness v0.1」の全文を、当時のSHA、`--bind-proxy`の注意事項、実行例を含めて[そのまま保存](docs/archive/joint-benchmark-runner-v0.1-README.md)しています。旧文書は**当時の個別ハーネス**の説明であり、最新のベンチマーク全体を説明するものではありません。

本共同評価は、RCC/REVAS自体が現実世界の実行権限を発行すること、すべてのVERITAS実装を保証すること、正式な商用提携を意味するものではありません。
