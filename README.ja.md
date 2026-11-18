# aws-waf-java4shell-base64-guard

[English](README.md)

Java4Shell（CVE-2026-114938）のトリガーになる「不正な Base64 トークン」を含むリクエストを、**Count（または Block）** する AWS WAF の CloudFormation サンプルです。パッチを当てるまでの検知と、WAF メトリクスの確認が目的です。

**これは修正ではありません。** JDK を更新するか、JVM を `-XX:-UseBASE64Intrinsics` で起動してください。Wiz は、デコーダに到達するコード経路は多いため、WAF ルールで全経路を覆うのは難しく、自社開発アプリは完全には覆えないとしています: https://www.wiz.io/blog/cve-2026-114938-rce-java4shell-openjdk

> **状態（2026-11-18）:** テンプレートは `cfn-lint` を通り、正規表現は `test/` のローカルテストを通っています。**AWS へのデプロイはまだ行っていません。** そのため、AWS WAF が正規表現を受け付けるか、各フィールドが想定どおり Count されるかは未確認です。「確認済みのこと・未確認のこと」を参照してください。

## Java4Shell の概要

- OpenJDK HotSpot の x86-64 向け Base64 デコード intrinsic にある、ヒープの境界外書き込みです。末尾に `=` がある不正な文字列で出力長が負になり、intrinsic が 64 バイトを書き込みます。Java は後から `IllegalArgumentException` を投げますが、書き込みは済んでいます。
- トリガー入力: `A` ×64 + `=`（OpenJDK 17 は `A` ×128 + `=`）。
- 対象: OpenJDK 17.0.6 以降、21、25、27、およびその派生ビルド。AVX-512 VBMI を持つ x86-64 CPU（Intel Ice Lake 以降、AMD Zen 4 以降）で動く場合のみです。ARM64 は対象外です。標準の Java 8 と 11 は対象外で、Oracle は Java 8 Performance Pack ビルド `8u511b33-perf` を対象として挙げています。
- 出典: [Calif の解説](https://calif.io/java4shell/)、[OpenJDK 勧告](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)、[CISA アラート](https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching)、[Wiz](https://www.wiz.io/blog/cve-2026-114938-rce-java4shell-openjdk)、[Upwind](https://www.upwind.io/blog/java4shell-what-we-know-now-and-what-comes-next)。

## 暫定対応の優先順位

1. **JVM フラグ `-XX:-UseBASE64Intrinsics`**。アプリの変更が要らず、原因のコードを止めます。`JAVA_TOOL_OPTIONS` 環境変数で渡せば、再ビルドなしで適用できます。コンテナは再作成して、設定が実プロセスに届くようにしてください。x86-64 では `-XX:UseAVX=2` も使えますが、ARM の JVM はこのフラグを認識せず起動に失敗するので、ARM が混在する環境では避けます。`-XX:DisableIntrinsic=_base64_decodeBlock` は単独で使わないでください。Upwind によると、JVM が起動しなくなります。
2. **パッチ適用**。Upwind によると、Oracle の修正版は末尾が `.1` です（17.0.21.1、21.0.13.1、25.0.5.1、27.0.1.1）。この番号は Oracle の勧告では確認できていないので、利用中のディストリビューションで確認してください。
3. **この Web ACL**。まず Count モードで使います。
4. **インベントリの確認**。同じイメージでも、動くノードの CPU によって影響の有無が変わります。Linux ホストの確認方法（Calif の記載）です。
   ```bash
   grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$'
   ```
   4 つのフラグがすべて出力されれば、そのホストは脆弱なハードウェア経路を通ります。

## Web ACL の内容

4 つのルールを持つ Web ACL です（デフォルトアクションは Allow）。4 つとも同じ正規表現パターンセットを参照します。

| 優先度 | ルール | 検査対象 |
|---|---|---|
| 10 | `MalformedBase64-AuthorizationHeader` | `Authorization` ヘッダー |
| 20 | `MalformedBase64-CookieValues` | すべての Cookie の値 |
| 30 | `MalformedBase64-QueryString` | クエリ文字列（そのままと URL デコード後） |
| 40 | `MalformedBase64-Body` | body（ALB は先頭 8KB） |

値の中に、次の条件を満たすトークンがあると一致します。

- 値の先頭、または `A-Za-z0-9+/_-` 以外の文字の直後から始まる。
- その文字種が 32 文字以上続く（Upwind の検知の目安です。Calif のトリガーは 64 文字以上、OpenJDK 17 では 128 文字以上）。
- 末尾が `=` で、その並びが正規のパディングになっていない。正規のパディングは、4 文字ずつの塊のあとに、文字 2 つ + `==`、または文字 3 つ + `=` が来る形です。

たとえば `A` ×64 + `=` は一致し、`...AA==` のように正しくパディングされた値や、パディングなしの値（JWT の各部分）は一致しません。正規表現は Calif の解説にある擬似コードから導いたもので、トリガー条件は私の推測を含みます。一致しなかったことは「見ていない」であり、「安全」ではありません。

## デプロイ

```bash
aws cloudformation deploy \
  --stack-name waf-java4shell-base64 \
  --template-file template.yaml \
  --region ap-northeast-1 \
  --parameter-overrides \
      Scope=REGIONAL \
      RuleAction=Count \
      AssociateResourceArn=arn:aws:elasticloadbalancing:REGION:ACCOUNT_ID:loadbalancer/app/NAME/ID
```

最初は `RuleAction=Count` にして、CloudWatch のメトリクスとサンプルリクエストを確認します。正規のリクエストが Count されないと分かってから `Block` に切り替えてください。スタックを削除すれば、作成したものはすべて消えます。

### パラメータ

| 名前 | 既定値 | 説明 |
|---|---|---|
| `Scope` | `REGIONAL` | `REGIONAL`（ALB、API Gateway、AppSync など）か `CLOUDFRONT`。CloudFront は `us-east-1` にデプロイします。 |
| `RuleAction` | `Count` | `Count` か `Block`。 |
| `WebAclName` | `java4shell-base64-count` | メトリクス名の接頭辞にも使います。 |
| `AssociateResourceArn` | （空） | 空なら Web ACL だけを作ります。1 つのリソースに付けられる Web ACL は 1 つなので、関連付けると、すでに付いているものを**置き換えます**。先に確認してください。CloudFront の場合は、ディストリビューション側で Web ACL の ID を指定します。 |

すでに Web ACL がある場合は、この Web ACL を付け替えるのではなく、4 つのルールとパターンセットをその Web ACL に追加してください。

## 限界

- **すべての経路が WAF を通るわけではありません。** 内部呼び出し、キューのメッセージ、S3 イベント、Web ACL を付けていないリスナーは検査されません。
- **body の検査範囲には上限があります。** ALB が WAF に渡すのは先頭 8KB（固定）です。CloudFront と API Gateway は既定で 16KB で、Web ACL の `AssociationConfig` で最大 64KB まで拡張できます。body のルールは `OversizeHandling: CONTINUE` なので、上限を超えた位置のトークンは見えません。`MATCH` と `Block` を組み合わせると、大きなアップロードをすべて拒否します。
- **別の形式に包まれると見逃します。** body の中の URL エンコード、JSON のエスケープ（`\u003d`）、gzip、multipart の各パートはデコードされません。URL デコード後も検査するのはクエリ文字列だけです。
- **ほかの値の中の Base64**（Cookie の中の JWT など）は、不正なトークンが上の条件どおりに始まり、終わる場合にだけ見つかります。
- **リクエストのストリーミング。** Calif によると、一部の攻撃は部分的なリクエスト body を使います。body 全体をバッファするプロキシ（nginx は既定でそうします）はそれらを止めますが、すべてではありません（Elasticsearch の手法は完全な 1 リクエストで成立します）。
- **Count が示すのは一致したルールだけです。** 攻撃かどうかは分かりません。
- **費用。** AWS WAF は Web ACL、ルール、リクエストに課金されます。AWS の料金ページを参照してください。

## 確認済みのこと・未確認のこと

確認済み（2026-11-18）:
- `cfn-lint` が通る（`python:3.12` のコンテナで実行）。
- `python3 test/test_patterns.py` が通る。一致すべき 13 件（トリガー文字列、各文字種、JSON、クエリ文字列、Cookie）と、一致すべきでない 10 件（正規のパディング、パディングなし、短いトークン、UUID、通常の文章）。

未確認:
- デプロイと、AWS WAF による正規表現の受理（テストは Python の `re` を使っており、これらのパターンでは RE2 に近いものの、同じエンジンではありません）。
- 実際の ALB で 4 つのフィールドが Count されること、実トラフィックでの誤検知の割合。
- 実際の脆弱な JVM に対するルールの動作。

## テスト

```bash
python3 test/test_patterns.py
```

デプロイ後は、自分が所有するテスト用 ALB に、無害な不正トークン 1 件と正規のトークン 1 件を送り、CloudWatch のルールのメトリクス（`java4shell-base64-count-authorization` など）を比べます。まだ実行していません。

```bash
# "A" ×64 + "=" : Count されるはず
curl -i -H "Authorization: Basic $(printf 'A%.0s' {1..64})=" http://<alb-dns-name>/
# 正規の Basic 認証 : Count されないはず
curl -i -u user:pass http://<alb-dns-name>/
```

これらのリクエストは不正な文字列を含むだけです。ただし、脆弱な JVM では 1 つ目が、Calif の説明にある境界外書き込みを引き起こす可能性があります（Calif の PoC では配列内に収まる小さな上書きですが、稼働中のサービスでは実際のヒープ破壊です）。自分が所有するテスト環境にだけ送り、できれば `-XX:-UseBASE64Intrinsics` を付けた状態で試してください。

## ライセンス

MIT。[LICENSE](LICENSE) を参照してください。
