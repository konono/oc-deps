# oc-deps architecture: Operator 関連リソースの探索と teardown 判断

## 1. この文書の目的

この文書は、`oc-deps` が Operator の関連リソースをどこから、どのような根拠で見つけるかを整理する。

主な用途は次のとおり。

- 本来見つかるべきリソースが plan に出ない原因を切り分ける
- 関係のないリソースが候補に出た理由を追跡する
- 新しい探索規則が deletion authority を意図せず広げていないか確認する
- 実 cluster から得た知見を、製品固有の分岐ではなく汎用的な evidence として追加する

この文書では、現在の実装と、安全上の設計規則を分けて記載する。実装が変わった場合は、この文書も同じ PR で更新する。

## 2. 最重要の区別

次の三つは別の概念である。

1. **Discovery**: リソースを候補集合に見つけること
2. **Attribution**: リソースが対象 Operator と関係している可能性を評価すること
3. **Deletion authority**: 現在の UID のリソースを削除してよいと判断すること

関係が見えるだけでは削除できない。

```text
discovered
  -> attributed
     -> REVIEW または deterministic safe rule
        -> fresh validation
           -> current UID binding
              -> DELETE authority
```

常に次を維持する。

```text
Attribution != deletion authority
API ownership != instance lifecycle ownership
Operator implementation attribution != lifecycle ownership
EXPECT_GONE != DELETE authority
WATCH observation != deletion authority
Saved Plan != runtime deletion authority
```

曖昧な関連は候補から捨てず、`REVIEW` と evidence を表示する。人の明示判断が必要な情報不足を、推論による自動 DELETE で埋めない。

## 3. Ownership の種類

Operator 周辺では、少なくとも三種類の ownership が現れる。

### 3.1 API ownership

CSV の `spec.customresourcedefinitions.owned` や `spec.apiservicedefinitions.owned` は、その Operator が API を提供することを示す。

```text
CSV -> provides -> CRD/APIService
```

これは CRD instance の削除権限を意味しない。instance はユーザーが作成した durable intent の可能性がある。CRD 自体の削除も `--prune-crds` の明示操作に限定する。APIService は常に KEEP（`--prune-crds` の対象外）。

### 3.2 Instance lifecycle ownership

Kubernetes `ownerReferences` は、同じ cluster scope の object 間で dependent lifecycle を表す。UID が一致する ownerRef chain は、現在利用できる最も強い lifecycle evidence である。

```text
root CR DELETE
  -> child Deployment EXPECT_GONE
  -> child Service EXPECT_GONE
```

namespaced owner から別 namespace または cluster-scoped dependent への ownerRef は使えない。この範囲では、ownerRef がないことを「無関係」の証明にはできない。

### 3.3 Operator implementation attribution

labels、annotations、managedFields manager、ServiceAccount、名前、namespace などは、controller が作成または操作した可能性を示す。

これらは mutable、共有可能、または衝突可能なので、通常は `REVIEW` の根拠として扱う。単独では lifecycle DELETE authority にしない。

## 4. 全体の探索パイプライン

```text
Kubernetes API discovery
  -> OLM identity discovery
  -> target-owned API discovery
  -> direct CR/APIService instance LIST
  -> related API discovery from exact label evidence
  -> ownerRef graph classification
  -> provenance classification
  -> ancillary namespace candidate discovery
  -> REVIEW/DELETE/EXPECT_GONE/KEEP plan
  -> pre-execution identity snapshot
  -> execution
  -> residual audit
```

resource graph は関係の説明に使う。実際の mutation は、UID-bound な action graph だけから行う。

## 5. Kubernetes API discovery

`src/kube/discovery.rs` は API server の discovery 情報から次の lookup を構築する。

- Kind から group/version/plural/scope を引く `KindMap`
- GVR から Kind を引く `GvrMap`
- `(group, kind)` と `(group, version, kind)` の lookup

CRD 名から plural を推測して DELETE や GET を行わず、可能な限り discovery の結果を使う。API を解決できない場合は、その API の instance を「存在しない」と扱わない。

```text
404 + endpoint LIST success -> object Gone
403 / timeout / transport error / API resolution failure -> Unknown
```

## 6. OLM identity の探索

`src/analyzers/olm.rs::discover_operators` は cluster-wide に CSV と Subscription を列挙する。

### 6.1 Subscription と CSV の対応

優先する根拠は次のとおり。

1. Subscription `status.installedCSV` または `status.currentCSV`
2. 同じ namespace に CSV が存在すること
3. Subscription `spec.name` と CSV の package evidence が矛盾しないこと
4. status が使えない場合は `operators.coreos.com/<package>.<namespace>` label を fallback に使う

複数 Subscription、矛盾する package evidence、同 namespace の未対応 Subscription は ambiguity として保持する。

Operator generation identity の package 名は Subscription `spec.name` から取得する。Subscription の `metadata.name` や CSV prefix から package 名を推測しない。

### 6.2 CSV から保存する情報

CSV から次を抽出する。

- owned / required CRDs
- owned / required APIService definitions
- install strategy の controller Deployments
- permissions / clusterPermissions の ServiceAccounts
- CSV UID、namespace、phase

controller Deployment と ServiceAccount の実 UID は mutation 前に GET して `OperatorIdentitySnapshot` に保存する。発見済み resource の UID を取得できない場合は mutation を始めない。

### 6.3 Operator 間依存

ある Operator の required CRD/APIService が別 Operator の owned API と一致する場合、Operator 間 dependency として記録する。

```text
RequiresApi -> dependency/order evidence
RequiresApi != provider Operator の削除権限
```

## 7. Operand API と instance の探索

### 7.1 Direct discovery

target CSV が owned と宣言した CRD と APIService の API を discovery で解決し、それぞれの instance を LIST する。

この段階では全 instance が候補になる。owned API に存在することは API attribution であり、その instance が Operator uninstall とともに削除されるべきことを意味しない。

各 instance について次を保存する。

- exact ResourceId: group/version/kind/namespace/name/UID
- ownerReferences の kind/name/UID
- labels
- managedFields manager 名
- どの owned API から見つかったかを表す `api_owner_key`
- discovery source

LIST 失敗は unavailable API として preflight に渡す。scan error をゼロ件と解釈しない。

### 7.2 Related API discovery

target-owned CRD、またはそれと同じ exact API group の CRDから、関連性を表し得る label の exact `(key, value)` pair を収集する。

対象にする label key は、現在は以下の限定集合である。

- `app.kubernetes.io/part-of`
- `app.kubernetes.io/managed-by`
- `app.kubernetes.io/instance`
- CRD 上に実在する `*/part-of`
- CRD 上に実在する `*/managed-by`

同じ exact pair を持つ別 CRD の instance を related candidate として LIST する。

```text
(foo.example.io/part-of, platform)
!=
(app.kubernetes.io/managed-by, platform)
```

値だけを比較しない。Plan Review で使った exact pair を保持し、Start 前の evidence revalidation でも同じ pair を要求する。

この探索は候補発見の recall を上げるためのもので、label-only resource は `REVIEW` になる。自動 DELETE authority は得ない。

### 7.3 Direct と related の重複

同じ Kubernetes UID が複数 API version や探索経路から見つかった場合は一つの graph node に正規化する。UID がない object は identity を確立できないため、mutation authority を作らない。

## 8. ownerRef graph の分類

発見した instance 集合内で ownerRef UID graph を作る。

| graph position | 条件 | 基本 action |
|---|---|---|
| root | 集合内 owner を持たず、集合内 child から参照される | provenance に応じて DELETE または REVIEW |
| descendant | 集合内 owner UID を持つ | `EXPECT_GONE` |
| independent | 集合内 parent/child を持たない | provenance に応じて REVIEW。強い evidence がある場合のみ既存規則を適用 |

中間 node は child を持っていても descendant に分類する。root DELETE によって消えることを期待する descendant を、重複して直接 DELETE しない。

related API の instance でも、ownerRef chain が direct instance または target CSV の UID に到達すれば linked descendant として graph に統合する。到達しなければ label-only independent `REVIEW` にする。

## 9. Provenance の評価

現在の planner は概ね次の順で評価する。

### Managed

- ownerRef が target CSV の name と **現在の CSV UID** に一致する

UID が一致しない ownerRef は current generation の強い evidence にしない。

### LikelyManaged

- target CSV と同名だが ownerRef UID が欠落または不一致
- controller Deployment 名への ownerRef があるが、その Deployment UID をこの分類点で検証できない
- label key が CSV prefix と関連する
- managedFields manager が controller Deployment 名または CSV prefix と関連する

### Unknown

- 上記の evidence がない
- ownerRef kind が owned API kind と一致しても group を検証できないなど、曖昧さが残る

`managedFields` は supplementary evidence である。manager 名だけで lifecycle ownership や DELETE authority を確定しない。

## 10. Namespace ancillary resource の探索

install namespace では、OperatorGroup、Lease、ConfigMap なども残存候補として調べる。

- OperatorGroup: 同 namespace に他 CSV がないことは関連性の参考になるが、ユーザーが管理する共有・再install用設定の可能性があるため `REVIEW`
- Lease: holderIdentity や名前が controller/CSV と一致しても mutable な attribution なので `REVIEW`
- ConfigMap: 標準の自動生成 ConfigMap を除外し、名前が関連しそうなものを `REVIEW`

名前、namespace、holderIdentity の一致だけから自動 DELETE しない。exact ownerRef UID などの lifecycle evidence がない ancillary resource は人が判断する。

## 11. Evidence と plan action の対応

### 11.1 自動的に扱えるもの

- target Subscription: OLM reconciliation を止めるため Phase 0 で UID-bound DELETE
- target CSV: operand cleanup 完了後、controller を最後に UID-bound DELETE
- explicit root DELETE の ownerRef descendant: `EXPECT_GONE`
- CRD: default KEEP。`--prune-crds` の明示指定、live instance check、UID bindingを満たす場合だけ DELETE candidate。APIService は常に KEEP

### 11.2 REVIEW にするもの

- owned API の user-created かもしれない root/independent CR
- label-only / managedFields-only candidate
- ownerRef の kind/name は一致するが UID/group を確認できない resource
- OperatorGroup、Lease、ConfigMap などの ancillary resource
- provenance を再検証できない resource

`REVIEW` は削除失敗ではない。cluster が提供していない lifecycle intent を、evidence とともに人へ問い合わせる正常な経路である。

### 11.3 明示承認後

承認は wildcard のまま executor に渡さない。

```text
user decision
  -> exact ResourceId
  -> fresh evidence validation
  -> current UID binding
  -> BoundTeardownPlan
  -> durable RunJournal
  -> UID-preconditioned DELETE
```

同名 resource が新 UID で再作成された場合、以前の承認を引き継がない。

## 12. 実行時にだけ分かる ordering

admission webhook が「A が Gone になるまで B を削除できない」と要求しても、その関係が Kubernetes metadata に記録されていない場合がある。

この制約を製品固有の kind 名で planner に埋め込まない。同一 phase に既に存在する明示承認済みの exact UID-bound DELETE の範囲で、汎用 delete wave を使う。

```text
wave 1: A accepted, B rejected
  -> A の Gone を authoritative GET/watch reconciliation で確認
wave 2: B を fresh GET、same UID 確認後に再試行
```

新たな Gone progress がなければ停止する。403、identity drift、new UID、解決不能な API error、unknown commit outcome では次の phase に進まない。error message や GVK 名から dependency を推測しない。

## 13. Residual Audit の探索

main teardown 成功と cluster cleanup complete は別である。pre-execution snapshot に保存した evidence を使い、controller 削除後に再探索する。

### Exact probes

- plan の DELETE resource を exact GET
- plan の EXPECT_GONE resource を exact GET
- GET 404 は endpoint LIST が成功した場合のみ Gone

### Collection scans

- OLM control plane: Subscription、CSV
- native workloads: Deployment、StatefulSet、DaemonSet、Service
- OpenShift resources: Route、ImageStream
- pre-execution snapshot で既知の owned CR APIs
- footprint namespaces と必要な cluster-scoped APIs

一つでも必要 probe に失敗すれば `AuditIncomplete` であり、residual cleanup を許可しない。

### Residual attribution

| confidence | evidence |
|---|---|
| HIGH | ownerRef UID が保存済み target UID に一致、または target ServiceAccount + matching manager |
| MEDIUM | matching manager + matching label |
| LOW | matching label のみ、または matching manager のみ |
| NONE | namespace affinity のみ、または evidence なし |

confidence は説明と REVIEW の優先順位に使う。residual DELETE には generation `Absent`、complete audit、current residual membership、explicit decision、current UID がすべて必要である。

## 14. metadata ごとの使い方

| metadata / signal | 分かること | 分からないこと | 用途 |
|---|---|---|---|
| ownerRef UID | Kubernetes dependent lifecycle | cross-namespace/shared/external lifecycle | strongest graph evidence、EXPECT_GONE |
| CSV owned CRD/API | Operator が API を提供する | instance を uninstall 時に消すべきか | direct discovery |
| CSV required API | Operator が API を必要とする | provider lifecycle ownership | ordering/blocker evidence |
| exact label pair | 同じ分類・installation hint | immutable ownership | related discovery、REVIEW basis |
| annotation | controller独自のrelation hint | 共通 semantics、immutability | 調査対象。typed rule がなければ REVIEW |
| managedFields manager | 過去に manager が更新した | 作成者、現在のowner、削除権限 | supplementary attribution |
| ServiceAccount | workload と controller identity の一致 | resource lifecycle | residual confidence |
| spec reference/selector | runtime dependency | ownership、削除方向 | graph/explanation |
| finalizer | cleanup controller が必要 | resource ownership | ordering、stall diagnosis |
| creationTimestamp | generation と時間的に矛盾するか | ownership | contradiction filter のみ |
| resource name/namespace | 探索候補 | ownership | REVIEW候補の絞り込みのみ |

### Parent UID を label/annotation に持つ場合

`example.io/instance.uid=<parent UID>` のような metadata は、有用な attribution evidence になり得る。ただし label/annotation は mutable なので ownerRef と同格にはしない。

- 値が current parent UID と一致する: 関連候補として REVIEW
- object が parent より古い: current parent generation が作成した object ではないため downgrade し、由来を調査
- object が parent より新しい: 関係の可能性は上がるが、ownership の証明にはならない
- UID が old generation を指す: current generation の authority に使わない

creationTimestamp は矛盾の検出には使えるが、時刻順だけで削除を承認しない。

## 15. 見つからない場合の調査手順

候補が欠けたときは、次の順に確認する。

1. API discovery に GVR と正しい scope が存在するか
2. target Subscription と CSV が正しく対応しているか
3. CSV の owned CRD/APIService に対象 API が宣言されているか
4. LIST が成功しているか。403、timeout、API unavailable が隠れていないか
5. object の UID が取得できているか
6. ownerRef が exact UID で graph 内の親に到達するか
7. governing CRD に target CRD と共通する exact label pair があるか
8. object が footprint namespace や residual scan target に含まれるか
9. Operator source code にだけ relation があり、cluster metadata に出ていないか

最後のケースは自動推論で埋めず、まず `REVIEW`、診断表示、fixture を追加する。繰り返し観測される安定 metadata が見つかった場合に、vendor-neutral な typed evidence へ昇格する。

## 16. 余分な候補が出る場合の調査手順

1. discovery source が `Direct`、`RelatedLinked`、`RelatedLabelOnly` のどれか確認する
2. direct の場合、どの CSV owned API から列挙されたか確認する
3. related の場合、decisive exact label pair を表示する
4. ownerRef chain の各 UID が current object と一致するか確認する
5. label/manager/name/namespace だけで confidence が上がっていないか確認する
6. action が `REVIEW` に留まり、自動 DELETE へ昇格していないことを確認する

false positive の候補表示は UX と performance の問題になり得るが、未承認 resource の DELETE より安全である。候補を減らす規則は、実 cluster の false positive を採取してから追加する。

## 17. 実 cluster で保存する観測項目

問題を再現したときは、mutation 前後で最低限以下を保存する。

- resource の group/version/kind/namespace/name/UID
- creationTimestamp、deletionTimestamp
- ownerReferences 全体
- labels と lifecycle に関係しそうな annotations
- managedFields の manager 名。大きな fieldsV1 payload は通常保存しない
- finalizers
- workload の ServiceAccount
- Subscription `spec.name`、status CSV linkage、UID
- CSV UID、owned/required APIs、install strategy
- InstallPlan linkage

製品名を使った観測結果は fixture や調査記録に置ける。本番ロジックへ kind 名、API group、label domain、error text の特例を追加しない。

## 18. 現在分かっている限界

- Operator が relation を source code 内だけで管理し、ownerRef や stable metadata を出さない場合、完全な自動判定はできない
- cross-namespace、cluster-scoped、shared resource は ownerRef だけでは表現できない
- managedFields と labels は attribution には役立つが mutable である
- user-created root CR と Operator-created root CR を API ownership だけでは区別できない
- namespace 外の resource は、known API または保存済み evidence がなければ探索範囲から漏れ得る
- creationTimestamp は current generation との矛盾を示せるが deletion authority は与えない
- admission ordering は mutation を試すまで見えない場合がある

この限界は、まず evidence を表示してユーザーに判断を求める。実 cluster のフィードバックなしに完全自動化を目指さない。

## 19. 新しい探索規則を追加する条件

新規 rule は次を説明できる必要がある。

1. どの cluster object から evidence を読むか
2. exact identity をどう比較するか
3. mutable/stale/recreated generation をどう扱うか
4. false positive の場合に action が何になるか
5. API failure 時に fail-closed するか
6. Saved Plan replay で decisive evidence を再検証できるか
7. その rule が discovery、attribution、deletion authority のどこに作用するか

原則として、新規 evidence は最初に discovery/REVIEW 用として導入する。実 cluster で十分な反例検証ができた後にだけ、deterministic safe rule への昇格を検討する。

## 20. 実 cluster 観測例: RHOAI 3.5

これは探索方法を検証するための観測記録であり、本番コードへ製品固有 rule を追加する根拠ではない。2026-09-21 に復旧後の cluster で確認した。

### DSC と DSCI

`DataScienceCluster/default-dsc` と `DSCInitialization/default-dsci` は、target CSV の owned CRD instance として direct discovery できる。一方、両 object には次の強い lifecycle metadata がなかった。

- ownerReferences
- labels
- annotations

managedFields manager は DSC で `OpenAPI-Generator`、`datasciencecluster`、`modules`、DSCI で `manager` が観測された。これらは操作履歴の hint にはなるが、target controller の immutable identity や削除 lifecycle を示さない。

`DSCInitialization` には finalizer があり、対応する ValidatingWebhookConfiguration は DSCI の DELETE を対象にしていた。Webhook configuration には OLM owner labels と operator Service への参照があるため、「この webhook を target Operator が提供する」ことは確認できる。しかし、「DSC が Gone になってから DSCI を削除する」という cross-resource ordering は webhook rule や object metadata には表現されていない。

したがって現在の汎用処理は次のとおりになる。

```text
CSV owned API から DSC / DSCI を発見
  -> lifecycle ownership 不明なので REVIEW
  -> 人が exact resource を承認
  -> current UID に bind
  -> 同一 phase の delete wave
  -> webhook に拒否された target だけ、他 target の Gone progress 後に再試行
```

GVK 名や webhook error message から製品固有順序を作らない。

### component metadata と古い resource

同じ API group の component CRD には `platform.opendatahub.io/part-of=platform` などの label があり、関連 API の発見に利用できた。これは label-only candidate を `REVIEW` に出すための evidence であり、自動 DELETE authority ではない。

ImageStream や ServiceAccount などの native resource にも component label がある。しかし、current DSC/DSCI より古い creationTimestamp の object が存在した。再install 前 generation の残存物、共有物、または別 controller が管理する object の可能性を時刻だけでは区別できない。

この観測から次を維持する。

- current parent より古い object は current generation が作成したとはみなさない
- current parent より新しくても label だけでは自動 DELETE しない
- native resource は residual audit で evidence と時刻を表示し、人の判断を受ける
- 繰り返し同じ lifecycle が観測できた場合も、製品名ではなく再検証可能な metadata rule として追加する

## 21. PR4: Teardown Engine

### 設計原則

1. **Discovery** が DELETE / EXPECT / REVIEW / KEEP と phase 順序を作る。vendor 固有の GVK 順序や事前 guard は置かない。
2. **UID-bound 共通 executor** が全 mutation を実行する。wave fixpoint で admission rejection を retry し、ReDeleteIfRecreated で controller 再作成を処理する。
3. **Residual audit** が generation Absent 後に planned DELETE/EXPECT の残存を検出し、同じ executor へ current live UID で戻す。
4. **TUI / Journal** は判断表示と mutation 前後の永続化を担う。watch は signal のみ、DELETE authority は持たない。

### Delete Wave Fixpoint
同一 phase 内の explicit DELETE を wave loop で実行。admission webhook denial (403/422) は Rejected として pending に残し、他 target の Gone 後にのみ retry。RBAC 403 は Blocked で即停止。

### ReDeleteIfRecreated（反復）
initial explicit DELETE Accepted の exact ResourceId + original UID のみが re-delete authority を得る。barrier が Recreated を検出するたび、authoritative GET で current live UID を確認し、durable ReDeleteRecord を persist してから UID-preconditioned DELETE を発行。controller 生存中は何度でも反復（上限 128 iteration）。AlreadyGone / Failed / Unknown / EXPECT / watch から authority を生成しない。mid re-delete crash (journal に未解決 Authorized/Accepted/UnknownOutcome record) は fail-closed で resume を block し、fresh plan を要求する。完全な live reconciliation resume は将来 PR で対応。

### Finalizer Recovery（デフォルト有効）
EXPECT descendant (single controller ownerRef → deleted root Gone) と explicit DELETE target (same UID + deletionTimestamp) の両方が strip candidate。各 PATCH は UID + finalizer 配列の atomic JSON test。protected kind (Namespace, CRD 等) は対象外。

### Residual Auto Cleanup
generation Absent + complete audit 後:
- **planned DELETE still present**: 同 run authority で current live UID cleanup
- **planned EXPECT still present**: deterministic authority で current live UID cleanup
- **ambiguous / unattributed / user-created root / data / protected**: REVIEW / 明示承認

### TUI 境界
journal は Prepared 状態で作成、Start 時に Applying へ遷移。Prepared の resume は reject。`can_finish_run` が pending cleanup を検査し Finished を guard。

## 22. 関連コード

- API discovery: `src/kube/discovery.rs`
- namespace snapshot: `src/kube/snapshot.rs`
- OLM discovery: `src/analyzers/olm.rs`
- evidence graph: `src/graph/evidence.rs`
- teardown discovery and planning: `src/teardown/planner.rs`
- UID-bound execution: `src/teardown/executor.rs`
- generation and residual audit: `src/teardown/audit.rs`
- persisted evidence and execution history: `src/teardown/journal.rs`
- Draft/Bound plan runtime: `src/teardown/app.rs`
