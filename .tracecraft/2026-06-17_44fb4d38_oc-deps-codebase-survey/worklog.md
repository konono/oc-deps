# oc-deps コードベース調査

- **開始日時**: 2026-06-17
- **セッション ID**: 44fb4d38
- **目的**: プロジェクトの機能と処理フローを調査し、ユーザーに全体像を説明する

## Step 1: プロジェクト全体調査

- **目的**: oc-deps の機能と処理フローを把握する
- **実行内容**: Cargo.toml と src/main.rs (2011行) を通読
- **結果**: 5つのモード（フルツリー、親のみ、子のみ、namespace マップ、CRD出自）を持つ Kubernetes リソース依存関係インスペクターであることを確認
- **解釈**: 全ロジックが main.rs 1ファイルに集約。namespace 全スキャン + 逆引きインデックスで子リソースを発見する設計

## Step 2: 逆引きインデックスの詳細解説

### 目的
NamespaceIndex の逆引きインデックス (children_of) がどう構築・利用されるかを詳細に解説する

### 実行内容
- NamespaceIndex::insert (L367-382) のロジックを追跡
- build_child_tree (L978-1021) と build_parent_chain (L948-976) のツリー探索を分析
- --up-only モード (find_parents_only) との設計の違いを比較

### 結果
- insert 時に「自分の ownerRef の親UIDの子リストに自分のUIDを追加」するだけで逆引きが完成
- insert の順序に依存しない（親が先でも子が先でも最終結果は同じ）
- ツリー探索は HashMap::get のみで API コールゼロ
- --up-only は namespace スキャンを完全にスキップし、1件ずつ Get API で親を辿る高速モード

### 解釈
Kubernetes API の非対称性（ownerRef は子→親の片方向のみ）を namespace 全スキャン + HashMap 逆引きで補う設計。スキャンのコストは高いが、一度完了すればツリー構築はメモリ内ルックアップのみ

