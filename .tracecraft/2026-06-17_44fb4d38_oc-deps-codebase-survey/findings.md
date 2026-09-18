# Findings

## Finding: oc-deps のアーキテクチャ

- **調べた理由**: プロジェクトの全体像を把握するため
- **わかった事実**:
  1. API Discovery → namespace全スキャン(並列度50) → 逆引きインデックス構築 → ツリー探索 の4段構成
  2. NamespaceIndex が核心データ構造: by_uid, children_of, by_kind_name, refs_from, refs_to の5つのHashMap
  3. children_of が逆引きインデックス: 親UID → [子UID] のマッピングで、ownerRef の逆方向を実現
  4. spec参照の検出は well-known refs (secretKeyRef等) と名前マッチ heuristic の2段構え
  5. cluster-scoped 親は namespace スキャンに含まれないため、個別 Get API で後から取得

## Finding: 逆引きインデックスの設計パターン

### 調べた理由
ユーザーがインデックス構築ロジックに関心を持ったため

### わかった事実
1. children_of の構築: insert(child) 時に child.ownerRefs の各親UIDをキーにして child.uid を push するだけ
2. 順序非依存: HashMap のエントリは遅延生成 (or_default) なので、親が未登録でもキーだけ先に作られる
3. 探索と取得の分離: API呼び出しはスキャン時に1回。ツリー構築は HashMap ルックアップのみ
4. --up-only との対比: フルモードは逆引きのために全スキャン必須、up-only は個別 Get で親だけ辿る

### 作業への影響
この逆引きパターンは他の「参照が片方向のみ」のシステムにも応用可能

