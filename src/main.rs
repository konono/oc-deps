// src/main.rs
use std::collections::HashMap;
use clap::Parser;
use anyhow::Result;
use futures::future::{BoxFuture, FutureExt};
use kube::{
    Client,
    config::Config,
    discovery::{Discovery, Scope},
    api::{Api, ApiResource, DynamicObject, ListParams, ResourceExt},
    core::GroupVersion,
};
use k8s_openapi::api::{
    core::v1::{Pod, Service},
    apps::v1::{Deployment, ReplicaSet},
};
use comfy_table::Table;

/// Kubernetes リソース依存チェーン表示ツール
#[derive(Parser, Debug)]
#[command(author, version, about = "Kubernetes Resource Dependency Inspector in Rust")]
struct Args {
    /// Namespace of the resource (省略時は kubeconfig の default namespace を使用)
    #[arg(short = 'n', long)]
    namespace: Option<String>,

    /// Kind of the resource (例: Pod, Deployment)。  
    /// RESOURCE に `kind/name` を渡した場合は不要です。
    #[arg(short = 'k', long)]
    kind: Option<String>,

    /// 対象リソース。`kind/name` または `name` のみ
    #[arg(value_name = "RESOURCE")]
    resource: String,
}

/// リソース情報を保持
struct KindInfo {
    group: String,
    version: String,
    plural: String,
    namespaced: bool,
}
type KindMap = HashMap<String, KindInfo>;
type GvrMap = HashMap<String, String>;

/// Config と Client を返す
async fn load_config_and_client() -> (Config, Client) {
    let config = Config::infer()
        .await
        .expect("❌ Kubernetes 設定の読み込みに失敗しました");
    let client = Client::try_from(config.clone())
        .expect("❌ Kubernetes クライアントの初期化に失敗しました");
    (config, client)
}

/// API リソース一覧を取得してマップを構築
async fn build_kind_lookup(client: &Client) -> Result<(KindMap, GvrMap)> {
    let discovery = Discovery::new(client.clone()).run().await?;
    let mut kind_map = KindMap::new();
    let mut gvr_map = GvrMap::new();

    for group in discovery.groups() {
        for (ar, caps) in group.recommended_resources() {
            let kind = ar.kind.clone();
            let group_name = ar.group.clone();
            let version = ar.version.clone();
            let plural = ar.plural.clone();
            let namespaced = caps.scope == Scope::Namespaced;

            kind_map.insert(
                kind.clone(),
                KindInfo {
                    group: group_name.clone(),
                    version: version.clone(),
                    plural: plural.clone(),
                    namespaced,
                },
            );

            // plural または plural.group を gvr_map に登録 (キーは小文字)
            let gvr_key = if group_name.is_empty() {
                plural.clone()
            } else {
                format!("{}.{}", plural, group_name)
            };
            gvr_map.insert(gvr_key.to_lowercase(), kind.clone());
        }
    }

    Ok((kind_map, gvr_map))
}

/// 再帰的オーナーチェーン探索 (BoxFuture)
fn find_owner_chain<'a>(
    client: &'a Client,
    kind: &'a str,
    name: &'a str,
    namespace: &'a str,
    kind_map: &'a KindMap,
    results: &'a mut Vec<(String, String, String)>,
    relation: &'a str,
) -> BoxFuture<'a, ()> {
    async move {
        if let Some(info) = kind_map.get(kind) {
            let gvk = GroupVersion::gv(&info.group, &info.version).with_kind(kind);
            let ar = ApiResource::from_gvk_with_plural(&gvk, &info.plural);
            let api: Api<DynamicObject> = if info.namespaced {
                Api::namespaced_with(client.clone(), namespace, &ar)
            } else {
                Api::all_with(client.clone(), &ar)
            };

            match api.get(name).await {
                Ok(obj) => {
                    results.push((relation.to_string(), kind.to_string(), name.to_string()));
                    if let Some(owners) = obj.metadata.owner_references.as_ref() {
                        for r in owners {
                            find_owner_chain(
                                client,
                                &r.kind,
                                &r.name,
                                namespace,
                                kind_map,
                                results,
                                "Parent",
                            )
                            .await;
                        }
                    }
                }
                Err(e) => {
                    results.push((
                        "Error".to_string(),
                        kind.to_string(),
                        format!("{}/{} not found: {}", kind, name, e),
                    ));
                }
            }
        } else {
            results.push((
                "Unknown".to_string(),
                kind.to_string(),
                format!("Unsupported kind: {}", kind),
            ));
        }
    }
    .boxed()
}

/// 関連リソースを取得
async fn get_related_resources(
    client: &Client,
    kind: &str,
    name: &str,
    namespace: &str,
    kind_map: &KindMap,
) -> Vec<(String, String, String)> {
    let mut results = Vec::new();
    let kind_lower = kind.to_lowercase();

    match kind_lower.as_str() {
        "deployment" | "replicaset" | "pod" | "statefulset" => {
            // 親チェーン取得
            let mut parents = Vec::new();
            let capitalized = format!(
                "{}{}",
                kind.chars().next().unwrap().to_ascii_uppercase(),
                &kind[1..]
            );
            find_owner_chain(
                client,
                &capitalized,
                name,
                namespace,
                kind_map,
                &mut parents,
                "Self",
            )
            .await;

            // Parent のみ逆順で追加
            for r in parents.into_iter().filter(|r| r.0 == "Parent").rev() {
                results.push(r);
            }

            // Self
            results.push(("Self".into(), capitalized.clone(), name.to_string()));

            // ReplicaSet の場合は子 Pod も列挙
            if kind_lower == "replicaset" {
                let rs_api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);
                if let Ok(rs) = rs_api.get(name).await {
                    if let Some(labels) = rs.spec.and_then(|s| s.selector.match_labels) {
                        let selector = labels
                            .into_iter()
                            .map(|(k, v)| format!("{}={}", k, v))
                            .collect::<Vec<_>>()
                            .join(",");
                        let pod_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
                        if let Ok(pods) = pod_api.list(&ListParams::default().labels(&selector)).await {
                            for p in pods {
                                results.push(("Child".into(), "Pod".into(), p.name_any()));
                            }
                        }
                    }
                }
            }

            // Deployment の場合は ReplicaSet → Pod も追加
            if kind_lower == "deployment" {
                let apps: Api<Deployment> = Api::namespaced(client.clone(), namespace);
                if let Ok(depl) = apps.get(name).await {
                    if let Some(labels) = depl.spec.and_then(|s| s.selector.match_labels) {
                        let rs_api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);
                        if let Ok(list) = rs_api.list(&ListParams::default()).await {
                            for rs in list {
                                if let Some(owners) = rs.metadata.owner_references.as_ref() {
                                    if owners.iter().any(|r| r.kind == "Deployment" && r.name == name) {
                                        results.push(("Child".into(), "ReplicaSet".into(), rs.name_any()));
                                        let selector = labels
                                            .iter()
                                            .map(|(k, v)| format!("{}={}", k, v))
                                            .collect::<Vec<_>>()
                                            .join(",");
                                        let pod_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
                                        if let Ok(pods) = pod_api.list(&ListParams::default().labels(&selector)).await {
                                            for p in pods {
                                                results.push(("Child".into(), "Pod".into(), p.name_any()));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        "service" => {
            results.push(("Self".into(), "Service".into(), name.to_string()));
            let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);
            if let Ok(svc) = svc_api.get(name).await {
                if let Some(sel) = svc.spec.and_then(|s| s.selector) {
                    let selector = sel
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join(",");
                    let pod_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
                    if let Ok(pods) = pod_api.list(&ListParams::default().labels(&selector)).await {
                        for p in pods {
                            results.push(("Child".into(), "Pod".into(), p.name_any()));
                        }
                    }
                } else {
                    results.push((
                        "Info".into(),
                        "Service".into(),
                        format!("'{}' has no selector", name),
                    ));
                }
            }
        }

        _ => {
            // その他はオーナーチェーンのみ
            find_owner_chain(client, kind, name, namespace, kind_map, &mut results, "Self")
                .await;
        }
    }

    results
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // kubeconfig の読み込みと Client 初期化
    let (config, client) = load_config_and_client().await;
    let namespace = args.namespace.unwrap_or(config.default_namespace.clone());

    println!("🔍 Discovering API resources from the cluster...");
    let (kind_map, gvr_map) = build_kind_lookup(&client).await?;

    // RESOURCE 引数から kind_input/name を抽出
    let (kind_input, name) = if let Some((k, n)) = args.resource.split_once('/') {
        (k.to_string(), n.to_string())
    } else {
        let k = args.kind.clone().unwrap_or_else(|| {
            eprintln!(
                "❌ リソース種別が指定されていません。RESOURCE に `kind/name` を渡すか、-k を指定してください。"
            );
            std::process::exit(1);
        });
        (k, args.resource.clone())
    };

    // Kind を大小区別せず解決し、singular.group 形式も許容
    let kind = {
        let lower = kind_input.to_lowercase();
        // 1) 正式な Kind 名（Pod, Deployment…）との照合
        if let Some(k) = kind_map.keys().find(|k| k.to_lowercase() == lower) {
            k.clone()
        }
        // 2) plural.group の GVR マッピング
        else if let Some(k) = gvr_map.get(&lower) {
            println!("ℹ️ GVR '{}' を Kind '{}' に変換しました。", kind_input, k);
            k.clone()
        }
        // 3) singular.group → plural.group に変換
        else if let Some((sing, grp)) = lower.split_once('.') {
            if let Some((_, info)) = kind_map.iter().find(|(k,_)| k.to_lowercase() == sing) {
                let gvr_key = format!("{}.{}", info.plural, grp);
                if let Some(k) = gvr_map.get(&gvr_key) {
                    println!("ℹ️ GVR '{}' を Kind '{}' に変換しました。", kind_input, k);
                    k.clone()
                } else {
                    eprintln!("❌ Unsupported kind or GVR: {}", kind_input);
                    std::process::exit(1);
                }
            } else {
                eprintln!("❌ Unsupported kind or GVR: {}", kind_input);
                std::process::exit(1);
            }
        }
        // どれにも該当しない
        else {
            eprintln!("❌ Unsupported kind or GVR: {}", kind_input);
            std::process::exit(1);
        }
    };

    // 関連リソースを取得・表示
    let deps = get_related_resources(&client, &kind, &name, &namespace, &kind_map).await;
    if !deps.is_empty() {
        println!("\n📌 Resource Dependency Chain:");
        let mut table = Table::new();
        table.set_header(vec!["Relation", "Resource Type", "Name"]);
        for (rel, ty, nm) in deps {
            table.add_row(vec![rel, ty, nm]);
        }
        println!("{table}");
    } else {
        println!("No related resources found.");
    }

    Ok(())
}
