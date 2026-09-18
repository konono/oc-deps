use std::collections::{HashMap, HashSet};

#[derive(Clone)]
pub struct ResourceInfo {
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
    pub uid: String,
    pub owner_refs: Vec<OwnerRef>,
}

#[derive(Clone)]
pub struct OwnerRef {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    pub controller: bool,
}

#[derive(Clone)]
pub struct SpecRef {
    pub target_kind: String,
    pub target_name: String,
    pub field_path: String,
}

#[derive(Clone)]
pub struct IncomingRef {
    pub source_kind: String,
    pub source_name: String,
    pub field_path: String,
}

pub type ScanItem = (ResourceInfo, Vec<SpecRef>, Vec<(String, String)>);
pub type RefData = (String, String, Vec<SpecRef>, Vec<(String, String)>);

pub struct NamespaceIndex {
    pub by_uid: HashMap<String, ResourceInfo>,
    pub children_of: HashMap<String, Vec<String>>,
    pub by_kind_name: HashMap<(String, String), String>,
    pub refs_from: HashMap<String, Vec<SpecRef>>,
    pub refs_to: HashMap<String, Vec<IncomingRef>>,
}

impl NamespaceIndex {
    pub fn new() -> Self {
        Self {
            by_uid: HashMap::new(),
            children_of: HashMap::new(),
            by_kind_name: HashMap::new(),
            refs_from: HashMap::new(),
            refs_to: HashMap::new(),
        }
    }

    pub fn insert(&mut self, info: ResourceInfo) {
        let uid = info.uid.clone();
        let kind_lower = info.kind.to_lowercase();
        let name = info.name.clone();

        for oref in &info.owner_refs {
            self.children_of
                .entry(oref.uid.clone())
                .or_default()
                .push(uid.clone());
        }

        self.by_kind_name.insert((kind_lower, name), uid.clone());
        self.by_uid.insert(uid, info);
    }
}

pub fn primary_owner(refs: &[OwnerRef]) -> Option<&OwnerRef> {
    refs.iter().find(|r| r.controller).or(refs.first())
}

pub fn dedup_spec_refs(refs: &mut Vec<SpecRef>) {
    let mut seen = HashSet::new();
    refs.retain(|r| seen.insert((r.target_kind.clone(), r.target_name.clone())));
}
