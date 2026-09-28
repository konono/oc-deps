use crate::audit::core::*;

pub fn print_audit_tree(report: &AuditReport) {
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());

    if !report.capability_warnings.is_empty() {
        eprintln!("⚠ Capability warnings:");
        for w in &report.capability_warnings {
            eprintln!("  {}", w);
        }
        eprintln!();
    }

    if !report.plan_collision_warnings.is_empty() {
        eprintln!("⚠ Plan collision warnings:");
        for w in &report.plan_collision_warnings {
            eprintln!("  {}", w);
        }
        eprintln!();
    }

    println!(
        "Audit: {} → {}",
        report.before_taken_at, report.after_taken_at
    );
    println!(
        "Raw observations: {} → {}",
        report.layers.raw_observations.pre, report.layers.raw_observations.post,
    );
    println!(
        "API-logical: {} → {}",
        report.layers.logical.pre, report.layers.logical.post,
    );
    println!(
        "Physical UIDs: {} → {} ({} removed, {} added, {} multi-observed)",
        report.layers.physical_uids.pre,
        report.layers.physical_uids.post,
        report.layers.physical_uids.removed,
        report.layers.physical_uids.added,
        report.layers.physical_uids.multi_observed,
    );
    println!(
        "UID-null: {} → {} (fp collisions: {}/{})",
        report.layers.uid_null.pre,
        report.layers.uid_null.post,
        report.layers.uid_null.pre_fingerprint_collision_groups,
        report.layers.uid_null.post_fingerprint_collision_groups,
    );
    println!();

    println!("Classification:");
    for (class, count) in &report.classification_summary {
        println!("  {}: {}", class, count);
    }
    println!();

    println!(
        "Closure: {} DELETE seeds → {} total ({} removed in closure)",
        report.closure.delete_seeds,
        report.closure.total_closure,
        report.closure.removed_in_closure,
    );
    println!();

    if !report.recreated.is_empty() {
        println!("Recreated ({}):", report.recreated.len());
        for r in &report.recreated {
            if is_tty {
                println!(
                    "  \x1b[33m↻ {}\x1b[0m  [UID {} → {}]",
                    r.identity, r.pre_uid, r.post_uid
                );
            } else {
                println!("  ↻ {}  [UID {} → {}]", r.identity, r.pre_uid, r.post_uid);
            }
        }
        println!();
    }

    println!(
        "Terminating: {} newly, {} preexisting",
        report.terminating.newly_terminating, report.terminating.preexisting_retained,
    );

    if !report.orphan_owner_refs.is_empty() {
        println!("\nOrphan ownerRefs ({}):", report.orphan_owner_refs.len());
        for o in &report.orphan_owner_refs {
            println!(
                "  {} → deleted {}/{} (UID {})",
                o.identity,
                o.deleted_owner_kind,
                o.deleted_owner_name,
                &o.deleted_owner_uid[..12.min(o.deleted_owner_uid.len())]
            );
        }
    }

    if !report.dangling_spec_refs.is_empty() {
        println!(
            "\nDangling spec refs ({}):",
            report.dangling_spec_refs.len()
        );
        for d in &report.dangling_spec_refs {
            println!(
                "  {} → {}/{} [{}] ({})",
                d.source_identity, d.target_kind, d.target_name, d.field_path, d.ref_type
            );
        }
    }

    if !report.provider_operand_results.is_empty() {
        println!(
            "\nProvider operands ({}):",
            report.provider_operand_results.len()
        );
        for p in &report.provider_operand_results {
            println!(
                "  {} [provider: {}, classification: {}]",
                p.identity, p.api_provider_operator, p.physical_classification,
            );
        }
    }
}

pub fn print_audit_table(report: &AuditReport) {
    if !report.capability_warnings.is_empty() {
        eprintln!("⚠ Capability warnings:");
        for w in &report.capability_warnings {
            eprintln!("  {}", w);
        }
        eprintln!();
    }

    let mut table = comfy_table::Table::new();
    table.set_header(vec![
        "Classification",
        "Kind",
        "Name",
        "Namespace",
        "UID (prefix)",
    ]);

    for r in &report.removals {
        table.add_row(vec![
            r.classification.to_string(),
            r.identity.kind.clone(),
            r.identity.name.clone(),
            r.identity.namespace.clone().unwrap_or_default(),
            r.uid[..12.min(r.uid.len())].to_string(),
        ]);
    }
    println!("{table}");

    println!(
        "\nSummary: {} removed, {} recreated, {} orphan refs, {} dangling refs",
        report.layers.physical_uids.removed,
        report.recreated.len(),
        report.orphan_owner_refs.len(),
        report.dangling_spec_refs.len(),
    );
}
