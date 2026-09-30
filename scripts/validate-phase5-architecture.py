#!/usr/bin/env python3
"""Phase 5 architecture validator — module split constraints."""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")

errors = []

def check(condition, msg):
    if not condition:
        errors.append(msg)

def loc(path):
    full = os.path.join(SRC, path)
    if not os.path.exists(full):
        return -1
    with open(full) as f:
        return sum(1 for _ in f)

def read(path):
    full = os.path.join(SRC, path)
    if not os.path.exists(full):
        return ""
    with open(full) as f:
        return f.read()

# 1. main.rs <= 1500 lines
main_loc = loc("main.rs")
check(main_loc <= 1500, f"main.rs is {main_loc} lines (max 1500)")

# 2. commands/helpers.rs must not exist
check(loc("commands/helpers.rs") == -1, "commands/helpers.rs must not exist")

# 3. No blanket allow(unused_imports) or allow(dead_code) at crate level
main_content = read("main.rs")
check("#![allow(unused_imports" not in main_content, "#![allow(unused_imports)] in main.rs")
check("#![allow(dead_code" not in main_content, "#![allow(dead_code)] in main.rs")

# 4. No wildcard bridge or use self::teardown::* in commands/mod.rs
cmd_mod = read("commands/mod.rs")
check("use self::teardown::*" not in cmd_mod, "wildcard re-export in commands/mod.rs")
check("pub use commands::*" not in main_content, "wildcard bridge in main.rs")

# 5. No pub(crate) use commands:: or pub use commands:: in main.rs (root re-exports)
for line in main_content.split('\n'):
    stripped = line.strip()
    if stripped.startswith('//'):
        continue
    check("pub(crate) use commands::" not in stripped, f"root re-export in main.rs: {stripped}")
    check("pub use commands::" not in stripped, f"root re-export in main.rs: {stripped}")

# 6. No std::process::Command or Command::new in production code (not in test modules)
for dirpath, _, filenames in os.walk(SRC):
    for f in filenames:
        if f.endswith(".rs"):
            path = os.path.join(dirpath, f)
            content = open(path).read()
            relpath = os.path.relpath(path, SRC)
            # Split on #[cfg(test)] — only check code before any test module
            parts = re.split(r'#\[cfg\(test\)\]', content)
            prod_code = parts[0] if parts else content
            if "std::process::Command" in prod_code or "Command::new(" in prod_code:
                check(False, f"std::process::Command in production code of {relpath}")

# 7. No execute_plan or MutationGate in main.rs
check("execute_plan" not in main_content, "direct mutation call in main.rs")
check("MutationGate" not in main_content, "MutationGate in main.rs")

# 8. No #[allow(dead_code)] in any commands/ file
commands_dir = os.path.join(SRC, "commands")
if os.path.isdir(commands_dir):
    for f in os.listdir(commands_dir):
        if f.endswith(".rs"):
            content = open(os.path.join(commands_dir, f)).read()
            check("#[allow(dead_code)]" not in content,
                  f"#[allow(dead_code)] in commands/{f}")

# 9. No crate:: re-export references in teardown/workflow.rs or teardown/ref_guard.rs
FORBIDDEN_REFS = [
    "crate::DeleteResourceSpec",
    "crate::ExplicitCleanupResumeMode",
    "crate::ResumeStage",
    "crate::build_execution_plan",
    "crate::classify_resume_stage",
    "crate::create_run_journal",
    "crate::discover_audit_scope",
    "crate::explicit_cleanup_resume",
    "crate::inject_explicit_phase",
    "crate::resolve_explicit_delete",
    "crate::should_refresh_discovery",
]
for rs_file in ["teardown/workflow.rs", "teardown/ref_guard.rs"]:
    content = read(rs_file)
    for ref_str in FORBIDDEN_REFS:
        check(ref_str not in content, f"{ref_str} found in {rs_file}")

# 10. All 9 required module files exist and are nonempty
REQUIRED_MODULES = [
    "commands/teardown.rs",
    "commands/network.rs",
    "commands/map.rs",
    "commands/snapshot.rs",
    "commands/tree.rs",
    "commands/operator.rs",
    "commands/trace.rs",
    "commands/graph.rs",
    "commands/backup.rs",
]
for mod in REQUIRED_MODULES:
    l = loc(mod)
    check(l > 0, f"{mod} missing or empty (loc={l})")

# 11. commands/mod.rs <= 400 lines
mod_loc = loc("commands/mod.rs")
check(mod_loc <= 400, f"commands/mod.rs is {mod_loc} lines (max 400)")

if errors:
    print("FAIL")
    for e in errors:
        print(f"  ✗ {e}")
    sys.exit(1)
else:
    print("PASS")
    print(f"  main.rs={main_loc}, commands/mod.rs={mod_loc}")
    for mod in REQUIRED_MODULES:
        print(f"  {mod}={loc(mod)}")
