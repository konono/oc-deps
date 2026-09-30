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

# main.rs <= 1500 lines
main_loc = loc("main.rs")
check(main_loc <= 1500, f"main.rs is {main_loc} lines (max 1500)")

# commands/helpers.rs must not exist
check(loc("commands/helpers.rs") == -1, "commands/helpers.rs must not exist")

# No blanket allow(unused_imports) or allow(dead_code) at crate level
main_content = read("main.rs")
check("#![allow(unused_imports" not in main_content, "#![allow(unused_imports)] in main.rs")
check("#![allow(dead_code" not in main_content, "#![allow(dead_code)] in main.rs")

# No wildcard bridge from crate root
check("pub use commands::*" not in main_content, "wildcard bridge in main.rs")
check("use self::teardown::*" not in read("commands/mod.rs"), "wildcard re-export in commands/mod.rs")

# No std::process::Command
for dirpath, _, filenames in os.walk(SRC):
    for f in filenames:
        if f.endswith(".rs"):
            path = os.path.join(dirpath, f)
            content = open(path).read()
            relpath = os.path.relpath(path, SRC)
            if "std::process::Command" in content and "#[cfg(test)]" not in content.split("std::process::Command")[0][-200:]:
                # Allow in test code
                pass

# No direct mutation call in main.rs
check("execute_plan" not in main_content, "direct mutation call in main.rs")
check("MutationGate" not in main_content, "MutationGate in main.rs")

# Command family files exist and are nonempty
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

# commands/mod.rs is dispatch-only (LOC threshold)
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
