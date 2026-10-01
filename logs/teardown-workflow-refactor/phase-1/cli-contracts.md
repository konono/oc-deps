# CLI Contracts — Phase 1 Freeze

Base commit: ad93e096eb05502a33281f3501eab001b834f544

## oc-deps teardown --help
```
Teardown planning for OLM operators

Usage: oc-deps teardown <COMMAND>

Commands:
  plan      Generate a teardown plan
  status    Check current status of resources in a teardown plan
  apply     Execute a teardown plan (reads from execution plan file)
  coverage  Show plan coverage: COVERED BY PLAN / INTENTIONALLY PRESERVED / NOT COVERED
  explain   Explain why a resource is scheduled at its position in the plan
  resume    Resume a paused or interrupted teardown run
  runs      List all teardown runs for the current cluster
  batch     Execute teardown for multiple operators from a config file (sequential)
  journal   Show teardown run journal for an operator (with live residual audit)
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## oc-deps teardown plan --help
```
Generate a teardown plan

Usage: oc-deps teardown plan [OPTIONS] <OPERATORS>...

Arguments:
  <OPERATORS>...
          Operator names (subscription or CSV name, partial match OK)

Options:
  -o, --output <OUTPUT>
          Output format: tree, table, json
          
          [default: tree]
          [possible values: tree, table, json]

      --refresh-discovery
          Refresh API discovery cache

      --prune-crds
          Include CRD deletion in plan (default: keep)

      --approve-scope <APPROVE_SCOPE>
          Approve deletion scope (repeatable)
          
          [possible values: root, independent, label-only, operator-group]

      --approve-resource <SPEC>
          Approve deletion of specific resource (Kind/name or group/Kind/ns/name, repeatable)

      --keep-resource <SPEC>
          Keep a resource (Kind/name or group/Kind/ns/name, repeatable)

      --delete-resource <SPEC>
          Explicitly delete a resource after operator removal.
          
          Format: group/Kind/ns/name or Kind/ns/name (core group) or Kind/-/name (cluster-scoped). Supported kinds: Gateway, ConfigMap, Service, ConsolePlugin, Deployment. Forbidden: Namespace, PersistentVolume, PersistentVolumeClaim, CRD, APIService. Safety: typed inbound ref scan must pass at plan and apply time (fail-closed).

      --file <PATH>
          Save the execution plan to file

  -h, --help
          Print help (see a summary with '-h')
```

## oc-deps teardown apply --help
```
Execute a teardown plan (reads from execution plan file)

Usage: oc-deps teardown apply [OPTIONS] <PLAN>

Arguments:
  <PLAN>  Path to execution plan JSON file

Options:
      --refresh-discovery  Refresh API discovery cache
      --dry-run            Dry run — show what would be done without executing
      --non-interactive    Non-interactive mode
  -y, --yes                Skip confirmation prompt (auto-approve execution)
      --script <PATH>      Headless script mode
      --tui                Enable TUI mode
      --backup-dir <DIR>   Save pre-delete backup to this directory root before executing
  -h, --help               Print help
```

## oc-deps teardown resume --help
```
Resume a paused or interrupted teardown run

Usage: oc-deps teardown resume [OPTIONS] [OPERATOR]

Arguments:
  [OPERATOR]  Operator CSV name to find latest run

Options:
      --run <RUN>          Specific run ID
      --refresh-discovery  Refresh API discovery cache
  -h, --help               Print help
```

## oc-deps teardown batch --help
```
Execute teardown for multiple operators from a config file (sequential)

Usage: oc-deps teardown batch [OPTIONS] <CONFIG>

Arguments:
  <CONFIG>  Path to JSON config file listing operators and their flags

Options:
      --refresh-discovery  Refresh API discovery once, then reuse within this batch
      --dry-run            Dry run — validate config and show plan without executing
      --skip-missing       Skip operators not found in the cluster instead of failing
      --backup-dir <DIR>   Save per-operator backup bundles to this directory
  -h, --help               Print help
```

## oc-deps teardown runs --help
```
List all teardown runs for the current cluster

Usage: oc-deps teardown runs

Options:
  -h, --help  Print help
```

## oc-deps teardown journal --help
```
Show teardown run journal for an operator (with live residual audit)

Usage: oc-deps teardown journal [OPTIONS] [OPERATOR]

Arguments:
  [OPERATOR]  Operator CSV name to find latest run

Options:
      --run <RUN>        Specific run ID
      --no-audit         Skip live residual audit
  -o, --output <OUTPUT>  Output format: tree, table, json [default: tree] [possible values: tree, table, json]
  -h, --help             Print help
```

## oc-deps teardown status --help
```
Check current status of resources in a teardown plan

Usage: oc-deps teardown status [OPTIONS] [OPERATORS]...

Arguments:
  [OPERATORS]...  Operator names (subscription or CSV name, partial match OK)

Options:
      --refresh-discovery  Refresh API discovery cache
      --plan-file <PATH>   Load plan from a saved JSON file instead of re-generating
  -h, --help               Print help
```

## oc-deps teardown coverage --help
```
Show plan coverage: COVERED BY PLAN / INTENTIONALLY PRESERVED / NOT COVERED

Usage: oc-deps teardown coverage [OPTIONS] <OPERATORS>...

Arguments:
  <OPERATORS>...  Operator names (subscription or CSV name, partial match OK)

Options:
  -o, --output <OUTPUT>    Output format: tree, table, json [default: tree] [possible values: tree, table, json]
      --refresh-discovery  Refresh API discovery cache
  -h, --help               Print help
```

## oc-deps teardown explain --help
```
Explain why a resource is scheduled at its position in the plan

Usage: oc-deps teardown explain [OPTIONS] --resource <RESOURCE> <OPERATORS>...

Arguments:
  <OPERATORS>...  Operator names to plan teardown for

Options:
      --resource <RESOURCE>  Resource to explain (kind/name format)
      --refresh-discovery    Refresh API discovery cache
  -h, --help                 Print help
```

## Modes to be removed in Phase 2

From `teardown apply --help`:
- `--tui`: Enable TUI mode
- `--script <PATH>`: Headless script mode
- `--non-interactive`: Non-interactive mode
