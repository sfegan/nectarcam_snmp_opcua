#!/usr/bin/env python3
"""
resolve_oids.py
───────────────
Read one or more device-config JSON files (same format as snmp_asyncua_bridge.py),
resolve every symbolic OID name to dotted-decimal notation using the same logic
the bridge uses at startup, and write the fully-resolved configs to stdout as JSON.

Multi-IP configs (where "ip" is a JSON array) are left as-is — they are NOT
expanded into one config per address.  The only modification made to each config
is that symbolic OID names are replaced with their dotted-decimal equivalents.

Usage
-----
    python resolve_oids.py devices.json [more.json ...]

Output
------
  • A single JSON object  if exactly one file was given and it contained a
                          single object (not an array).
  • A JSON array          in all other cases (multiple files, or any file that
                          contained a top-level array).

Exit codes
----------
  0  All OIDs resolved; JSON written to stdout.
  1  One or more OIDs could not be resolved, or a config file could not be
     read / parsed.  An error message is printed to stderr; nothing is written
     to stdout.
"""

import json
import os
import sys

# ── locate the bridge module ──────────────────────────────────────────────────
# resolve_oids.py is intended to live alongside snmp_asyncua_bridge.py.
# Insert its directory at the front of sys.path so the import works regardless
# of where the script is invoked from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from snmp_asyncua_bridge import resolve_oid_name
except ImportError as _e:
    sys.exit(f"Cannot import snmp_asyncua_bridge: {_e}\n"
             "Ensure resolve_oids.py is in the same directory as snmp_asyncua_bridge.py.")

# ─────────────────────────────────────────────────────────────────────────────


def load_raw_configs(paths: list) -> tuple:
    """
    Read each JSON file and return (raw_configs, output_as_list).

    Each file may contain a JSON object (one config) or a JSON array (multiple
    configs).  All configs are collected into a flat list.  Multi-IP configs
    are left completely intact.

    output_as_list is False only when exactly one file was given and it
    contained a single top-level object — preserving round-trip fidelity for
    the common single-file single-device case.

    Exits with an error message if any file cannot be read or parsed.
    """
    all_configs = []
    output_as_list = len(paths) > 1   # multiple files -> always a list

    for path in paths:
        try:
            with open(path) as fh:
                data = json.load(fh)
        except FileNotFoundError:
            sys.exit(f"Config file not found: {path}")
        except json.JSONDecodeError as exc:
            sys.exit(f"Config file is not valid JSON ({path}): {exc}")

        if isinstance(data, dict):
            all_configs.append(data)
            # A single file with a single object only: output stays as object.
            # (output_as_list already True if len(paths) > 1.)
        elif isinstance(data, list):
            if not all(isinstance(item, dict) for item in data):
                sys.exit(f"Config array in {path} must contain only objects")
            all_configs.extend(data)
            output_as_list = True   # file was an array -> preserve array form
        else:
            sys.exit(f"Config file {path} must be a JSON object or array, "
                     f"got {type(data).__name__}")

    return all_configs, output_as_list


def resolve_config(cfg: dict) -> dict:
    """
    Return a copy of *cfg* with every OID string replaced by its
    dotted-decimal equivalent.

    Raises ValueError (from resolve_oid_name) if any OID cannot be resolved.
    The message identifies which device / OID entry failed so the caller can
    report it clearly.
    """
    # Determine a human-readable device identifier for error messages.
    # For multi-IP configs "ip" is a list; show the first address in that case.
    ip = cfg.get("ip", "?")
    device_id = cfg.get("opcua_path") or (ip[0] if isinstance(ip, list) else ip)

    out = dict(cfg)
    resolved_oids = []
    for i, oid_entry in enumerate(cfg.get("oids", [])):
        entry = dict(oid_entry)
        raw = entry.get("oid", "")
        try:
            entry["oid"] = resolve_oid_name(raw)
        except ValueError as exc:
            raise ValueError(
                f"Device {device_id!r}, OID entry {i} ({raw!r}): {exc}"
            ) from exc
        resolved_oids.append(entry)
    out["oids"] = resolved_oids
    return out


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    paths = sys.argv[1:]

    # ── load raw configs (no expansion) ──────────────────────────────────────
    configs, output_as_list = load_raw_configs(paths)

    # ── resolve all OIDs — collect every failure before aborting ─────────────
    errors = []
    resolved = []
    for cfg in configs:
        try:
            resolved.append(resolve_config(cfg))
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        print("ERROR: could not resolve the following OID(s):", file=sys.stderr)
        for msg in errors:
            print(f"  • {msg}", file=sys.stderr)
        sys.exit(1)

    # ── emit JSON ─────────────────────────────────────────────────────────────
    if output_as_list:
        print(json.dumps(resolved, indent=2))
    else:
        print(json.dumps(resolved[0], indent=2))


if __name__ == "__main__":
    main()
