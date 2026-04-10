#!/usr/bin/env python3
"""
resolve_oids.py
───────────────
Read one or more device-config JSON files (same format as snmp_asyncua_bridge.py),
resolve every OID string in the config and write the updated configs to stdout as JSON.

Default (forward) mode
  Symbolic OID names  →  dotted-decimal notation.
  Uses the same resolution logic as the bridge (snmptranslate, then pysnmp).

Reverse mode  (-r / --reverse)
  Dotted-decimal OIDs  →  symbolic names (MODULE::objectName.instance).
  Relies solely on ``snmptranslate -OS`` (net-snmp must be installed).
  OIDs that are already symbolic, or that snmptranslate cannot look up, are
  left unchanged and a warning is printed to stderr (non-fatal).

Multi-IP configs (where "ip" is a JSON array) are left as-is — they are NOT
expanded into one config per address.  The only modification made to each config
is that OID strings are translated as described above.

Usage
-----
    python resolve_oids.py [-r] devices.json [more.json ...]

Output
------
  • A single JSON object  if exactly one file was given and it contained a
                          single object (not an array).
  • A JSON array          in all other cases (multiple files, or any file that
                          contained a top-level array).

Exit codes
----------
  0  All applicable OIDs translated (or left unchanged in reverse mode);
     JSON written to stdout.
  1  One or more OIDs could not be resolved in forward mode, or a config file
     could not be read / parsed.  An error message is printed to stderr;
     nothing is written to stdout.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# ── locate the bridge module ──────────────────────────────────────────────────
# resolve_oids.py is intended to live alongside snmp_asyncua_bridge.py.
# Insert its directory at the front of sys.path so the import works regardless
# of where the script is invoked from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from snmp_asyncua_bridge import resolve_oid_name, expand_oid_range
except ImportError as _e:
    sys.exit(f"Cannot import snmp_asyncua_bridge: {_e}\n"
             "Ensure resolve_oids.py is in the same directory as snmp_asyncua_bridge.py.")

# ─────────────────────────────────────────────────────────────────────────────


_DOTTED_RE = re.compile(r'^\.?\d+(\.\d+)+$')


def _is_dotted(oid: str) -> bool:
    return bool(_DOTTED_RE.match(oid))


def unresolve_oid(oid: str) -> tuple[str, bool]:
    """
    Convert a dotted-decimal OID to its symbolic name using ``snmptranslate -OS``.

    Returns ``(result, changed)`` where *result* is the symbolic name on
    success, or the original *oid* string if the translation failed (either
    because snmptranslate is unavailable, or the OID is unknown).
    *changed* is True when the OID was actually translated.

    OIDs that are already symbolic are returned unchanged (changed=False).
    """
    if not _is_dotted(oid):
        return oid, False          # already symbolic — nothing to do

    if shutil.which("snmptranslate") is None:
        return oid, False

    try:
        result = subprocess.run(
            ["snmptranslate", "-m", "ALL", "-OS", oid],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            symbolic = result.stdout.strip()
            # Reject partial translations like "SNMPv2-SMI::enterprises.96.101…"
            # where snmptranslate reached the limit of its installed MIBs and
            # left a numeric suffix.  The part after "::" (or the whole string
            # when there is no "::") must not begin with a digit.
            stem = symbolic.split("::", 1)[-1]   # drop "MODULE::" if present
            if symbolic and not _is_dotted(symbolic) and not stem[0].isdigit():
                return symbolic, True
    except (subprocess.TimeoutExpired, OSError):
        pass

    return oid, False


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


def resolve_config(cfg: dict, *, reverse: bool = False) -> tuple[dict, list[str]]:
    """
    Return ``(updated_cfg, warnings)``.

    Forward mode (reverse=False):
      Every symbolic OID name is replaced by its dotted-decimal equivalent.
      Raises ValueError if any OID cannot be resolved.

    Reverse mode (reverse=True):
      Every dotted-decimal OID is replaced by its symbolic name via
      ``snmptranslate -OS``.  OIDs that cannot be translated are left
      unchanged and a warning string is appended to *warnings*.
    """
    # Determine a human-readable device identifier for error/warning messages.
    ip = cfg.get("ip", "?")
    device_id = cfg.get("opcua_path") or (ip[0] if isinstance(ip, list) else ip)

    out = dict(cfg)
    resolved_oids = []
    warnings: list[str] = []

    for i, oid_entry in enumerate(cfg.get("oids", [])):
        entry = dict(oid_entry)
        raw = entry.get("oid", "")

        if reverse:
            if isinstance(raw, list):
                new_oids = []
                for j, item in enumerate(raw):
                    symbolic, changed = unresolve_oid(item)
                    if not changed and _is_dotted(item):
                        warnings.append(
                            f"Device {device_id!r}, OID entry {i}, element {j} ({item!r}): "
                            "snmptranslate could not resolve this OID — left unchanged"
                        )
                    new_oids.append(symbolic)
                entry["oid"] = new_oids
            else:
                symbolic, changed = unresolve_oid(raw)
                if not changed and _is_dotted(raw):
                    warnings.append(
                        f"Device {device_id!r}, OID entry {i} ({raw!r}): "
                        "snmptranslate could not resolve this OID — left unchanged"
                    )
                entry["oid"] = symbolic
        else:
            if isinstance(raw, str):
                expanded = expand_oid_range(raw)
            else:
                expanded = raw

            try:
                if isinstance(expanded, list):
                    if len(expanded) > 1 or isinstance(raw, list):
                        entry["oid"] = [resolve_oid_name(o) for o in expanded]
                    else:
                        entry["oid"] = resolve_oid_name(expanded[0])
                else:
                    entry["oid"] = resolve_oid_name(expanded)
            except ValueError as exc:
                raise ValueError(
                    f"Device {device_id!r}, OID entry {i} ({raw!r}): {exc}"
                ) from exc

        resolved_oids.append(entry)

    out["oids"] = resolved_oids
    return out, warnings


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-r", "--reverse",
        action="store_true",
        help="Reverse mode: convert dotted-decimal OIDs to symbolic names "
             "using snmptranslate. Unresolvable OIDs are left unchanged "
             "(warning printed to stderr).",
    )
    parser.add_argument(
        "configs",
        nargs="+",
        metavar="FILE",
        help="One or more device-config JSON files.",
    )
    args = parser.parse_args()

    if args.reverse and shutil.which("snmptranslate") is None:
        sys.exit("ERROR: snmptranslate not found — install net-snmp to use reverse mode.")

    # ── load raw configs (no expansion) ──────────────────────────────────────
    configs, output_as_list = load_raw_configs(args.configs)

    # ── translate all OIDs — collect every failure before aborting ────────────
    errors = []
    all_warnings = []
    resolved = []
    for cfg in configs:
        try:
            out_cfg, warnings = resolve_config(cfg, reverse=args.reverse)
            resolved.append(out_cfg)
            all_warnings.extend(warnings)
        except ValueError as exc:
            errors.append(str(exc))

    if all_warnings:
        print("WARNING: the following OID(s) could not be reverse-resolved "
              "and were left unchanged:", file=sys.stderr)
        for msg in all_warnings:
            print(f"  • {msg}", file=sys.stderr)

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
