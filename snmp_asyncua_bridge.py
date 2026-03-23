"""
snmp_asyncua_bridge.py
────────────────────
SNMP → OPC UA bridge using pysnmp (SNMPv2c) and asyncua.

Usage
-----
python snmp_asyncua_bridge.py \
    --opcua-endpoint opc.tcp://0.0.0.0:4840/nectarcam/ \
    --opcua-namespace http://cta-observatory.org/nectarcam/snmpdevices/ \
    --opcua-root SNMPDevices \
    --opcua-user admin:secret \
    --log-level INFO \
    --log-file bridge.log

Configuration example
---------------------
Each SNMPPoller is built from a dict like:

    {
        "host":        "192.168.1.10",
        "port":        161,             # optional, defaults to 161
        "community":   "public",        # optional, defaults to "public"
        "description": "Main distribution switch, rack A",  # optional, defaults to ""
        "opcua_path":  "Switch01",      # relative to --opcua-root (or Objects/ if root is empty)
        "poll_interval": 10,            # optional, defaults to 10 (seconds)
        "snmp_timeout":  2.0,           # optional, defaults to 2.0 (seconds per attempt)
        "snmp_retries":  1,             # optional, defaults to 1
        "default_lifetime": 30, # optional; per-OID default for lifetime (0 = never expire)
        "oids_per_get":  1,     # optional; max OIDs per SNMP GET request:
                                #   -1 (default) → use the server-wide default (--default-oids-per-get)
                                #    0            → unlimited (all due OIDs in one request)
                                #   >0            → at most this many OIDs per GET (batched)
        "oids": [
            {
                "oid":         "1.3.6.1.2.1.1.1.0",   # sysDescr  (dotted-decimal)
                "opcua_name":  "sysDescr",
                "opcua_type":  "String",
                "description": "System description",   # optional, defaults to ""
                "poll_every":  5,                      # optional; read every 5 cycles (default 1)
            },
            {
                "oid":         "SNMPv2-MIB::sysUpTime.0",   # symbolic name also accepted
                "opcua_name":  "sysUpTime",
                "opcua_type":  "UInt32",
                "description": "System uptime in hundredths of a second",
                                                       # poll_every defaults to 1 (every cycle)
            },
        ],
        "constants": [                          # optional; written once at startup
            {
                "opcua_name":  "SoftwareVersion",
                "opcua_type":  "String",
                "value":       "2.0.0",
                "description": "Firmware version of the device",   # optional
            },
        ],
    }

OPC UA root path (--opcua-root)
--------------------------------
Controls the container node(s) created above every device object:

  --opcua-root SNMPDevices        → Objects/SNMPDevices/Switch01  (default)
  --opcua-root Camera0.SNMPDevices → Objects/Camera0/SNMPDevices/Switch01
  --opcua-root ""                  → Objects/Switch01  (devices directly under Objects/)

The value is split on "." so each segment becomes one Object node level.
Passing an empty string (or omitting the flag and passing "") places devices
directly under the server's Objects/ node with no intermediate container.

Supported opcua_type values
---------------------------
  Boolean, SByte, Byte, Int16, UInt16, Int32, UInt32,
  Int64, UInt64, Float, Double, String, ByteString, DateTime

Multiple identical devices (ip array)
--------------------------------------
When "host" is a JSON array of strings, one SNMPPoller is created per
address.  The fields "opcua_path" and "description" may contain the
placeholder {instance}, which is replaced with the zero-based index of
the address in the array using Python str.format_map(), so any format
spec is valid:

    "host":       ["192.168.1.10", "192.168.1.11", "192.168.1.12"],
    "opcua_path": "Switch{instance:02d}",
    "description": "Distribution switch {instance}",

If "host" is an array and "opcua_path" does not contain {instance}, a
warning is logged and "_{instance}" is appended automatically as a fallback.

Within each entry in "constants", {instance} is substituted into the
"value" field (when it is a string) and the "description" field, allowing
per-device metadata such as serial numbers or slot identifiers:

    "constants": [{"opcua_name": "SlotIndex", "opcua_type": "UInt16",
                   "value": "{instance}",
                   "description": "Physical slot {instance}"}]
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import logging.handlers
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ── third-party ──────────────────────────────────────────────────────────────
try:
    # pysnmp 7.x (lextudio fork) uses v3arch.asyncio
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,                        # 7.x uses snake_case names
    )
    from pysnmp.proto.rfc1902 import (
        Counter32,
        Counter64,
        Gauge32,
        Integer,
        Integer32,
        IpAddress,
        OctetString,
        TimeTicks,
        Unsigned32,
    )
    from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject
except ImportError:
    sys.exit("pysnmp is required:  pip install pysnmp-lextudio")

try:
    from asyncua import Server, ua
except ImportError:
    sys.exit("asyncua is required:  pip install asyncua")

# UserRole moved between asyncua releases; try both locations
try:
    from asyncua.server.users import UserRole
except ImportError:
    try:
        from asyncua.server.user_managers import UserRole
    except ImportError:
        UserRole = None   # will fall back to a plain string check in _SingleUserManager

# ─────────────────────────────────────────────────────────────────────────────
# Logging helpers
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(level: str, log_file: Optional[str], name: str = "snmp_asyncua_bridge") -> logging.Logger:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    fmt = logging.Formatter(
        "%(asctime)s.%(msecs)03d  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=3
        ))
    for h in handlers:
        h.setFormatter(fmt)
        root.addHandler(h)
    logging.getLogger("asyncua").setLevel(logging.WARNING)
    return logging.getLogger(name)


log = logging.getLogger("snmp_asyncua_bridge")

# ─────────────────────────────────────────────────────────────────────────────
# Type mapping:  OPC UA type name  →  (ua.VariantType,  Python cast)
# ─────────────────────────────────────────────────────────────────────────────

_UA_TYPE_MAP: Dict[str, tuple[ua.VariantType, Any]] = {
    "Boolean":    (ua.VariantType.Boolean,    bool),
    "SByte":      (ua.VariantType.SByte,      int),
    "Byte":       (ua.VariantType.Byte,       int),
    "Int16":      (ua.VariantType.Int16,      int),
    "UInt16":     (ua.VariantType.UInt16,     int),
    "Int32":      (ua.VariantType.Int32,      int),
    "UInt32":     (ua.VariantType.UInt32,     int),
    "Int64":      (ua.VariantType.Int64,      int),
    "UInt64":     (ua.VariantType.UInt64,     int),
    "Float":      (ua.VariantType.Float,      float),
    "Double":     (ua.VariantType.Double,     float),
    "String":     (ua.VariantType.String,     str),
    "ByteString": (ua.VariantType.ByteString, bytes),
    "DateTime":   (ua.VariantType.DateTime,   None),  # cast_fn unused; values are datetime objects
}

# Typed zero values for each OPC UA type -- used when a constant is declared
# with value=None (BadWaitingForInitialData) so asyncua can infer the VariantType
# from the initial value before the real value is written.
_UA_TYPE_ZEROS: Dict[str, Any] = {
    "Boolean":    False,
    "SByte":      0,
    "Byte":       0,
    "Int16":      0,
    "UInt16":     0,
    "Int32":      0,
    "UInt32":     0,
    "Int64":      0,
    "UInt64":     0,
    "Float":      0.0,
    "Double":     0.0,
    "String":     "",
    "ByteString": b"",
    "DateTime":   datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc),
}


# Names of the built-in variables added automatically by SNMPPoller to every
# device node.  Defined once here so __post_init__, docstrings, and any other
# code that needs the set can reference a single authoritative source.
#
# Ordering reflects the logical grouping used in build_variable_specs() and
# _init_store():
#   identity       : device_host, device_port
#   polling metrics: device_polling_timestamp, device_polling_age,
#                    device_polling_interval, device_polling_success_count
#   state flags    : device_server_online (bridge fact), device_state (overridable)
_BUILTIN_VARIABLE_NAMES: frozenset[str] = frozenset({
    "device_host",
    "device_port",
    "device_polling_timestamp",
    "device_polling_age",
    "device_polling_interval",
    "device_polling_success_count",
    "device_server_online",
    "device_state",
})


def _make_status_dv(opcua_type: str, status: ua.StatusCode) -> ua.DataValue:
    """
    Build a ua.DataValue carrying *status* and a typed zero value for *opcua_type*.

    asyncua rejects writing a DataValue whose Variant type is Null to a node
    that was created with a concrete type, even when the intent is only to
    communicate a bad/uncertain status.  Always pairing the status code with a
    correctly-typed (zero) value avoids the BadTypeMismatch error while still
    letting OPC UA clients see the status code.
    """
    variant_type = _UA_TYPE_MAP[opcua_type][0]
    zero = _UA_TYPE_ZEROS.get(opcua_type, "")
    return ua.DataValue(
        Value=ua.Variant(zero, variant_type),
        StatusCode_=status,
    )


def _snmp_value_to_python(raw_value: Any) -> Any:
    """Convert a pysnmp value object to a plain Python value.

    OctetString is always returned as raw bytes rather than via prettyPrint().
    prettyPrint() is unreliable for binary data: it returns a lossy ASCII
    string for printable bytes, or a '0x...' hex string for non-ASCII bytes
    (the exact form depends on the pysnmp version and whether lookupMib is
    enabled).  Returning bytes lets _cast_to_ua() apply the correct conversion
    to whichever OPC UA type the configuration declares (String, ByteString,
    etc.), and keeps the behaviour consistent regardless of MIB availability.

    TimeTicks is returned as a datetime.timedelta (the natural Python type for
    a duration) rather than as a raw centisecond integer.  _cast_to_ua() then
    converts it to milliseconds for any numeric UA type, or to the str()
    representation (e.g. "5:23:49.160000") for String.
    """
    if isinstance(raw_value, TimeTicks):
        return datetime.timedelta(seconds=int(raw_value) / 100)
    if isinstance(raw_value, (Integer, Integer32,
                               Counter32, Counter64, Gauge32, Unsigned32)):
        return int(raw_value)
    if isinstance(raw_value, IpAddress):
        return raw_value.prettyPrint()   # gives "10.10.3.250", not raw bytes
    if isinstance(raw_value, OctetString):
        return bytes(raw_value)
    return raw_value.prettyPrint()


def _cast_to_ua(value: Any, opcua_type: str) -> ua.DataValue | ua.Variant:
    """
    Cast a Python value to the requested OPC UA Variant.

    Returns a ua.Variant on success.  On cast failure returns a ua.DataValue
    with status BadDataEncodingInvalid so OPC UA clients see a proper error
    status rather than a silently mis-typed String value written to a node
    that was declared with a different type.

    Special case: when the target type is String and the value is bytes
    (as returned by _snmp_value_to_python for OctetString), the bytes are
    decoded to a Python str using UTF-8 with a latin-1 fallback rather than
    calling str() which would produce the Python repr "b'...'".

    For numeric target types (Float, Double, and integer variants), bytes are
    also decoded to a string first so that DisplayString OIDs whose values are
    numeric (e.g. wrpcTemperatureValue = b"41.9375") can be cast correctly.
    Without this, float(b"41.9375") would raise TypeError.

    datetime.timedelta values (from TimeTicks OIDs) are converted to
    milliseconds (as a float) for any numeric UA type, or to their str()
    representation (e.g. "5:23:49.160000") for String.
    """
    variant_type, cast_fn = _UA_TYPE_MAP[opcua_type]
    try:
        if isinstance(value, datetime.timedelta):
            if opcua_type == "String":
                value = str(value)
            else:
                value = value.total_seconds() * 1000.0
        elif isinstance(value, (bytes, bytearray)) and opcua_type != "ByteString":
            try:
                value = value.decode("utf-8").strip()
            except UnicodeDecodeError:
                value = value.decode("latin-1").strip()
        return ua.Variant(cast_fn(value), variant_type)
    except (ValueError, TypeError) as exc:
        log.warning("Type cast failed (%s → %s): %s – writing BadDataEncodingInvalid",
                    value, opcua_type, exc)
        zero = _UA_TYPE_ZEROS.get(opcua_type, "")
        return ua.DataValue(
            Value=ua.Variant(zero, variant_type),
            StatusCode_=ua.StatusCode(ua.StatusCodes.BadDataEncodingInvalid),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Symbolic OID resolution  (e.g. "SNMPv2-MIB::sysName.0" → "1.3.6.1.2.1.1.5.0")
# ─────────────────────────────────────────────────────────────────────────────

_DOTTED_RE = re.compile(r'^\d+(\.\d+)+$')


def _is_dotted(oid: str) -> bool:
    """Return True if *oid* is already in valid dotted-decimal notation."""
    return bool(_DOTTED_RE.match(oid))


def _resolve_via_snmptranslate(oid: str) -> Optional[str]:
    """
    Use the ``snmptranslate`` command (net-snmp) to convert a symbolic OID to
    dotted-decimal.  Returns the numeric string, or None if the tool is
    unavailable or the name is unknown.
    """
    import shutil
    import subprocess
    if shutil.which("snmptranslate") is None:
        return None
    try:
        result = subprocess.run(
            ["snmptranslate", "-On", oid],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            numeric = result.stdout.strip()
            if _is_dotted(numeric.lstrip(".")):
                return numeric.lstrip(".")
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def _resolve_via_pysnmp(oid: str) -> Optional[str]:
    """
    Use pysnmp's built-in MIB compiler to resolve a symbolic OID.  Only works
    for MIBs that pysnmp ships with (RFC MIBs, SNMPv2-MIB, IF-MIB, etc.).
    Returns the dotted-decimal string, or None on failure.
    """
    try:
        from pysnmp.smi import builder, view, compiler, rfc1902 as smi_rfc1902
        mib_builder = builder.MibBuilder()
        compiler.addMibCompiler(mib_builder)
        mib_view = view.MibViewController(mib_builder)
        obj = ObjectIdentity(oid)
        obj.resolveWithMib(mib_view)
        return str(obj.getOid())
    except Exception as exc:
        log.debug("pysnmp MIB resolution failed for %r: %s", oid, exc)
        return None


def resolve_oid_name(oid: str) -> str:
    """
    Convert a symbolic OID name to dotted-decimal notation.

    Accepts both ``MODULE::objectName.instance`` (MIB-qualified) and plain
    ``objectName.instance`` forms.  Dotted-decimal OIDs are returned unchanged.

    Resolution order:
      1. Already dotted-decimal → return as-is.
      2. ``snmptranslate`` (net-snmp, respects the system MIB path).
      3. pysnmp's bundled MIB compiler (covers RFC/IANA MIBs without net-snmp).

    Raises ``ValueError`` if neither resolver can translate the name.
    """
    if _is_dotted(oid):
        return oid

    numeric = _resolve_via_snmptranslate(oid)
    if numeric is not None:
        log.debug("Resolved OID %r → %s (via snmptranslate)", oid, numeric)
        return numeric

    numeric = _resolve_via_pysnmp(oid)
    if numeric is not None:
        log.debug("Resolved OID %r → %s (via pysnmp MIB compiler)", oid, numeric)
        return numeric

    raise ValueError(
        f"Cannot resolve symbolic OID {oid!r}: "
        "snmptranslate was not found or returned an error, and pysnmp's "
        "bundled MIBs do not contain this name. "
        "Install net-snmp (for snmptranslate) or add the required MIB files."
    )


# ─────────────────────────────────────────────────────────────────────────────
# OID configuration dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OIDConfig:
    oid: str                  # dotted-decimal or symbolic, e.g. "SNMPv2-MIB::sysName.0"
                              # Symbolic names are resolved to dotted-decimal in __post_init__
                              # so the poll loop and OID-key resolver always see numeric OIDs.
    opcua_name: str           # variable name on OPC UA side; names beginning with "_" are
                              # "local" — polled and stored but not published to OPC UA.
    opcua_type: str           # one of the keys in _UA_TYPE_MAP
    description: str = ""
    lifetime: float = -1.0   # seconds; <0 means "use device default"; 0 means never expire
    poll_every: int = 1       # read this OID every N PLL cycles (1 = every cycle)

    @property
    def is_local(self) -> bool:
        """True when this OID should not be published to OPC UA (name starts with '_')."""
        return self.opcua_name.startswith("_")

    def __post_init__(self):
        if self.opcua_type not in _UA_TYPE_MAP:
            raise ValueError(
                f"Unknown opcua_type '{self.opcua_type}' for OID {self.oid}. "
                f"Valid types: {list(_UA_TYPE_MAP)}"
            )
        # poll_every < 1 is meaningless — clamp silently to 1 (every cycle).
        if self.poll_every < 1:
            self.poll_every = 1
        # Resolve symbolic names (e.g. "SNMPv2-MIB::sysName.0") to dotted-decimal
        # once at construction time so the poll loop and OID-key resolver always
        # see numeric OIDs.
        self.oid = resolve_oid_name(self.oid)


# ─────────────────────────────────────────────────────────────────────────────
# Constant variable configuration dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ConstantConfig:
    """
    A fixed OPC UA variable whose value is written once at startup and never
    updated again.  Useful for metadata such as firmware version, serial number,
    or any other static property of a device.

    If *value* is ``None`` the node is created with a typed zero initial value
    and immediately stamped with ``BadWaitingForInitialData``.  This is useful
    for derived variables that are computed from polled data (e.g. a MAC address
    assembled from two raw OIDs) -- they can be declared alongside true constants
    in the config while still indicating to OPC UA clients that no value is
    available until the first poll completes.

    Both *value* and *description* support ``{instance}`` substitution when the
    parent device config uses a multi-IP array (see _expand_multi_ip).

    The *lifetime* field controls expiry of the store entry and uses the same
    sentinel convention as OIDConfig:

      lifetime == -1  (default)
          Resolved automatically in _init_store():
            • value is not None  →  0.0  (true constant, never expires)
            • value is None      →  device default_lifetime  (derived variable,
                                    expires like a polled OID when its sources
                                    are unavailable)
      lifetime >= 0
          Used as-is, overriding the automatic resolution above.
    """
    opcua_name: str           # variable name on the OPC UA side
    opcua_type: str           # one of the keys in _UA_TYPE_MAP
    value: Any                # the constant value, or None for BadWaitingForInitialData
    description: str = ""
    lifetime: float = -1.0  # seconds; -1 = resolve automatically (see docstring)

    def __post_init__(self):
        if self.opcua_type not in _UA_TYPE_MAP:
            raise ValueError(
                f"Unknown opcua_type '{self.opcua_type}' for constant "
                f"'{self.opcua_name}'. Valid types: {list(_UA_TYPE_MAP)}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Node specification dataclass  (used by build_variable_specs / create_variables)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class NodeSpec:
    """
    Describes a single OPC UA variable to be created under a device node.

    Produced by SNMPPoller.build_variable_specs() and consumed by
    SNMPPoller.create_variables().  Subclasses may add, remove, or modify
    entries in the spec dict before create_variables() is called.

    Fields
    ------
    opcua_type    One of the keys in _UA_TYPE_MAP (e.g. "String", "UInt32").
    initial_value The value written at node creation.  For SNMP-polled variables
                  this is a typed zero / empty so asyncua knows the VariantType;
                  the node is immediately overwritten with BadWaitingForInitialData.
                  For constants this is the actual constant value.
    description   Written to the node's Description attribute if non-empty.
    initial_status Optional OPC UA status code written right after creation.
                  None means "leave at Good / the value written by add_variable".
    """
    opcua_type:     str
    initial_value:  Any
    description:    str = ""
    initial_status: Optional[ua.StatusCode] = None


@dataclass
class StoreEntry:
    """
    A single entry in the SNMPPoller internal data store.

    Fields
    ------
    data_value      The current ua.DataValue (value + status code).  The Value
                    field may be None when the status is bad (e.g. BadNoCommunication).
    timestamp       Wall-clock time (time.monotonic()) when the value was last
                    successfully read from the SNMP device.  None until the first
                    successful read.
    lifetime  Seconds before an unread variable is considered expired
                    (0 = never expire).  Copied from OIDConfig / ConstantConfig.
    opcua_type      OPC UA type name string (key into _UA_TYPE_MAP).  Kept here
                    so write_variables can inspect the type if needed.
    is_local        True for OID variables whose opcua_name starts with '_'.
                    These are stored but no OPC UA node is created for them.
    next_cycle      The PLL cycle number on which this variable is next due to be
                    polled.  Initialised to 0 so all variables fire on cycle 1.
                    Advanced by poll_every on each successful read (scheduled polls
                    only — forced full-reloads never advance next_cycle).
                    Reset to _polling_cycle when the device goes offline so all
                    variables are re-read on the next successful cycle.
    updated_this_cycle
                    True when this entry received a fresh value from SNMP in the
                    current _poll_once() cycle.  Cleared at the start of every
                    cycle (before the GET) and set when the SNMP response is
                    stored.  Always False for constants and built-in variables.
                    Subclasses may read this in write_variables() to gate
                    derived-value computation on whether the source OID(s) were
                    actually updated this cycle.
    """
    data_value:       ua.DataValue
    timestamp:        Optional[float]   # time.monotonic(), or None if never read
    lifetime: float             # seconds; 0 = never expire
    opcua_type:       str
    is_local:         bool = False
    next_cycle:       int  = 0        # PLL cycle on which this variable is next due
    updated_this_cycle: bool = False  # set by _poll_once when a fresh SNMP value is
                                      # stored; cleared at the start of each cycle


@dataclass
class SNMPPoller:
    """
    Polls a single SNMP device (SNMPv2c) and writes values to OPC UA nodes.

    Automatically adds eight built-in variables to the OPC UA object
    (see also ``_BUILTIN_VARIABLE_NAMES``):
      • device_host                   (String)    – IP address of the device
      • device_port                   (UInt16)    – UDP port of the SNMP agent
      • device_polling_timestamp      (DateTime)  – wall-clock time of the last successful poll
      • device_polling_age            (Double)    – seconds since the last successful poll (always Good)
      • device_polling_interval       (Double)    – configured poll interval in seconds
      • device_polling_success_count  (UInt32)    – cumulative count of successful polls (always Good)
      • device_server_online          (Boolean)   – True when SNMP agent is reachable; never modified by subclasses
      • device_state                (Int32)     – 0 = offline, 1 = online (may be overridden by subclasses)

    OID variables whose ``opcua_name`` begins with ``"_"`` are *local*: they are
    polled from SNMP and stored in the internal data store but no OPC UA node is
    created for them.  Subclasses can read them from ``self._store`` to compute
    derived variables.

    Internal data store (``self._store``)
    -------------------------------------
    A dict mapping ``opcua_name`` → ``StoreEntry`` for every variable managed by
    this poller: OID variables (local and published), constants, and server
    variables listed in ``_BUILTIN_VARIABLE_NAMES``.

    Each entry tracks:
      • ``data_value``          – current ua.DataValue (value + status)
      • ``timestamp``           – monotonic time of last successful SNMP read
      • ``lifetime``            – expiry window in seconds (0 = never)
      • ``opcua_type``          – OPC UA type name string
      • ``is_local``            – True for underscore-prefixed OID variables
      • ``updated_this_cycle``  – True when a fresh SNMP value was stored this
                                  cycle; always False for constants and built-ins.
                                  Subclasses may gate derived-value computation on
                                  this flag in ``write_variables()``.

    Lifetime / staleness management (handled in poll_once)
    -------------------------------------------------------
    When a variable is not updated in a poll cycle (e.g. the device is offline):
      • Never successfully read: left as BadWaitingForInitialData, not touched.
      • Has a prior value, within lifetime (or lifetime == 0):
            status → UncertainLastUsableValue, value preserved.
      • Has a prior value, lifetime expired (lifetime > 0):
            status → BadNoCommunication, value → typed zero for the OPC UA type.
      • BadNotSupported: permanent, never overwritten by staleness logic.

    Subclassing hooks
    -----------------
    build_variable_specs()    Override to add, remove, or modify the NodeSpec
                              dict before nodes are created.
    create_variables()        Override to customise how nodes are actually
                              created (e.g. add nodes outside the spec dict).
    write_variables()         Override to intercept writes.  The override can
                              inspect and mutate ``self._store`` entries before
                              calling ``super().write_variables()``, which writes
                              every non-local store entry to its OPC UA node.
    on_address_space_ready()  Called once after all nodes have been created.

    Polling loop
    ------------
    ``run()`` is phase-locked: each slot is exactly ``poll_interval`` seconds
    wide.  If a poll overruns into future slots, the missed slots are logged and
    skipped.  If the previous poll is still in flight when the next slot fires
    (possible when ``snmp_timeout * (snmp_retries + 1) > poll_interval``), that
    slot is skipped entirely with a warning — no store updates, no OPC UA writes.

    Per-variable poll frequency
    ---------------------------
    Each OID may specify ``poll_every`` (default 1) to be read only every N PLL
    cycles.  The store entry for each OID tracks ``next_cycle`` — the cycle
    number on which it is next due.  On each scheduled poll only the due OIDs are
    included in the SNMP GET; non-due OIDs are left entirely untouched (no
    staleness is applied).  On a successful read ``next_cycle`` is advanced by
    ``poll_every``.  When the device goes offline ``next_cycle`` is reset to
    ``_polling_cycle`` for all OIDs so they all fire together on the next
    successful cycle (PLL phasing for slow-polled OIDs resets at that point).

    Staleness (``_apply_staleness``) is called only for OIDs that were actually
    requested this cycle and did not respond, or for all OIDs when the device is
    offline.  OIDs that were simply not due are never touched.

    On-demand full reload
    ---------------------
    ``force_reload()`` acquires ``_poll_lock`` (waiting for any in-flight
    scheduled poll to finish) then issues a GET for *all* OIDs regardless of
    ``next_cycle``.  ``next_cycle`` is never advanced and ``_polling_cycle`` is
    never changed, so the PLL schedule is undisturbed.  Returns True if the
    device responded.  Intended for use by subclass OPC UA method handlers that
    change hardware state via a side channel and need fresh values immediately.
    """

    # ── config ────────────────────────────────────────────────────────────────
    host: str
    port: int
    community: str
    description: str          # human-readable device description (written to OPC UA object)
    opcua_path: str           # dot-separated path relative to root, e.g. "Switch01"
    poll_interval: float      # seconds
    oids: List[OIDConfig]
    constants: List[ConstantConfig] = field(default_factory=list)
    snmp_timeout: float = 2.0   # seconds per SNMP request attempt
    snmp_retries: int = 1       # number of retries after the first attempt
    # Default lifetime (seconds) for OID variables that do not specify their own.
    # 0 means variables with lifetime=-1 never expire.
    default_lifetime: float = 0.0
    # Maximum number of OIDs sent in a single SNMP GET request.
    #  -1  (default) → resolved at registration time to the server-wide default
    #                   (OPCUAServer.default_oids_per_get, set via --default-oids-per-get)
    #   0             → unlimited — all due OIDs are sent in one GET
    #  >0             → at most this many OIDs per GET; the list is split into
    #                   sequential batches and results are merged before processing
    #
    # Unlike other sentinel fields (e.g. OIDConfig.lifetime, which is resolved
    # lazily at _init_store() time against the device's own default_lifetime),
    # this sentinel is resolved eagerly in OPCUAServer.register() because the
    # server default is external to the poller and not available at construction
    # time.  After registration the field always holds a concrete value (>= 0)
    # and to_dict() serialises that resolved value so that dumped configs are
    # fully self-contained and CLI-independent.
    oids_per_get: int = -1

    # ── runtime state (set by OPCUAServer during registration) ───────────────
    _node_map: Dict[str, Any] = field(default_factory=dict, init=False, repr=False)
    # Internal data store: opcua_name → StoreEntry for ALL variables managed by
    # this poller (OIDs, constants, server variables).  Populated in
    # _init_store() which is called from on_address_space_ready().
    _store: Dict[str, "StoreEntry"] = field(default_factory=dict, init=False, repr=False)
    # Lock that prevents concurrent polls.  If a poll cycle starts while the
    # previous one is still awaiting its SNMP response, the new cycle is skipped
    # entirely and the in-flight poll is left to complete normally.
    # force_reload() also acquires this lock and waits — it never skips.
    _poll_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    # PLL cycle number of the last poll actually *launched* by run().
    # Updated only when a poll fires, not when a slot is skipped.
    # Read by _poll_once() to decide which OIDs are due and to reset
    # next_cycle values when the device goes offline.
    _polling_cycle: int = field(default=0, init=False, repr=False)
    # The asyncua Object node for this device — available to subclasses from
    # on_address_space_ready() onwards.
    _device_node: Any = field(default=None, init=False, repr=False)
    _snmp_engine: Any = field(default=None, init=False, repr=False)
    # UdpTransportTarget is async to construct, so it is created lazily on the
    # first poll and cached here.  ip/port/timeout/retries never change so one
    # instance suffices for the lifetime of the poller.
    _transport_target: Any = field(default=None, init=False, repr=False)

    # ── OID resolution cache ──────────────────────────────────────────────────
    # Maps opcua_name -> exact OID key string as returned by pysnmp.
    # Populated on the first successful poll; cleared when the device goes
    # offline so keys are re-resolved on recovery.
    _oid_key_cache: Dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _was_offline: bool = field(default=True, init=False, repr=False)

    # ─────────────────────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        if self.poll_interval <= 0:
            raise ValueError(
                f"poll_interval must be > 0, got {self.poll_interval!r} "
                f"for poller {self.opcua_path!r}"
            )
        if self.snmp_timeout <= 0:
            raise ValueError(
                f"snmp_timeout must be > 0, got {self.snmp_timeout!r} "
                f"for poller {self.opcua_path!r}"
            )
        if self.snmp_retries < 0:
            raise ValueError(
                f"snmp_retries must be >= 0, got {self.snmp_retries!r} "
                f"for poller {self.opcua_path!r}"
            )
        if self.default_lifetime < 0:
            raise ValueError(
                f"default_lifetime must be >= 0, got {self.default_lifetime!r} "
                f"for poller {self.opcua_path!r}"
            )

        # Create the SnmpEngine once and reuse it across all polls.
        # Recreating it on every call is heavyweight (dispatcher threads, etc.)
        # and leaks resources even when close_dispatcher() is called.
        self._snmp_engine = SnmpEngine()

        # Names reserved for built-in server variables — cannot be used as OID
        # or constant names because they would silently overwrite each other's
        # OPC UA node in _node_map and their store entries.
        # Detect duplicate opcua_name values within this poller's OID list and
        # constants, and guard against collisions with the built-in variable names.
        seen: set[str] = set()
        for o in self.oids:
            if o.opcua_name in _BUILTIN_VARIABLE_NAMES:
                raise ValueError(
                    f"OID opcua_name {o.opcua_name!r} in poller {self.opcua_path!r} "
                    f"conflicts with a built-in variable name: {sorted(_BUILTIN_VARIABLE_NAMES)}"
                )
            if o.opcua_name in seen:
                raise ValueError(
                    f"Duplicate opcua_name {o.opcua_name!r} in poller {self.opcua_path!r}"
                )
            seen.add(o.opcua_name)
        for c in self.constants:
            if c.opcua_name in _BUILTIN_VARIABLE_NAMES:
                raise ValueError(
                    f"Constant opcua_name {c.opcua_name!r} in poller {self.opcua_path!r} "
                    f"conflicts with a built-in variable name: {sorted(_BUILTIN_VARIABLE_NAMES)}"
                )
            if c.opcua_name in seen:
                raise ValueError(
                    f"Duplicate opcua_name {c.opcua_name!r} in poller {self.opcua_path!r} "
                    f"(conflicts with an OID or another constant)"
                )
            seen.add(c.opcua_name)

    @classmethod
    def from_dict(cls, cfg: dict) -> "SNMPPoller":
        """Construct from a plain configuration dictionary."""
        oids = []
        for i, o in enumerate(cfg["oids"]):
            try:
                oids.append(OIDConfig(**o))
            except TypeError as exc:
                raise ValueError(
                    f"OID entry {i} in poller {cfg.get('opcua_path', '?')!r} "
                    f"has an unrecognised field: {exc}"
                ) from exc
        constants = []
        for i, c in enumerate(cfg.get("constants", [])):
            try:
                constants.append(ConstantConfig(**c))
            except TypeError as exc:
                raise ValueError(
                    f"Constant entry {i} in poller {cfg.get('opcua_path', '?')!r} "
                    f"has an unrecognised field: {exc}"
                ) from exc
        return cls(
            host=cfg["host"],
            port=int(cfg.get("port", 161)),
            community=cfg.get("community", "public"),
            description=cfg.get("description", ""),
            opcua_path=cfg["opcua_path"],
            poll_interval=float(cfg.get("poll_interval", 10)),
            snmp_timeout=float(cfg.get("snmp_timeout", 2.0)),
            snmp_retries=int(cfg.get("snmp_retries", 1)),
            oids=oids,
            constants=constants,
            default_lifetime=float(cfg.get("default_lifetime", 0.0)),
            oids_per_get=int(cfg.get("oids_per_get", -1)),
        )

    def to_dict(self) -> dict:
        """
        Serialise this poller back to a configuration dictionary equivalent to
        what would be loaded from a JSON file, with every field fully specified.

        All values reflect the live dataclass state: symbolic OIDs have been
        resolved to dotted-decimal, multi-IP instances are fully expanded (one
        dict per host), and every optional field that was defaulted is present
        with its resolved value.  The result can be written to JSON and reloaded
        with any CLI options to reproduce identical behaviour.
        """
        return {
            "host":             self.host,
            "port":             self.port,
            "community":        self.community,
            "description":      self.description,
            "opcua_path":       self.opcua_path,
            "poll_interval":    self.poll_interval,
            "snmp_timeout":     self.snmp_timeout,
            "snmp_retries":     self.snmp_retries,
            "default_lifetime": self.default_lifetime,
            "oids_per_get":     self.oids_per_get,
            "oids": [
                {
                    "oid":         o.oid,
                    "opcua_name":  o.opcua_name,
                    "opcua_type":  o.opcua_type,
                    "description": o.description,
                    "lifetime":    o.lifetime,
                    "poll_every":  o.poll_every,
                }
                for o in self.oids
            ],
            "constants": [
                {
                    "opcua_name":  c.opcua_name,
                    "opcua_type":  c.opcua_type,
                    "value":       c.value,
                    "description": c.description,
                    "lifetime":    c.lifetime,
                }
                for c in self.constants
            ],
        }

    # ── subclassing hooks ─────────────────────────────────────────────────────

    def build_variable_specs(self) -> Dict[str, "NodeSpec"]:
        """
        Build and return the complete dict of NodeSpecs for this poller.

        Keys are opcua_name strings.  The dict is ordered: built-ins first
        (see _BUILTIN_VARIABLE_NAMES for the canonical ordered list),
        then published OID variables (local/underscore-prefixed OIDs are omitted —
        they have no OPC UA node), then constants.

        Override to add, remove, or modify specs before node creation.
        Entries added here with names that also appear in _node_map will be
        available to write_variables() automatically.
        """
        specs: Dict[str, NodeSpec] = {}

        # ── built-in server metadata variables ───────────────────────────────
        specs["device_host"] = NodeSpec(
            opcua_type="String",
            initial_value=self.host,
            description="IP address of the SNMP device",
        )
        specs["device_port"] = NodeSpec(
            opcua_type="UInt16",
            initial_value=self.port,
            description="UDP port of the SNMP agent",
        )
        specs["device_polling_timestamp"] = NodeSpec(
            opcua_type="DateTime",
            initial_value=datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc),
            description="Wall-clock time of the last successful poll",
            initial_status=ua.StatusCode(ua.StatusCodes.BadWaitingForInitialData),
        )
        specs["device_polling_age"] = NodeSpec(
            opcua_type="Double",
            initial_value=0.0,
            description="Seconds since the last successful poll (always Good status)",
            initial_status=ua.StatusCode(ua.StatusCodes.BadWaitingForInitialData),
        )
        specs["device_polling_interval"] = NodeSpec(
            opcua_type="Double",
            initial_value=self.poll_interval,
            description="Configured poll interval in seconds",
        )
        specs["device_polling_success_count"] = NodeSpec(
            opcua_type="UInt32",
            initial_value=0,
            description="Cumulative count of successful SNMP polls (always Good status)",
        )
        specs["device_server_online"] = NodeSpec(
            opcua_type="Boolean",
            initial_value=False,
            description=(
                "True when the SNMP agent is reachable. "
                "Mirrors the bridge reachability state; never modified by subclasses."
            ),
        )
        specs["device_state"] = NodeSpec(
            opcua_type="Int32",
            initial_value=0,
            description="Device state: 0 = offline, 1 = online",
        )

        # ── SNMP-polled OID variables (published only — skip local ones) ─────
        # Local (underscore-prefixed) OIDs are still polled from the device and
        # held in the data store, but no OPC UA node is created for them.
        for oid_cfg in self.oids:
            if oid_cfg.is_local:
                continue
            zero = _UA_TYPE_ZEROS.get(oid_cfg.opcua_type, "")
            specs[oid_cfg.opcua_name] = NodeSpec(
                opcua_type=oid_cfg.opcua_type,
                initial_value=zero,
                description=oid_cfg.description,
                initial_status=ua.StatusCode(ua.StatusCodes.BadWaitingForInitialData),
            )

        # ── constants ─────────────────────────────────────────────────────────
        for const_cfg in self.constants:
            if const_cfg.value is None:
                # None means "derived / not yet available" -- create a typed
                # zero placeholder and stamp BadWaitingForInitialData, exactly
                # like polled variables on startup.
                _zero = _UA_TYPE_ZEROS.get(const_cfg.opcua_type, "")
                specs[const_cfg.opcua_name] = NodeSpec(
                    opcua_type=const_cfg.opcua_type,
                    initial_value=_zero,
                    description=const_cfg.description,
                    initial_status=ua.StatusCode(ua.StatusCodes.BadWaitingForInitialData),
                )
            else:
                variant = _cast_to_ua(const_cfg.value, const_cfg.opcua_type)
                if isinstance(variant, ua.DataValue):
                    raise ValueError(
                        f"Constant {const_cfg.opcua_name!r} in poller "
                        f"{self.opcua_path!r}: value {const_cfg.value!r} "
                        f"cannot be cast to {const_cfg.opcua_type}"
                    )
                specs[const_cfg.opcua_name] = NodeSpec(
                    opcua_type=const_cfg.opcua_type,
                    initial_value=const_cfg.value,
                    description=const_cfg.description,
                )

        return specs

    async def create_variables(
        self,
        device_node: Any,
        ns_idx: int,
        specs: Dict[str, "NodeSpec"],
    ) -> None:
        """
        Create OPC UA variable nodes from *specs* under *device_node* and
        register them in self._node_map.

        Each variable is created with a string NodeId derived from the full
        path to the device plus the variable name, e.g.::

            ns=2;s="SNMPDevices.Switch01.Monitoring.sysDescr"

        This replaces the auto-generated numeric NodeIds (``ns=2;i=19``) with
        stable, human-readable identifiers that survive server restarts.

        Override to customise node creation — e.g. to set different access
        levels or add nodes that live outside the spec dict entirely.  Call
        super() to let the base implementation handle the standard specs, then
        add your extra nodes afterwards.
        """
        # _opcua_node_path is set by OPCUAServer._build_address_space before
        # create_variables is called.  Fall back to opcua_path (without the
        # server root prefix) when called outside that context, e.g. in tests.
        base_path = getattr(self, "_opcua_node_path", None) or self.opcua_path

        for opcua_name, spec in specs.items():
            variant_type, _cast_fn = _UA_TYPE_MAP[spec.opcua_type]
            # Build a stable string NodeId: "BasePath.VariableName"
            string_id = f"{base_path}.{opcua_name}" if base_path else opcua_name
            node_id = ua.NodeId(string_id, ns_idx, ua.NodeIdType.String)
            var_node = await device_node.add_variable(
                node_id,
                ua.QualifiedName(opcua_name, ns_idx),
                ua.Variant(spec.initial_value, variant_type),
            )
            await var_node.set_writable(False)
            if spec.initial_status is not None:
                await var_node.write_value(
                    ua.DataValue(
                        Value=ua.Variant(spec.initial_value, variant_type),
                        StatusCode_=spec.initial_status,
                    )
                )
            if spec.description:
                await var_node.write_attribute(
                    ua.AttributeIds.Description,
                    ua.DataValue(
                        ua.Variant(
                            ua.LocalizedText(spec.description),
                            ua.VariantType.LocalizedText,
                        )
                    ),
                )
            self._node_map[opcua_name] = var_node
            log.debug("  OPC UA variable: %s.%s (%s)  node_id=%s",
                      self.opcua_path, opcua_name, spec.opcua_type, var_node.nodeid)

    async def write_variables(self) -> None:
        """
        Write every non-local store entry to its OPC UA node.

        Iterates ``self._store`` and writes every entry that has a node in
        ``_node_map``.  Local OID entries (``is_local=True``) and entries with
        no corresponding node are silently skipped.

        Override to intercept or modify store entries before writing.  Your
        override can inspect and mutate ``self._store`` (e.g. to compute a
        derived variable and add/update an entry), then call
        ``await super().write_variables()`` to perform the actual writes.

        Example — derive a computed variable from a local raw OID::

            async def write_variables(self):
                raw_entry = self._store.get("_rawPower")
                if raw_entry and raw_entry.data_value.Value is not None:
                    watts = raw_entry.data_value.Value.Value * 1000
                    entry = self._store.get("PowerMilliWatts")
                    if entry:
                        entry.data_value = ua.DataValue(
                            ua.Variant(float(watts), ua.VariantType.Double)
                        )
                await super().write_variables()
        """
        for opcua_name, entry in self._store.items():
            if entry.is_local:
                continue
            node = self._node_map.get(opcua_name)
            if node is None:
                continue
            log.debug("  Writing %s.%s = %s", self.opcua_path, opcua_name, entry.data_value)
            try:
                await node.write_value(entry.data_value)
            except Exception as exc:
                log.error("OPC UA write failed for %s.%s: %s",
                          self.opcua_path, opcua_name, exc)

    async def on_address_space_ready(self) -> None:
        """
        Called once after all OPC UA nodes have been created for this poller.

        self._device_node and self._node_map are fully populated at this point.
        The default implementation initialises the internal data store.
        Override to perform any one-time setup that requires access to the
        node tree — but always call ``await super().on_address_space_ready()``
        first so the data store is ready before your code runs.
        """
        self._init_store()

    def _init_store(self) -> None:
        """
        Populate ``self._store`` with a StoreEntry for every variable managed
        by this poller: server variables, published OID variables, local OID
        variables, and constants.

        Called once from on_address_space_ready().  Subclasses that add extra
        OPC UA nodes in create_variables() should add corresponding StoreEntry
        objects here (override _init_store or add entries after calling super).
        """
        _waiting = ua.StatusCode(ua.StatusCodes.BadWaitingForInitialData)

        # ── server variables ──────────────────────────────────────────────────
        for name, opcua_type, value in [
            ("device_host",             "String",  self.host),
            ("device_port",             "UInt16",  self.port),
            ("device_polling_interval", "Double",  self.poll_interval),
        ]:
            variant_type, cast_fn = _UA_TYPE_MAP[opcua_type]
            self._store[name] = StoreEntry(
                data_value=ua.DataValue(ua.Variant(cast_fn(value), variant_type)),
                timestamp=time.monotonic(),
                lifetime=0.0,
                opcua_type=opcua_type,
                is_local=False,
            )

        # device_polling_timestamp and device_polling_age start as BadWaitingForInitialData;
        # both are updated only on a successful SNMP poll.
        self._store["device_polling_timestamp"] = StoreEntry(
            data_value=_make_status_dv("DateTime", _waiting),
            timestamp=None,
            lifetime=0.0,
            opcua_type="DateTime",
            is_local=False,
        )
        self._store["device_polling_age"] = StoreEntry(
            data_value=_make_status_dv("Double", _waiting),
            timestamp=None,
            lifetime=0.0,
            opcua_type="Double",
            is_local=False,
        )
        # device_polling_success_count: server-side counter, always Good, never expires.
        self._store["device_polling_success_count"] = StoreEntry(
            data_value=ua.DataValue(ua.Variant(0, ua.VariantType.UInt32)),
            timestamp=time.monotonic(),
            lifetime=0.0,
            opcua_type="UInt32",
            is_local=False,
        )
        # device_server_online: bridge-level reachability flag, always Good, never expires.
        # Set only by _poll_once(); subclasses must not modify this entry.
        self._store["device_server_online"] = StoreEntry(
            data_value=ua.DataValue(ua.Variant(False, ua.VariantType.Boolean)),
            timestamp=time.monotonic(),
            lifetime=0.0,
            opcua_type="Boolean",
            is_local=False,
        )
        self._store["device_state"] = StoreEntry(
            data_value=ua.DataValue(ua.Variant(0, ua.VariantType.Int32)),
            timestamp=time.monotonic(),
            lifetime=0.0,
            opcua_type="Byte",
            is_local=False,
        )

        # ── OID variables (local and published) ───────────────────────────────
        for oid_cfg in self.oids:
            # Resolve effective lifetime: if the OID specifies -1, fall
            # back to the device-level default.
            if oid_cfg.lifetime < 0:
                effective_lifetime = self.default_lifetime
            else:
                effective_lifetime = oid_cfg.lifetime

            self._store[oid_cfg.opcua_name] = StoreEntry(
                data_value=_make_status_dv(oid_cfg.opcua_type, _waiting),
                timestamp=None,
                lifetime=effective_lifetime,
                opcua_type=oid_cfg.opcua_type,
                is_local=oid_cfg.is_local,
                next_cycle=0,   # due on cycle 1
            )

        # ── constants ─────────────────────────────────────────────────────────
        for const_cfg in self.constants:
            if const_cfg.value is None:
                dv = _make_status_dv(const_cfg.opcua_type, _waiting)
            else:
                variant = _cast_to_ua(const_cfg.value, const_cfg.opcua_type)
                if isinstance(variant, ua.DataValue):
                    dv = variant   # cast failed — already a bad-status DataValue
                else:
                    dv = ua.DataValue(variant)
            # Resolve effective lifetime using the same sentinel convention as OIDs:
            #   -1 + real value  → 0.0  (true constant, never expires)
            #   -1 + None value  → device default_lifetime  (derived variable)
            #   explicit >= 0    → use as-is
            if const_cfg.lifetime < 0:
                if const_cfg.value is not None:
                    effective_lifetime = 0.0
                else:
                    effective_lifetime = self.default_lifetime
            else:
                effective_lifetime = const_cfg.lifetime
            self._store[const_cfg.opcua_name] = StoreEntry(
                data_value=dv,
                timestamp=time.monotonic() if const_cfg.value is not None else None,
                lifetime=effective_lifetime,
                opcua_type=const_cfg.opcua_type,
                is_local=False,
            )

    # ── SNMP helpers ──────────────────────────────────────────────────────────

    async def _get_one_chunk(
        self,
        oid_list: List[OIDConfig],
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch exactly the OIDs in *oid_list* in a single SNMP GET request.

        Returns a dict mapping oid_str -> raw_value for every OID that responded
        successfully, or None if the device was unreachable (error_indication set
        before any var-bind was returned).

        Individual OIDs that the agent reports an error for are skipped and logged
        as warnings; the remaining results are still returned.

        This is the low-level transport primitive.  Callers should normally use
        _get_all_oids(), which handles batching according to oids_per_get.
        """
        object_types = [
            ObjectType(ObjectIdentity(oid_cfg.oid)) for oid_cfg in oid_list
        ]
        log.debug("SNMP GET %s:%d — requesting %d OID(s): %s",
                  self.host, self.port, len(oid_list),
                  ", ".join(o.oid for o in oid_list))
        # Re-use the engine and transport target created once; recreating them
        # on every call is heavyweight and leaks resources.
        if self._transport_target is None:
            self._transport_target = await UdpTransportTarget.create(
                (self.host, self.port), timeout=self.snmp_timeout, retries=self.snmp_retries
            )
        error_indication, error_status, error_index, var_binds = await get_cmd(
            self._snmp_engine,
            CommunityData(self.community, mpModel=1),   # mpModel=1 → SNMPv2c
            self._transport_target,
            ContextData(),
            *object_types,
            lookupMib=False,
        )

        # Transport / auth failure — device completely unreachable
        if error_indication:
            log.debug("SNMP GET %s: %s", self.host, error_indication)
            return None

        # Agent-level error — one or more var-binds bad, rest may be ok
        if error_status:
            bad_idx = int(error_index) - 1 if error_index else None
            bad_oid = (
                str(var_binds[bad_idx][0]) if bad_idx is not None else "unknown"
            )
            log.warning(
                "SNMP GET %s: agent error '%s' at OID %s – skipping that OID",
                self.host, error_status.prettyPrint(), bad_oid,
            )
            # SNMPv2c GET responses carry at most one error_index (RFC 3416
            # §4.2.1), so removing the single offending var-bind is sufficient.
            # The positions of the remaining var-binds still correspond 1-to-1
            # with the original request order after the pop.
            # Remove the offending var-bind so we can still use the rest
            if bad_idx is not None:
                var_binds = list(var_binds)
                var_binds.pop(bad_idx)

        results: Dict[str, Any] = {}
        for oid_obj, value in var_binds:
            # pysnmp returns NoSuchObject / NoSuchInstance / EndOfMibView as
            # value sentinels rather than raising an error.  Exclude them so
            # that _resolve_oid_key correctly returns None for these OIDs and
            # they get marked BadNotSupported on the OPC UA side.
            if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                log.debug("SNMP GET %s: OID %s returned %s – treating as unsupported",
                          self.host, oid_obj, type(value).__name__)
                continue
            results[str(oid_obj)] = value

        if log.isEnabledFor(logging.DEBUG):
            log.debug("SNMP GET %s:%d — %d var-bind(s) received:",
                      self.host, self.port, len(results))
            for oid_key, raw_val in results.items():
                log.debug("  %s = %s (%s)",
                          oid_key, raw_val.prettyPrint(), type(raw_val).__name__)

        return results

    async def _get_all_oids(
        self,
        oid_list: List[OIDConfig],
        effective_limit: int,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch the given list of OIDs, splitting them into sequential batches
        when *effective_limit* is non-zero.

        Parameters
        ----------
        oid_list : List[OIDConfig]
            The OIDs to request.  Callers build this list from the full
            ``self.oids`` (force_full) or from the subset that is due this
            cycle (scheduled poll).
        effective_limit : int
            Maximum number of OIDs per individual GET request.
            0  → send all OIDs in a single request (unlimited).
            >0 → split *oid_list* into chunks of at most this size; each chunk
                 is sent as a separate sequential GET and the results are merged.

        Returns a dict mapping oid_str -> raw_value for every OID that
        responded successfully across all batches, or None if the device was
        unreachable (i.e. _get_one_chunk returned None for any batch — the
        remaining batches are not sent).
        """
        if effective_limit == 0 or len(oid_list) <= effective_limit:
            # Common fast path: everything fits in one request.
            return await self._get_one_chunk(oid_list)

        # Batched path: split into chunks and send sequentially.
        n_chunks = (len(oid_list) + effective_limit - 1) // effective_limit
        log.debug(
            "SNMP GET %s: splitting %d OID(s) into %d chunk(s) of ≤%d (oids_per_get=%d)",
            self.host, len(oid_list), n_chunks, effective_limit, effective_limit,
        )
        merged: Dict[str, Any] = {}
        for chunk_idx in range(n_chunks):
            start = chunk_idx * effective_limit
            chunk = oid_list[start : start + effective_limit]
            log.debug("SNMP GET %s: sending chunk %d/%d (%d OID(s))",
                      self.host, chunk_idx + 1, n_chunks, len(chunk))
            partial = await self._get_one_chunk(chunk)
            if partial is None:
                # Device stopped responding mid-batch.  Discard any results from
                # earlier chunks and return None so _poll_once treats the whole
                # cycle as a failure — consistent with the single-GET behaviour
                # where a transport failure always discards the entire cycle.
                # A warning is raised only when earlier chunks had succeeded, as
                # that pattern (responded then stopped) is worth flagging.
                if chunk_idx > 0:
                    log.warning(
                        "SNMP GET %s: chunk %d/%d failed after %d successful chunk(s)"
                        " — discarding partial results and treating cycle as offline",
                        self.host, chunk_idx + 1, n_chunks, chunk_idx,
                    )
                else:
                    log.debug("SNMP GET %s: chunk %d/%d failed — aborting batch",
                              self.host, chunk_idx + 1, n_chunks)
                return None
            merged.update(partial)
        log.debug("SNMP GET %s: batch complete — %d var-bind(s) total",
                  self.host, len(merged))
        return merged

    # ── polling loop ──────────────────────────────────────────────────────────

    async def run(self) -> None:
        """
        Phase-locked polling loop.  Must be called after the OPC UA nodes have
        been created (i.e. after OPCUAServer.build_address_space()).

        Slot skipping
        -------------
        Each cycle occupies one slot of duration ``poll_interval``.  If a poll
        overruns into future slots, every overrun slot is logged and skipped so
        the loop re-locks to the correct phase rather than firing repeatedly to
        catch up.

        Concurrent-poll guard
        ---------------------
        If a poll is still in progress when the next slot fires (possible when
        ``snmp_timeout * (snmp_retries + 1) > poll_interval``), the new slot is
        skipped entirely — no store updates, no OPC UA writes.  The in-flight
        poll is left to complete and will handle all staleness updates itself.
        """
        log.info("Poller started: %s  path=%s  interval=%.1fs  timeout=%.1fs  retries=%d",
                 self.host, self.opcua_path, self.poll_interval,
                 self.snmp_timeout, self.snmp_retries)
        log.info("Waiting for device to respond: %s", self.host)

        loop = asyncio.get_running_loop()
        origin = loop.time()
        cycle = 0

        while True:
            # ── Fire the poll, or skip if the previous one is still in flight ──
            log.debug("Poller %s: starting slot %d", self.host, cycle + 1)
            if self._poll_lock.locked():
                log.warning("Poller %s: slot %d skipped — previous poll still in flight",
                            self.host, cycle + 1)
                poll_ran = False
                was_offline = self._was_offline
            else:
                was_offline = self._was_offline
                # Update _polling_cycle *before* calling _poll_once so that
                # next_cycle comparisons inside the poll see the correct value.
                # _polling_cycle is only advanced here — never on a skipped slot.
                self._polling_cycle = cycle + 1
                async with self._poll_lock:
                    await self._poll_once()
                poll_ran = True

            # ── Advance cycle until the next deadline is in the future ──────────
            cycle += 1
            now = loop.time()
            while origin + cycle * self.poll_interval <= now:
                if not poll_ran or was_offline or self._was_offline:
                    log.debug("Poller %s: skipping overrun slot %d (device offline)",
                              self.host, cycle + 1)
                else:
                    log.warning("Poller %s: skipping overrun slot %d",
                                self.host, cycle + 1)
                cycle += 1

            # ── Sleep until the start of the next slot ────────────────────────
            sleep_for = origin + cycle * self.poll_interval - now
            log.debug("Poller %s: sleeping %.3fs until slot %d",
                      self.host, sleep_for, cycle + 1)
            await asyncio.sleep(sleep_for)

    def _resolve_oid_key(self, oid_cfg: OIDConfig, results: Dict[str, Any]) -> Optional[str]:
        """
        Find the exact key string pysnmp used for this OID in a response dict.

        pysnmp may reformat OID strings (e.g. resolving symbolic names or
        normalising instance suffixes), so we try several strategies:
          1. Exact match on the configured dotted-decimal string
          2. Configured OID with ".0" appended (scalar instance suffix)
          3. Any key that ends with the configured OID, or vice-versa
        Returns the matching key, or None if the OID was not in the response.
        """
        if oid_cfg.oid in results:
            log.debug("  OID key match (exact): %s", oid_cfg.oid)
            return oid_cfg.oid
        suffixed = oid_cfg.oid.rstrip(".0") + ".0"
        if suffixed in results:
            log.debug("  OID key match (suffixed .0): %s → %s", oid_cfg.oid, suffixed)
            return suffixed
        for key in results:
            if key.endswith("." + oid_cfg.oid) or oid_cfg.oid.endswith("." + key):
                log.debug("  OID key match (suffix boundary): %s → %s", oid_cfg.oid, key)
                return key
        log.debug("  OID key not found in response: %s  (available keys: %s)",
                  oid_cfg.oid, list(results))
        return None

    def _apply_staleness(self, opcua_name: str, entry: "StoreEntry", now: float) -> None:
        """
        Apply staleness logic to a single store entry that was not refreshed
        this poll cycle.  Mutates ``entry.data_value`` in place.

        This method is intentionally scoped to one entry so that callers
        control iteration and subclasses can apply the same logic to any
        store entry they manage (not just OID variables).

        Rules
        -----
        • Never successfully read (timestamp is None):
              Left unchanged — keeps BadWaitingForInitialData.
        • BadNotSupported: permanent — never overwritten.
        • Has a prior value, within lifetime (or lifetime == 0):
              status → UncertainLastUsableValue, value preserved.
        • Has a prior value, lifetime expired (lifetime > 0, elapsed > lifetime):
              status → BadNoCommunication, value → typed zero.
        """
        _uncertain   = ua.StatusCode(ua.StatusCodes.UncertainLastUsableValue)
        _bad_no_comm = ua.StatusCode(ua.StatusCodes.BadNoCommunication)
        _bad_no_supp = ua.StatusCode(ua.StatusCodes.BadNotSupported)

        if entry.data_value.StatusCode == _bad_no_supp:
            return   # permanent — never overwrite

        if entry.timestamp is None:
            return   # never successfully read — leave as BadWaitingForInitialData

        elapsed = now - entry.timestamp

        if entry.lifetime > 0 and elapsed > entry.lifetime:
            if entry.data_value.StatusCode != _bad_no_comm:
                log.debug(
                    "Lifetime expired for %s.%s (last read %.1fs ago, limit %.1fs)"
                    " — marking BadNoCommunication",
                    self.opcua_path, opcua_name, elapsed, entry.lifetime,
                )
            entry.data_value = ua.DataValue(
                Value=ua.Variant(
                    _UA_TYPE_ZEROS.get(entry.opcua_type, ""),
                    _UA_TYPE_MAP[entry.opcua_type][0],
                ),
                StatusCode_=_bad_no_comm,
            )
        else:
            if entry.data_value.StatusCode != _uncertain:
                log.debug("Marking %s.%s UncertainLastUsableValue",
                          self.opcua_path, opcua_name)
            entry.data_value = ua.DataValue(
                Value=entry.data_value.Value,
                StatusCode_=_uncertain,
            )

    async def _poll_once(self, force_full: bool = False) -> bool:
        """
        Fetch OIDs from the device, update the internal data store, then call
        write_variables() to push the entire store to OPC UA.

        Parameters
        ----------
        force_full : bool
            When True, request *all* configured OIDs regardless of their
            ``next_cycle`` schedule.  ``next_cycle`` is never advanced and
            ``_polling_cycle`` is never changed, so the PLL schedule is
            undisturbed.  Intended for use by ``force_reload()`` only.
            When False (default), only OIDs whose ``next_cycle <=
            _polling_cycle`` are requested; ``next_cycle`` is advanced for
            each OID that responds successfully.

        Returns
        -------
        bool
            True if the device responded (results were received); False if the
            device was unreachable this cycle.

        Responsibilities
        ----------------
        • Build the per-cycle OID request list from due variables (or all OIDs
          when force_full=True).
        • Update device_polling_timestamp and device_polling_age only on a
          successful poll, using the initiation time so they reflect when the
          request was sent rather than when the response arrived.
        • On a successful response: update store entries for every OID that
          replied; resolve and cache OID keys on the first post-offline cycle;
          advance next_cycle for each responding OID (scheduled polls only).
        • On a failed response (device offline): reset next_cycle to
          _polling_cycle for all OIDs (so they all fire on the next successful
          cycle), then apply staleness to all OIDs immediately.
        • Staleness (_apply_staleness) is called only for OIDs that were
          requested this cycle and did not respond (online path), or for all
          OIDs (offline path).  OIDs not due this cycle are never touched.
        • Update device_state (1 = online, 0 = offline) in the store.
        • Call write_variables() once at the end of every cycle.

        OID key resolution is cached after the first successful poll and
        cleared when the device goes offline so keys are re-resolved on
        recovery.

        Locking
        -------
        Does NOT acquire _poll_lock.  Callers (run() and force_reload()) are
        responsible for holding the lock around this call.
        """
        now = time.monotonic()
        wall_now = datetime.datetime.now(datetime.timezone.utc)

        # ── Clear per-cycle freshness flag on all OID entries ─────────────────
        # Done unconditionally before the GET so write_variables() always sees a
        # consistent state regardless of whether this is a scheduled poll, a
        # force_full, or a cycle where the device turns out to be offline.
        for oid_cfg in self.oids:
            entry = self._store.get(oid_cfg.opcua_name)
            if entry is not None:
                entry.updated_this_cycle = False

        # ── Build the set of OIDs to request this cycle ───────────────────────
        if force_full:
            due_oids = self.oids
        else:
            due_oids = [
                oid_cfg for oid_cfg in self.oids
                if self._store[oid_cfg.opcua_name].next_cycle <= self._polling_cycle
            ]

        log.debug("Poller %s: cycle %d — requesting %d/%d OID(s)%s",
                  self.host, self._polling_cycle, len(due_oids), len(self.oids),
                  " (force_full)" if force_full else "")

        # ── Empty cycle: no OIDs due this cycle ───────────────────────────────
        # Skip the GET entirely rather than sending a zero-OID request (whose
        # behaviour is agent-dependent and likely wrong).  device_polling_age keeps
        # ticking so OPC UA clients see time advancing; everything else is left
        # untouched — we have no new information about the device this cycle.
        if not due_oids:
            now = time.monotonic()
            last_ts = self._store["device_polling_timestamp"].timestamp
            if last_ts is not None:
                self._store["device_polling_age"].data_value = ua.DataValue(
                    ua.Variant(now - last_ts, ua.VariantType.Double)
                )
            await self.write_variables()
            return True

        results = await self._get_all_oids(due_oids, self.oids_per_get)

        if results is None:
            # ── Device offline ────────────────────────────────────────────────
            if not self._was_offline:
                log.warning("Device went offline: %s", self.host)
                self._oid_key_cache.clear()
                self._was_offline = True

            log.debug("Device offline: %s", self.host)

            # Reset next_cycle for all OIDs to _polling_cycle so they all fire
            # together on the next successful cycle.  PLL phasing for slow-polled
            # OIDs resets at this point — this is intentional.
            for oid_cfg in self.oids:
                entry = self._store.get(oid_cfg.opcua_name)
                if entry is not None:
                    entry.next_cycle = self._polling_cycle

            # Apply staleness to all OIDs immediately — we don't know the state
            # of any variable when the device is unreachable.
            for oid_cfg in self.oids:
                entry = self._store.get(oid_cfg.opcua_name)
                if entry is not None:
                    self._apply_staleness(oid_cfg.opcua_name, entry, now)

            self._store["device_state"].data_value = ua.DataValue(
                ua.Variant(0, ua.VariantType.Int32)
            )
            self._store["device_server_online"].data_value = ua.DataValue(
                ua.Variant(False, ua.VariantType.Boolean)
            )

            # device_polling_age keeps ticking even while offline using the initiation
            # time of this cycle vs the timestamp of the last successful poll.
            # device_polling_timestamp is NOT updated — it stays at the last success.
            last_ts = self._store["device_polling_timestamp"].timestamp
            if last_ts is not None:
                self._store["device_polling_age"].data_value = ua.DataValue(
                    ua.Variant(now - last_ts, ua.VariantType.Double)
                )

            await self.write_variables()
            return False

        # ── Device is responding ──────────────────────────────────────────────
        if self._was_offline:
            log.warning("Device came online: %s — resolving OID keys", self.host)
            self._oid_key_cache.clear()
            for oid_cfg in self.oids:
                key = self._resolve_oid_key(oid_cfg, results)
                if key is not None:
                    self._oid_key_cache[oid_cfg.opcua_name] = key
                    log.debug("  OID resolved: %s -> %s (%s)",
                              oid_cfg.oid, key, oid_cfg.opcua_name)
                else:
                    log.warning(
                        "OID not supported by device – marking BadNotSupported: "
                        "%s on %s", oid_cfg.oid, self.host,
                    )
                    entry = self._store[oid_cfg.opcua_name]
                    entry.data_value = ua.DataValue(
                        Value=ua.Variant(
                            _UA_TYPE_ZEROS.get(entry.opcua_type, ""),
                            _UA_TYPE_MAP[entry.opcua_type][0],
                        ),
                        StatusCode_=ua.StatusCode(ua.StatusCodes.BadNotSupported),
                    )
            self._was_offline = False

        # ── Update store entries for OIDs present in the response ─────────────
        responded: set[str] = set()
        for oid_cfg in due_oids:
            key = self._oid_key_cache.get(oid_cfg.opcua_name)
            if key is None:
                continue    # marked BadNotSupported on coming online

            raw = results.get(key)
            if raw is None:
                log.warning("Cached OID key no longer in response: %s on %s",
                            key, self.host)
                continue

            py_val = _snmp_value_to_python(raw)
            variant = _cast_to_ua(py_val, oid_cfg.opcua_type)
            log.debug("  Read %s.%s = %r (raw type: %s)",
                      self.opcua_path, oid_cfg.opcua_name,
                      py_val, type(raw).__name__)

            entry = self._store[oid_cfg.opcua_name]
            if isinstance(variant, ua.Variant):
                entry.data_value = ua.DataValue(variant)
            else:
                entry.data_value = variant   # already a DataValue (cast failed)
            entry.timestamp = now
            entry.updated_this_cycle = True
            responded.add(oid_cfg.opcua_name)

            # Advance next_cycle for scheduled polls only — force_full never
            # advances next_cycle so the PLL schedule is undisturbed.
            if not force_full:
                entry.next_cycle = self._polling_cycle + oid_cfg.poll_every

        # ── Apply staleness to due OIDs that did not respond this cycle ───────
        # Only due_oids are candidates — non-due OIDs are left entirely untouched.
        for oid_cfg in due_oids:
            if oid_cfg.opcua_name not in responded                     and self._oid_key_cache.get(oid_cfg.opcua_name) is not None:
                entry = self._store.get(oid_cfg.opcua_name)
                if entry is not None:
                    self._apply_staleness(oid_cfg.opcua_name, entry, now)

        # ── Update device_polling_timestamp and device_polling_age on success ─────
        # Stamped with the initiation time of this cycle (now/wall_now), so
        # device_polling_age resets to ~0.0 on success and device_polling_timestamp
        # reflects when the request was sent rather than when the response arrived.
        self._store["device_polling_timestamp"].data_value = ua.DataValue(
            ua.Variant(wall_now, ua.VariantType.DateTime)
        )
        self._store["device_polling_timestamp"].timestamp = now
        self._store["device_polling_age"].data_value = ua.DataValue(
            ua.Variant(0.0, ua.VariantType.Double)
        )
        self._store["device_polling_age"].timestamp = now

        self._store["device_state"].data_value = ua.DataValue(
            ua.Variant(1, ua.VariantType.Int32)
        )
        self._store["device_server_online"].data_value = ua.DataValue(
            ua.Variant(True, ua.VariantType.Boolean)
        )
        # Increment success counter, wrapping at UInt32 max.
        prev = self._store["device_polling_success_count"].data_value.Value.Value
        self._store["device_polling_success_count"].data_value = ua.DataValue(
            ua.Variant((prev + 1) & 0xFFFFFFFF, ua.VariantType.UInt32)
        )
        await self.write_variables()
        return True

    async def force_reload(self) -> bool:
        """
        Issue an immediate full SNMP GET for all configured OIDs and update the
        OPC UA address space, regardless of each OID's scheduled ``next_cycle``.

        Intended for subclass OPC UA method handlers that change hardware state
        via a side channel (e.g. a serial or Ethernet command) and need fresh
        values immediately after the change is applied.

        Behaviour
        ---------
        • Acquires ``_poll_lock``, waiting for any in-flight scheduled poll to
          finish first.  The poll is never silently dropped — if a scheduled poll
          was in progress just before the hardware command was sent, this method
          waits for it to complete and then fires a fresh GET so the post-command
          state is captured.
        • Requests all OIDs (``force_full=True``).
        • Never advances ``next_cycle`` for any variable.
        • Never modifies ``_polling_cycle``.
        • If the scheduled PLL slot fires while this reload is holding the lock,
          that slot is skipped (the normal skip-if-busy path in ``run()``).

        Returns
        -------
        bool
            True if the device responded; False if it was unreachable.

        Example usage in a subclass OPC UA method::

            @ua_method(...)
            async def apply_setting(self, new_value):
                await self._send_command(new_value)   # side-channel write
                ok = await self.force_reload()
                if not ok:
                    raise ua.UaError("Device did not respond after applying setting")
        """
        log.debug("force_reload: %s — waiting for lock", self.host)
        async with self._poll_lock:
            log.debug("force_reload: %s — lock acquired, issuing full GET", self.host)
            return await self._poll_once(force_full=True)

# ─────────────────────────────────────────────────────────────────────────────
# Simple username/password validator for asyncua
# ─────────────────────────────────────────────────────────────────────────────

class _SingleUserManager:
    """
    Accepts exactly one username/password pair; rejects anonymous access.

    Compatible with asyncua 1.0.x and 1.1.x -- the return type changed
    between releases, so we handle both.
    """

    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password

    def get_user(self, iserver, username=None, password=None, certificate=None):
        # NOTE: The password is stored and compared as plain text.
        # For a hardened deployment consider storing a hash instead
        # (e.g. hashlib.pbkdf2_hmac) and comparing against that, particularly
        # because the password arrives via the CLI and may appear in process
        # listings or shell history.
        if username == self._username and password == self._password:
            log.debug("OPC UA client authenticated: user=%r", username)
            # Return UserRole.User when available, otherwise any truthy value
            if UserRole is not None:
                return UserRole.User
            return True      # asyncua 1.1.x: truthy value grants access
        # Failed auth is always worth seeing at normal log levels — it may
        # indicate a misconfigured client or an unauthorised access attempt.
        peer = getattr(iserver, "peer_name", None) or getattr(iserver, "peer", None)
        if peer:
            log.warning("OPC UA authentication failed: user=%r from %s", username, peer)
        else:
            log.warning("OPC UA authentication failed: user=%r", username)
        return None          # None/falsy -> deny


# ─────────────────────────────────────────────────────────────────────────────
# OPCUAServer
# ─────────────────────────────────────────────────────────────────────────────

class OPCUAServer:
    """
    Hosts an OPC UA server and manages any number of SNMPPoller instances.

    Example
    -------
    server = OPCUAServer(
        endpoint="opc.tcp://0.0.0.0:4840/nectarcam/",
        namespace="http://cta-observatory.org/nectarcam/snmpdevices/",
        root_path="SNMPDevices",
        user="admin",
        password="secret",
    )
    server.register(SNMPPoller.from_dict(cfg))
    await server.run()
    """

    def __init__(
        self,
        endpoint: str,
        namespace: str,
        root_path: str = "SNMPDevices",
        user: Optional[str] = None,
        password: Optional[str] = None,
        default_oids_per_get: int = 0,
    ):
        self.endpoint = endpoint
        self.namespace = namespace
        # Split root_path on "." and discard any empty segments so that
        # root_path="" (no container) and root_path="A..B" (typo) both
        # behave sensibly.
        self.root_parts: List[str] = [p for p in root_path.split(".") if p]
        self.user = user
        self.password = password
        self._pollers: List[SNMPPoller] = []
        # Server-wide default: maximum OIDs per SNMP GET (0 = unlimited).
        # Used for pollers whose oids_per_get is -1 (inherit server default).
        if default_oids_per_get < 0:
            raise ValueError(
                f"OPCUAServer default_oids_per_get must be >= 0, "
                f"got {default_oids_per_get!r}"
            )
        self.default_oids_per_get: int = default_oids_per_get

    def register(self, poller: SNMPPoller) -> None:
        """Register an SNMPPoller with this server."""
        clash = next(
            (p for p in self._pollers if p.opcua_path == poller.opcua_path), None
        )
        if clash is not None:
            raise ValueError(
                f"Duplicate opcua_path {poller.opcua_path!r}: "
                f"already registered for {clash.host}, cannot add {poller.host}"
            )
        # Resolve the per-poller oids_per_get sentinel (-1 = inherit server
        # default) by overwriting the field with the concrete value.  From this
        # point on oids_per_get is always >= 0 and to_dict() serialises the
        # resolved value, making dumped configs CLI-independent.
        if poller.oids_per_get < 0:
            poller.oids_per_get = self.default_oids_per_get
        self._pollers.append(poller)
        limit_desc = (
            "unlimited" if poller.oids_per_get == 0
            else f"{poller.oids_per_get} OID(s)/GET"
        )
        log.info("Registered poller: %s → %s  (oids_per_get: %s)",
                 poller.host, poller.opcua_path, limit_desc)

    # ── address space construction ────────────────────────────────────────────

    async def _ensure_path(
        self,
        server: Server,
        ns_idx: int,
        path_parts: List[str],
    ) -> tuple[Any, str]:
        """
        Walk (and create where missing) a chain of Object nodes under Objects/.

        Returns ``(node, path_string)`` where *path_string* is the dot-joined
        absolute path of the deepest node (e.g. ``"SNMPDevices.Switch01"``).
        Object nodes are created with string NodeIds derived from that path so
        that clients see stable, human-readable identifiers instead of
        auto-generated numeric ones (``ns=2;s="SNMPDevices.Switch01"``).
        """
        parent = server.nodes.objects
        accumulated: List[str] = []
        for part in path_parts:
            accumulated.append(part)
            node_path_str = ".".join(accumulated)
            node_id = ua.NodeId(node_path_str, ns_idx, ua.NodeIdType.String)
            found = None
            try:
                for child in await parent.get_children():
                    if await child.read_browse_name() == ua.QualifiedName(part, ns_idx):
                        found = child
                        break
            except Exception as exc:
                log.warning("Error walking OPC UA address space at %r: %s — "
                            "will attempt to create the node anyway", part, exc)
            if found is None:
                found = await parent.add_object(node_id, ua.QualifiedName(part, ns_idx))
                log.debug("Created OPC UA object node: %s  (node_id=%s)", part, node_id)
            else:
                log.debug("Reused existing OPC UA object node: %s", part)
            parent = found
        return parent, ".".join(path_parts)

    async def _build_address_space(self, server: Server, ns_idx: int) -> None:
        """Create all OPC UA nodes for every registered poller."""
        root_desc = ".".join(self.root_parts) if self.root_parts else "(Objects root)"
        log.debug("Building address space under: %s", root_desc)
        for poller in self._pollers:
            # Combine the root path segments with the poller's own path segments.
            # Either or both may be empty: an empty root means devices land
            # directly under Objects/; an empty opcua_path is unusual but valid
            # and would place the device node inside the root container itself.
            poller_parts = [p for p in poller.opcua_path.split(".") if p]
            all_parts = self.root_parts + poller_parts
            device_node, node_path_str = await self._ensure_path(
                server, ns_idx, all_parts
            )
            poller._device_node = device_node
            # Store the absolute dot-joined path so create_variables can build
            # string NodeIds of the form  ns=2;s="SNMPDevices.Switch01.some_var"
            poller._opcua_node_path = node_path_str

            # ── device description on the object node ─────────────────────────
            if poller.description:
                await device_node.write_attribute(
                    ua.AttributeIds.Description,
                    ua.DataValue(
                        ua.Variant(
                            ua.LocalizedText(poller.description),
                            ua.VariantType.LocalizedText,
                        )
                    ),
                )

            # ── build specs, create nodes, notify poller ──────────────────────
            specs = poller.build_variable_specs()
            await poller.create_variables(device_node, ns_idx, specs)
            await poller.on_address_space_ready()

            log.info("Address space built for %s (%d variable(s))",
                     poller.opcua_path, len(poller._node_map))

    # ── heartbeat ─────────────────────────────────────────────────────────────

    _HEARTBEAT_INTERVAL: float = 300.0   # seconds between summary log lines

    async def _heartbeat(self) -> None:
        """
        Log a one-line summary for every registered poller every
        _HEARTBEAT_INTERVAL seconds (default: 5 minutes).

        Each line reports:
          • opcua_path  — the poller's OPC UA path (device identity)
          • host        — SNMP device IP
          • online      — current device_server_online value
          • polls       — cumulative successful SNMP poll count
          • age         — seconds since last successful poll (or "never")
        """
        await asyncio.sleep(self._HEARTBEAT_INTERVAL)
        while True:
            for poller in self._pollers:
                store = poller._store
                online_entry = store.get("device_server_online")
                count_entry  = store.get("device_polling_success_count")
                age_entry    = store.get("device_polling_age")

                online = (
                    online_entry.data_value.Value.Value
                    if online_entry and online_entry.data_value.Value else "?"
                )
                count = (
                    int(count_entry.data_value.Value.Value)
                    if count_entry and count_entry.data_value.Value else "?"
                )
                age_val = (
                    age_entry.data_value.Value.Value
                    if age_entry and age_entry.data_value.Value else None
                )
                age_str = f"{age_val:.1f}s ago" if isinstance(age_val, float) else "never"

                log.info(
                    "Heartbeat: %s (%s)  online=%s  polls=%s  last_poll=%s",
                    poller.opcua_path, poller.host, online, count, age_str,
                )
            await asyncio.sleep(self._HEARTBEAT_INTERVAL)

    # ── main entry point ──────────────────────────────────────────────────────

    async def run(self) -> None:
        """Start the OPC UA server and all pollers; run until cancelled."""
        server = Server()
        await server.init()
        server.set_endpoint(self.endpoint)

        # ── authentication ────────────────────────────────────────────────────
        if self.user and self.password:
            # set_security_IDs is async in some versions, sync in others
            try:
                await server.set_security_IDs(["Username"])
            except TypeError:
                server.set_security_IDs(["Username"])
            # iserver.user_manager path changed in asyncua 1.1.x
            user_mgr = _SingleUserManager(self.user, self.password)
            if hasattr(server, "user_manager"):
                server.user_manager = user_mgr           # 1.1.x
            else:
                server.iserver.user_manager = user_mgr  # 1.0.x
            log.info("OPC UA authentication enabled for user '%s'", self.user)
        else:
            log.warning("OPC UA server running WITHOUT authentication")

        # ── namespace ─────────────────────────────────────────────────────────
        ns_idx = await server.register_namespace(self.namespace)
        log.info("OPC UA namespace index %d: %s", ns_idx, self.namespace)

        await self._build_address_space(server, ns_idx)

        async with server:
            log.info("OPC UA server listening on %s", self.endpoint)

            def _task_done(task: asyncio.Task) -> None:
                # Called when a poller task exits for any reason.
                # CancelledError is expected on shutdown; anything else is a bug.
                if task.cancelled():
                    return
                exc = task.exception()
                if exc is not None:
                    log.error("Poller task %s crashed unexpectedly: %s: %s",
                              task.get_name(), type(exc).__name__, exc,
                              exc_info=exc)

            tasks = [
                asyncio.create_task(poller.run(), name=f"poller-{poller.host}")
                for poller in self._pollers
            ]
            tasks.append(
                asyncio.create_task(self._heartbeat(), name="heartbeat")
            )
            for t in tasks:
                t.add_done_callback(_task_done)
            log.debug("Launched %d poller task(s): %s",
                      len(tasks), ", ".join(t.get_name() for t in tasks))
            try:
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                log.info("Server shutting down")
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SNMP → OPC UA bridge",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--opcua-endpoint",
        default="opc.tcp://0.0.0.0:4840/nectarcam/",
        help="OPC UA server endpoint URL",
    )
    p.add_argument(
        "--opcua-namespace",
        default="http://cta-observatory.org/nectarcam/snmpdevices/",
        help="OPC UA namespace URI",
    )
    p.add_argument(
        "--opcua-root",
        default="SNMPDevices",
        metavar="PATH",
        help=(
            "Dot-separated OPC UA path of the container node created above all "
            "device objects (e.g. 'SNMPDevices' or 'Camera0.SNMPDevices'). "
            "Pass an empty string to place devices directly under Objects/."
        ),
    )
    p.add_argument(
        "--opcua-user",
        default=None,
        metavar="USER:PASS",
        help="OPC UA username and password (disables anonymous access)",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    p.add_argument("--log-file", default=None, help="Optional log file path")
    p.add_argument(
        "--snmp-timeout",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="SNMP request timeout in seconds (per attempt). Can be overridden per device in JSON config.",
    )
    p.add_argument(
        "--snmp-retries",
        type=int,
        default=1,
        metavar="N",
        help="Number of SNMP retries after the first attempt. Can be overridden per device in JSON config.",
    )
    p.add_argument(
        "--device-config",
        metavar="FILE.json",
        action="append",
        dest="device_configs",
        default=[],
        help=(
            "Path to a JSON file describing one or more device configurations. "
            "The top-level element may be a single object (one device) or an "
            "array (multiple devices). May be specified more than once to load "
            "several files. When any --device-config is given, EXAMPLE_CONFIGS "
            "is ignored."
        ),
    )
    p.add_argument(
        "--default-poll-interval",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help=(
            "Default SNMP poll interval in seconds applied to every device that "
            "does not specify its own poll_interval in its JSON config."
        ),
    )
    p.add_argument(
        "--publish-local-oids",
        action="store_true",
        default=False,
        help=(
            "Strip leading underscores from local (underscore-prefixed) OID names "            "so they are published as OPC UA variables instead of being kept "            "server-side only.  Intended for testing and diagnostics."
        ),
    )
    p.add_argument(
        "--default-oids-per-get",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Server-wide default for the maximum number of OIDs sent in a single "
            "SNMP GET request. 0 (default) means unlimited — all due OIDs are "
            "fetched in one request. A positive value splits the OID list into "
            "sequential batches of at most N, which is required by devices that "
            "reject multi-OID GETs. Can be overridden per device with "
            "\"oids_per_get\" in the JSON config (use -1 there to inherit this "
            "server default)."
        ),
    )
    p.add_argument(
        "--dump-device-config",
        metavar="FILE.json",
        default=None,
        help=(
            "Write the fully-resolved device configuration to FILE.json just "
            "before starting the OPC UA event loop, then continue running normally. "
            "The output is reconstructed from the live SNMPPoller instances so "
            "every field is present with its resolved value: symbolic OIDs are "
            "in dotted-decimal, multi-IP entries are expanded, and all defaults "
            "are filled in.  Reloading the file reproduces identical behaviour "
            "regardless of CLI defaults."
        ),
    )
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Example / demo  (replace with your real config)
# ─────────────────────────────────────────────────────────────────────────────

EXAMPLE_CONFIGS = [
    {
        "host":          "127.0.0.1",
        "port":          1161,
        "community":     "public",
        "description":   "Local test SNMP agent (net-snmp on localhost)",
        "opcua_path":    "Localhost",
        "poll_interval": 10,
        "oids": [
            {
                "oid":         "1.3.6.1.2.1.1.1.0",
                "opcua_name":  "sysDescr",
                "opcua_type":  "String",
                "description": "System description",
            },
            {
                "oid":         "1.3.6.1.2.1.1.3.0",
                "opcua_name":  "sysUpTime",
                "opcua_type":  "UInt32",
                "description": "System uptime (hundredths of a second)",
            },
            {
                "oid":         "1.3.6.1.2.1.1.5.0",
                "opcua_name":  "sysName",
                "opcua_type":  "String",
                "description": "Administratively assigned system name",
            },
            {
                "oid":         "1.3.6.1.2.1.1.6.0",
                "opcua_name":  "sysLocation",
                "opcua_type":  "String",
                "description": "Physical location of the system",
            },
        ],
    },
]


def _expand_multi_ip(cfg: dict) -> List[dict]:
    """
    If cfg["host"] is a list, expand it into one config dict per address,
    substituting {instance} (zero-based index) into "opcua_path" and
    "description" via str.format_map().

    Within each entry in "constants", {instance} is also substituted into
    the "value" and "description" fields (when they are strings).

    If "opcua_path" does not contain {instance}, a warning is logged and
    "_{instance}" is appended automatically to avoid duplicate OPC UA paths.

    Returns a list with a single element when "ip" is a plain string.
    """
    ip = cfg["host"]
    if isinstance(ip, str):
        return [cfg]

    if not isinstance(ip, list) or not all(isinstance(a, str) for a in ip):
        sys.exit(
            f'Config "host" must be a string or a list of strings, '
            f'got: {ip!r}'
        )

    opcua_path_template = cfg.get("opcua_path", "")
    if "{instance" not in opcua_path_template:
        log.warning(
            'Multi-IP config "opcua_path" (%r) does not contain {instance} --'
            ' appending "_{instance}" automatically to avoid duplicate paths.',
            opcua_path_template,
        )
        opcua_path_template = opcua_path_template + "_{instance}"

    expanded: List[dict] = []
    for idx, address in enumerate(ip):
        fmt = {"instance": idx}
        instance_cfg = dict(cfg)
        instance_cfg["host"] = address
        try:
            instance_cfg["opcua_path"] = opcua_path_template.format_map(fmt)
        except (KeyError, ValueError) as exc:
            sys.exit(f'Bad opcua_path template {opcua_path_template!r}: {exc}')
        desc = cfg.get("description", "")
        if desc:
            try:
                instance_cfg["description"] = desc.format_map(fmt)
            except (KeyError, ValueError) as exc:
                sys.exit(f'Bad description template {desc!r}: {exc}')

        # Apply {instance} substitution to each constant's "value" (strings
        # only) and "description" fields.
        if cfg.get("constants"):
            expanded_constants = []
            for i, c in enumerate(cfg["constants"]):
                c_out = dict(c)
                if isinstance(c.get("value"), str):
                    try:
                        c_out["value"] = c["value"].format_map(fmt)
                    except (KeyError, ValueError) as exc:
                        sys.exit(
                            f'Bad value template {c["value"]!r} in constant '
                            f'{c.get("opcua_name", i)!r}: {exc}'
                        )
                if c.get("description"):
                    try:
                        c_out["description"] = c["description"].format_map(fmt)
                    except (KeyError, ValueError) as exc:
                        sys.exit(
                            f'Bad description template {c["description"]!r} in constant '
                            f'{c.get("opcua_name", i)!r}: {exc}'
                        )
                expanded_constants.append(c_out)
            instance_cfg["constants"] = expanded_constants

        expanded.append(instance_cfg)
        log.debug("Expanded multi-IP config: ip=%s opcua_path=%s",
                  address, instance_cfg["opcua_path"])
    return expanded


def load_device_configs(
    paths: List[str],
    strip_leading_underscore: bool = False,
) -> List[dict]:
    """
    Load device configuration(s) from one or more JSON files.

    Each file may contain either:
      • a JSON object  → treated as a single device configuration
      • a JSON array   → treated as a list of device configurations

    When a config's "host" field is a JSON array of strings, it is
    automatically expanded into one config per address (see _expand_multi_ip).

    When *strip_leading_underscore* is True, the leading underscore is removed
    from the opcua_name of every OID entry whose name starts with _.
    This causes those OIDs to be published as OPC UA variables rather than kept
    as server-side-only local values.  Intended for testing and diagnostics.

    All files are merged into a single flat list and returned.
    Exits with an error message if any file cannot be read or parsed.
    """
    configs: List[dict] = []
    for path in paths:
        try:
            with open(path) as fh:
                data = json.load(fh)
        except FileNotFoundError:
            sys.exit(f"Device config file not found: {path}")
        except json.JSONDecodeError as exc:
            sys.exit(f"Device config file is not valid JSON ({path}): {exc}")

        if isinstance(data, dict):
            raw_list = [data]
            log.debug("Loaded 1 device config from %s", path)
        elif isinstance(data, list):
            if not all(isinstance(item, dict) for item in data):
                sys.exit(
                    f"Device config array in {path} must contain only objects"
                )
            raw_list = data
            log.debug("Loaded %d device config(s) from %s", len(data), path)
        else:
            sys.exit(
                f"Device config file {path} must be a JSON object or array, "
                f"got {type(data).__name__}"
            )

        for raw_cfg in raw_list:
            for expanded_cfg in _expand_multi_ip(raw_cfg):
                if strip_leading_underscore:
                    for oid in expanded_cfg.get("oids", []):
                        if oid.get("opcua_name", "").startswith("_"):
                            oid["opcua_name"] = oid["opcua_name"].lstrip("_")
                configs.append(expanded_cfg)

    return configs


async def async_main() -> None:
    args = parse_args()
    setup_logging(args.log_level, args.log_file)

    user = password = None
    if args.opcua_user:
        parts = args.opcua_user.split(":", 1)
        if len(parts) != 2:
            sys.exit("--opcua-user must be in USER:PASS format")
        user, password = parts

    opcua_server = OPCUAServer(
        endpoint=args.opcua_endpoint,
        namespace=args.opcua_namespace,
        root_path=args.opcua_root,
        user=user,
        password=password,
        default_oids_per_get=args.default_oids_per_get,
    )
    root_display = args.opcua_root if args.opcua_root else "(none — devices under Objects/)"
    log.info("OPC UA root path: %s", root_display)

    if args.device_configs:
        configs = load_device_configs(args.device_configs, strip_leading_underscore=args.publish_local_oids)
        log.info("Using %d device config(s) from command-line JSON file(s)", len(configs))
    else:
        configs = EXAMPLE_CONFIGS
        log.info("No --device-config given — using built-in EXAMPLE_CONFIGS")

    for cfg in configs:
        try:
            # CLI defaults act as fallbacks; per-device JSON keys take precedence.
            cfg.setdefault("poll_interval", args.default_poll_interval)
            cfg.setdefault("snmp_timeout",  args.snmp_timeout)
            cfg.setdefault("snmp_retries",  args.snmp_retries)
            opcua_server.register(SNMPPoller.from_dict(cfg))
        except (ValueError, KeyError) as exc:
            sys.exit(f"Invalid device configuration for "
                     f"{cfg.get('opcua_path', cfg.get('ip', '?'))!r}: {exc}")

    # ── optional config dump (written just before the event loop starts) ─────
    if args.dump_device_config:
        configs_out = [p.to_dict() for p in opcua_server._pollers]
        payload = configs_out[0] if len(configs_out) == 1 else configs_out
        try:
            with open(args.dump_device_config, "w") as fh:
                json.dump(payload, fh, indent=2, default=str)
            log.info("Device config dumped to %s", args.dump_device_config)
        except OSError as exc:
            log.error("Could not write device config dump to %s: %s",
                      args.dump_device_config, exc)

    await opcua_server.run()


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        log.info("Interrupted by user")


if __name__ == "__main__":
    main()
