"""
snmp_asyncua_bridge.py
────────────────────
SNMP → OPC UA bridge using pysnmp (SNMPv2c) and asyncua.

Usage
-----
python snmp_asyncua_bridge.py \
    --opcua-endpoint opc.tcp://0.0.0.0:4840/nectarcam/ \
    --opcua-namespace http://cta-observatory.org/nectarcam/snmpdevices/ \
    --opcua-user admin:secret \
    --log-level INFO \
    --log-file bridge.log

Configuration example
---------------------
Each SNMPPoller is built from a dict like:

    {
        "ip":        "192.168.1.10",
        "port":      161,
        "community": "public",
        "description": "Main distribution switch, rack A",
        "opcua_path": "Switch01",              # relative to SNMPDevices/
        "poll_interval": 10,                   # seconds
        "oids": [
            {
                "oid":         "1.3.6.1.2.1.1.1.0",   # sysDescr
                "opcua_name":  "sysDescr",
                "opcua_type":  "String",
                "description": "System description",
            },
            {
                "oid":         "1.3.6.1.2.1.1.3.0",   # sysUpTime
                "opcua_name":  "sysUpTime",
                "opcua_type":  "UInt32",
                "description": "System uptime in hundredths of a second",
            },
        ],
    }

Supported opcua_type values
---------------------------
  Boolean, SByte, Byte, Int16, UInt16, Int32, UInt32,
  Int64, UInt64, Float, Double, String, ByteString
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import logging.handlers
import sys
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

def setup_logging(level: str, log_file: Optional[str]) -> logging.Logger:
    logger = logging.getLogger("snmp_asyncua_bridge")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=3
        ))
    for h in handlers:
        h.setFormatter(fmt)
        logger.addHandler(h)
    return logger


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
}


def _snmp_value_to_python(raw_value: Any) -> Any:
    """Convert a pysnmp value object to a plain Python value."""
    if isinstance(raw_value, (Integer, Integer32, TimeTicks,
                               Counter32, Gauge32, Unsigned32)):
        return int(raw_value)
    if isinstance(raw_value, Counter64):
        return int(raw_value)
    if isinstance(raw_value, IpAddress):
        return str(raw_value)
    if isinstance(raw_value, OctetString):
        try:
            return raw_value.prettyPrint()          # human-readable if ASCII
        except Exception:
            return bytes(raw_value)
    return raw_value.prettyPrint()


def _cast_to_ua(value: Any, opcua_type: str) -> ua.DataValue | ua.Variant:
    """
    Cast a Python value to the requested OPC UA Variant.

    Returns a ua.Variant on success.  On cast failure returns a ua.DataValue
    with status BadDataEncodingInvalid so OPC UA clients see a proper error
    status rather than a silently mis-typed String value written to a node
    that was declared with a different type.
    """
    variant_type, cast_fn = _UA_TYPE_MAP[opcua_type]
    try:
        return ua.Variant(cast_fn(value), variant_type)
    except (ValueError, TypeError) as exc:
        log.warning("Type cast failed (%s → %s): %s – writing BadDataEncodingInvalid",
                    value, opcua_type, exc)
        return ua.DataValue(
            ua.Variant(None, ua.VariantType.Null),
            ua.StatusCode(ua.StatusCodes.BadDataEncodingInvalid),
        )


# ─────────────────────────────────────────────────────────────────────────────
# OID configuration dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OIDConfig:
    oid: str                  # dotted-decimal  e.g. "1.3.6.1.2.1.1.1.0"
    opcua_name: str           # variable name on OPC UA side
    opcua_type: str           # one of the keys in _UA_TYPE_MAP
    description: str = ""

    def __post_init__(self):
        if self.opcua_type not in _UA_TYPE_MAP:
            raise ValueError(
                f"Unknown opcua_type '{self.opcua_type}' for OID {self.oid}. "
                f"Valid types: {list(_UA_TYPE_MAP)}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# SNMPPoller
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SNMPPoller:
    """
    Polls a single SNMP device (SNMPv2c) and writes values to OPC UA nodes.

    Automatically adds three built-in variables to the OPC UA object:
      • host       (String)  – IP address of the device
      • port       (UInt16)  – UDP port of the SNMP agent
      • cls_state  (Byte)    – 0 = offline, 1 = online
    """

    # ── config ────────────────────────────────────────────────────────────────
    ip: str
    port: int
    community: str
    description: str          # human-readable device description (written to OPC UA object)
    opcua_path: str           # dot-separated path relative to SNMPDevices/, e.g. "Switch01"
    poll_interval: float      # seconds
    oids: List[OIDConfig]

    # ── runtime state (set by OPCUAServer during registration) ───────────────
    _ns_idx: int = field(default=0, init=False, repr=False)
    _node_map: Dict[str, Any] = field(default_factory=dict, init=False, repr=False)
    _state_node: Any = field(default=None, init=False, repr=False)
    _snmp_engine: Any = field(default=None, init=False, repr=False)

    # ── OID resolution cache ──────────────────────────────────────────────────
    # Maps opcua_name -> exact OID key string as returned by pysnmp.
    # Populated on the first successful poll; cleared when the device goes
    # offline so keys are re-resolved on recovery.
    _oid_key_cache: Dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _was_offline: bool = field(default=True, init=False, repr=False)

    # ─────────────────────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        # Create the SnmpEngine once and reuse it across all polls.
        # Recreating it on every call is heavyweight (dispatcher threads, etc.)
        # and leaks resources even when close_dispatcher() is called.
        self._snmp_engine = SnmpEngine()

    @classmethod
    def from_dict(cls, cfg: dict) -> "SNMPPoller":
        """Construct from a plain configuration dictionary."""
        oids = [OIDConfig(**o) for o in cfg["oids"]]
        return cls(
            ip=cfg["ip"],
            port=int(cfg.get("port", 161)),
            community=cfg["community"],
            description=cfg.get("description", ""),
            opcua_path=cfg["opcua_path"],
            poll_interval=float(cfg.get("poll_interval", 10)),
            oids=oids,
        )

    # ── SNMP helpers ──────────────────────────────────────────────────────────

    async def _get_all_oids(self) -> Optional[Dict[str, Any]]:
        """
        Fetch all configured OIDs in a single bulk GET request.

        Returns a dict mapping oid_str -> raw_value for every OID that
        responded successfully, or None if the device was unreachable entirely
        (error_indication set before any var-bind was returned).

        Individual OIDs that the agent reports an error for are skipped and
        logged as warnings; the remaining results are still returned.
        """
        object_types = [
            ObjectType(ObjectIdentity(oid_cfg.oid)) for oid_cfg in self.oids
        ]
        # Re-use the engine that was created once in __post_init__.
        # Do NOT call close_dispatcher() here — that would tear down the shared
        # engine and break all subsequent polls on this poller.
        error_indication, error_status, error_index, var_binds = await get_cmd(
            self._snmp_engine,
            CommunityData(self.community, mpModel=1),   # mpModel=1 → SNMPv2c
            await UdpTransportTarget.create(
                (self.ip, self.port), timeout=2, retries=1
            ),
            ContextData(),
            *object_types,
        )

        # Transport / auth failure — device completely unreachable
        if error_indication:
            log.debug("SNMP bulk GET %s: %s", self.ip, error_indication)
            return None

        # Agent-level error — one or more var-binds bad, rest may be ok
        if error_status:
            bad_idx = int(error_index) - 1 if error_index else None
            bad_oid = (
                str(var_binds[bad_idx][0]) if bad_idx is not None else "unknown"
            )
            log.warning(
                "SNMP GET %s: agent error '%s' at OID %s – skipping that OID",
                self.ip, error_status.prettyPrint(), bad_oid,
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
            results[str(oid_obj)] = value
        return results

    # ── polling loop ──────────────────────────────────────────────────────────

    async def run(self) -> None:
        """
        Phase-locked polling loop.  Must be called after the OPC UA nodes have
        been created (i.e. after OPCUAServer.build_address_space()).

        The first poll fires immediately and its wall-clock time is recorded as
        the phase origin.  Every subsequent deadline is origin + N * interval,
        so accumulated drift from poll latency is corrected each cycle rather
        than compounding.  If a poll overruns its slot the next sleep is simply
        zero (we never skip a cycle).
        """
        log.info("Poller started: %s  path=%s  interval=%.1fs",
                 self.ip, self.opcua_path, self.poll_interval)

        loop = asyncio.get_running_loop()
        origin = loop.time()          # phase reference: time of first poll
        cycle = 0

        while True:
            online = await self._poll_once()
            state_val = ua.Variant(1 if online else 0, ua.VariantType.Byte)
            await self._state_node.write_value(state_val)

            cycle += 1
            next_deadline = origin + cycle * self.poll_interval
            sleep_for = next_deadline - loop.time()
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            else:
                # Poll overran its slot — log and continue immediately
                log.warning("Poller %s overran slot by %.3fs (cycle %d)",
                            self.ip, -sleep_for, cycle)

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
            return oid_cfg.oid
        suffixed = oid_cfg.oid.rstrip(".0") + ".0"
        if suffixed in results:
            return suffixed
        for key in results:
            # Guard with a dot boundary so that e.g. "1.1.0" does not
            # accidentally match a key ending in "11.0" (plain string-suffix
            # would pass but the OIDs are unrelated).
            if key.endswith("." + oid_cfg.oid) or oid_cfg.oid.endswith("." + key):
                return key
        return None

    async def _poll_once(self) -> bool:
        """
        Fetch all configured OIDs in one bulk GET and write results to OPC UA.

        OID key resolution is performed on the first successful poll after the
        device was offline, then cached for subsequent cycles.  The cache is
        cleared when the device goes offline so keys are re-resolved on
        recovery.

        On the offline transition every node whose OID key was successfully
        resolved is stamped with UncertainLastUsableValue, preserving the last
        known value while signalling to clients that it is stale.

        Returns True if the device responded (even partially), False if totally
        unreachable.
        """
        results = await self._get_all_oids()

        if results is None:
            # Complete transport failure — device offline
            if not self._was_offline:
                # Transition online → offline: stamp resolved nodes as stale.
                # UncertainLastUsableValue is not a bad status code, so asyncua
                # still enforces the type check on the Value field — we must
                # supply the correct typed variant.  We read the current DataValue
                # from each node and reuse its Value, replacing only the status.
                log.warning("Device went offline: %s", self.ip)
                _uncertain = ua.StatusCode(ua.StatusCodes.UncertainLastUsableValue)
                for opcua_name, _key in self._oid_key_cache.items():
                    node = self._node_map.get(opcua_name)
                    if node is not None:
                        try:
                            current_dv = await node.read_data_value()
                            stale_dv = ua.DataValue(
                                Value=current_dv.Value,
                                StatusCode_=_uncertain,
                            )
                            await node.write_value(stale_dv)
                        except Exception as exc:
                            log.error("Failed to write UncertainLastUsableValue for %s.%s: %s",
                                      self.opcua_path, opcua_name, exc)
                self._oid_key_cache.clear()
                self._was_offline = True
            else:
                log.debug("Device still offline: %s", self.ip)
            return False

        # ── Device is responding ──────────────────────────────────────────────
        if self._was_offline:
            # Transition offline → online: resolve and cache OID keys
            log.info("Device came online: %s — resolving OID keys", self.ip)
            self._oid_key_cache.clear()
            for oid_cfg in self.oids:
                key = self._resolve_oid_key(oid_cfg, results)
                if key is not None:
                    self._oid_key_cache[oid_cfg.opcua_name] = key
                    log.debug("  OID resolved: %s -> %s (%s)",
                              oid_cfg.oid, key, oid_cfg.opcua_name)
                else:
                    log.warning("OID not supported by device – marking BadNotSupported: "
                                "%s on %s", oid_cfg.oid, self.ip)
                    node = self._node_map.get(oid_cfg.opcua_name)
                    if node is not None:
                        try:
                            current_dv = await node.read_data_value()
                            await node.write_value(ua.DataValue(
                                Value=current_dv.Value,
                                StatusCode_=ua.StatusCode(ua.StatusCodes.BadNotSupported),
                            ))
                        except Exception as exc:
                            log.error("Failed to write BadNotSupported for %s.%s: %s",
                                      self.opcua_path, oid_cfg.opcua_name, exc)
            self._was_offline = False

        # ── Write values to OPC UA ────────────────────────────────────────────
        any_ok = False
        for oid_cfg in self.oids:
            key = self._oid_key_cache.get(oid_cfg.opcua_name)
            node = self._node_map.get(oid_cfg.opcua_name)
            if node is None or key is None:
                continue

            raw = results.get(key)
            if raw is None:
                # Key resolved correctly at startup but absent in this response;
                # log and leave the node at its current status until next cycle.
                log.warning("Cached OID key no longer in response: %s on %s",
                            key, self.ip)
                continue

            any_ok = True
            py_val = _snmp_value_to_python(raw)
            variant = _cast_to_ua(py_val, oid_cfg.opcua_type)
            try:
                await node.write_value(variant)
            except Exception as exc:
                log.error("OPC UA write failed for %s.%s: %s",
                          self.opcua_path, oid_cfg.opcua_name, exc)

        return any_ok


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
            # Return UserRole.User when available, otherwise any truthy value
            if UserRole is not None:
                return UserRole.User
            return True      # asyncua 1.1.x: truthy value grants access
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
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.endpoint = endpoint
        self.namespace = namespace
        self.user = user
        self.password = password
        self._pollers: List[SNMPPoller] = []

    def register(self, poller: SNMPPoller) -> None:
        """Register an SNMPPoller with this server."""
        self._pollers.append(poller)
        log.info("Registered poller: %s → %s", poller.ip, poller.opcua_path)

    # ── address space construction ────────────────────────────────────────────

    async def _ensure_path(
        self,
        server: Server,
        ns_idx: int,
        path_parts: List[str],
    ) -> Any:
        """
        Walk (and create where missing) a chain of Object nodes under Objects/.
        Returns the deepest node in the chain.
        """
        parent = server.nodes.objects
        for part in path_parts:
            found = None
            try:
                for child in await parent.get_children():
                    if await child.read_browse_name() == ua.QualifiedName(part, ns_idx):
                        found = child
                        break
            except Exception:
                pass
            if found is None:
                found = await parent.add_object(ns_idx, part)
                log.debug("Created OPC UA object node: %s", part)
            parent = found
        return parent

    async def _build_address_space(self, server: Server, ns_idx: int) -> None:
        """Create all OPC UA nodes for every registered poller."""
        for poller in self._pollers:
            # opcua_path is relative to SNMPDevices/; _ensure_path handles both
            # the root node and all sub-segments in one shot, eliminating the
            # duplicated child-walk logic that used to live here.
            parts = poller.opcua_path.split(".")
            device_node = await self._ensure_path(
                server, ns_idx, ["SNMPDevices"] + parts
            )

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

            # ── built-in variables ────────────────────────────────────────────
            host_node = await device_node.add_variable(
                ns_idx, "host", ua.Variant(poller.ip, ua.VariantType.String)
            )
            await host_node.set_writable(False)

            port_node = await device_node.add_variable(
                ns_idx, "port", ua.Variant(poller.port, ua.VariantType.UInt16)
            )
            await port_node.set_writable(False)

            state_node = await device_node.add_variable(
                ns_idx, "cls_state", ua.Variant(0, ua.VariantType.Byte)
            )
            await state_node.set_writable(False)
            poller._state_node = state_node

            # ── configured OIDs ───────────────────────────────────────────────
            poller._ns_idx = ns_idx
            for oid_cfg in poller.oids:
                variant_type, _cast_fn = _UA_TYPE_MAP[oid_cfg.opcua_type]
                # Create the node with a typed zero so asyncua knows the
                # correct VariantType, then immediately overwrite the status
                # to BadWaitingForInitialData so clients see the node as
                # uninitialised until the first successful poll arrives.
                try:
                    zero = _cast_fn(0)
                except (ValueError, TypeError):
                    zero = _cast_fn()   # e.g. str(), bytes()
                var_node = await device_node.add_variable(
                    ns_idx,
                    oid_cfg.opcua_name,
                    ua.Variant(zero, variant_type),
                )
                await var_node.set_writable(False)
                await var_node.write_value(ua.DataValue(
                    StatusCode_=ua.StatusCode(ua.StatusCodes.BadWaitingForInitialData),
                ))
                if oid_cfg.description:
                    await var_node.write_attribute(
                        ua.AttributeIds.Description,
                        ua.DataValue(
                            ua.Variant(
                                ua.LocalizedText(oid_cfg.description),
                                ua.VariantType.LocalizedText,
                            )
                        ),
                    )
                poller._node_map[oid_cfg.opcua_name] = var_node
                log.debug("  OPC UA variable: %s.%s (%s)",
                          poller.opcua_path, oid_cfg.opcua_name, oid_cfg.opcua_type)

            log.info("Address space built for %s", poller.opcua_path)

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
            tasks = [
                asyncio.create_task(poller.run(), name=f"poller-{poller.ip}")
                for poller in self._pollers
            ]
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
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Example / demo  (replace with your real config)
# ─────────────────────────────────────────────────────────────────────────────

EXAMPLE_CONFIGS = [
    {
        "ip":            "127.0.0.1",
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


def load_device_configs(paths: List[str]) -> List[dict]:
    """
    Load device configuration(s) from one or more JSON files.

    Each file may contain either:
      • a JSON object  → treated as a single device configuration
      • a JSON array   → treated as a list of device configurations

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
            configs.append(data)
            log.debug("Loaded 1 device config from %s", path)
        elif isinstance(data, list):
            if not all(isinstance(item, dict) for item in data):
                sys.exit(
                    f"Device config array in {path} must contain only objects"
                )
            configs.extend(data)
            log.debug("Loaded %d device config(s) from %s", len(data), path)
        else:
            sys.exit(
                f"Device config file {path} must be a JSON object or array, "
                f"got {type(data).__name__}"
            )

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
        user=user,
        password=password,
    )

    if args.device_configs:
        configs = load_device_configs(args.device_configs)
        log.info("Using %d device config(s) from command-line JSON file(s)", len(configs))
    else:
        configs = EXAMPLE_CONFIGS
        log.info("No --device-config given — using built-in EXAMPLE_CONFIGS")

    for cfg in configs:
        opcua_server.register(SNMPPoller.from_dict(cfg))

    await opcua_server.run()


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        log.info("Interrupted by user")


if __name__ == "__main__":
    main()
