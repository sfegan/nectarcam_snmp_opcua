# nectarcam_snmp_opcua

OPC UA server bridge for NectarCAM SNMP devices

This project provides an OPC UA server that polls SNMP devices and exposes their OID values as OPC UA variables. It supports monitoring multiple devices with configurable polling intervals and automatic type conversion.

## Features

- Polls SNMPv2c devices asynchronously
- Exposes OID values as typed OPC UA variables
- Supports multiple devices with individual configurations
- Automatic handling of device online/offline states
- Configurable polling intervals, including per-OID sub-sampling via `poll_every`
- Configurable SNMP timeout and retry settings
- Configurable maximum OIDs per GET request, for devices that reject multi-OID GETs
- Lifetime management for OID staleness detection
- Type-safe OPC UA variable creation with proper status codes
- Authentication support for OPC UA server

## Installation

Install the required dependencies:

```bash
pip install pysnmp-lextudio asyncua
```

For symbolic OID name resolution, install `net-snmp` (provides `snmptranslate`) or ensure pysnmp's built-in MIBs are sufficient. Symbolic names like `"SNMPv2-MIB::sysDescr.0"` are automatically converted to numeric OIDs at startup.

## Usage

Run the bridge with default settings:

```bash
python snmp_asyncua_bridge.py
```

For production use, specify configuration files and options:

```bash
python snmp_asyncua_bridge.py \
    --opcua-endpoint opc.tcp://0.0.0.0:4840/nectarcam/ \
    --opcua-namespace http://cta-observatory.org/nectarcam/snmpdevices/ \
    --opcua-root SNMPDevices \
    --opcua-user admin:secret \
    --log-level INFO \
    --log-file bridge.log \
    --device-config device_localhost.json \
    --device-config device_x-cisco.in2p3.fr.json
```

### Command Line Options

- `--opcua-endpoint`: OPC UA server endpoint URL (default: `opc.tcp://0.0.0.0:4840/nectarcam/`)
- `--opcua-namespace`: OPC UA namespace URI (default: `http://cta-observatory.org/nectarcam/snmpdevices/`)
- `--opcua-root`: Dot-separated OPC UA path of the container node created above all device objects (default: `SNMPDevices`). Pass an empty string to place devices directly under `Objects/`.
- `--opcua-user`: Username and password for OPC UA authentication in `USER:PASS` format (optional, enables authentication)
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL; default: INFO)
- `--log-file`: Optional log file path
- `--snmp-timeout`: SNMP request timeout in seconds (per attempt) (default: 2.0). Can be overridden per device in JSON config.
- `--snmp-retries`: Number of SNMP retries after the first attempt (default: 1). Can be overridden per device in JSON config.
- `--default-poll-interval`: Default poll interval in seconds applied to every device that does not specify its own `poll_interval` in its JSON config (default: 10.0). Can be overridden per device.
- `--default-oids-per-get`: Server-wide default for the maximum number of OIDs sent in a single SNMP GET request (default: 0 = unlimited). A positive value causes the OID list to be split into sequential batches of at most that size, which is required by devices that reject multi-OID GETs. Can be overridden per device with `oids_per_get` in the JSON config.
- `--device-config`: Path to JSON configuration file (can be specified multiple times).
- `--dump-device-config`: Path to a JSON file to write the fully-resolved device configuration just before the event loop starts, then continue running normally. The output is reconstructed from the live poller instances so every field is present with its resolved value: symbolic OIDs are in dotted-decimal, multi-IP entries are fully expanded, and all defaults are filled in. Reloading the file reproduces identical behaviour regardless of CLI defaults.
- `--publish-local-oids`: Strip leading underscores from local (underscore-prefixed) OID names so they are published as OPC UA variables instead of being kept server-side only. Intended for testing and diagnostics.

## Configuration

Devices are configured using JSON files specified with the `--device-config` option. Each JSON file can contain either a single device configuration object or an array of device configuration objects.

### Device Configuration Structure

Each device configuration is a JSON object with the following fields:

- `host` (string or array of strings): IP address(es) of the SNMP device(s). If an array, multiple identical devices are created with `{instance}` placeholder substitution.
- `port` (integer, optional): SNMP port (default: 161)
- `community` (string, optional): SNMP community string (default: `"public"`)
- `description` (string, optional): Human-readable description of the device
- `opcua_path` (string): Dot-separated OPC UA path relative to the root container (set by `--opcua-root`), e.g., `"Switch01"` or `"Switch.Monitoring"`. For multi-IP configurations, use `{instance}` for substitution.
- `poll_interval` (number, optional): Polling interval in seconds (default: value of `--default-poll-interval`, which defaults to 10.0)
- `snmp_timeout` (number, optional): SNMP request timeout in seconds (per attempt) (default: value of `--snmp-timeout`)
- `snmp_retries` (integer, optional): Number of SNMP retries after the first attempt (default: value of `--snmp-retries`)
- `default_lifetime` (number, optional): Default lifetime in seconds for OID variables that do not specify their own `lifetime`. `0` means never expire (default: 0).
- `oids_per_get` (integer, optional): Maximum number of OIDs to include in a single SNMP GET request for this device. `-1` (default) inherits the server-wide `--default-oids-per-get` value. `0` means unlimited (all due OIDs in one request). A positive value splits the OID list into sequential batches of at most that size. Use this for devices that reject multi-OID GETs — set it to `1` if the device documentation states only one OID per request is supported. See [Batched GET Requests](#batched-get-requests) below.
- `oids` (array): List of OID configurations
- `constants` (array, optional): List of constant variable configurations

### OID Configuration Structure

Each OID in the `oids` array is a JSON object with:

- `oid` (string): OID identifier, either in dotted-decimal notation (e.g., `"1.3.6.1.2.1.1.1.0"`) or symbolic name (e.g., `"SNMPv2-MIB::sysDescr.0"`). Symbolic names are automatically resolved to numeric form at startup.
- `opcua_name` (string): Name of the OPC UA variable. Names beginning with `_` are *local*: polled and stored internally but not published as OPC UA nodes (useful as inputs for derived variables in subclasses).
- `opcua_type` (string): OPC UA data type. Supported types: `Boolean`, `SByte`, `Byte`, `Int16`, `UInt16`, `Int32`, `UInt32`, `Int64`, `UInt64`, `Float`, `Double`, `String`, `ByteString`, `DateTime`
- `description` (string, optional): Description of the OID (default: `""`)
- `lifetime` (number, optional): Lifetime in seconds for this variable. Any negative value means use the device-level `default_lifetime`. `0` means never expire. When the device is unreachable and the lifetime has elapsed the variable transitions from `UncertainLastUsableValue` to `BadNoCommunication`.
- `poll_every` (integer, optional): Read this OID only every N poll cycles (default: 1, meaning every cycle). Values less than 1 are silently treated as 1. Use this to reduce SNMP traffic for slowly-changing values such as device names, firmware versions, or link status while keeping faster-changing values (counters, temperatures) at the full poll rate. See [Per-OID Poll Frequency](#per-oid-poll-frequency) below.

### Constants Configuration Structure

Each constant in the `constants` array is a JSON object with:

- `opcua_name` (string): Name of the OPC UA variable
- `opcua_type` (string): OPC UA data type. Supported types: `Boolean`, `SByte`, `Byte`, `Int16`, `UInt16`, `Int32`, `UInt32`, `Int64`, `UInt64`, `Float`, `Double`, `String`, `ByteString`, `DateTime`
- `value` (any): The constant value to write (must be compatible with `opcua_type`). Use `null` to create a placeholder node that starts as `BadWaitingForInitialData` and is intended to be filled in by a subclass.
- `description` (string, optional): Description of the constant
- `lifetime` (number, optional): Lifetime in seconds. Any negative value means use the device-level `default_lifetime` (for `null`-value derived constants) or `0` (for true constants). `0` means never expire.

Constants are fixed OPC UA variables whose values are written once at startup and never updated by the poll loop. They are useful for static metadata such as firmware version, serial number, or device model.

For multi-IP configurations, the `{instance}` placeholder can be used in `value` (if it is a string) and `description` fields for per-device customization.

## OPC UA Root Path

The `--opcua-root` option controls the base path where all device objects are placed in the OPC UA address space. It is a dot-separated string that creates nested Object nodes under the server's `Objects/` folder.

Examples:
- `--opcua-root SNMPDevices` → Devices under `Objects/SNMPDevices/`
- `--opcua-root Camera0.SNMPDevices` → Devices under `Objects/Camera0/SNMPDevices/`
- `--opcua-root ""` → Devices directly under `Objects/`

Each device's `opcua_path` is appended to this root path, allowing for hierarchical organization.

## Multi-IP Configurations

When `host` is an array of strings, the bridge creates one poller per address. The `{instance}` placeholder (zero-based index) can be used in `opcua_path` and `description` for customization:

```json
{
  "host": ["192.168.1.10", "192.168.1.11", "192.168.1.12"],
  "opcua_path": "Switch{instance:02d}",
  "description": "Distribution switch {instance}",
  "oids": [...]
}
```

This creates devices at `SNMPDevices/Switch00`, `SNMPDevices/Switch01`, `SNMPDevices/Switch02`, etc.

If `opcua_path` doesn't contain `{instance}`, a suffix `_{instance}` is automatically appended to avoid conflicts.

## Per-OID Poll Frequency

By default every OID is read on every poll cycle (`poll_every: 1`). Setting `poll_every: N` causes the OID to be included in the SNMP GET only every N cycles, reducing traffic for slowly-changing values.

```json
{
  "host": "192.168.1.10",
  "opcua_path": "Switch01",
  "poll_interval": 1,
  "oids": [
    {
      "oid": "1.3.6.1.2.1.2.2.1.10.1",
      "opcua_name": "ifInOctets",
      "opcua_type": "UInt32",
      "description": "Bytes received — read every cycle",
      "poll_every": 1
    },
    {
      "oid": "SNMPv2-MIB::sysDescr.0",
      "opcua_name": "sysDescr",
      "opcua_type": "String",
      "description": "System description — read every 60 cycles (once per minute)",
      "poll_every": 60
    }
  ]
}
```

**Staleness behaviour with `poll_every > 1`:** only OIDs that were actually requested in a given cycle can be marked `UncertainLastUsableValue`. OIDs not due that cycle are left entirely untouched — their status remains `Good` from the last successful read until they are next polled.

**Device going offline:** when the SNMP agent becomes unreachable, all OIDs are immediately marked stale (regardless of `poll_every`) and all per-OID schedules are reset so that every variable is re-read on the next successful cycle. The sub-sampling phase is reset from that point.

**Cycles with no OIDs due:** if a combination of `poll_every` values results in a cycle where no OID is due, the SNMP GET is skipped entirely. `snmp_polling_age` continues to tick and is pushed to OPC UA; all other state is left unchanged.

## Batched GET Requests

Some devices only accept a single OID per SNMP GET request. Use `oids_per_get` in the device config (or `--default-oids-per-get` for a server-wide default) to enable batching:

```json
{
  "host": "192.168.1.50",
  "opcua_path": "RestrictedDevice",
  "oids_per_get": 1,
  "oids": [
    {"oid": "1.3.6.1.2.1.1.1.0", "opcua_name": "sysDescr",  "opcua_type": "String"},
    {"oid": "1.3.6.1.2.1.1.3.0", "opcua_name": "sysUpTime", "opcua_type": "UInt32"}
  ]
}
```

With `oids_per_get: 1`, the two OIDs above are fetched in two separate GET requests per cycle. The results are merged before any store updates or staleness logic runs, so the rest of the polling behaviour is identical to the unlimited case.

If the device stops responding part-way through a batch, any results already received from earlier chunks are discarded and the entire cycle is treated as a failure — consistent with how a transport failure behaves in the single-GET case.

## Example Configuration File

```json
{
  "host": "192.168.1.10",
  "description": "Main distribution switch, rack A",
  "opcua_path": "Switch.Monitoring",
  "poll_interval": 5,
  "default_lifetime": 30,
  "oids": [
    {
      "oid": "SNMPv2-MIB::sysDescr.0",
      "opcua_name": "sysDescr",
      "opcua_type": "String",
      "description": "System description",
      "poll_every": 12
    },
    {
      "oid": "SNMPv2-MIB::sysUpTime.0",
      "opcua_name": "sysUpTime",
      "opcua_type": "UInt32",
      "description": "System uptime in hundredths of a second"
    }
  ],
  "constants": [
    {
      "opcua_name": "SoftwareVersion",
      "opcua_type": "String",
      "value": "2.0.0",
      "description": "Firmware version of the device"
    }
  ]
}
```

## Multiple Devices in One File

You can define multiple devices in a single JSON file as an array:

```json
[
  {
    "host": "192.168.1.10",
    "opcua_path": "Switch01",
    "oids": [...]
  },
  {
    "host": "192.168.1.11",
    "opcua_path": "Switch02",
    "oids": [...]
  }
]
```

## OPC UA Address Space

The bridge creates the following structure in the OPC UA server:

- `Objects/{root_path}/` (configurable root container)
  - `{opcua_path}/` (device folder, can be multi-level)
    - `snmp_host` (String): Device IP address
    - `snmp_port` (UInt16): Device SNMP UDP port
    - `snmp_polling_timestamp` (DateTime): Wall-clock time of the last successful poll
    - `snmp_polling_age` (Double): Seconds since the last successful poll
    - `snmp_polling_interval` (Double): Configured poll interval in seconds
    - `snmp_polling_success_count` (UInt32): Cumulative count of successful polls
    - `snmp_server_online` (Boolean): True when the SNMP agent is reachable
    - `device_state` (Int32): Bridge connection state (0 = offline, 1 = online)
    - `{opcua_name}`: Configured OID and constant variables

For example, with `--opcua-root SNMPDevices` and `opcua_path: "Switch.Monitoring"`, the device variables would be under `Objects/SNMPDevices/Switch/Monitoring/`.

All variables are read-only. Device state and OID values are updated automatically based on polling results.

## Status Codes

The bridge uses appropriate OPC UA status codes:

- `Good`: Valid data from a successful poll
- `BadWaitingForInitialData`: Node created but no data received yet
- `BadNotSupported`: OID not supported by the device
- `UncertainLastUsableValue`: Device unreachable; showing last known value (within lifetime)
- `BadNoCommunication`: Device unreachable and variable lifetime has expired
- `BadDataEncodingInvalid`: Type conversion failed

## Subclassing

`SNMPPoller` is designed to be subclassed for devices that require derived variables or custom OPC UA method handlers. The key hooks are `build_variable_specs()`, `create_variables()`, `write_variables()`, and `on_address_space_ready()`.

### The `updated_this_cycle` flag

Each OID store entry (`self._store[opcua_name]`) carries an `updated_this_cycle` boolean that is `True` only when the SNMP poll in the current cycle successfully stored a fresh value for that OID. It is cleared at the start of every cycle before the GET, and is never set for constants or built-in variables.

This flag is particularly important in `write_variables()` overrides that compute derived values from raw OID data. Without it, a derived conversion applied to a value that was already converted in a previous cycle (because `poll_every > 1` means the OID was not re-read this cycle) will fail or produce a wrong result. The correct pattern is:

```python
async def write_variables(self):
    entry = self._store["_rawTemperature"]
    if entry.updated_this_cycle:
        # raw bytes fresh from SNMP — safe to convert
        raw = entry.data_value.Value.Value
        self._store["temperature"].data_value = ua.DataValue(
            ua.Variant(self._convert_temperature(raw), ua.VariantType.Float)
        )
    await super().write_variables()
```

If `updated_this_cycle` is `False`, the source OID was not polled this cycle and the derived variable's existing store value (from the last cycle it was updated) should be left unchanged.

## Logging

Logs include polling activity, device state changes, and errors. Use `--log-level DEBUG` for detailed per-cycle SNMP transaction logs including which OIDs were requested each cycle, and — when batching is active — how many chunks were sent per cycle.

## License

See LICENSE file for details.
