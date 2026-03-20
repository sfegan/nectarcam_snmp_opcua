# nectarcam_snmp_opcua

OPC UA server bridge for NectarCAM SNMP devices

This project provides an OPC UA server that polls SNMP devices and exposes their OID values as OPC UA variables. It supports monitoring multiple devices with configurable polling intervals and automatic type conversion.

## Features

- Polls SNMPv2c devices asynchronously
- Exposes OID values as typed OPC UA variables
- Supports multiple devices with individual configurations
- Automatic handling of device online/offline states
- Configurable polling intervals
- Configurable SNMP timeout and retry settings
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
- `--device-config`: Path to JSON configuration file (can be specified multiple times)

## Configuration

Devices are configured using JSON files specified with the `--device-config` option. Each JSON file can contain either a single device configuration object or an array of device configuration objects.

### Device Configuration Structure

Each device configuration is a JSON object with the following fields:

- `ip` (string or array of strings): IP address(es) of the SNMP device(s). If an array, multiple identical devices are created with `{instance}` placeholder substitution.
- `port` (integer, optional): SNMP port (default: 161)
- `community` (string, optional): SNMP community string (default: "public")
- `description` (string, optional): Human-readable description of the device
- `opcua_path` (string): Dot-separated OPC UA path relative to the root container (set by `--opcua-root`), e.g., `"Switch01"` or `"Switch.Monitoring"`. For multi-IP configurations, use `{instance}` for substitution.
- `poll_interval` (number, optional): Polling interval in seconds (default: 10)
- `snmp_timeout` (number, optional): SNMP request timeout in seconds (per attempt) (default: 2.0, or value from `--snmp-timeout`)
- `snmp_retries` (integer, optional): Number of SNMP retries after the first attempt (default: 1, or value from `--snmp-retries`)
- `default_lifetime` (number, optional): Default lifetime in seconds for OID variables that do not specify their own lifetime (default: 0, meaning never expire)
- `oids` (array): List of OID configurations
- `constants` (array, optional): List of constant variable configurations

### OID Configuration Structure

Each OID in the `oids` array is a JSON object with:

- `oid` (string): OID identifier, either in dotted-decimal notation (e.g., `"1.3.6.1.2.1.1.1.0"`) or symbolic name (e.g., `"SNMPv2-MIB::sysDescr.0"`). Symbolic names are automatically resolved to numeric form at startup.
- `opcua_name` (string): Name of the OPC UA variable
- `opcua_type` (string): OPC UA data type. Supported types: `Boolean`, `SByte`, `Byte`, `Int16`, `UInt16`, `Int32`, `UInt32`, `Int64`, `UInt64`, `Float`, `Double`, `String`, `ByteString`
- `description` (string, optional): Description of the OID (default: "")

### Constants Configuration Structure

Each constant in the `constants` array is a JSON object with:

- `opcua_name` (string): Name of the OPC UA variable
- `opcua_type` (string): OPC UA data type. Supported types: `Boolean`, `SByte`, `Byte`, `Int16`, `UInt16`, `Int32`, `UInt32`, `Int64`, `UInt64`, `Float`, `Double`, `String`, `ByteString`
- `value` (any): The constant value to write (must be compatible with `opcua_type`)
- `description` (string, optional): Description of the constant
- `lifetime` (number, optional): Lifetime in seconds for this constant variable (default: 0, meaning never expire; not enforced for constants)

Constants are fixed OPC UA variables whose values are written once at startup and never updated. They are useful for static metadata such as firmware version, serial number, or device model.

For multi-IP configurations, the `{instance}` placeholder can be used in `value` (if it is a string) and `description` fields for per-device customization.

## OPC UA Root Path

The `--opcua-root` option controls the base path where all device objects are placed in the OPC UA address space. It is a dot-separated string that creates nested Object nodes under the server's `Objects/` folder.

Examples:
- `--opcua-root SNMPDevices` → Devices under `Objects/SNMPDevices/`
- `--opcua-root Camera0.SNMPDevices` → Devices under `Objects/Camera0/SNMPDevices/`
- `--opcua-root ""` → Devices directly under `Objects/`

Each device's `opcua_path` is appended to this root path, allowing for hierarchical organization.

### Multi-IP Configurations

When `ip` is an array of strings, the bridge creates one SNMPPoller per address. The `{instance}` placeholder (zero-based index) can be used in `opcua_path` and `description` for customization:

```json
{
  "ip": ["192.168.1.10", "192.168.1.11", "192.168.1.12"],
  "opcua_path": "Switch{instance:02d}",
  "description": "Distribution switch {instance}",
  "oids": [...]
}
```

This creates devices at `SNMPDevices/Switch00`, `SNMPDevices/Switch01`, `SNMPDevices/Switch02`, etc.

If `opcua_path` doesn't contain `{instance}`, a suffix `_{instance}` is automatically appended to avoid conflicts.

### Example Configuration File

```json
{
  "ip": "192.168.1.10",
  "description": "Main distribution switch, rack A",
  "opcua_path": "Switch.Monitoring",
  "oids": [
    {
      "oid": "SNMPv2-MIB::sysDescr.0",
      "opcua_name": "sysDescr",
      "opcua_type": "String",
      "description": "System description"
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

### Multiple Devices in One File

You can define multiple devices in a single JSON file as an array:

```json
[
  {
    "ip": "192.168.1.10",
    "opcua_path": "Switch01",
    "oids": [...]
  },
  {
    "ip": "192.168.1.11",
    "opcua_path": "Switch02",
    "oids": [...]
  }
]
```

## OPC UA Address Space

The bridge creates the following structure in the OPC UA server:

- `Objects/{root_path}/` (configurable root container)
  - `{opcua_path}/` (device folder, can be multi-level)
    - `host` (String): Device IP address
    - `port` (UInt16): Device port
    - `cls_state` (Byte): Online state (1 = online, 0 = offline)
    - `{opcua_name}`: Configured OID and constant variables

For example, with `--opcua-root SNMPDevices` and `opcua_path: "Switch.Monitoring"`, the device variables would be under `Objects/SNMPDevices/Switch/Monitoring/`.

All variables are read-only. Device state and OID values are updated automatically based on polling results.

## Status Codes

The bridge uses appropriate OPC UA status codes:

- `Good`: Valid data from successful poll
- `BadWaitingForInitialData`: Node created but no data received yet
- `BadNotSupported`: OID not supported by device
- `UncertainLastUsableValue`: Device offline, showing last known value (within lifetime) or lifetime expired
- `BadDataEncodingInvalid`: Type conversion failed

## Logging

Logs include polling activity, device state changes, and errors. Use `--log-level DEBUG` for detailed SNMP transaction logs.

## License

See LICENSE file for details.
