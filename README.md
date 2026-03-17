# nectarcam_snmp_opcua

OPC UA server bridge for NectarCAM SNMP devices

This project provides an OPC UA server that polls SNMP devices and exposes their OID values as OPC UA variables. It supports monitoring multiple devices with configurable polling intervals and automatic type conversion.

## Features

- Polls SNMPv2c devices asynchronously
- Exposes OID values as typed OPC UA variables
- Supports multiple devices with individual configurations
- Automatic handling of device online/offline states
- Configurable polling intervals
- Type-safe OPC UA variable creation with proper status codes
- Authentication support for OPC UA server

## Installation

Install the required dependencies:

```bash
pip install pysnmp-lextudio asyncua
```

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
    --opcua-user admin:secret \
    --log-level INFO \
    --log-file bridge.log \
    --device-config device_localhost.json \
    --device-config device_x-cisco.in2p3.fr.json
```

### Command Line Options

- `--opcua-endpoint`: OPC UA server endpoint URL (default: `opc.tcp://0.0.0.0:4840/nectarcam/`)
- `--opcua-namespace`: OPC UA namespace URI (default: `http://cta-observatory.org/nectarcam/snmpdevices/`)
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
- `opcua_path` (string): OPC UA path relative to `SNMPDevices/`, e.g., `"Switch01"`. For multi-IP configurations, use `{instance}` for substitution.
- `poll_interval` (number, optional): Polling interval in seconds (default: 10)
- `oids` (array): List of OID configurations

### OID Configuration Structure

Each OID in the `oids` array is a JSON object with:

- `oid` (string): Dotted-decimal OID string, e.g., `"1.3.6.1.2.1.1.1.0"`
- `opcua_name` (string): Name of the OPC UA variable
- `opcua_type` (string): OPC UA data type. Supported types: `Boolean`, `SByte`, `Byte`, `Int16`, `UInt16`, `Int32`, `UInt32`, `Int64`, `UInt64`, `Float`, `Double`, `String`, `ByteString`
- `description` (string, optional): Description of the OID

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

If `opcua_path` doesn't contain `{instance}`, a suffix `_{index}` is automatically appended to avoid conflicts.

### Example Configuration File

```json
{
  "ip": "192.168.1.10",
  "description": "Main distribution switch, rack A",
  "opcua_path": "Switch01",
  "oids": [
    {
      "oid": "1.3.6.1.2.1.1.1.0",
      "opcua_name": "sysDescr",
      "opcua_type": "String",
      "description": "System description"
    },
    {
      "oid": "1.3.6.1.2.1.1.3.0",
      "opcua_name": "sysUpTime",
      "opcua_type": "UInt32",
      "description": "System uptime in hundredths of a second"
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

- `SNMPDevices/` (root folder)
  - `{opcua_path}/` (device folder)
    - `host` (String): Device IP address
    - `port` (UInt16): Device port
    - `cls_state` (Byte): Online state (1 = online, 0 = offline)
    - `{opcua_name}`: Configured OID variables

All variables are read-only. Device state and OID values are updated automatically based on polling results.

## Status Codes

The bridge uses appropriate OPC UA status codes:

- `Good`: Valid data from successful poll
- `BadWaitingForInitialData`: Node created but no data received yet
- `BadNotSupported`: OID not supported by device
- `UncertainLastUsableValue`: Device offline, showing last known value
- `BadDataEncodingInvalid`: Type conversion failed

## Logging

Logs include polling activity, device state changes, and errors. Use `--log-level DEBUG` for detailed SNMP transaction logs.

## License

See LICENSE file for details.
