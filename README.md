# nectarcam_snmp_opcua
OPC UA server bridge for NectarCAM SNMP devices

Monitor SNMP OIDs from multiple devices and export them as OPC UA variables.

`python snmp_opcua_bridge.py \
    --opcua-endpoint opc.tcp://0.0.0.0:4840/nectarcam/ \
    --log-level INFO`
