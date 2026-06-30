# Use official Python image
FROM python:3.14-slim

# Install dependencies
RUN pip install asyncua==2.0 pysnmp

# Copy project files into container
COPY . /app

# Set working directory inside container
WORKDIR /app

# Command to run the Python script
ENTRYPOINT ["python", "snmp_asyncua_bridge.py", "--system-monitoring=Monitoring"]
CMD ["--opcua-endpoint=opc.tcp://0.0.0.0:48060", "--device-config", "switches/nectarcam2_controlswitch_resolved.json", "--device-config", "switches/nectarcam2_dataswitches_resolved.json"]
# ENTRYPOINT ["tail", "-f", "/dev/null"]
