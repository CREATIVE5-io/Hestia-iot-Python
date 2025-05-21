# NTN IoT Modbus Client

## Overview

The `ntn_iot.py` script is a Python program that connects to an NTN IoT device using Modbus RTU over a serial port. It reads and sends data like GPS coordinates, RSRP, and SINR. The script uses a `config.ini` file for settings and supports threading for uplink and downlink tasks.

## Features

- Connects to NTN devices via Modbus RTU.
- Reads and updates settings from `config.ini`.
- Sends data (latitude, longitude, RSRP, SINR) periodically.
- Processes incoming data to update settings.
- Uses threading to avoid conflicts with the serial port.
- Logs errors and status to the console.

## Requirements

- Python 3.6 or higher
- Libraries: `modbus-tk`, `pyserial`
- Hardware: NTN IoT device with Modbus RTU, serial port (e.g., `/dev/ttyAMA0`)
- OS: Linux (tested on Raspberry Pi)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/CREATIVE5-io/Hestia-iot-Python.git
   cd Hestia-iot-Python
   ```

2. Install libraries:
   ```
   pip install modbus-tk pyserial
   ```

3. Check serial port availability (e.g., `/dev/ttyAMA0`).

## Configuration

The script uses `config.ini` for settings. If it doesn't exist, defaults are created:

```
[NTN.IOT]
data_publish_interval = 300
mobile_device = 1
```

- `data_publish_interval`: Time between data sends (seconds).
- `mobile_device`: 1 for mobile (includes GPS), 0 for non-mobile.

Edit `config.ini` directly or update via incoming data.

## Usage

Run the script:
```
python ntn_iot.py --port /dev/ttyAMA0
```

- `--port`: Serial port (default: `/dev/ttyAMA0`).

The script:
- Connects to the NTN device with password `00000000`.
- Reads firmware version and IMSI.
- Sends data (e.g., GPS, RSRP) at set intervals.
- Checks for incoming data to update settings.
- Logs status and errors.

## Running as a Systemd Service

To run `ntn_iot.py` as a background service on Linux using systemd:

1. **Create the Service File**:
   Create a file named `ntn-iot.service` in `/etc/systemd/system/`:
   ```
   sudo nano /etc/systemd/system/ntn-iot.service
   ```
   Add the following content:
   ```
   [Unit]
   Description=C5 Hestia NTN-IOT service
   After=network.target

   [Service]
   ExecStartPre=/bin/sleep 1m
   ExecStart=/usr/bin/python3 /path/to/your-repo/ntn_iot.py --port /dev/ttyAMA0
   WorkingDirectory=/path/to/your-repo
   Restart=always
   User=your-username
   Environment=PYTHONUNBUFFERED=1

   [Install]
   WantedBy=multi-user.target
   ```
   Replace `/path/to/your-repo` with the full path to your repository and `your-username` with the user running the service.

2. **Enable and Start the Service**:
   ```
   sudo systemctl enable ntn-iot.service
   sudo systemctl start ntn-iot.service
   ```

3. **Check Service Status**:
   ```
   sudo systemctl status ntn-iot.service
   ```

4. **View Logs**:
   ```
   journalctl -u ntn-iot.service -f
   ```

5. **Stop or Restart the Service**:
   ```
   sudo systemctl stop ntn-iot.service
   sudo systemctl restart ntn-iot.service
   ```

## Modbus Registers

- `0x0000`: Password
- `0xEA6B`: Firmware version
- `0xEA71`: Device status
- `0xEB00`: IMSI
- `0xEB13`: SINR
- `0xEB15`: RSRP
- `0xEB1B`: Latitude
- `0xEB20`: Longitude
- `0xEC60`: Downlink data size
- `0xEC61`: Downlink data
- `0xC550`: Uplink data
- `0xF060`: Uplink response length
- `0xF061`: Uplink response

## Logging

Logs show connection status, data operations, and errors on the console. Edit the script to change log details.

## Troubleshooting

- **Serial Port**: Check port with `ls /dev/tty*`.
- **Modbus Errors**: Ensure device settings (baudrate: 115200, parity: none, stop bits: 1).
- **Config Issues**: Verify `config.ini` or reset defaults in the script.
- **Connection Fails**: Check device address (1) and password. Retries 3 times.

## License

MIT License. See LICENSE file.

## Contact

For help, open an issue or email info@creative5.io
