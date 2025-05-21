import argparse
import binascii
import configparser
import json
import logging
import modbus_tk
import modbus_tk.defines as cst
import modbus_tk.modbus_rtu as modbus_rtu
import os
import re
import serial
import struct
import sys
import threading
from time import sleep
from time import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

def parse_arguments():
    parser = argparse.ArgumentParser(description="NTN-IOT")
    parser.add_argument("--port", type=str, help="Specify port", default='/dev/ttyAMA0')
    return parser.parse_args()

g_args = parse_arguments()

""" Cretet theading lock to control modbus port access """
PORT_LOCK = threading.Lock()

update_interval = 300
mobile_device = 1

logger = modbus_tk.utils.create_logger('console')

class config_manager(ABC):
    """Abstract base class for managing configuration files."""
    def __init__(self, config_file: str):
        """Initialize with a config file path."""
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self._load_config()

    def _load_config(self):
        """Load the config file or apply defaults if it doesn't exist."""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self._apply_default_config()
            self._save_config()

    @abstractmethod
    def _get_default_config(self) -> Dict[str, Dict[str, str]]:
        """Return the default configuration for this manager."""
        pass

    @abstractmethod
    def _validate_default_config(self):
        """Validate the default configuration."""
        pass

    def _apply_default_config(self):
        """Apply the default configuration to the ConfigParser object."""
        for section, options in self._get_default_config().items():
            self.config[section] = options

    def _save_config(self):
        """Save the current configuration to the file."""
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)

    def get_value(self, section: str, key: str, fallback=None):
        """Get a value from the config with an optional fallback."""
        return self.config.get(section, key, fallback=fallback)

    def get_int(self, section: str, key: str, fallback: int = 0):
        """Get an integer value from the config with an optional fallback."""
        return self.config.getint(section, key, fallback=fallback)

    def get_boolean(self, section: str, key: str, fallback: bool = False):
        """Get a boolean value from the config with an optional fallback."""
        return self.config.getboolean(section, key, fallback=fallback)

    def get_float(self, section: str, key: str, fallback: float = 0.0):
        """Get a float value from the config with an optional fallback."""
        return self.config.getfloat(section, key, fallback=fallback)

    def set_value(self, section: str, key: str, value):
        """Set a value in the config and save it."""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = str(value)
        self._save_config()

    def get_sections(self):
        """Return a list of all sections in the config."""
        return self.config.sections()

    def get_options(self, section: str):
        """Return a list of all options in a section."""
        return self.config.options(section) if section in self.config else []

    def file_exists(self):
        """Check if the config file exists."""
        return os.path.exists(self.config_file)

    def reset_to_default(self):
        """Reset the configuration to the default and save it."""
        self.config.clear()
        self._apply_default_config()
        self._save_config()
        
class master_config_manager(config_manager):
    def _get_default_config(self) -> Dict[str, Dict[str, str]]:
        """Return the default configuration for config.ini."""
        return {
            'NTN.IOT': {
                'data_publish_interval': '300',
                'mobile_device': '1',
            }
        }

    def _validate_default_config(self):
        """Validate the default configuration for config.ini."""
        default_config = self._get_default_config()
        required_section = 'NTN.IOT'
        required_keys = ['data_publish_interval', 'mobile_device']

        if required_section not in default_config:
            raise ValueError(f"Default config missing required section: {required_section}")
        for key in required_keys:
            if key not in default_config[required_section]:
                raise ValueError(f"Default config missing required key '{key}' in section '{required_section}'")

master_manager = master_config_manager('config.ini')

class ntn_modbus_master():
    def __init__(self, slaveAddress, port, baudrate=115200, bytesize=8, parity='N', stopbits=1, xonxoff=0):
        try:
            self.master = modbus_rtu.RtuMaster(serial.Serial(port = port, baudrate = baudrate, bytesize = bytesize, parity = parity, stopbits = stopbits, xonxoff = xonxoff))
            self.master.set_timeout(1)
            self.master.set_verbose(False)
            self.slaveAddr = slaveAddress
            logger.info('NTN dongle init!')
        except modbus_tk.modbus.ModbusError as e:
            logger.error(f'{e} - Code={e.get_exception_code()}')
            raise (e)

    def read_register(self, reg, functioncode=cst.READ_INPUT_REGISTERS):
        try:
            value=self.master.execute(self.slaveAddr, functioncode, reg, 1)
            return value[0]
        except Exception as e:
            logger.info(e)
            return None

    def read_registers(self, reg, num, functioncode=cst.READ_INPUT_REGISTERS):
        try:
            values = self.master.execute(self.slaveAddr, functioncode, reg, num)
            return values
        except Exception as e:
            logger.info(e)
            return None

    def set_registers(self, reg, val):
        try:
            if val != None:
                value = self.master.execute(self.slaveAddr, cst.WRITE_MULTIPLE_REGISTERS, reg, output_value=val)
                return True
            else:
                return False
        except Exception as e:
            logger.info(e)
            return False

def modbus_data_to_string(modbus_data):
    try:
        """ int => byte """
        byte_data = b''.join(struct.pack('>H', value) for value in modbus_data)
        """ byte => str """
        result_str = byte_data.decode('utf-8')
        return result_str
    except (UnicodeDecodeError, struct.error) as e:
        logger.error(f"Error decoding Modbus data: {e}")
        return None

def bytes_to_integers(byte_list):
    """ Convert each 2-byte string to an integer """
    logger.info(f'byte_list: {byte_list}')
    return [int.from_bytes(b, byteorder='big') for b in byte_list]

def bytes_to_list_with_padding(data):
    """ Split the data into 2-byte chunks """
    chunks = [data[i:i+2] for i in range(0, len(data), 2)]
    """ Pad the last chunk with a zero byte if needed """
    chunks[-1] = chunks[-1].ljust(2, b'0')
    return bytes_to_integers(chunks)

def dl_read(ntn_dongle):
    while True:
        try:
            data_len = 0
            PORT_LOCK.acquire()
            # Check Downlink Data Size
            data_len = ntn_dongle.read_register(0xEC60)
            PORT_LOCK.release()
            if data_len:
                logger.info(f'Downlink data length: {data_len}')
                PORT_LOCK.acquire()
                # Read Downlink Data
                dl_resp = ntn_dongle.read_registers(0xEC61, data_len)
                PORT_LOCK.release()
                logger.info(f'Downlink data response: {dl_resp}')
                dl_data = b''.join(struct.pack('>H', v) for v in dl_resp)
                dl_data = json.loads(binascii.unhexlify(dl_data).decode('utf-8'))
                logger.info(f'Downlink data: {dl_data}')
                message_process(dl_data)
            else:
                #logger.debug(f'Downlink data length: {data_len}')
                sleep(1)
        except Exception as e:
            logger.error(f"Error in downlink_modbus: {e}")
            sleep(1)

def message_process(payload):
    global mobile_device
    global update_interval

    data = payload.get('data', None)
    if data and isinstance(data, dict):
        if 'timeperiods' in data:
            timeperiods = data.get('timeperiods', None)
            logger.debug(f'timeperiods: {timeperiods}')
            update_interval = timeperiods
            master_manager.set_value('NTN.IOT', 'data_publish_interval', timeperiods)
        elif 'gpstype' in data:
            gpstype = data.get('gpstype')
            logger.debug(f'gpstype: {gpstype}')
            mobile_device = gpstype
            master_manager.set_value('NTN.IOT', 'mobile_device', gpstype)

def data_publisher(ntn_dongle):
    global mobile_device
    global update_interval

    while True:
        try:
            attempts = 0
            """ check NTN dongle status """ 
            while True:
                with PORT_LOCK:
                    # NTN module status
                    ntn_status = ntn_dongle.read_register(0xEA71)
                if ntn_status:
                    module_at_ready = ntn_status & 0x01
                    downlink_ready = (ntn_status & 0x02) >> 1
                    sim_ready = (ntn_status & 0x04) >> 2
                    network_registered = (ntn_status & 0x08) >> 3

                    logger.info('=== NTN dongle status ===')
                    logger.info(f'module_at_ready: {module_at_ready}')
                    logger.info(f'downlink_ready: {downlink_ready}')
                    logger.info(f'sim_ready: {sim_ready}')
                    logger.info(f'network_registered: {network_registered}')
                    if ntn_status == 0xF:
                        break
                if attempts >= 10:
                    break
                attempts+=1
                sleep(3)

            if ntn_status == 0xF:
                d_list = []
                """ Latitude """
                with PORT_LOCK:
                    lat_val = ntn_dongle.read_registers(0xEB1B, 5)
                if lat_val:
                    lat = modbus_data_to_string(lat_val)
                    d_list.append(lat)
                    logger.info(f'Latitude: {lat}')
                """ Longtitude """
                with PORT_LOCK:
                    longi_val = ntn_dongle.read_registers(0xEB20, 5)
                if longi_val:
                    longi = modbus_data_to_string(longi_val)
                    d_list.append(longi)
                    logger.info(f'Longitude: {longi}')
                """ RSRP """
                with PORT_LOCK:
                    rsrp_val = ntn_dongle.read_registers(0xEB15, 2)
                if rsrp_val:
                    rsrp = modbus_data_to_string(rsrp_val)
                    d_list.append(rsrp)
                    logger.info(f'RSRP: {rsrp}')
                """ SINR """
                with PORT_LOCK:
                    sinr_val = ntn_dongle.read_registers(0xEB13, 2)
                if sinr_val:
                    sinr = modbus_data_to_string(sinr_val)
                    d_list.append(sinr)
                    logger.info(f'SINR: {sinr}')
                
                if len(d_list) == 4:
                    if mobile_device:
                        d_payload = {'m':d_list}
                    else:
                        d_list.pop(0)
                        d_list.pop(0)
                        d_payload = {'c':d_list}

                    d_bytes = json.dumps(d_payload).encode('utf-8')
                    logger.info(f'd_bytes: {d_bytes}')
                    d_hex  = binascii.hexlify(d_bytes)
                    logger.info(f'packet: {d_hex}')

                    modbus_data = bytes_to_list_with_padding(d_hex)
                    """ add "\r\n" in the end of data """
                    modbus_data.extend([3338])
                    logger.info(f'modbus data: {modbus_data}')

                    with PORT_LOCK:
                        """ Data send """
                        response = ntn_dongle.set_registers(0xC550, modbus_data)
                    logger.info(f'response: {response}')
                    if response:
                        while True:
                            with PORT_LOCK:
                                # check response length
                                data_len = ntn_dongle.read_register(0xF060)
                            if data_len:
                                logger.info(f'reply data len: {data_len}')
                                """ read uplink response """
                                with PORT_LOCK:
                                    # read response data
                                    data_resp = ntn_dongle.read_registers(0xF061, data_len)
                                    logger.info(f'responsed data: {data_resp}')
                                if data_resp:
                                    uplink_resp = modbus_data_to_string(data_resp)
                                    logger.info(f'Uplink response: {uplink_resp}')
                                    if 'Uplink Completed' in uplink_resp:
                                        logger.info('Uplink Success!')
                                break
                            else:
                                sleep(1)
            else:
                logger.info('Network is not registered')
        except Exception as e:
            logger.error(f'{e} - Code={e}')
        sleep(update_interval)

def main():
    NTN_DONGLE_ADDR = 1
    global update_interval
    global mobile_device
    
    update_interval = master_manager.get_int('NTN.IOT', 'data_publish_interval')
    logger.info(f'update_interval: {update_interval}')
    mobile_device = master_manager.get_int('NTN.IOT', 'mobile_device')
    logger.info(f'mobile_device: {mobile_device}')

    """ NTN Modbus slave mode Initial """
    attempts = 0
    while True:
        try:
            ntn_dongle = ntn_modbus_master(NTN_DONGLE_ADDR, port = g_args.port, baudrate=115200)
            
            DEFAULT_PASSWD = '00000000'
            passwd = []
            for i in range(0, len(DEFAULT_PASSWD), 2):
                passwd.append(int(DEFAULT_PASSWD[i:i+2]))
            logger.info(f'password: {passwd}')
            valid_passwd = ntn_dongle.set_registers(0x0000, passwd)
            if not valid_passwd:
                if attempts >= 3:
                    raise ValueError('Not a valid password')
                attempts+=1
                continue
            
            """ FW version """
            fw_ver_val = ntn_dongle.read_registers(0xEA6B, 2)
            if fw_ver_val:
                logger.info(f'FW ver: {modbus_data_to_string(fw_ver_val)}')
                
            imsi_val = ntn_dongle.read_registers(0xEB00, 8)
            if imsi_val:
                imsi = modbus_data_to_string(imsi_val)

            if not imsi:
                if attempts >= 3:
                    raise ValueError('Invalid IMSI')
            else:
                logger.info(f'IMSI: {imsi}')
                break
        except Exception as e:
            logger.error(f'ERROR: {e}')
            sys.exit(1)
        
    try:
        dl_thread = threading.Thread(target = dl_read, args = (ntn_dongle,))
        dl_thread.start()
        publish_thread = threading.Thread(target = data_publisher, args = (ntn_dongle,))
        publish_thread.start()
    except Exception as e:
        logger.error(f'{e} - Code={e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
