import requests
import datetime
import logging
import os
import ConfigParser
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
import xml.etree.ElementTree as etree

logger = logging.getLogger(__name__)

Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'Security_agent_creds'))
jamf_user = Config.get('Settings', 'Jamf_User')
jamf_password = Config.get('Settings', 'Jamf_password')
jamf_api = Config.get('Settings', 'JAMF_API')

MAX_THREADS = 14  # Get max number of threads for multi-threading


# A class to hold Mac devices
class Jamf:
    def __init__(self):
        self.id = None
        self.name = None
        self.last_connected = None
        self.user = []
        self.serial_number = None
        self.location = None
        self.mac_address = None
        self.ip = None
        self.encrypted = False
        self.domain = None

    # Get device details from their id
    def get_device_details(self):
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        headers = {"Content-Type": "application/xml; charset=utf-8", "Accept": "application/xml"}
        resp = requests.get('%s/computers/id/%s' % (jamf_api, self.id), headers=headers, auth=(jamf_user, jamf_password), verify=False)
        if resp.ok:
            response = etree.fromstring(resp.content)
            self.location = response.findtext('./location/building')

            self.serial_number = response.findtext('./general/serial_number')
            self.mac_address = response.findtext('./general/mac_address')
            last_connected = response.find('./general/last_contact_time_epoch')
            self.ip = response.findtext('./general/last_reported_ip')
            self.domain = response.findtext('./hardware/active_directory_status')

            for device in response.findall("./hardware/storage/device/partition[type='boot']"):
                if (device.find('filevault_status').text == 'Encrypted' and device.find('filevault_percent').text == '100') or (device.find('filevault2_status').text == 'Encrypted' and device.find('filevault2_percent').text == '100'):
                    self.encrypted = True

            for username in response.findall("./extension_attributes//extension_attribute[name='Logged in User']"):
                self.user.append(username.findtext('value'))

            for username in response.findall("./extension_attributes//extension_attribute[name='Currently Logged In User']"):
                self.user.append(username.findtext('value'))
            '''
            for username in response.findall("./extension_attributes//extension_attribute[name='Admin Users']"):
                self.user.append(username.findtext('value'))
            '''
            response.clear()

            if etree.iselement(last_connected) and last_connected.text is not None:
                self.last_connected = datetime.datetime.utcfromtimestamp(int(last_connected.text)/1000).replace(tzinfo=datetime.timezone.utc)

            self.user = list(set(self.user))

            if self.domain is not None and 'CORP' in self.domain.upper():
                self.domain = 'CORP'
            else:
                self.domain = None
        else:
            logger.error("Unable to get device details from JAMF for device %s with id %s" % (self.name, self.id))
        return self

    def print(self):
        print(self.id)
        print(self.name)
        print(self.last_connected)
        print(self.user)
        print(self.serial_number)
        print(self.location)
        print(self.mac_address)
        print(self.ip)
        print(self.encrypted)
        print(self.domain)
        print()


# Parse result from all devices in JAMF to create new device objects
def parse_devices_result(computer):
    jamfobj = Jamf()
    # Get device name
    jamfobj.name = computer['name'].upper()
    if 'MACBOOK' in jamfobj.name:
        jamfobj.name = jamfobj.name.replace(' ', '-').replace('(', '')
    if ' (' in computer['name']:
        jamfobj.name = computer['name'].split(' (')[0].upper()

    if ' ' in computer['name']:
        if computer['name'].split(' ')[0].isalpha() and len(computer['name'].split(' ')) < 4:
            jamfobj.name = computer['name'].replace(' ', '-')

    jamfobj.name = jamfobj.name.replace('\'', '').upper()

    # Get device id
    jamfobj.id = computer['id']
    return jamfobj


'''
    Get the devices names and ids.
'''
# Getting all Mac devices from JAMF
def get_devices():
    devices = []
    logger.info("Getting all Mac devices from JAMF")
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json"}
    resp = requests.get('%s/computers' % jamf_api, headers=headers, auth=(jamf_user, jamf_password), verify=False)
    if resp.ok:
        response = resp.json()
        with concurrent.futures.ProcessPoolExecutor() as executor:
            for jamfobj in executor.map(parse_devices_result, response['computers']):
                devices.append(jamfobj)
    else:
        logger.error('JAMF Error %d:%s', resp.status_code, resp.text)
    return devices


# Fill in device details of each device and filter devices based on last activity
def populate_device_details(devices, since_days):
    active_devices = []
    stale_devices = []

    populated_devices = []
    logger.info("Populating device info")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for deviceobj in executor.map(lambda device: device.get_device_details(), devices):
            populated_devices.append(deviceobj)

    logger.info("Filtering devices")
    for device in populated_devices:
        if device.last_connected is not None:
            if (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - device.last_connected).days <= since_days:
                active_devices.append(device)
            else:
                stale_devices.append(device)
        else:
            stale_devices.append(device)

    return active_devices, stale_devices


# Remove duplicate from device list
def remove_duplicates(workstations):
    logger.info('Removing duplicate devices')
    devices = {}
    non_duplicate_devices = []

    # Get dict of all devices with same name
    for device in workstations:
        if device.name in devices:
            devices[device.name].append(device)
        else:
            devices[device.name] = [device]

    for device_name in devices:
        # Ignore if a single device is mapped to a name
        if len(devices[device_name]) > 1:

            # Filter based on last online date
            devices_last_online_dates = {device: device.last_connected for device in devices[device_name]}
            last_online_dates = [devices_last_online_dates[device] for device in devices_last_online_dates]

            if last_online_dates[0] > last_online_dates[1]:
                most_recent_online_date = last_online_dates[0]
            else:
                most_recent_online_date = last_online_dates[1]

            if len(last_online_dates) > 2:
                for index in range(2, len(last_online_dates)):
                    if last_online_dates[index] > most_recent_online_date:
                        most_recent_online_date = last_online_dates[index]

            # Get device associated with most_recent_online_date
            for device in devices_last_online_dates:
                if devices_last_online_dates[device] == most_recent_online_date:
                    non_duplicate_devices.append(device)
                    break
        else:
            non_duplicate_devices.extend(devices[device_name])

    return non_duplicate_devices


# Get all non duplicate macs that were active in the last 30 days
def fetch_devices(since_days):
    non_duplicate_active_devices = []
    devices = get_devices()

    if devices:
        logger.info("Total number of devices found: %d" % len(devices))
        active_devices, stale_devices = populate_device_details(devices, since_days)
        if active_devices:
            logger.info("Total number of active devices found since %d days: %d" % (since_days, len(active_devices)))
            non_duplicate_active_devices = remove_duplicates(active_devices)
            if non_duplicate_active_devices:
                logger.info(
                    "Total number of non duplicate active devices found since %d days: %d" % (
                    since_days, len(non_duplicate_active_devices)))

    return non_duplicate_active_devices
