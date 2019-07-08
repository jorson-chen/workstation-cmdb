import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import datetime
import uuid
import jwt
import ConfigParser
import os
import logging
import concurrent.futures

logger = logging.getLogger(__name__)

MAX_THREADS = 14  # Get max number of threads for multi-threading
cylance_api = 'https://protectapi.cylance.com/'  # Base Cylance API
Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)),'Cylance_creds'))
cylance_client_id = Config.get('Settings', 'Cylance_Application_ID')
cylance_secret = Config.get('Settings', 'Cylance_Secret')
cylance_tenant_id = Config.get('Settings', 'Cylance_Tenant_ID')


# Generate session with max of 3 retries and interval of 60 second
def session_generator():
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=30)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# Create session token
'''
Output: Return session token
'''
def session_creation():
    logger.info('Creation session token to be used in Cylance')

    # Use epoch time in seconds
    session_time_start = int((datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)).total_seconds())
    session_time_end = int(
        (datetime.datetime.utcnow() + datetime.timedelta(minutes=30) - datetime.datetime(1970, 1, 1)).total_seconds())

    random_token = str(uuid.uuid4())
    auth_api = '%sauth/v2/token' % cylance_api
    data = {
        "exp": session_time_end,
        "iat": session_time_start,
        "iss": "http://cylance.com",
        "sub": cylance_client_id,
        "tid": cylance_tenant_id,
        "jti": random_token
    }

    payload = {'auth_token': jwt.encode(data, cylance_secret, algorithm='HS256').decode('utf8').replace("'", '"')}
    headers = {"Content-Type": "application/json; charset=utf-8"}
    session = session_generator()
    resp = session.post(auth_api, headers=headers, json=payload)
    if resp.ok:
        response = resp.json()
        if 'access_token' in response:
            return response['access_token']
    else:
        logger.error('Cylance Error %d:%s' % (resp.status_code, resp.text))
        return None


# Class to store device information
class cylance_devices:
    def __init__(self):
        self.name = None  # Not the host_name. Sometimes is not the same as the 1st part of hostname
        self.dns_name = None  # Device host name.
        self.id = None  # Device ID
        self.user = None
        self.os = None
        self.last_connected = None
        self.ip = []
        self.domain = None

    # Get information associated with device
    '''
    Output: Return username, os, hostname and last_connected associated with device ID
    '''
    def get_user_os_hostname_last_connected(self, access_token):
        device_api = '%sdevices/v2/%s' % (cylance_api, self.id)
        headers = {'Authorization': 'Bearer %s' % access_token, "Content-Type": "application/json; charset=utf-8"}
        resp = requests.get(device_api, headers=headers)
        if resp.ok:
            response = resp.json()

            if 'last_logged_in_user' in response and response['last_logged_in_user'] is not None and response['last_logged_in_user']:
                self.user = response['last_logged_in_user']
            self.os = response['os_version']
            self.dns_name = response['host_name']

            if response['state'] == 'Online':
               self.last_connected = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
            elif response['date_offline']:
                self.last_connected = datetime.datetime.strptime(response['date_offline'].split('.')[0], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
            else:
                if response['date_last_modified']:
                    self.last_connected = datetime.datetime.strptime(response['date_last_modified'].split('.')[0],
                                                                     '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
                elif response['date_first_registered']:
                    self.last_connected = datetime.datetime.strptime(response['date_first_registered'].split('.')[0],
                                                                     '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
            self.ip = response['ip_addresses']
        elif resp.status_code == 401:
            logger.warning('Cylance session token expired. Recreating cylance session.')
            access_token = session_creation()
            if access_token is not None:
                self.get_user_os_hostname_last_connected(access_token)
        else:
            logger.warning('Unable to fetch user info for device %s' % self.name)
            logger.error('Cylance Error %d:%s' % (resp.status_code, resp.text))
        return self


# Parse results from devices to only include workstations
def parse_device_results(device):
    '''
    Define which devices you want to take from the Cylance Policy
    '''
    if 'macOS' in device['policy']['name'] or 'Windows' in device['policy']['name'] or 'Default' in device['policy']['name']:
        deviceobj = cylance_devices()
        deviceobj.id = device['id']
        deviceobj.name = device['name']
        if 'DC' not in deviceobj.name.upper():
            return True, deviceobj
    return False, None


# Get all devices in Cylance
'''
Output: Fills up device into devices list
'''
def get_devices(access_token):
    page = 1
    devices = []
    logger.info("Fetching device list from Cylance")
    session = session_generator()
    while True:
        headers = {'Authorization': 'Bearer %s' % access_token, "Content-Type": "application/json; charset=utf-8"}
        device_api = '%sdevices/v2?page=%d&page_size=200' % (cylance_api, page)
        resp = session.get(device_api, headers=headers)
        if resp.ok:
            response = resp.json()
            total_pages = response['total_pages']
            if response['page_items']:
                with concurrent.futures.ProcessPoolExecutor() as executor:
                    for object_created, deviceobj in executor.map(parse_device_results, response['page_items']):
                        if object_created:
                            devices.append(deviceobj)

            page = page + 1
            if page > total_pages:
                break
        elif resp.status_code == 401:
            logger.warning('Cylance session token expired. Recreating cylance session.')
            access_token = session_creation()
        else:
            logger.critical('Unable to fetch device list from Cylance.')
            logger.error('Cylance Error %d:%s' % (resp.status_code, resp.text))
            break
    return access_token, devices


# Harmonize/Normalize device results
def modify_device_details(device):
    # Remove domain associated with the user
    if device.user is not None and '\\' in device.user:
        device.user = device.user.split('\\')[0]

    # Standardize os accross different security tools
    if "WIN" in device.os.upper():
        device.os = "Windows"
    elif "MAC" in device.os.upper():
        device.os = "Mac OS"

    # Normalize device names
    device.dns_name = device.dns_name.upper()
    device.name = device.name.upper()

    if 'CORP' in device.dns_name:
        device.domain = 'CORP'

    if '.' in device.name:
        device.name = device.name.split('.')[0]
    if '.' in device.dns_name:
        device.dns_name = device.dns_name.split('.')[0]

    if '-' in device.name and device.name != device.dns_name:
        device.name = device.dns_name

    if '(' in device.name and device.name != device.dns_name:
        device.name = device.dns_name
        if '-' in device.name:
            device.name = device.name.split('-')[0]

    if ' ' in device.name and device.name != device.dns_name:
        device.name = device.dns_name

    # Don't include IPV6
    device_ip = device.ip.copy()
    for ip in device.ip:
        if ':' in ip:
            device_ip.remove(ip)
    device.ip = device_ip

    return device


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


# Fetch all devices and populate missing device information
def get_device_details(access_token, devices):
    populated_devices = []
    # If the previous call failed for any reason, exit the program
    if devices:
        logger.info("Found %d devices in Cylance" % len(devices))
        logger.info("Populating user, os and zone information for %d devices" % len(devices))
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            for deviceobj in executor.map(lambda device: device.get_user_os_hostname_last_connected(access_token), devices):
                populated_devices.append(deviceobj)
    return populated_devices


# Fetch all non-duplicate devices that were last active in the past 30 days
def fetch_devices(since_days):
    modified_device_details = []
    access_token = session_creation()
    if access_token is None:
        return modified_device_details

    token, devices = get_devices(access_token)
    if token != access_token:
        access_token = token

    devices = get_device_details(access_token, devices)

    active_devices = []
    stale_devices = []

    for device in devices:
        if device.last_connected is not None:
            if (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - device.last_connected).days <= since_days:
                active_devices.append(device)
            else:
                stale_devices.append(device)
        else:
            stale_devices.append(device)

    logger.info("Total number of devices found: %d" % len(devices))
    if active_devices:
        logger.info("Total number of active devices found since %d days: %d" % (since_days, len(active_devices)))
        non_duplicate_active_devices = remove_duplicates(active_devices)
        logger.info(
            "Total number of non duplicate active devices found since %d days: %d" % (
            since_days, len(non_duplicate_active_devices)))
        logger.info('Modifying device details of non duplicate active devices')

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            for deviceobj in executor.map(modify_device_details, non_duplicate_active_devices):
                modified_device_details.append(deviceobj)

    return modified_device_details
