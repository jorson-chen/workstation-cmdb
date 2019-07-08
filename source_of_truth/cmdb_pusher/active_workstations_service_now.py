import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import concurrent.futures
import logging
import os
import ConfigParser
import datetime

logger = logging.getLogger(__name__)

MAX_THREADS = 14

Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'Service_Now_creds'))
snow_user = Config.get('Settings', 'Computer_Table_User')
snow_password = Config.get('Settings', 'Computer_Table_Secret')
service_now_computer_table = Config.get('Settings', 'API')
app_name = Config.get('Settings', 'Application_Name')


# Generate session with max of 3 retries and interval of 1 second
def session_generator():
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# Class to define and work on the fields from the Computers cmdb table
class active_workstations:
    def __init__(self):
        self.id = None
        self.name = ""
        self.user = ""
        self.os = ""
        self.last_connected = ""
        self.internal_ip = ""
        self.external_ip = ""
        self.location = ""
        self.last_scanned = ""
        self.tenable_present = ""
        self.cylance_present = ""
        self.crowdstrike_present = ""
        self.jamf_present = ""
        self.discovery_source = ""
        self.asset_link = ""
        self.created_on = ""
        self.serial_number = ""
        self.encrypted = ""
        self.domain = ""
        self.mac_address = ""

    def convert_to_dict(self):
        workstation = {}
        workstation['id'] = self.id
        workstation['name'] = self.name
        workstation['user'] = self.user
        workstation['os'] = self.os
        workstation['last_connected'] = self.last_connected
        workstation['ip_address'] = self.internal_ip
        workstation['u_external_ip_addresses'] = self.external_ip
        workstation['location'] = self.location
        workstation['last_scanned'] = self.last_scanned
        workstation['tenable_present'] = self.tenable_present
        workstation['cylance_present'] = self.cylance_present
        workstation['crowdstrike_present'] = self.crowdstrike_present
        workstation['jamf_present'] = self.jamf_present
        workstation['discovery_source'] = self.discovery_source
        workstation['asset link'] = self.asset_link
        return workstation


# Parse response for each device from Computers
def parse_asset_results(asset):
    workstationobj = active_workstations()
    if not asset['asset_tag']:
        logger.critical('Asset Tag is empty for sys id: %s' % asset['sys_id'])
        exit(-1)
    workstationobj.id = asset['sys_id']
    workstationobj.name = asset['asset_tag']
    workstationobj.user = asset['u_usernames']
    workstationobj.os = asset['os']
    workstationobj.last_connected = asset['last_discovered']
    workstationobj.internal_ip = asset['ip_address']
    workstationobj.external_ip = asset['u_external_ip_addresses']
    workstationobj.location = asset['u_office']
    workstationobj.last_scanned = asset['u_last_scanned_in_tenable']
    workstationobj.tenable_present = asset['u_present_in_tenable']
    workstationobj.cylance_present = asset['u_present_in_cylance']
    workstationobj.crowdstrike_present = asset['u_present_in_crowdstrike']
    workstationobj.jamf_present = asset['u_present_in_jamf']
    workstationobj.discovery_source = asset['discovery_source']
    workstationobj.created_on = asset['sys_created_on']
    workstationobj.asset_link = asset['asset']
    workstationobj.serial_number = asset['serial_number']
    workstationobj.encrypted = asset['u_encrypted']
    workstationobj.domain = asset['u_ad_domain']
    workstationobj.mac_address = asset['mac_address']
    return workstationobj


# A hack to get the total number of devices
def get_assets_total():
    logger.info('Fetching total number of assets from Snow')
    total = 0
    headers = {"Accept": "application/json", "Content-Type": "application/json;charset=UTF-8"}
    # Fetch only 1 device
    params = {"sysparm_limit": '1',
              'sysparm_query': 'asset_tagISNOTEMPTY^install_statusNOT IN9,7,8',
              'sysparm_fields': 'sys_id,asset_tag,u_usernames,os,last_discovered,ip_address,u_office,u_last_scanned_in_tenable,u_present_in_crowdstrike,u_present_in_jamf,u_present_in_cylance,u_present_in_tenable,discovery_source,u_external_ip_addresses,asset,u_encrypted,mac_address,u_ad_domain,sys_created_on,serial_number'}

    session = session_generator()
    resp = session.get(service_now_computer_table, auth=(snow_user, snow_password), headers=headers, params=params)
    if resp.ok:
        total = resp.headers['X-Total-Count']
    else:
        logger.error('Unable to make the api call to fetch 1 device details')
        logger.error('Snow Error %d:%s', resp.status_code, resp.text)
    return total


# Get all devices from Computers
def get_all_assets(total_count):
    assets = []
    logger.info('Fetching devices from Snow')
    offsets = [offset for offset in range(0, int(total_count), 10000)]
    for offset in offsets:
        headers = {"Accept": "application/json", "Content-Type": "application/json;charset=UTF-8"}
        # Asset is not stolen, retired or lost
        params = {'sysparm_offset': str(offset),
                  'sysparm_limit': '10000',
                  'sysparm_query': 'asset_tagISNOTEMPTY^install_statusNOT IN9,7,8',
                  'sysparm_fields': 'sys_id,asset_tag,u_usernames,os,last_discovered,ip_address,u_office,u_last_scanned_in_tenable,u_present_in_crowdstrike,u_present_in_jamf,u_present_in_cylance,u_present_in_tenable,discovery_source,u_external_ip_addresses,u_encrypted,mac_address,u_ad_domain,asset,sys_created_on,serial_number'}

        session = session_generator()
        resp = session.get(service_now_computer_table, auth=(snow_user, snow_password), headers=headers, params=params)
        if resp.ok:
            response = resp.json()
            if response['result']:
                # Perform multi-threading to parse each device details
                logger.info('Populating device details')
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    for deviceobj in executor.map(parse_asset_results, response['result']):
                        assets.append(deviceobj)
            else:
                logger.info('No devices found in the table.')
        else:
            logger.error('Snow Error %d:%s', resp.status_code, resp.text)
    return assets


# Covert obj into dict for API consumption
def convert_object_to_dict(asset, new_record=False):
    asset_json = {}
    asset_json['asset_tag'] = asset.name
    asset_json['name'] = asset.name
    if asset.user:
        asset_json['u_usernames'] = asset.user
    asset_json['os'] = asset.os
    if asset.last_connected is not None:
        asset_json['last_discovered'] = asset.last_connected
    if asset.last_scanned is not None:
        asset_json['u_last_scanned_in_tenable'] = asset.last_scanned
    if asset.internal_ip:
        asset_json['ip_address'] = asset.internal_ip
    if asset.external_ip:
        asset_json['u_external_ip_addresses'] = asset.external_ip
    if asset.location:
        asset_json['u_office'] = asset.location
    asset_json['u_present_in_tenable'] = asset.tenable_present
    asset_json['u_present_in_cylance'] = asset.cylance_present
    asset_json['u_present_in_crowdstrike'] = asset.crowdstrike_present
    asset_json['u_present_in_jamf'] = asset.jamf_present
    asset_json['u_encrypted'] = asset.encrypted
    asset_json['u_ad_domain'] = asset.domain
    asset_json['mac_address'] = asset.mac_address
    if new_record:
        asset_json['sys_created_on'] = datetime.datetime.now().isoformat().split('.')[0].replace('T', ' ')
    asset_json['discovery_source'] = app_name
    asset_json['sys_updated_on'] = datetime.datetime.now().isoformat().split('.')[0].replace('T', ' ')

    return asset_json


# Add new record/row into the Computers table
def insert_asset_data(asset):
    headers = {"Accept": "application/json", "Content-Type": "application/json;charset=UTF-8"}
    data = convert_object_to_dict(asset, new_record=True)
    session = session_generator()
    resp = session.post(service_now_computer_table, auth=(snow_user, snow_password), headers=headers, json=data)
    if not resp.ok:
        logger.error('Snow Error %d:%s', resp.status_code, resp.text)


# Update existing record into the Computer table
def update_asset_data(asset):
    headers = {"Accept": "application/json", "Content-Type": "application/json;charset=UTF-8"}
    assets_table_api = '%s/%s' % (service_now_computer_table, asset.id)
    data = convert_object_to_dict(asset)
    session = session_generator()
    resp = session.patch(assets_table_api, auth=(snow_user, snow_password), headers=headers, json=data)
    if not resp.ok:
        logger.error('Snow Error %d:%s', resp.status_code, resp.text)


# Mark multiple additional assets with same name as duplicate
def mark_asset_as_duplicate(asset):
    headers = {"Accept": "application/json", "Content-Type": "application/json;charset=UTF-8"}
    params = {'sysparm_fields': 'discovery_source'}
    data = {'discovery_source': 'Duplicate',
            'sys_updated_on': datetime.datetime.now().isoformat().split('.')[0].replace('T', ' ')}
    assets_table_api = '%s/%s' % (service_now_computer_table, asset.id)
    session = session_generator()
    resp = session.patch(assets_table_api, auth=(snow_user, snow_password), headers=headers, params=params, json=data)
    if not resp.ok:
        logger.error('Snow Error %d:%s', resp.status_code, resp.text)
    else:
        response = resp.json()
        if response['result']['discovery_source'] != 'Duplicate':
            logger.warning('Unable to mark asset %s with id %s as Duplicate' % (asset.name, asset.id))


# Mark asset as non duplicate
def mark_asset_as_non_duplicate(asset):
    headers = {"Accept": "application/json", "Content-Type": "application/json;charset=UTF-8"}
    params = {'sysparm_fields': 'discovery_source'}
    data = {'discovery_source': app_name, 'sys_updated_on': datetime.datetime.now().isoformat().split('.')[0].replace('T', ' ')}
    assets_table_api = '%s/%s' % (service_now_computer_table, asset.id)
    session = session_generator()
    resp = session.patch(assets_table_api, auth=(snow_user, snow_password), headers=headers, params=params, json=data)
    if not resp.ok:
        logger.error('Snow Error %d:%s', resp.status_code, resp.text)
    else:
        response = resp.json()
        if response['result']['discovery_source'] != app_name:
            logger.warning('Unable to mark asset %s with id %s as Duplicate' % (asset.name, asset.id))


# Filter into duplicate and non-duplicate workstations/assets for Macs
def filter_duplicates_non_duplicates_macs(workstations, jamf_devices_with_serial_numbers):

    '''
        Filter based on the below criteria
        (1) asset link
        (2) which ones have a serial number matching from JAMF
        (3) which ones have serial number
        (4) oldest record
    '''

    duplicate_devices = []
    non_duplicate_devices = []
    devices = {}

    # Get dict of all devices with same name
    for device in workstations:
        if device.name in devices:
            devices[device.name].append(device)
        else:
            devices[device.name] = [device]

    for device_name in devices:
        # Ignore if a single device is mapped to a name
        if len(devices[device_name]) > 1:
            # Get all devices with Asset attached to CI
            devices_with_asset_link = [device for device in devices[device_name] if device.asset_link]
            # If only device has Asset attached to it, that is a non duplicate device
            if len(devices_with_asset_link) == 1:
                non_duplicate_device_id = devices_with_asset_link[0].id
                non_duplicate_devices.append(devices_with_asset_link[0])
            else:
                non_duplicate_device_id = ""
                devices_with_creation_dates = {}
                if devices_with_asset_link:
                    leftover_device_list = devices_with_asset_link
                else:
                    leftover_device_list = devices[device_name]

                # Check for serial numbers associated
                devices_with_serial_number = [device for device in leftover_device_list if device.serial_number]
                if len(devices_with_serial_number) == 1:
                    non_duplicate_device_id = devices_with_serial_number[0].id
                    non_duplicate_devices.append(devices_with_serial_number[0])
                elif len(devices_with_serial_number) > 1:
                    # Check serial number of Mac's and match with JAMF
                    mac_devices_with_serial_numbers = [device for device in devices_with_serial_number if 'mac' in device.os.lower() and device.name in jamf_devices_with_serial_numbers and jamf_devices_with_serial_numbers[device.name] == device.serial_number]
                    if len(mac_devices_with_serial_numbers) == 1:
                        non_duplicate_device_id = mac_devices_with_serial_numbers[0].id
                        non_duplicate_devices.append(mac_devices_with_serial_numbers[0])
                    else:
                        # Else sort by creation date of the CI
                        if len(mac_devices_with_serial_numbers) > 1:
                            devices_with_creation_dates = {device: device.created_on for device in mac_devices_with_serial_numbers}
                        else:
                            devices_with_creation_dates = {device: device.created_on for device in
                                                           devices_with_serial_number}
                else:
                    # Else sort by creation date of the CI
                    devices_with_creation_dates = {device: device.created_on for device in leftover_device_list}

                if devices_with_creation_dates:
                    # Get the least creation date from all devices in devices_with_creation_dates
                    creation_dates = [devices_with_creation_dates[device] for device in devices_with_creation_dates]
                    if datetime.datetime.strptime(creation_dates[0], '%Y-%m-%d %H:%M:%S') < datetime.datetime.strptime(creation_dates[1], '%Y-%m-%d %H:%M:%S'):
                        oldest_creation_date = creation_dates[0]
                    else:
                        oldest_creation_date = creation_dates[1]

                    if len(creation_dates) > 2:
                        for index in range(2, len(creation_dates)):
                            if datetime.datetime.strptime(creation_dates[index], '%Y-%m-%d %H:%M:%S') < datetime.datetime.strptime(oldest_creation_date, '%Y-%m-%d %H:%M:%S'):
                                oldest_creation_date = creation_dates[index]

                    # Get device associated with oldest_creation_date
                    for device in devices_with_creation_dates:
                        if devices_with_creation_dates[device] == oldest_creation_date:
                            non_duplicate_device_id = device.id
                            non_duplicate_devices.append(device)
                            break

            if non_duplicate_device_id:
                duplicate_devices.extend([device for device in devices[device_name] if device.id != non_duplicate_device_id])
        else:
            non_duplicate_devices.extend(devices[device_name])

    return duplicate_devices, non_duplicate_devices


# Filter into duplicate and non-duplicate workstations/assets for Windows
def filter_duplicates_non_duplicates_windows(workstations):

    '''
        Filter based on the below criteria
        (1) asset link
        (2) which ones have serial number
        (3) oldest record
    '''

    duplicate_devices = []
    non_duplicate_devices = []
    devices = {}

    # Get dict of all devices with same name
    for device in workstations:
        if device.name in devices:
            devices[device.name].append(device)
        else:
            devices[device.name] = [device]

    for device_name in devices:
        # Ignore if a single device is mapped to a name
        if len(devices[device_name]) > 1:
            # Get all devices with Asset attached to CI
            devices_with_asset_link = [device for device in devices[device_name] if device.asset_link]
            # If only device has Asset attached to it, that is a non duplicate device
            if len(devices_with_asset_link) == 1:
                non_duplicate_device_id = devices_with_asset_link[0].id
                non_duplicate_devices.append(devices_with_asset_link[0])
            else:
                non_duplicate_device_id = ""
                devices_with_creation_dates = {}
                if devices_with_asset_link:
                    leftover_device_list = devices_with_asset_link
                else:
                    leftover_device_list = devices[device_name]

                # Check for serial numbers associated
                devices_with_serial_number = [device for device in leftover_device_list if device.serial_number]
                if len(devices_with_serial_number) == 1:
                    non_duplicate_device_id = devices_with_serial_number[0].id
                    non_duplicate_devices.append(devices_with_serial_number[0])
                elif len(devices_with_serial_number) > 1:
                    devices_with_creation_dates = {device: device.created_on for device in devices_with_serial_number}
                else:
                    # Else sort by creation date of the CI
                    devices_with_creation_dates = {device: device.created_on for device in leftover_device_list}

                if devices_with_creation_dates:
                    # Get the least creation date from all devices in devices_with_creation_dates
                    creation_dates = [devices_with_creation_dates[device] for device in devices_with_creation_dates]
                    if datetime.datetime.strptime(creation_dates[0], '%Y-%m-%d %H:%M:%S') < datetime.datetime.strptime(creation_dates[1], '%Y-%m-%d %H:%M:%S'):
                        oldest_creation_date = creation_dates[0]
                    else:
                        oldest_creation_date = creation_dates[1]

                    if len(creation_dates) > 2:
                        for index in range(2, len(creation_dates)):
                            if datetime.datetime.strptime(creation_dates[index], '%Y-%m-%d %H:%M:%S') < datetime.datetime.strptime(oldest_creation_date, '%Y-%m-%d %H:%M:%S'):
                                oldest_creation_date = creation_dates[index]

                    # Get device associated with oldest_creation_date
                    for device in devices_with_creation_dates:
                        if devices_with_creation_dates[device] == oldest_creation_date:
                            non_duplicate_device_id = device.id
                            non_duplicate_devices.append(device)
                            break

            if non_duplicate_device_id:
                duplicate_devices.extend([device for device in devices[device_name] if device.id != non_duplicate_device_id])
        else:
            non_duplicate_devices.extend(devices[device_name])

    return duplicate_devices, non_duplicate_devices


# Fetch assets that have no duplicates from the computer table
def fetch_categorized_workstations(total_count, jamf_devices_with_serial_numbers):
    workstations = get_all_assets(total_count)

    mac_workstations = [workstation for workstation in workstations if 'mac' in workstation.os.lower()]
    windows_workstations = [workstation for workstation in workstations if 'wind' in workstation.os.lower() and workstation.discovery_source != 'Duplicate']

    mac_duplicates, mac_non_duplicates = filter_duplicates_non_duplicates_macs(mac_workstations, jamf_devices_with_serial_numbers)
    logger.info('Found additional %d duplicates and %d non-duplicate workstations for Macs' % (len(mac_duplicates), len(mac_non_duplicates)))

    windows_duplicates, windows_non_duplicates = filter_duplicates_non_duplicates_windows(windows_workstations)
    logger.info('Found additional %d duplicates and %d non-duplicate workstations for Windows' % (len(windows_duplicates), len(windows_non_duplicates)))

    mac_duplicate_workstations_without_duplicate_tag = [device for device in mac_duplicates if
                                                    device.discovery_source != 'Duplicate']
    mac_non_duplicate_workstations_with_duplicate_tag = [device for device in mac_non_duplicates if
                                                     device.discovery_source == 'Duplicate']

    # Deal with duplicates in the Computer table
    logger.info('Marking %d duplicate mac workstations as duplicate' % len(mac_duplicate_workstations_without_duplicate_tag))
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for device in mac_duplicate_workstations_without_duplicate_tag:
            executor.submit(mark_asset_as_duplicate, device)

    # Deal with non duplicates in the Computer table
    logger.info(
        'Marking %d non duplicate mac workstations as non_duplicate' % len(mac_non_duplicate_workstations_with_duplicate_tag))
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for device in mac_non_duplicate_workstations_with_duplicate_tag:
            executor.submit(mark_asset_as_non_duplicate, device)

    # Deal with duplicates in the Computer table
    logger.info('Marking %d duplicate windows workstations as duplicate' % len(windows_duplicates))
    for device in windows_duplicates:
        mark_asset_as_duplicate(device)

    non_duplicates = mac_non_duplicates + windows_non_duplicates

    # Convert the assets into a dict form
    assets = {workstation.name: workstation for workstation in non_duplicates}
    return assets
