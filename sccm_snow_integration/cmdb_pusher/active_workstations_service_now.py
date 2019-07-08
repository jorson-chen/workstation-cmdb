import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import ConfigParser
import os
import concurrent.futures
import logging
import datetime

logger = logging.getLogger(__name__)

MAX_THREADS = 14

Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)),'Service_Now_creds'))
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
        self.discovery_source = ""
        self.encrypted = ""
        self.domain = ""
        self.sccm_present = ""
        self.asset_link = ""
        self.created_on = ""
        self.serial_number = ""

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
        workstation['discovery_source'] = self.discovery_source
        workstation['encrypted'] = self.encrypted
        workstation['domain'] = self.domain
        workstation['sccm_present'] = self.sccm_present
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
    workstationobj.discovery_source = asset['discovery_source']
    workstationobj.encrypted = asset['u_encrypted']
    workstationobj.domain = asset['u_ad_domain']
    workstationobj.sccm_present = asset['u_present_in_sccm']
    workstationobj.created_on = asset['sys_created_on']
    workstationobj.asset_link = asset['asset']
    workstationobj.serial_number = asset['serial_number']
    return workstationobj


# A hack to get the total number of devices
def get_assets_total():
    logger.info('Fetching total number of assets from Snow')
    total = 0
    headers = {"Accept": "application/json", "Content-Type": "application/json;charset=UTF-8"}
    # Fetch only 1 device
    params = {"sysparm_limit": '1',
              'sysparm_query': 'asset_tagISNOTEMPTY^osLIKEwind^install_statusNOT IN9,7,8',
              'sysparm_fields': 'sys_id,asset_tag,u_usernames,os,last_discovered,ip_address,u_office,discovery_source,u_external_ip_addresses,u_encrypted,u_ad_domain,u_present_in_sccm,asset,sys_created_on,serial_number'}

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
                  'sysparm_query': 'asset_tagISNOTEMPTY^osLIKEwind^install_statusNOT IN9,7,8',
                  'sysparm_fields': 'sys_id,asset_tag,u_usernames,os,last_discovered,ip_address,u_office,discovery_source,u_external_ip_addresses,u_encrypted,u_ad_domain,u_present_in_sccm,asset,sys_created_on,serial_number'
                  }

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
    if asset.internal_ip:
        asset_json['ip_address'] = asset.internal_ip
    if asset.external_ip:
        asset_json['u_external_ip_addresses'] = asset.external_ip
    if asset.location:
        asset_json['u_office'] = asset.location

    asset_json['u_encrypted'] = asset.encrypted
    asset_json['u_ad_domain'] = asset.domain
    asset_json['u_present_in_sccm'] = asset.sccm_present
    if new_record:
        asset_json['u_present_in_tenable'] = 'false'
        asset_json['u_present_in_cylance'] = 'false'
        asset_json['u_present_in_crowdstrike'] = 'false'
        asset_json['u_present_in_jamf'] = 'false'
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


# Filter into duplicate and non-duplicate workstations/assets
def filter_duplicates_non_duplicates(workstations, sccm_devices_with_serial_numbers):

    '''
        Filter based on the below criteria
        (1) asset link
        (2) which ones have a serial number matching from SCCM
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
                    # Check serial number of Windows and SCCM
                    sccm_devices_with_serial_numbers = [device for device in devices_with_serial_number if device.name in sccm_devices_with_serial_numbers and sccm_devices_with_serial_numbers[device.name] == device.serial_number]
                    if len(sccm_devices_with_serial_numbers) == 1:
                        non_duplicate_device_id = sccm_devices_with_serial_numbers[0].id
                        non_duplicate_devices.append(sccm_devices_with_serial_numbers[0])
                    else:
                        # Else sort by creation date of the CI
                        if len(sccm_devices_with_serial_numbers) > 1:
                            devices_with_creation_dates = {device: device.created_on for device in
                                                           sccm_devices_with_serial_numbers}
                        else:
                            devices_with_creation_dates = {device: device.created_on for device in
                                                           devices_with_serial_number}
                else:
                    # Else sort by creation date of the CI
                    devices_with_creation_dates = {device: device.created_on for device in leftover_device_list}

                if devices_with_creation_dates:
                    # Get the least creation date from all devices in devices_with_creation_dates
                    creation_dates = [devices_with_creation_dates[device] for device in devices_with_creation_dates]
                    if datetime.datetime.strptime(creation_dates[0], '%Y-%m-%d %H:%M:%S') < datetime.datetime.strptime(
                            creation_dates[1], '%Y-%m-%d %H:%M:%S'):
                        oldest_creation_date = creation_dates[0]
                    else:
                        oldest_creation_date = creation_dates[1]

                    if len(creation_dates) > 2:
                        for index in range(2, len(creation_dates)):
                            if datetime.datetime.strptime(creation_dates[index],
                                                          '%Y-%m-%d %H:%M:%S') < datetime.datetime.strptime(
                                    oldest_creation_date, '%Y-%m-%d %H:%M:%S'):
                                oldest_creation_date = creation_dates[index]

                    # Get device associated with oldest_creation_date
                    for device in devices_with_creation_dates:
                        if devices_with_creation_dates[device] == oldest_creation_date:
                            non_duplicate_device_id = device.id
                            non_duplicate_devices.append(device)
                            break

            if non_duplicate_device_id:
                duplicate_devices.extend(
                    [device for device in devices[device_name] if device.id != non_duplicate_device_id])
        else:
            non_duplicate_devices.extend(devices[device_name])

    return duplicate_devices, non_duplicate_devices


# Fetch assets that have no duplicates from the computer table
def fetch_categorized_workstations(total_count, sccm_devices_with_serial_numbers):
    workstations = get_all_assets(total_count)
    duplicates, non_duplicates = filter_duplicates_non_duplicates(workstations, sccm_devices_with_serial_numbers)
    logger.info('Found %d non-duplicate workstations' % len(non_duplicates))

    duplicate_workstations_without_duplicate_tag = [device for device in duplicates if device.discovery_source != 'Duplicate']
    non_duplicate_workstations_with_duplicate_tag = [device for device in non_duplicates if device.discovery_source == 'Duplicate']

    # Deal with duplicates in the Computer table
    logger.info('Marking %d duplicate workstations as duplicate' % len(duplicate_workstations_without_duplicate_tag))
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for device in duplicate_workstations_without_duplicate_tag:
            executor.submit(mark_asset_as_duplicate, device)

    # Deal with non duplicates in the Computer table
    logger.info('Marking %d non duplicate workstations as non_duplicate' % len(non_duplicate_workstations_with_duplicate_tag))
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for device in non_duplicate_workstations_with_duplicate_tag:
            executor.submit(mark_asset_as_non_duplicate, device)

    # Convert the assets into a dict form
    assets = {workstation.name: workstation for workstation in non_duplicates}

    return assets
