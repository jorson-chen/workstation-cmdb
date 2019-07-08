import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import ConfigParser
import os
import logging
import datetime
import time
import base64
import concurrent.futures

logger = logging.getLogger(__name__)

MAX_THREADS = 15  # Get max number of threads for multi-threading

crowdstrike_api = 'https://api.crowdstrike.com'
Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)),'Crowdstrike_creds'))
crowdstrike_client_id = Config.get('Settings', 'Crowdstroke_Client_Id')
crowdstrike_secret = Config.get('Settings', 'Crowdstrike_Secret_Id')


# Generate session with max of 3 retries and interval of 1 second
def session_generator():
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# Hold necessary information for each crowdstrike asset
class CrowdStrikeHost:
    def __init__(self):
        self.user = None
        self.name = None
        self.id = None
        self.ip = []
        self.os = None
        self.location = None
        self.last_connected = None
        self.domain = None
        self.mac_address = None


# Generate OAUTH token to be used
def generate_access_token():
    logger.info('Generating Crowdstrike access token')
    access_token = None
    expiry_time = None
    headers = {'Content-Type': 'application/x-www-form-urlencoded', "accept": "application/json"}
    data = {'client_id': crowdstrike_client_id, 'client_secret': crowdstrike_secret}
    session = session_generator()
    url = "%s/oauth2/token" % crowdstrike_api
    resp = session.post(url, headers=headers, data=data)
    if resp.ok:
        response = resp.json()
        access_token = response['access_token']
        expiry_time = datetime.datetime.now() + datetime.timedelta(seconds=response['expires_in'])

        if "errors" in response:
            for error in response['errors']:
                logger.error("Error Code %d: %s " % (error['code'], error['message']))

    elif resp.status_code == 429:
        logger.warning('Rate Limiting encountered. Sleeping')
        response_headers = resp.headers
        seconds_to_sleep = response_headers['Retry-After']
        logger.info("Sleeping for %d seconds" % seconds_to_sleep)
        time.sleep(seconds_to_sleep)
        access_token, expiry_time = generate_access_token()
    else:
        logger.error("Unable to generate token from Query API")
        logger.error("%d:%s" % (resp.status_code, resp.text))
    return access_token, expiry_time


# Kill OAUTH token after use
def revoke_access_token(access_token, expiry):
    logger.info('Revoking Crowdstrike access token')

    query_start_time = datetime.datetime.now()

    # Make the API call if token expiry time is greater than 1 minute
    if int((expiry - query_start_time).seconds) > 60:
        encoded_id_secret = base64.b64encode(bytes("%s:%s" % (crowdstrike_client_id, crowdstrike_secret), 'utf-8')).decode(encoding='UTF-8')
        headers = {'Authorization': 'Basic %s' % encoded_id_secret, 'Content-Type': 'application/x-www-form-urlencoded', "accept": "application/json"}
        data = {'token': access_token}
        session = session_generator()
        url = "%s/oauth2/revoke" % crowdstrike_api
        resp = session.post(url, headers=headers, data=data)
        if resp.ok:
            response = resp.json()
            if "errors" in response:
                for error in response['errors']:
                    logger.error("Error Code %d: %s " % (error['code'], error['message']))

        elif resp.status_code == 429:
            logger.warning('Rate Limiting encountered. Sleeping')
            response_headers = resp.headers
            seconds_to_sleep = response_headers['Retry-After']
            logger.info("Sleeping for %d seconds" % seconds_to_sleep)
            time.sleep(seconds_to_sleep)
            revoke_access_token(access_token, expiry)
        else:
            logger.error("Unable to revoke token from Query API")
            logger.error("%d:%s" % (resp.status_code, resp.text))
    else:
        logger.info("Token has already expired. Not revoking.")


# Fetch host IDS of all workstations
def get_host_ids(access_token, expiry, offset=0):
    device_ids = []
    total = 0
    headers = {'Authorization': 'Bearer %s' % access_token, 'Content-Type': 'application/json',
               "accept": "application/json"}
    url = "%s/devices/queries/devices/v1" % crowdstrike_api
    params = {'limit': 5000, 'sort': 'hostname.asc', 'offset': offset}
    session = session_generator()
    query_start_time = datetime.datetime.now()

    # Make the API call if token expiry time is greater than 1 minute
    if int((expiry - query_start_time).seconds) > 60:
        resp = session.get(url, headers=headers, params=params)
        if resp.ok:
            response = resp.json()
            device_ids.extend(response['resources'])
            total = response['meta']['pagination']['total']

            if "errors" in response:
                for error in response['errors']:
                    logger.error("Error Code %d: %s " % (error['code'], error['message']))

        elif resp.status_code == 429:
            logger.warning('Rate Limiting encountered. Sleeping')
            response_headers = resp.headers
            seconds_to_sleep = response_headers['Retry-After']
            logger.info("Sleeping for %d seconds" % seconds_to_sleep)
            time.sleep(seconds_to_sleep)
            get_host_ids(access_token, expiry, offset)
        else:
            logger.error("Unable to get host ids from Query API")
            logger.error("%d:%s" % (resp.status_code, resp.text))
    return total, device_ids


# Parse results from host response
def parse_host_results(device):
    if 'product_type_desc' in device:
        if 'Server' in device['product_type_desc']:
            return False, None

    if 'hostname' in device:
        crowdstrikehostobj = CrowdStrikeHost()
        crowdstrikehostobj.name = device['hostname'].upper()
        if '.' in crowdstrikehostobj.name:
            crowdstrikehostobj.name = crowdstrikehostobj.name.split('.')[0]
        if 'local_ip' in device:
            crowdstrikehostobj.ip.append(device['local_ip'])
        if 'external_ip' in device:
            crowdstrikehostobj.ip.append(device['external_ip'])
        crowdstrikehostobj.os = device['platform_name']
        if crowdstrikehostobj.os == 'Mac':
            crowdstrikehostobj.os = 'Mac OS'
        crowdstrikehostobj.id = device['device_id']
        '''
        if 'last_login_user' in device:
            crowdstrikehostobj.user = device['last_login_user']
        '''
        if 'last_seen' in device:
            crowdstrikehostobj.last_connected = datetime.datetime.strptime(device['last_seen'],
                                                                           '%Y-%m-%dT%H:%M:%SZ').replace(
                tzinfo=datetime.timezone.utc)
        if 'site_name' in device and '.com' not in device['site_name']:
            crowdstrikehostobj.location = device['site_name']

        if 'machine_domain' in device:
            crowdstrikehostobj.domain = device['machine_domain'].upper()

        if 'mac_address' in device:
            if 'external_ip' in device and device['external_ip']:
                crowdstrikehostobj.mac_address = device['mac_address'].replace('-', ':').upper()

        return True, crowdstrikehostobj
    else:
        return False, None


# Get host details from host ids
def get_hosts(access_token, expiry, block_of_device_ids):
    devices = []
    headers = {'Authorization': 'Bearer %s' % access_token, 'Content-Type': 'application/json',
               "accept": "application/json"}
    query_filter = ''

    for host_id in block_of_device_ids:
        query_filter = '%s%s%s&' % (query_filter, 'ids=', host_id)
    filter = query_filter[:len(query_filter) - 1]

    url = "%s/devices/entities/devices/v1?%s" % (crowdstrike_api, filter)
    session = session_generator()
    query_start_time = datetime.datetime.now()

    # Make the API call if token expiry time is greater than 1 minute
    if int((expiry - query_start_time).seconds) > 60:
        resp = session.get(url, headers=headers)
        if resp.ok:
            response = resp.json()
            with concurrent.futures.ProcessPoolExecutor() as executor:
                for object_created, crowdstrikehostobj in executor.map(parse_host_results, response['resources']):
                    if object_created:
                        devices.append(crowdstrikehostobj)

            if "errors" in response:
                for error in response['errors']:
                    logger.error("Error Code %d: %s " % (error['code'], error['message']))

        elif resp.status_code == 429:
            logger.warning("Rate Limiting encountered. Sleeping")
            response_headers = resp.headers
            seconds_to_sleep = response_headers['Retry-After']
            logger.info("Sleeping for %d seconds" % seconds_to_sleep)
            time.sleep(seconds_to_sleep)
            devices.extend(get_hosts(access_token, expiry, block_of_device_ids))
        else:
            logger.error("Unable to get device info from Query API")
            logger.error("%d:%s" % (resp.status_code, resp.text))

    return devices


# Remove duplicate from device list
def remove_duplicates(workstations):
    logger.info('Removing duplicate devices')
    devices = {}
    duplicate_devices = []
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
            non_duplicate_device_id = ""

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
                    non_duplicate_device_id = device.id
                    non_duplicate_devices.append(device)
                    break

            if non_duplicate_device_id:
                duplicate_devices.extend([device for device in devices[device_name] if device.id != non_duplicate_device_id])
        else:
            non_duplicate_devices.extend(devices[device_name])

    return non_duplicate_devices, duplicate_devices


# Get non-duplicate workstations that were last active in the past 30 days
def fetch_devices(since_days):
    non_duplicate_active_devices = []
    devices = []
    access_token, expiry = generate_access_token()

    all__device_ids = []
    if access_token is not None:
        logger.info('Fetch all devices')
        total_host, device_ids = get_host_ids(access_token, expiry)
        all__device_ids.extend(device_ids)

        # Divide the total host into batches of 15 each containing 5000 devices
        if total_host > 5000:
            offsets = [i for i in range(5001, total_host, 5000)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                for _, device_ids in executor.map(lambda offset: get_host_ids(access_token, expiry, offset),
                                                  offsets):
                    all__device_ids.extend(device_ids)

            if all__device_ids:
                blocks_of_device_ids = [all__device_ids[i:i+15] for i in range(0, len(all__device_ids), 15)]

                logger.info('Populating device details')
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    for deviceobj in executor.map(lambda device_ids: get_hosts(access_token, expiry, device_ids), blocks_of_device_ids):
                        devices.extend(deviceobj)

                revoke_access_token(access_token, expiry)

        active_devices = []
        stale_devices = []
        if devices:
            logger.info("Total number of devices found: %d" % len(devices))
            for device in devices:
                if device.last_connected is not None:
                    if (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - device.last_connected).days <= since_days:
                        active_devices.append(device)
                    else:
                        stale_devices.append(device)
                else:
                    stale_devices.append(device)

        if active_devices:
            logger.info("Total number of active devices found since %d days: %d" % (since_days, len(active_devices)))
            non_duplicate_active_devices, duplicates = remove_duplicates(active_devices)

            if non_duplicate_active_devices:
                logger.info("Total number of non duplicate active devices found since %d days: %d" % (since_days, len(non_duplicate_active_devices)))

    return non_duplicate_active_devices
