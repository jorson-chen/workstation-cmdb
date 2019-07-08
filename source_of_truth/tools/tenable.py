import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import datetime
import logging
import ConfigParser
import os
import concurrent.futures
import time

logger = logging.getLogger(__name__)
MAX_THREADS = 14  # Get max number of threads for multi-threading

# Read credentials for tenable
Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)),'Tenable_creds'))
tenable_client_id = Config.get('Settings', 'Tenable_Client_Id')
tenable_secret_id = Config.get('Settings', 'Tenable_Secret_Id')
tenable_api = "https://cloud.tenable.com"


# Generate session with max of 3 retries and interval of 1 second
def session_generator():
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# A class to hold tenable agent details
class TenableAgents:
    def __init__(self):
        self.id = None
        self.name = None
        self.last_scanned = None
        self.last_connected = None
        self.os = None
        self.scanner_id = None
        self.ip = None

    # Check if a particular agent is present in Tenable
    def verify_agent(self):
        headers = {'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (tenable_client_id, tenable_secret_id),
                   'Content-Type': 'application/json'}
        session = session_generator()
        resp = session.get("%s/scanners/%d/agents?f=name:match:%s" % (tenable_api, self.scanner_id, self.name),
                           headers=headers)
        if resp.ok:
            response = resp.json()
            if response['pagination']['total'] > 0:
                for agent in response['agents']:
                    if '.' in agent['name']:
                        if agent['name'].split('.')[0].upper() == self.name.upper():
                            logger.info("Agent %s with id %d found." % (self.name, agent['id']))
                            break
                    else:
                        if agent['name'].upper() == self.name.upper():
                            break
            else:
                logger.info("Agent %s not found" % self.name)
        elif resp.status_code == 429:
            time.sleep(60)
            self.verify_agent()
        else:
            logger.error('Error %d:%s', resp.status_code, resp.text)


# Get any scanner id as all devices agents are associated with all scanners
def get_any_scanner_id():
    headers = {'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (tenable_client_id, tenable_secret_id),
               'Content-Type': 'application/json'}
    session = session_generator()
    r = session.get("%s/scanners" % tenable_api, headers=headers)
    if r.ok:
        response = r.json()
        scanner_id = response['scanners'][0]['id']
        logger.info("Received Tenable Scanner ID")
        return scanner_id
    else:
        logger.error('Unable to make rest call to get scanner id')
        logger.error('ERROR %s: %s' % (r.status_code, r.text))
        return None


# Fetch the groups (id and text) associated with the scanner
def get_agent_groups(scanner_id):
    logger.info("Fetching all agent groups...")
    agent_group_ids = {}
    headers = {'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (tenable_client_id, tenable_secret_id),
               'Content-Type': 'application/json'}
    session = session_generator()
    agent_group_request = session.get("%s/scanners/%d/agent-groups" % (tenable_api, scanner_id), headers=headers)
    if agent_group_request.ok:
        agent_group_response = agent_group_request.json()
        for agent_group in agent_group_response['groups']:
            agent_group_ids[agent_group['id']] = agent_group['name']
        logger.info("Completed collecting all agent groups")
    return agent_group_ids


# Parse response for each device from the agent group
def parse_agents_results(device):
    deviceobj = TenableAgents()
    # Get device id
    deviceobj.id = device['id']

    if device['ip']:
        deviceobj.ip = device['ip']
    else:
        deviceobj.ip = ''

    # Standardize OS accross different security tools
    if device['platform'] == "DARWIN":
        deviceobj.os = 'Mac OS'
    else:
        deviceobj.os = device['platform'].capitalize()

    deviceobj.name = device['name'].replace(' ', '').upper()

    if '.' in deviceobj.name:
        deviceobj.name = deviceobj.name.split('.')[0]

    # Get last connected to Tenable
    if 'last_connect' in device:
        last_connected = device['last_connect']
        # Get number of days since it was connected.
        deviceobj.last_connected = datetime.datetime.utcfromtimestamp(
            last_connected).replace(tzinfo=datetime.timezone.utc)

    # Get last scanned by Tenable
    if 'last_scanned' in device:
        last_scanned = device['last_scanned']
        # Get number of days since it was scanned.
        deviceobj.last_scanned = datetime.datetime.utcfromtimestamp(
            last_scanned).replace(tzinfo=datetime.timezone.utc)

    return deviceobj


# Fetches all agents in a particular agent group
def get_agents_in_agent_group(scanner_id, group_id):
    devices = []
    offset = 0
    session = session_generator()
    logger.info("Getting all agents belonging to group id %d", group_id)
    while True:
        headers = {'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (tenable_client_id, tenable_secret_id),
                   'Content-Type': 'application/json'}
        agent_request = session.get(
            "%s/scanners/%d/agent-groups/%s?limit=5000&offset=%d" % (tenable_api, scanner_id, group_id, offset),
            headers=headers)
        if agent_request.ok:
            agent_response = agent_request.json()
            with concurrent.futures.ProcessPoolExecutor() as executor:
                for deviceobj in executor.map(parse_agents_results, agent_response['agents']):
                    devices.append(deviceobj)

            # Tackle pagination
            if agent_response['pagination']['total'] - offset <= 5000:
                break
            else:
                offset = offset + 5000
        else:
            logger.error('Error %d:%s', agent_request.status_code, agent_request.text)
    return devices


# Group agents based on last connected and last scanned
def divide_agents_into_groups(devices, since_days):
    stale_devices = []
    active_devices = []
    unscanned_devices = []

    for device in devices:
        # Filter based on last connected to Tenable
        if device.last_connected is not None:
            # Comparision is based on days
            if (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - device.last_connected).days > since_days:
                stale_devices.append(device)
            else:
                active_devices.append(device)
        else:
            stale_devices.append(device)

        # Filter based on device last scanned
        if device.last_scanned is not None:
            # Comparision is based on days
            if (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - device.last_scanned).days > 14 and (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - device.last_connected).days <= since_days:
                unscanned_devices.append(device)
        else:
            if device.last_connected is not None and (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - device.last_connected).days <= since_days:
                unscanned_devices.append(device)
    return stale_devices, active_devices, unscanned_devices


# Fetch all workstations
def get_workstations(scanner_id):
    """
    Mention which group contains your workstations
    """
    devices = []
    logger.info("Getting all workstations")
    agent_group_ids = get_agent_groups(scanner_id)
    if agent_group_ids:
        # Map based on the value to the group id and fetch agents accordingly
        for group_id in agent_group_ids:
            if 'Workstations' in agent_group_ids[group_id]:
                devices.extend(get_agents_in_agent_group(scanner_id, group_id))
    return devices


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


# Get all non duplicate devices that are last active in the past 30 days
def fetch_devices(since_days):
    non_duplicate_active_devices = []
    # Fetch any scanner as each scanner has the same devices associated with it
    scanner_id = get_any_scanner_id()
    if scanner_id is not None:
        # Fetches all workstations
        devices = get_workstations(scanner_id)

        if devices:
            logger.info("Total number of devices found: %d" % len(devices))
            # Filter devices into stale and non_stale groups
            stale_devices, active_devices, unscanned_devices = divide_agents_into_groups(devices, since_days)
            logger.info("Total number of active devices found since %d days: %d" % (since_days, len(active_devices)))
            if active_devices:
                non_duplicate_active_devices = remove_duplicates(active_devices)
                logger.info(
                    "Total number of non duplicate active devices found since %d days: %d" % (since_days, len(non_duplicate_active_devices)))

    return non_duplicate_active_devices
