from tools import cylance
from tools import tenable
from tools import crowdstrike_hosts as crowdstrike
from tools import jamf
from netaddr import IPAddress
import concurrent.futures
import logging

logger = logging.getLogger(__name__)

MAX_THREADS = 15

list_of_company_external_ips = []


# A class to hold the result of each device after merging results from the different security tools
class Device:
    def __init__(self):
        self.name = None
        self.user = []
        self.os = None
        self.last_connected = None
        self.ip = []
        self.external_ip = ""
        self.internal_ip = ""
        self.location = ""
        self.last_scanned = None
        self.tenable_present = False
        self.cylance_present = False
        self.crowdstrike_present = False
        self.jamf_present = False
        self.mac_address = None
        self.encrypted = False
        self.domain = ""

    def return_as_dict(self):
        device_dict = {}
        device_dict[self.name] = {}
        device_dict[self.name]['IP'] = self.ip
        device_dict[self.name]['OS'] = self.os
        device_dict[self.name]['User'] = self.user
        device_dict[self.name]['Last Online'] = self.last_connected
        device_dict[self.name]['Tenable'] = self.tenable_present
        device_dict[self.name]['Cylance'] = self.cylance_present
        device_dict[self.name]['Crowdstrike'] = self.crowdstrike_present
        device_dict[self.name]['JAMF'] = self.jamf_present
        device_dict[self.name]['MAC Address'] = self.mac_address
        device_dict[self.name]['Location'] = self.location
        device_dict[self.name]['Last Scanned'] = self.last_scanned
        device_dict[self.name]['Encrypted'] = self.encrypted
        device_dict[self.name]['Domain'] = self.domain
        return device_dict


# Use the respective api to scan the object
def fetch(since_days, api):
    apis = {
        'cylance_api': cylance.fetch_devices,
        'tenable_api': tenable.fetch_devices,
        'jamf_api': jamf.fetch_devices,
        'crowdstrike_api': crowdstrike.fetch_devices
    }
    result = apis[api](since_days)
    return result, api


# Add tenable results and create new devices
def parse_results_tenable(each_device):
    deviceobj = Device()
    deviceobj.name = each_device.name
    deviceobj.ip.append(each_device.ip)
    if each_device.last_scanned is not None:
        deviceobj.last_scanned = each_device.last_scanned
    deviceobj.last_connected = each_device.last_connected
    deviceobj.os = each_device.os
    deviceobj.tenable_present = True
    return deviceobj


# Merge results from crowdstrike into the existing devices
def parse_results_crowdstrike(each_device, workstations):
    # Device was present in Tenable
    if each_device.name in workstations.keys():
        deviceobj = workstations[each_device.name]
        deviceobj.crowdstrike_present = True
        if not deviceobj.ip:
            deviceobj.ip = each_device.ip
        if deviceobj.last_connected < each_device.last_connected:
            deviceobj.last_connected = each_device.last_connected
            deviceobj.ip = each_device.ip
        if each_device.location is not None:
            deviceobj.location = each_device.location
        if each_device.domain is not None and each_device.domain != "N/A":
            deviceobj.domain = each_device.domain
        if each_device.mac_address is not None and each_device.mac_address in list_of_company_external_ips:
            deviceobj.mac_address = each_device.mac_address
    else:
        # New Device as device was not in Tenable
        deviceobj = Device()
        deviceobj.name = each_device.name
        deviceobj.crowdstrike_present = True
        deviceobj.ip = each_device.ip
        deviceobj.last_connected = each_device.last_connected
        deviceobj.os = each_device.os
        if each_device.location is not None:
            deviceobj.location = each_device.location
        if each_device.domain is not None and each_device.domain != "N/A":
            deviceobj.domain = each_device.domain
        if each_device.mac_address is not None and each_device.mac_address in list_of_company_external_ips:
            deviceobj.mac_address = each_device.mac_address

    workstation = {deviceobj.name: deviceobj}
    return workstation


# Merge results from jamf into the existing devices
def parse_results_jamf(each_device, workstations):
    # Device was present in Tenable or Crowdstrike
    if each_device.name in workstations.keys():
        deviceobj = workstations[each_device.name]
        deviceobj.jamf_present = True
        if each_device.user is not None:
            deviceobj.user.extend(each_device.user)
        if not deviceobj.ip and each_device.ip is not None and each_device.ip:
            deviceobj.ip.append(each_device.ip)
        if deviceobj.last_connected < each_device.last_connected:
            deviceobj.last_connected = each_device.last_connected
            if each_device.ip is not None and each_device.ip:
                deviceobj.ip = [each_device.ip]
        deviceobj.encrypted = each_device.encrypted
        if each_device.domain is not None and not deviceobj.domain:
            deviceobj.domain = each_device.domain
        if each_device.location and not deviceobj.location:
            deviceobj.location = each_device.location
    else:
        # New Device as device was not in Tenable or Crowdstrike
        deviceobj = Device()
        deviceobj.name = each_device.name
        deviceobj.jamf_present = True
        if each_device.ip is not None and each_device.ip:
            deviceobj.ip = [each_device.ip]
        if each_device.user is not None:
            deviceobj.user = each_device.user
        deviceobj.last_connected = each_device.last_connected
        deviceobj.os = 'Mac OS'
        deviceobj.encrypted = each_device.encrypted
        if each_device.domain is not None:
            deviceobj.domain = each_device.domain
        deviceobj.location = each_device.location

    workstation = {deviceobj.name: deviceobj}
    return workstation


# Merge results from cylance into the existing devices
def parse_results_cylance(each_device, workstations):
    # Device was present in Tenable, Crowdstrike or JAMF
    if each_device.name in workstations.keys():
        deviceobj = workstations[each_device.name]
        deviceobj.cylance_present = True
        if each_device.user is not None:
            deviceobj.user.append(each_device.user)
        if not deviceobj.ip:
            deviceobj.ip = each_device.ip
        if deviceobj.last_connected < each_device.last_connected:
            deviceobj.last_connected = each_device.last_connected
            deviceobj.ip = each_device.ip
        if each_device.domain is not None and not deviceobj.domain:
            deviceobj.domain = each_device.domain
    else:
        # New Device as device was not in Tenable, Crowdstrike or JAMF
        deviceobj = Device()
        deviceobj.name = each_device.name
        deviceobj.ip = each_device.ip
        if each_device.user is not None:
            deviceobj.user.append(each_device.user)
        deviceobj.last_connected = each_device.last_connected
        deviceobj.os = each_device.os
        deviceobj.cylance_present = True
        if each_device.domain is not None:
            deviceobj.domain = each_device.domain

    workstation = {deviceobj.name: deviceobj}
    return workstation


# Create a csv of the aggregated result
def create_csv(fileobj, device):
    fileobj.write('%s,%s,"%s","%s",%s,"%s",%s,%s,%s,%s\n' % (device.name, device.os,
                                                             device.ip,
                                                             device.user,
                                                             device.last_connected,
                                                             device.location,
                                                             device.cylance_present,
                                                             device.tenable_present,
                                                             device.crowdstrike_present,
                                                             device.jamf_present))


# Remove duplicates from each device's details
def remove_duplicates_from_device_fields(deviceobj):
    if deviceobj.ip:
        ip_addresses = []
        for ip in deviceobj.ip:
            if ',' in ip:
                ip_addresses.extend(ip.split(','))
            else:
                ip_addresses.append(ip)

        deviceobj.ip = sorted(list(set(ip_addresses)))
    if deviceobj.user:
        users = []
        for user in deviceobj.user:
            if user[0:2] == 'a-':
                user = user[2:]
            users.append(user)
        deviceobj.user = sorted(list(set(users)))
    return deviceobj.name, deviceobj


# Check and removes if a string has the 1st letter as comma
def check_and_remove_if_1st_letter_is_a_comma(input):
    output = ""
    if input:
        if input[0] == ",":
            output = input[1:]
        else:
            output = input
    return output


# Divide IP into Internal and External address
def divide_into_internal_external_ips(ips):
    external_ips = []
    internal_ips = []
    if ips:
        for ip in ips:
            if ip is not None and ip:
                if IPAddress(ip).is_private():
                    internal_ips.append(ip)
                else:
                    external_ips.append(ip)

    # Convert list to string
    external_ips = str(external_ips).strip('[').strip(']').replace(' ', '').replace("'", "")
    internal_ips = str(internal_ips).strip('[').strip(']').replace(' ', '').replace("'", "")
    return internal_ips, external_ips


# Convert the type of each field of device objects into strings as it service now takes in only string
def convert_all_fields_to_string(deviceobj):
    if deviceobj.name is None:
        deviceobj.name = ""

    if deviceobj.os == "win32nt":
        deviceobj.os = "Windows"
    deviceobj.user = str(deviceobj.user).strip('[').strip(']').replace("'", "").strip('",').replace(' ', '').lower()
    deviceobj.user = check_and_remove_if_1st_letter_is_a_comma(deviceobj.user)
    if deviceobj.last_connected is not None:
        deviceobj.last_connected = deviceobj.last_connected.isoformat().split('.')[0].replace('T', ' ')
    else:
        deviceobj.last_connected = ""
    deviceobj.internal_ip, deviceobj.external_ip = divide_into_internal_external_ips(deviceobj.ip)

    if deviceobj.last_scanned is not None:
        deviceobj.last_scanned = deviceobj.last_scanned.isoformat().split('.')[0].replace('T', ' ')
    else:
        deviceobj.last_scanned = ""

    if deviceobj.mac_address is None:
        deviceobj.mac_address = ""

    deviceobj.tenable_present = str(deviceobj.tenable_present).lower()
    deviceobj.cylance_present = str(deviceobj.cylance_present).lower()
    deviceobj.crowdstrike_present = str(deviceobj.crowdstrike_present).lower()
    deviceobj.jamf_present = str(deviceobj.jamf_present).lower()
    deviceobj.encrypted = str(deviceobj.encrypted).lower()

    return deviceobj.name, deviceobj


# Aggregate and create a single unified list of devices with the results merged from different security tools
def main(since_days):
    result_tenable = []
    result_cylance = []
    result_jamf = []
    result_crowdstrike = []

    # Create a multi process to hit 2 API at once
    logger.info("Collecting device information from different APIs")
    apis_to_hit = ['tenable_api', 'jamf_api', 'crowdstrike_api', 'cylance_api']
    with concurrent.futures.ProcessPoolExecutor(max_workers=2) as executor:
        fs = [executor.submit(fetch, since_days, api) for api in apis_to_hit]
        block_of_futures = []
        if len(fs) > 15:
            block_of_futures = [fs[i:i + 15] for i in range(0, len(fs), 15)]
        else:
            block_of_futures.append(fs)
        for futures in block_of_futures:
            if futures:
                for future in concurrent.futures.as_completed(futures):
                    if future.result():
                        fetch_result, api = future.result()
                        if 'tenable' in api:
                            result_tenable = fetch_result
                        elif 'jamf' in api:
                            result_jamf = fetch_result
                        elif 'crowdstrike' in api:
                            result_crowdstrike = fetch_result
                        elif 'cylance' in api:
                            result_cylance = fetch_result

    # Exit the script if at least one API has no results
    if not result_cylance:
        logger.error('No results available from cylance')

    if not result_tenable:
        logger.error('No results available from tenable')

    if not result_jamf:
        logger.error('No results available from jamf')

    if not result_crowdstrike:
        logger.error('No results available from crowdstrike')

    if not result_cylance or not result_tenable or not result_jamf or not result_crowdstrike:
        exit(-1)

    # Merge results from each script with dict format: {device_name: device_object}
    workstations = {}
    logger.info('Merging Tenable results')
    with concurrent.futures.ProcessPoolExecutor() as executor:
        for device_name, deviceobj in zip([device.name for device in result_tenable],
                                          executor.map(parse_results_tenable, result_tenable)):
            workstations[device_name] = deviceobj

    logger.info('Merging Crowdstrike results')
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        fs = [executor.submit(parse_results_crowdstrike, each_device, workstations) for each_device in
              result_crowdstrike]
        block_of_futures = []
        if len(fs) > 15:
            block_of_futures = [fs[i:i + 15] for i in range(0, len(fs), 15)]
        else:
            block_of_futures.append(fs)
        for futures in block_of_futures:
            if futures:
                for future in concurrent.futures.as_completed(futures):
                    workstations.update(future.result())

    logger.info('Merging JAMF results')
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        fs = [executor.submit(parse_results_jamf, each_device, workstations) for each_device in result_jamf]
        block_of_futures = []
        if len(fs) > 15:
            block_of_futures = [fs[i:i + 15] for i in range(0, len(fs), 15)]
        else:
            block_of_futures.append(fs)
        for futures in block_of_futures:
            if futures:
                for future in concurrent.futures.as_completed(futures):
                    workstations.update(future.result())

    logger.info('Merging Cylance results')
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        fs = [executor.submit(parse_results_cylance, each_device, workstations) for each_device in result_cylance]
        block_of_futures = []
        if len(fs) > 15:
            block_of_futures = [fs[i:i + 15] for i in range(0, len(fs), 15)]
        else:
            block_of_futures.append(fs)
        for futures in block_of_futures:
            if futures:
                for future in concurrent.futures.as_completed(futures):
                    workstations.update(future.result())

    devices = {}
    logger.info("Removing duplicates entries in each device field")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for device_name, deviceobj in executor.map(remove_duplicates_from_device_fields, workstations.values()):
            devices[device_name] = deviceobj

    workstations.clear()

    logger.info("Converting each device field to string for ease of consumption into cmdb")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for device_name, deviceobj in executor.map(convert_all_fields_to_string, devices.values()):
            devices[device_name] = deviceobj

    jamf_devices_with_serial_numbers = {device.name: device.serial_number for device in result_jamf if
                                        device.serial_number}

    return devices, jamf_devices_with_serial_numbers
