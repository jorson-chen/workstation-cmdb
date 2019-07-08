import pymssql
import ConfigParser
import os
import concurrent.futures
import logging
import datetime
from netaddr import IPAddress

logger = logging.getLogger(__name__)

MAX_THREADS = 15


class sccmEndpoints:
    def __init__(self):
        self.id = None
        self.name = None
        self.type = None
        self.domain = None
        self.user = []
        self.location = []
        self.encrypted = False
        self.encrypted_drive = []
        self.last_connected = None
        self.ip = None
        self.os = 'Windows'
        self.external_ip = ""
        self.internal_ip = ""
        self.serial_number = None
        self.sccm_present = 'true'


# Get device information from SCCM tables
def get_device_info(sql_username, sql_password, sccm_database, sccm_host):
    devices = []
    # Connector to config management database
    try:
        sql_conn = pymssql.connect(host=sccm_host, user=sql_username, password=sql_password,
                               database=sccm_database)
    except Exception as e:
        logger.error(e)
        logger.error('Failed to establish database connection')
        return devices

    logger.info('Connection to database established')
    query = "Select distinct \
                    CS.Name0 ComputerName\
                    ,WORK.SystemRole Type\
                    ,CS.Domain0 Domain\
                    ,RV.User_Name0 LastUser\
                    ,CU.TopConsoleUser0 PrimaryUser\
                    ,RV.AD_Site_Name0 Location\
                    ,CS.CurrentTimeZone0 TimeZoneOffset\
                    ,BIT.DriveLetter0 BitlockerDriveLetter\
                    ,SCAN.LastScanDate LastScan\
                    ,BIOS.SerialNumber0 SerialNumber\
                    ,IP.IP_Addresses0 IPAddress\
                    ,BIT.ProtectionStatus0 ProtectionStatus \
                    FROM v_R_System_Valid RV \
                    left join v_GS_COMPUTER_SYSTEM CS on RV.ResourceID=CS.ResourceID \
                    left join v_GS_PC_BIOS BIOS on RV.ResourceID=BIOS.ResourceID \
                    left join vWorkstationStatus WORK on RV.ResourceID=WORK.ResourceID \
                    left join v_GS_SYSTEM_CONSOLE_USAGE CU on RV.ResourceID=CU.ResourceID \
                    left join v_GS_BITLOCKER_DETAILS BIT on RV.ResourceID=BIT.ResourceID \
                    left join v_RA_System_IPAddresses IP on RV.ResourceID=IP.ResourceID \
                    left join v_GS_LASTSOFTWARESCAN SCAN on RV.ResourceID=SCAN.ResourceID \
                    WHERE WORK.SystemRole='Workstation'"

    cursor = sql_conn.cursor(as_dict=True)  # Get the output as dictionary rather than tuple
    cursor.execute(query)
    if cursor:
        with concurrent.futures.ProcessPoolExecutor(max_workers=2) as executor:
            fs = [executor.submit(parse_results, index, row) for index, row in enumerate(cursor)]
            for future in concurrent.futures.as_completed(fs):
                devices.append(future.result())
    else:
        logger.error("No results found from SCCM")
    return devices


# Print user information
def parse_results(index, row):
    if row['ComputerName'] is not None:
        deviceobj = sccmEndpoints()
        deviceobj.id = index
        deviceobj.name = row['ComputerName'].upper()
        if row['Type'] is not None:
            deviceobj.type = row['Type']
        if row['Domain'] is not None:
            deviceobj.domain = row['Domain'].upper()
        if row['LastUser'] is not None:
            deviceobj.user.append(row['LastUser'])
        if row['PrimaryUser'] is not None:
            deviceobj.user.append(row['PrimaryUser'])
        if row['Location'] is not None:
            deviceobj.location.append(row['Location'].upper())
        if row['LastScan'] is not None:
            deviceobj.last_connected = row['LastScan']
        if row['SerialNumber'] is not None:
            deviceobj.serial_number = row['SerialNumber']
        if row['IPAddress'] is not None and ':' not in row['IPAddress']:
            deviceobj.ip = row['IPAddress']
        if row['ProtectionStatus'] is not None and row['ProtectionStatus'] == 1:
            deviceobj.encrypted = True
            deviceobj.encrypted_drive.append(row['BitlockerDriveLetter'].strip(':'))
        return deviceobj
    return None


def print_row(row):
    print('Name: %s' % row['ComputerName'])
    print('Type: %s' % row['Type'])
    print('Domain: %s' % row['Domain'])
    print('Location: %s' % row['Location'])
    print('Encryption: %s' % row['ProtectionStatus'])
    print('Encryption Disk: %s' % row['BitlockerDriveLetter'])
    print('Users: %s %s' % (row['LastUser'], row['PrimaryUser']))
    print()


def merge_duplicates(workstations):
    logger.info('Merging duplicates')
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
            # Merge to the 1st device in the list
            for device in devices[device_name][1:]:
                # Merge domain
                if devices[device_name][0].domain != device.domain and device.domain is not None:
                    if devices[device_name][0].domain is None:
                        devices[device_name][0].domain = device.domain
                    else:
                        devices[device_name][0].domain = devices[device_name][0].domain + ' ' + device.domain

                # Merge location
                if devices[device_name][0].location != device.location:
                    devices[device_name][0].location.extend(device.location)

                # Merge encryption
                # Multiple drive encryption is split into multiple dict objects instead on 1 dict object. Hence the below shenanigans
                if devices[device_name][0].encrypted != device.encrypted and not devices[device_name][0].encrypted:
                    devices[device_name][0].encrypted = True
                    devices[device_name][0].encrypted_drive.extend(device.encrypted_drive)
                if devices[device_name][0].encrypted == device.encrypted and devices[device_name][0].encrypted:
                    devices[device_name][0].encrypted_drive.extend(device.encrypted_drive)

                # Merge user
                if set(devices[device_name][0].user) != set(device.user):
                    devices[device_name][0].user.extend(device.user)

                # Merge last connected
                if devices[device_name][0].last_connected < device.last_connected:
                    devices[device_name][0].last_connected = device.last_connected
                    if devices[device_name][0].ip != device.ip and device.ip is not None:
                        devices[device_name][0].ip = device.ip

                # Get Serial Number if its empty for the 1st device
                if devices[device_name][0].serial_number is None and device.serial_number is not None:
                    devices[device_name][0].serial_number = device.serial_number
                    '''
                    elif device.serial_number is not None and devices[device_name][0].serial_number is not None and devices[device_name][0].serial_number != device.serial_number:
                    print('Serial number mismatch for device %s' % device.name)
                    print(devices[device_name][0].serial_number)
                    print(device.serial_number)
                    '''
        non_duplicate_devices.append(devices[device_name][0])

    return non_duplicate_devices


# Divide IP into Internal and External address
def divide_into_internal_external_ips(ip):
    external_ips = []
    internal_ips = []
    if ip is not None:
        if IPAddress(ip).is_private():
            internal_ips = ip
        else:
            external_ips = ip
    return internal_ips, external_ips


# Remove duplicates from each device's details
def remove_duplicates_from_device_fields(deviceobj):
    if deviceobj.user:
        users = []
        for user in deviceobj.user:
            users.append(user)
        deviceobj.user = sorted(list(set(users)))
    if deviceobj.location:
        deviceobj.location = sorted(list(set(deviceobj.location)))
    return deviceobj.name, deviceobj


# Convert the type of each field of device objects into strings as it service now takes in only string
def convert_all_fields_to_string(deviceobj):
    deviceobj.user = str(deviceobj.user).strip('[').strip(']').replace("'", "").strip('",').replace(' ', '').lower()
    if deviceobj.last_connected is not None:
        deviceobj.last_connected = deviceobj.last_connected.isoformat().split('.')[0].replace('T', ' ')

    deviceobj.internal_ip, deviceobj.external_ip = divide_into_internal_external_ips(deviceobj.ip)

    deviceobj.location = str(deviceobj.location).strip('[').strip(']').replace("'", "").replace(' ', '')
    deviceobj.encrypted = str(deviceobj.encrypted).lower()
    if deviceobj.domain is None:
        deviceobj.domain = ""
    return deviceobj.name, deviceobj


# Fetch all non-duplicate devices that were last active in the past 30 days
def fetch_devices(since_days):
    active_workstations = {}
    sccm_devices_with_serial_numbers = {}
    Config = ConfigParser.ConfigParser()
    Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'SCCM_creds'))
    sql_username = Config.get('Settings', 'User')
    sql_password = Config.get('Settings', 'Password')
    sccm_database = Config.get('Settings', 'Database')
    sccm_host = Config.get('Settings', 'Host')

    logger.info('Fetching all devices from SCCM tables')
    devices = get_device_info(sql_username, sql_password, sccm_database, sccm_host)

    if devices:
        devices = list(set(devices) - {None})
        logger.info('Found %d devices' % len(devices))
        active_devices = [device for device in devices if device.last_connected is not None and (
                datetime.datetime.utcnow() - device.last_connected).days <= since_days]
        if active_devices:
            devices.clear()
            logger.info('Found %d active devices since %d days' % (len(active_devices), since_days))
            logger.info('Merging active device duplicates')
            non_duplicate_devices = merge_duplicates(active_devices)
            if non_duplicate_devices:
                active_devices.clear()
                logger.info('Found %d unique devices' % len(non_duplicate_devices))

                active_workstations = {device.name: device for device in non_duplicate_devices}

                logger.info("Removing duplicates entries in each device field")
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    for device_name, deviceobj in executor.map(remove_duplicates_from_device_fields,
                                                               active_workstations.values()):
                        active_workstations[device_name] = deviceobj

                logger.info("Converting each device field to string for ease of consumption into cmdb")
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    for device_name, deviceobj in executor.map(convert_all_fields_to_string, active_workstations.values()):
                        active_workstations[device_name] = deviceobj

                sccm_devices_with_serial_numbers = {device_name: active_workstations[device_name].serial_number for device_name in active_workstations if active_workstations[device_name].serial_number is not None}

    return active_workstations, sccm_devices_with_serial_numbers
