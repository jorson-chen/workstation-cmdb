import cmdb_pusher.active_workstations_service_now as active_workstations_service_now
import concurrent.futures
import aggregator
import logging
import click

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)-15s [%(levelname)-8s]: %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger(__name__)

MAX_THREADS = 14


# Decide whether an Service Now device needs to get updated or a new device is to be entered into Service Now
def divide_devices_based_on_insert_or_update(asset, workstations_from_service_now):
    update = False
    insert_new = False
    if asset in workstations_from_service_now:
        update = True
    else:
        insert_new = True
    return update, insert_new


# Decide if the Service Now device actually needs an update
def update_service_now_workstation(snowobj, workstationobj):
    update_needed = False
    if snowobj.user != workstationobj.user:
        update_needed = True
        snowobj.user = workstationobj.user

    if snowobj.last_connected != workstationobj.last_connected:
        update_needed = True
        snowobj.last_connected = workstationobj.last_connected

    if snowobj.internal_ip != workstationobj.internal_ip:
        update_needed = True
        snowobj.internal_ip = workstationobj.internal_ip

    if snowobj.external_ip != workstationobj.external_ip:
        update_needed = True
        snowobj.external_ip = workstationobj.external_ip

    if snowobj.location != workstationobj.location:
        update_needed = True
        snowobj.location = workstationobj.location

    if snowobj.last_scanned != workstationobj.last_scanned:
        update_needed = True
        snowobj.last_scanned = workstationobj.last_scanned

    if snowobj.cylance_present != workstationobj.cylance_present:
        update_needed = True
        snowobj.cylance_present = workstationobj.cylance_present

    if snowobj.crowdstrike_present != workstationobj.crowdstrike_present:
        update_needed = True
        snowobj.crowdstrike_present = workstationobj.crowdstrike_present

    if snowobj.tenable_present != workstationobj.tenable_present:
        update_needed = True
        snowobj.tenable_present = workstationobj.tenable_present

    if snowobj.jamf_present != workstationobj.jamf_present:
        update_needed = True
        snowobj.jamf_present = workstationobj.jamf_present

    if snowobj.encrypted != workstationobj.encrypted and workstationobj.os == 'Mac OS':
        update_needed = True
        snowobj.encrypted = workstationobj.encrypted

    if not snowobj.os:
        snowobj.os = workstationobj.os
        update_needed = True

    if snowobj.domain != workstationobj.domain:
        snowobj.domain = workstationobj.domain
        update_needed = True

    if snowobj.mac_address != workstationobj.mac_address and workstationobj.mac_address:
        snowobj.mac_address = workstationobj.mac_address
        update_needed = True

    return update_needed, snowobj


@click.command()
@click.option("-d", "--duration", default=30, show_default=True, nargs=1, type=int, required=False, help="Update Active Workstations Table in Service Now for all workstation that were last seen since 'duration' days")
def main(duration):
    # Fetch all active workstations in the past 30 days from aggregator
    workstations_from_tool_aggregator, jamf_devices_with_serial_numbers = aggregator.main(duration)

    # Push all workstations to service now cmdb
    if workstations_from_tool_aggregator:
        # Get all workstation from Computers table
        total_count = active_workstations_service_now.get_assets_total()
        if int(total_count) > 0:
            workstations_from_service_now = active_workstations_service_now.fetch_categorized_workstations(total_count,
                                                                                                           jamf_devices_with_serial_numbers)

            records_that_need_to_be_updated = []
            records_that_need_to_be_created = []
            logger.info('Checking if devices from aggregator are present in service now table or not')
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                for asset, status in zip(workstations_from_tool_aggregator.keys(), executor.map(
                        lambda asset: divide_devices_based_on_insert_or_update(asset,
                                                                               workstations_from_service_now.keys()),
                        workstations_from_tool_aggregator.keys())):
                    if status[0]:
                        records_that_need_to_be_updated.append(asset)
                    if status[1]:
                        records_that_need_to_be_created.append(asset)

            # A list of service now devices that need to be updated
            devices_that_need_to_be_updated = []
            if records_that_need_to_be_updated:
                logger.info('Checking if the device actually needs to be modified in service now table')
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    for update_needed, snowobj in executor.map(
                            lambda asset: update_service_now_workstation(workstations_from_service_now[asset],
                                                                         workstations_from_tool_aggregator[asset]),
                            records_that_need_to_be_updated):
                        if update_needed:
                            devices_that_need_to_be_updated.append(snowobj)

            # A list of devices that need to be created in Service Now
            if records_that_need_to_be_created:
                logger.info("Devices that need to be added to the table: %d" % len(records_that_need_to_be_created))
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    for asset in records_that_need_to_be_created:
                        executor.submit(active_workstations_service_now.insert_asset_data,
                                        workstations_from_tool_aggregator[asset])

            if devices_that_need_to_be_updated:
                logger.info("Devices that need to be modified in the table: %d" % len(devices_that_need_to_be_updated))
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    for asset in devices_that_need_to_be_updated:
                        executor.submit(active_workstations_service_now.update_asset_data, asset)

        else:
            # Create new devices in service now from all devices in the aggregator
            logger.info("Active Workstations is completely empty. Filling up the devices from the aggregator")
            logger.info("Devices that need to be added to the table: %d" % len(workstations_from_tool_aggregator))
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                for asset in workstations_from_tool_aggregator.keys():
                    executor.submit(active_workstations_service_now.insert_asset_data,
                                    workstations_from_tool_aggregator[asset])

            # Cross check if all deivces were created
            total_count = active_workstations_service_now.get_assets_total()
            if int(total_count) == len(workstations_from_tool_aggregator):
                logger.info('Completed adding all devices into the table')
            else:
                logger.info('Devices skipped while adding to table: %d' % (
                            len(workstations_from_tool_aggregator) - int(total_count)))


if __name__ == "__main__":
    main()
