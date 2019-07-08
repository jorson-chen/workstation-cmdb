import cmdb_pusher.active_workstations_service_now as active_workstations_service_now
import concurrent.futures
import sccm
import click
import logging
import datetime

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

    if not snowobj.internal_ip and workstationobj.internal_ip:
        update_needed = True
        snowobj.internal_ip = workstationobj.internal_ip

    if not snowobj.external_ip and workstationobj.external_ip:
        update_needed = True
        snowobj.external_ip = workstationobj.external_ip

    if not snowobj.location and workstationobj.location:
        update_needed = True
        snowobj.location = workstationobj.location

    if not snowobj.user and workstationobj.user:
        update_needed = True
        snowobj.user = workstationobj.user

    if not snowobj.last_connected:
        update_needed = True
        snowobj.last_connected = workstationobj.last_connected

    if snowobj.last_connected != workstationobj.last_connected and datetime.datetime.strptime(snowobj.last_connected, '%Y-%m-%d %H:%M:%S') < datetime.datetime.strptime(workstationobj.last_connected, '%Y-%m-%d %H:%M:%S'):
        update_needed = True
        snowobj.last_connected = workstationobj.last_connected

        if workstationobj.internal_ip and snowobj.internal_ip != workstationobj.internal_ip:
            update_needed = True
            snowobj.internal_ip = workstationobj.internal_ip

        if workstationobj.external_ip and snowobj.external_ip != workstationobj.external_ip:
            update_needed = True
            snowobj.external_ip = workstationobj.external_ip

        if workstationobj.user and workstationobj.user not in snowobj.user.split(','):
            update_needed = True
            snowobj.user = snowobj.user + ',' + workstationobj.user

        if workstationobj.location and snowobj.location != workstationobj.location:
            update_needed = True
            snowobj.location = workstationobj.location

    if snowobj.encrypted != workstationobj.encrypted:
        update_needed = True
        snowobj.encrypted = workstationobj.encrypted

    if not snowobj.os:
        snowobj.os = workstationobj.os
        update_needed = True

    if snowobj.domain != workstationobj.domain:
        snowobj.domain = workstationobj.domain
        update_needed = True

    if snowobj.sccm_present != workstationobj.sccm_present:
        update_needed = True
        snowobj.sccm_present = workstationobj.sccm_present

    return update_needed, snowobj


@click.command()
@click.option("-d", "--duration", default=30, show_default=True, nargs=1, type=int, required=False, help="Update Active Workstations Table in Service Now for all workstation that were last seen since 'duration' days")
def main(duration):

    # Fetch all active workstations in the past 30 days from SCCM
    sccm_devices, sccm_devices_with_serial_numbers = sccm.fetch_devices(duration)

    # Push all workstations to service now cmdb
    if sccm_devices:
        # Get all workstation from Computers table
        total_count = active_workstations_service_now.get_assets_total()
        if int(total_count) > 0:
                workstations_from_service_now = active_workstations_service_now.fetch_categorized_workstations(total_count, sccm_devices_with_serial_numbers)

                records_that_need_to_be_updated = []
                records_that_need_to_be_created = []
                logger.info('Checking if devices from aggregator are present in service now table or not')
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    for asset, status in zip(sccm_devices.keys(), executor.map(lambda asset: divide_devices_based_on_insert_or_update(asset, workstations_from_service_now.keys()), sccm_devices.keys())):
                        if status[0]:
                            records_that_need_to_be_updated.append(asset)
                        if status[1]:
                            records_that_need_to_be_created.append(asset)

                # A list of service now devices that need to be updated
                devices_that_need_to_be_updated = []
                if records_that_need_to_be_updated:
                    logger.info('Checking if the device actually needs to be modified in service now table')
                    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                        for update_needed, snowobj in executor.map(lambda asset: update_service_now_workstation(workstations_from_service_now[asset], sccm_devices[asset]), records_that_need_to_be_updated):
                            if update_needed:
                                devices_that_need_to_be_updated.append(snowobj)

                # A list of devices that need to be created in Service Now
                if records_that_need_to_be_created:
                    logger.info("Devices that need to be added to the table: %d" % len(records_that_need_to_be_created))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                        for asset in records_that_need_to_be_created:
                            executor.submit(active_workstations_service_now.insert_asset_data, sccm_devices[asset])

                if devices_that_need_to_be_updated:
                    logger.info("Devices that need to be modified in the table: %d" % len(devices_that_need_to_be_updated))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                        for asset in devices_that_need_to_be_updated:
                            executor.submit(active_workstations_service_now.update_asset_data, asset)

        else:
            # Create new devices in service now from all devices in the aggregator
            logger.info("Active Workstations is completely empty. Filling up the devices from the aggregator")
            logger.info("Devices that need to be added to the table: %d" % len(sccm_devices))
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                for asset in sccm_devices.keys():
                    executor.submit(active_workstations_service_now.insert_asset_data, sccm_devices[asset])

            # Cross check if all deivces were created
            total_count = active_workstations_service_now.get_assets_total()
            if int(total_count) == len(sccm_devices):
                logger.info('Completed adding all devices into the table')
            else:
                logger.info('Devices skipped while adding to table: %d' % (len(sccm_devices) - int(total_count)))


if __name__ == "__main__":
    main()
