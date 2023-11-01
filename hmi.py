# TODO: Send departure data to the gui
# TODO: changing departure time should update in the gui
# TODO: data should be available in hmi
# TODO: should be able to add a new train

import json
from datetime import datetime, timedelta
import asyncio
import multiprocessing
import logging
import requests
import hashlib
import secrets
import os

from pymodbus import __version__ as pymodbus_version
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.server import StartAsyncTlsServer

from cryptography.fernet import Fernet

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s', level=logging.INFO)
_logger = logging.getLogger(__file__)

# Modbus variables
datastore_size = 110  # cant be bigger than 125
modbus_port = 12345

cert = r"cert.pem"
key = r"key.pem"

train_sent_away = False
lock = asyncio.Lock()
arrival_file_mutex = asyncio.Lock()
departure_file_mutex = asyncio.Lock()

last_acquired_switch = datetime.now() - timedelta(minutes=5)
departure_event = asyncio.Event()
arrival_event = asyncio.Event()

wake_arrival = asyncio.Event()
wake_departure = asyncio.Event()

track1 = asyncio.Event()
track2 = asyncio.Event()
track3 = asyncio.Event()
track4 = asyncio.Event()
track5 = asyncio.Event()
track6 = asyncio.Event()

track_status = [track1, track2, track3, track4, track5, track6]  # this is the track_status that the trains use when deciding on a track.
real_track_status = ["Available"]*6  # this is the actual representation if a track is available or not (attack control)

switch_status = 1  # 0 - 6

modbus_data_queue = multiprocessing.Queue()


async def modbus_server_thread(context: ModbusServerContext) -> None:
    """Creates the server that will listen at localhost"""

    identity = ModbusDeviceIdentification(
        info_name={
            "VendorName": "Pymodbus",
            "ProductCode": "PM",
            "VendorUrl": "https://github.com/pymodbus-dev/pymodbus/",
            "ProductName": "Pymodbus Server",
            "ModelName": "Pymodbus Server",
            "MajorMinorRevision": pymodbus_version,
        }
    )

    address = ("localhost", modbus_port)

    await StartAsyncTlsServer(
        context=context,
        host="host",
        identity=identity,
        address=address,
        framer=ModbusTlsFramer,
        certfile=cert,
        keyfile=key,
    )


def setup_server() -> ModbusServerContext:
    """Generates our holding register for the server"""
    # global context
    datablock = ModbusSequentialDataBlock(0x00, [0] * datastore_size)
    context = ModbusSlaveContext(
        di=datablock, co=datablock, hr=datablock, ir=datablock)
    context = ModbusServerContext(slaves=context, single=True)

    _logger.debug("Created datastore")
    return context


async def handle_simulation_communication(context: ModbusServerContext) -> None:
    """Takes data from queue and sends to client"""
    global last_acquired_switch
    global switch_status
    global modbus_data_queue
    global train_sent_away

    loop = asyncio.get_event_loop()
    switch_queue = asyncio.Queue()

    func_code = 3  # function code for modbus that we want to read and write data from holding register
    slave_id = 0x00  # we broadcast the data to all the connected slaves
    address = 0x00  # the address to where we want to write in the holding register
    prior_data = ""
    prior_signature = ""
    data_sent = 0
    secret_key = b"b$0!9Lp^z2QsE1Yf"

    # overwrite old data in json file
    try:
        os.remove("departure.json")
        os.remove("arrival.json")
    except FileNotFoundError:
        pass

    # we then start the tasks and this process continues with the above things
    loop.create_task(update_departure())
    loop.create_task(update_arrival())

    # wait so we have time to update the json files
    await asyncio.sleep(10)

    async with arrival_file_mutex:
        with open('arrival.json', 'r') as json_file:
            json_data = json.load(json_file)

    current_time = datetime.now()
    entries_to_remove = 0
    for entry in json_data[:2]:
        # Parse the estimated time from the entry
        estimated_time = datetime.strptime(entry["EstimatedTime"], "%Y-%m-%d %H:%M")

        # Check if the estimated time is less than the current time
        if estimated_time < current_time:
            real_track_status[int(entry['TrackAtLocation'])] = "occupied"
            track_status[int(entry['TrackAtLocation'])].set()
            entries_to_remove += 1
        else:
            break

    for i in range(entries_to_remove):
        json_data.pop(0)

    async with arrival_file_mutex:
        with open('arrival.json', 'w') as json_file:
            json.dump(json_data, json_file, indent=2)

    loop.create_task(arrival())
    loop.create_task(departure())
    loop.create_task(acquire_switch(switch_queue))

    # wait until client has connected
    while context[slave_id].getValues(func_code, datastore_size - 2, 1) == [0]:
        _logger.info("Waiting for client to connect; sleeping 2 second")
        await asyncio.sleep(2)  # give the server control so it can answer the client

    while True:
        # Run blocking call in executor so all the other tasks can run and the server
        data = await loop.run_in_executor(None, modbus_data_queue.get)

        # A: Adds a new train to the timetable in the gui.
        # Packet: ["A", "AdvertisedTime", "EstimatedTime", "ToLocation", "Track"]

        # a: A "status" message that a train has arrived at the station. Updates the real track status. Attack helper.
        # Packet: ["a", track]

        # s: helps handling the request for the switch and updates last acquired switch time.
        # Packet: ["s", func_code, "track_number", (func_code 1 only) "arrival time"]
        # func_code: 0: departure, 1: arrival, 2: HMI

        # S: Sends the new status of the switch to the gui.
        # Packet: ["S", "switch_status"]

        # r: Removes a train from the station. Checks whether the switch was in the correct posititon or not
        # Packet ["r", track, "AdvertisedTime"]

        # R: sends a remove train message to the gui.
        # Packet ["R", "AdvertisedTime"]

        # P: Sends a problem message to the gui, that an attack has happened.
        # Packet ["P", "message"]

        # t: message from the hmi to change track status, to the simulation
        # Packet ["t", track, "status"]  --> track is an int

        # T: message to gui to change track status
        # Packet ["T", "track", "status"]

        # u: update the departure track in the json file for a specific train
        # Paket ["u", "AdvertisedTime", "track"]

        # U: update the departure track in the gui
        # Packet ["U", "AdvertisedTime", "track"]

        # K: update the key for the gui
        # Packet ["K", b"key", b"encrypted new key"]

        match data[0]:
            case "a":
                _logger.info("Received arrival update from a train")

                if real_track_status[switch_status] == "occupied":
                    # we have a crash since we tried to drive into a already occupied track
                    modbus_data_queue.put(["P", "A train collided while trying to drive into the station"])
                else:
                    real_track_status[switch_status] = "occupied"

                if switch_status != data[1]:
                    _logger.info("Updating track in json, due to switch being to another track")

                    async with arrival_file_mutex:
                        with open('arrival.json', 'r+') as json_file:
                            json_data = json.load(json_file)
                            json_data[0]["TrackAtLocation"] = str(switch_status)
                            json_file.seek(0)
                            json.dump(json_data, json_file, indent=2)

                    modbus_data_queue.put(["u", json_data[0]["AdvertisedTime"], str(switch_status)])
            case "s":
                # TODO: changing departure time should update in the gui
                if data[1] == 2:
                    _logger.info("Received switch update from hmi")
                    switch_status = int(data[2])
                    last_acquired_switch = datetime.now()
                    modbus_data_queue.put(["S", data[2]])
                else:
                    _logger.info("Received switch update from simulation")
                    await switch_queue.put(data[1:])

                    difference = (last_acquired_switch - datetime.now()).total_seconds()
                    update_time = (5 * switch_queue.qsize() + difference) // 60  # Convert to minutes

                    # Format update_time as hh:mm
                    formatted_time = "{:02d}:{:02d}".format(int(update_time // 60), int(update_time % 60))

                    if data[1] == 0:
                        async with arrival_file_mutex:
                            with open("arrival.json", "r") as json_file:
                                json_data = json.load(json_file)

                        if formatted_time <= json_data[0]:
                            formatted_time = json_data[0] + timedelta(minutes=5)

                        async with departure_file_mutex:
                            with open('departure.json', 'r+') as json_file:
                                json_data = json.load(json_file)
                                json_data[0]["EstimatedTime"] = formatted_time
                                json.dump(json_data, json_file, indent=2)
                    else:
                        async with arrival_file_mutex:
                            with open('arrival.json', 'r+') as json_file:
                                json_data = json.load(json_file)
                                json_data[0]["EstimatedTime"] = formatted_time
                                json.dump(json_data, json_file, indent=2)

            case "r":
                _logger.info("Received removal wish")
                async with lock:
                    train_sent_away = True

                if switch_status != data[1]:
                    modbus_data_queue.put(
                        ["P", "A train had greenlight and was allowed to leave but switch was in the wrong position"])

                async with departure_file_mutex:
                    with open('departure.json', 'r+') as json_file:
                        json_data = json.load(json_file)
                        json_data.pop(0)
                        json.dump(json_data, json_file, indent=2)

                # clear track
                track_status[data[1]].clear()
                real_track_status[data[1]] = "available"
                modbus_data_queue.put("R", data[2])
            case "t":
                track_status[data[1]] = data[2]
            case "u":
                async with departure_file_mutex:
                    with open("arrival.json", "r+") as json_file:
                        json_data = json.load(json_file)

                        for i in range(len(json_data)):
                            if json_data[i]["AdvertisedTime"] == data[1]:
                                json_data[i]["TrackAtLocation"] = data[2]
                                modbus_data_queue.put(["U", json_data[i]["AdvertisedTime"], json_data[i]["TrackAtLocation"]])

                        json_file.seek(0)
                        json.dump(json_data, json_file, indent=2)
            case _:
                data_sent += 1

                # holding register should now contain [amount to read, [Packet], nonce, signature]
                sha256 = hashlib.sha256()

                if data[0] == "K":
                    temp = secret_key
                    secret_key = data[1]

                    data = "K " + " ".join(str(value.decode("utf-8")) for value in data[2:])
                    signature = data + temp.decode("utf-8")
                else:
                    data = " ".join(str(value) for value in data)
                    signature = data + secret_key.decode("utf-8") + str(data_sent)

                sha256.update(signature.encode("utf-8"))
                signature = sha256.hexdigest()
                nonce = [char for char in secrets.token_bytes(2) if char != 32]

                data = [len(data)] + [ord(char) for char in data] + [32] + nonce + [32] + [char for char in signature]

                sha256 = hashlib.sha256()
                expected_signature = bytes(nonce) + secret_key
                sha256.update(expected_signature)
                expected_signature = sha256.hexdigest()

                # continue sending old data until the client writes the correct signature
                while True:
                    # wait until the client has read the data
                    while context[slave_id].getValues(func_code, datastore_size - 2, 1) == [0]:
                        _logger.debug("Waiting for client to copy datastore; sleeping 2 second")
                        await asyncio.sleep(2)  # give the server control so it can answer the client

                    if context[slave_id].getValues(func_code, 0, 32) == [prior_signature]:
                        break

                    _logger.warning("Wrong signature tried to validate data in the holding register")
                    context[slave_id].setValues(func_code, address, prior_data)
                    _logger.info("Resetting flag")
                    context[slave_id].setValues(func_code, datastore_size - 2, [0])

                _logger.debug("Client has read data from datastore, writing new data")
                context[slave_id].setValues(func_code, address, data)

                _logger.info("Resetting flag")
                context[slave_id].setValues(func_code, datastore_size - 2, [0])

                prior_data = data
                prior_signature = expected_signature

                if data_sent == 100:
                    await update_keys(secret_key)
                    data_sent = 0


def modbus_helper() -> None:
    """Sets up server and send data task"""
    loop = asyncio.new_event_loop()
    context = setup_server()

    loop.create_task(handle_simulation_communication(context))
    loop.run_until_complete(modbus_server_thread(context))

    return


async def departure() -> None:
    """Simulates control for departing trains from the train station.
    Tries to acquire the switch so it is at the correct track and then remove the train from the list."""
    global train_sent_away
    global lock

    while True:
        try:
            async with departure_file_mutex:
                with open('departure.json', 'r') as json_file:
                    json_data = json.load(json_file)

                async with lock:
                    train_sent_away = False
        except (FileNotFoundError, json.JSONDecodeError):
            _logger.error("Cannot find or decode file")

        if json_data:
            # Extract information from the first entry in the json_data list
            first_entry = json_data[0]
            estimated_time = datetime.strptime(first_entry['EstimatedTime'], "%Y-%m-%d %H:%M")

            # Calculate the time difference until the estimated departure time and sleep until 5 minutes before arrival
            difference = estimated_time - datetime.now()

            _, pending = await asyncio.wait([asyncio.sleep(max(0, difference.total_seconds() - 5 * 60)), wake_departure.wait()],
                                            return_when=asyncio.FIRST_COMPLETED)

            if wake_departure.is_set():
                wake_departure.clear()
                continue

            # Check if the train has already been sent away
            async with lock:
                if train_sent_away:
                    _logger.debug("Train sent away already")
                    train_sent_away = False
                    continue

            # Put a message in the modbus_data_queue to control the switch
            modbus_data_queue.put(["s", 0, first_entry['TrackAtLocation']])

            # Wait for the departure_event signal
            await departure_event.wait()
            departure_event.clear()

            # Check again if the train has been sent away during the waiting period
            async with lock:
                if train_sent_away:
                    _logger.debug("Train sent away already")
                    train_sent_away = False
                    continue

            try:
                async with departure_file_mutex:
                    with open('departure.json', 'r') as json_file:
                        json_data = json.load(json_file)
            except (FileNotFoundError, json.JSONDecodeError):
                _logger.error("Cannot find or decode file")

            if json_data:
                # Retrieve the updated first entry after waiting for the departure event
                first_entry = json_data[0]
                updated_estimated_time = datetime.strptime(first_entry['EstimatedTime'], "%Y-%m-%d %H:%M")

                # Check if the estimated time has been updated or if the current time is greater than the estimated time
                if updated_estimated_time > estimated_time or datetime.now() > updated_estimated_time:
                    # Wait 20 seconds before leaving
                    await asyncio.sleep(20)

                    async with lock:
                        if train_sent_away:
                            _logger.debug("Train sent away already")
                            train_sent_away = False
                            continue

                    # Put a message in the modbus_data_queue to indicate train departure
                    modbus_data_queue.put(["r", int(first_entry["TrackAtLocation"]), first_entry['AdvertisedTime']])

                    # Remove the first entry from the json_data list
                    json_data.pop(0)

                    # Update the 'departure.json' file with the modified json_data
                    async with departure_file_mutex:
                        with open('departure.json', 'w') as json_file:
                            json_file.write(json.dumps(json_data, indent=2))
                else:
                    # Otherwise wait until the updated estimated time to leave
                    difference = updated_estimated_time - datetime.now()
                    await asyncio.sleep(difference.total_seconds())

                    async with lock:
                        if train_sent_away:
                            _logger.debug("Train sent away already")
                            train_sent_away = False
                            continue

                    # Put a message in the modbus_data_queue to indicate train departure
                    modbus_data_queue.put(["r", int(first_entry["TrackAtLocation"]), first_entry['AdvertisedTime']])

                    # Remove the first entry from the json_data list
                    json_data.pop(0)

                    # Update the 'departure.json' file with the modified json_data
                    async with departure_file_mutex:
                        with open('departure.json', 'w') as json_file:
                            json_file.write(json.dumps(json_data, indent=2))
        else:
            _logger.error("No entry found in json file: departure.json")


async def arrival() -> None:
    while True:
        try:
            # Attempt to read data from the 'arrival.json' file
            async with arrival_file_mutex:
                with open('arrival.json', 'r') as json_file:
                    json_data = json.load(json_file)
        except (FileNotFoundError, json.JSONDecodeError):
            # Handle file not found or JSON decoding errors and log an error message
            _logger.error("Error reading arrival.json file.")

        if json_data:
            # Extract information from the first entry in the JSON data
            first_entry = json_data[0]
            estimated_time = datetime.strptime(first_entry['EstimatedTime'], "%Y-%m-%d %H:%M")

            # Calculate the time difference between estimated time and current time
            difference = (estimated_time - datetime.now()).total_seconds()

            # Sleep until 5 minutes before estimated time
            _, pending = await asyncio.wait([asyncio.sleep(max(0, difference - 5 * 60)), wake_arrival.wait()],
                                            return_when=asyncio.FIRST_COMPLETED)

            if wake_arrival.is_set():
                wake_arrival.clear()
                continue

            # Retrieve the track number from the JSON data
            track_number = int(first_entry['TrackAtLocation'])

            if not track_status[track_number - 1].is_set():
                # If the track is available, occupy it and update track status
                _logger.info("Track was available for arrival")
                modbus_data_queue.put(["s", 1, str(track_number), first_entry['AdvertisedTime']])
                modbus_data_queue.put(["t", track_number, "occupied"])
            else:
                for i in range(1, 7):
                    if not track_status[(i-1) % 2].is_set():
                        # If the alternate track is available, occupy it and update track status
                        _logger.info("Original track wasn't available, chose another track instead")
                        track_number = (i - 1) % 2 + 1
                        json_data[0]['TrackAtLocation'] = str(track_number)
                        modbus_data_queue.put(["t", track_number, "occupied"])
                        modbus_data_queue.put(["s", 1, str(track_number), first_entry['AdvertisedTime']])

                        # Update the track information in depafirture
                        modbus_data_queue.put(["U", first_entry['AdvertisedTime'], str(track_number)])
                        break

                    # await the departure of a train to be able to get a track
                    _logger.info("No track available. Waiting for a clear track")
                    # TODO fix for 6 tracks
                    _, pending = await asyncio.wait([track_status[0].wait(), track_status[1].wait()],
                                                    return_when=asyncio.FIRST_COMPLETED)

                    _logger.info("Track found")
                    for event in pending:
                        event.clear()

                if not track_status[track_number - 1].is_set():
                    # If the track is available, occupy it and update track status
                    _logger.info("Track was available for arrival")
                    modbus_data_queue.put(["s", 1, str(track_number), first_entry['AdvertisedTime']])
                    modbus_data_queue.put(["t", track_number, "occupied"])
                else:
                    for i in range(6):
                        if not track_status[(i - 1) % 2].is_set():
                            # If the alternate track is available, occupy it and update track status
                            _logger.info("Original track wasn't available, chose another track instead")
                            track_number = (i - 1) % 2 + 1
                            json_data[0]['TrackAtLocation'] = str(track_number)
                            modbus_data_queue.put(["t", track_number, "occupied"])
                            modbus_data_queue.put(["s", 1, str(track_number), first_entry['AdvertisedTime']])

                            # Update the track information in depafirture
                            modbus_data_queue.put(["U", first_entry['AdvertisedTime'], str(track_number)])
                            break

            # Wait for the arrival event
            await arrival_event.wait()
            _logger.info("Clear to arrive")
            arrival_event.clear()

            try:
                # Read the updated data from 'arrival.json'
                async with arrival_file_mutex:
                    with open('arrival.json', 'r') as json_file:
                        json_data = json.load(json_file)
            except (FileNotFoundError, json.JSONDecodeError):
                # Handle file not found or JSON decoding errors and log an error message
                _logger.error("Error reading arrival.json file.")

            if json_data:
                # Extract information from the updated first entry in the JSON data
                first_entry = json_data[0]
                updated_estimated_time = datetime.strptime(first_entry['EstimatedTime'], "%Y-%m-%d %H:%M")

                # Wait for 20 seconds if the train is late, or wait until the new estimated time
                if updated_estimated_time > datetime.now():
                    _logger.info("Train is late, arriving in 20 seconds")
                    await asyncio.sleep(20)
                else:
                    difference = (updated_estimated_time - datetime.now()).total_seconds()
                    _logger.info("Train is planned to arrive at the estimated tine")
                    await asyncio.sleep(max(0, difference))

                # Send an update that the train has now arrived
                modbus_data_queue.put(["a", track_number])


async def acquire_switch(switch_queue: asyncio.Queue) -> None:
    """Empties the switch queue and keeps track of when the switch will be available, then notifies the correct function."""
    while True:
        # switch_queue should contain [func_code, track_number]  departure: 0, arrival: 1
        func_codes = [departure_event, arrival_event]

        # Wait until a request to change the switch status has arrived
        data = await switch_queue.get()

        # Arrival and departure don't have precedence over each other, so if anyone has acquired the switch, wait
        difference = last_acquired_switch + timedelta(minutes=5) - datetime.now()

        while difference > timedelta(minutes=0):
            _logger.info("Currently waiting for the switch to be available again")
            _logger.info(f"next check in {int(difference.total_seconds()) % 60} minutes")
            await asyncio.sleep(difference.total_seconds())
            difference = last_acquired_switch + timedelta(minutes=5) - datetime.now()

        # Notify the corresponding function (departure_event or arrival_event) to acquire the switch
        func_codes[int(data[0])].set()

        # Send an update message to the GUI
        modbus_data_queue.put(["S", str(switch_status)])


async def update_arrival() -> None:
    """Updates arrival.json every 15 minutes with new trains and update estimated time for all the trains"""
    xml_arrival = """<REQUEST>
                <LOGIN authenticationkey='eb2fa89aebd243cb9cba7068aac73244'/> 
                <QUERY objecttype='TrainAnnouncement' orderby='AdvertisedTimeAtLocation' schemaversion='1'>
                    <FILTER>
                        <AND>
                            <OR>
                                <AND>
                                    <GT name='AdvertisedTimeAtLocation' value='$dateadd(00:00:00)' /> 
                                    <LT name='AdvertisedTimeAtLocation' value='$dateadd(02:00:00)' />
                                </AND>
                                <GT name='EstimatedTimeAtLocation' value='$now' />
                            </OR>
                            <EQ name='LocationSignature' value='ck' />
                            <EQ name='ActivityType' value='Ankomst' />
                        </AND>
                    </FILTER>
                    <INCLUDE>AdvertisedTimeAtLocation</INCLUDE>
                    <INCLUDE>EstimatedTimeAtLocation</INCLUDE>
                    <INCLUDE>TrackAtLocation</INCLUDE>
                </QUERY>
                </REQUEST>"""
    headers = {'Content-Type': 'text/xml'}

    def update_existing_data(new_data) -> list:
        # Add new entries that don't exist in the existing data
        new_entries = [new_train for new_train in new_data
                       if not any(existing_train['AdvertisedTime'] == new_train['AdvertisedTime']
                                  for existing_train in existing_data) and new_train['TrackAtLocation'] != "-"]

        # Combine existing data and new entries
        updated_data = existing_data + new_entries

        return updated_data

    try:
        async with arrival_file_mutex:
            with open('arrival.json', 'r') as json_file:
                existing_data = json.load(json_file)
    except (FileNotFoundError, json.JSONDecodeError):
        _logger.warning("update_arrival: found no prior arrival file")
        existing_data = []

    new_api_response = requests.post('https://api.trafikinfo.trafikverket.se/v2/data.json', data=xml_arrival,
                                     headers=headers).content

    # Check if the API response is not None
    if new_api_response is not None:
        # Load new data from the API response
        new_response_dict = json.loads(new_api_response.decode('utf-8'))
        new_train_info_list = new_response_dict['RESPONSE']['RESULT'][0]['TrainAnnouncement']

        # Convert new data to the desired format
        new_formatted_data = []

        for new_train_info in new_train_info_list:
            advertised_time = datetime.strptime(new_train_info['AdvertisedTimeAtLocation'],
                                                "%Y-%m-%dT%H:%M:%S.%f%z").strftime("%Y-%m-%d %H:%M")
            estimated_time = datetime.strptime(
                new_train_info.get('EstimatedTimeAtLocation', new_train_info['AdvertisedTimeAtLocation']),
                "%Y-%m-%dT%H:%M:%S.%f%z").strftime("%Y-%m-%d %H:%M")
            if datetime.now().hour <= int(advertised_time.split()[1].split(":")[0]):

                if new_train_info['TrackAtLocation'] != "-":
                    train_data = {
                        'AdvertisedTime': advertised_time,
                        'EstimatedTime': estimated_time,
                        'TrackAtLocation': new_train_info['TrackAtLocation']
                    }

                    new_formatted_data.append(train_data)

        # Update existing data with new data
        updated_data = update_existing_data(new_formatted_data)

        # Save updated data to the JSON file
        async with arrival_file_mutex:
            with open('arrival.json', 'w') as json_file:
                json.dump(updated_data, json_file, indent=2)

        _logger.info("Updated values in arrival.json")
    else:
        _logger.error("API response was None")

    _logger.info(f"Sleeping 15 minutes. Next update {(datetime.now() + timedelta(minutes=15)).strftime("%H:%M")}")
    await asyncio.sleep(15 * 60)


async def update_departure() -> None:
    """Updates departure.json every 4 hour, won't remove anything just update with new trains"""
    xml_departure = """<REQUEST>
    <LOGIN authenticationkey='eb2fa89aebd243cb9cba7068aac73244'/> 
    <QUERY objecttype='TrainAnnouncement' orderby='AdvertisedTimeAtLocation' schemaversion='1'>
        <FILTER>
            <AND>
                <OR>
                    <AND>
                        <GT name='AdvertisedTimeAtLocation' value='$dateadd(-00:15:00)' /> 
                        <LT name='AdvertisedTimeAtLocation' value='$dateadd(08:00:00)' />
                    </AND>
                    <GT name='EstimatedTimeAtLocation' value='$now' />
                </OR>
                <EQ name='LocationSignature' value='ck' />
                <EQ name='ActivityType' value='Avgang' />
            </AND>
        </FILTER>
        <INCLUDE>AdvertisedTimeAtLocation</INCLUDE>
        <INCLUDE>TrackAtLocation</INCLUDE>
        <INCLUDE>ToLocation</INCLUDE>
    </QUERY>
    </REQUEST>"""

    headers = {'Content-Type': 'text/xml'}

    def update_existing_data(new_data) -> list:
        # Add new entries that don't exist in the existing data
        new_entries = [new_train for new_train in new_data
                       if not any(existing_train['AdvertisedTime'] == new_train['AdvertisedTime']
                                  for existing_train in existing_data) and new_train['TrackAtLocation'] != "-"]

        # Combine existing data and new entries
        updated_data = existing_data + new_entries

        return updated_data

    # Load existing data from the previous JSON file or create an empty list if the file doesn't exist
    try:
        async with departure_file_mutex:
            with open('departure.json', 'r') as json_file:
                existing_data = json.load(json_file)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []

    new_api_response = requests.post('https://api.trafikinfo.trafikverket.se/v2/data.json', data=xml_departure,
                                     headers=headers).content

    # Check if the API response is not None
    if new_api_response is not None:
        # Load new data from the API response
        new_response_dict = json.loads(new_api_response.decode('utf-8'))
        new_train_info_list = new_response_dict['RESPONSE']['RESULT'][0]['TrainAnnouncement']

        # Convert new data to the desired format
        new_formatted_data = []

        for new_train_info in new_train_info_list:
            advertised_time = datetime.strptime(new_train_info['AdvertisedTimeAtLocation'],
                                                "%Y-%m-%dT%H:%M:%S.%f%z").strftime("%Y-%m-%d %H:%M")
            estimated_time = datetime.strptime(
                new_train_info.get('EstimatedTimeAtLocation', new_train_info['AdvertisedTimeAtLocation']),
                "%Y-%m-%dT%H:%M:%S.%f%z").strftime("%Y-%m-%d %H:%M")

            to_location = ["Köpenhamn" if "Dk.kh" in new_train_info.get("ToLocation", []) else "Emmaboda"]

            track_at_location = new_train_info.get('TrackAtLocation', '')

            if track_at_location != "-":
                train_data = {
                    'AdvertisedTime': advertised_time,
                    'EstimatedTime': estimated_time,
                    'ToLocation': to_location,
                    'TrackAtLocation': track_at_location
                }

                new_formatted_data.append(train_data)

        # Update existing data with new data
        updated_data = update_existing_data(new_formatted_data)

        # Save updated data to the JSON file
        async with departure_file_mutex:
            with open('departure.json', 'w') as json_file:
                json.dump(updated_data, json_file, indent=2)

        _logger.info("Data has been updated in departure.json")
    else:
        _logger.error("API response is None. Check for issues with the API call.")

    _logger.info(f"Sleeping 4 hours. Next update {(datetime.now() + timedelta(hours=4)).strftime("%H:%M")}")
    await asyncio.sleep(4 * 60 * 60)


async def update_keys(secret_key: bytes) -> None:
    new_key = Fernet.generate_key()
    cipher = Fernet(secret_key)
    encrypted_message = cipher.encrypt(new_key)

    modbus_data_queue.put(["K", new_key, encrypted_message])


if __name__ == '__main__':
    modbus_process = multiprocessing.Process(target=modbus_helper)
    modbus_process.start()

    while True:
        pass

    modbus_process.join()
