from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
import bcrypt

import modules as SQL
import bisect
import json
from datetime import datetime, timedelta
import asyncio
import multiprocessing
import logging
import hashlib
import secrets
import os
import hmac
from typing import Union, List
import base64
import aiohttp

from pymodbus import __version__ as pymodbus_version
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.server import StartAsyncTlsServer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s', level=logging.INFO)
_logger = logging.getLogger(__file__)

# Modbus variables
datastore_size = 124  # cant be bigger than 125
modbus_port = 12345

cert = r"cert.pem"
key = r"key.pem"

arrival_file_mutex = asyncio.Lock()
departure_file_mutex = asyncio.Lock()
mutex = multiprocessing.Lock()

last_acquired_switch = datetime.now() - timedelta(minutes=3)

departure_event = asyncio.Event()
arrival_event = asyncio.Event()
serving_departure = asyncio.Event()
serving_arrival = asyncio.Event()
arrival_switch_request = asyncio.Event()
departure_switch_request = asyncio.Event()
wake_arrival = asyncio.Event()
wake_departure = asyncio.Event()
give_up_switch = asyncio.Event()

track_semaphore = asyncio.Semaphore(value=6)
track_status_sim = [0] * 6  # this is the track_status that the trains use when deciding on a track.

switch_lock = asyncio.Lock()
switch_status = 1  # 1 - 6
entries_in_gui = 0
send_data = asyncio.Event()

modbus_data_queue = multiprocessing.Queue()

app = Flask(__name__)
app.logger.setLevel(logging.ERROR)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Sessions för login
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

login_manager = LoginManager()
login_manager.init_app(app)

departure_file_version = 0
arrival_file_version = 0
file_secret_key = Fernet.generate_key()

# TODO: we have an attack where we either change the diffie hellman group to a much smaller group and we attack the key.
# TODO: or we can do a man in the middle attack and generate two sets of keys. One key for the hmi and one key for the gui.
# TODO. all the messages will then be decrypted and encrypted again in the man in the middle

# TODO remove tls from modbus?. We can't have a man in the middle otherwise because the packets will be encrypted
# TODO otherwise we have to spam the modbus server and try to change the values that way instead which modbus won't like


class Users(UserMixin):
    def __init__(self, username, password, is_active=True):
        self.id = 1
        self.username = username
        self.password = password
        self.is_active = is_active

    def get_id(self):
        return self.id

    def is_active(self, value):
        self.is_active = value
        return


@login_manager.user_loader
def loader_user(user_id):
    # Här måste vi löser ett säkrare sätt
    authenticate = SQL.checkAuthentication()

    user = Users(authenticate[0], authenticate[1])
    return user


@app.route('/', methods=["POST", "GET"])
def loginPage(invalid=False):
    if request.method == "POST":
        authenticate = SQL.checkAuthentication()

        # Här får vi data från loginet. Gör backend saker som kontroller etc
        user_credentials = {'username': request.form["username"], 'password': request.form["pwd"]}
        user = Users(user_credentials['username'], user_credentials['password'])

        if user.username == authenticate[0] and bcrypt.checkpw(user.password.encode(), authenticate[1].encode()):
            login_user(user)
            session['username'] = user.username
            json_data = open_json("data.json")
            json_data = logData(json_data, "User login", session['username'])
            writeToJson('data.json', json_data)
            return redirect(url_for('timetablePage'))
        else:
            invalid = True
            return render_template("login.html", invalid=invalid, loginPage=True)

    return render_template("login.html", invalid=invalid, loginPage=True)


@app.route('/timetable', methods=["POST", "GET"])
@login_required
def timetablePage(change=None):
    json_data = open_json("data.json")

    if request.method == "GET":
        json_data['trains'] = sortTimeTable(json_data['trains'])
        writeToJson('data.json', json_data)

    if request.method == "POST":
        button_clicked = request.form.get("button", False)

        if button_clicked:
            match button_clicked:
                case "addTimeForm":
                    change = "addTimeForm"

                case "deleteTimeForm":
                    change = "deleteTimeForm"

                case "addNewTime":
                    train_data = {
                        'trainNumber': request.form.get('trainNumber', False),
                        'time': request.form.get('departure', False),
                        'track': request.form.get('tracktype', False)}

                    json_data['trains'].append(train_data)
                    json_data = logData(json_data, "New entry in timetable",
                                        f"Train {train_data['trainNumber']} was added")

                    data = ["h", train_data["time"], train_data["time"], train_data['trainNumber'], train_data['track']]
                    modbus_data_queue.put(data)

                case "deleteTime":
                    id = int(request.form.get('id', False))
                    if id <= len(json_data['trains']):
                        json_data = logData(json_data, "Deleted entry in timetable",
                                            f"Train {json_data['trains'][id - 1]['trainNumber']} was deleted")
                        json_data['trains'].pop(id - 1)
                        data = ["g"] + [id - 1]
                        modbus_data_queue.put(data)

        writeToJson('data.json', json_data)
    return render_template("timetable.html", change=change, trainList=json_data['trains'])


@app.route('/logout')
@login_required
def logOutUser():
    logout_user()
    json_data = open_json("data.json")
    json_data = logData(json_data, "User logout", session['username'])
    print(json_data)
    writeToJson("data.json", json_data)
    return redirect(url_for("loginPage"))


@app.route('/railway', methods=["POST", "GET"])
@login_required
def railwayPage():
    json_data = open_json("data.json")

    track_status = json_data['trackStatus']
    current_trackStatus = json_data['currentTrackStatus']

    if request.method == "POST":
        button_clicked = request.form.get("button", False)
        if button_clicked:
            match button_clicked:

                case "track1":
                    if current_trackStatus['1'] == track_status[0]:
                        json_data['currentTrackStatus']['1'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 1 changed from Available to Occupied")
                    else:
                        json_data['currentTrackStatus']['1'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 1 changed from Occupied to Available")

                    data = ["t", 1, json_data['currentTrackStatus']['1'][0]]
                    modbus_data_queue.put(data)

                case "track2":
                    if current_trackStatus['2'] == track_status[0]:
                        json_data['currentTrackStatus']['2'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 2 changed from available to Occupied")
                    else:
                        json_data['currentTrackStatus']['2'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 2 changed from Occupied to Available")

                    data = ["t", 2, json_data['currentTrackStatus']['2'][0]]
                    modbus_data_queue.put(data)

                case "track3":
                    if current_trackStatus['3'] == track_status[0]:
                        json_data['currentTrackStatus']['3'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 3 changed from available to Occupied")
                    else:
                        json_data['currentTrackStatus']['3'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 3 changed from Occupied to Available")

                    data = ["t", 3, json_data['currentTrackStatus']['3'][0]]
                    modbus_data_queue.put(data)

                case "track4":
                    if current_trackStatus['4'] == track_status[0]:
                        json_data['currentTrackStatus']['4'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 4 changed from available to Occupied")
                    else:
                        json_data['currentTrackStatus']['4'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 4 changed from Occupied to Available")

                    data = ["t", 4, json_data['currentTrackStatus']['4'][0]]
                    modbus_data_queue.put(data)

                case "track5":
                    if current_trackStatus['5'] == track_status[0]:
                        json_data['currentTrackStatus']['5'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 5 changed from available to Occupied")
                    else:
                        json_data['currentTrackStatus']['5'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 5 changed from Occupied to Available")

                    data = ["t", 5, json_data['currentTrackStatus']['5'][0]]
                    modbus_data_queue.put(data)

                case "track6":
                    if current_trackStatus['6'] == track_status[0]:
                        json_data['currentTrackStatus']['6'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 6 changed from available to Occupied")
                    else:
                        json_data['currentTrackStatus']['6'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 6 changed from Occupied to Available")

                    data = ["t", 6, json_data['currentTrackStatus']['6'][0]]
                    modbus_data_queue.put(data)

        else:
            button_clicked = request.form.get('switchconnection', False)

            if button_clicked:
                tempSwitchData = json_data['switchStatus']
                json_data['switchStatus'] = "Track " + button_clicked
                json_data = logData(json_data, "Changed Switch Connection",
                                    f"Switch connection changed from {tempSwitchData} to {json_data['switchStatus']}")
                data = ["s", 2, button_clicked]
                modbus_data_queue.put(data)

        writeToJson('data.json', json_data)

    return render_template("railway.html", trackStatus=track_status, current_trackStatus=current_trackStatus,
                           switchStatus=json_data['switchStatus'])


@app.route('/logs')
@login_required
def logPage():
    json_data = open_json("data.json")

    return render_template("logs.html", logData=json_data['logs'])


def open_json(json_file):
    with mutex, open(json_file, 'r') as dataFile:
        json_data = json.load(dataFile)
    return json_data


def writeToJson(json_file, data_json):
    data_json = json.dumps(data_json, indent=3)
    with mutex, open(json_file, 'w') as dataFile:
        dataFile.write(data_json)


def logData(json_data, action, information):
    """Någon form utav erorr hantering"""
    try:
        currentDateTime = datetime.now()
        currentDateTime = currentDateTime.strftime('%Y-%m-%d || %H:%M:%S')
        logInformation = (f"[{currentDateTime}] Done by User: {session['username']}, Action: {action}, "
                          f"Information: {information}")

        json_data['logs'].append(logInformation)
    except:
        print("ERROR : List Index out of range")

    return json_data


def sortTimeTable(train_list):
    """Functions takes in a trainList with Dict in it"""
    now = datetime.now()
    cur_time = now.strftime("%H:%M")
    temp_train_list = sorted(train_list, key=lambda x: (x['time'] >= cur_time, x['time']))
    train_list = temp_train_list.copy()
    for train in train_list:
        if train['time'] > cur_time:
            break
        else:
            temp_train_list.append(train)
            temp_train_list.pop(0)

    train_list = temp_train_list

    return train_list


# ------------------------------- #
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


async def update_departure() -> None:
    """Updates departure.json every 1 hour, won't remove anything just update with new trains"""
    global modbus_data_queue

    while True:
        xml_departure = """<REQUEST>
        <LOGIN authenticationkey='eb2fa89aebd243cb9cba7068aac73244'/> 
        <QUERY objecttype='TrainAnnouncement' orderby='AdvertisedTimeAtLocation' schemaversion='1.8'>
            <FILTER>
                <AND>
                    <OR>
                        <AND>
                            <GT name='AdvertisedTimeAtLocation' value='$dateadd(00:00:00)' /> 
                            <LT name='AdvertisedTimeAtLocation' value='$dateadd(06:00:00)' />
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
            <INCLUDE>TrainOwner</INCLUDE>   
        </QUERY>
        </REQUEST>"""

        headers = {'Content-Type': 'text/xml'}

        def update_existing_data(new_data) -> list:
            updated_data = []
            removed_entries = []

            # Iterate over existing data
            for idx, existing_train in enumerate(existing_data):
                # Find the corresponding entry in new data based on time and train owner
                corresponding_entry = next(
                    (new_train for new_train in new_data if
                     datetime.strptime(existing_train['AdvertisedTime'], "%Y-%m-%d %H:%M") == datetime.strptime(
                         new_train['AdvertisedTime'], "%Y-%m-%d %H:%M")
                     and existing_train['TrainOwner'] == new_train['TrainOwner']),
                    None
                )

                if corresponding_entry:
                    if existing_train['IsRemoved']:
                        removed_entries.append(existing_train)
                        continue

                    # Check if the estimated time has changed
                    if (datetime.strptime(existing_train['EstimatedTime'], "%Y-%m-%d %H:%M") != datetime.strptime(
                            corresponding_entry['EstimatedTime'], "%Y-%m-%d %H:%M")):
                        if idx == 0:
                            if departure_switch_request.is_set():
                                # if the first departure entry already has asked for the switch, don't change its value
                                continue

                            # wake the departure function, so it uses the new estimated time instead
                            wake_departure.set()

                        # Update the estimated time for the existing entry with the new data
                        existing_train['EstimatedTime'] = corresponding_entry['EstimatedTime']

                        # check if we need to update the data in the gui
                        if idx < 4:
                            modbus_data_queue.put(["U", str(idx), existing_train['EstimatedTime'],
                                                   existing_train['TrackAtLocation']])

                    updated_data.append(existing_train)
                else:
                    # If there is no corresponding entry, check if it's marked as removed
                    if not existing_train['IsRemoved']:
                        updated_data.append(existing_train)

            # Iterate over new data
            for new_train in new_data:
                # Check if there is no corresponding entry in existing data
                if all(existing_train['AdvertisedTime'] != new_train['AdvertisedTime'] or
                       existing_train['TrainOwner'] != new_train['TrainOwner']
                       for existing_train in existing_data):
                    updated_data.append(new_train)

            # Sort the updated entries based on the estimated time
            updated_data.sort(key=lambda x: x['EstimatedTime'])

            # Add entries with IsRemoved set to True to the end of the list
            updated_data.extend(removed_entries)

            return updated_data

        # Load existing data from the previous JSON file or create an empty list if the file doesn't exist
        existing_data = await read_from_file(1)

        async with aiohttp.ClientSession() as ses:
            async with ses.post('https://api.trafikinfo.trafikverket.se/v2/data.json', data=xml_departure,
                                headers=headers) as response:
                new_api_response = await response.read()

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

                to_location = "Köpenhamn" if any(location.get('LocationName') == 'Dk.kh' for location in
                                                 new_train_info.get("ToLocation", [])) else "Emmaboda"

                if new_train_info['TrackAtLocation'] != "-":
                    train_data = {
                        'AdvertisedTime': advertised_time,
                        'EstimatedTime': estimated_time,
                        'ToLocation': to_location,
                        'TrackAtLocation': new_train_info['TrackAtLocation'],
                        'TrainOwner': new_train_info['TrainOwner'],
                        'IsRemoved': False
                    }

                    new_formatted_data.append(train_data)

            # Update existing data with new data
            updated_data = update_existing_data(new_formatted_data)

            # Save updated data to the JSON file
            await write_to_file(updated_data, 1)
            await departure_to_data()

            _logger.info("Data has been updated in departure.json")
        else:
            _logger.error("API response is None. Check for issues with the API call.")

        _logger.info(f"Sleeping 1 hours. Next update {(datetime.now() + timedelta(hours=1)).strftime('%H:%M')}")
        await asyncio.sleep(1 * 60 * 60)


async def update_arrival() -> None:
    """Updates arrival.json every 15 minutes with new trains and update estimated time for all the trains"""
    while True:
        xml_arrival = """<REQUEST>
                    <LOGIN authenticationkey='eb2fa89aebd243cb9cba7068aac73244'/> 
                    <QUERY objecttype='TrainAnnouncement' orderby='AdvertisedTimeAtLocation' schemaversion='1.8'>
                        <FILTER>
                            <AND>
                                <OR>
                                    <AND>
                                        <GT name='AdvertisedTimeAtLocation' value='$dateadd(00:00:00)' /> 
                                        <LT name='AdvertisedTimeAtLocation' value='$dateadd(06:00:00)' />
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
                        <INCLUDE>TrainOwner</INCLUDE>
                    </QUERY>
                    </REQUEST>"""
        headers = {'Content-Type': 'text/xml'}

        def update_existing_data(new_data) -> list:
            updated_data = []
            removed_entries = []

            for idx, existing_train in enumerate(existing_data):
                # Find the corresponding entry in new data based on time and train owner
                corresponding_entry = next(
                    (new_train for new_train in new_data if
                     datetime.strptime(existing_train['AdvertisedTime'], "%Y-%m-%d %H:%M") == datetime.strptime(
                         new_train['AdvertisedTime'], "%Y-%m-%d %H:%M")
                     and existing_train['TrainOwner'] == new_train['TrainOwner']),
                    None
                )

                if corresponding_entry:
                    if existing_train['IsRemoved']:
                        removed_entries.append(existing_train)
                        continue

                    # Check if the estimated time has changed
                    if datetime.strptime(existing_train['EstimatedTime'], "%Y-%m-%d %H:%M") != datetime.strptime(
                            corresponding_entry['EstimatedTime'], "%Y-%m-%d %H:%M"):
                        if idx == 0:
                            if arrival_switch_request.is_set():
                                # if the first departure entry already has asked for the switch, don't change its value
                                continue

                            # wake the departure function, so it uses the new estimated time instead
                            wake_arrival.set()

                        # Update the estimated time for the existing entry with the new data
                        existing_train['EstimatedTime'] = corresponding_entry['EstimatedTime']

                    updated_data.append(existing_train)
                else:
                    if not existing_train['IsRemoved']:
                        updated_data.append(existing_train)

            for new_train in new_data:
                # Check if there is no corresponding entry in existing data
                if all(existing_train['AdvertisedTime'] != new_train['AdvertisedTime'] or
                       existing_train['TrainOwner'] != new_train['TrainOwner']
                       for existing_train in existing_data):
                    updated_data.append(new_train)

            updated_data.sort(key=lambda x: x['EstimatedTime'])

            # Add entries with IsRemoved set to True to the end of the list
            updated_data.extend(removed_entries)

            return updated_data

        existing_data = await read_from_file(0)

        async with aiohttp.ClientSession() as ses:
            async with ses.post('https://api.trafikinfo.trafikverket.se/v2/data.json', data=xml_arrival,
                                headers=headers) as response:
                new_api_response = await response.read()

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
                            'TrackAtLocation': new_train_info['TrackAtLocation'],
                            'TrainOwner': new_train_info['TrainOwner'],
                            'IsRemoved': False
                        }

                        new_formatted_data.append(train_data)

            # Update existing data with new data
            updated_data = update_existing_data(new_formatted_data)

            # Save updated data to the JSON file
            await write_to_file(updated_data, 0)

            _logger.info("Updated values in arrival.json")
        else:
            _logger.error("API response was None")

        _logger.info(f"Sleeping 15 minutes. Next update {datetime.now() + timedelta(minutes=15):%H:%M}")
        await asyncio.sleep(15 * 60)


async def arrival() -> None:
    """Simulates control for arriving trains to the train station.
    Tries to acquire the switch, so it is at the correct track and then notifies gui when it has arrived"""
    while True:
        json_data = await read_from_file(0)

        if json_data:
            # Extract information from the first entry in the JSON data
            first_entry = json_data[0]

            estimated_time = datetime.strptime(first_entry['EstimatedTime'], "%Y-%m-%d %H:%M")

            # Calculate the time difference between estimated time and current time
            difference = estimated_time - datetime.now()

            try:
                # Wait for the arrival event, with a timeout based on the estimated arrival time
                await asyncio.wait_for(wake_arrival.wait(), timeout=max(0, difference.total_seconds() - 2 * 60))
                wake_arrival.clear()
                _logger.info("Received a wakeup call")
                continue
            except asyncio.TimeoutError:
                pass

            # Retrieve the track number from the JSON data
            track_number = int(first_entry['TrackAtLocation'])
            has_changed_time = False

            if track_semaphore.locked():
                departure_data = await read_from_file(1)
                checked_trains = 0

                # Find the first departing train that matches the arrival train
                for train in departure_data:
                    if not train['IsRemoved']:
                        train_id = train['id']

                        corresponding_arrival = next(
                            (arrival_train for arrival_train in json_data if arrival_train['id'] == train_id),
                            None
                        )

                        if not corresponding_arrival:
                            first_entry['EstimatedTime'] = train['EstimatedTime']
                            # Update the departure time for the arrival train
                            await update_departure_time(first_entry['id'], datetime.strptime(
                                first_entry['EstimatedTime'], "%Y-%m-%d %H:%M"), has_changed_time)

                            has_changed_time = True
                            break

                        checked_trains += 1

                        if checked_trains >= 6:
                            break
                    else:
                        break

            await track_semaphore.acquire()

            if wake_arrival.is_set():
                wake_arrival.clear()
                continue

            first_entry['EstimatedTime'] = datetime.now().strftime("%Y-%m-%d %H:%M")

            # Update the departure time for the arrival train
            await update_departure_time(first_entry['id'], datetime.now(), has_changed_time)

            await write_to_file(json_data, 0)

            if wake_arrival.is_set():
                wake_arrival.clear()
                continue

            if track_status_sim[track_number - 1] == 0:
                # If the track is available, occupy it and update track status
                _logger.info("Track was available for arrival")
                arrival_switch_request.set()
                modbus_data_queue.put(["s", 1, str(track_number)])
                modbus_data_queue.put(["t", track_number, "O"])
            else:
                for i in range(6):
                    if track_status_sim[i] == 0:
                        # If the alternate track is available, occupy it and update track status
                        _logger.info("Original track wasn't available, chose another track instead")
                        track_number = i + 1
                        first_entry['TrackAtLocation'] = str(track_number)
                        arrival_switch_request.set()
                        modbus_data_queue.put(["s", 1, str(track_number)])
                        modbus_data_queue.put(["t", track_number, "O"])

                        await write_to_file(json_data, 0)

                        # Update the track information in departure
                        modbus_data_queue.put(["u", first_entry['id'], str(track_number)])
                        break

            await asyncio.sleep(0.5)

            # Wait for the arrival event
            await arrival_event.wait()
            _logger.info("Clear to arrive")
            arrival_event.clear()

            if wake_arrival.is_set():
                wake_arrival.clear()
                give_up_switch.set()
                continue

            json_data = await read_from_file(0)

            if json_data:
                # Extract information from the updated first entry in the JSON data
                first_entry = json_data[0]

                updated_estimated_time = datetime.strptime(first_entry['EstimatedTime'], "%Y-%m-%d %H:%M")

                # Wait for 20 seconds if the train is late, or wait until the new estimated time
                if updated_estimated_time > estimated_time:
                    wait = estimated_time - datetime.now()
                    await asyncio.sleep(max(0, wait.total_seconds()))

                    _logger.info("Train is late, arriving in 20 seconds")
                    await asyncio.sleep(20)
                else:
                    difference = (updated_estimated_time - datetime.now()).total_seconds()
                    _logger.info("Train is planned to arrive at the estimated tine")
                    await asyncio.sleep(max(0, difference))

                if wake_arrival.is_set():
                    wake_arrival.clear()
                    give_up_switch.set()
                    continue

                # Send an update that the train has now arrived
                modbus_data_queue.put(["a", first_entry['id'], first_entry['TrackAtLocation']])

                # remove train from pending arrivals
                del json_data[0]
                await write_to_file(json_data, 0)

                # sleep 0.5 seconds so we can send data to the gui so it will show that the train has arrived
                await asyncio.sleep(0.5)


async def departure() -> None:
    """Simulates control for departing trains from the train station.
    Tries to acquire the switch so it is at the correct track and then remove the train from the list."""
    while True:
        json_data = await read_from_file(1)

        if json_data:
            first_entry = json_data[0]

            estimated_time = datetime.strptime(first_entry['EstimatedTime'], "%Y-%m-%d %H:%M")

            # Calculate the time difference until the estimated departure time and sleep until 3 minutes before arrival
            difference = estimated_time - datetime.now()

            try:
                # sleep until 2 minutes before departure or if another train departs before this
                await asyncio.wait_for(wake_departure.wait(), timeout=max(0, difference.total_seconds() - 2 * 60))
                wake_departure.clear()
                _logger.debug("Function has been woken")
                continue
            except asyncio.TimeoutError:
                pass

            departure_switch_request.set()

            # Put a message in the modbus_data_queue to control the switch
            modbus_data_queue.put(["s", 0, first_entry['TrackAtLocation']])

            # Wait for the departure_event signal
            await departure_event.wait()
            departure_event.clear()

            # Check again if the train has been sent away during the waiting period
            if wake_departure.is_set():
                _logger.debug("Function has been woken")
                wake_departure.clear()
                give_up_switch.set()
                continue

            json_data = await read_from_file(1)

            if json_data:
                # Retrieve the updated first entry after waiting for the departure event
                first_entry = json_data[0]

                updated_estimated_time = datetime.strptime(first_entry['EstimatedTime'], "%Y-%m-%d %H:%M")

                # Check if the estimated time has been updated or if the current time is greater than the estimated time
                if updated_estimated_time > estimated_time:
                    wait = estimated_time - datetime.now()

                    await asyncio.sleep(max(0, wait.total_seconds()))
                    _logger.info("Train is late, leaving in 20 seconds")
                    await asyncio.sleep(20)

                    if wake_departure.is_set():
                        _logger.debug("Function has been woken")
                        wake_departure.clear()
                        give_up_switch.set()
                        continue

                    # Put a message in the modbus_data_queue to indicate train departure
                    modbus_data_queue.put(["r", int(first_entry["TrackAtLocation"]), first_entry['id']])
                    await asyncio.sleep(3)
                    give_up_switch.set()
                    await departure_to_data()
                else:
                    # Otherwise wait until the updated estimated time to leave
                    difference = updated_estimated_time - datetime.now()
                    await asyncio.sleep(max(difference.total_seconds(), 0))

                    if wake_departure.is_set():
                        _logger.debug("Function has been woken")
                        wake_departure.clear()
                        continue

                    # Put a message in the modbus_data_queue to indicate train departure
                    modbus_data_queue.put(["r", int(first_entry["TrackAtLocation"]), first_entry['id']])

                    await asyncio.sleep(1.5)

                    # Update the 'departure.json' file with the modified json_data
                    await write_to_file(json_data, 1)
                    await departure_to_data()
        else:
            _logger.error("No entry found in departure.json")

        # sleep 0.5 seconds so we can send data to the gui so it will show that the train has departed
        await asyncio.sleep(0.5)


def modbus_helper() -> None:
    """Sets up server and send data task"""
    loop = asyncio.new_event_loop()
    context = setup_server()

    loop.create_task(handle_simulation_communication(context))
    loop.run_until_complete(modbus_server_thread(context))

    return


async def update_departure_time(id: str, est_time: datetime, has_changed: bool) -> None:
    """Updates the departure time based on the arrival time"""
    global entries_in_gui
    departure_data = await read_from_file(1)

    # Find the index of the departure entry with the given id
    corresponding_depart_index = next(
        (index for index, departure_train in enumerate(departure_data) if
         departure_train['id'] == id), None)

    # Convert the existing estimated time to a datetime object for that entry
    departure_data[corresponding_depart_index]['EstimatedTime'] = (
        datetime.strptime(departure_data[corresponding_depart_index]["EstimatedTime"], "%Y-%m-%d %H:%M"))

    # Check if the estimated time needs to be updated
    if ((not has_changed and est_time > departure_data[corresponding_depart_index]['EstimatedTime'] - timedelta(minutes=2))
            or (has_changed and est_time != departure_data[corresponding_depart_index]['EstimatedTime'] - timedelta(minutes=2))):

        depart_train = departure_data[corresponding_depart_index]
        depart_train['EstimatedTime'] = (est_time + timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M")

        del departure_data[corresponding_depart_index]

        idx = bisect.bisect_right(departure_data, datetime.strptime(depart_train['EstimatedTime'], "%Y-%m-%d %H:%M"))

        departure_data.insert(idx, depart_train)

        await write_to_file(departure_data, 1)

        # Check if the update is for the first entry or if it was inserted at the beginning
        if corresponding_depart_index == 0 or idx == 0:
            wake_departure.set()

        # Check if the corresponding index is the same as the inserted index
        if corresponding_depart_index == idx:
            # Update the modbus data queue for the GUI
            modbus_data_queue.put(["U", str(idx), depart_train['EstimatedTime'],
                                   depart_train['TrackAtLocation']])
        elif corresponding_depart_index < 4 or idx < 4:  # only do this if the entry was in the timetable before
            # Remove all entries and resend all the data again. Clear the timetable and rebuild
            for i in range(3, -1, -1):
                modbus_data_queue.put(["R", str(i)])
                entries_in_gui -= 1
            send_data.set()


async def update_keys(secret_key: bytes) -> None:
    new_modbus_key = Fernet.generate_key()
    new_file_key = Fernet.generate_key()
    cipher = Fernet(secret_key)
    encrypted_message = cipher.encrypt(new_modbus_key)

    modbus_data_queue.put(["K", new_modbus_key, new_file_key, encrypted_message])


async def train_match() -> None:
    """compares arrivals against departures and gives train ids based on the arrival.json list"""
    timeformat = '%Y:%m:%d:%H:%M'

    departure_data = await read_from_file(1)
    arrival_data = await read_from_file(0)
    idcounter = 1

    # creates one bestmatch which contains the departure train that needs to be updated
    bestmatch = departure_data[0]
    timedelta0 = timedelta(hours=0)

    for atrain in arrival_data:
        # if the train doesnt have an id
        if len(atrain) == 5:

            # makes the atrain advertised time into a comparable format
            formatted_str = atrain['AdvertisedTime'].replace('-', ' ').replace(' ', ':')
            atraintime = datetime.strptime(formatted_str, timeformat)
            for dtrain in departure_data:

                # if the dtrain is on the same track as the atrain and it doesnt have an id
                if dtrain['TrackAtLocation'] == atrain['TrackAtLocation'] and len(dtrain) == 6:

                    # makes the dtrain advertised time into a comparable format
                    formatted_str = dtrain['AdvertisedTime'].replace('-', ' ').replace(' ', ':')
                    dtraintime = datetime.strptime(formatted_str, timeformat)

                    # compares the traintimes
                    comparetime = dtraintime - atraintime

                    # if the compared train times are positive
                    if comparetime > timedelta0:
                        bestmatch = dtrain
                        break

        # give atrain and bestmatch the same id then increase id
        atrain['id'] = str(idcounter)
        bestmatch['id'] = str(idcounter)

        idcounter += 1

    await write_to_file(departure_data, 1)
    await write_to_file(arrival_data, 0)


async def departure_to_data():
    departure_data = await read_from_file(1)

    with mutex, open('data.json', 'r') as datafile:
        data = json.load(datafile)

    for i in range(1, 7):
        data['currentTrackStatus'][str(i)] = data['trackStatus'][track_status_sim[i - 1] != 0]

    data['switchStatus'] = "Track " + str(switch_status)

    # deletes data in data['trains']
    if len(data['trains']) == 0:
        data['trains'].append({'trainNumber': '', 'time': '', 'track': ''})
    else:
        data['trains'] = [data['trains'][0]]

    # creates new train and then gives it data based on departure file
    for i in range(min(len(departure_data), 4)):
        data['trains'].append({'trainNumber': '', 'time': '', 'track': ''})
        data['trains'][i]['trainNumber'] = departure_data[i]['ToLocation']
        data['trains'][i]['time'] = departure_data[i]['EstimatedTime']
        data['trains'][i]['track'] = departure_data[i]['TrackAtLocation']

    with mutex, open('data.json', 'w') as datafile:
        json.dump(data, datafile, indent=3)


async def write_to_file(data: Union[dict, List], file_nr: int) -> None:
    """Calculates hmac for the data and writes it the specified file. 0 for arrival, 1 for departure"""
    global arrival_file_version
    global departure_file_version

    json_data = json.dumps(data, indent=2)

    if file_nr == 0:
        json_data = f"{json_data}\nfileVersion={arrival_file_version}"

        # Calculate HMAC using HMAC-SHA-256
        hmac_value = hmac.new(file_secret_key, json_data.encode(), hashlib.sha256).hexdigest()

        content = f"{json_data}\nHMAC={hmac_value}"

        # Write content to the file
        async with arrival_file_mutex:
            with open("arrival.json", 'w') as file:
                file.write(content)

        arrival_file_version += 1
    else:
        json_data = f"{json_data}\nfileVersion={departure_file_version}"

        # Calculate HMAC using HMAC-SHA-256
        hmac_value = hmac.new(file_secret_key, json_data.encode(), hashlib.sha256).hexdigest()

        content = f"{json_data}\nHMAC={hmac_value}"

        # Write content to the file
        async with departure_file_mutex:
            with open("departure.json", 'w') as file:
                file.write(content)

        departure_file_version += 1


async def read_from_file(file_nr: int) -> Union[dict, List]:
    """Reads data from specified file and calculates hmac and compare to the one in the file. 0 for arrival,
    1 for departure"""
    global arrival_file_version
    global departure_file_version

    if file_nr == 0:
        try:
            async with arrival_file_mutex:
                with open("arrival.json", 'r') as file:
                    content = file.read()
        except (FileNotFoundError, json.JSONDecodeError):
            _logger.error("Cannot find or decode file")
            return []

        parts = content.rsplit("HMAC=", 1)
        json_data, file_version = parts[0].rsplit("fileVersion=", 1)

        # Calculate HMAC from JSON data and sequence number
        recalculated_hmac = hmac.new(file_secret_key, parts[0].strip().encode(), hashlib.sha256).hexdigest()

        if recalculated_hmac == parts[1] and int(file_version) == arrival_file_version - 1:
            # HMAC verification successful
            return json.loads(json_data)
        else:
            # HMAC verification failed or sequence number is incorrect
            _logger.critical("Failed integrity check")
            raise ValueError("Integrity check failed")
    else:
        try:
            async with departure_file_mutex:
                with open("departure.json", 'r') as file:
                    content = file.read()
        except (FileNotFoundError, json.JSONDecodeError):
            _logger.error("Cannot find or decode file")
            return []

        parts = content.rsplit("HMAC=", 1)
        json_data, file_version = parts[0].rsplit("fileVersion=", 1)

        # Calculate HMAC from JSON data and sequence number
        recalculated_hmac = hmac.new(file_secret_key, parts[0].strip().encode(), hashlib.sha256).hexdigest()

        if recalculated_hmac == parts[1] and int(file_version) == departure_file_version - 1:
            # HMAC verification successful
            return json.loads(json_data)
        else:
            # HMAC verification failed or sequence number is incorrect
            _logger.critical("Failed integrity check")
            raise ValueError("Integrity check failed")


async def acquire_switch(switch_queue: asyncio.Queue) -> None:
    """Empties the switch queue and keeps track of when the switch will be available,
    then notifies the correct function."""
    global switch_status
    global last_acquired_switch

    # switch_queue should contain [func_code, track_number]  departure: 0, arrival: 1
    func_codes = [departure_event, arrival_event]
    serving = [serving_departure, serving_arrival]

    while True:
        # Wait until a request to change the switch status has arrived
        data = await switch_queue.get()

        serving[int(data[0])].set()

        # Arrival and departure don't have precedence over each other, so if anyone has acquired the switch, wait
        difference = last_acquired_switch + timedelta(minutes=2) - datetime.now()

        while difference > timedelta(minutes=0):
            _logger.info("Currently waiting for the switch to be available again")
            _logger.info(f"next check in {difference.total_seconds() % 60} minutes")

            try:
                await asyncio.wait_for(give_up_switch.wait(), timeout=max(0, difference.total_seconds() - 2 * 60))
                give_up_switch.clear()
                _logger.info("Received a wakeup call")
                serving[int(data[0])].clear()
                continue
            except asyncio.TimeoutError:
                pass

            difference = last_acquired_switch + timedelta(minutes=2) - datetime.now()

            if difference <= timedelta(minutes=2):
                break

        last_acquired_switch = datetime.now()

        async with switch_lock:
            switch_status = int(data[1])

        # Notify the corresponding function (departure_event or arrival_event) that they have the switch
        func_codes[int(data[0])].set()

        # Send an update message to the GUI
        modbus_data_queue.put(["S", str(switch_status)])

        await departure_to_data()

        # give the train 60 seconds to arrive/depart
        try:
            await asyncio.wait_for(give_up_switch.wait(), timeout=60)
            give_up_switch.clear()
            _logger.info("Received a wakeup call")
        except asyncio.TimeoutError:
            pass

        serving[int(data[0])].clear()


async def update_switch_from_gui(reader: asyncio.StreamReader) -> None:
    """If the switch status get attacked on the way to the gui, the gui will respond with the new status to this
    function"""
    global switch_status
    while True:
        data = await reader.read(1024)

        async with switch_lock:
            switch_status = int(data.decode())


async def send_new_entry() -> None:
    """Sends a new entry to the gui when there is a free place"""
    global entries_in_gui

    while True:
        await send_data.wait()

        departure_data = await read_from_file(1)

        modbus_data_queue.put(
            ['A', str(entries_in_gui), departure_data[entries_in_gui]['EstimatedTime'],
             departure_data[entries_in_gui]['ToLocation'], departure_data[entries_in_gui]['TrackAtLocation']])

        entries_in_gui += 1

        if entries_in_gui == 4:
            await departure_to_data()
            send_data.clear()


async def handle_simulation_communication(context: ModbusServerContext) -> None:
    """Takes data from queue and sends to client"""
    global last_acquired_switch
    global switch_status
    global modbus_data_queue
    global arrival_file_version
    global departure_file_version
    global file_secret_key
    global entries_in_gui

    loop = asyncio.get_event_loop()
    switch_queue = asyncio.Queue()

    func_code = 3  # function code for modbus that we want to read and write data from holding register
    slave_id = 0x00  # we broadcast the data to all the connected slaves
    address = 0x00

    sequence_number = 0

    # remove old json files
    try:
        _logger.info("Removed old files")
        os.remove("departure.json")
        os.remove("arrival.json")
    except FileNotFoundError:
        pass

    await asyncio.sleep(1)

    loop.create_task(update_departure())
    loop.create_task(update_arrival())

    # wait so we have time to update the json files
    await asyncio.sleep(1)

    await train_match()

    departure_data = await read_from_file(1)
    arrival_data = await read_from_file(0)

    max_arrival_id = max([int(atrain.get('id', 0)) for atrain in arrival_data], default=0)

    success = False

    _logger.info("Finding tracks where a train already has arrived to")
    for d_train in departure_data:
        if 'id' not in d_train:
            max_arrival_id += 1
            d_train['id'] = str(max_arrival_id)
            _logger.info(f"Found train and occupied track {d_train['TrackAtLocation']}")
            track_status_sim[int(d_train['TrackAtLocation']) - 1] = 1
            modbus_data_queue.put(["T", d_train['TrackAtLocation'], "O"])
            modbus_data_queue.put(["C", d_train['TrackAtLocation']])
            await track_semaphore.acquire()
        else:
            if success:
                break
            success = True

    await write_to_file(departure_data, 1)

    await departure_to_data()

    send_data.set()
    loop.create_task(send_new_entry())
    loop.create_task(arrival())
    loop.create_task(departure())
    loop.create_task(acquire_switch(switch_queue))

    # wait until client has connected
    while context[slave_id].getValues(func_code, datastore_size - 2, 1) == [0]:
        _logger.info("Waiting for client to connect; sleeping 2 second")
        await asyncio.sleep(2)  # give the server control so it can answer the client

    _logger.info("Client has connected to modbus")

    while True:
        try:
            reader, writer = await asyncio.open_connection('localhost', 12346)
            break  # Break out of the loop if connection is successful
        except ConnectionRefusedError:
            _logger.info("Connection to asyncio server failed. Retrying...")
            await asyncio.sleep(1)  # Wait for a while before retrying

    _logger.info("Connected to asyncio server")

    # -------------------------------------------------#
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2

    params_numbers = dh.DHParameterNumbers(p, g)
    parameters = params_numbers.parameters(default_backend())

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    writer.write(public_key_bytes)
    await writer.drain()

    public_key_bytes = await reader.read(2048)

    received_public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

    shared_secret = private_key.exchange(received_public_key)

    # Derive a key from the shared secret using a key derivation function (KDF)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)

    # Use the key material to generate a Fernet key
    modbus_secret_key = base64.urlsafe_b64encode(derived_key)

    # -------------------------------------------------#
    loop.create_task(update_switch_from_gui(reader))

    while True:
        # Run blocking call in executor so all the other tasks can run and the server
        data = await loop.run_in_executor(None, modbus_data_queue.get)

        # ----------------- HMI ----------------- #
        # s: helps handling the request for the switch and updates last acquired switch time.
        # Packet: ["s", 2, "track_number"]

        # r: Removes a train from the station. Checks whether the switch was in the correct position or not
        # Packet ["r", track, "id"]

        # t: message from the hmi to change track status, to the simulation
        # Packet ["t", track, "status"]  --> track is an int

        # h: inserts a new time in the json files
        # Packet ["h", "AdvertisedTimeArrival", "AdvertisedTimeDeparture", "ToLocation", Track]

        # g: hmi call to remove an entry
        # Packet ["g", "idx"]

        # ----------------- SIMULATION ----------------- #
        # a: A "status" message that a train has arrived at the station. Updates the real track status. Attack helper.
        # Packet: ["a", "id", "track"]

        # s: helps handling the request for the switch and updates last acquired switch time.
        # Packet: ["s", func_code, "track_number"]
        # func_code: 0: departure, 1: arrival

        # r: Removes a train from the station. Checks whether the switch was in the correct position or not
        # Packet ["r", track, "id"]

        # u: update the departure track in the json file for a specific train
        # Paket ["u", "id", "track"]

        # ----------------- GUI ----------------- #
        # A: Adds a new train to the timetable in the gui.
        # Packet: ["A", "idx", "EstimatedTime", "ToLocation", "Track"]

        # S: Sends the new status of the switch to the gui.
        # Packet: ["S", "switch_status"]

        # R: sends a remove train message to the gui.
        # Packet ["R", "index"]

        # T: message to gui to change track status
        # Packet ["T", "track", "status"]

        # U: update the departure in the gui
        # Packet ["U", "id", EstimatedTime, "track"]

        # K: update the key for the gui
        # Packet ["K", b"key", b"encrypted new key"]

        # H: arrival package to the gui. Marks that a train has arrived and to which track it has arrived
        # Packet: ["H", "track"]

        # B: Remove a train from the timetable. Only send if train hasn't arrived yet.
        # Packet: ["B", "index"]

        # C: populates the train station at the beginning if a train already exists there
        # Packet: ["C", "track"]

        match data[0]:
            case "a":
                _logger.info("Received arrival update from a train")
                if switch_status != int(data[2]):
                    _logger.info("Updating track in json, due to switch status being different to expected track")

                    modbus_data_queue.put(["u", data[1], str(switch_status)])

                modbus_data_queue.put(["H", str(switch_status)])
            case "s":
                if data[1] == 2:
                    _logger.info("Received switch update from hmi")
                    async with switch_lock:
                        switch_status = int(data[2])
                    last_acquired_switch = datetime.now()
                    modbus_data_queue.put(["S", data[2]])
                else:
                    _logger.info("Received switch update from simulation")
                    await switch_queue.put(data[1:])

                    difference = max((last_acquired_switch - datetime.now()).total_seconds(), 0)
                    update_time = (3 * 60 * switch_queue.qsize() + 60 * (switch_queue.qsize() - 1) + difference) // 60

                    if data[1] == 0:
                        _logger.info("Received switch update from departure function")

                        json_data = await read_from_file(1)

                        json_data[0]["EstimatedTime"] = (datetime.now() + timedelta(
                            minutes=update_time)).strftime("%Y-%m-%d %H:%M")

                        await write_to_file(json_data, 1)

                        modbus_data_queue.put(["U", str(0), json_data[0]['EstimatedTime'],
                                               json_data[0]['TrackAtLocation']])
                    else:
                        _logger.info("Received switch update from arrival function")

                        json_data = await read_from_file(0)
                        json_data[0]["EstimatedTime"] = (datetime.now() + timedelta(
                            minutes=update_time)).strftime("%Y-%m-%d %H:%M")
                        await write_to_file(json_data, 0)
            case "r":
                _logger.info("Received removal wish")

                entries_in_gui -= 1

                if entries_in_gui < 4:
                    send_data.set()

                json_data = await read_from_file(0)

                has_arrived = True

                for idx, train in enumerate(json_data):
                    if 'id' in train and train['id'] == data[2]:
                        has_arrived = False
                        _logger.info("Train hasn't arrived yet")
                        if idx == 0:
                            if serving_arrival.is_set():
                                give_up_switch.set()
                            elif arrival_switch_request.is_set():
                                temp = await switch_queue.get()

                                if temp[0] != 1:
                                    await switch_queue.put(temp)

                            wake_arrival.set()

                        train['IsDeleted'] = True
                        json_data.append(json_data.pop(idx))
                        await write_to_file(json_data, 0)
                        break

                _logger.info("Finished ")
                json_data = await read_from_file(1)

                for idx, train in enumerate(json_data):
                    if 'id' in train and train['id'] == data[2]:
                        # wake departure function if this is the first train to depart
                        if idx == 0:
                            if serving_departure.is_set():
                                give_up_switch.set()
                            elif departure_switch_request.is_set():
                                try:
                                    temp = switch_queue.get_nowait()

                                    if temp[0] != 0:
                                        await switch_queue.put(temp)
                                except asyncio.QueueEmpty:
                                    pass

                            wake_departure.set()
                            _logger.info("Woke departure function")

                        if has_arrived:
                            if switch_status != data[1]:
                                _logger.error("The train derailed when it tried to leave the station")

                            # clear track
                            track_status_sim[data[1] - 1] = 0
                            _logger.info("Cleared track")
                            track_semaphore.release()
                            modbus_data_queue.put(["R", train['TrackAtLocation'], str(idx)])
                        else:
                            modbus_data_queue.put(["B", str(idx)])

                        train['IsDeleted'] = True
                        json_data.append(json_data.pop(idx))
                        await write_to_file(json_data, 1)
                        await departure_to_data()
                        break
            case "t":
                _logger.info("Received track status update")

                if data[2] == "O":
                    track_status_sim[data[1] - 1] = 1
                    await departure_to_data()
                    _logger.info("Occupied track")
                    await track_semaphore.acquire()
                    modbus_data_queue.put(["T", data[1], "O"])
                else:
                    track_status_sim[data[1] - 1] = 0
                    await departure_to_data()
                    _logger.info("Cleared track")
                    track_semaphore.release()
                    modbus_data_queue.put(["T", data[1], "A"])

                await departure_to_data()
            case "u":
                _logger.info("Received wish to update track for departure from simulation")

                json_data = await read_from_file(1)

                for i in range(len(json_data)):
                    if json_data[i]["id"] == data[1]:
                        json_data[i]["TrackAtLocation"] = int(data[2])
                        modbus_data_queue.put(
                            ["U", str(i), json_data[i]['EstimatedTime'],
                             json_data[i]["TrackAtLocation"]])
                        _logger.info("updated track in departure file")
                        break

                await write_to_file(json_data, 1)
            case "h":
                _logger.info("Received a new train from hmi")

                arrival_data = await read_from_file(0)
                departure_data = await read_from_file(1)

                used_ids_list1 = set(item.get('id') for item in arrival_data)
                used_ids_list2 = set(item.get('id') for item in departure_data)

                used_ids = used_ids_list1.union(used_ids_list2)

                available_id = 1

                _logger.info("Finding available id")
                while str(available_id) in used_ids:
                    available_id += 1

                current_time = datetime.now()
                today_date = current_time.date()
                recv_time = datetime.combine(today_date, datetime.strptime(data[2], "%H:%M").time())

                if recv_time < current_time:
                    recv_time += timedelta(days=1)

                arrival_time = recv_time - timedelta(minutes=3)

                train_data = {'AdvertisedTime': arrival_time.strftime("%Y-%m-%d %H:%M"),
                              'EstimatedTime': arrival_time.strftime("%Y-%m-%d %H:%M"),
                              'TrackAtLocation': data[4],
                              'IsRemoved': False,
                              'TrainOwner': "hmi",
                              'id': str(available_id)}

                arrival_data = await read_from_file(0)

                existing_times = [item['EstimatedTime'] for item in arrival_data]
                arrival_index = bisect.bisect_left(existing_times, train_data['EstimatedTime'])
                arrival_data.insert(arrival_index, train_data)

                await write_to_file(arrival_data, 0)

                train_data = {'AdvertisedTime': recv_time.strftime("%Y-%m-%d %H:%M"),
                              'EstimatedTime': recv_time.strftime("%Y-%m-%d %H:%M"),
                              'ToLocation': data[3],
                              'TrackAtLocation': data[4],
                              'IsRemoved': False,
                              'TrainOwner': "hmi",
                              'id': str(available_id)}

                departure_data = await read_from_file(1)

                existing_times = [item['EstimatedTime'] for item in departure_data]
                departure_index = bisect.bisect_left(existing_times, train_data['EstimatedTime'])
                departure_data.insert(departure_index, train_data)

                await write_to_file(departure_data, 1)
                await departure_to_data()

                if arrival_index == 0:
                    if serving_arrival.is_set():
                        give_up_switch.set()
                    wake_arrival.set()

                if departure_index == 0:
                    if serving_departure.is_set():
                        give_up_switch.set()
                    wake_departure.set()

                for i in range(3, -1, -1):
                    modbus_data_queue.put(["B", str(i)])
                    entries_in_gui -= 1
                send_data.set()

                await departure_to_data()
            case "K":
                arrival_data = await read_from_file(0)
                departure_data = await read_from_file(1)
                departure_file_version = 0
                arrival_file_version = 0

                modbus_secret_key = data[1]
                file_secret_key = data[2]
                writer.write(data[3])
                await writer.drain()
                _logger.info("sent new secret key")
                sequence_number = 0

                await write_to_file(arrival_data, 0)
                await write_to_file(departure_data, 1)
                _logger.info("updated HMAC in files")
            case "g":
                json_data = await read_from_file(1)
                modbus_data_queue.put(['r', int(json_data[data[1]]['TrackAtLocation']), json_data[data[1]]['id']])
            case _:
                data = " ".join(str(value) for value in data)

                client_verified = False

                while not client_verified:
                    sequence_number += 1
                    temp_signature = data + str(sequence_number)
                    _logger.debug(temp_signature)
                    temp_signature = hmac.new(modbus_secret_key, temp_signature.encode(), hashlib.sha256).hexdigest()
                    nonce = [char for char in secrets.token_bytes(2)]

                    if sequence_number == 100:
                        _logger.info("Updating secret key")
                        await update_keys(modbus_secret_key)

                    data_to_send = ([sequence_number] + [len(data)] + [ord(char) for char in data] + [32] + nonce +
                                    [32] + [ord(char) for char in temp_signature])

                    _logger.debug("Sending data")
                    context[slave_id].setValues(func_code, address, data_to_send)

                    _logger.debug("Resetting flag")
                    context[slave_id].setValues(func_code, datastore_size - 2, [0])

                    expected_signature = hmac.new(modbus_secret_key, str(nonce).encode(), hashlib.sha256).hexdigest()

                    _logger.debug(f"nonce {str(nonce)}")
                    expected_signature = [ord(char) for char in expected_signature]
                    _logger.debug(f"Expecting: {expected_signature}")

                    while context[slave_id].getValues(func_code, datastore_size - 2, 1) == [0]:
                        _logger.debug("Waiting for client to copy datastore; sleeping 1 second")
                        await asyncio.sleep(1)  # give the server control so it can answer the client

                    if context[slave_id].getValues(func_code, 0, 64) == expected_signature:
                        _logger.debug("Client is verified")
                        client_verified = True
                    else:
                        _logger.critical("Found wrong signature in holding register")

# ------------------------------- #


if __name__ == '__main__':
    modbus_process = multiprocessing.Process(target=modbus_helper)
    modbus_process.start()

    app.run(ssl_context=(cert, key), debug=False, port=5001)
    SQL.closeSession()

    modbus_process.join()
