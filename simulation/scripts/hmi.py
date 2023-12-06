from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
import bcrypt

# flask listening on 5001
# switch tcp listening on port 12344
# hmi modbus listening on 12345
# gui tcp listening on 12346
# track_sensor modbus listening on 13000-13005
# track_sensor tcp listening on 13006
# track_sensor tcp for trains listening on port 13007
# train tcp listening on port 15000

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
from heapq import merge
import random
import struct
import ast

from pymodbus import __version__ as pymodbus_version
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.server import StartAsyncTlsServer
from pymodbus.client import AsyncModbusTlsClient

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet

try:
    os.remove(f"{os.getcwd()}/logs/HMI.log")
except FileNotFoundError:
    pass

# Configure the logger
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s', level=logging.ERROR)

# Create a FileHandler to write log messages to a file
file_handler = logging.FileHandler(f"{os.getcwd()}/logs/HMI.log")
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
logging.getLogger().addHandler(file_handler)

# Modbus variables
datastore_size = 95  # cant be bigger than 125
modbus_port = 12345

cert = f"{os.getcwd()}/TLS/cert.pem"
key = f"{os.getcwd()}/TLS/key.pem"

arrival_file_mutex = asyncio.Lock()
departure_file_mutex = asyncio.Lock()
mutex = multiprocessing.Lock()

last_acquired_switch = datetime.now() - timedelta(minutes=3)

wake_arrival = asyncio.Event()
wake_departure = asyncio.Event()
departure_event = asyncio.Event()
arrival_event = asyncio.Event()
serving_departure = asyncio.Event()
serving_arrival = asyncio.Event()
arrival_switch_request = asyncio.Event()
departure_switch_request = asyncio.Event()
give_up_switch = asyncio.Event()

track_semaphore = asyncio.Semaphore(value=6)
track_status = [0] * 6  # this is the track_status that the trains use when deciding on a track.
track_reservations = [0] * 6

created_trains = []
arrived_trains = []

switch_lock = asyncio.Lock()
entries_in_gui = 0
send_data = asyncio.Event()

hmi_data_queue = multiprocessing.Queue()
modbus_data_queue = asyncio.Queue()

app = Flask(__name__,
            template_folder=f"{os.getcwd()}/templates",
            static_folder=f"{os.getcwd()}/static")

app.logger.setLevel(logging.ERROR)

log = logging.getLogger('werkzedug')
log.setLevel(logging.ERROR)

# Sessions för login
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

login_manager = LoginManager()
login_manager.init_app(app)

departure_file_version = 0
arrival_file_version = 0
file_secret_key = Fernet.generate_key()

switch_status = 1
serving_id = 0
switch_given_to = 0

sensor_key = b""
sensor_requests = asyncio.Queue()

train_queue = asyncio.Queue()
sequence_number_train = 0
train_key = b""

MESSAGE_TYPE_PACKED = 1
MESSAGE_TYPE_SINGLE_CHAR = 2
MESSAGE_TYPE_SIGNATURE = 3

train_mutex = asyncio.Lock()

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
    credentials = open_json("usercredentials.json")
    user = Users(credentials["username"], credentials["password"])
    return user


@app.route('/', methods=["POST", "GET"])
def loginPage(invalid=False):
    if request.method == "POST":

        # Här får vi data från loginet. Gör backend saker som kontroller etc
        user_credentials = {'username': request.form["username"], 'password': request.form["pwd"]}
        user = Users(user_credentials['username'], user_credentials['password'])
        credentials = open_json("usercredentials.json")

        if user.username == credentials["username"] and bcrypt.checkpw(user.password.encode(),
                                                                       credentials["password"].encode()):
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
                    hmi_data_queue.put(data)

                case "deleteTime":
                    id = int(request.form.get('id', False))
                    if id <= len(json_data['trains']):
                        json_data = logData(json_data, "Deleted entry in timetable",
                                            f"Train {json_data['trains'][id - 1]['trainNumber']} was deleted")
                        json_data['trains'].pop(id - 1)
                        data = ["g"] + [id - 1]
                        hmi_data_queue.put(data)

        writeToJson('data.json', json_data)
    return render_template("timetable.html", change=change, trainList=json_data['trains'])


@app.route('/logout')
@login_required
def logOutUser():
    logout_user()
    json_data = open_json("data.json")
    json_data = logData(json_data, "User logout", session['username'])
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

                    data = ["t", 1, json_data['currentTrackStatus']['1'][0], "-"]
                    hmi_data_queue.put(data)

                case "track2":
                    if current_trackStatus['2'] == track_status[0]:
                        json_data['currentTrackStatus']['2'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 2 changed from available to Occupied")
                    else:
                        json_data['currentTrackStatus']['2'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 2 changed from Occupied to Available")

                    data = ["t", 2, json_data['currentTrackStatus']['2'][0], "-"]
                    hmi_data_queue.put(data)

                case "track3":
                    if current_trackStatus['3'] == track_status[0]:
                        json_data['currentTrackStatus']['3'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 3 changed from available to Occupied")
                    else:
                        json_data['currentTrackStatus']['3'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 3 changed from Occupied to Available")

                    data = ["t", 3, json_data['currentTrackStatus']['3'][0], "-"]
                    hmi_data_queue.put(data)

                case "track4":
                    if current_trackStatus['4'] == track_status[0]:
                        json_data['currentTrackStatus']['4'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 4 changed from available to Occupied")
                    else:
                        json_data['currentTrackStatus']['4'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 4 changed from Occupied to Available")

                    data = ["t", 4, json_data['currentTrackStatus']['4'][0], "-"]
                    hmi_data_queue.put(data)

                case "track5":
                    if current_trackStatus['5'] == track_status[0]:
                        json_data['currentTrackStatus']['5'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 5 changed from available to Occupied")
                    else:
                        json_data['currentTrackStatus']['5'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 5 changed from Occupied to Available")

                    data = ["t", 5, json_data['currentTrackStatus']['5'][0], "-"]
                    hmi_data_queue.put(data)

                case "track6":
                    if current_trackStatus['6'] == track_status[0]:
                        json_data['currentTrackStatus']['6'] = track_status[1]
                        logData(json_data, "Track status changed", "Track 6 changed from available to Occupied")
                    else:
                        json_data['currentTrackStatus']['6'] = track_status[0]
                        logData(json_data, "Track status changed", "Track 6 changed from Occupied to Available")

                    data = ["t", 6, json_data['currentTrackStatus']['6'][0], "-"]
                    hmi_data_queue.put(data)

        else:
            button_clicked = request.form.get('switchconnection', False)

            if button_clicked:
                tempSwitchData = json_data['switchStatus']
                json_data['switchStatus'] = "Track " + button_clicked
                json_data = logData(json_data, "Changed Switch Connection",
                                    f"Switch connection changed from {tempSwitchData} to {json_data['switchStatus']}")
                data = ["s", 2, button_clicked]
                hmi_data_queue.put(data)

        writeToJson('data.json', json_data)

    return render_template("railway.html", trackStatus=track_status, current_trackStatus=current_trackStatus,
                           switchStatus=json_data['switchStatus'])


@app.route('/logs')
@login_required
def logPage():
    json_data = open_json("data.json")

    return render_template("logs.html", logData=json_data['logs'])


def open_json(json_file):
    with mutex, open(f"{os.getcwd()}/JSONs/{json_file}","r") as dataFile:
        json_data = json.load(dataFile)
    return json_data


def writeToJson(json_file, data_json):
    data_json = json.dumps(data_json, indent=3)

    with mutex, open(f"{os.getcwd()}/JSONs/{json_file}","w") as dataFile:
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
async def communication_with_trains() -> None:
    """Handles the write operations to the trains"""
    global train_queue
    global sequence_number_train
    global train_key
    data_queue = asyncio.Queue()
    rotation = 0

    loop = asyncio.get_event_loop()

    while True:
        try:
            reader_train, writer_train = await asyncio.open_connection("localhost", 15000)
            break  # Break out of the loop if connection is successful
        except ConnectionRefusedError:
            logging.info("Connection to asyncio server failed. Retrying...")
            await asyncio.sleep(1)  # Wait for a while before retrying
        except OSError:
            logging.info("Connection to asyncio server failed. Retrying...")
            await asyncio.sleep(1)  # Wait for a while before retrying


    derived_key = await dh_exchange(reader_train, writer_train)

    train_key = base64.urlsafe_b64encode(derived_key)

    loop.create_task(read_comm_with_trains(reader_train, writer_train, data_queue))

    while True:
        data = await train_queue.get()

        logging.info("Received train")

        logging.info(data)

        data = " ".join(str(value) for value in data)

        client_verified = False

        while not client_verified:
            sequence_number_train += 1
            temp_signature = data + str(sequence_number_train)
            logging.info(temp_signature)
            temp_signature = hmac.new(train_key, temp_signature.encode(), hashlib.sha256).hexdigest()
            while True:
                # Generate 2 bytes
                nonce = [char for char in secrets.token_bytes(2)]

                # Check if any character is a space
                if b' ' not in nonce:
                    break

            if sequence_number_train == 100:
                logging.info("Updating secret key")

                new_key = Fernet.generate_key()
                cipher = Fernet(train_key)
                encrypted_message = cipher.encrypt(new_key)

                if rotation == 3:
                    msg = ":>D"

                    writer_train.write(msg.encode())
                    await writer_train.drain()

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

                    writer_train.write(public_key_bytes)
                    await writer_train.drain()

                    public_key_bytes = await data_queue.get()

                    writer_train.write(new_key)
                    await writer_train.drain()

                    secret = choose_characters(new_key)

                    received_public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

                    shared_secret = private_key.exchange(received_public_key)

                    shared_secret += secret.encode()

                    # Derive a key from the shared secret using a key derivation function (KDF)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data',
                    ).derive(shared_secret)

                    train_key = base64.urlsafe_b64encode(derived_key)
                    expected_signature = hmac.new(train_key, new_key, hashlib.sha256)

                    recv_signature = await data_queue.get()

                    if not expected_signature.hexdigest() == recv_signature.decode():
                        logging.critical("MITM detected")
                        raise RuntimeError

                    rotation = 0
                else:
                    msg = ":>K"
                    writer_train.write(msg.encode())
                    await writer_train.drain()

                    writer_train.write(encrypted_message)
                    await writer_train.drain()

                    train_key = new_key

                    rotation += 1

            data_to_send = ([sequence_number_train] + [len(data)] + [ord(char) for char in data] + [32] + nonce +
                            [32] + [ord(char) for char in temp_signature])

            logging.info(data_to_send)

            logging.info("Sending data")
            packed_data = str(data_to_send)
            combined_data = "1" + packed_data

            logging.info(combined_data)

            async with train_mutex:
                writer_train.write(combined_data.encode())
                await writer_train.drain()

            expected_signature = [ord(char) for char in
                                  hmac.new(train_key, str(nonce).encode(), hashlib.sha256).hexdigest()]

            logging.info(f"nonce {str(nonce)}")
            # logging.info(f"Expecting: {expected_signature}")

            received_signature = await data_queue.get()

            if str(received_signature) == str(expected_signature):
                logging.info("Client is verified")
                client_verified = True
            else:
                logging.critical("Found wrong signature in holding register")


async def read_comm_with_trains(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                data_queue: asyncio.Queue) -> None:
    """Handles the read data from the trains"""
    global sequence_number_train
    global train_key

    while True:
        data = await reader.read(1024)

        logging.info("Received data")
        data = data.decode()
        logging.info(data)

        packets = data.split("]")

        for data in packets[:-1]:
            # Add the "]" back to the packet to form a valid packet
            data += "]"

            message_type = int(data[0])

            if message_type == MESSAGE_TYPE_PACKED:
                logging.info("Received data to train")

                data = data[2:-1]

                data = list(ast.literal_eval(data))

                data_id = data[0]
                amount_to_read = data[1]

                received_data = "".join(
                    chr(char) for char in data[2:2 + amount_to_read + 1
                                                 + 2 + 1 + 64])

                nonce = received_data[1 + amount_to_read:1 + amount_to_read + 2]
                signature = received_data[1 + amount_to_read + 3:]

                data = received_data[:amount_to_read].split(" ")

                if not data_id >= sequence_number_train:
                    continue

                sequence_number_train = data_id

                # verify signature
                calc_signature = " ".join(str(value) for value in data) + str(data_id)
                logging.debug(f"calculating signature for this {calc_signature}")
                calc_signature = hmac.new(train_key, calc_signature.encode(), hashlib.sha256).hexdigest()

                if signature == calc_signature:
                    # calculate new signature for nonce
                    nonce = [ord(char) for char in nonce]

                    calc_signature = hmac.new(train_key, str(nonce).encode(), hashlib.sha256).hexdigest()

                    calc_signature = [ord(char) for char in calc_signature]
                    logging.info(calc_signature)

                    packed_data = str(calc_signature)

                    combined_data = "3" + packed_data

                    logging.info(combined_data)

                    async with train_mutex:
                        writer.write(combined_data.encode())
                        await writer.drain()

                    logging.info("Verified signature on data, notified simulation.")

                    # put data in queue for simulation
                    await modbus_data_queue.put(data)
                else:
                    logging.critical("Found wrong signature in data")
            elif MESSAGE_TYPE_SIGNATURE:
                data = data[1:]
                data = list(ast.literal_eval(data))
                await data_queue.put(data)


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

    logging.info("Created datastore")
    return context


async def update_departure() -> None:
    """Updates departure.json every 40 minutes, will remove all trains that IsRemoved is set to true on and
    they don't exist in the new data from trafikverket"""
    global modbus_data_queue

    while True:
        logging.info("Updating departure")

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

        async def update_existing_data(new_data) -> list:
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
                        logging.info("Found removed train in departure")
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
                            await modbus_data_queue.put(["U", str(idx), existing_train['EstimatedTime'],
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

            logging.info("Updated data in departure.json")
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
            updated_data = await update_existing_data(new_formatted_data)

            # Save updated data to the JSON file
            await write_to_file(updated_data, 1)
            await departure_to_data()

            logging.info("Data has been updated in departure.json")
        else:
            logging.error("API response is None. Check for issues with the API call.")

        logging.info(f"Sleeping 40 minutes. Next update {(datetime.now() + timedelta(minutes=40)).strftime('%H:%M')}")
        await asyncio.sleep(40 * 60)


async def update_arrival() -> None:
    """Updates arrival.json every 10 minutes with new trains and update estimated time for all the trains"""
    while True:
        logging.info("Updating arrival")
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
                        logging.info("Found removed trains")
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

            logging.info("Updated values in arrival.json")
        else:
            logging.error("API response was None")

        logging.info(f"Sleeping 10 minutes. Next update {datetime.now() + timedelta(minutes=10):%H:%M}")
        await asyncio.sleep(10 * 60)


async def arrival() -> None:
    """Simulates control for arriving trains to the train station.
    Sleeps until 2 minutes before arrival and then checks track status and notifies the trains object of the data"""
    global train_queue
    while True:
        logging.info("Starting arrival function")
        json_data = await read_from_file(0)

        if json_data:
            # Extract information from the first entry in the JSON data
            first_entry = json_data[0]

            estimated_time = datetime.strptime(first_entry['EstimatedTime'], "%Y-%m-%d %H:%M")

            # Calculate the time difference between estimated time and current time
            difference = estimated_time - datetime.now()

            logging.info(f"{difference.total_seconds()} until train arrival")

            try:
                # Wait for the arrival event, with a timeout based on the estimated arrival time
                await asyncio.wait_for(wake_arrival.wait(), timeout=max(0, difference.total_seconds() - 2 * 60))
                wake_arrival.clear()
                logging.info("Received a wakeup call")
                continue
            except asyncio.TimeoutError:
                logging.info("TimeoutError on waiting for wakeup. Will ask for switch soon")
                pass

            # Retrieve the track number from the JSON data
            track_number = int(first_entry['TrackAtLocation'])
            has_changed_time = False

            if track_semaphore.locked():
                logging.info("Track semaphore was locked. Will do necessary work before waiting.")
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
                logging.info("Wake arrival event has been set. Line 751")
                continue

            first_entry['EstimatedTime'] = datetime.now().strftime("%Y-%m-%d %H:%M")

            # Update the departure time for the arrival train
            await update_departure_time(first_entry['id'], datetime.now(), has_changed_time)

            await write_to_file(json_data, 0)

            if wake_arrival.is_set():
                wake_arrival.clear()
                logging.info("Wake arrival event has been set. Line 763")
                continue

            if track_status[track_number - 1] != 0 or track_reservations[track_number - 1] != 0:
                for i in range(6):
                    if track_status[i] == 0 and track_reservations[i] == 0:
                        # If the alternate track is available, occupy it and update track status
                        logging.info("Original track wasn't available, chose another track instead")
                        track_number = i + 1
                        first_entry['TrackAtLocation'] = str(track_number)
                        await write_to_file(json_data, 0)

                        # Update the track information in departure
                        await modbus_data_queue.put(["u", first_entry['id'], str(track_number)])
                        break

            # create reservation for this track
            track_reservations[track_number - 1] = 1

            departure_data = await read_from_file(1)

            for i in range(len(departure_data)):
                if departure_data[i]['id'] == first_entry['id']:
                    new_train = ["N", first_entry['EstimatedTime'], departure_data[i]['EstimatedTime'],
                                 first_entry['TrackAtLocation'], first_entry['id']]
                    await train_queue.put(new_train)

                    logging.info(new_train)

                    logging.info("Created new train")

                    break

            created_trains.append(first_entry['id'])

            json_data[0]['IsRemoved'] = True
            json_data.append(json_data.pop(0))
            await write_to_file(json_data, 0)

            # sleep 2 seconds so we can send data to the gui so it will show that the train has arrived
            await asyncio.sleep(2)


def modbus_helper() -> None:
    """Sets up server and send data task"""
    loop = asyncio.new_event_loop()
    context = setup_server()

    loop.create_task(handle_simulation_communication(context))
    loop.run_until_complete(modbus_server_thread(context))

    return


async def hmi_helper() -> None:
    """Reads data from hmi and adds it to the asyncio queue"""
    # Run blocking call in executor so all the other tasks can run and the server
    loop = asyncio.get_event_loop()

    while True:
        data = await loop.run_in_executor(None, hmi_data_queue.get)
        await modbus_data_queue.put(data)


async def update_departure_time(id: str, est_time: datetime, has_changed: bool) -> None:
    """Updates the departure time based on the arrival time"""
    global entries_in_gui
    departure_data = await read_from_file(1)
    logging.info("Updating departure time")

    # Find the index of the departure entry with the given id
    corresponding_depart_index = next(
        (index for index, departure_train in enumerate(departure_data) if
         departure_train['id'] == id), None)

    # Convert the existing estimated time to a datetime object for that entry
    departure_data[corresponding_depart_index]['EstimatedTime'] = (
        datetime.strptime(departure_data[corresponding_depart_index]["EstimatedTime"], "%Y-%m-%d %H:%M"))

    # Check if the estimated time needs to be updated
    if ((not has_changed and est_time > departure_data[corresponding_depart_index]['EstimatedTime'] - timedelta(
            minutes=2))
            or (has_changed and est_time != departure_data[corresponding_depart_index]['EstimatedTime'] - timedelta(
                minutes=2))):

        depart_train = departure_data[corresponding_depart_index]
        logging.info(depart_train)

        new_time = est_time + timedelta(minutes=2)

        if new_time > datetime.strptime(depart_train['AdvertisedTime'], "%Y-%m-%d %H:%M"):
            depart_train['EstimatedTime'] = new_time.strftime("%Y-%m-%d %H:%M")
        else:
            depart_train['EstimatedTime'] = depart_train['AdvertisedTime']

        del departure_data[corresponding_depart_index]

        temp = [datetime.strptime(item['EstimatedTime'], "%Y-%m-%d %H:%M") for item in departure_data]
        idx = bisect.bisect_right(temp, datetime.strptime(depart_train['EstimatedTime'], "%Y-%m-%d %H:%M"))

        logging.info(depart_train)

        departure_data.insert(idx, depart_train)

        await write_to_file(departure_data, 1)

        # Check if the corresponding index is the same as the inserted index
        if corresponding_depart_index == idx:
            # Update the modbus data queue for the GUI
            await modbus_data_queue.put(["U", str(idx), depart_train['EstimatedTime'],
                                         depart_train['TrackAtLocation']])
        elif corresponding_depart_index < 4 or idx < 4:  # only do this if the entry was in the timetable before
            # Remove all entries and resend all the data again. Clear the timetable and rebuild
            for i in range(3, -1, -1):
                await modbus_data_queue.put(["R", str(i)])
                entries_in_gui -= 1
            send_data.set()


async def update_keys(secret_key: bytes, requestor: int) -> None:
    """updates the modbus keys and sends it to correct entity. requestor 0 for switch and 1 for gui"""
    new_key = Fernet.generate_key()
    new_file_key = Fernet.generate_key()
    cipher = Fernet(secret_key)
    encrypted_message = cipher.encrypt(new_key)

    await modbus_data_queue.put(["K", requestor, new_key, new_file_key, encrypted_message])


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
    """Copies departure.json to data.json for the hmi"""
    departure_data = await read_from_file(1)

    with mutex, open(f"{os.getcwd()}/JSONs/data.json","r") as datafile:
        data = json.load(datafile)

    for i in range(1, 7):
        data['currentTrackStatus'][str(i)] = data['trackStatus'][track_status[i - 1] != 0]

    data['switchStatus'] = "Track " + str(switch_status)

    # Clear existing data in data['trains']
    data['trains'] = []

    # Create new trains and give them data based on departure file
    for i in range(min(len(departure_data), 4)):
        data['trains'].append({
            'trainNumber': departure_data[i]['ToLocation'],
            'time': departure_data[i]['EstimatedTime'],
            'track': departure_data[i]['TrackAtLocation']
        })

    with mutex, open(f"{os.getcwd()}/JSONs/data.json","w") as datafile:
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
            with open(f"{os.getcwd()}/JSONs/arrival.json","w") as file:
                file.write(content)

        arrival_file_version += 1
    else:
        json_data = f"{json_data}\nfileVersion={departure_file_version}"

        # Calculate HMAC using HMAC-SHA-256
        hmac_value = hmac.new(file_secret_key, json_data.encode(), hashlib.sha256).hexdigest()

        content = f"{json_data}\nHMAC={hmac_value}"

        # Write content to the file
        async with departure_file_mutex:
            with open(f"{os.getcwd()}/JSONs/derparture.json","w") as file:
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
                with open(f"{os.getcwd()}/JSONs/arrival.json","r") as file:
                    content = file.read()
        except (FileNotFoundError, json.JSONDecodeError):
            logging.error("Cannot find or decode file")
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
            logging.critical("Failed integrity check")
            raise ValueError("Integrity check failed")
    else:
        try:
            async with departure_file_mutex:
                with open(f"{os.getcwd()}/JSONs/derparture.json","r") as file:
                    content = file.read()
        except (FileNotFoundError, json.JSONDecodeError):
            logging.error("Cannot find or decode file")
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
            logging.critical("Failed integrity check")
            raise ValueError("Integrity check failed")


async def acquire_switch(switch_queue: asyncio.Queue) -> None:
    """Handles delegation of switch"""
    global switch_status
    global last_acquired_switch
    global serving_id
    global switch_given_to

    wish = ["depart", "arrive"]

    while True:
        data = await switch_queue.get()
        logging.info(f"Got new switch request from train with id: {data[2]}. It wishes to {wish[int(data[0])]}")

        serving_id = int(data[2])

        # Calculate how long it was since the last switch request
        difference = max(timedelta(minutes=0), last_acquired_switch + timedelta(minutes=2) - datetime.now())

        while difference > timedelta(minutes=0):
            logging.info("Currently waiting for the switch to be available again")
            logging.info(f"Next check in {int(difference.total_seconds())} seconds")

            try:
                await asyncio.wait_for(give_up_switch.wait(), timeout=max(0, difference.total_seconds()))
                give_up_switch.clear()
                logging.info(f"Received a wakeup call from {data[0]}")
                continue
            except asyncio.TimeoutError:
                pass

            # Recalculate the difference after waiting
            difference = max(timedelta(minutes=0), last_acquired_switch + timedelta(minutes=2) - datetime.now())

        # Update last_acquired_switch after the while loop
        last_acquired_switch = datetime.now()

        switch_given_to = int(data[2])

        await modbus_data_queue.put(["Z", str(data[1])])
        await train_queue.put(["G", str(data[2])])

        switch_status = int(data[1])
        await modbus_data_queue.put(["S", str(switch_status)])
        await departure_to_data()

        # Give the train 60 seconds to arrive/depart
        try:
            await asyncio.wait_for(give_up_switch.wait(), timeout=180)
            give_up_switch.clear()
            logging.info("Received a wakeup call. Released switch")
        except asyncio.TimeoutError:
            pass

        logging.info("Released switch")
        switch_given_to = -1
        serving_id = -1


async def send_new_entry() -> None:
    """Sends a new entry to the gui when there is a free place"""
    global entries_in_gui

    while True:
        await send_data.wait()

        departure_data = await read_from_file(1)

        await modbus_data_queue.put(
            ['A', str(entries_in_gui), departure_data[entries_in_gui]['EstimatedTime'],
             departure_data[entries_in_gui]['ToLocation'], departure_data[entries_in_gui]['TrackAtLocation']])

        entries_in_gui += 1

        if entries_in_gui == 4:
            await departure_to_data()
            send_data.clear()


async def dh_exchange(reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> bytes:
    """Handles basic diffie hellman exchange in group 14"""
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

    return derived_key


async def get_switch_status(context: ModbusServerContext, switch_key: bytes, sequence_number: int) -> (int, int):
    """Queries the switch for its status"""
    global switch_status
    func_code = 3  # function code for modbus that we want to read and write data from holding register
    slave_id = 0x00  # we broadcast the data to all the connected slaves

    data = "Y"

    client_verified = False

    while not client_verified:
        sequence_number += 1
        temp_signature = data + str(sequence_number)
        logging.info(temp_signature)
        temp_signature = hmac.new(switch_key, temp_signature.encode(), hashlib.sha256).hexdigest()
        while True:
            # Generate 2 bytes
            nonce = [char for char in secrets.token_bytes(2)]

            # Check if any character is a space
            if b' ' not in nonce:
                break

        if sequence_number == 100:
            logging.info("Updating secret key")
            await update_keys(switch_key, 0)

        data_to_send = ([sequence_number] + [len(data)] + [ord(char) for char in data] + [32] + nonce +
                        [32] + [ord(char) for char in temp_signature])

        logging.debug("Sending data")
        context[slave_id].setValues(func_code, 0x00, data_to_send)

        logging.debug("Resetting flag")
        context[slave_id].setValues(func_code, datastore_size - 2, [0])

        logging.debug(f"nonce {str(nonce)}")

        while context[slave_id].getValues(func_code, datastore_size - 2, 1) == [0]:
            logging.debug("Waiting for client to copy datastore; sleeping 0.5 seconds")
            await asyncio.sleep(0.5)  # give the server control so it can answer the client

        recv_data = context[slave_id].getValues(func_code, 0, 65)

        temp_sig = [recv_data[0]] + nonce

        calc_signature = [ord(char) for char in
                          hmac.new(switch_key, str(temp_sig).encode(), hashlib.sha256).hexdigest()]

        if calc_signature == recv_data[1:]:
            logging.info("Client is verified")
            switch_status = recv_data[0]
            client_verified = True
        else:
            logging.critical("Found wrong signature in holding register")
            switch_status = -1

    return switch_status, sequence_number


def choose_characters(secret: bytes) -> str:
    """Chose a few random characters"""
    hash_object = hashlib.sha256(secret)
    hash_hex = hash_object.hexdigest()

    indexes = list(range(len(hash_hex) // 2))

    random.seed(int(hash_hex[:16], 16))  # Use the first 16 characters of the hash as the seed
    selected_indexes = random.choices(indexes, k=32)
    result = [hash_hex[i * 2: (i + 1) * 2] for i in selected_indexes]

    return "".join(result)


async def sensor_comm() -> None:
    """Handles communication with the track sensors"""
    sensor_sequence_number = 0
    global sensor_key
    global sensor_requests
    sensor_clients = []
    ports = [13000, 13001, 13002, 13003, 13004, 13005]

    for i in range(6):
        sensor_clients.append(AsyncModbusTlsClient(
            "localhost",
            port=ports[i],
            framer=ModbusTlsFramer,
            certfile=cert,
            keyfile=key,
            server_hostname="host",
        ))

        logging.info("Started client")

        await sensor_clients[i].connect()
        # if we can't connect try again after 5 seconds, if the server hasn't been started yet
        while not sensor_clients[i].connected:
            logging.info(f"Couldn't connect to sensor {i + 1}, trying again in 5 seconds")
            await asyncio.sleep(5)
            await sensor_clients[i].connect()
        logging.info(f"Connected to sensor {i + 1}")

    while True:
        for i in range(6):
            hold_register = await sensor_clients[i].read_holding_registers(datastore_size - 2, 1, slave=1)

            if hold_register.registers != [0]:
                hold_register = await sensor_clients[i].read_holding_registers(0x00, datastore_size - 3, slave=1)
                data_id = hold_register.registers[0]
                amount_to_read = hold_register.registers[1]

                received_data = "".join(chr(char) for char in hold_register.registers[2:2 + amount_to_read + 1
                                                                                        + 2 + 1 + 64])

                logging.info(received_data)

                nonce = received_data[1 + amount_to_read:1 + amount_to_read + 2]
                signature = received_data[1 + amount_to_read + 3:]
                data = received_data[:amount_to_read].split(" ")

                if not data_id > sensor_sequence_number:
                    continue

                sensor_sequence_number = data_id

                # verify signature
                calc_signature = " ".join(str(value) for value in data) + str(data_id)
                logging.info(f"calculating signature for this {calc_signature}")
                calc_signature = hmac.new(sensor_key, calc_signature.encode(), hashlib.sha256).hexdigest()

                if signature == calc_signature:
                    logging.info("Verified signature on data. Checking received status")

                    if data == ['0']:
                        logging.info("Cleared track")
                        track_semaphore.release()
                        await modbus_data_queue.put(["T", str(i+1), "A"])
                        track_status[i] = 0
                    else:
                        logging.info("Occupied track")
                        await modbus_data_queue.put(["T", str(i+1), "O"])
                        track_reservations[i] = 0
                        track_status[i] = 1

                    nonce = [ord(char) for char in nonce]
                    calc_signature = hmac.new(sensor_key, str(nonce).encode(), hashlib.sha256).hexdigest()

                    calc_signature = [ord(char) for char in calc_signature]

                    await sensor_clients[i].write_registers(0x00, calc_signature, slave=1)
                    await sensor_clients[i].write_register(datastore_size - 2, 0, slave=1)
                else:
                    logging.critical("Wrong signature found in modbus register")
            else:
                logging.info("No new data from track sensors")

        await asyncio.sleep(10)


async def rotation_comm(reader: asyncio.StreamReader, secret_key_sensors: bytes) -> None:
    while True:
        await reader.read(1024)
        await update_keys(secret_key_sensors, 2)


async def handle_simulation_communication(context: ModbusServerContext) -> None:
    """Takes data from queue and sends to client"""
    global last_acquired_switch
    global switch_status
    global modbus_data_queue
    global arrival_file_version
    global departure_file_version
    global file_secret_key
    global entries_in_gui
    global sensor_key

    loop = asyncio.get_event_loop()
    switch_queue = asyncio.Queue()

    func_code = 3  # function code for modbus that we want to read and write data from holding register
    slave_id = 0x00  # we broadcast the data to all the connected slaves

    sequence_number_switch = 0
    sequence_number_gui = 0
    sequence_number_track = 0

    rotation_switch = 0
    rotation_gui = 0
    rotation_track = 0

    # remove old json files
    try:
        logging.info("Removed old files")
        os.remove(f"{os.getcwd()}/JSONs/derparture.json")
        os.remove(f"{os.getcwd()}/JSONs/arrival.json")

    except FileNotFoundError:
        pass

    await asyncio.sleep(1)

    loop.create_task(update_departure())
    loop.create_task(update_arrival())

    # wait so we have time to update the json files
    await asyncio.sleep(3)

    await train_match()

    departure_data = await read_from_file(1)
    arrival_data = await read_from_file(0)

    max_arrival_id = max([int(atrain.get('id', 0)) for atrain in arrival_data], default=0)

    success = False

    logging.info("Finding tracks where a train already has arrived to")
    for d_train in departure_data:
        if 'id' not in d_train:
            max_arrival_id += 1
            d_train['id'] = str(max_arrival_id)
            logging.info(f"Found train and occupied track {d_train['TrackAtLocation']}")
            track_status[int(d_train['TrackAtLocation']) - 1] = 1
            await modbus_data_queue.put(["T", d_train['TrackAtLocation'], "O"])
            await modbus_data_queue.put(["C", d_train['TrackAtLocation']])
            await track_semaphore.acquire()

            train_data = [
                "N",
                "-",
                d_train['EstimatedTime'],
                d_train['TrackAtLocation'],
                str(max_arrival_id)
            ]

            await train_queue.put(train_data)
            created_trains.append(str(max_arrival_id))
        else:
            if success:
                break
            success = True

    await write_to_file(departure_data, 1)

    await departure_to_data()

    send_data.set()
    loop.create_task(send_new_entry())
    loop.create_task(arrival())
    loop.create_task(sensor_comm())
    loop.create_task(acquire_switch(switch_queue))
    loop.create_task(hmi_helper())
    loop.create_task(communication_with_trains())

    # wait until client has connected
    while context[slave_id].getValues(func_code, datastore_size - 2, 1) == [0]:
        logging.info("Waiting for client to connect; sleeping 2 second")
        await asyncio.sleep(2)  # give the server control so it can answer the client

    logging.info("Switch has connected to modbus")

    while True:
        try:
            reader_switch, writer_switch = await asyncio.open_connection('localhost', 12344)
            break  # Break out of the loop if connection is successful
        except ConnectionRefusedError:
            logging.info("Connection to asyncio server failed. Retrying...")
            await asyncio.sleep(1)  # Wait for a while before retrying
        except OSError:
            logging.info("Connection to asyncio server failed. Retrying...")
            await asyncio.sleep(1)  # Wait for a while before retrying

    logging.info("Connected to asyncio switch server")

    derived_key = await dh_exchange(reader_switch, writer_switch)
    switch_key = base64.urlsafe_b64encode(derived_key)

    while True:
        try:
            reader_gui, writer_gui = await asyncio.open_connection('localhost', 12346)
            break  # Break out of the loop if connection is successful
        except ConnectionRefusedError:
            logging.info("Connection to asyncio server failed. Retrying...")
            await asyncio.sleep(1)  # Wait for a while before retrying
        except OSError:
            logging.info("Connection to asyncio server failed. Retrying...")
            await asyncio.sleep(1)  # Wait for a while before retrying

    logging.info("Connected to asyncio gui server")

    derived_key = await dh_exchange(reader_gui, writer_gui)
    gui_key = base64.urlsafe_b64encode(derived_key)

    while True:
        try:
            reader_track, writer_track = await asyncio.open_connection('localhost', 13006)
            break  # Break out of the loop if connection is successful
        except ConnectionRefusedError:
            logging.info("Connection to asyncio server failed. Retrying...")
            await asyncio.sleep(1)  # Wait for a while before retrying
        except OSError:
            logging.info("Connection to asyncio server failed. Retrying...")
            await asyncio.sleep(1)  # Wait for a while before retrying

    logging.info("Connected to asyncio track server")

    derived_key = await dh_exchange(reader_track, writer_track)
    sensor_key = base64.urlsafe_b64encode(derived_key)

    loop.create_task(rotation_comm(reader_track, sensor_key))

    track_client = AsyncModbusTlsClient(
        "localhost",
        port=13000,
        framer=ModbusTlsFramer,
        certfile=cert,
        keyfile=key,
        server_hostname="host",
    )

    await track_client.connect()
    # if we can't connect try again after 5 seconds, if the server hasn't been started yet
    while not track_client.connected:
        logging.info("Couldn't connect to track server, trying again in 5 seconds")
        await asyncio.sleep(5)
        await track_client.connect()
    logging.info("Connected to track sensor server")

    while True:
        # Run blocking call in executor so all the other tasks can run and the server
        data = await modbus_data_queue.get()
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
        # Packet: ["a", "track", "id"]

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

        # C: populates the train station at the beginning if a train already exists there
        # Packet: ["C", "track"]

        # H: arrival package to the gui. Marks that a train has arrived and to which track it has arrived
        # Packet: ["H", "track"]

        # B: Remove a train from the timetable. Only send if train hasn't arrived yet.
        # Packet: ["B", "index"]

        # ----------------- PLC ----------------- #
        # Z: update the key for modbus/tcp
        # Packet ["Z", "track"]

        # ----------------- Uncategorized ----------------- #
        # K: update the key for modbus/tcp
        # Packet ["K", requestor, b"key", b"encrypted new key"]

        match data[0]:
            case "a":
                logging.info("Received arrival update from a train")

                arrived_trains.append(int(data[2]))

                switch_status, sequence_number_switch = await get_switch_status(context, switch_key,
                                                                                sequence_number_switch)

                if int(switch_status) != int(data[1]):
                    logging.info("Updating track in json, due to switch status being different to expected track")
                    await modbus_data_queue.put(["u", data[2], switch_status])

                await modbus_data_queue.put(["S", switch_status])

                msg = [
                    "T",
                    data[2],
                    str(switch_status)
                ]
                await train_queue.put(msg)

                await modbus_data_queue.put(["H", str(switch_status)])
            case "s":
                if data[1] == 2:
                    logging.info("Received switch update from hmi")

                    await modbus_data_queue.put(["Z", data[2]])

                    switch_status = int(data[2])
                    last_acquired_switch = datetime.now()
                    await modbus_data_queue.put(["S", data[2]])
                else:
                    logging.info("Received switch update from a train")
                    await switch_queue.put(data[1:])

                    difference = max((last_acquired_switch - datetime.now()).total_seconds(), 0)
                    update_time = (3 * 60 * switch_queue.qsize() + 60 * (switch_queue.qsize() - 1) + difference) // 60

                    if int(data[1]) == 0:
                        logging.info("Received switch update from departure function")

                        json_data = await read_from_file(1)

                        for i in range(len(json_data)):
                            if json_data[i]['id'] == data[3]:
                                json_data[i]["EstimatedTime"] = (
                                        datetime.now() + timedelta(minutes=update_time) - timedelta(
                                    minutes=1)).strftime("%Y-%m-%d %H:%M")

                                await write_to_file(json_data, 1)

                                await modbus_data_queue.put(["U", str(i), json_data[i]['EstimatedTime'],
                                                             json_data[i]['TrackAtLocation']])
                    else:
                        logging.info("Received switch update from arrival function")

                        json_data = await read_from_file(0)
                        n_time = (datetime.now() + timedelta(minutes=update_time) - timedelta(minutes=1))

                        for i in range(len(json_data) - 1, -1, -1):
                            if json_data[i]['id'] == data[3]:
                                if datetime.strptime(json_data[i]["EstimatedTime"], "%Y-%m-%d %H:%M") != n_time:
                                    json_data[i]["EstimatedTime"] = n_time.strftime("%Y-%m-%d %H:%M")
                                    await write_to_file(json_data, 0)
                                    await update_departure_time(json_data[i]['id'], n_time, True)
                                    break
            case "r":
                logging.info("Received removal wish")

                entries_in_gui -= 1

                if entries_in_gui < 4:
                    send_data.set()

                json_data = await read_from_file(0)

                has_arrived = False

                for idx, train in enumerate(json_data):
                    if 'id' in train and train['id'] == data[2]:
                        if data[2] in arrived_trains:
                            has_arrived = True
                        else:
                            logging.info("Train hasn't arrived yet")

                            for j in range(len(created_trains)):
                                if data[2] == created_trains[j]:
                                    logging.info("Found created train")
                                    msg = [
                                        "R",
                                        train['id']
                                    ]
                                    await train_queue.put(msg)
                                    del created_trains[j]
                                    track_reservations[int(train["TrackAtLocation"]) - 1] = 0

                                    break

                            for i in range(switch_queue.qsize()):
                                t = await switch_queue.get()

                                if t[3] != data[2]:
                                    await switch_queue.put(t)

                        if idx == 0:
                            wake_arrival.set()

                        train['IsRemoved'] = True
                        json_data.append(json_data.pop(idx))
                        await write_to_file(json_data, 0)
                        break
                    else:
                        has_arrived = True

                json_data = await read_from_file(1)

                for idx, train in enumerate(json_data):
                    if 'id' in train and train['id'] == data[2]:
                        if has_arrived:
                            switch_status, sequence_number_switch = await get_switch_status(context, switch_key,
                                                                                            sequence_number_switch)
                            if switch_status != data[1]:
                                logging.error("The train derailed when it tried to leave the station")

                            logging.info(created_trains)
                            logging.info(data[2])

                            for i in range(len(created_trains)):
                                if data[2] == created_trains[i]:
                                    logging.info("Found created train")
                                    msg = [
                                        "R",
                                        train['id']
                                    ]
                                    await train_queue.put(msg)
                                    del created_trains[i]
                                    break
                            await modbus_data_queue.put(["R", train['TrackAtLocation'], str(idx)])
                        else:
                            await modbus_data_queue.put(["B", str(idx)])

                        train['IsRemoved'] = True
                        json_data.append(json_data.pop(idx))
                        await write_to_file(json_data, 1)
                        await departure_to_data()
                        break
            case "t":
                logging.info("Received track status update")
                if data[2] == "O":
                    track_status[data[1] - 1] = 1
                    logging.info("Occupied track")

                    # Just for the hmi. If all the tracks are occupied don't lock this function
                    if not track_semaphore.locked() and len(data) == 4:
                        await track_semaphore.acquire()

                    await modbus_data_queue.put(["T", data[1], "O"])
                else:
                    track_status[data[1] - 1] = 0

                    logging.info("Cleared track")
                    track_semaphore.release()
                    await modbus_data_queue.put(["T", str(data[1]), "A"])

                await departure_to_data()
            case "u":
                logging.info("Received wish to update train data for departure from simulation")

                json_data = await read_from_file(1)

                for i in range(len(json_data)):
                    if json_data[i]["id"] == data[1]:
                        json_data[i]["TrackAtLocation"] = data[2]
                        await modbus_data_queue.put(
                            ["U", str(i), json_data[i]['EstimatedTime'],
                             json_data[i]["TrackAtLocation"]])
                        logging.info("updated track in departure file")
                        break

                await write_to_file(json_data, 1)
            case "h":
                logging.info("Received a new train from hmi")

                arrival_data = await read_from_file(0)
                departure_data = await read_from_file(1)

                used_ids_list1 = set(item.get('id') for item in arrival_data)
                used_ids_list2 = set(item.get('id') for item in departure_data)

                used_ids = used_ids_list1.union(used_ids_list2)

                available_id = 1

                logging.info("Finding available id")
                while str(available_id) in used_ids:
                    available_id += 1

                existing_times_arrival = [datetime.strptime(item['EstimatedTime'], "%Y-%m-%d %H:%M") for item in
                                          arrival_data]
                existing_times_departure = [datetime.strptime(item['EstimatedTime'], "%Y-%m-%d %H:%M") for item in
                                            departure_data]

                # Merge the two lists while keeping them sorted
                merged_existing_times = list(merge(existing_times_arrival, existing_times_departure))

                current_time = datetime.now()
                today_date = current_time.date()

                # Parse the received time from the HMI data
                recv_time = datetime.combine(today_date, datetime.strptime(data[2], "%H:%M").time())

                # Ensure received time is in the future
                if recv_time < current_time:
                    recv_time += timedelta(days=1)

                advertised_arrival_time = recv_time - timedelta(minutes=10)

                # Ensure the advertised arrival time is in the future
                if advertised_arrival_time < current_time:
                    estimated_time = current_time
                else:
                    estimated_time = advertised_arrival_time

                idx = bisect.bisect_left(merged_existing_times, estimated_time)

                is_found = False
                arrival_idx = 0

                # case 1: can be scheduled before all the other trains
                if idx == 0:
                    # Check that the train has enough time to arrive before the next train
                    difference = merged_existing_times[0] - (estimated_time + timedelta(minutes=1))
                    # Ensure trains are not scheduled too close together
                    if difference >= timedelta(minutes=2):
                        train_data = {'AdvertisedTime': advertised_arrival_time.strftime("%Y-%m-%d %H:%M"),
                                      'EstimatedTime': estimated_time.strftime("%Y-%m-%d %H:%M"),
                                      'TrackAtLocation': data[4],
                                      'IsRemoved': False,
                                      'TrainOwner': "hmi",
                                      'id': str(available_id)}

                        arrival_data.insert(arrival_idx, train_data)

                        is_found = True

                # Case 2: Train can be scheduled between existing trains
                if not is_found and idx != len(merged_existing_times):
                    for _idx in range(idx - 1, idx + len(merged_existing_times[idx:]) - 1):
                        # Check if there is enough time between adjacent trains for scheduling
                        if ((merged_existing_times[_idx + 1] - timedelta(minutes=2)) - (
                                merged_existing_times[_idx] + timedelta(
                            minutes=1)) > timedelta(minutes=3) and max(
                            (merged_existing_times[_idx] + timedelta(minutes=1)),
                            advertised_arrival_time + timedelta(minutes=1)) <
                                merged_existing_times[_idx + 1] - timedelta(minutes=2)):
                            estimated_time = max((merged_existing_times[_idx] + timedelta(minutes=1)),
                                                 advertised_arrival_time)

                            train_data = {'AdvertisedTime': advertised_arrival_time.strftime("%Y-%m-%d %H:%M"),
                                          'EstimatedTime': estimated_time.strftime("%Y-%m-%d %H:%M"),
                                          'TrackAtLocation': data[4],
                                          'IsRemoved': False,
                                          'TrainOwner': "hmi",
                                          'id': str(available_id)}

                            arrival_idx = bisect.bisect_right(existing_times_arrival, estimated_time)
                            arrival_data.insert(arrival_idx, train_data)

                            is_found = True
                            break

                # Case 3: Train can be scheduled after all existing trains
                if not is_found:
                    # Calculate the estimated time for scheduling the train after the last existing train
                    estimated_time = max((merged_existing_times[-1] + timedelta(minutes=1)), advertised_arrival_time)

                    train_data = {'AdvertisedTime': advertised_arrival_time.strftime("%Y-%m-%d %H:%M"),
                                  'EstimatedTime': estimated_time.strftime("%Y-%m-%d %H:%M"),
                                  'TrackAtLocation': data[4],
                                  'IsRemoved': False,
                                  'TrainOwner': "hmi",
                                  'id': str(available_id)}

                    arrival_data.append(train_data)

                await write_to_file(arrival_data, 0)

                is_found = False
                best_departure_time = timedelta(minutes=0)
                departure_estimated_time = estimated_time + timedelta(minutes=5)
                departure_idx = bisect.bisect_right(merged_existing_times, departure_estimated_time)

                departure_index = 0

                # case 1: can be scheduled before all the other trains
                if departure_idx == 0:
                    start_interval = (merged_existing_times[0] - timedelta(minutes=2)) - (
                            departure_estimated_time + timedelta(minutes=1))

                    if start_interval >= timedelta(minutes=10):
                        is_found = True
                        train_data = {
                            'AdvertisedTime': (estimated_time + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M"),
                            'EstimatedTime': (estimated_time + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M"),
                            'ToLocation': data[3],
                            'TrackAtLocation': data[4],
                            'IsRemoved': False,
                            'TrainOwner': "hmi",
                            'id': str(available_id)}

                        departure_data.insert(0, train_data)
                    elif start_interval >= timedelta(minutes=5):
                        best_departure_time = start_interval

                if not is_found and departure_idx != len(merged_existing_times):
                    for _idx in range(idx - 1, idx + len(merged_existing_times[idx:]) - 1):
                        start_interval = (merged_existing_times[_idx] + timedelta(minutes=1)) - (
                                departure_estimated_time - timedelta(minutes=2))
                        end_interval = (merged_existing_times[_idx + 1] - timedelta(minutes=2)) - (
                                departure_estimated_time + timedelta(minutes=1))

                        if start_interval <= timedelta(minutes=10) <= end_interval:
                            is_found = True

                            train_data = {
                                'AdvertisedTime': (estimated_time + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M"),
                                'EstimatedTime': (estimated_time + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M"),
                                'ToLocation': data[3],
                                'TrackAtLocation': data[4],
                                'IsRemoved': False,
                                'TrainOwner': "hmi",
                                'id': str(available_id)}

                            departure_index = bisect.bisect_right(existing_times_departure,
                                                                  (estimated_time + timedelta(minutes=10)))
                            departure_data.insert(departure_index, train_data)
                            break

                        closest_time = min(max(timedelta(minutes=10), start_interval), end_interval)

                        if timedelta(minutes=5) <= closest_time:
                            dist1 = abs(timedelta(minutes=10) - best_departure_time)
                            dist2 = abs(timedelta(minutes=10) - closest_time)

                            if best_departure_time >= timedelta(minutes=5):
                                if dist1 > dist2:
                                    best_departure_time = closest_time
                                else:
                                    # all the other times will be greater. No need to look more
                                    train_data = {'AdvertisedTime': (
                                            estimated_time + min(timedelta(minutes=10), best_departure_time)).strftime(
                                        "%Y-%m-%d %H:%M"),
                                        'EstimatedTime': (estimated_time + best_departure_time).strftime(
                                            "%Y-%m-%d %H:%M"),
                                        'ToLocation': data[3],
                                        'TrackAtLocation': data[4],
                                        'IsRemoved': False,
                                        'TrainOwner': "hmi",
                                        'id': str(available_id)}

                                    departure_index = bisect.bisect_right(existing_times_departure,
                                                                          (estimated_time + best_departure_time))

                                    departure_data.insert(departure_index, train_data)

                                    is_found = True
                                    break
                            elif closest_time > timedelta(minutes=10):
                                train_data = {
                                    'AdvertisedTime': (estimated_time + timedelta(minutes=10)).strftime(
                                        "%Y-%m-%d %H:%M"),
                                    'EstimatedTime': (estimated_time + closest_time).strftime("%Y-%m-%d %H:%M"),
                                    'ToLocation': data[3],
                                    'TrackAtLocation': data[4],
                                    'IsRemoved': False,
                                    'TrainOwner': "hmi",
                                    'id': str(available_id)}

                                departure_index = bisect.bisect_right(existing_times_departure,
                                                                      (estimated_time + closest_time))
                                departure_data.insert(departure_index, train_data)
                                is_found = True
                                break

                if not is_found:
                    best_departure_time = max((merged_existing_times[-1] + timedelta(minutes=1)),
                                              departure_estimated_time + timedelta(minutes=5))

                    train_data = {'AdvertisedTime': (estimated_time + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M"),
                                  'EstimatedTime': best_departure_time.strftime("%Y-%m-%d %H:%M"),
                                  'ToLocation': data[3],
                                  'TrackAtLocation': data[4],
                                  'IsRemoved': False,
                                  'TrainOwner': "hmi",
                                  'id': str(available_id)}

                    departure_index = len(departure_data)
                    departure_data.append(train_data)

                await write_to_file(departure_data, 1)
                await departure_to_data()

                if arrival_idx == 0:
                    wake_arrival.set()

                if departure_index < 4:
                    for i in range(3, -1, -1):
                        await modbus_data_queue.put(["B", str(i)])
                        entries_in_gui -= 1
                    send_data.set()

                await departure_to_data()
            case "K":
                arrival_data = await read_from_file(0)
                departure_data = await read_from_file(1)
                departure_file_version = 0
                arrival_file_version = 0

                rotation = [rotation_switch, rotation_gui, rotation_track]
                writer = [writer_switch, writer_gui, writer_track]
                reader = [reader_switch, reader_gui, reader_track]
                sequence_number = [sequence_number_switch, sequence_number_gui, sequence_number_track]

                if rotation[data[1]] == 3:
                    header_char = struct.pack('!II', MESSAGE_TYPE_SINGLE_CHAR, 1)
                    combined_data_char = header_char + b'D'

                    writer[data[1]].write(combined_data_char)
                    await writer[data[1]].drain()

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

                    writer[data[1]].write(public_key_bytes)
                    await writer[data[1]].drain()

                    public_key_bytes = await reader[data[1]].read(2048)

                    writer[data[1]].write(data[2])
                    await writer[data[1]].drain()

                    # can just reuse the generated key as our challenge
                    secret = choose_characters(data[2])
                    received_public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

                    shared_secret = private_key.exchange(received_public_key)

                    shared_secret += secret.encode()

                    # Derive a key from the shared secret using a key derivation function (KDF)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data',
                    ).derive(shared_secret)

                    # Use the key material to generate a Fernet key
                    if data[1] == 0:
                        switch_key = base64.urlsafe_b64encode(derived_key)
                        expected_signature = hmac.new(switch_key, data[2], hashlib.sha256)
                    else:
                        gui_key = base64.urlsafe_b64encode(derived_key)
                        expected_signature = hmac.new(gui_key, data[2], hashlib.sha256)

                    recv_signature = await reader[data[1]].read(1024)

                    if not expected_signature.hexdigest() == recv_signature.hex():
                        logging.critical("MITM detected")
                        raise RuntimeError

                    rotation[data[1]] = 0
                else:
                    if data[1] == 0:
                        switch_key = data[2]
                    else:
                        gui_key = data[2]

                    header_char = struct.pack('!II', MESSAGE_TYPE_SINGLE_CHAR, 1)
                    combined_data_char = header_char + b'K'

                    writer[data[1]].write(combined_data_char)
                    await writer[data[1]].drain()

                    await asyncio.sleep(1)
                    
                    writer[data[1]].write(data[4])
                    await writer[data[1]].drain()
                    logging.info("sent new secret key")
                    rotation[data[1]] += 1

                file_secret_key = data[3]
                sequence_number[data[1]] = 0

                await write_to_file(arrival_data, 0)
                await write_to_file(departure_data, 1)
                logging.info("updated HMAC in files")
            case "g":
                json_data = await read_from_file(1)
                await modbus_data_queue.put(['r', int(json_data[data[1]]['TrackAtLocation']), json_data[data[1]]['id']])
            case "Z":
                data = "X " + " ".join(str(value) for value in data[1:])

                client_verified = False

                while not client_verified:
                    sequence_number_switch += 1
                    temp_signature = data + str(sequence_number_switch)
                    temp_signature = hmac.new(switch_key, temp_signature.encode(), hashlib.sha256).hexdigest()
                    while True:
                        # Generate 2 bytes
                        nonce = [char for char in secrets.token_bytes(2)]

                        # Check if any character is a space
                        if b' ' not in nonce:
                            break

                    if sequence_number_switch == 100:
                        logging.info("Updating secret key")
                        await update_keys(switch_key, 0)

                    data_to_send = (
                            [sequence_number_switch] + [len(data)] + [ord(char) for char in data] + [32] + nonce +
                            [32] + [ord(char) for char in temp_signature])

                    logging.debug("Sending data")
                    context[slave_id].setValues(func_code, 0x00, data_to_send)

                    logging.debug("Resetting flag")
                    context[slave_id].setValues(func_code, datastore_size - 2, [0])

                    expected_signature = hmac.new(switch_key, str(nonce).encode(), hashlib.sha256).hexdigest()

                    logging.debug(f"nonce {str(nonce)}")
                    expected_signature = [ord(char) for char in expected_signature]
                    logging.debug(f"Expecting: {expected_signature}")

                    while context[slave_id].getValues(func_code, datastore_size - 2, 1) == [0]:
                        logging.debug("Waiting for client to copy datastore; sleeping 0.5 seconds")
                        await asyncio.sleep(0.5)  # give the server control so it can answer the client

                    if context[slave_id].getValues(func_code, 0, 64) == expected_signature:
                        logging.debug("Client is verified")
                        client_verified = True
                    else:
                        logging.critical("Found wrong signature in holding register")
            case _:
                data = " ".join(str(value) for value in data)

                client_verified = False

                while not client_verified:
                    sequence_number_gui += 1
                    temp_signature = data + str(sequence_number_gui)
                    logging.info(temp_signature)
                    temp_signature = hmac.new(gui_key, temp_signature.encode(), hashlib.sha256).hexdigest()
                    while True:
                        # Generate 2 bytes
                        nonce = [char for char in secrets.token_bytes(2)]

                        # Check if any character is a space
                        if b' ' not in nonce:
                            break

                    if sequence_number_gui == 100:
                        logging.info("Updating secret key")
                        await update_keys(gui_key, 1)

                    data_to_send = ([sequence_number_gui] + [len(data)] + [ord(char) for char in data] + [32] + nonce +
                                    [32] + [ord(char) for char in temp_signature])

                    logging.info(data_to_send)

                    logging.debug("Sending data")
                    packed_data = struct.pack('!I{}I'.format(len(data_to_send)), len(data_to_send), *data_to_send)
                    header_packed_data = struct.pack('!II', MESSAGE_TYPE_PACKED, len(packed_data))
                    combined_data_packed_data = header_packed_data + packed_data
                    writer_gui.write(combined_data_packed_data)
                    await writer_gui.drain()

                    expected_signature = [ord(char) for char in
                                          hmac.new(gui_key, str(nonce).encode(), hashlib.sha256).hexdigest()]

                    logging.debug(f"nonce {str(nonce)}")
                    logging.debug(f"Expecting: {expected_signature}")

                    packed_data = await reader_gui.read(1024)

                    received_signature = list(struct.unpack('!64I', packed_data))

                    logging.info(received_signature)

                    if received_signature == expected_signature:
                        logging.debug("Client is verified")
                        client_verified = True
                    else:
                        logging.critical("Found wrong signature")


# ------------------------------- #

if __name__ == '__main__':
    modbus_process = multiprocessing.Process(target=modbus_helper)
    modbus_process.start()

    app.run(ssl_context=(cert, key), debug=False, port=5001)

    modbus_process.join()
