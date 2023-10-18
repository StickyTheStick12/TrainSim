from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
import bcrypt

import modules as SQL

import json
from datetime import datetime, timedelta
import asyncio
import multiprocessing
import logging
from bisect import bisect_right, bisect_left

from pymodbus import __version__ as pymodbus_version
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.server import StartAsyncTlsServer

logging.basicConfig()
_logger = logging.getLogger(__file__)
_logger.setLevel("WARNING")

# Modbus variables
datastore_size = 41  # cant be bigger than 125
modbus_port = 12345

cert = "/home/vboxuser/tls/cert.pem"
key = "/home/vboxuser/tls/key.pem"

app = Flask(__name__)
app.logger.setLevel(logging.ERROR)

# Sessions för login
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

login_manager = LoginManager()
login_manager.init_app(app)

mutex = multiprocessing.Lock()


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
            return redirect(url_for('plcPage'))
        else:
            invalid = True
            return render_template("login.html", invalid=invalid)

    return render_template("login.html", invalid=invalid)


@app.route('/plc', methods=["POST", "GET"])
@login_required
def plcPage(change=None):
    json_data = open_json("data.json")

    track_status = json_data['trackStatus']
    track_status_one = json_data['trackOneStatus']
    track_status_two = json_data['trackTwoStatus']

    if request.method == "GET":
        json_data['trains'] = sortTimeTable(json_data['trains'])
        json_data = trainoccupiestrack(json_data)
        writeToJson('data.json', json_data)

    if request.method == "POST":
        button_clicked = request.form.get("button", False)

        if button_clicked:
            match button_clicked:
                case "track1":
                    if track_status_one == track_status[0]:
                        json_data['trackOneStatus'] = track_status[1]
                    else:
                        json_data['trackOneStatus'] = track_status[0]

                    data = ["T", 1, json_data["trackOneStatus"]]
                    with mutex:
                        modbus_data_queue.put(data)

                case "track2":
                    if track_status_two == track_status[0]:
                        json_data['trackTwoStatus'] = track_status[1]
                    else:
                        json_data['trackTwoStatus'] = track_status[0]

                    data = ["T", 2, json_data["trackTwoStatus"]]
                    with mutex:
                        modbus_data_queue.put(data)

                case "addTimeForm":
                    change = "addTimeForm"

                case "deleteTimeForm":
                    change = "deleteTimeForm"

                case "addNewTime":
                    train_data = {
                        'trainNumber': request.form.get('trainNumber', False),
                        'time': request.form.get('departure', False),
                        'track': request.form.get('tracktype', False),
                        'tracktoken': '0'}

                    temp = insert_timetable(json_data['trains'], train_data)
                    json_data['trains'] = temp[0]
                    json_data = trainoccupiestrack(json_data)
                    data = (["A"] + [temp[1]] + [json_data["trains"][temp[1]]["trainNumber"]] +
                            [json_data["trains"][temp[1]]["time"]] +
                            [json_data["trains"][temp[1]]["track"]])

                    with mutex:
                        modbus_data_queue.put(data)

                case "deleteTime":
                    id = int(request.form.get('id', False))
                    if id <= len(json_data['trains']):
                        json_data['trains'].pop(id - 1)
                        data = ["R"] + [id - 1]
                        with mutex:
                            modbus_data_queue.put(data)

        writeToJson('data.json', json_data)

    return render_template("plc.html", trackStatus=track_status, trackStatusOne=json_data['trackOneStatus'],
                           trackStatusTwo=json_data['trackTwoStatus'], change=change, trainList=json_data['trains'])


@app.route('/logout')
@login_required
def logOutUser():
    logout_user()
    return redirect(url_for("loginPage"))


def open_json(json_file):
    with open(json_file, 'r') as dataFile:
        json_data = json.load(dataFile)
    return json_data


def writeToJson(json_file, data_json):
    data_json = json.dumps(data_json, indent=3)
    with mutex, open(json_file, 'w') as dataFile:
        dataFile.write(data_json)


def trainoccupiestrack(json_data):
    # sets all train tokens to 0 then gives train tokens to the next train thats arriving at the station or the train
    # at the station so it doesnt update its own time
    time_format = "%H:%M"
    now = datetime.now()
    cur_time = now.strftime(time_format)
    cur_time_obj = now.strptime(cur_time, time_format)
    track_status_one = 'Available'
    track_status_two = 'Available'
    for train in json_data['trains']:
        train['tracktoken'] = '0'
    for train in json_data['trains']:
        train_time_obj = datetime.strptime(train['time'], time_format)
        if train['time'] >= cur_time and train_time_obj - timedelta(minutes=5) <= cur_time_obj:
            if train['track'] == '1' and track_status_one == 'Available':
                train['tracktoken'] = '1'
                track_status_one = 'Occupied'
                json_data['trackOneStatus'] = track_status_one

                data = ["T", 1, json_data["trackOneStatus"]]
                with mutex:
                    modbus_data_queue.put(data)

            elif train['track'] == '2' and track_status_two == 'Available':
                train['tracktoken'] = '2'
                track_status_two = 'Occupied'
                json_data['trackTwoStatus'] = track_status_two

                data = ["T", 2, json_data["trackTwoStatus"]]
                with mutex:
                    modbus_data_queue.put(data)

            elif (train['track'] == '1' and track_status_one == 'Occupied') or (
                    train['track'] == '2' and track_status_two == 'Occupied'):
                if train['tracktoken'] == '0':
                    train_time_obj += timedelta(minutes=5)
                    newtime = train_time_obj.strftime("%H:%M")
                    train['time'] = newtime

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


def insert_timetable(train_list: list, new_element: dict) -> (list, int):
    """Insert a new element into the json file and removes the entries whose times have passed."""
    time_to_insert = new_element['time']

    # find the last position with time less than the current time
    current_time = datetime.now().strftime("%H:%M")
    index_to_remove = bisect_right([d['time'] for d in train_list], current_time)

    # send message to gui to remove the entries
    for i in range(1, index_to_remove + 1):
        data = ["R"] + [i]
        with mutex:
            modbus_data_queue.put(data)

    temp = train_list[index_to_remove:]

    # find the first position with time greater than or equal to the new time
    index_to_insert = bisect_left([d['time'] for d in temp], time_to_insert)
    temp.insert(index_to_insert, new_element)
    return temp, index_to_insert


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

    # ssl_context = ssl.create_default_context()
    # ssl_context.load_cert_chain(certfile="cert.perm", keyfile="key.perm")  # change to file path
    address = ("localhost", modbus_port)  # change to correct port
    # _logger.info(f"Server is listening on {"localhost"}:{modbus_port}")

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


async def send_data(context: ModbusServerContext) -> None:
    """Takes data from queue and sends to client"""
    loop = asyncio.get_event_loop()

    func_code = 3  # function code for modbus that we want to read and write data from holding register
    slave_id = 0x00  # we broadcast the data to all the connected slaves
    address = 0x00  # the address to where we want to write in the holding register

    while True:
        # empty any data that is left in the queue and don't let the flask server write more data to the queue
        # we also won't let the flask server to change the json file now because we want to copy the current values

        with mutex:
            # empty queue if there is any data in it
            while not modbus_data_queue.empty():
                modbus_data_queue.get_nowait()

            json_data = open_json("data.json")

        current_time = datetime.now().strftime("%H:%M")
        index_to_remove = bisect_right([d['time'] for d in json_data['trains']], current_time)
        json_data['trains'] = json_data['trains'][index_to_remove:]

        writeToJson("data.json", json_data)

        # First send track status
        data = ["T", 1, json_data["trackOneStatus"]]
        modbus_data_queue.put(data)
        data = ["T", 2, json_data["trackTwoStatus"]]
        modbus_data_queue.put(data)

        idx = 0

        # send train data
        for item in json_data['trains']:
            data = ["A"] + [idx] + [value for dict_key, value in item.items() if dict_key != 'tracktoken']
            idx += 1
            modbus_data_queue.put(data)

        # wait until client has connected then go in to the other while loop
        while context[slave_id].getValues(func_code, datastore_size - 2, 1) == [0]:
            _logger.info("Waiting for client to connect; sleeping 2 second")
            await asyncio.sleep(1)  # give the server control so it can answer the client

        restart = False

        # now start sending data
        while not restart:
            restart = False
            # Run blocking call in executor so the server can respond to the client requests
            data = await loop.run_in_executor(None, modbus_data_queue.get)

            # check that index isn't bigger than what can be placed inside a single modbus register
            if data[1] < 65535:
                # convert our list to a string seperated by space "ghjfjfjf 15:14 1"
                t_data = data[0] + " " + " ".join(str(value) for value in data[2:])
                _logger.debug(f"Sending {t_data}")

                # check that we don't write too much data
                if len(t_data) > datastore_size - 5:
                    _logger.error("data is too long to send over modbus")
                    break

                # add the length of the data to the package. We save space if we don't convert it to ascii.
                data = [len(t_data)] + [data[1]] + [ord(char) for char in t_data]
            else:
                # a register is 2 bytes, if we have a number greater than 2 bytes we have to use more than one register
                _logger.error("Maximum allowed trains are 65535")
                return

            _logger.debug(f"converted data: {data}")

            client_check = 0
            while context[slave_id].getValues(func_code, datastore_size - 2, 1) == [0]:
                if client_check == 5:
                    _logger.critical("Client hasn't emptied datastore in 10 seconds; connection may be lost")
                    _logger.info("Restarting server")
                    restart = True
                    break
                client_check += 1
                _logger.debug("Waiting for client to copy datastore; sleeping 2 second")
                await asyncio.sleep(1)  # give the server control so it can answer the client

            if not restart:
                _logger.debug("Client has read data from datastore, writing new data")
                context[slave_id].setValues(func_code, address, data)

                _logger.info("Resetting flag")
                context[slave_id].setValues(func_code, datastore_size - 2, [0])

        # for value in data:
        #    context[slave_id].setValues(func_code, address, value)
        #    address += 1

        # server starting with flag 0
        # client connects and changes it to a 1
        # server writes a 0 to the flag when it writes a new value
        # client polls the flag for a 0 and when it finds that it will read the holding register and change it to a 1


def modbus_helper() -> None:
    """Sets up server and send data task"""
    loop = asyncio.new_event_loop()
    context = setup_server()

    loop.create_task(send_data(context))
    loop.run_until_complete(modbus_server_thread(context))

    return


if __name__ == '__main__':
    modbus_data_queue = multiprocessing.Queue()

    modbus_process = multiprocessing.Process(target=modbus_helper)
    modbus_process.start()

    app.run(ssl_context=(cert, key), debug=False, port="5001")
    SQL.closeSession()
    modbus_process.join()
