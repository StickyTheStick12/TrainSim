from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
import modules as SQL
import json
import bcrypt
from datetime import datetime, timedelta

import asyncio
import threading
import logging
import socket
import time
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

# TODO: fix modbus communication so we send an index to the gui
# TODO: there may be a problem when we write to the context and the server tries to send the data simultaneously. We may either need to change the modbus source code
# or change the way we send data. The modbus thread may need to read data from the json file instead so we create an async task that will look for anything new to write.

logging.basicConfig()
_logger = logging.getLogger(__file__)
_logger.setLevel("DEBUG")

# Modbus variables
datastore_size = 41
modbus_port = 12345

app = Flask(__name__)

##Sessions för login
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

login_manager = LoginManager()
login_manager.init_app(app)


class Users(UserMixin):
    def __init__(self, username, password, is_active=True):
        self.id = 1
        self.username = username
        self.password = password
        self.is_active = is_active

    def get_id(self):
        return (self.id)

    def is_active(self, value):
        self.is_active = value
        return


@login_manager.user_loader
def loader_user(user_id):
    #Här måste vi löser ett säkrare sätt
    authenticate = SQL.checkAuthentication()

    user = Users(authenticate[0],authenticate[1])
    return user


@app.route('/', methods=["POST", "GET"])
def loginPage(invalid=False):
    if request.method == "POST":

        authenticate = SQL.checkAuthentication()

        ## Här får vi data från loginet. Gör backend saker som kontroller etc
        user_credentials = {'username': request.form["username"], 'password': request.form["pwd"]}
        user = Users(user_credentials['username'], user_credentials['password'])

        if user.username == authenticate[0] and bcrypt.checkpw(user.password.encode(), authenticate[1].encode()):
            login_user(user)
            return redirect(url_for('plcPage'))
        else:
            invalid = True
            return render_template("login.html", invalid=invalid)


    return render_template("login.html",invalid=invalid)


@app.route('/plc', methods=["POST", "GET"])
@login_required
def plcPage(change=None):
    jsonData = openJson("data.json")

    trackStatus = jsonData['trackStatus']
    trackStatusOne = jsonData['trackOneStatus']
    trackStatusTwo = jsonData['trackTwoStatus']

    if request.method == "GET":
        jsonData['trains'] = sortTimeTable(jsonData['trains'])
        jsonData = trainoccupiestrack(trackStatusOne,trackStatusTwo,jsonData)
        writeToJson('data.json', jsonData)

    if request.method == "POST":
        buttonClicked = request.form.get("button", False)
        print(buttonClicked)

        if buttonClicked != False:
            match buttonClicked:
                case "track1":
                    if trackStatusOne == trackStatus[0]:
                        trackStatusOne = trackStatus[1]
                        jsonData['trackOneStatus'] = trackStatus[1]
                    else:
                        trackStatusOne = trackStatus[0]
                        jsonData['trackOneStatus'] = trackStatus[0]

                    data = ["t", 1, jsonData["trackOneStatus"]]
                    send_data(context, data)

                case "track2":
                    if trackStatusTwo == trackStatus[0]:
                        trackStatusTwo = trackStatus[1]
                        jsonData['trackTwoStatus'] = trackStatus[1]
                    else:
                        trackStatusTwo = trackStatus[0]
                        jsonData['trackTwoStatus'] = trackStatus[0]

                    data = ["T", 2, jsonData["trackTwoStatus"]]
                    send_data(context, data)

                case "addTimeForm":
                    change = "addTimeForm"

                case "deleteTimeForm":
                    change = "deleteTimeForm"

                case "addNewTime":
                    trainData = {'trainNumber': request.form.get('trainNumber', False),
                                 'time': request.form.get('departure', False),
                                 'track': request.form.get('tracktype', False)}

                    temp = insert_timetable(jsonData['trains'], trainData)
                    jsonData['trains'] = temp[0]
                    data = ["A"] + list(trainData.values())
                    # add temp[1]

                    send_data(context, data)

                case "deleteTime":
                    id = int(request.form.get('id', False))
                    if id <= len(jsonData['trains']):
                        data = ["R"] + list(jsonData["trains"][id - 1])
                        send_data(context, data)
                        jsonData['trains'].pop(id - 1)

        writeToJson('data.json', jsonData)

    return render_template("plc.html", trackStatus=trackStatus, trackStatusOne=trackStatusOne,
                           trackStatusTwo=trackStatusTwo, change=change, trainList=jsonData['trains'])


@app.route('/logout')
@login_required
def logOutUser():
    logout_user()
    return redirect(url_for("loginPage"))


def openJson(jsonFile):
    with open(jsonFile, 'r') as dataFile:
        jsonData = json.load(dataFile)
    return jsonData


def writeToJson(jsonFile, dataJson):
    dataJson = json.dumps(dataJson, indent=3)
    with open(jsonFile, 'w') as dataFile:
        dataFile.write(dataJson)


def trainoccupiestrack(trackStatusOne,trackStatusTwo,jsonData):
    #goes through the latest train departures and makes tracks available
    timeFormat = "%H:%M"
    now = datetime.now()
    curTime = now.strftime(timeFormat)
    curTimeObj = now.strptime(curTime,timeFormat)

    for train in reversed(jsonData['trains']):
        trainTimeObj = datetime.strptime(train['time'],timeFormat)


def sortTimeTable(trainList):
    '''
        Functions takes in a trainList with Dict in it
    '''
    now = datetime.now()
    curTime = now.strftime("%H:%M")
    tempTrainList = sorted(trainList, key=lambda x: (x['time'] >= curTime, x['time']))
    trainList = tempTrainList.copy()
    for train in trainList:
        if train['time']>curTime:
            break
        else:
            tempTrainList.append(train)
            tempTrainList.pop(0)

    trainList = tempTrainList

    return trainList


def insert_timetable(train_list: list, new_element: dict) -> (list, int):
    """Insert a new element into the json file and removes the entries whose times have passed."""
    time_to_insert = new_element['time']

    # Binary search to find the last position with time less than the current time
    current_time = datetime.now().strftime("%H:%M")
    index_to_remove = bisect_right([d['time'] for d in train_list], current_time)
    # Remove elements with times lower than the current time
    temp = train_list[index_to_remove:]

    # Binary search to find the first position with time greater than or equal to the new time
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
    _logger.info(f"Server is listening on {socket.gethostbyname(socket.gethostname())}:{modbus_port}")

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

    _logger.info("Created datastore")
    return context


def send_data(context: ModbusServerContext, data: list) -> None:
    """Sends data to client"""
    func_code = 3  # function code for modbus that we want to read and write data from holding register
    slave_id = 0x00  # we broadcast the data to all the connected slaves
    address = 0x00  # the address to where to holding register are, i.e the start address in our case but we can write in the middle too

    # convert our list to a string seperated by space "ghjfjfjf 15:14 1"
    data = " ".join(str(value) for value in data)

    # check that we don't write too much data
    if len(data) > datastore_size - 4:
        _logger.error("data is too long to send over modbus")
        return

    # add the length of the data to the package. We save space if we don't convert it to ascii.
    data = [len(data)] + [ord(char) for char in data]

    client_check = 0
    while context[slave_id].getValues(func_code, datastore_size-2, 1) == 0:
        if client_check == 5:
            _logger.critical("Client hasn't emptied datastore in 5 seconds; connection may be lost")
            return
        client_check += 1
        _logger.info("Waiting for client to copy datastore; sleeping 1 second")
        time.sleep(1)

    _logger.info("Client has read data from datastore, writing new data")
    context[slave_id].setValues(func_code, address, data)

    _logger.debug("Resetting flag")
    context[slave_id].setValues(func_code, datastore_size-2, [0])

    # for value in data:
    #    context[slave_id].setValues(func_code, address, value)
    #    address += 1

    # server starting with flag 0
    # client connects and changes it to a 1
    # server writes a 0 to the flag when it writes a new value
    # client polls the flag for a 0 and when it finds that it will read the holding register and change it to a 1


def modbus_helper() -> None:
    """Helps start modbus from a new thread"""
    loop = asyncio.get_event_loop()
    loop.run_until_complete(modbus_server_thread(context))


if __name__ == '__main__':
    cert = "cert.perm"
    key = "key.perm"

    context = setup_server()

    modbus_thread = threading.Thread(target=modbus_helper, args=(context,))
    modbus_thread.start()

    _logger.info("starting flask server")
    app.run(ssl_context=(cert, key), debug=True, port="5001")
    SQL.closeSession()

    modbus_thread.join()

