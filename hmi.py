from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
import bcrypt

import modules as SQL

import json
from datetime import datetime, timedelta
import asyncio
import threading
import logging
from bisect import bisect_right, bisect_left
from queue import Queue

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
_logger.setLevel("DEBUG")

# Modbus variables
datastore_size = 41  # cant be bigger than 125
modbus_port = 12345

cert = "/home/vboxuser/tls/cert.pem"
key = "/home/vboxuser/tls/key.pem"

app = Flask(__name__)

##Sessions för login
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

login_manager = LoginManager()
login_manager.init_app(app)


class Users(UserMixin):
    def __init__(self,username, password,is_active=True):
        self.id = 1
        self.username = username
        self.password = password
        self.is_active = is_active


    def get_id(self):
        return (self.id)

    def is_active(self,value):
         self.is_active = value
         return


@login_manager.user_loader
def loader_user(user_id):
    #Här måste vi löser ett säkrare sätt
    authenticate = SQL.checkAuthentication()

    user = Users(authenticate[0],authenticate[1])
    return user


@app.route('/', methods=["POST","GET"])
def loginPage(invalid=False):
    if request.method == "POST":

        authenticate = SQL.checkAuthentication()

        ## Här får vi data från loginet. Gör backend saker som kontroller etc
        user_credentials = {'username': request.form["username"], 'password': request.form["pwd"]}
        user = Users(user_credentials['username'],user_credentials['password'])

        if user.username == authenticate[0]:
            login_user(user)
            return redirect(url_for('plcPage'))
        else:
            invalid=True
            return render_template("login.html",invalid=invalid)


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
        jsonData = trainoccupiestrack(trackStatusOne, trackStatusTwo, jsonData)
        writeToJson('data.json', jsonData)

    if request.method == "POST":
        buttonClicked = request.form.get("button", False)

        if buttonClicked != False:
            match buttonClicked:
                case "track1":
                    if trackStatusOne == trackStatus[0]:
                        trackStatusOne = trackStatus[1]
                        jsonData['trackOneStatus'] = trackStatus[1]
                    else:
                        trackStatusOne = trackStatus[0]
                        jsonData['trackOneStatus'] = trackStatus[0]

                    data = ["T", 1, jsonData["trackOneStatus"]]
                    modbus_data_queue.put(data)

                case "track2":
                    if trackStatusTwo == trackStatus[0]:
                        trackStatusTwo = trackStatus[1]
                        jsonData['trackTwoStatus'] = trackStatus[1]
                    else:
                        trackStatusTwo = trackStatus[0]
                        jsonData['trackTwoStatus'] = trackStatus[0]

                    data = ["T", 2, jsonData["trackTwoStatus"]]
                    modbus_data_queue.put(data)

                case "addTimeForm":
                    change = "addTimeForm"

                case "deleteTimeForm":
                    change = "deleteTimeForm"

                case "addNewTime":
                    trainData = {
                                 'trainNumber': request.form.get('trainNumber', False),
                                 'time': request.form.get('departure', False),
                                 'track': request.form.get('tracktype', False)}

                    data = trainData.copy()
                    trainData['tracktoken'] = '0'

                    temp = insert_timetable(jsonData['trains'], trainData)
                    jsonData['trains'] = temp[0]
                    jsonData = trainoccupiestrack(trackStatusOne, trackStatusTwo, jsonData)
                    data = ["A"] + [temp[1]] + list(data.values())

                    modbus_data_queue.put(data)

                case "deleteTime":
                    id = int(request.form.get('id', False))
                    if id <= len(jsonData['trains']):
                        jsonData['trains'].pop(id - 1)
                        data = ["R"] + [id - 1]
                        modbus_data_queue.put(data)

        writeToJson('data.json', jsonData)

    return render_template("plc.html", trackStatus=trackStatus, trackStatusOne=jsonData['trackOneStatus'],
                           trackStatusTwo=jsonData['trackTwoStatus'], change=change, trainList=jsonData['trains'])


@app.route('/logout')
@login_required
def logOutUser():
    logout_user()
    return redirect(url_for("loginPage"))


def openJson(jsonFile):
    with open(jsonFile, 'r') as dataFile:
        jsonData = json.load(dataFile)
    return jsonData


def writeToJson(jsonFile,dataJson):
    dataJson = json.dumps(dataJson,indent=3)
    with open(jsonFile, 'w') as dataFile:
        dataFile.write(dataJson)


def trainoccupiestrack(trackStatusOne, trackStatusTwo, jsonData):
    # sets all train tokens to 0 then gives train tokens to the next train thats arriving at the station or the train at the station so it doesnt update its own time
    timeFormat = "%H:%M"
    now = datetime.now()
    curTime = now.strftime(timeFormat)
    curTimeObj = now.strptime(curTime, timeFormat)
    trackStatusOne = 'Available'
    trackStatusTwo = 'Available'
    for train in jsonData['trains']:
        train['tracktoken'] = '0'
    for train in jsonData['trains']:
        trainTimeObj = datetime.strptime(train['time'], timeFormat)
        if train['time'] >= curTime and trainTimeObj - timedelta(minutes=5) <= curTimeObj:
            if train['track'] == '1' and trackStatusOne == 'Available':
                train['tracktoken'] = '1'
                trackStatusOne = 'Occupied'
                jsonData['trackOneStatus'] = trackStatusOne
            elif train['track'] == '2' and trackStatusTwo == 'Available':
                train['tracktoken'] = '2'
                trackStatusTwo = 'Occupied'
                jsonData['trackTwoStatus'] = trackStatusTwo
            elif (train['track'] == '1' and trackStatusOne == 'Occupied') or (
                    train['track'] == '2' and trackStatustwo == 'Occupied'):
                if train['tracktoken'] == '0':
                    trainTimeObj += timedelta(minutes=5)
                    newtime = trainTimeObj.strftime("%H:%M")
                    train['time'] = newtime

    return jsonData


def sortTimeTable(trainList):
    '''
        Functions takes in a trainList with Dict in it
    '''
    now = datetime.now()
    curTime = now.strftime("%H:%M")
    tempTrainList = sorted(trainList, key=lambda x: (x['time'] >= curTime, x['time']))
    trainList= tempTrainList.copy()
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

    # find the last position with time less than the current time
    current_time = datetime.now().strftime("%H:%M")
    index_to_remove = bisect_right([d['time'] for d in train_list], current_time)
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

    while True:
        # Run blocking call in executor so the server can respond to the client requests
        data = await loop.run_in_executor(None, modbus_data_queue.get)

        func_code = 3  # function code for modbus that we want to read and write data from holding register
        slave_id = 0x00  # we broadcast the data to all the connected slaves
        address = 0x00  # the address to where to holding register are, i.e the start address in our case but we can write in the middle too

        # check that index isn't bigger than what can be placed inside a single modbus register
        if data[1] < 65535:
            # convert our list to a string seperated by space "ghjfjfjf 15:14 1"
            tData = data[0] + " " + " ".join(str(value) for value in data[2:])
            _logger.debug(f"Sending {tData}")

            # check that we don't write too much data
            if len(tData) > datastore_size - 5:
                _logger.error("data is too long to send over modbus")
                return

            # add the length of the data to the package. We save space if we don't convert it to ascii.
            data = [len(tData)] + [data[1]] + [ord(char) for char in tData]
        else:
            # a register is 2 bytes, if we have a number greater than 2 bytes we have to use more than one register
            _logger.critical("Maximum allowed trains are 65535")
            return

        _logger.debug(f"converted data: {data}")

        client_check = 0
        while context[slave_id].getValues(func_code, datastore_size-2, 1) == [0]:
            if client_check == 5:
                _logger.critical("Client hasn't emptied datastore in 10 seconds; connection may be lost")
                return
            client_check += 1
            _logger.debug("Waiting for client to copy datastore; sleeping 2 second")
            await asyncio.sleep(2)  # give the server control so it can answer the client

        _logger.debug("Client has read data from datastore, writing new data")
        context[slave_id].setValues(func_code, address, data)

        _logger.debug("Resetting flag")
        context[slave_id].setValues(func_code, datastore_size - 2, [0])

        # for value in data:
        #    context[slave_id].setValues(func_code, address, value)
        #    address += 1

        # server starting with flag 0
        # client connects and changes it to a 1
        # server writes a 0 to the flag when it writes a new value
        # client polls the flag for a 0 and when it finds that it will read the holding register and change it to a 1


def modbus_helper() -> None:
    """Helps start modbus from a new thread"""
    loop = asyncio.new_event_loop()
    context = setup_server()

    jsonData = openJson("data.json")

    current_time = datetime.now().strftime("%H:%M")
    index_to_remove = bisect_right([d['time'] for d in jsonData['trains']], current_time)
    jsonData['trains'] = jsonData['trains'][index_to_remove:]

    writeToJson("data.json", jsonData)

    # First send track status
    data = ["T", 1, jsonData["trackOneStatus"]]
    modbus_data_queue.put(data)
    data = ["T", 2, jsonData["trackTwoStatus"]]
    modbus_data_queue.put(data)

    # send train data
    for item in jsonData['trains']:
        data = ["A"] + [value for key, value in item.items() if key != 'tracktoken']
        data[1] = int(data[1]) 
        modbus_data_queue.put(data)

    loop.create_task(send_data(context))
    loop.run_until_complete(modbus_server_thread(context))
    _logger.info("Exiting modbus thread")


if __name__ == '__main__':
    modbus_data_queue = Queue()

    modbus_thread = threading.Thread(target=modbus_helper)
    modbus_thread.start()

    app.run(ssl_context=(cert, key), debug=False, port="5001")
    SQL.closeSession()

    modbus_thread.join()
