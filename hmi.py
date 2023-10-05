from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
import modules as SQL
import json
from datetime import datetime

import asyncio
import threading

from pymodbus import __version__ as pymodbus_version
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)

from pymodbus.device import ModbusDeviceIdentification
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.server import StartAsyncTlsServer

global context

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
    # Här måste vi löser ett säkrare sätt
    user = Users("admin", "password")
    return user


@app.route('/', methods=["POST", "GET"])
def loginPage(invalid=False):
    if request.method == "POST":

        authenticate = SQL.checkAuthentication()

        ## Här får vi data från loginet. Gör backend saker som kontroller etc
        user_credentials = {'username': request.form["username"], 'password': request.form["pwd"]}
        user = Users(user_credentials['username'], user_credentials['password'])

        if user.username == authenticate[0] and user.password == authenticate[1]:
            login_user(user)
            return redirect(url_for('plcPage'))
        else:
            invalid = True
            return render_template("login.html", invalid=invalid)

    return render_template("login.html", invalid=invalid)


@app.route('/plc', methods=["POST", "GET"])
@login_required
def plcPage(change=None):
    now = datetime.now()
    curTime = now.strftime("%H : %M")
    print(curTime)

    jsonData = openJson("data.json")

    trackStatus = jsonData['trackStatus']
    trackStatusOne = jsonData['trackOneStatus']
    trackStatusTwo = jsonData['trackTwoStatus']

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

                case "track2":
                    if trackStatusTwo == trackStatus[0]:
                        trackStatusTwo = trackStatus[1]
                        jsonData['trackTwoStatus'] = trackStatus[1]
                    else:
                        trackStatusTwo = trackStatus[0]
                        jsonData['trackTwoStatus'] = trackStatus[0]

                case "addTime":
                    change = "addTime"

                case "removeTime":
                    change = "removeTime"

        formData = {'trainNumber': request.form.get('trainNumber', False), 'time': request.form.get('departure', False),
                    'track': request.form.get('tracktype', False)}
        print(formData)

        writeToJson('data.json', jsonData)

    return render_template("plc.html", trackStatus=trackStatus, trackStatusOne=trackStatusOne,
                           trackStatusTwo=trackStatusTwo, curTime=curTime, change=change)


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

    address = ("localhost", 12345)  # change to correct port

    await StartAsyncTlsServer(
        context=context,
        host="host",
        identity=identity,
        address=address,
        framer=ModbusTlsFramer,
        certfile="cert.perm",
        keyfile="key.perm",
    )


def setup_server() -> ModbusServerContext:
    """Generates our holding register for the server"""
    # global context
    datablock = ModbusSequentialDataBlock(0x00, [0] * 10) # change to however big our list needs to be
    context = ModbusSlaveContext(
        di=datablock, co=datablock, hr=datablock, ir=datablock)
    context = ModbusServerContext(slaves=context, single=True)

    return context


async def send_data(context: ModbusServerContext, data: list) -> None:
    """Sends data to client"""
    func_code = 3  # function code for modbus that we want to read and write data from holding register
    slave_id = 0x00  # we broadcast the data to all the connected slaves
    address = 0x00  # the address to where to holding register are, i.e the start address in our case but we can write in the middle too

    result = " ".join(data)

    data = [ord(char) for char in result]

    for value in data:
        context[slave_id].setValues(func_code, address, value)
        address += 1


def modbus_helper() -> None:
    global context
    context = setup_server()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(modbus_server_thread(context))


if __name__ == '__main__':
    modbus_thread = threading.Thread(target=modbus_helper)
    modbus_thread.start()

    app.run(ssl_context=("cert.perm", "key.perm"), debug=True, port="5001")
    SQL.closeSession()
