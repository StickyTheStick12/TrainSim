from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import login_user, logout_user, login_required, current_user, LoginManager, UserMixin
import modules as SQL
import json
from datetime import datetime

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


if __name__ == '__main__':
    app.run(debug=True, port="5001")
    SQL.closeSession()