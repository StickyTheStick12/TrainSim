## Introduction - Project Structure

The project is organized into two main directories: `attack` and `simulation`. The `simulation` directory is further divided into several subdirectories:

### Simulation Directory

#### 1. **TLS Subdirectory**
   - Contains TLS certificates and keys used for securing communication in Flask and Modbus.

#### 2. **Log Subdirectory**
   - Stores log files generated by the program, excluding Flask logs, which are placed inside `data.json`.

#### 3. **Static Subdirectory**
   - Holds CSS files used for styling.

#### 4. **Templates Subdirectory**
   - Contains HTML files utilized by the Flask application for rendering pages.

#### 5. **Script Subdirectory**
   - Houses all the necessary scripts required to run the simulation.

## Installation and Execution Guidelines

To run the program, start by installing the required dependencies. The simplest way is to use the provided requirements list and execute the following command:

```bash
pip install -r requirements.txt
```

Once the dependencies are installed, you can use the provided Makefile for convenient program execution. The Makefile supports three different start commands:

1. **Single Terminal (make start):**
    ```bash
    make start
    ```
   - This command runs all scripts in the same terminal.

2. **Gnome Terminals (make gnomestart):**
    ```bash
    make gnomestart
    ```
   - Spawns a new Gnome terminal for each script. Note: Gnome terminals are required for this option.

3. **Xterminals (make xstart):**
    ```bash
    make xstart
    ```
   - Spawns a new Xterminal for each script. Note: Xterminals are required for this option.

Choose the option that best fits your environment and preferences. 


## Architecture picture

## HMI Description

The project features two different HMIs:

### GUI Application

The GUI application is designed to provide information similar to what a user would observe at a train station. Key features include:
- **Departure Times:** Displays departure times for trains, at which track they depart and to where.
- **Switch Status:** Indicates the status of the switch.
- **Train Presence:** Shows if a train is currently at the station.
- **Track Status:** Provides track status information (not visible in a typical train station).
  
The GUI is read-only and does not allow data modification. It serves as a tool for viewing changes for unauthorized users.

### Web Application

The web application, listening on localhost at port 5001, allows authorized users to modify data. Login credentials are as follows:
- **Username:** root
- **Password:** password

Credentials are stored in `credentials.json`. To change the password, generate a new password using the bcrypt command:
```python
hash = bcrypt.hashpw(your_password.encode(), bcrypt.gensalt())
```
Set the generated hash in the password field.

#### Subpages

1. **Timetable Page:**
   - Default page allowing the creation and deletion of trains.
   - To delete a train, press the delete button and input the train ID shown on the webpage.
   - To create a train, select a track, departure time, and destination.
   - Arrival time is calculated by the simulation based on the provided departure time.
   - Departure time is treated as a wish; the simulation will attempt to find a close match.
   - Track selection is also a wish; the simulation will prefer the chosen track but may adjust based on availability.

2. **Railway Page:**
   - Displays the statuses of tracks (green for available, red for occupied).
   - Buttons are pressable, allowing users to change the status of a specific track.
   - Features a manual switch for selecting a track, which takes precedence over the simulation.

3. **Log Page:**
   - Contains logs of changes made in the Flask app, showing who made the changes and at what time.
   
These three subpages are accessible through the navigation bar.

## Back-end (SCADA-like) Server and PLCs Description

The backend server plays a central role in the simulation, handling various tasks:

### Backend Server
- Queries Trafikverket for train data:
  - Arrivals every 10 minutes.
  - Departures every 40 minutes.
- Saves data into `arrival.json` and `departure.json`, protected with an HMAC for data integrity.
- Manages data received from the web HMI, including logic for creating, deleting, or modifying train, track and switch information.
- Communicates with the GUI application to provide real-time information.

#### SCADA-like Simulation
- Handles switch requests:
  - Immediate response for HMI requests.
  - 3-minute cooldown for train requests, ensuring priority for the train requesting the switch.
- Manages information from track sensors to determine track occupancy.

### Trains Script
- Operates independently and receives necessary data from the simulation.
- Sends switch requests to SCADA server when departing or arriving.
- Updates track sensors when arriving or departing.

### Track Sensors
- Not PLCs themselves, but their data is forwarded to PLCs.
- Each track has its own PLC and Modbus register.
- Notifies the SCADA server of changes in track occupancy when an update occurs.

### Switch
- Receives updates from the SCADA server to change to specific tracks.
- Includes functionality to query its status when a train arrives.
- Adjusts the train route based on the actual switch status if it differs from expectations.


## Communication Protocols (Operator-HMI-SCADA-PLCs)

The simulation employs various communication protocols to facilitate interaction between different components:

### Client and Flask Web App
- **Protocol:** HTTPS
- **Description:** Ensures secure communication between the client and the Flask web application.

### Flask and Simulation/SCADA Server
- **Protocol:** Inter-Process Communication (IPC)
- **Description:** Direct communication method between Flask and the simulation/SCADA server.

### SCADA Server and GUI
- **Protocol:** TCP
- **Authentication:** HMAC with a secret key generated in Diffie-Hellman Group 14
- **Description:** Authenticated TCP communication for real-time information exchange between the SCADA server and the GUI application.

### SCADA Server and Trains
- **Protocol:** TCP
- **Authentication:** HMAC with a secret key generated in Diffie-Hellman Group 14
- **Description:** Secure TCP communication for interaction between the SCADA server and trains.

### Track Sensors
- **Protocol:** TCP (Two Ports)
  - **Port 1:**
    - **Used by:** Trains to send status.
    - **Authentication:** HMAC with a secret key generated in Diffie-Hellman Group 14.
  - **Port 2:**
    - **Used by:** SCADA server to generate a secret key in Diffie-Hellman Group 14 for Modbus communication.
 - **Protocol:** Modbus
 - **Authentication:** HMAC with prior secret.
- **Description:** Modbus communication for sending data to the SCADA server.

### Switch
- **Protocol:** TCP
- **Description:** TCP communication for generating a secret in Diffie-Hellman Group 14.
-  **Protocol:** Modbus
 - **Authentication:** HMAC with prior secret.
- **Description:** Modbus communication for sending and receiving data from the SCADA server.



