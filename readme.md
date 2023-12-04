
## **Appendix**

- [Introduction - Project Structure](#introduction---project-structure)
  - [Simulation Directory](#simulation-directory)
    - [TLS Subdirectory](#1-tls-subdirectory)
    - [Log Subdirectory](#2-log-subdirectory)
    - [Static Subdirectory](#3-static-subdirectory)
    - [Templates Subdirectory](#4-templates-subdirectory)
    - [Script Subdirectory](#5-script-subdirectory)
    - [JSONs Subdirectory](#6-jsons-subdirectory)
  
- [Installation and Execution Guidelines](#installation-and-execution-guidelines)
- [Architecture Picture](#architecture-picture)
- [HMI Description](#hmi-description)
  - [GUI Application](#gui-application)
  - [Web Application](#web-application)
    - [Subpages](#subpages)
- [Back-end (SCADA-like) Server and PLCs Description](#back-end-scada-like-server-and-plcs-description)
  - [Backend Server](#backend-server)
    - [SCADA-like Simulation](#scada-like-simulation)
  - [Trains Script](#trains-script)
  - [Track Sensors](#track-sensors)
  - [Switch](#switch)
- [Communication Protocols (Operator-HMI-SCADA-PLCs)](#communication-protocols-operator-hmi-scada-plcs)
  - [Client and Flask Web App](#client-and-flask-web-app)
  - [Flask and Simulation/SCADA Server](#flask-and-simulation-scada-server)
  - [SCADA Server and GUI](#scada-server-and-gui)
  - [SCADA Server and Trains](#scada-server-and-trains)
  - [Track Sensors](#track-sensors-1)
  - [Switch](#switch-1)
- [Description of Normal Operation](#description-of-normal-operation)
- [Description of the Attack Scenario and Steps to Reproduce the Attack](#description-of-the-attack-scenario-and-steps-to-reproduce-the-attack)
- [Security Considerations](#security-considerations)
  - [Key Rotation for Authentication](#key-rotation-for-authentication)
  - [Secure Communication with Modbus and TCP](#secure-communication-with-modbus-and-tcp)
  - [Data Integrity Protection](#data-integrity-protection)
  - [Authentication for Modbus and TCP](#authentication-for-modbus-and-tcp)
    - [Authentication Failure Handling](#authentication-failure-handling)
- [Known Limitations](#known-limitations)
  - [Daytime Operation](#1-daytime-operation)
  - [Maximum Trains](#2-maximum-trains)
  - [Internet Connection](#3-internet-connection)
  
- [References](#references)

## Introduction - Project Structure

The project is organized into two main directories: `attack` and `simulation`. The `simulation` directory is further divided into several subdirectories:

### Simulation Directory

#### 1. **TLS Subdirectory**
   - Contains TLS certificates and keys used for securing communication in Flask and Modbus.

#### 2. **Log Subdirectory**
   - Stores log files generated by the program, excluding Flask logs, which are placed inside `data.json` in the JSONs subdirectory.

#### 3. **Static Subdirectory**
   - Holds CSS files used for styling.

#### 4. **Templates Subdirectory**
   - Contains HTML files utilized by the Flask application for rendering pages.

#### 5. **Script Subdirectory**
   - Houses all the necessary scripts required to run the simulation.
  
#### 6 **JSONs Subdirectory**
- Contains all the JSON files used by the program. data.json is saved between runs while arrival and departure will be deleted when the simulation first is started.

## Installation and Execution Guidelines

To run the program, start by installing the required dependencies. The simplest way is to use the provided requirements list and execute the following command:

```bash
pip install -r requirements.txt
```
Once the dependencies are installed, you can use the provided Makefile for convenient program execution. The Makefile supports four different start commands:

1. **Single Terminal (make start):**
    ```bash
    make start
    ```
   - This command runs all scripts in the same terminal.
   
2. **Konsole (make kstart):**
    ```bash
    make kstart
    ```
    or simply:
    ```bash
    make
    ```
   - Initiates the program with a separate Konsole terminal for each script. Ensure you have Konsole installed to utilize this option.

4. **Gnome Terminals (make gnomestart):**
    ```bash
	make gnomestart
    ```
   - Spawns a new Gnome terminal for each script. Note: Gnome terminals are required for this option.

5. **Xterminals (make xstart):**
    ```bash
    make xstart
    ```
   - Spawns a new Xterminal for each script. Note: Xterminals are required for this option.

Choose the option that best fits your environment and preferences. 

To stop the program, execute either of the following commands:
```bash
make stop
```
or
```bash
make kill
```

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

Credentials are stored in `usercredentials.json`. To change the password, generate a new password using the bcrypt command:
```python
hash = bcrypt.hashpw(your_password.encode(), bcrypt.gensalt())
```
Set the generated hash in the password field.

There is also the possibility to generate a new passsword using this website: [bcrypt-generator.com](https://bcrypt-generator.com/). Gather the given hash and replace it in the password field.

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
- Not a PLC, but part of the simulation part of the project
- Operates independently and receives necessary data from the simulation.
- Sends switch requests to SCADA server when departing or arriving.
- Updates track sensors when arriving or departing*.
- *Please note: In real life the sensors can find the trains alone. How the detection works differs but it can be cameras or infrared sensors. Due to us having virtual trains we have to tell the sensors that a train is at this track and when it isn't anymore but isn't something that trains do in real life. 

### Track Sensors
- Not PLCs themselves, but their data is forwarded to PLCs.
- Each track has its own PLC and Modbus register.
- Notifies the SCADA server of changes in track occupancy when an update occurs.

### Switch
- Receives updates from the SCADA server to change to specific tracks.
- Includes functionality to query its status when a train arrives*.
- The simulation will change which track the train is going to if the recieved switch status differs from the expected.
- *Please note: This is probably not something that exists in real life. Ateast not like the way it is used in our simulation. By having a physical switch and trains the trains can just go forward and go to the correct track. Due to us having a virtual switch and virtual trains we have to query the switch for its status when we want to arrive/depart so we know the status of the switch, but we don't actively poll the switch for it's status, only when we need to. 


## Communication Protocols (Operator-HMI-SCADA-PLCs)

The simulation employs various communication protocols to facilitate interaction between different components:

### Client and Flask Web App
- **Protocol:** HTTPS (port 5001)
- **Description:** Ensures secure communication between the client and the Flask web application.

### Flask and Simulation/SCADA Server
- **Protocol:** Inter-Process Communication (IPC)
- **Description:** Direct communication method between Flask and the simulation/SCADA server.

### SCADA Server and GUI receiver
- **Protocol:** TCP (port 12346)
- **Authentication:** HMAC with a secret key generated in Diffie-Hellman Group 14
- **Description:** Authenticated TCP communication for real-time information exchange between the SCADA server and the GUI application.

### GUI receiver and GUI
- **Protocol:** Inter-Process Communication (IPC)
- **Description:** Direct communication method between GUI socket and the tkinter application.

### SCADA Server and Trains
- **Protocol:** TCP (port 15000)
- **Authentication:** HMAC with a secret key generated in Diffie-Hellman Group 14
- **Description:** Secure TCP communication for interaction between the SCADA server and trains.

### Track Sensors
- **Protocol:** TCP (Two Ports)
  - **Port 1:** (port 13007)
    - **Used by:** Trains to send status.
    - **Authentication:** HMAC with a secret key generated in Diffie-Hellman Group 14.
  - **Port 2:** (port 13006)
    - **Used by:** SCADA server to generate a secret key in Diffie-Hellman Group 14 for Modbus communication.
 - **Protocol:** Modbus (port 13000 - 13005)
 - **Authentication:** HMAC with prior secret.
- **Description:** Modbus communication for sending data to the SCADA server.

### Switch
- **Protocol:** TCP (port 12344)
- **Description:** TCP communication for generating a secret in Diffie-Hellman Group 14.
-  **Protocol:** Modbus (port 12345)
 - **Authentication:** HMAC with prior secret.
- **Description:** Modbus communication for sending and receiving data from the SCADA server.

## Description of Normal Operation
   - Screenshots and comments illustrating the running simulation environment under normal conditions.

## Description of the Attack Scenario and Steps to Reproduce the Attack
The attack relies on the assumption that the attacker possesses knowledge of how the packages are constructed. It is essential to know the Modbus register size, given the utilization of a flag bit to indicate when a write operation has occurred. Furthermore, the understanding of the data's meaning, the application of HMAC-SHA256, and the existence of a 2-byte nonce within the packet must also be known.

The execution of the attack involves positioning oneself as a proxy between the SCADA server and the switch. In scenarios where ports are open, and the simulation operates over the internet, ARP poisoning is employed to redirect the packets to the attacker. Alternatively, if the simulation runs on the same host, it is assumed that there is already a means of access to the machine, allowing the creation of a Python script and the implementation of four iptables rules.

To carry out the attack, a TCP socket is established for the SCADA server to connect to, and a TCP client is created to connect to the switch. Subsequently, active participation in the Diffie-Hellman key exchange is required, leading to the generation of two distinct keys—one for the SCADA server and another for the switch. Following this, a Modbus client is created to connect to the simulation, and a Modbus server is established for the switch to connect to.

 
## Key Rotation and Secure Communication

To enhance security measures, the simulation implements key rotation alongside robust cryptographic techniques for secure communication. Key aspects include:

### Key Rotation for Authentication

**Implementation Details:**
- **Frequency:** The current key rotation is set at a conservative threshold of 100 sent packages.
- **Soft Key Rotation:**
  1. **Soft Key Rotation:** Facilitates a seamless transition by generating a new 32-byte base64 URL-safe encoded key.
  2. The new key is then encrypted with Fernet using the existing key and transmitted over TCP. Fernet is a symmetric cipher and thus we assume the key is still secure.
  3. This method ensures a gradual shift between keys, minimizing disruptions in data transmission and don't take as much time as creating a new key in diffie hellman group 14. 

- **More Complex Key Rotation with Diffie-Hellman Group 14:**
  1. After three rotations or 300 packages, a more intricate key rotation is initiated.
  2. A new key is generated using Diffie-Hellman in group 14, enhancing the security of the key exchange process.
  3. This process includes a challenge, serving as both keying material and authentication for the other client.
  4. A portion of the challenge is used as a seed for a random function, introducing an additional layer of complexity to deter potential man-in-the-middle attacks. The random function will then pick a few characters, 32 right now, and add them to the keying material we got from the diffie hellman exchange earlier. This means that an attacker needs to have more knowledge on how to create the key to be able to attack the communication.
- **Impact:** During key updates, data transmission is temporarily halted to prevent authentication failures. Different communication channels respond variably; some abort the ongoing transmission, while others allow the package to send until it is authenticated. Some communication channels keep sending all the data that is queued before changing the key while some give the key rotation priority.

### Secure Communication with Modbus and TCP

In addition to key rotation, Modbus communication and TCP connections are fortified with authentication measures and Modbus also utilizes encryption:

**TLS Encryption for Modbus:**
- Modbus communication is secured with Transport Layer Security (TLS). This ensures that data exchanged between devices over Modbus is encrypted, safeguarding it from unauthorized interception.

**Data Integrity Protection:**
- To ensure data integrity, the transmitted package includes a hash or signature, calculated with HMAC-SHA256. The receiver replicates this process to authenticate the package, confirming that it has not been tampered with during transmission.

**Authentication for Modbus and TCP:**
- Both Modbus communication and TCP connections are protected by a robust authentication mechanism. Each transmitted package includes a challenge that the sender must sign as an acknowledgment. This challenge-response mechanism adds an extra layer of security, as the receiver calculates an HMAC-SHA256 for the challenge nonce and returns it to the sender for verification.

#### Authentication Failure Handling

In the event of authentication failures during data transmission, the system prioritizes data integrity over continuity:

**Sender's Response:**
- If the receiver fails to calculate a correct signature for the nonce, the sender incrementally increases the sequence number and re-sends the package until a correct signature is verified.

**Receiver's Response:**
- On the receiver side, in case of an authentication failure, the system rejects the incoming data, logs the failure, and awaits the next package. The authentication failure can both be a signature that differs from the received or that the sequence number for the data is lower than the expected.

## Known Limitations

While the simulation strives to represent a realistic train station environment, there are certain limitations that users should be aware of:

1.  **Daytime Operation:**

-   The simulation is optimized for daytime operation, aligning with typical train arrivals and departures. Consequently, the program's functionality may be limited during evenings or extended periods without incoming trains. To ensure continuous operation, it is advisable to initiate the simulation during the day or evening when at least one train is expected to arrive. Additional trains can be added through the HMI interface. The simulation will continue to run until there are no more trains listed in the arrival.json file.

2.  **Maximum Trains:**

-   The simulation currently supports a maximum of seven trains running concurrently. This limitation is imposed by the available number of tracks (six) in the simulated train station and one extra train for the attack scenario. Attempting to add more trains than seven may lead to uninteded behavior and potential simulation issues. The most probable consequence is that the simulation won't be able to create the eight train and may work anyway. Having more than six trains means that there is a pending crash anyway and that the program will exit soon anyways.

3.  **Internet Connection:**

-   Additionally, please note that the simulation requires a consistent internet connection as it periodically queries Trafikverket for train data. This ensures that the simulation stays synchronized with real-world train arrivals and departures. A stable internet connection is essential for the accurate functioning of the program, especially during the scheduled intervals for obtaining updated train information from Trafikverket. If the internet connection is lost, it may lead to potential issues and disrupt the normal operation of the simulation.

It's recommended to consider these limitations when using the simulation and to plan scenarios accordingly.

**References**
    - Citations and references used in the documentation.

