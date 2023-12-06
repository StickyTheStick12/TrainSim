- [Introduction - Project Structure](#introduction-project-structure)
   * [Simulation Directory](#simulation-directory)
      + [1. TLS Subdirectory](#1-tls-subdirectory)
      + [2. Log Subdirectory](#2-log-subdirectory)
      + [3. Static Subdirectory](#3-static-subdirectory)
      + [4. Templates Subdirectory](#4-templates-subdirectory)
      + [5. Script Subdirectory](#5-script-subdirectory)
      + [6. JSONs Subdirectory](#6-jsons-subdirectory)
- [Installation and Execution Guidelines](#installation-and-execution-guidelines)
- [Architecture picture](#architecture-picture)
- [HMI Description](#hmi-description)
   * [GUI Application](#gui-application)
   * [Web Application](#web-application)
      + [Subpages](#subpages)
- [Back-end (SCADA-like) Server and PLCs Description](#back-end-scada-like-server-and-plcs-description)
   * [Backend Server](#backend-server)
      + [SCADA-like Simulation](#scada-like-simulation)
   * [Trains Script](#trains-script)
   * [Track Sensors](#track-sensors)
   * [Switch](#switch)
- [Communication Protocols (Operator-HMI-SCADA-PLCs)](#communication-protocols-operator-hmi-scada-plcs)
   * [Client and Flask Web App](#client-and-flask-web-app)
   * [Flask and Simulation/SCADA Server](#flask-and-simulationscada-server)
   * [SCADA Server and GUI receiver](#scada-server-and-gui-receiver)
   * [GUI receiver and GUI](#gui-receiver-and-gui)
   * [SCADA Server and Trains](#scada-server-and-trains)
   * [Track Sensors](#track-sensors-1)
   * [Switch](#switch-1)
- [Description of Normal Operation](#description-of-normal-operation)
   * [Adding trains & train arrivals:](#adding-trains-train-arrivals)
   * [Removing trains & train departures:](#removing-trains-train-departures)
   * [Continuous Operation (Quick Overview):](#continuous-operation-quick-overview)
      + [Additional Insights:](#additional-insights)
         - [Time scheduling](#time-scheduling)
         - [Updates to departure time and switch acqusition](#updates-to-departure-time-and-switch-acqusition)
         - [Sensor communications](#sensor-communications)
         - [Updating times from Trafikverket](#updating-times-from-trafikverket)
- [Description of the Attack Scenario and Steps to Reproduce the Attack](#description-of-the-attack-scenario-and-steps-to-reproduce-the-attack)
- [Key Rotation and Secure Communication](#key-rotation-and-secure-communication)
   * [Key Rotation for Authentication](#key-rotation-for-authentication)
   * [Secure Communication with Modbus and TCP](#secure-communication-with-modbus-and-tcp)
      + [Authentication Failure Handling](#authentication-failure-handling)
- [Known Limitations](#known-limitations)


## Introduction - Project Structure

The project is organized into two main directories: `attack` and `simulation`. The `simulation` directory is further divided into several subdirectories:

### Simulation Directory
#### 1. **TLS Subdirectory**
   - Contains TLS certificates and keys used for securing communication in Flask and Modbus.

#### 2. **Log Subdirectory**
   - Stores log files generated by the program, excluding Flask logs, which are placed inside `data.json` in the JSONs subdirectory.

<!-- TOC --><a name="3-static-subdirectory"></a>
#### 3. **Static Subdirectory**
   - Holds CSS files used for styling.

<!-- TOC --><a name="4-templates-subdirectory"></a>
#### 4. **Templates Subdirectory**
   - Contains HTML files utilized by the Flask application for rendering pages.

<!-- TOC --><a name="5-script-subdirectory"></a>
#### 5. **Script Subdirectory**
   - Houses all the necessary scripts required to run the simulation.
  
<!-- TOC --><a name="6-jsons-subdirectory"></a>
#### 6. **JSONs Subdirectory**
   - Contains all the JSON files used by the program. `data.json` is saved between runs, while `arrival.json` and `departure.json` will be deleted when the simulation first starts.

<!-- TOC --><a name="installation-and-execution-guidelines"></a>
## Installation and Execution Guidelines
For quick assistance, use:
```bash
make help
```

To run the program, begin by installing the necessary dependencies. You can either utilize the provided requirements list with the following command:
```bash
pip install -r requirements.txt
```
Alternatively, within the simulation directory, execute:
```bash
make install
```
This command will also install `gnome-terminal`.

Once the dependencies are installed, employ the provided Makefile for streamlined program execution. The Makefile offers four distinct start commands:

1. **Single Terminal (Recommended):**
    ```bash
    make start
    ```
- This command executes all scripts in a single terminal. It's the recommended way to run the program. Please note that all eventual error messages will be redirected to the same terminal but can be found in each script's individual log in the `logs` directory.

2. **Gnome Terminal:**
    ```bash
    make gnomestart
    ```
    or simply:
    ```bash
    make
    ```
   - Initiates the program with separate Gnome terminals for each script. Ensure you have Gnome Terminal installed to use this option. 

4. **Konsole Terminals:**
    ```bash
	make kstart
    ```
   - Spawns a new Konsole terminal for each script. Note: Konsole is required for this option.

5. **Xterminals:**
    ```bash
    make xstart
    ```
   - Spawns a new Xterminal for each script. Note: Xterminals are required for this option.

Select the option that best suits your environment and preferences.

To halt the program, execute either of the following commands:

```bash
make stop
```
or
```bash
make kill
```

Please note that the simulation doesn't support verbose mode by default. Instead, it is up to the user to change the logging level in each script to something lower. The default is set for error and is the recommended level.

<!-- TOC --><a name="architecture-picture"></a>
## Architecture picture
![alt text](https://github.com/StickyTheStick12/TrainSim/blob/master/High_level_architecture.png?raw=true)

<!-- TOC --><a name="hmi-description"></a>
## HMI Description

The project features two different HMIs:

<!-- TOC --><a name="gui-application"></a>
### GUI Application

The GUI application is designed to provide information similar to what a user would observe at a train station. Key features include:
- **Departure Times:** Displays departure times for trains, at which track they depart and to where.
- **Switch Status:** Indicates the status of the switch.
- **Train Presence:** Shows if a train is currently at the station.
- **Track Status:** Provides track status information (not visible in a typical train station).
  
The GUI is read-only and does not allow data modification. It serves as a tool for viewing changes for unauthorized users.

<!-- TOC --><a name="web-application"></a>
### Web Application

The web application, listening on localhost at port 5001, allows authorized users to modify data. Login credentials are as follows:
- **Username:** root
- **Password:** password

Credentials are stored in `usercredentials.json`. To change the password, generate a new password using the bcrypt command:
```python
hash = bcrypt.hashpw(your_password.encode(), bcrypt.gensalt())
```
Set the generated hash in the password field.

Alternatively, you can generate a new password using this website: [bcrypt-generator.com](https://bcrypt-generator.com/). Obtain the given hash and replace it in the password field.

<!-- TOC --><a name="subpages"></a>
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


<!-- TOC --><a name="back-end-scada-like-server-and-plcs-description"></a>
## Back-end (SCADA-like) Server and PLCs Description

The backend server plays a central role in the simulation, handling various tasks:

<!-- TOC --><a name="backend-server"></a>
### Backend Server
- Queries Trafikverket for train data:
  - Arrivals every 10 minutes.
  - Departures every 40 minutes.
- Saves data into `arrival.json` and `departure.json`, protected with an HMAC for data integrity.
- Manages data received from the web HMI, including logic for creating, deleting, or modifying train, track and switch information.
- Communicates with the GUI application to provide real-time information.

<!-- TOC --><a name="scada-like-simulation"></a>
#### SCADA-like Simulation
- Handles switch requests:
  - Immediate response for HMI requests.
  - 3-minute cooldown for train requests, ensuring priority for the train requesting the switch.
- Manages information from track sensors to determine track occupancy.

<!-- TOC --><a name="trains-script"></a>
### Trains Script
- Not a PLC, but part of the simulation part of the project
- Operates independently and receives necessary data from the simulation.
- Sends switch requests to SCADA server when departing or arriving
- Updates track sensors when arriving or departing*.
- *Please note: In real life the sensors can find the trains alone. How the detection works differs but it can be cameras or infrared sensors. Due to us having virtual trains we have to tell the sensors that a train is at this track and when it isn't anymore but isn't something that trains do in real life. 

<!-- TOC --><a name="track-sensors"></a>
### Track Sensors
- Not PLCs themselves, but their data is forwarded to PLCs.
- Each track has its own PLC and Modbus register.
- Notifies the SCADA server of changes in track occupancy when an update occurs.

<!-- TOC --><a name="switch"></a>
### Switch
- Receives updates from the SCADA server to change to specific tracks.
- Includes functionality to query its status when a train arrives*.
- The simulation will change which track the train is going to if the recieved switch status differs from the expected.
- *Please note: This is probably not something that exists in real life. Ateast not like the way it is used in our simulation. By having a physical switch and trains the trains can just go forward and go to the correct track. Due to us having a virtual switch and virtual trains we have to query the switch for its status when we want to arrive/depart so we know the status of the switch, but we don't actively poll the switch for it's status, only when we need to. 


<!-- TOC --><a name="communication-protocols-operator-hmi-scada-plcs"></a>
## Communication Protocols (Operator-HMI-SCADA-PLCs)

The simulation employs various communication protocols to facilitate interaction between different components:

<!-- TOC --><a name="client-and-flask-web-app"></a>
### Client and Flask Web App
- **Protocol:** HTTPS (port 5001)
- **Description:** Ensures secure communication between the client and the Flask web application.

<!-- TOC --><a name="flask-and-simulationscada-server"></a>
### Flask and Simulation/SCADA Server
- **Protocol:** Inter-Process Communication (IPC)
- **Description:** Direct communication method between Flask and the simulation/SCADA server.

<!-- TOC --><a name="scada-server-and-gui-receiver"></a>
### SCADA Server and GUI receiver
- **Protocol:** TCP (port 12346)
- **Authentication:** HMAC with a secret key generated in Diffie-Hellman Group 14
- **Description:** Authenticated TCP communication for real-time information exchange between the SCADA server and the GUI application.

<!-- TOC --><a name="gui-receiver-and-gui"></a>
### GUI receiver and GUI
- **Protocol:** Inter-Process Communication (IPC)
- **Description:** Direct communication method between GUI socket and the tkinter application.

<!-- TOC --><a name="scada-server-and-trains"></a>
### SCADA Server and Trains
- **Protocol:** TCP (port 15000)
- **Authentication:** HMAC with a secret key generated in Diffie-Hellman Group 14
- **Description:** Secure TCP communication for interaction between the SCADA server and trains.

<!-- TOC --><a name="track-sensors-1"></a>
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

<!-- TOC --><a name="switch-1"></a>
### Switch
- **Protocol:** TCP (port 12344)
- **Description:** TCP communication for generating a secret in Diffie-Hellman Group 14.
-  **Protocol:** Modbus (port 12345)
 - **Authentication:** HMAC with prior secret.
- **Description:** Modbus communication for sending and receiving data from the SCADA server.


<!-- TOC --><a name="description-of-normal-operation"></a>
## Description of Normal Operation

<!-- TOC --><a name="adding-trains-train-arrivals"></a>
### Adding trains & train arrivals:

1.  **Screenshot:**
  -   Capture a snapshot of the streamlined process for adding a train.
2.  **Process Overview:**
   -   Adding a train is a straightforward process accessed through the HMI's timetable page. Users input a desired departure time, restricted to a maximum of 24 hours into the future. The simulation dynamically calculates both the arrival and actual departure times.
   -  Track selection offers flexibility, with users choosing from any of the 6 available tracks. The train name, serving as an identifier on the timetable GUI, can be customized at the user's discretion.
    -   Behind the scenes, the simulation seamlessly manages the creation of the train, handling all necessary details effortlessly.
   3. **Track Availability Check:**
  -   Two minutes prior to a train's scheduled arrival, the simulation checks the availability of the chosen track. If the track is occupied, the simulation intelligently seeks an alternative available track. In the event of no available tracks, the train patiently waits until a track becomes free.
-   The simulation then communicates essential data to an available train, enabling it to operate autonomously.
4.  **Train Arrival Process:**
-   When the train receives data from the simulation, it begins the procedure by requesting access to the switch. To facilitate this, we've incorporated a basic balise that provides the train with the essential code for switch request. In reality, a balise typically conveys details about the proximity of a switch and speed limits.
-   The train patiently waits for the simulation's authorization before initiating its arrival animation.

<!-- TOC --><a name="removing-trains-train-departures"></a>
### Removing trains & train departures:

1.  **Screenshot:**
    -   Feature a screenshot capturing a train's departure phase.
2.  **Process Overview:**
-   Removing a train mirrors the simplicity of adding one. To remove a train, users need only choose the ID displayed on the website.
-   When a train is ready to depart, it follows a familiar process of requesting the switch and awaiting a green light from the simulation. The train then smoothly transitions into its departure animation.
-   Both train removal and departure share the same function. The simulation initially checks whether the train has arrived. If it hasn't, indicative of removal scenarios, the entry in the timetable is promptly deleted. In the case of an arrived train, the same deletion process occurs, accompanied by the initiation of the train's departure animation.

<!-- TOC --><a name="continuous-operation-quick-overview"></a>
### Continuous Operation (Quick Overview):

1.  **Screenshot:**
    
    -   Showcase a screenshot capturing the system's continuous operation.
    
2.  **Explanation:**
The simulation is meticulously crafted for uninterrupted, autonomous operation. It dynamically generates trains based on real-time data from Trafikverket, ensuring a continuous flow of train activities. The system operates seamlessly without the need for manual intervention through the HMI. From train creation to switch requests, and through the entire arrival and departure process, the system adeptly manages the railway operations.

<!-- TOC --><a name="additional-insights"></a>
#### Additional Insights:
<!-- TOC --><a name="time-scheduling"></a>
##### Time scheduling
The departure time that is inserted into the the HMI will be treated as a wish as stated prior. What the simulation does when it is creating a train is that it first will try to find the arrival time. The simulation will take the departure time and subtract 10 minutes as the base case. If there are other trains that need the switch at this time the simulation will start adding time to the arrival until it finds a time where the switch will be available for this train. This helps minimizing the time a train needs to wait for the switch and helps prevent some issues. Once the arrival time is set, the simulation seeks a departure time, ideally 5 minutes post-arrival. While it prefers a departure close to 10 minutes, any time greater than 5 minutes is accepted. This means that the departure for some inputted trains can be 5 minutes after arrival while some trains can wait 20-30 minutes before being allowed to leave.
<!-- TOC --><a name="updates-to-departure-time-and-switch-acqusition"></a>
##### Updates to departure time and switch acqusition
Several factors prompt departure time updates. If no track is available, the simulation intelligently guesses when a track will be available based on existing departures and updates the train's departure time accordingly. When a track becomes available, the departure time resets to the current time plus 10 minutes.  The simulation won't set a departure time that is earlier than the departure time it had when it was created, meaning a train can't depart earlier than the advertised time, only later. The switch is time based as stated earlier. When a train wants to depart the simulation will calculate the aproximate time the switch will become available and update the departure time accordingly.
<!-- TOC --><a name="sensor-communications"></a>
##### Sensor communications
Upon arrival or departure, trains communicate their track status to track sensors, enabling real-time registration. Track sensors actively relay status to the SCADA server, which polls for status updates every 10 seconds. The server utilizes a local cache for efficient status management instead of actively querying the sensors during arrivals.
<!-- TOC --><a name="updating-times-from-trafikverket"></a>
##### Updating times from Trafikverket
As the system integrates real-time data from Trafikverket, deleting data poses challenges. Instead of removing trains, the system marks them for deletion. During subsequent queries to Trafikverket, it cross-references the marked data with new data. If absent, the system removes them; otherwise, it retains them for future considerations. This approach maintains consistency in data handling and prevents unexpected inconsistencies.

<!-- TOC --><a name="description-of-the-attack-scenario-and-steps-to-reproduce-the-attack"></a>
## Description of the Attack Scenario and Steps to Reproduce the Attack
The attack relies on the assumption that the attacker possesses knowledge of how the packages are constructed. It is essential to know the Modbus register size, given the utilization of a flag bit to indicate when a write operation has occurred. Furthermore, the understanding of the data's meaning, the application of HMAC-SHA256, and the existence of a 2-byte nonce within the packet must also be known.

The execution of the attack involves positioning oneself as a proxy between the SCADA server and the switch. In scenarios where ports are open, and the simulation operates over the internet, ARP poisoning is employed to redirect the packets to the attacker. Alternatively, if the simulation runs on the same host, it is assumed that there is already a means of access to the machine, allowing the creation of a Python script and the implementation of four iptables rules.

To carry out the attack, a TCP socket is established for the SCADA server to connect to, and a TCP client is created to connect to the switch. Subsequently, active participation in the Diffie-Hellman key exchange is required, leading to the generation of two distinct keys—one for the SCADA server and another for the switch. Following this, a Modbus client is created to connect to the simulation, and a Modbus server is established for the switch to connect to.

For seamless transmission, it's essential to forward or at least acknowledge the packages the SCADA server sends to the switch, ensuring the SCADA server perceives communication with the PLC. Various options are available in this regard, including the choice to drop a package, modify its content, or generate entirely new packages to send to the switch as long as we acknowledge that we have received the SCADA package. Alternatively, the payload can be directly forwarded to the switch for a more transparent mitm attack and just change some packages which will make this harder to notice. 

It's essential to highlight that a response to the SCADA server with the switch status is mandatory, achieved either by utilizing a local cache or querying the switch. Merely sending any response without considering the actual switch status isn't recommended from a realistic standpoint. This precaution is necessary due to the earlier point that, in most cases, a train won't actively query the switch for its status. Otherwise we could change that data too because that is the actual data the simulation uses for the trains.

 
<!-- TOC --><a name="key-rotation-and-secure-communication"></a>
## Key Rotation and Secure Communication

To enhance security measures, the simulation implements key rotation alongside robust cryptographic techniques for secure communication. Key aspects include:

<!-- TOC --><a name="key-rotation-for-authentication"></a>
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

<!-- TOC --><a name="secure-communication-with-modbus-and-tcp"></a>
### Secure Communication with Modbus and TCP

In addition to key rotation, Modbus communication and TCP connections are fortified with authentication measures and Modbus also utilizes encryption:

**TLS Encryption for Modbus:**
- Modbus communication is secured with Transport Layer Security (TLS). This ensures that data exchanged between devices over Modbus is encrypted, safeguarding it from unauthorized interception.

**Data Integrity Protection:**
- To ensure data integrity, the transmitted package includes a hash or signature, calculated with HMAC-SHA256. The receiver replicates this process to authenticate the package, confirming that it has not been tampered with during transmission.

**Authentication for Modbus and TCP:**
- Both Modbus communication and TCP connections are protected by a robust authentication mechanism. Each transmitted package includes a challenge that the sender must sign as an acknowledgment. This challenge-response mechanism adds an extra layer of security, as the receiver calculates an HMAC-SHA256 for the challenge nonce and returns it to the sender for verification.

<!-- TOC --><a name="authentication-failure-handling"></a>
#### Authentication Failure Handling

In the event of authentication failures during data transmission, the system prioritizes data integrity over continuity:

**Sender's Response:**
- If the receiver fails to calculate a correct signature for the nonce, the sender incrementally increases the sequence number and re-sends the package until a correct signature is verified.

**Receiver's Response:**
- On the receiver side, in case of an authentication failure, the system rejects the incoming data, logs the failure, and awaits the next package. The authentication failure can both be a signature that differs from the received or that the sequence number for the data is lower than the expected.

<!-- TOC --><a name="known-limitations"></a>
## Known Limitations

While the simulation strives to represent a realistic train station environment, there are certain limitations that users should be aware of:

1.  **Daytime Operation:**

-   The simulation is optimized for daytime operation, aligning with typical train arrivals and departures. Consequently, the program's functionality may be limited during evenings or extended periods without incoming trains. To ensure continuous operation, it is advisable to initiate the simulation during the day or evening when at least one train is expected to arrive. Additional trains can be added through the HMI interface. The simulation will continue to run until there are no more trains listed in the arrival.json file.

2.  **Maximum Trains:**

-   The simulation currently supports a maximum of seven trains running concurrently. This limitation is imposed by the available number of tracks (six) in the simulated train station and one extra train for the attack scenario. Attempting to add more trains than seven may lead to uninteded behavior and potential simulation issues. The most probable consequence is that the simulation won't be able to create the eight train and may work anyway. Having more than six trains means that there is a pending crash anyway and that the program will exit soon anyways.

3.  **Internet Connection:**

-   Additionally, please note that the simulation requires a consistent internet connection as it periodically queries Trafikverket for train data. This ensures that the simulation stays synchronized with real-world train arrivals and departures. A stable internet connection is essential for the accurate functioning of the program, especially during the scheduled intervals for obtaining updated train information from Trafikverket. If the internet connection is lost, it may lead to potential issues and disrupt the normal operation of the simulation.
4. **Trafikverket**
Regrettably, our program is at the mercy of Trafikverket's data consistency. Issues may arise when the data received from Trafikverket deviates from the expected format. In testing, instances have occurred where arriving or departing trains had their tracks erroneously set to 'x' or '-' while they still are arriving or departing from the station. Unfortunately, due to Trafikverket's inconsistent data, such as canceling only the arrival or departure, our program may struggle to detect and handle these cases, leading to potential terminations when processing affected trains. Due to the fact that the arrival and departure is HMAC protected a user cant edit out that train if they find it. Sadly, the only viable solutions for this issue are to either wait until the specified arrival or departure time has passed or attempt to modify the incoming data fetched from Trafikverket over HTTP.

It's recommended to consider these limitations when using the simulation and to plan scenarios accordingly.

**References**
    - Citations and references used in the documentation.
