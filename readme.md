Dependencies:
bcrypt 4.0.1 \n
flask 2.3.3 \n
flask login 0.6.2
flask talisman 1.1.0
mysql
pymodbus
customtkinter

To run the simulation you have to run GUI.py before HMI.py. The GUI.py will log an warning every second until the HMI comes online but isn't anything to worry about.

Good to know:
* The modbus server currently only supports 65535 trains simultaneously. 
* A ' '. space, inside of the name isn't allowed
* The modbus that runs with the HMI will shutdown after 10 seconds if the client doesn't read any data.
* You can increase the available length of the train name in the modbus_data_size, max 125 which results in a name that is a little over 100 characters. Both the HMI and GUI needs to have the same length.  
