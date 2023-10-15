**Dependencies:**                                          
bcrypt 4.0.1,                                          
flask 2.3.3,                             
flask login 0.6.2                                          
flask talisman 1.1.0                                          
mysql                                          
pymodbus                                          
customtkinter                                          

**How to run**
It doesn't matter if you start hmi.py or gui.py first. GUI.py will log an error every second until the HMI.py starts but the error can be neglected. 

**Good to know:**
* The modbus server only supports 65535 trains simultaneously. 
* A ' '. space, inside of the name isn't allowed
* The modbus server, the hmi, will restart after 10 seconds if the server doesn't read data that is sent. It will then send all the data again. 
* You can increase the available length of the train name in the modbus_data_size, max 125 which results in a name that is a little over 100 characters. Both the HMI and GUI needs to have the same length.  
