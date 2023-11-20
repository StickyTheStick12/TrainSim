## Dependencies
aiohttp == 3.8.6
bcrypt == 3.2.0
cryptography == 3.4.8
customtkinter == 5.2.0
flask == 2.3.3
flask-login == 0.6.2 
mysql-connector-python == 8.1.0
pymodbus == 3.5.4
Pillow == 10.1.0
werkzeug == 2.3.7


## Tutorial - Project Setup

This is a small walkthrough guide reagarding the project setup. 

### Step 1
Clone the repository to gather all files

### Step 2
Install all dependencies using pip and requirements.txt with the command:

```python 
pip install -r requirements.txt
```

### Step 3
After above tasks we need to make sure that the database exists. This guide does not cover database server setup. Meaning, it assumes that a database server actually exists. Make sure to configure password and username in:
```python
modules.py
```

### Step 4 
In step 4, we go through how the application is going to connect to the existing database. Run this command in terminal: 
```python 
python3 hmi.py
```
If it is first time setup, the application will create a schema in your database and then wanting you to input login credentials. In the terminal, it should promt something like this: 
```python
First time setup :
    
Username: "input of your choice"

Password: "input of your choice"

(usernamevalue,passwordvalue)

```

Now, you should be able to login into the hmi uing the credentials given above.

### Step 5
Done! Just start the hmi and gui and you're good to go: 
```python=
python3 hmi.py
python3 gui.py
```
