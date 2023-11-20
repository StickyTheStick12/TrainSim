import mysqlx
import bcrypt

from mysqlx.errors import DatabaseError
# Connect to server on localhost, close session also defined here
session = mysqlx.get_session({
    'host': 'localhost',
    'port': 33060,
    'user': 'root',
    'password': 'password',
})

DB_NAME = 'test5'


def createDatabase(session, DB_NAME):
    '''Creates database with given DB_NAME in session workbench'''

    try:
        print("Creating database {}".format(DB_NAME))
        session.sql("CREATE DATABASE {} DEFAULT CHARACTER SET 'utf8'".format(DB_NAME)).execute()
    except DatabaseError as de:
        print("Faild to create database, error: {}".format(de))
        exit(1)
        
def createTableUserCredentials(session):
    '''Essential table for user login. Create database table where ID username, password exists'''
    userCredentials = "CREATE TABLE `user_credentials` (" \
                 "  `ID` int NOT NULL AUTO_INCREMENT," \
                 "  `username` varchar(255) NOT NULL," \
                 "  `password` varchar(255) NOT NULL," \
                 "  PRIMARY KEY (`ID`)" \
                 ") ENGINE=InnoDB"

    try:
        print("Creating table user credentials: ")
        session.sql(userCredentials).execute()
    except DatabaseError as de:
        if de.errno == 1050:
            print("already exists.")
        else:
            print(de.msg)
    else:
        print("OK")
     
def createInputData(session):
    '''Gathers login credentials from user'''

    print("First time setup | Create admin login to PLC : \n")
    username = input("Username: ")
    password = input("Password: ")
     
    salt = bcrypt.gensalt()
    hashedPassword = bcrypt.hashpw(password.encode(), salt)
     
    query = "INSERT INTO user_credentials(username,password) VALUES " + \
    f"('{username}', '{hashedPassword.decode()}');"
     
    session.sql(query).execute()
    print(username,password)
     


def closeSession():
	session.close()
	return 0


def checkAuthentication():
	try:
		query = "SELECT username, password FROM user_credentials;"
		result = session.sql(query).execute()
		data = result.fetch_all()[0]
	except DatabaseError as error:
		print("ERROR : Database error noticed: ",error)

	return data

#Database creation code
try:
    session.sql("USE {}".format(DB_NAME)).execute()
except DatabaseError as de:
    if de.errno == 1049:
        print("Error: Database '{}' does not exist.".format(DB_NAME))

        createDatabase(session, DB_NAME)
        session.sql("USE {}".format(DB_NAME)).execute()
        createTableUserCredentials(session)
        createInputData(session)
    else:
        print("Error executing SQL command: {}".format(de))
        raise
