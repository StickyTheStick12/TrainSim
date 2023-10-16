import mysqlx
from mysqlx.errors import DatabaseError

# Connect to server on localhost, close session also defined here
session = mysqlx.get_session({
	'host': 'localhost',
	'port': 33060,
	'user': 'debian-sys-maint',
	'password': 'RocmET1Ek1eikelK',
	'schema': 'tssc'
})


def closeSession():
	session.close()
	return 0


def checkAuthentication():
	try:
		query = "SELECT username, password FROM user_credentials;"
		result = session.sql(query).execute()
		data = result.fetch_all()[0]
	except DatabaseError as error:
		print("ERROR : Database error noticed: ", error)
		data = None

	return data
