import mysqlx
from mysqlx.errors import DatabaseError
# Connect to server on localhost, close session also defined here
tls_options = {
    'ssl-mode': 'REQUIRED',
    'key': "/home/vboxuser/tls/key.pem",    # Your client's private key
    'cert': "/home/vboxuser/tls/cert.pem",  # Your client's certificate
    'ca': "/home/vboxuser/tls/cert.pem",    # Your server's certificate (which is also the CA certificate in this case)
}

mysql_options = {
    'host': 'localhost',
    'port': 33060,
    'user': 'debian-sys-maint',
    'password': 'RocmET1Ek1eikelK',
    'schema': 'tssc',
}

session = get_session(mysql_options, **tls_options)


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
