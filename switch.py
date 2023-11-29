from pymodbus.client import AsyncModbusTlsClient
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.exceptions import ModbusException

import asyncio
import logging
import hmac
import hashlib
import base64
import random
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet

try:
    os.remove(os.path.join(os.getcwd(), "logs", "switch.log"))
except FileNotFoundError:
    pass

# Configure the logger
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s', level=logging.INFO)

# Create a FileHandler to write log messages to a file
file_handler = logging.FileHandler(os.path.join(os.getcwd(), "logs", 'switch.log'))
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
logging.getLogger().addHandler(file_handler)


# Modbus variables
datastore_size = 95  # needs to be the same size as the server, max 125 though
cert = os.path.join(os.getcwd(), "TLS", "switch_cert.pem")
key = os.path.join(os.getcwd(), "TLS", "switch_key.pem")
host = "localhost"
port = 12345

if __name__ == "__main__":
    client = None
    loop = asyncio.new_event_loop()
    secret_key = b""
    highest_data_id = 0

    async def run_client() -> None:
        """Run client"""
        global client

        client = AsyncModbusTlsClient(
            host,
            port=port,
            framer=ModbusTlsFramer,
            certfile=cert,
            keyfile=key,
            server_hostname="host",
        )

        logging.info("Started client")

        await client.connect()
        # if we can't connect try again after 5 seconds, if the server hasn't been started yet
        while not client.connected:
            logging.info("Couldn't connect to server, trying again in 5 seconds")
            await asyncio.sleep(5)
            await client.connect()
        logging.info("Connected to server")

        # Write confirmation to server that we are active
        await client.write_register(datastore_size - 2, 1, slave=1)
        logging.debug("Wrote confirmation that we have connected to server")

    async def read_holding_register() -> None:
        """Reads data from holding register"""
        global client
        global secret_key
        global highest_data_id
        switch_status = 1

        try:
            while True:
                # poll the flag bit to see if new information has been written
                hold_register = await client.read_holding_registers(datastore_size - 2, 1, slave=1)

                if hold_register.registers == [0]:
                    hold_register = await client.read_holding_registers(0x00, datastore_size - 3, slave=1)

                    if not hold_register.isError():
                        data_id = hold_register.registers[0]
                        amount_to_read = hold_register.registers[1]

                        received_data = "".join(chr(char) for char in hold_register.registers[2:2 + amount_to_read + 1
                                                                                                + 2 + 1 + 64])

                        nonce = received_data[1 + amount_to_read:1 + amount_to_read + 2]
                        signature = received_data[1 + amount_to_read + 3:]
                        data = received_data[:amount_to_read].split(" ")

                        if not data_id > highest_data_id:
                            continue

                        highest_data_id = data_id

                        # verify signature
                        calc_signature = " ".join(str(value) for value in data) + str(data_id)
                        logging.info(f"calculating signature for this {calc_signature}")
                        calc_signature = hmac.new(secret_key, calc_signature.encode(), hashlib.sha256).hexdigest()

                        if signature == calc_signature:
                            logging.info("Verified signature on data. Checking request")
                            if data[0] == "X":
                                logging.info("Received switch status update")
                                switch_status = int(data[1])

                                nonce = [ord(char) for char in nonce]
                                calc_signature = hmac.new(secret_key, str(nonce).encode(), hashlib.sha256).hexdigest()

                                calc_signature = [ord(char) for char in calc_signature]
                                logging.info(calc_signature)

                                await client.write_registers(0x00, calc_signature, slave=1)
                            elif data[0] == "Y":
                                logging.info("Received wish to return status")

                                data_to_send = [switch_status] + [ord(char) for char in nonce]

                                calc_signature = hmac.new(secret_key, str(data_to_send).encode(), hashlib.sha256).hexdigest()

                                calc_signature = [switch_status] + [ord(char) for char in calc_signature]

                                await client.write_registers(0x00, calc_signature, slave=1)

                            logging.info("Resetting flag")
                            await client.write_register(datastore_size - 2, 1, slave=1)
                        else:
                            logging.critical("Wrong signature found in modbus register")
                    else:
                        logging.error("Error reading holding register")

                logging.debug("sleeping for 0.5 seconds")
                await asyncio.sleep(0.5)
        except ModbusException as exc:
            logging.error(f"Received ModbusException({exc}) from library")
            client.close()

    async def handle_server() -> None:
        async def receive_key(reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> None:

            global secret_key
            global highest_data_id

            p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            g = 2

            params_numbers = dh.DHParameterNumbers(p, g)
            parameters = params_numbers.parameters(default_backend())

            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()

            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            server_public_key = await reader.read(2048)
            writer.write(public_key_bytes)
            await writer.drain()

            server_public_key = serialization.load_pem_public_key(server_public_key, backend=default_backend())

            shared_secret = private_key.exchange(server_public_key)

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_secret)

            secret_key = base64.urlsafe_b64encode(derived_key)

            while True:
                data = await reader.read(1024)

                if data.decode() == "D":
                    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
                    g = 2

                    params_numbers = dh.DHParameterNumbers(p, g)
                    parameters = params_numbers.parameters(default_backend())

                    private_key = parameters.generate_private_key()
                    public_key = private_key.public_key()

                    public_key_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )

                    server_public_key = await reader.read(2048)
                    writer.write(public_key_bytes)
                    await writer.drain()

                    test = await reader.read(1024)

                    secret = await choose_characters(test)

                    server_public_key = serialization.load_pem_public_key(server_public_key, backend=default_backend())

                    shared_secret = private_key.exchange(server_public_key)

                    shared_secret += secret.encode()

                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data',
                    ).derive(shared_secret)

                    secret_key = base64.urlsafe_b64encode(derived_key)

                    signature = hmac.new(secret_key, test, hashlib.sha256).hexdigest()
                    writer.write(signature.encode())
                    await writer.drain()
                else:
                    cipher = Fernet(secret_key)
                    secret_key = cipher.decrypt(data)

                logging.info("Updated secret key")
                highest_data_id = 0

        server = await asyncio.start_server(receive_key, "localhost", 12344)
        async with server:
            await server.serve_forever()


    async def choose_characters(secret: bytes) -> str:
        hash_object = hashlib.sha256(secret)
        hash_hex = hash_object.hexdigest()
        indexes = list(range(len(hash_hex) // 2))

        random.seed(int(hash_hex[:16], 16))  # Use the first 16 characters of the hash as the seed
        selected_indexes = random.choices(indexes, k=32)
        result = [hash_hex[i * 2: (i + 1) * 2] for i in selected_indexes]

        return "".join(result)

    loop.run_until_complete(run_client())
    loop.create_task(handle_server())
    loop.run_until_complete(read_holding_register())
