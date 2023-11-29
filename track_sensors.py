import asyncio
import logging
import hashlib
import os
import hmac
import base64
import random

from pymodbus import __version__ as pymodbus_version
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.server import StartAsyncTlsServer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet

# Modbus variables
datastore_size = 95  # cant be bigger than 125
modbus_port = 13000

cert = os.path.join(os.getcwd(), "TLS", "cert.pem")
key = os.path.join(os.getcwd(), "TLS", "key.pem")

lst_of_statuses = [0]*6

sequence_number = 0

secret_key = b""


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

    server = await asyncio.start_server(receive_key, "localhost", 13006)
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


async def modbus_server_thread(context: ModbusServerContext, port) -> None:
    """Creates the server that will listen at localhost"""

    identity = ModbusDeviceIdentification(
        info_name={
            "VendorName": "Pymodbus",
            "ProductCode": "PM",
            "VendorUrl": "https://github.com/pymodbus-dev/pymodbus/",
            "ProductName": "Pymodbus Server",
            "ModelName": "Pymodbus Server",
            "MajorMinorRevision": pymodbus_version,
        }
    )

    address = ("localhost", port)

    await StartAsyncTlsServer(
        context=context,
        host="host",
        identity=identity,
        address=address,
        framer=ModbusTlsFramer,
        certfile=cert,
        keyfile=key,
    )


async def answer_client(idx: int, context: ModbusServerContext) -> None:
    global sequence_number
    global lst_of_statuses

    hold_register = context[0x00].getValues(3, 0x00, datastore_size - 3)
    data_id = hold_register[0]
    amount_to_read = hold_register[0]

    received_data = "".join(chr(char) for char in hold_register[2:2 + amount_to_read + 1
                                                                  + 2 + 1 + 64])

    nonce = received_data[1 + amount_to_read:1 + amount_to_read + 2]
    signature = received_data[1 + amount_to_read + 3:]
    data = received_data[:amount_to_read].split(" ")

    if not data_id > sequence_number:
        return

    sequence_number = data_id

    # verify signature
    calc_signature = " ".join(str(value) for value in data) + str(data_id)
    logging.info(f"calculating signature for this {calc_signature}")
    calc_signature = hmac.new(secret_key, calc_signature.encode(), hashlib.sha256).hexdigest()

    if signature == calc_signature:
        logging.info("Verified signature on data. Checking request")

        if data[0] == "X":
            logging.info("Received Track status update")
            lst_of_statuses[idx] = data[1]

            nonce = [ord(char) for char in nonce]
            calc_signature = hmac.new(secret_key, str(nonce).encode(), hashlib.sha256).hexdigest()

            calc_signature = [ord(char) for char in calc_signature]
            logging.info(calc_signature)

            context[0x00].setValues(3, 0x00, calc_signature)
        elif data[0] == "Y":
            logging.info("Received wish to return track status")

            data_to_send = [lst_of_statuses[idx]] + [ord(char) for char in nonce]

            calc_signature = hmac.new(secret_key, str(data_to_send).encode(), hashlib.sha256).hexdigest()

            calc_signature = [lst_of_statuses] + [ord(char) for char in calc_signature]

            context[0x00].setValues(3, 0x00, calc_signature)

        logging.info("Resetting flag")
        context[0x00].setValues(3, datastore_size - 2, [0])


async def run_modbus(lst_of_contexts: list) -> None:
    while True:
        for i in range(6):
            if lst_of_contexts[i][0x00].getValues(3, datastore_size - 2, 1) == [0]:
                await answer_client(i, lst_of_contexts[i])

            await asyncio.sleep(0.3)


def setup_server() -> ModbusServerContext:
    """Generates our holding register for the server"""
    # global context
    datablock = ModbusSequentialDataBlock(0x00, [0] * datastore_size)
    context = ModbusSlaveContext(
        di=datablock, co=datablock, hr=datablock, ir=datablock)
    context = ModbusServerContext(slaves=context, single=True)

    logging.info("Created datastore")
    return context


def modbus_helper() -> None:
    """Sets up server and send data task"""
    loop = asyncio.new_event_loop()

    context1 = setup_server()
    context2 = setup_server()
    context3 = setup_server()
    context4 = setup_server()
    context5 = setup_server()
    context6 = setup_server()

    loop.create_task(modbus_server_thread(context1, 13000))
    loop.create_task(modbus_server_thread(context2, 13001))
    loop.create_task(modbus_server_thread(context3, 13002))
    loop.create_task(modbus_server_thread(context4, 13003))
    loop.create_task(modbus_server_thread(context5, 13004))
    loop.create_task(modbus_server_thread(context6, 13005))
    loop.create_task(handle_server())

    lst_of_contexts = [context1, context2, context3, context4, context5, context6]

    loop.run_until_complete(run_modbus(lst_of_contexts))

modbus_helper()
