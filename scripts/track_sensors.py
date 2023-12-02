import asyncio
import logging
import hashlib
import os
import hmac
import base64
import random
import struct
import secrets

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

cert = os.path.join(os.path.dirname(os.getcwd()), "TLS", "track_cert.pem")
key = os.path.join(os.path.dirname(os.getcwd()), "TLS", "track_key.pem")

track_status = [0]*6
track_updates = [0]*6

sequence_number_modbus = 0
sequence_number_train = 0

secret_key_modbus = b""
secret_key_trains = b""
update_key_event = asyncio.Event()
update_key_mutex = asyncio.Lock()


async def handle_train_server() -> None:
    async def receive_data(reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:

        global secret_key_trains
        global sequence_number_train
        MESSAGE_TYPE_PACKED = 1

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

        secret_key_trains = base64.urlsafe_b64encode(derived_key)

        while True:
            data = await reader.read(1024)
            logging.info("Received data")

            received_header = data[:8]
            message_type, data_length = struct.unpack('!II', received_header)

            if message_type == MESSAGE_TYPE_PACKED:
                logging.info("Received data")
                # unpacked_length = struct.unpack('!I', data[4:8])[0]
                data = list(struct.unpack('!{}I'.format(data_length // 4), data[8:]))
                data = data[1:]

                data_id = data[0]
                amount_to_read = data[1]

                received_data = "".join(
                    chr(char) for char in data[2:2 + amount_to_read + 1
                                                 + 2 + 1 + 64])

                logging.info(received_data)
                nonce = received_data[1 + amount_to_read:1 + amount_to_read + 2]
                signature = received_data[1 + amount_to_read + 3:]

                data = received_data[:amount_to_read].split(" ")

                if not data_id > sequence_number_train:
                    continue

                sequence_number_train = data_id

                # verify signature
                calc_signature = " ".join(str(value) for value in data) + str(data_id)
                logging.debug(f"calculating signature for this {calc_signature}")
                calc_signature = hmac.new(secret_key_trains, calc_signature.encode(), hashlib.sha256).hexdigest()

                if signature == calc_signature:
                    # calculate new signature for nonce
                    nonce = [ord(char) for char in nonce]

                    calc_signature = hmac.new(secret_key_trains, str(nonce).encode(), hashlib.sha256).hexdigest()

                    calc_signature = [ord(char) for char in calc_signature]
                    logging.info(calc_signature)

                    packed_data = struct.pack('!64I', *calc_signature)

                    writer.write(packed_data)
                    await writer.drain()

                    logging.info("Verified signature on data. Updating status")

                    track_status[int(data[1]) - 1] = int(data[2])
                    track_updates[int(data[1]) - 1] = 1
                else:
                    logging.critical("Found wrong signature in data")
            else:
                received_single_char = data[8:8 + data_length]

                if received_single_char.decode() == "D":
                    logging.info("Received diffie hellman update wish")
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

                    server_public_key = serialization.load_pem_public_key(server_public_key,
                                                                          backend=default_backend())

                    shared_secret = private_key.exchange(server_public_key)

                    shared_secret += secret.encode()

                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data',
                    ).derive(shared_secret)

                    secret_key_trains = base64.urlsafe_b64encode(derived_key)

                    signature = hmac.new(secret_key_trains, test, hashlib.sha256).hexdigest()

                    writer.write(signature.encode())
                    await writer.drain()
                else:
                    logging.info("Received wish for ordinary key rotation")
                    data = await reader.read(1024)
                    cipher = Fernet(secret_key_trains)
                    secret_key_trains = cipher.decrypt(data)

                logging.info("Updated secret key")
                sequence_number_train = 0

    server = await asyncio.start_server(receive_data, "localhost", 13007)
    async with server:
        await server.serve_forever()


async def handle_server() -> None:
    async def receive_key(reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:

        global secret_key_modbus
        global sequence_number_modbus

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

        secret_key_modbus = base64.urlsafe_b64encode(derived_key)

        while True:
            await update_key_event.wait()
            update_key_event.clear()

            async with update_key_mutex:
                writer.write("-".encode())
                await writer.drain()

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

                    secret_key_modbus = base64.urlsafe_b64encode(derived_key)

                    signature = hmac.new(secret_key_modbus, test, hashlib.sha256).hexdigest()
                    writer.write(signature.encode())
                    await writer.drain()
                else:
                    cipher = Fernet(secret_key_modbus)
                    secret_key_modbus = cipher.decrypt(data)

                logging.info("Updated secret key")
                sequence_number_modbus = 0

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


def setup_server() -> ModbusServerContext:
    """Generates our holding register for the server"""
    # global context
    datablock = ModbusSequentialDataBlock(0x00, [0] * datastore_size)
    context = ModbusSlaveContext(
        di=datablock, co=datablock, hr=datablock, ir=datablock)
    context = ModbusServerContext(slaves=context, single=True)

    logging.info("Created datastore")
    return context


async def update_track_simulation(idx: int, context: ModbusServerContext) -> None:
    global sequence_number_modbus
    global track_status

    data = str(idx) + str(track_status[idx])

    client_verified = False

    async with update_key_mutex:
        while not client_verified:
            sequence_number_modbus += 1
            temp_signature = data + str(sequence_number_modbus)
            temp_signature = hmac.new(secret_key_modbus, temp_signature.encode(), hashlib.sha256).hexdigest()
            while True:
                # Generate 2 bytes
                nonce = [char for char in secrets.token_bytes(2)]

                # Check if any character is a space
                if b' ' not in nonce:
                    break

            if sequence_number_modbus == 100:
                logging.info("Updating secret key")
                update_key_event.set()

            data_to_send = (
                    [sequence_number_modbus] + [len(data)] + [ord(char) for char in data] + [32] + nonce +
                    [32] + [ord(char) for char in temp_signature])

            logging.debug("Sending data")
            context[0x00].setValues(3, 0x00, data_to_send)

            logging.debug("Resetting flag")
            context[0x00].setValues(3, datastore_size - 2, [0])

            expected_signature = hmac.new(secret_key_modbus, str(nonce).encode(), hashlib.sha256).hexdigest()

            logging.debug(f"nonce {str(nonce)}")
            expected_signature = [ord(char) for char in expected_signature]
            logging.debug(f"Expecting: {expected_signature}")

            while context[0x00].getValues(3, datastore_size - 2, 1) == [0]:
                logging.debug("Waiting for client to copy datastore; sleeping 0.5 seconds")
                await asyncio.sleep(0.5)  # give the server control so it can answer the client

            if context[0x00].getValues(3, 0, 64) == expected_signature:
                logging.debug("Client is verified")
                client_verified = True
            else:
                logging.critical("Found wrong signature in holding register")


async def run_modbus(lst_of_contexts: list) -> None:
    while True:
        for i in range(6):
            if track_updates[i] != 0:
                await update_track_simulation(i, lst_of_contexts[i])

            await asyncio.sleep(5)


if __name__ == "__main__":
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
    loop.create_task(handle_train_server())

    lst_of_contexts = [context1, context2, context3, context4, context5, context6]

    loop.run_until_complete(run_modbus(lst_of_contexts))
