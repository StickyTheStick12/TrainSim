import asyncio
from datetime import datetime, timedelta
import logging
import hmac
import hashlib
import base64
import random
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet

secret_key = b''
sequence_number = 0
MESSAGE_TYPE_PACKED = 1
mutex = asyncio.Lock()

# TODO. connect to track sensors and send data
# TODO fix so we can send data to the simulation
# TODO fix so we can receive data from the simulation

try:
    os.remove(os.path.join(os.getcwd(), "logs", "Train.log"))
except FileNotFoundError:
    pass

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s', level=logging.INFO)

# Create a FileHandler to write log messages to a file
file_handler = logging.FileHandler(os.path.join(os.getcwd(), "logs", 'Train.log'))
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
logging.getLogger().addHandler(file_handler)

trains = []

trains.append([
    asyncio.Event(),  # is active, 0
    "2023-11-28 07:47",  # arrival time, 1
    "2023-11-28 07:59",  # departure time, 2
    asyncio.Event(),  # green light / clear to continue, 3
    asyncio.Event(),  # wakeup, 4
    4,  # track number, 5
    12  # train id when communicating with the hmi. Use the already defined id, 6
])

send_queue = asyncio.Queue()


async def handle_train(idx: int) -> None:
    """Handles train logic"""
    global send_queue
    while True:
        # wait until this train becomes active
        await trains[idx][0].wait()

        this_train = trains[idx]

        current_arrival = datetime.strptime(this_train[1])
        current_departure = datetime.strptime(this_train[2], "%Y-%m-%d %H:%M")

        request_for_switch = [
            0,  # arrival code
            this_train[5],
            this_train[6]
        ]

        await send_queue.put(request_for_switch)
        await this_train[3].wait()
        logging.info("Train is clear to arrive")
        this_train[3].clear()

        if this_train[4].is_set():
            this_train[4].clear()
            logging.info("Wakeup event has been set. Return switch")
            await send_queue.put(["Give up switch message"])
            trains[idx][0].clear()
            continue

        updated_arrival = datetime.strptime(this_train[1], "%Y-%m-%d %H:%M")

        if updated_arrival > current_arrival:
            wait = current_arrival - datetime.now()
            await asyncio.sleep(max(0, wait.total_seconds()))

            logging.info("Train is late, arriving as soon as possible")
        else:
            difference = (updated_arrival - datetime.now()).total_seconds()
            logging.info("Train is planned to arrive at the estimated tine")
            await asyncio.sleep(max(0, difference - 20))

        if this_train[4].is_set():
            this_train[4].clear()
            logging.info("Wakeup event has been set. Return switch")
            await send_queue.put(["Give up switch message"])
            trains[idx][0].clear()
            continue

        # should hopefully let us change the switch
        logging.info("Sleeping 20 seconds so we can change the switch")
        await asyncio.sleep(20)

        # Send an update that the train has now arrived
        msg = [
            this_train[5],
            this_train[6]
        ]

        await send_queue.put(msg)

        # message the correct sensor that we are now here
        await send_queue.put(["Has changed sensor release mutex"])
        # ------------------departure------------------#

        departure_time = datetime.strptime(this_train[2], "%Y-%m-%d %H:%M")

        difference = departure_time - datetime.now()

        try:
            await asyncio.wait_for(this_train[4].wait(), timeout=max(0, difference.total_seconds() - 2 * 60))
            this_train[4].clear()
            logging.info("Received a wakeup call")
            continue
        except asyncio.TimeoutError:
            logging.info("Timeout error")
            pass

        request_for_switch = [
            1,  # departure code
            this_train[5],
            this_train[6]
        ]

        await send_queue.put(request_for_switch)
        await this_train[3].wait()
        logging.info("Train is clear to depart")
        this_train[3].clear()

        if this_train[4].is_set():
            this_train[4].clear()
            logging.info("Wakeup event has been set. Return switch")
            await send_queue.put(["Give up switch message"])
            trains[idx][0].clear()
            return

        updated_departure = datetime.strptime(this_train[2], "%Y-%m-%d %H:%M")

        if updated_departure == current_departure:
            difference = (updated_departure - datetime.now()).total_seconds()
            logging.info("Train is planned to depart at the estimated time")
            await asyncio.sleep(max(0, difference - 20))

            if this_train[4].is_set():
                this_train[4].clear()
                logging.info("Wakeup event has been set. Return switch")
                await send_queue.put(["Give up switch message"])
                trains[idx][0].clear()
                return

        try:
            await asyncio.wait_for(this_train[4], timeout=20)
            this_train[4].clear()
            await send_queue.put(["I want to return the switch"])
            logging.info("Received a wakeup call")
            return
        except asyncio.TimeoutError:
            logging.info("Timeout error")
            pass

        # depart message
        msg = [
            this_train[5],
            this_train[6]
        ]

        await send_queue.put(msg)
        await asyncio.sleep(20)

        # update sensors

        # clear when we depart or it is deleted
        trains[idx][0].clear()


async def handle_server() -> None:
    async def receive_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        global secret_key
        global sequence_number

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
            logging.info("Received data")
            data = await reader.read(1024)

            received_header = data[:8]
            message_type, data_length = struct.unpack('!II', received_header)

            if message_type == MESSAGE_TYPE_PACKED:
                logging.info("Received data to GUI")
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

                if not data_id > sequence_number:
                    continue

                sequence_number = data_id

                # verify signature
                calc_signature = " ".join(str(value) for value in data) + str(data_id)
                logging.debug(f"calculating signature for this {calc_signature}")
                calc_signature = hmac.new(secret_key, calc_signature.encode(), hashlib.sha256).hexdigest()

                if signature == calc_signature:
                    # calculate new signature for nonce
                    nonce = [ord(char) for char in nonce]

                    calc_signature = hmac.new(secret_key, str(nonce).encode(), hashlib.sha256).hexdigest()

                    calc_signature = [ord(char) for char in calc_signature]
                    logging.info(calc_signature)

                    packed_data = struct.pack('!64I', *calc_signature)

                    writer.write(packed_data)
                    await writer.drain()

                    logging.info("Verified signature on data, notified gui.")

                    # put data in queue for the GUI thread
                    modbus_data_queue.put(data)
                else:
                    logging.critical("Found wrong signature in data")
            else:
                received_single_char = data[8:8 + data_length]

                with mutex:
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

                        secret_key = base64.urlsafe_b64encode(derived_key)

                        signature = hmac.new(secret_key, test, hashlib.sha256).hexdigest()

                        writer.write(signature.encode())
                        await writer.drain()
                    else:
                        logging.info("Received wish for ordinary key rotation")
                        data = await reader.read(1024)
                        cipher = Fernet(secret_key)
                        secret_key = cipher.decrypt(data)

                    logging.info("Updated secret key")
                    sequence_number = 0

    server = await asyncio.start_server(receive_data, "localhost", 12346)
    async with server:
        await server.serve_forever()


async def handle_data(a_queue: asyncio.Queue) -> None:
    # N: add a new train
    # packet: arrivaltime, departuretime, track, id when talking with hmi
    # S: greenlight a train
    # packet: id
    # R: remove train
    # packet: id

    loop = asyncio.new_event_loop()

    while True:
        data = await a_queue.get()

        if data[0] == "N":
            idx = len(train)
            train.append([data[1], data[2], asyncio.Event(), asyncio.Event(), data[3], data[4]])
            asyn_queue = asyncio.Queue()
            loop.create_task(main_loop(asyn_queue, a_queue, idx))
        elif data[0] == "S":
            train[int(data[1])][2].set()
        elif data[0] == "R":
            train[int(data[1])][3].set()


async def main_loop(write_queue: asyncio.Queue, idx: int) -> None:
    advertised_time = datetime.strptime(train[idx], "%Y-%m-%d %H:%M")

    request = train[5]

    await write_queue.put(" ".join(request).encode())

    await train[2].wait()

    logging.info("Train is clear to arrive")
    train[2].clear()

    if train[3].is_set():
        train[3].clear()
        logging.info("Wake arrival event has been set. Return switch")
        await a_queue.put(["Give up switch message"])
        # return to socket and wait until next time we use this socket for a train
        return

    updated_time = datetime.strptime(train[0], "%Y-%m-%d %H:%M")

    if updated_time == advertised_time:
        difference = (updated_time - datetime.now()).total_seconds()
        logging.info("Train is planned to arrive at the estimated time")
        await asyncio.sleep(max(0, difference - 20))

        if train[3].is_set():
            logging.info("Function has been woken. Returning switch")
            train[3].clear()
            await a_queue.put(["Give up switch message"])
            return

    # should hopefully let us change the switch
    logging.info("Sleeping 20 seconds so we can change the switch")
    await asyncio.sleep(20)

    # Send an update that the train has now arrived
    a_queue(["Train has arrived message"])

    # message the correct sensor that we are now here

    a_queue(["Has changed sensor release mutex"])

    # departure
    departure_time = datetime.strptime(train[1], "%Y-%m-%d %H:%M")

    difference = departure_time - datetime.now()

    try:
        await asyncio.wait_for(train[3].wait(), timeout=max(0, difference.total_seconds() - 2 * 60))
        train[3].clear()
        logging.info("Received a wakeup call")
        return
    except asyncio.TimeoutError:
        logging.info("Timeout error")
        pass

    await a_queue.put(["I want the switch"])

    await train[2].wait()
    train[2].clear()

    if train[3].is_set():
        logging.info("Function has been woken. Returning swtich")
        train[3].clear()
        a_queue.put(["I want to return the switch"])
        return

    update_depart_time = datetime.strptime(train[1], "%Y-%m-%d %H:%M")

    if update_depart_time > departure_time:
        logging.info("Train is late, leaving in 20 seconds")

        try:
            await asyncio.wait_for(train[3], timeout=20)
            train[3].clear()
            await a_queue.put(["I want to return the switch"])
            logging.info("Received a wakeup call")
            return
        except asyncio.TimeoutError:
            logging.info("Timeout error")
            pass

        await a_queue.put(["i want to depart"])
        await asyncio.sleep(20)
    else:
        difference = update_depart_time - datetime.now()
        logging.info(f"sleeping {difference} seconds")

        try:
            await asyncio.wait_for(train[3].wait(), timeout=max(difference.total_seconds(), 0))
            train[3].clear()
            await a_queue.put(["I want to return the switch"])
            logging.info("Received a wakeup call")
            return
        except asyncio.TimeoutError:
            logging.info("Timeout error")
            pass

        await a_queue.put(["I wish to depart"])

        await asyncio.sleep(20)


async def write_data(writer: asyncio.StreamWriter, a_queue: asyncio.Queue):
    # task in handle_com_one
    while True:
        data = await a_queue.get()

        async with mutex:
            writer.write(data)
            await writer.drain()
