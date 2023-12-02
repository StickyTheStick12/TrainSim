import asyncio
from datetime import datetime, timedelta
import logging
import hmac
import hashlib
import base64
import random
import os
import struct
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet

secret_key_sim = b''
sequence_number_sim = 0
data_queue = asyncio.Queue()

MESSAGE_TYPE_PACKED = 1
MESSAGE_TYPE_SINGLE_CHAR = 2

track_queue = asyncio.Queue()
track_key = b""
sequence_number_track = 0
update_key_event = asyncio.Event()
mutex = asyncio.Lock()

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


async def dh_exchange(reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> bytes:
    """Handles basic diffie hellman exchange in group 14"""
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

    writer.write(public_key_bytes)
    await writer.drain()

    public_key_bytes = await reader.read(2048)

    received_public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

    shared_secret = private_key.exchange(received_public_key)

    # Derive a key from the shared secret using a key derivation function (KDF)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)

    return derived_key


async def rotation(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    global track_key
    global sequence_number_track

    rotation_track = 0

    while True:
        await update_key_event.wait()
        update_key_event.clear()

        new_key = Fernet.generate_key()
        cipher = Fernet(track_key)
        encrypted_message = cipher.encrypt(new_key)

        async with mutex:
            if rotation_track == 3:
                header_char = struct.pack('!II', MESSAGE_TYPE_SINGLE_CHAR, 1)
                combined_data_char = header_char + b'D'

                writer.write(combined_data_char)
                await writer.drain()

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

                writer.write(public_key_bytes)
                await writer.drain()

                public_key_bytes = await reader.read(2048)

                writer.write(new_key)
                await writer.drain()

                # can just reuse the generated key as our challenge
                secret = choose_characters(new_key)
                received_public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

                shared_secret = private_key.exchange(received_public_key)

                shared_secret += secret.encode()

                # Derive a key from the shared secret using a key derivation function (KDF)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                ).derive(shared_secret)

                # Use the key material to generate a Fernet key
                track_key = base64.urlsafe_b64encode(derived_key)
                expected_signature = hmac.new(track_key, new_key, hashlib.sha256)

                recv_signature = await reader.read(1024)

                if not expected_signature.hexdigest() == recv_signature.hex():
                    logging.critical("MITM detected")
                    raise RuntimeError

                rotation_track = 0
            else:
                track_key = new_key

                header_char = struct.pack('!II', MESSAGE_TYPE_SINGLE_CHAR, 1)
                combined_data_char = header_char + b'K'

                writer.write(combined_data_char)
                await writer.drain()

                writer.write(encrypted_message)
                await writer.drain()
                logging.info("sent new secret key")
                rotation_track += 1

            sequence_number_track = 0


def choose_characters(secret: bytes) -> str:
    """Chose a few random characters"""
    hash_object = hashlib.sha256(secret)
    hash_hex = hash_object.hexdigest()

    indexes = list(range(len(hash_hex) // 2))

    random.seed(int(hash_hex[:16], 16))  # Use the first 16 characters of the hash as the seed
    selected_indexes = random.choices(indexes, k=32)
    result = [hash_hex[i * 2: (i + 1) * 2] for i in selected_indexes]

    return "".join(result)


async def handle_track_data() -> None:
    global track_queue
    global track_key
    global sequence_number_track

    reader_track, writer_track = asyncio.open_connection("localhost", 13007)

    derived_key = await dh_exchange(reader_track, writer_track)
    track_key = base64.urlsafe_b64encode(derived_key)

    while True:
        data = await track_queue.get()

        data = " ".join(str(value) for value in data)

        client_verified = False

        async with mutex:
            while not client_verified:
                sequence_number_track += 1
                temp_signature = data + str(sequence_number_track)
                logging.info(temp_signature)
                temp_signature = hmac.new(track_key, temp_signature.encode(), hashlib.sha256).hexdigest()
                while True:
                    # Generate 2 bytes
                    nonce = [char for char in secrets.token_bytes(2)]

                    # Check if any character is a space
                    if b' ' not in nonce:
                        break

                if sequence_number_track == 100:
                    logging.info("Updating secret key")
                    update_key_event.set()

                data_to_send = ([sequence_number_track] + [len(data)] + [ord(char) for char in data] + [32] + nonce +
                                [32] + [ord(char) for char in temp_signature])

                logging.info(data_to_send)

                packed_data = struct.pack('!I{}I'.format(len(data_to_send)), len(data_to_send), *data_to_send)
                header_packed_data = struct.pack('!II', MESSAGE_TYPE_PACKED, len(packed_data))
                combined_data_packed_data = header_packed_data + packed_data
                writer_track.write(combined_data_packed_data)
                await writer_track.drain()

                expected_signature = [ord(char) for char in
                                      hmac.new(track_key, str(nonce).encode(), hashlib.sha256).hexdigest()]

                logging.debug(f"nonce {str(nonce)}")
                logging.debug(f"Expecting: {expected_signature}")

                packed_data = await reader_track.read(1024)

                received_signature = list(struct.unpack('!64I', packed_data))

                logging.info(received_signature)

                if received_signature == expected_signature:
                    logging.debug("Client is verified")
                    client_verified = True
                else:
                    logging.critical("Found wrong signature")


async def handle_train(idx: int) -> None:
    """Handles train logic"""
    global send_queue
    global track_queue

    while True:
        # wait until this train becomes active
        await trains[idx][0].wait()

        this_train = trains[idx]

        current_arrival = datetime.strptime(this_train[1], "%Y-%m-%d %H:%M")
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

        wait = current_arrival - datetime.now()

        await asyncio.sleep(max(0, wait.total_seconds() - 20))

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

        await this_train[3].wait()
        logging.info("Got track from simulation")
        this_train[3].clear()

        msg = [
            this_train[5],
            "1"
        ]

        # message the correct sensor that we are now here
        await track_queue.put(msg)
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
            await asyncio.wait_for(this_train[4].wait(), timeout=20)
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

        msg = [
            this_train[5],
            "0"
        ]

        await track_queue.put(msg)

        # clear when we depart or it is deleted
        trains[idx][0].clear()


async def handle_data() -> None:
    global data_queue
    # N: add a new train
    # packet: arrivaltime, departuretime, track, id when talking with hmi
    # G: give switch to a train
    # packet: id
    # R: remove train
    # packet: id
    # T: change track of a train
    # id, track

    while True:
        data = await data_queue.get()

        match data[0]:
            case "N":
                for i in range(7):
                    if not trains[i][0].is_set():
                        trains[i][1] = data[1]
                        trains[i][2] = data[2]
                        trains[i][3].clear()
                        trains[i][4].clear()
                        trains[i][5] = data[3]
                        trains[i][6] = data[4]
                        trains[i][0].set()
            case "G":
                for i in range(7):
                    if trains[i][6] == data[1]:
                        trains[i][3].set()
            case "R":
                for i in range(7):
                    if trains[i][6] == data[1]:
                        trains[i][4].set()
            case "T":
                for i in range(7):
                    if trains[i][6] == data[1]:
                        trains[i][5] = data[2]


async def read_data_sim(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, recv_queue: asyncio.Queue, recv_event: asyncio.Event) -> None:
    global sequence_number_sim
    global secret_key_sim
    global data_queue

    while True:
        data = await reader.read(1024)

        if recv_event.is_set():
            await recv_queue.put(data)
        else:
            data_id = data[0]
            amount_to_read = data[1]

            received_data = "".join(
                chr(char) for char in data[2:2 + amount_to_read + 1
                                             + 2 + 1 + 64])

            nonce = received_data[1 + amount_to_read:1 + amount_to_read + 2]
            signature = received_data[1 + amount_to_read + 3:]

            data = received_data[:amount_to_read].split(" ")

            if not data_id > sequence_number_sim:
                continue

            sequence_number_sim = data_id

            # verify signature
            calc_signature = " ".join(str(value) for value in data) + str(data_id)
            logging.debug(f"calculating signature for this {calc_signature}")
            calc_signature = hmac.new(secret_key_sim, calc_signature.encode(), hashlib.sha256).hexdigest()

            if signature == calc_signature:
                # calculate new signature for nonce
                nonce = [ord(char) for char in nonce]

                calc_signature = hmac.new(secret_key_sim, str(nonce).encode(), hashlib.sha256).hexdigest()

                calc_signature = [ord(char) for char in calc_signature]
                logging.info(calc_signature)

                packed_data = struct.pack('!64I', *calc_signature)

                writer.write(packed_data)
                await writer.drain()

                logging.info("Verified signature on data, notified gui.")

                # put data in queue for train
                await data_queue.put(data)
            else:
                logging.critical("Found wrong signature in data")


async def handle_server() -> None:
    async def receive_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        global secret_key_sim
        global sequence_number_sim
        global send_queue

        recv_queue = asyncio.Queue()
        recv_event = asyncio.Event()

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

        secret_key_sim = base64.urlsafe_b64encode(derived_key)

        loop = asyncio.get_event_loop()

        loop.create_task(read_data_sim(reader, writer, recv_queue, recv_event))

        while True:
            data = await send_queue.get()

            data = " ".join(str(value) for value in data)

            client_verified = False

            while not client_verified:
                sequence_number_sim += 1
                temp_signature = data + str(sequence_number_sim)
                logging.info(temp_signature)
                temp_signature = hmac.new(secret_key_sim, temp_signature.encode(), hashlib.sha256).hexdigest()
                while True:
                    # Generate 2 bytes
                    nonce = [char for char in secrets.token_bytes(2)]

                    # Check if any character is a space
                    if b' ' not in nonce:
                        break

                if sequence_number_sim == 100:
                    logging.info("Updating secret key")
                    # await update_keys(gui_key, 1)

                data_to_send = ([sequence_number_sim] + [len(data)] + [ord(char) for char in data] + [32] + nonce +
                                [32] + [ord(char) for char in temp_signature])

                logging.info(data_to_send)

                logging.debug("Sending data")
                packed_data = struct.pack('!I{}I'.format(len(data_to_send)), len(data_to_send), *data_to_send)
                header_packed_data = struct.pack('!II', MESSAGE_TYPE_PACKED, len(packed_data))
                combined_data_packed_data = header_packed_data + packed_data
                writer.write(combined_data_packed_data)
                await writer.drain()

                expected_signature = [ord(char) for char in
                                      hmac.new(secret_key_sim, str(nonce).encode(), hashlib.sha256).hexdigest()]

                logging.debug(f"nonce {str(nonce)}")
                logging.debug(f"Expecting: {expected_signature}")

                recv_event.set()

                packed_data = await recv_queue.get()

                received_signature = list(struct.unpack('!64I', packed_data))

                logging.info(received_signature)

                if received_signature == expected_signature:
                    logging.debug("Client is verified")
                    client_verified = True
                else:
                    logging.critical("Found wrong signature in holding register")

    server = await asyncio.start_server(receive_data, "localhost", 12346)
    async with server:
        await server.serve_forever()