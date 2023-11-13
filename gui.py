import customtkinter as ctk
from pymodbus.client import AsyncModbusTlsClient
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.exceptions import ModbusException

from PIL import Image, ImageTk

import asyncio
import logging
import multiprocessing
import hmac
import hashlib
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s', level=logging.INFO)
_logger = logging.getLogger(__file__)

# Modbus variables
datastore_size = 124  # needs to be the same size as the server, max 125 though
path_to_cert = "/home/vboxuser/tls/cert.pem"
path_to_key = "/home/vboxuser/tls/key.pem"
host = "localhost"
port = 12345


class TrainStation(ctk.CTk):
    class TrainStation(ctk.CTk):

        def __init__(self):
            super().__init__()
            ctk.set_appearance_mode("dark")
            self.geometry("900x700")
            self.title("Train station")

            # Fonts for text
            self.title_font = ctk.CTkFont(size=24)
            self.subtitle_font = ctk.CTkFont(size=20)
            self.text_font = ctk.CTkFont(size=16)

            # Data containers
            self.timetable_data = []
            self.track_indicators = []
            self.track_canvases = []
            # nested list represent what track the train/trains are on
            # E.g. self.trains[0] represent track 1, self.trains[1] represent track 2, etc
            self.trains = [[], [], [], [], [], []]
            self.track_switch_canvases = []

            # Grid for frames in master window
            self.grid_columnconfigure(0, weight=1)
            self.grid_columnconfigure(1, weight=1)
            self.grid_rowconfigure(0, weight=1)

            # Create the left frame that'll contain the timetable
            self.timetable_frame = ctk.CTkFrame(self, fg_color="transparent")
            self.timetable_frame.grid(row=0, column=0, sticky="nsew")

            # Create the right frame that'll contain the tracks
            self.tracks_frame = ctk.CTkFrame(self, fg_color="transparent")
            self.tracks_frame.grid(row=0, column=1, sticky="nsew")

            # Create the grid in the timetable frame
            for c in range(3):
                self.timetable_frame.grid_columnconfigure(c, weight=1)
            for r in range(25):
                self.timetable_frame.grid_rowconfigure(r, weight=1)

            # Create the grid in the tracks frame
            for c in range(6):
                self.tracks_frame.grid_columnconfigure(c, weight=1)

            self.image = Image.open("train.png")
            self.image = self.image.resize((50, 140))
            self.image = ImageTk.PhotoImage(self.image)

            # Create the timetable layout
            self.create_timetable_layout()

            # Create the track layout
            self.create_track_layout()

            self.current_switch_location = 1

        def create_timetable_layout(self):
            """Create the timetable layout in the timetable frame"""
            # Create labels for each header
            timetable_label = ctk.CTkLabel(self.timetable_frame, text="Timetable", font=self.title_font,
                                           corner_radius=6)
            train_label = ctk.CTkLabel(self.timetable_frame, text="Departure", font=self.subtitle_font, corner_radius=3)
            track_label = ctk.CTkLabel(self.timetable_frame, text="Destination", font=self.subtitle_font,
                                       corner_radius=3)
            departure_label = ctk.CTkLabel(self.timetable_frame, text="Track", font=self.subtitle_font, corner_radius=3)

            # Put the labels in the timetable frame's grid
            timetable_label.grid(row=0, column=0, columnspan=3, sticky="n", pady=10)
            train_label.grid(row=1, column=0, sticky="n", padx=20)
            track_label.grid(row=1, column=1, sticky="n")
            departure_label.grid(row=1, column=2, sticky="n")

        def create_track_layout(self):
            """Create the track layout in the tracks frame"""
            # Each iteration is one track
            for i in range(6):
                # Track label for the header and put it in the tracks frame's grid
                track_label_title = ctk.CTkLabel(self.tracks_frame, text=f"Track {i + 1}", font=self.title_font,
                                                 corner_radius=3)
                track_label_title.grid(row=0, column=i, pady=10)

                # Create the track indicator(show if track is available or occupied)
                track_indicator = ctk.CTkCanvas(self.tracks_frame, bg="green", width=100, height=50,
                                                highlightthickness=0)
                track_indicator.grid(row=1, column=i)
                self.track_indicators.append(track_indicator)

                # Create the track canvas, put it in the tracks frame's grid and store it in a list
                track_canvas = ctk.CTkCanvas(self.tracks_frame, width=100, height=400, highlightthickness=0)
                track_canvas.grid(row=2, column=i)
                self.track_canvases.append(track_canvas)

                # Creation of the tracks in the track canvas
                track_width = 10
                gap_width = 5

                # Create each individual piece of the track, iteration 0 to 400 to fill the entire track canvas height
                for y in range(0, 400, track_width + gap_width):
                    track_canvas.create_rectangle(10, y, 90, y + track_width, fill="grey")

                # Create switch canvas for each track
                track_switch_canvas = ctk.CTkCanvas(self.tracks_frame, width=100, height=100, highlightthickness=0,
                                                    bg=self["bg"])
                track_switch_canvas.grid(row=3, column=i, pady=10)
                self.track_switch_canvases.append(track_switch_canvas)

        def track_switch(self, track_switch):
            """create a track switch that points at a specific track"""
            old_switch_canvas = self.track_switch_canvases[self.current_switch_location - 1]
            old_switch_canvas.delete("all")
            track_switch_index = track_switch - 1
            track_switch_canvas = self.track_switch_canvases[track_switch_index]
            track_switch_canvas.create_polygon(20, 20, 80, 20, 50, 0, fill="pink")
            track_switch_canvas.create_line(50, 60, 50, 20, fill="pink", width=5)
            track_switch_canvas.create_text(50, 70, text="Track switch", font=self.text_font, fill="pink")
            self.current_switch_location = track_switch

        def create_train(self, track):
            """Creates a train on a given track(1-6) outside the train station"""
            # Track index in the list (0 - 5)
            track_index = track - 1
            # Get the track canvas we want to create the train on
            track_canvas = self.track_canvases[track_index]
            # Create the train on the track canvas
            train = track_canvas.create_image(50, 450, image=self.image)
            # Append it to the nested list of trains in a given track
            self.trains[track_index].append([train])
            # Move the created train in to the train station
            self.move_train_to_station(track, train)

        def create_train_in_station(self, track):
            """Creates a train on a given track(1-6) positioned in the train station"""
            # Track index in the list (0 - 5)
            track_index = track - 1
            # Get the track canvas we want to create the train on
            track_canvas = self.track_canvases[track_index]
            # Create the train on the track canvas
            train = track_canvas.create_image(50, 80, image=self.image)
            # Set the specified track to occupied
            self.track_indicator_update(track, "O")
            # Append it to the nested list of trains in a given track
            self.trains[track_index].append([train])

        def move_train_to_station(self, track, train_object):
            """Moves a given train object on a given track to the train station"""
            # Get the given track's canvas
            track_index = track - 1
            track_canvas = self.track_canvases[track_index]
            # If train is arriving it starts from y = 400
            y0 = 450
            self.train_arrive(track, track_canvas, train_object, y0)

        def train_arrive(self, track, track_canvas, train_object, current_y):
            """Move train to the train station by calling itself and updating current y-value"""
            if len(self.trains[track - 1]) > 1:  # if multiple trains are on the same track
                if current_y > 220:  # If train hasn't reached the station yet
                    track_canvas.move(train_object, 0, -2)  # Move the train up
                    self.after(100, self.train_arrive, track, track_canvas, train_object,
                               current_y - 2)  # Schedule next move after 50 milliseconds
                else:  # When train arrive
                    self.crash(track)  # multiple trains on the track result in a crash
            else:  # Only one train is on the given track
                if current_y > 80:  # If train hasn't reached the station yet
                    track_canvas.move(train_object, 0, -2)  # Move the train up
                    self.after(100, self.train_arrive, track, track_canvas, train_object,
                               current_y - 2)  # Schedule next move after 50 milliseconds
                else:  # When train arrive
                    self.track_indicator_update(track, "O")  # Update track indicator to occupied

        def move_train_from_station(self, track, train_number):
            """Moves a given train on a given track out of the train station"""
            # Get the given track's canvas
            track_index = track - 1
            track_canvas = self.track_canvases[track_index]

            # Get the train index from the train number
            train_index = train_number - 1
            train_object = self.trains[track_index][train_index]

            y0 = 120
            # Call iterative function that call itself for the sole purpose to move object
            self.train_depart(track_index, track_canvas, train_index, train_object, y0)

        def train_depart(self, track_index, track_canvas, train_index, train_object, current_y):
            """Move train out of the train station by calling itself and updating current y-value"""
            if current_y < 520:  # If train hasn't exit the station yet
                track_canvas.move(train_object, 0, 2)  # Move the train down
                self.after(50, self.train_depart, track_index, track_canvas, train_index, train_object,
                           current_y + 2)  # Schedule next move after 50 milliseconds
            else:  # When train is out of the station
                self.track_indicator_update(track_index + 1, "A")  # Update the track indicator to available
                self.trains = self.trains[track_index].pop(train_index)  # Remove the train from the trains list

        def add_data_timetable(self, index, data):
            """Add a train in the timetable"""
            self.timetable_data.insert(index, data)
            # Remove all the old data in the timetable frame
            for obj in self.timetable_frame.winfo_children():
                obj.grid_forget()
            # Create the timetable layout in timetable frame
            self.create_timetable_layout()

            # Plot the new data in the timetable
            for current_row, data in enumerate(self.timetable_data, start=2):
                train, track, departure = data

                train_label = ctk.CTkLabel(self.timetable_frame, text=train, font=self.text_font)
                track_label = ctk.CTkLabel(self.timetable_frame, text=track, font=self.text_font)
                departure_label = ctk.CTkLabel(self.timetable_frame, text=departure, font=self.text_font)

                train_label.grid(row=current_row, column=0, padx=20)
                track_label.grid(row=current_row, column=1)
                departure_label.grid(row=current_row, column=2)

        def remove_data_timetable(self, index):
            """Remove a train from the timetable"""

            # If the row(index) exist in timetable
            if 0 <= index < len(self.timetable_data):
                self.timetable_data.pop(index)  # Remove the data on the given index

                for obj in self.timetable_frame.winfo_children():  # Wipe the frame
                    obj.grid_forget()

                self.create_timetable_layout()  # Create the timetable layout

                for current_row, data in enumerate(self.timetable_data,
                                                   start=2):  # Plot the updated data to the timetable
                    train, track, departure = data

                    train_label = ctk.CTkLabel(self.timetable_frame, text=train, font=self.text_font)
                    track_label = ctk.CTkLabel(self.timetable_frame, text=track, font=self.text_font)
                    departure_label = ctk.CTkLabel(self.timetable_frame, text=departure, font=self.text_font)

                    train_label.grid(row=current_row, column=0, padx=20)
                    track_label.grid(row=current_row, column=1)
                    departure_label.grid(row=current_row, column=2)

        def track_indicator_update(self, track_number, status):
            """Update a given track's(1-6) indicator"""
            if track_number < 1 or track_number > 6:
                print(f"Invalid track number: {track_number}")
                return
            track_index = track_number - 1
            track_status = self.track_indicators[track_index]
            if status == "O":
                track_status.config(bg="red")  # Set the indicator to red(occupied)
            else:
                track_status.config(bg="green")  # Set the indicator to green(available)

        def crash(self, track):
            """Crash simulation"""
            track_index = track - 1
            train_canvas = self.track_canvases[track_index]
            train_canvas.create_oval(0, 100, 100, 200,
                                     fill="orange")  # Create the explosion between the train in the station and the train moving towards the station

    def process_modbus_data(self) -> None:
        if not modbus_data_queue.empty():
            # Don't block this thread if no data is available
            data = modbus_data_queue.get_nowait()
            match data[0]:
                case "A":
                    # Packet: ["A", "index", "EstimatedTime", "ToLocation", "Track"]
                    self.add_data_timetable(int(data[1]), [data[3], data[4], data[5]])
                case "S":
                    # Packet: ["S", "switch_status"]
                    self.track_switch(int(data[1]))
                case "R":
                    # Packet ["R", "index"]
                    self.move_train_from_station(int(data[1]), 1)
                    self.remove_data_timetable(int(data[2]))
                case "T":
                    # Packet ["T", "track", "status"]
                    self.track_indicator_update(int(data[1]), data[2])
                case "U":
                    # Packet ["U", "index", EstimatedTime, "track"]
                    location = self.timetable_data[int(data[1])][1]
                    self.remove_data_timetable(int(data[1]))
                    self.add_data_timetable(int(data[1]), [data[3], location, data[4]])
                case "H":
                    # Packet: ["H", "track"]
                    train_station_hmi.create_train(int(data[1]))
                case "B":
                    self.remove_data_timetable(int(data[1]))
                case "C":
                    self.create_train_in_station(int(data[1]))

        self.after(1000, self.process_modbus_data)


def modbus_client_thread() -> None:
    """This thread will start the modbus client and connect to the server"""
    client = None
    loop = asyncio.new_event_loop()
    a_queue = asyncio.Queue()
    secret_key = b""
    highest_data_id = 0

    async def run_client() -> None:
        """Run client"""
        nonlocal client

        client = AsyncModbusTlsClient(
            host,
            port=port,
            framer=ModbusTlsFramer,
            certfile=path_to_cert,
            keyfile=path_to_key,
            server_hostname="host",
        )

        _logger.info("Started client")

        await client.connect()
        # if we can't connect try again after 5 seconds, if the server hasn't been started yet
        while not client.connected:
            _logger.info("Couldn't connect to server, trying again in 5 seconds")
            await asyncio.sleep(5)
            await client.connect()
        _logger.info("Connected to server")

        # Write confirmation to server that we are active
        await client.write_register(datastore_size - 2, 1, slave=1)
        _logger.debug("Wrote confirmation to server")

    async def read_holding_register() -> None:
        """Reads data from holding register"""
        nonlocal client
        nonlocal secret_key
        nonlocal highest_data_id

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
                        _logger.info(f"calcualting signature for this {calc_signature}")
                        calc_signature = hmac.new(secret_key, calc_signature.encode(), hashlib.sha256).hexdigest()

                        if signature == calc_signature:
                            # calculate new signature for nonce
                            nonce = [ord(char) for char in nonce]
                            calc_signature = hmac.new(secret_key, str(nonce).encode(), hashlib.sha256).hexdigest()

                            calc_signature = [ord(char) for char in calc_signature]
                            _logger.info(calc_signature)
                            for i in range(len(calc_signature)):
                                await client.write_register(i, calc_signature[i], slave=1)

                            _logger.info("Resetting flag")
                            await client.write_register(datastore_size - 2, 1, slave=1)

                            _logger.info(f"received {data}")

                            _logger.info("Verified signature on data, notified gui.")

                            # This is only for attack scenario
                            if data[0] == "Q":
                                await a_queue.put(data[1])
                                data[0] = "S"

                            # put data in queue for the GUI thread
                            modbus_data_queue.put(data)
                    else:
                        _logger.error("Error reading holding register")

                _logger.debug("sleeping for 1 second")
                await asyncio.sleep(1)
        except ModbusException as exc:
            _logger.error(f"Received ModbusException({exc}) from library")
            client.close()

    async def send_data(writer: asyncio.StreamWriter) -> None:
        data = await a_queue.get()
        writer.write(data)
        await writer.drain()

    async def handle_server() -> None:
        async def receive_key(reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> None:
            loop.create_task(send_data(writer))

            nonlocal secret_key
            nonlocal highest_data_id

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
                cipher = Fernet(secret_key)
                secret_key = cipher.decrypt(data)
                _logger.info("Updated secret key")
                highest_data_id = 0

        server = await asyncio.start_server(receive_key, "localhost", 12346)
        async with server:
            await server.serve_forever()

    loop.run_until_complete(run_client())
    loop.create_task(handle_server())
    loop.run_until_complete(read_holding_register())


if __name__ == "__main__":
    modbus_data_queue = multiprocessing.Queue()

    modbus_process = multiprocessing.Process(target=modbus_client_thread)
    modbus_process.start()
    # Initialize the Train Station HMI
    train_station_hmi = TrainStation()
    train_station_hmi.after(5000, train_station_hmi.process_modbus_data)
    train_station_hmi.mainloop()
