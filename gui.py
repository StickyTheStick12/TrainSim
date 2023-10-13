import customtkinter as ctk
from pymodbus.client import AsyncModbusTlsClient
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.exceptions import ModbusException

import asyncio
import logging
import threading
from queue import Queue

logging.basicConfig()
_logger = logging.getLogger(__file__)
_logger.setLevel("DEBUG")

# Modbus variables
datastore_size = 41  # needs to be the same size as the server, max 125 though
path_to_cert = "/home/vboxuser/tls/cert.pem"
path_to_key = "/home/vboxuser/tls/key.pem"
host = "localhost"
port = 12345


class TrainStation(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        self.geometry("900x700")
        self.title("Train station")

        self.title_font = ctk.CTkFont(size = 24)
        self.subtitle_font = ctk.CTkFont(size = 20)
        self.text_font = ctk.CTkFont(size = 14)

        self.grid_columnconfigure(0, weight = 1)
        self.grid_columnconfigure(1, weight = 1)
        self.grid_rowconfigure(0, weight = 1)

        self.timetable_frame = ctk.CTkFrame(self, fg_color = "transparent")
        self.timetable_frame.grid(row = 0, column = 0, sticky = "nsew")

        self.tracks_frame = ctk.CTkFrame(self, fg_color = "transparent")
        self.tracks_frame.grid(row = 0, column = 1, sticky = "nsew")

        #grid for timetable frame
        for c in range(3):
            self.timetable_frame.grid_columnconfigure(c, weight = 1)
            self.tracks_frame.grid_columnconfigure(c, weight = 1)
        for r in range(25):
            self.timetable_frame.grid_rowconfigure(r, weight = 1)
            self.tracks_frame.grid_rowconfigure(r, weight = 1)


        self.track1_indicator = ctk.CTkCanvas(self.tracks_frame, bg = "green", width = 100, height = 50, highlightthickness = 0)
        self.track2_indicator = ctk.CTkCanvas(self.tracks_frame, bg = "green", width = 100, height = 50, highlightthickness = 0)


        self.create_timetable_layout()
        self.create_track_layout()

        self.timetable_data = []
        self.track_data = []

    def create_timetable_layout(self):
        timetable_label = ctk.CTkLabel(self.timetable_frame, text = "Timetable", font = self.title_font,
                                       corner_radius = 6)
        train_label = ctk.CTkLabel(self.timetable_frame, text = "Train", font = self.subtitle_font, corner_radius = 3)
        track_label = ctk.CTkLabel(self.timetable_frame, text = "Track", font = self.subtitle_font, corner_radius = 3)
        departure_label = ctk.CTkLabel(self.timetable_frame, text = "Departure", font = self.subtitle_font, corner_radius = 3)

        timetable_label.grid(row = 0, column = 0, columnspan = 3, sticky = "n", pady = 10)
        train_label.grid(row = 1, column = 0, sticky = "n", padx = 20)
        track_label.grid(row = 1, column = 1, sticky = "n")
        departure_label.grid(row = 1, column = 2, sticky = "n")

    def create_track_layout(self):
        track1_label_title = ctk.CTkLabel(self.tracks_frame, text="Track1", font=self.title_font, corner_radius=3)
        track2_label_title = ctk.CTkLabel(self.tracks_frame, text="Track2", font=self.title_font, corner_radius=3)

        track1_label_title.grid(row=0, column=0, columnspan=1)
        track2_label_title.grid(row=0, column=1, columnspan=1)

        self.track1_indicator.grid(row=1, column=0, columnspan=1)
        self.track2_indicator.grid(row=1, column=1, columnspan=1)

    def add_data_timetable(self, index, data):
        data[1], data[2] = data[2], data[1]
        self.timetable_data.insert(index, data)
        current_row = len(self.timetable_data)
        train_label = ctk.CTkLabel(self.timetable_frame, text=data[0], font=self.text_font)
        track_label = ctk.CTkLabel(self.timetable_frame, text=data[1], font=self.text_font)
        departure_label = ctk.CTkLabel(self.timetable_frame, text=data[2], font=self.text_font)

        train_label.grid(row=current_row + 2, column=0, padx=20)
        track_label.grid(row=current_row + 2, column=1)
        departure_label.grid(row=current_row + 2, column=2)

    def remove_data_timetable(self, index):
        if index < len(self.timetable_data):
            self.timetable_data.pop(index)
            for obj in self.timetable_frame.winfo_children():
                obj.grid_forget()
            self.create_timetable_layout()
            for current_row, data in enumerate(self.timetable_data, start=2):
                train, track, departure = data
                train_label = ctk.CTkLabel(self.timetable_frame, text=train, font=self.text_font)
                track_label = ctk.CTkLabel(self.timetable_frame, text=track, font=self.text_font)
                departure_label = ctk.CTkLabel(self.timetable_frame, text=departure, font=self.text_font)

                train_label.grid(row=current_row, column=0, padx=20)
                track_label.grid(row=current_row, column=1)
                departure_label.grid(row=current_row, column=2)
    def update_data_tracks(self, track_number, status):
        if track_number == 1:
            track_status = self.track1_indicator
        elif track_number == 2:
            track_status = self.track2_indicator
        else:
            print(f"Invalid track number: {track_number}")
            return

        if status == "Occupied":
            track_status.config(bg="red")
        else:
            track_status.config(bg="green")

    def process_modbus_data(self) -> None:
        if not modbus_data_queue.empty():
            # Don't block this thread if no data is available
            data = modbus_data_queue.get_nowait()

            match data[1]:
                case "A":
                    self.add_data_timetable(int(data[0]), data[2:])  # (index)1, [(Train)'1', '09:00', (Track)'1'])
                case "R":
                    self.remove_data_timetable(int(data[0]))  # (index) 1
                case "T":
                    self.update_data_tracks(int(data[0]), data[2])  # (track) 1, (status) "occupied"

        self.after(1000, self.process_modbus_data)


def modbus_client_thread(modbus_data_queue) -> None:
    """This thread will start the modbus client and connect to the server"""
    client = None

    loop = asyncio.new_event_loop()

    async def run_client() -> None:
        """Run client"""
        nonlocal client
        # ssl_context = ssl.create_default_context()
        # ssl_context.load_cert_chain(certfile="rootCA.pm", keyfile="rootCA.key")  # change to file path

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
        try:
            while True:
                # poll the flag bit to see if new information has been written
                hold_register = await client.read_holding_registers(datastore_size - 2, 1, slave=1)
                if hold_register.registers == [0]:
                    _logger.debug("New information available")
                    hold_register = await client.read_holding_registers(0x00, datastore_size - 3, slave=1)

                    if not hold_register.isError():
                        # 10 1 A gffff 15:15 1
                        amount_to_read = hold_register.registers[0]
                        idx = hold_register.registers[1]
                        data = [idx] + "".join(
                            [chr(char) for char in hold_register.registers[2:2 + amount_to_read]]).split(" ")
                        _logger.debug(f"received {data}")
                        _logger.debug("Resetting flag")
                        await client.write_register(datastore_size - 2, 1, slave=1)

                        # put data in queue for the GUI thread
                        modbus_data_queue.put(data)
                    else:
                        _logger.error("Error reading holding register")

                _logger.debug("sleeping for 1 second")
                await asyncio.sleep(1)
        except ModbusException as exc:
            _logger.error(f"Received ModbusException({exc}) from library")
            client.close()
        except KeyboardInterrupt:
            _logger.info("Keyboard interrupt received. Exiting.")
            client.close()

    print(path_to_cert)

    loop.run_until_complete(run_client())
    loop.run_until_complete(read_holding_register())


if __name__ == "__main__":
    modbus_data_queue = Queue()

    modbus_thread = threading.Thread(target=modbus_client_thread, args=(modbus_data_queue,))
    modbus_thread.start()
    # Initialize the Train Station HMI
    train_station_hmi = TrainStation()
    train_station_hmi.after(1000, train_station_hmi.process_modbus_data)

    try:
        train_station_hmi.mainloop()
    except KeyboardInterrupt:
        _logger.info("Program terminated by user")
        modbus_thread.join()
    modbus_thread.join()
