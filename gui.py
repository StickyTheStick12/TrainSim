from tkinter import *
import customtkinter
import asyncio
from pymodbus.client import AsyncModbusTlsClient
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.exceptions import ModbusException
import logging
import threading
from queue import Queue

logging.basicConfig()
_logger = logging.getLogger(__file__)
_logger.setLevel("DEBUG")

# Modbus variables
datastore_size = 41  # needs to be the same size as the server
path_to_cert = "cert.perm"
path_to_key = "key.perm"
host = ""
port = 12345

class TrainStationHMI(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title("Train Station HMI")
        customtkinter.set_appearance_mode("dark")
        self.geometry('800x400')

        for c in range(3):
            self.columnconfigure(index=c, weight=1)

        for r in range(2):
            self.rowconfigure(index=r, weight=1)

        self.track1_label = customtkinter.CTkLabel(self, text="Track 1", fg_color="gray30", corner_radius=6)
        self.track1_label.grid(row=0, column=0, sticky="nwe", padx=(10, 0), pady=(100, 50))

        self.track2_label = customtkinter.CTkLabel(self, text="Track 2", fg_color="gray30", corner_radius=6)
        self.track2_label.grid(row=1, column=0, sticky="nwe", padx=(10, 1), pady=(100, 50))

        self.track1_rect = customtkinter.CTkCanvas(self, width=100, height=50, highlightthickness=0, bg="green")
        self.track1_rect.grid(row=0, column=1, pady=(1, 5), padx=(0, 10), sticky="w")

        self.track2_rect = customtkinter.CTkCanvas(self, width=100, height=50, highlightthickness=0, bg="red")
        self.track2_rect.grid(row=1, column=1, pady=(5, 10), padx=(0, 10), sticky="w")

        self.timetable_frame = customtkinter.CTkFrame(self, width=10)
        self.timetable_frame.grid(row=0, column=2, rowspan=2, sticky="nsew")

        self.timetable_title = customtkinter.CTkLabel(self.timetable_frame, text="Timetable", fg_color="gray30", corner_radius=6, font=("Arial", 14))
        self.timetable_title.grid(row=0, column=0, columnspan=3, sticky="nwe", pady=(10, 5))

        self.train_data = []  # List to store train data

        self.train_number_label = customtkinter.CTkLabel(self.timetable_frame, text="Train Number ", font=("Arial", 12), anchor="w")
        self.train_number_label.grid(row=1, column=0, sticky="ew", padx=(10, 0))

        self.departure_time_label = customtkinter.CTkLabel(self.timetable_frame, text="Departure Time ", font=("Arial", 12), anchor="w")
        self.departure_time_label.grid(row=1, column=1, sticky="ew")

        self.track_number_label = customtkinter.CTkLabel(self.timetable_frame, text="Track Number", font=("Arial", 12), anchor="w")
        self.track_number_label.grid(row=1, column=2, sticky="ew", padx=(0, 10))


    def add_train_to_timetable(self, train_number, departure_time, track_number):
        idx = len(self.train_data)  # Get the current number of trains

        self.train_data.append({'train_number': train_number, 'departure_time': departure_time, 'track_number': track_number})

        train_number_label = customtkinter.CTkLabel(self.timetable_frame, text=f"{train_number}", font=("Arial", 12), anchor="w")
        train_number_label.grid(row=idx+2, column=0, sticky="ew", padx=(10, 0))

        departure_time_label = customtkinter.CTkLabel(self.timetable_frame, text=f"{departure_time}", font=("Arial", 12), anchor="w")
        departure_time_label.grid(row=idx+2, column=1, sticky="ew")

        track_number_label = customtkinter.CTkLabel(self.timetable_frame, text=f"{track_number}", font=("Arial", 12), anchor="w")
        track_number_label.grid(row=idx+2, column=2, sticky="ew", padx=(0, 10))


    def remove_train_from_timetable(self, idx):
        if 0 <= idx < len(self.train_data):
            del self.train_data[idx]
            # Clear all widgets in the timetable frame

            for widget in self.timetable_frame.winfo_children():
                widget.grid_forget()

            # Rebuild the timetable
            self.timetable_title.grid(row=0, column=0, columnspan=4, sticky="nwe", pady=(10, 5))
            self.train_number_label.grid(row=1, column=0, sticky="ew", padx=(10, 0))
            self.departure_time_label.grid(row=1, column=1, sticky="ew")
            self.track_number_label.grid(row=1, column=2, sticky="ew", padx=(0, 10))

            for i, data in enumerate(self.train_data):
                train_number_label = customtkinter.CTkLabel(self.timetable_frame, text=data['train_number'], font=("Arial", 12), anchor="w")
                train_number_label.grid(row=i + 2, column=0, sticky="ew", padx=(10, 0))

                departure_time_label = customtkinter.CTkLabel(self.timetable_frame, text=data['departure_time'], font=("Arial", 12), anchor="w")
                departure_time_label.grid(row=i + 2, column=1, sticky="ew")

                track_number_label = customtkinter.CTkLabel(self.timetable_frame, text=data['track_number'], font=("Arial", 12), anchor="w")
                track_number_label.grid(row=i + 2, column=2, sticky="ew", padx=(0, 10))


    def process_modbus_data(self) -> None:
        try:
            data = modbus_data_queue.get_nowait()
        except Queue.Empty:
            data = None

        if data:
            match data[0]:
                case "A":
                    train_station_hmi.add_train_to_timetable('Train 1', '09:00', 'Track 1')
                case "R":
                    train_station_hmi.remove_train_from_timetable(0)
                case "T":
                    pass

        self.after(1000, self.process_modbus_data)

def modbus_client_thread(queue) -> None:
    """This thread will start the modbus client and connect to the server"""
    client = None

    async def run_client() -> None:
        """Run client"""
        nonlocal client
        # ssl_context = ssl.create_default_context()
        # ssl_context.load_cert_chain(certfile="rootCA.pm", keyfile="rootCA.key")  # change to file path

        client = await AsyncModbusTlsClient(
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
        await client.write_register(datastore_size-2, 1, slave=1)
        _logger.info("Wrote confirmation to server")

    async def read_holding_register() -> None:
        """Reads data from holding register"""
        nonlocal client
        try:
            while True:
                # poll the flag bit to see if new information has been written
                if client.read_holding_registers(datastore_size-2, 1, slave=1).registers == [0]:
                    _logger.info("New information available")
                    hold_register = await client.read_holding_registers(0x00, datastore_size-3, slave=1)

                    if hold_register.isError():
                        _logger.error("Error reading holding register")

                    amount_to_read = hold_register.registers[0]
                    data = "".join([chr(char) for char in hold_register.registers[1:amount_to_read]]).split(" ")
                    _logger.debug("Resetting flag")
                    client.write_register(datastore_size-2, 1, slave=1)

                    # put data in queue for the GUI thread
                    queue.put(data)

                    # sleeping for 1 second before starting polling again
                    await asyncio.sleep(1)
                else:
                    _logger.info("sleeping for 1 second")
                    await asyncio.sleep(1)
        except ModbusException as exc:
            _logger.error(f"Received ModbusException({exc}) from library")
            client.close()
        except KeyboardInterrupt:
            _logger.info("Keyboard interrupt received. Exiting.")
            client.close()

    asyncio.get_event_loop().run_until_complete(run_client())
    asyncio.get_event_loop().run_until_complete(read_holding_register())

if __name__ == "__main__":
    modbus_data_queue = Queue()

    modbus_thread = threading.Thread(target=modbus_client_thread, args=(modbus_data_queue, ))
    modbus_thread.start()
    # Initialize the Train Station HMI
    train_station_hmi = TrainStationHMI()
    train_station_hmi.after(1000, train_station_hmi.process_modbus_data)

    try:
        train_station_hmi.mainloop()
    except KeyboardInterrupt:
        _logger.info("Program terminated by user")
        modbus_thread.join()
