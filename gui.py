from tkinter import *
import customtkinter
import asyncio
from pymodbus.client import AsyncModbusTlsClient
from pymodbus.transaction import ModbusTlsFramer
from pymodbus.exceptions import ModbusException

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


# Initialize the Train Station HMI
train_station_hmi = TrainStationHMI()


# Adding some trains
train_station_hmi.add_train_to_timetable('Train 1', '09:00', 'Track 1')
train_station_hmi.add_train_to_timetable('Train 2', '10:30', 'Track 2')

# Removing a train (by index)
train_station_hmi.remove_train_from_timetable(0)  # Removes 'Train 1'
train_station_hmi.remove_train_from_timetable(0)  # Removes 'Train 1'

# Start the main event loop
train_station_hmi.mainloop()




async def modbus_client_thread(host: str, port: int) -> None:
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
            certfile="cert.perm",
            keyfile="key.perm",
            server_hostname="host",
        )

        await client.connect()
        # if we can't connect try again after 5 seconds, if the server hasn't been started yet
        while not client.connected:
            await asyncio.sleep(5)
            await client.connect()

        print("connected")

    async def read_holding_register() -> None:
        """Reads data from holding register"""
        nonlocal client
        try:
            while True:
                hold_register = await client.read_holding_registers(0x00, 40, slave=1) # 40 may need to be lower, it is amount we want to read
                print("New data received:", hold_register.registers)
                amount_to_read = hold_register.registers[0]
                data = "".join([chr(char) for char in hold_register.registers[1:amount_to_read]]).split(" ")
                # call functions to update values in hmi/gui here

                match data[0]:
                    case "A":
                        train_station_hmi.add_train_to_timetable('Train 1', '09:00', 'Track 1')
                    case "R":
                        train_station_hmi.remove_train_from_timetable(0)
                    case "T":
                        pass

                await asyncio.sleep(1)  # wait 1 second before trying to receive more data
        except ModbusException as exc:
            print(f"Received ModbusException({exc}) from library")
            client.close()

    await run_client()
    await read_holding_register()





