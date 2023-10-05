from tkinter import *
import customtkinter


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

