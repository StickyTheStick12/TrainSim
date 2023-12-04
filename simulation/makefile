#runs the program as 5 different gnome terminals its the same as "make kstart"
all: gnomestart

help:
	@echo "to install all dependencies: make install"
	@echo "to run program: make all or make gnomestart"
	@echo "to open webclient use https://127.0.0.1:5001"

install:
	pip install -r requirements.txt
	sudo apt update
	sudo apt install gnome-terminal

#stops the program, is the same as "make stop"
kill: stop

# starts the program in the same terminal as the command is run
start:
	@echo "starting program 1"
	python3 scripts/track_sensors.py &
	@echo "starting program 2"
	python3 scripts/gui.py &
	@echo "starting program 3"
	python3 scripts/Train.py &
	@echo "starting program 4"
	python3 scripts/switch.py &
	@echo "starting program 5"
	python3 scripts/hmi.py &
	@echo "To close the simulation type 'make stop'"

# starts the program in three different kde-terminals requires konsole and bash
kstart:
	@echo "Starting Program 1"
	konsole --noclose -e bash -c "python3 scripts/track_sensors.py; exec bash" &
	@echo "Starting Program 2"
	konsole --noclose -e bash -c "python3 scripts/gui.py; exec bash" &
	@echo "Starting Program 3"
	konsole --noclose -e bash -c "python3 scripts/Train.py; exec bash" &
	@echo "starting program 4"
	konsole --noclose -e bash -c "python3 scripts/switch.py; exec bash" &
	@echo "starting program 5"
	konsole --noclose -e bash -c "python3 scripts/hmi.py; exec bash" &
	@echo "------------------"
	@echo "To close the simulation type 'make stop'"

#starts the program in three different gnome-terminals requires gnome-terminal and bash
gnomestart:
	@echo "Starting Program 1"
	gnome-terminal --title="track_sensors" -- bash -c "python3 scripts/track_sensors.py; exec bash" &
	@echo "Starting Program 2"
	gnome-terminal --title="gui" -- bash -c "python3 scripts/gui.py; exec bash" &
	@echo "Starting Program 3"
	gnome-terminal --title="train"  -- bash -c "python3 scripts/train.py; exec bash" &
	@echo "Starting Program 4"
	gnome-terminal --title="switch" -- bash -c "python3 scripts/switch.py; exec bash" &
	@echo "Starting Program 5"
	gnome-terminal --title="hmi" -- bash -c "python3 scripts/hmi.py; exec bash" &
	@echo "------------------"
	@echo "To close the simulation type 'make stop'"

#starts the program in three different xterminals requires xterm
xstart:
	@echo "Starting Program 1"
	xterm -e python3 scrpits/track_sensors.py &
	@echo "Starting Program 2"
	xterm -e python3 scrpits/gui.py &
	@echo "Starting Program 3"
	xterm -e python3 scrpits/train.py &
	@echo "Starting Program 4"
	xterm -e python3 scrpits/switch.py &
	@echo "Starting Program 5"
	xterm -e python3 scrpits/hmi.py &
	@echo "To close the simulation type 'make stop'"

# Target to stop the programs
stop:
	@echo "Stopping Program 1"
	pkill -f train.py
	@echo "Stopping Program 2"
	pkill -f hmi.py
	@echo "Stopping Program 3"
	pkill -f switch.py
	@echo "Stopping Program 4"
	pkill -f gui.py
	@echo "Stopping Program 5"
	pkill -f track_sensors.py
	@echo "Program stopped"

#this assumes your program is not running, this is unfinished
attack:
	cd .. && gnome-terminal --title="modbus_attack" -- bash -c "python3 Attack/modbus_attack.py; exec bash" &
	make all
