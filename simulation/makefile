#runs the program as 5 different konsoles its the same as "make kstart"
all: kstart

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
	gnome-terminal -- bash -c "python3 scripts/track_sensors.py; exec bash" &
	@echo "Starting Program 2"
	gnome-terminal -- bash -c "python3 scripts/gui.py; exec bash" &
	@echo "Starting Program 3"
	gnome-terminal -- bash -c "python3 scripts/train.py; exec bash" &
	@echo "Starting Program 4"
	gnome-terminal -- bash -c "python3 scripts/switch.py; exec bash" &
	@echo "Starting Program 5"
	gnome-terminal -- bash -c "python3 scripts/hmi.py; exec bash" &
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
	pkill -f gui.py
	@echo "Stopping Program 2"
	pkill -f hmi.py
	@echo "Stopping Program 3"
	pkill -f switch.py
	@echo "Stopping Program 4"
	pkill -f Train.py
	@echo "Stopping Program 5"
	pkill -f track_sensors.py
	@echo "Program stopped"