# Define the default target (the first one is executed by default)
all: gnomestart

kill: stop

# starts the program in the same terminal as the command is run
start:
	@echo "starting program 1"
	python3 hmi.py &
	@echo "starting program 2"
	python3 gui.py &
	@echo "starting program 3"
	python3 switch.py &
	@echo "To close the simulation type 'make stop'"

#starts the program in three different gnome-terminals requires gnome-terminal and bash
gnomestart:
	@echo "Starting Program 1"
	gnome-terminal -- bash -c "python3 hmi.py; exec bash" &
	@echo "Starting Program 2"
	gnome-terminal -- bash -c "python3 gui.py; exec bash" &
	@echo "Starting Program 3"
	gnome-terminal -- bash -c "python3 switch.py; exec bash" &
	@echo "------------------"
	@echo "To close the simulation type 'make stop'"

#starts the program in three different xterminals requires xterm
xstart:
	xterm -e python3 hmi.py &
	xterm -e python3 gui.py &
	xterm -e python3 switch.py &
	@echo "To close the simulation type 'make stop'"

# Target to stop the programs
stop:
	@echo "Stopping Program 1"
	pkill -f hmi.py
	@echo "Stopping Program 2"
	pkill -f gui.py
	@echo "Stopping Program 3"
	pkill -f switch.py
