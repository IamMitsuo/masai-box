#!/bin/bash

SETUP_PATH=$(readlink -f "$0")
MASAI_ROOT_DIR=$(dirname "$SETUP_PATH")
VFEED_DIR="$MASAI_ROOT_DIR/vfeed/vfeed"
VFEED_DB_PATH="$VFEED_DIR/vfeed.db"
VENV_DIR="$MASAI_ROOT_DIR/venv"

# Check if there is internet connection, otherwise exit with code 1
wget --spider --quiet http://www.google.com
if [ $? -eq 0 ]
	then
		echo "[INFO] There is the Internet connection. Start next process"
	else
		echo "[ERROR] No Internet connection. Exit with code 1" >&2
		exit 1
fi

# Download vfeed.db first if it does not exist
if ! [ -e $VFEED_DB_PATH ]
	then
		echo "[INFO] vfeed.db does not exist"
		echo "[DOWNLOAD] Start downloading from https://github.com/IamMitsuo/masai-box/releases/download/v0.1-alpha/vfeed.db"
		wget -O $VFEED_DB_PATH https://github.com/IamMitsuo/masai-box/releases/download/v0.1-alpha/vfeed.db
		echo "[INFO] Downloading process finished."
	else
		echo "[INFO] vfeed.db exists, skip downloading"
fi

# Check if Python 3 is installed, otherwise install python3
if ! [ -x "$(command -v python3)" ]; then
	echo "[WARNING] python3 is not installed." >&2
	echo "[INFO] Running 'apt-get install -y python3'"
	apt-get install -y python3
	if [[ $? -gt 0 ]]; then
		echo "[ERROR] Unsuccesfully install python3. Exit with code 1" >&2
		exit 1
	else 
		echo "[INFO] Finish Python3 installation"
	fi
else
	echo "[INFO] Python3 is found"
fi

# Check if there exists pip3, otherwise install pip3
if ! [ -x "$(command -v pip3)" ]; then
	echo "[WARNING] pip3 is not installed." >&2
	echo "[INFO] Running 'apt-get install -y python3-pip'"
	apt-get install -y python3-pip
	if ! [ $? -eq 0 ]; then
		echo "[WARNING] Unsuccessfully install pip3."
		echo "[INFO] Try to using --fix-missing option"
		echo "[INFO] Running 'apt-get install -y --fix-missing python3-pip'"
		apt-get install -y --fix-missing python3-pip
		if ! [ $? -eq 0]; then
			echo "[ERROR] Unsuccessfully install pip3. Exit with code 1" >&2
			exit 1
		else
			echo "[INFO] Finish pip3 installation"
		fi
	else
		echo "[INFO] Finish pip3 installation"
	fi
else
	echo "[INFO] pip3 is found"
fi

# Check if there exists venv directory, otherwise install venv
if ! [ -e $VENV_DIR ]; then
	echo "[WARNING] venv does not exist"
else
	echo "[WARNING] venv exists. Remove venv directory"
	rm -r $VENV_DIR
	echo "[INFO] venv was removed"
fi
echo "[INFO] Create a venv directory"
mkdir $VENV_DIR

# Check if virtualenv is installed
pip3 list | grep virtualenv
if ! [ $? -eq 0 ]; then
	echo "[WARNING] virtualenv is not installed."
	echo "[INFO] Start install virtualenv"
	pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org virtualenv
	echo "[INFO] Finish virtualenv installation"
else
	echo "[INFO] virtualenv is found"
fi

# Create virtualenv to venv directory
echo "[INFO] Running python3 -m virtualenv $VENV_DIR"
python3 -m virtualenv $VENV_DIR
