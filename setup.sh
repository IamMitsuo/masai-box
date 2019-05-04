#!/bin/bash

SETUP_PATH=$(readlink -f "$0")
MASAI_ROOT_DIR=$(dirname "$SETUP_PATH")
VFEED_DIR="$MASAI_ROOT_DIR/vfeed/vfeed"
VFEED_DB_PATH="$VFEED_DIR/vfeed.db"
VENV_DIR="$MASAI_ROOT_DIR/venv"
MASAI_SRC_DIR="$MASAI_ROOT_DIR/masai/"
VFEED_SRC_DIR="$MASAI_ROOT_DIR/vfeed/"
BLUETOOTH_SERVICE_PATH="/lib/systemd/system/bluetooth.service"
QR_CODE_GENERATOR_PATH=$MASAI_ROOT_DIR/qrcode_generator.py
WORDLIST_PATH=$MASAI_ROOT_DIR/wordlists/wordlist.txt
PASSWORD_PATH=$MASAI_ROOT_DIR/wordlists/password.txt
LOGIN_PATH=$MASAI_ROOT_DIR/wordlists/login.txt

# Check if there is internet connection, otherwise exit with code 1
wget --spider --quiet http://www.google.com
if [ $? -eq 0 ]
	then
		echo "[INFO] There is the Internet connection. Start next process"
	else
		echo "[ERROR] No Internet connection. Exit with code 1" >&2
		exit 1
fi

# Copy wordlist, password, and login to /usr/share/dict
cp $WORDLIST_PATH /usr/share/dict/
cp $PASSWORD_PATH /usr/share/dict/
cp $LOGIN_PATH /usr/share/dict/

# Enable bluetooth service
systemctl enable bluetooth

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

# Upgrade pip3 to the newest version
# echo "[INFO] Upgrade pip3 to the newest version"
# pip3 install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org pip --upgrade
# echo "[INFO] Finish Upgrade"

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
	pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host pypi.python.org virtualenv
	echo "[INFO] Finish virtualenv installation"
else
	echo "[INFO] virtualenv is found"
fi

# Create virtualenv to venv directory
echo "[INFO] Running python3 -m virtualenv $VENV_DIR"
python3 -m virtualenv $VENV_DIR

# Activate virtualenv on venv directory
echo "[INFO] activate virtualenv on venv directory"
source $VENV_DIR/bin/activate
echo "[INFO] venv has been activated"

# Download debian packages required for python libraries
echo "[INFO] Install required system packages"
apt-get install -y libbluetooth-dev \
 python-dev \
 libglib2.0-dev \
 libboost-python-dev \
 libboost-thread-dev \
 libffi-dev \
 libssl-dev

if ! [ $? -eq 0 ]; then
	echo "[ERROR] Unsuccefully install some packages" >&2
	exit 1
fi

echo "[INFO] Finish required system packages installation"

echo "[INFO] Start installing xmltodict, pyqrcode and pypng"
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org xmltodict
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org pyqrcode
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org pypng

echo "[INFO] Start installing PyblueZ"
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org git+https://github.com/pybluez/pybluez.git

if ! [ $? -eq 0 ]; then
	echo "[ERROR] Python libraries installation from requirements.txt failed" >&2
	exit 1
fi
echo "[INFO] Finish Python libraries installation from requirements.txt"
echo "[INFO] Start installing masai and vfeed in development"
pip install -e $MASAI_SRC_DIR
pip install -e $VFEED_SRC_DIR
echo "[INFO] Finish masai and vfeed installation"
echo "[INFO] Start installing pwntools"
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org --upgrade git+https://github.com/arthaud/python3-pwntools.git
echo "[INFO] Finish pwntools installation"

# Fix Bluetooth service
cat $BLUETOOTH_SERVICE_PATH | grep 'ExecStart=/usr/lib/bluetooth/bluetoothd -C'
if ! [ $? -eq 0 ]; then
	# Not fixed yet, fix it
	echo "[INFO] Fix Bluetooth service by changing /lib/systemd/system/bluetooth.service"
	cp $BLUETOOTH_SERVICE_PATH /lib/systemd/system/bluetooth.service.tmp
	sed 's/\/bluetoothd/\/bluetoothd -C/g' /lib/systemd/system/bluetooth.service.tmp > $BLUETOOTH_SERVICE_PATH
	cat $BLUETOOTH_SERVICE_PATH
	rm /lib/systemd/system/bluetooth.service.tmp

else
	echo "[INFO] $BLUETOOTH_SERVICE_PATH
 has been already modified"
fi

echo "[INFO] adding Serial Port Profile to BLUEZ"
sdptool add SP

echo "[INFO] Restarting bluetooth service"
systemctl daemon-reload
systemctl restart bluetooth

# Generate QR Code
echo "[INFO] Generate QR Code"
python qrcode_generator.py
echo "[INFO] Finish QR Code generation"
echo "[FINISH] Finish Setup MASai Box. You can start masai box by connecting the monitorable external Wi-Fi adapter and running the following command: ./run.sh"