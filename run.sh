#!/bin/bash

hciconfig hci0 piscan
. venv/bin/activate && python main.py
