#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import socket
import pyqrcode
import bluetooth

def generate_qr():
    info = {}
    info['name'] = socket.gethostname()
    info['address'] = bluetooth.read_local_bdaddr()
    info['uuid'] = "94f39d29-7d6d-437d-973b-fba39e49d4ee"
    info_str = json.dumps(info, indent=4)
    url = pyqrcode.create(info_str)
    url.png('')