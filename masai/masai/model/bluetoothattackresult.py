#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.model.result import Result

class BluetoothAttackResult(Result):

    def __init__(self):
        super(BluetoothAttackResult, self).__init__(result_type='bluetoothAttack')

    def to_json_str(self):
        from json import dumps
        from masai.utils.serializer import ComplexEncoder
        return dumps(self.result, cls=ComplexEncoder)
    
    def set_result(self, target_bluetooth_device, status):
        self.payload['bluetoothDevice'] = target_bluetooth_device
        self.payload['status'] = status
        self.result['payload'] = self.payload