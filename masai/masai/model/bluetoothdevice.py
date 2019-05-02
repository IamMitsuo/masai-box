#!/usr/bin/env python
# -*- coding: utf-8 -*-


class BluetoothDevice(object):

    def __init__(self, mac, name, device_cls, device_type):
        self.mac = mac
        self.name = name
        self.device_cls = device_cls
        self.device_type = device_type

    def to_json_str(self):
        from json import dumps
        return dumps(self.reprJSON())

    def reprJSON(self):
        json_dict = {}
        json_dict['mac'] = self.mac
        json_dict['name'] = self.name
        json_dict['class'] = self.device_cls
        json_dict['type'] = self.device_type
        return json_dict

    @staticmethod
    def get_bluetooth_device_from_json(json_dict):
        mac = json_dict['mac']
        name = None
        if 'name' in json_dict:
            name = json_dict['name']
        device_cls = json_dict['class']
        device_type = json_dict['type']
        return BluetoothDevice(mac,
                               name,
                               device_cls,
                               device_type)
