#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.model.result import Result

class CrackResult(Result):

    def __init__(self):
        super(CrackResult, self).__init__(result_type='wifiCracking')

    def to_json_str(self):
        from json import dumps
        return dumps(self.result)
    
    def set_result(self, attack_type, crack_result):
        self.payload['attackType'] = attack_type
        self.payload['crackResult'] = crack_result
        self.result['payload'] = self.payload