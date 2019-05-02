#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.model.result import Result

class PortAttackResult(Result):

    def __init__(self):
        super(PortAttackResult, self).__init__(result_type='portAttack')

    def to_json_str(self):
        from json import dumps
        from masai.utils.serializer import ComplexEncoder
        return dumps(self.result, cls=ComplexEncoder)
    
    def set_result(self, host, service, attack_result, username=None, password=None):
        self.payload['host'] = host
        self.payload['service'] = service
        self.payload['attackResult'] = attack_result
        self.payload['username'] = username
        self.payload['password'] = password
        self.result['payload'] = self.payload