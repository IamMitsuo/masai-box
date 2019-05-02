#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.model.result import Result

class InterruptResult(Result):

    def __init__(self):
        super(InterruptResult, self).__init__(result_type='interruptResult')
        self.set_result()

    def to_json_str(self):
        from json import dumps
        return dumps(self.result)
    
    def set_result(self, status='terminate'):
        self.payload['status'] = status
        self.result['payload'] = self.payload