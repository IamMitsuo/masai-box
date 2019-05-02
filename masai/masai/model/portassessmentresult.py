#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.model.result import Result

class PortAssessmentResult(Result):

    def __init__(self):
        super(PortAssessmentResult, self).__init__(result_type='portAssessment')

    def to_json_str(self):
        from json import dumps
        from masai.utils.serializer import ComplexEncoder
        return dumps(self.result, cls=ComplexEncoder)
    
    def set_result(self, host, insecure_services, secure_services):
        self.payload['host'] = host
        self.payload['insecureServices'] = insecure_services
        self.payload['secureServices'] = secure_services
        self.result['payload'] = self.payload