#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.model.result import Result

class NmapScanResult(Result):

    def __init__(self):
        super(NmapScanResult, self).__init__(result_type='nmapScan')

    def to_json_str(self):
        from json import dumps
        from masai.utils.serializer import ComplexEncoder
        return dumps(self.result, cls=ComplexEncoder)
    
    def set_result(self, time_stats, host_stats, hosts):
        self.payload['timeStats'] = time_stats
        self.payload['hostStats'] = host_stats
        self.payload['hosts'] = hosts
        self.result['payload'] = self.payload