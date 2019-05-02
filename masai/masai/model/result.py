#!/usr/bin/env python
# -*- coding: utf-8 -*-

class Result(object):

    def __init__(self, result_type, activity_id=None):
        self.result = {'resultType': result_type}
        self.payload = {}
        self.activity_id = activity_id

    def to_json_str(self):
        raise NotImplementedError()
    
    def set_result(self):
        raise NotImplementedError()
    
