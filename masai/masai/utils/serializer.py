#!/usr/bin/env python
# -*- coding: utf-8 -*-

from json import JSONEncoder

class ComplexEncoder(JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'reprJSON'):
            return obj.reprJSON()
        else:
            return JSONEncoder.default(self, obj)