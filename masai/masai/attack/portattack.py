#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.tools.hydra import Hydra

class PortAttack(object):
    def __init__(self, host, target_service):
        self.target = host
        self.target_service = target_service
    
    def run(self):
        result = Hydra.crack_password(self.target, self.target_service)
        return result