#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.tools.dependency import Dependency
from masai.tools.ifconfig import Ifconfig

class Macchanger(Dependency):
    dependency_required = False
    dependency_name = 'macchanger'
    dependency_url = 'apt-get install macchanger'

    is_changed = False

    @classmethod
    def down_macch_up(cls, iface, options):
        '''Put interface down, run macchanger with options, put interface up'''
        from masai.utils.process import Process

        Ifconfig.down(iface)

        command = ['macchanger']
        command.extend(options)
        command.append(iface)
        macch = Process(command)
        macch.wait()
        if macch.poll() != 0:
            return False

        Ifconfig.up(iface)

        return True


    @classmethod
    def get_interface(cls):
        # Helper method to get interface from configuration
        from masai.config import Configuration
        return Configuration.interface


    @classmethod
    def reset(cls):
        iface = cls.get_interface()
        # -p to reset to permanent MAC address
        if cls.down_macch_up(iface, ['-p']):
            new_mac = Ifconfig.get_mac(iface)


    @classmethod
    def random(cls):
        from masai.utils.process import Process
        if not Process.exists('macchanger'):
            return

        iface = cls.get_interface()

        # -r to use random MAC address
        # -e to keep vendor bytes the same
        if cls.down_macch_up(iface, ['-e']):
            cls.is_changed = True
            new_mac = Ifconfig.get_mac(iface)


    @classmethod
    def reset_if_changed(cls):
        if cls.is_changed:
            cls.reset()