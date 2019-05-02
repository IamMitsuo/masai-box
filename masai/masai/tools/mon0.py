#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.tools.ifconfig import Ifconfig
from masai.tools.iwconfig import Iwconfig
from masai.utils.process import Process

class Mon0(object):
    '''
        Wrapper around mon0up and mon0down program in Re4son/Kali-pi
        Note that the kernel does not support airmon-ng, but it comes along with mon0up and mon0down instead
        References: https://whitedome.com.au/re4son/topic/sticky-fingers-kali-pi-2/#post-13278
    '''

    @staticmethod
    def start():
        '''
            Starts an interface phy0 in monitor mode using mon0up
            Returns:
                Name of the interface put into monitor mode
        '''
        mon0_output = Process(['mon0up']).stdout()
        
    @staticmethod
    def get_mon0_interface():
        '''
            Check if mon0 is up or not
            Returns:
                'mon0' if mon0 is found
                None otherwise
        '''
        monitor_interfaces = Iwconfig.get_interfaces(mode='Monitor')
        if len(monitor_interfaces) >= 1:
            for interface in monitor_interfaces:
                if interface == 'mon0': return interface
        return None

    @staticmethod
    def stop():
        '''
            Stops an interface mon0
        '''
        mon0_output = Process(['mon0down']).stdout()

if __name__ == "__main__":
    Mon0.start()
    print(Mon0.get_mon0_interface())
    Mon0.stop()