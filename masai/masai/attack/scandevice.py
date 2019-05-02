#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.tools.nmap import NmapScanner
from masai.tools.ifconfig import Ifconfig
from masai.tools.networkmanager import WifiConnectionManager

class ScanDevice(object):

    def __init__(self, wifi_connection_manager:WifiConnectionManager):
        self.wifi_connection_manager = wifi_connection_manager
    
    def run(self):
        address = Ifconfig.get_ip_address_and_netmask(self.wifi_connection_manager.ifacename)
        if address:
            return NmapScanner.scan_service_and_os(ip_address=address[0], subnetmask=address[1])
        return None