#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import time
from masai.tools.airmon import Airmon
from masai.utils.process import Process
from masai.model.router import Router
from masai.model.wificonnectionresult import WifiScanResult, WifiConnectResult, WifiDisconnectResult

class Connection(object):
    '''
        Connection class is the class that will keep information of the wifi connection in nmcli
        NAME            UUID            TYPE            DEVICE
    '''
    def __init__(self, essid=None, uuid=None, con_type=None, device=None):
        self.essid = essid
        self.uuid = uuid
        self.connection_type = con_type
        self.device = device

    def __str__(self):
        return 'SSID: ' + self.essid + ', uuid: ' + self.uuid + ', type: ' + self.connection_type + ', device: ' + self.device

class WifiConnectionManager(object):
    '''
        WifiConnectionManager is a tool class which will manage the connection, specifically WiFi.
        This class utilzes 'nmcli' tool in order to scan, connect and disconnect wifi in the area.
    '''
    
    def __init__(self, ifacename=None):
        self.ifacename = ifacename
        if ifacename is None:
            interfaces = Airmon.get_interfaces()
            for interface in interfaces:
                if interface.driver == 'brcmfmac':
                    self.ifacename = interface.interface
                    break
        self.connection = None
    
    def get_current_connection(self):
        return self.connection
    
    def scan_wifi(self, ifacename=None):
        '''
            Parameter
                String - ifacename: the interface name e.g. wlan0 to scan list of wifi
            Returns
                dict: a dict object
                    {
                        "count": int (number of routers found)
                        "0 -> count - 1": {router}
                    }
        '''
        if ifacename is None:
            ifacename = self.ifacename

        # command = 'nmcli -w 10 -m multiline -f name,ssid,bssid,mode,chan,signal,security dev wifi list ifname %s' % ifacename
        command = ['nmcli',
                        '-w',
                        '10',
                        '-m',
                        'multiline',
                        '-f',
                        'name,ssid,bssid,mode,chan,signal,security',
                        'dev',
                        'wifi',
                        'list',
                        'ifname',
                        '%s' % ifacename]
        try:
            process = Process(command)
            stdout, _ = process.get_output()
            result = WifiScanResult()
            result.set_result(stdout)
            return result
        except KeyboardInterrupt:
            process.interrupt(wait_time=0.0)
            print('Scan wifi was interrupted!')
        # router_dict = json.dumps(router_dict)
        # return json.loads(router_dict)


    def disconnect_wifi(self, ifacename=None):
        '''
            Parameters
                String - ifacename: the interface name e.g. wlan0 to be disconnected
            Returns
                True: if disconnect successfully
                False: otherwise or no connection before

            Procedures
                nmcli calls device disconnect
                nmcli calls connection delete
                Therefore, there is no saved connection for simplicity of this project
        '''
        if ifacename is None:
            ifacename = self.ifacename

        ssid = WifiConnectionManager.find_connection(ifacename)
        stdout, stderr = WifiConnectionManager.delete_connection(ssid)
        result = WifiDisconnectResult()
        if stdout:
            print(stdout)
            self.connection = None
            result.set_result('success')
        if stderr:
            print(stderr)
            result.set_result('failure')

        result.set_result('failure')
        return result

    def connect_wifi(self, target_router, password=None, ifacename=None):
        '''
            Parameters
                Router - target_router: the router object to be connected
                String - password: a password for the wifi
                String - ifacename: an interface name to connect (default uses brcmfmac)
            Returns
                True - if connection was successful
                False - otherwise
            Procedures
                If there is any connection before, terminate old connection and connect new connection
        '''

        if ifacename is None:
            ifacename = self.ifacename
        
        self.disconnect_wifi()
        time.sleep(3)

        ssid = target_router.bssid
        if target_router.essid is not None:
            ssid = target_router.essid
        # command = 'nmcli -w 10 dev wifi connect "%s" ' % ssid
        command = ['nmcli',
                        '-w',
                        '10',
                        'dev',
                        'wifi',
                        'connect',
                        '%s' % ssid]
        if password is not None:
            # command += 'password "%s" ' % password
            command.extend(['password', '%s' % password])
        if target_router.encryption == 'WEP':
            # command += 'wep-key-type key '
            command.extend(['wep-key-type', 'key'])
        
        # command += 'ifname %s' % ifacename
        command.extend(['ifname', '%s' % ifacename])
        try:
            process = Process(command)
            # (stdout, stderr) = Process.call(command)
            stdout, stderr = process.get_output()
            # print(stdout, stderr)
            result = WifiConnectResult()
            if stdout != '' and stdout is not None:
                lines = stdout.splitlines()
                regex_format = re.compile(r'Device\s+\'(.+?)\'\s+successfully activated with \'(.+?)\'\.')
                for line in lines:
                    matches = regex_format.match(line)
                    if matches:
                        self.connection = Connection(ssid, matches.group(2), 'wifi', matches.group(1))
                        result.set_result('success')
                        print('Connect to %s successfully' % ssid)
                        print('Connection info: %s' % self.connection)
                        return result
            if stderr != '' and stderr is not None:
                regex_format = re.compile(r'Error: Timeout 10 sec expired.')
                lines = stderr.splitlines()
                for line in lines:
                    matches = regex_format.match(line)
                    if matches:
                        WifiConnectionManager.delete_connection(ssid)
                        break
                print('Connection is failed, password is wrong or not given')
                result.set_result('failure')
                return result
            result.set_result('failure')
            return result
        except KeyboardInterrupt:
            process.interrupt(wait_time=0.0)
            print('Connect Wifi was interrupted!')
        # result = WifiConnectResult()
        # self.connecttion= result.set_result(stdout, stderr, ssid)
        # return result

    @staticmethod
    def delete_connection(ssid):
        command = 'nmcli -w 10 c delete "%s"' % ssid
        (stdout, stderr) = Process.call(command)
        return stdout, stderr
    
    @staticmethod
    def find_connection(ifname):
        command = 'nmcli d'
        stdout, _ = Process.call(command)
        regex = re.compile(r'^(.+?)\s+wifi\s+connected\s+(.+?)\s+$')
        for line in stdout.splitlines():
            matches = regex.match(line)
            if matches:
                if matches.group(1) == ifname:
                    return matches.group(2)
        return None

if __name__ == "__main__":
    fields = '3E:F8:62:39:EF:68,2015-05-27 19:28:44,2015-05-27 19:28:46,1,54,WPA2,CCMP TKIP,PSK,-58,2,0,0.0.0.0,9,whoa,'.split(',')
    router = Router(fields)
    # password = input('Please input password for "whoa": ')
    wifi_connection_manager = WifiConnectionManager()
    print(wifi_connection_manager.scan_wifi())
    # print(wifi_connection_manager.connect_wifi(router, password=password))
    # print(wifi_connection_manager.disconnect_wifi())
    