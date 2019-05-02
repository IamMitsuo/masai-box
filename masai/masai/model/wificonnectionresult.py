#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.model.result import Result
import re

class WifiScanResult(Result):
    
    def __init__(self):
        super(WifiScanResult, self).__init__(result_type='wifiScan')
    
    def set_result(self, stdout):
        self.payload = {}
        router_info = {}
        routers = []
        line_count = 0
        router_count = 0
        regex_format = re.compile(r'(.*):\s+(.*)')
        for line in stdout.splitlines():
            line_count += 1
            if line_count < 8:
                matches = regex_format.match(line)
                if matches:
                    router_info[matches.group(1)] = matches.group(2)
            if line_count == 7:
                routers.append(router_info)
                router_info = {}
                line_count = 0
                router_count += 1
        self.payload['routers'] = routers
        self.payload["count"] = router_count
        self.result['payload'] = self.payload
        
    def to_json_str(self):
        from json import dumps
        return dumps(self.result)

class WifiConnectResult(Result):
    def __init__(self):
        super(WifiConnectResult, self).__init__(result_type='wifiConnect')
    
    def set_result(self, status):
        # if stdout != '':
        #     lines = stdout.splitlines()
        #     regex_format = re.compile(r'Device\s+\'(.+?)\'\s+successfully activated with \'(.+?)\'\.')
        #     for line in lines:
        #         matches = regex_format.match(line)
        #         if matches:
        #             connection = Connection(ssid, matches.group(2), 'wifi', matches.group(1))
        #             self.payload['status'] = 'success'
        #             self.payload['info'] = 'connect'
        #             self.result['payload'] = self.payload
        #             print('Connect to %s successfully' % ssid)
        #             print('Connection info: %s' % connection)
        #             return connection
        # if stderr != '':
        #     regex_format = re.compile(r'Error: Timeout 10 sec expired.')
        #     lines = stderr.splitlines()
        #     for line in lines:
        #         matches = regex_format.match(line)
        #         if matches:
        #             WifiConnectionManager.delete_connection(ssid)
        #             break
        #     print('Connection is failed, password is wrong or not given')
        #     self.payload['status'] = 'failure'
        #     self.payload['info'] = 'connect'
        #     self.result['payload'] = self.payload
        #     return None
        # return None
        self.payload['status'] = status
        self.payload['info'] = 'connect'
        self.result['payload'] = self.payload
    
    def to_json_str(self):
        from json import dumps
        return dumps(self.result)

class WifiDisconnectResult(Result):
    def __init__(self):
        super(WifiDisconnectResult, self).__init__(result_type='wifiDisconnect')
    
    def set_result(self, status):
        # if stdout != '':
        #     print(stdout)
        #     regex_format = re.compile(r'Device\s+\'.+?\'\s+successfully\s+disconnected\.')
        #     for line in stdout.splitlines():
        #         matches = regex_format.match(line)
        #         if matches and connection is not None:
        #             WifiConnectionManager.delete_connection(connection.essid)
        #             self.payload['status'] = 'success'
        #             self.payload['info'] = 'disconnect'
        #             self.result['payload'] = self.payload
        #             return None
        #     # return True
        # if stderr != '':
        #     print(stderr)
        #     self.payload['status'] = 'failure'
        #     self.payload['info'] = 'disconnect'
        #     self.result['payload'] = self.payload
        #     return None
        self.payload['status'] = status
        self.payload['info'] = 'disconnect'
        self.result['payload'] = self.payload

    def to_json_str(self):
        from json import dumps
        return dumps(self.result)

if __name__ == "__main__":
    from masai.utils.process import Process
    command = 'nmcli -w 10 -m multiline -f name,ssid,bssid,mode,chan,signal,security dev wifi list ifname wlan0'
    stdout, _ = Process.call(command)
    wifi_scan_result = WifiScanResult()
    wifi_scan_result.set_result(stdout)
    print(wifi_scan_result.to_json_str())