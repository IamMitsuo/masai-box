#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import xmltodict
import json
from masai.utils.process import Process
from masai.tools.dependency import Dependency
from masai.model.device import Host, Service
from masai.model.nmapscanresult import NmapScanResult

class NmapScanner(Dependency):
    dependency_required = True
    dependency_name = 'nmap'
    dependency_url = 'apt-get install nmap'

    @staticmethod
    def scan(ip_adress=None, subnetmask=None, args=None):
        '''
            This static method is for nmap scan
            subnetmask can be either String '255.255.255.255' or decimal 24
        '''

        subnetmask_regex = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        if type(subnetmask) is str and subnetmask_regex.match(subnetmask):
            # TODO: Convert dot decimal to cidr
            subnetmask = sum([bin(int(x)).count("1") for x in subnetmask.split(".")])
        
        if type(subnetmask) is str:
            subnetmask = int(subnetmask)
        
        if subnetmask is not None:
            hosts = '%s/%d' % (ip_adress, subnetmask)
        else:
            hosts = '%s' % ip_adress

        command = ['nmap']
        if args is not None:
            command.extend(args)
        else:
            command.extend(['-sn'])
        command.extend(['-T4', '-oX', '-', '%s' % hosts])
        print(command)
        try:
            process = Process(command)
            stdout, _ = process.get_output()
            if stdout:
                print(stdout)
                nmap_result_dict = xmltodict.parse(stdout)
                return NmapScanner.parse_dict_to_nmap_result(nmap_result_dict)
            else:
                return None
        except KeyboardInterrupt:
            process.interrupt(wait_time=0.0)
            print('nmap scan was interrupted!')
    
    @staticmethod
    def scan_service_and_os(ip_address=None, subnetmask=None):
        return NmapScanner.scan(ip_address, subnetmask, args=['-O'])
    
    @staticmethod
    def parse_dict_to_nmap_result(data=None):
        result = NmapScanResult()
        nmaprun = data['nmaprun']
        start_datetime = nmaprun['@startstr']
        runstats = nmaprun['runstats']
        finish_datetime = runstats['finished']['@timestr']
        elapsed = runstats['finished']['@elapsed']
        hosts_up = runstats['hosts']['@up']
        hosts_down = runstats['hosts']['@down']
        hosts_total = runstats['hosts']['@total']
        _time_stats = {'startTime': start_datetime, \
                                'finishTime': finish_datetime, \
                                'elapsed': elapsed}
        _host_stats = {'up': hosts_up, \
                                'down': hosts_down, \
                                'total': hosts_total}
        _hosts = []
        if 'host' in nmaprun:
            hosts = nmaprun['host']
            host_list = []
            if type(hosts) is list:
                host_list = hosts
            else:
                host_list.append(hosts)
            for h in host_list:
                _hosts.append(NmapScanner._parse_host(h))
            
        result.set_result(time_stats=_time_stats, 
                            host_stats=_host_stats,
                            hosts=_hosts)
        return result
    
    @staticmethod
    def _parse_host(host):
        _host = {}
        _status = host['status']['@state']
        addresses = host['address']
        address_list = []
        if type(addresses) is not list:
            address_list.append(addresses)
        else:
            address_list = addresses
        _address = object()
        _address = lambda: None
        for address in address_list:
            setattr(_address, address['@addrtype'], address['@addr'])

        _device_type = None
        _os_name = None
        _os_vendor = None
        _os_cpe = None

        if 'os' in host:
            if host['os'] is not None:
                if 'osmatch' in host['os']:
                    osmatch_list = []
                    if type(host['os']['osmatch']) is list:
                        osmatch_list = host['os']['osmatch']
                    else:
                        osmatch_list.append(host['os']['osmatch'])
                    best_accuracy = 0
                    for osmatch in osmatch_list:
                        if int(osmatch['@accuracy']) > best_accuracy:
                            best_accuracy = int(osmatch['@accuracy'])
                            _os_name = osmatch['@name']
                            _os_cpe = []
                            if '@type' in osmatch['osclass']:
                                _device_type = osmatch['osclass']['@type']
                            if '@vendor' in osmatch['osclass']:
                                _os_vendor = osmatch['osclass']['@vendor']
                            if 'cpe' in osmatch['osclass']:
                                if type(osmatch['osclass']['cpe']) is list:
                                    _os_cpe = osmatch['osclass']['cpe']
                                else:
                                    _os_cpe.append(osmatch['osclass']['cpe'])
        
        __host = Host(status=_status,
                        addresses=_address, 
                        device_type=_device_type, 
                        os_name=_os_name,
                        os_vendor=_os_vendor,
                        os_cpe=_os_cpe)
        
        if 'port' in host['ports']:
            ports = host['ports']['port']
            _services = NmapScanner._parse_services(ports)
            __host.set_services(_services)
        return __host
    
    @staticmethod
    def _parse_services(ports):
        port_list = []
        if type(ports) is not list:
            port_list.append(ports)
        else:
            port_list = ports
        
        services = []
        for port in port_list:
            service = {}
            _port = port['@portid']
            _protocol = port['@protocol']
            _state = port['state']['@state']
            _name = port['service']['@name']
            _product = None
            _version = None
            _cpe = []
            if '@product' in port['service']:
                _product = port['service']['@product']
            if '@version' in port['service']:
                _version = port['service']['@version']
            if 'cpe' in port['service']:
                if type(port['service']['cpe']) is list:
                    _cpe = port['service']['cpe']
                else:
                    _cpe.append(port['service']['cpe'])
            service = Service(port=_port, 
                                protocol=_protocol, 
                                state=_state, 
                                name=_name, 
                                product=_product, 
                                version=_version, 
                                cpe=_cpe)
            services.append(service)
        
        return services

    @staticmethod
    def test():
        with open('nmap_output.xml', 'r') as f:
            json_dict = xmltodict.parse(f.read())
            result = NmapScanner.parse_dict_to_nmap_result(json_dict)
            with open('nmap_output.json', 'w') as fp:
                json.dump(json.loads(result.to_json_str()), fp, indent=4)
                fp.close()
            f.close()

if __name__ == "__main__":
    # result = NmapScanner.scan_service_and_os(ip_address='192.168.1.1')
    # print(result.to_json_str())
    NmapScanner.test()
