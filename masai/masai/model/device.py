#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.utils.serializer import ComplexEncoder

class Host(object):

    def __init__(self, status, addresses, device_type=None, os_name=None, 
                    os_vendor=None, os_cpe=None, services=[]):
        self.status = status
        self.ipv4 = addresses.ipv4
        self.device_type = device_type
        self.os_name = os_name
        self.os_vendor = os_vendor
        self.os_cpe = os_cpe
        self.services = services
        if hasattr(addresses, 'mac'):
            self.mac = addresses.mac 
    
    def add_service(self, service):
        self.services.append(service)

    def set_services(self, services):
        self.services = services

    def get_services(self):
        return self.services

    def to_json_str(self):
        from json import dumps
        return dumps(self.reprJSON(), cls=ComplexEncoder)

    def reprJSON(self):
        json_dict = {'status': self.status,
                        'ipv4': self.ipv4,
                        'deviceType': self.device_type,
                        'osName': self.os_name,
                        'osVendor': self.os_vendor,
                        'osCpe': self.os_cpe,
                        'services': self.services}
        if hasattr(self, 'mac'):
            json_dict['mac'] = self.mac
        return json_dict

    @staticmethod
    def get_host_from_json(json_dict):
        status = json_dict['status']
        addresses = lambda: None
        setattr(addresses, 'ipv4', json_dict['ipv4'])
        ipv4 = json_dict['ipv4']
        if 'mac' in json_dict:
            mac = json_dict['mac']
            setattr(addresses, 'mac', mac)
        os_name = None
        device_type = None
        os_vendor = None
        os_cpe = None
        if 'osName' in json_dict:
            os_name = json_dict['osName']
        if 'deviceType' in json_dict:
            device_type = json_dict['deviceType']
        if 'osVendor' in json_dict:
            os_vendor = json_dict['osVendor']
        if 'osCpe' in json_dict:
            os_cpe = json_dict['osCpe']
        services = []
        for service in json_dict['services']:
            services.append(Service.get_service_from_json(service))
        
        return Host(status=status, 
                        addresses=addresses, 
                        device_type=device_type, 
                        os_name=os_name,
                        os_cpe=os_cpe,
                        os_vendor=os_vendor, 
                        services=services)

class Service(object):
    
    def __init__(self, port, protocol, state, name, product=None, version=None, cpe=None):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.name = name
        if product:
            self.product = product
        if version:
            self.version = version
        self.cpe = []
        if cpe:
            self.cpe = cpe
        self.cves = []
    
    def add_cve(self, cve_id, cve_desc, cve_severity):
        cve = {'id': cve_id, \
                'description': cve_desc, \
                'severity': cve_severity }
        self.cves.append(cve)

    def to_json_str(self):
        from json import dumps
        return dumps(self.reprJSON())
    
    def reprJSON(self):
        return self.__dict__

    @staticmethod
    def get_service_from_json(json_dict):
        port = json_dict['port']
        protocol = json_dict['protocol']
        state = json_dict['state']
        name = json_dict['name']
        product = None
        version = None
        cpe = None
        if 'product' in json_dict:
            product = json_dict['product']
        if 'version' in json_dict:
            version = json_dict['version']
        if 'cpe' in json_dict:
            cpe = json_dict['cpe']
        return Service(port=port, 
                        protocol=protocol, 
                        state=state, 
                        name=name, 
                        product=product, 
                        version=version, 
                        cpe=cpe)