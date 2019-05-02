#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import re
from masai.tools.nmap import NmapScanner
from masai.model.device import Host, Service
from masai.model.portassessmentresult import PortAssessmentResult
from vfeed.lib.core.search import Search
from vfeed.lib.core.methods import CveInfo, CveRisk
from masai.utils.serializer import ComplexEncoder

class PortAssessment(object):
    insecure_network_services = ['iiop', 'rpki-rts', 'http', 'ddm-rdb', 'smtp', 'nntp', 'ldap',
                                    'ieee-mms', 'ftp', 'telnet', 'imap', 'irc', 'pop3', 'msft-gc',
                                    'tftp', 'xtrm', 'seclayer-tcp', 'asap-tcp', 'sdo', 'ipfix',
                                    'opcua', 'sip', 'llrp', 'xmpp-client', 'stun-behavior', 'amqp', 'wsman',
                                    'tl1-raw', 'netconf-ssh', 'syslog', 'odette-ftp', 'mqtt']
    
    secure_network_services = ['ssh', 'nsiiops', 'rpki-rtr-tls', 'https', 'ddm-ssl', 'smtps', 'nntps',
                                    'sshell', 'ldaps', 'ieee-mms-ssl', 'ftps', 'telnets', 'imaps', 'ircs', 'pop3s',
                                    'msft-gc-ssl', 'xtrms', 'seclayer-tls', 'tftps', 'asap-tcp-tls', 'sdo-tls', 'ipfixs',
                                    'opcua-tls', 'sip-tls', 'encrypted-llrp', 'hpvirtgrp', 'stun-bahviors', 'amqps',
                                    'wsmans', 'tl1-raw-ssl', 'netconf-tls', 'syslog-tls', 'odette-ftps', 'secure-mqtt']

    def __init__(self, host:Host=None):
        self.target_host = host
        self.insecure_services = []
        self.secure_services = []
    
    def run(self):
        result = NmapScanner.scan(ip_adress=self.target_host.ipv4, args=['-sV', '-O'])
        hosts = result.payload['hosts']
        cpe_application_regex = re.compile(r'(cpe:\/[a](?::(?:[a-zA-Z0-9!"#$%&\'()*+,\\\-_.\/;<=>?@\[\]^`{|}~]|\\:)+){1,10})(\s.*)*$')
        cpe_operating_system_regex = re.compile(r'(cpe:\/[o](?::(?:[a-zA-Z0-9!"#$%&\'()*+,\\\-_.\/;<=>?@\[\]^`{|}~]|\\:)+){1,10})(\s.*)*$')
        cpe_hardware_regex = re.compile(r'(cpe:\/[h](?::(?:[a-zA-Z0-9!"#$%&\'()*+,\\\-_.\/;<=>?@\[\]^`{|}~]|\\:)+){1,10})(\s.*)*$')
        for host in hosts:
            self.target_host = host
            self.target_services = self.target_host.get_services()
            for target_service in self.target_services:
                for cpe in target_service.cpe:
                    matches = cpe_application_regex.match(cpe)
                    if matches:
                        cpe = matches.group(1)
                        print(cpe, 'application')
                        cves = PortAssessment.find_cve_and_severity(keyword=cpe, search_type='cpe')
                        for cve in cves:
                            target_service.add_cve(cve_id=cve[0], cve_desc=cve[1], cve_severity=cve[2])
                    elif cpe_operating_system_regex.match(cpe):
                        print(cpe, 'operating system')
                    elif cpe_hardware_regex.match(cpe):
                        print(cpe, 'hardware')
                if hasattr(target_service, 'name') and target_service.name is not None:
                    insecure_service = PortAssessment.find_insecure_services(target_service.name)
                    secure_service = PortAssessment.find_secure_services(target_service.name)
                    if insecure_service is not None:
                        self.insecure_services.append(insecure_service)
                    if secure_service is not None:
                        self.secure_services.append(secure_service)
        result = PortAssessmentResult()
        result.set_result(self.target_host, self.insecure_services, self.secure_services)
        return result

    @staticmethod
    def find_cve_and_severity(keyword=None, search_type=None):
        cves = []
        search_result = None
        if search_type == 'cpe':
            search_result = Search(keyword).cpe()
        elif search_type == 'text':
            search_result = Search(keyword).text()
        search_result = json.loads(search_result)
        if search_result:
            for result in search_result:
                for key in result.keys():
                    info = result[key]
                    if 'vulnerability' in info:
                        vulnerabilities = info['vulnerability']
                        for vulnerability in vulnerabilities:
                            cve_info = CveInfo(vulnerability).get_cve()
                            cve_info = json.loads(cve_info)
                            cve_info = cve_info[0]
                            cve_id = cve_info['id']
                            cve_desc = cve_info['summary']
                            severity = CveRisk(cve_id).get_severity()
                            severity = json.loads(severity)
                            severity = severity[0]
                            cves.append((cve_id, cve_desc, severity))
        return cves
    
    @staticmethod
    def find_insecure_services(name):
        for service_name in PortAssessment.insecure_network_services:
            if service_name == name:
                return service_name
        return None
    
    @staticmethod
    def find_secure_services(name):
        for service_name in PortAssessment.secure_network_services:
            if service_name == name:
                return service_name
        return None
        
if __name__ == "__main__":
    PortAssessment().run()