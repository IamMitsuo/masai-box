#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

from masai.tools.dependency import Dependency

class Ifconfig(Dependency):
    dependency_required = True
    dependency_name = 'ifconfig'
    dependency_url = 'apt-get install net-tools'

    @classmethod
    def up(cls, interface, args=[]):
        '''Put interface up'''
        from masai.utils.process import Process

        command = ['ifconfig', interface]
        if type(args) is list:
            command.extend(args)
        elif type(args) is 'str':
            command.append(args)
        command.append('up')

        pid = Process(command)
        pid.wait()
        if pid.poll() != 0:
            raise Exception('Error putting interface %s up:\n%s\n%s' % (interface, pid.stdout(), pid.stderr()))


    @classmethod
    def down(cls, interface):
        '''Put interface down'''
        from masai.utils.process import Process

        pid = Process(['ifconfig', interface, 'down'])
        pid.wait()
        if pid.poll() != 0:
            raise Exception('Error putting interface %s down:\n%s\n%s' % (interface, pid.stdout(), pid.stderr()))


    @classmethod
    def get_mac(cls, interface):
        from masai.utils.process import Process

        output = Process(['ifconfig', interface]).stdout()

        # Mac address separated by dashes
        mac_dash_regex = ('[a-zA-Z0-9]{2}-' * 6)[:-1]
        match = re.search(' ({})'.format(mac_dash_regex), output)
        if match:
            return match.group(1).replace('-', ':')

        # Mac address separated by colons
        mac_colon_regex = ('[a-zA-Z0-9]{2}:' * 6)[:-1]
        match = re.search(' ({})'.format(mac_colon_regex), output)
        if match:
            return match.group(1)

        raise Exception('Could not find the mac address for %s' % interface)

    @classmethod
    def get_ip_address_and_netmask(cls, interface):
        from masai.utils.process import Process
        command = 'ifconfig %s | grep netmask' % interface
        (stdout, _) = Process.call(command)
        lines = stdout.splitlines()
        for line in lines:
            ifcon_regex = re.compile(r'\s+inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+netmask\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*')
            match = ifcon_regex.match(line)
            if match:
                ipv4 = match.group(1)
                netmask = match.group(2)
                return (ipv4, netmask)
        return None