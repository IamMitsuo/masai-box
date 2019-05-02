#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from masai.utils.process import Process
from masai.config import Configuration
from masai.model.portattackresult import PortAttackResult

class Hydra(object):
    available_services = ['adam6500', 'asterisk', 'afp',
                            'cisco', 'cisco-enable', 'cvs',
                            'firebird', 'ftp', 'ftps',
                            'icq', 'imap', 'imaps',
                            'irc', 'ldap2', 'ldap2s',
                            'mssql', 'mysql', 'ncp',
                            'nntp', 'oracle-listener', 'oracle-sid',
                            'pcanywhere', 'pcnfs', 'pop3', 'pop3s', 
                            'postgres', 'rdp', 'rexec', 
                            'rlogin', 'rsh', 's7-300',
                            'sip', 'smb', 'smtp', 'smtps',
                            'smtp-enum', 'snmp', 'socks5', 
                            'ssh', 'sshkey', 'svn', 
                            'teamspeak', 'telnet', 'telnets', 'vmauthd',
                            'vnc', 'xmpp']
    
    non_required_username_services = ['adam5900', 'cisco', 'oracle-listener',
                                        's7-300', 'snmp', 'vnc']

    @staticmethod
    def crack_password(host, target_service):
        result = PortAttackResult()
        for service_name in Hydra.available_services:
            if service_name in target_service:
                command = ['hydra',
                            '-I',
                            '-t',
                            '4',
                            '-f',
                            '-P',
                            '%s' % Configuration.passlist]
                if service_name not in Hydra.non_required_username_services:
                    command.extend(['-L', '%s' % Configuration.userlist])
                # Find port of target_service
                for service in host.services:
                    if service_name in service.name:
                        port = service.port
                        target = '%s://%s:%d' % (service_name, host.ipv4, int(port))
                        command.extend(['%s' % target])
                        try:
                            process = Process(command)
                            stdout, stderr = process.get_output()
                            print('stdout: %s' % stdout)
                            print('stderr: %s' % stderr)
                            found_str_pattern = '[%d][%s]' % (int(port), service_name)
                            if stdout:
                                for line in stdout.splitlines():
                                    if found_str_pattern in line:
                                        str_list = line.split()
                                        password = None
                                        login = None
                                        for index, item in enumerate(str_list):
                                            if 'login:' in item:
                                                login = str_list[index + 1]
                                            if 'password:' in item:
                                                password = str_list[index + 1]
                                        result.set_result(host=host, service=service, attack_result='success', username=login, password=password)
                                        return result
                            result.set_result(host=host, service=service, attack_result='failure')
                            return result
                        except KeyboardInterrupt:
                            process.interrupt(wait_time=0.0)
                            print('hydra was interrupted!')