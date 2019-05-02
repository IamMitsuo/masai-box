#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys

class Dependency(object):
    required_attr_names = ['dependency_name', 'dependency_url', 'dependency_required']

    # https://stackoverflow.com/a/49024227
    def __init_subclass__(cls):
        for attr_name in cls.required_attr_names:
            if not attr_name in cls.__dict__:
                raise NotImplementedError(
                    'Attribute "{}" has not been overridden in class "{}"' \
                    .format(attr_name, cls.__name__)
                )


    @classmethod
    def exists(cls):
        from masai.utils.process import Process
        return Process.exists(cls.dependency_name)


    @classmethod
    def run_dependency_check(cls):
        from masai.tools.airmon import Airmon
        #from aircrack import Aircrack
        #from aireplay import Aireplay
        from masai.tools.ifconfig import Ifconfig
        from masai.tools.iwconfig import Iwconfig
        # from .bully import Bully
        # from .reaver import Reaver
        # from .wash import Wash
        # from .pyrit import Pyrit
        # from .tshark import Tshark
        # from .macchanger import Macchanger
        # from .hashcat import Hashcat, HcxDumpTool, HcxPcapTool

        # apps = [
        #         # Aircrack
        #         Aircrack, #Airodump, Airmon, Aireplay,
        #         # wireless/net tools
        #         Iwconfig, Ifconfig
        #         # WPS
        #         # Reaver, Bully,
        #         # Cracking/handshakes
        #         # Pyrit, Tshark,
        #         # Hashcat
        #         # Hashcat, HcxDumpTool, HcxPcapTool,
        #         # Misc
        #         # Macchanger
        #     ]
        apps = [Ifconfig, Iwconfig, Airmon]
        missing_required = any([app.fails_dependency_check() for app in apps])

        if missing_required:
            # Color.pl('{!} {O}At least 1 Required app is missing. Wifite needs Required apps to run{W}')
            sys.stdout.write('At least 1 Required app is missing')
            sys.exit(-1)


    @classmethod
    def fails_dependency_check(cls):
        from masai.utils.process import Process

        if Process.exists(cls.dependency_name):
            return False

        if cls.dependency_required:
            sys.stdout.write('Error: Required app {0} was not found' % cls.dependency_name)
            return True

        else:
            sys.stdout.write('Warning: Recommended app {0} was not found' % cls.dependency_name)
            return False