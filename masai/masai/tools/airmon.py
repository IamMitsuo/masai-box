#!/usr/bin/env python
# -*- coding: utf-8 -*-

from masai.tools.dependency import Dependency
from masai.tools.ifconfig import Ifconfig
from masai.tools.iwconfig import Iwconfig
from masai.utils.process import Process
# from ..util.color import Color
# from ..util.input import raw_input
from masai.config import Configuration

import re
import os
import signal

class AirmonIface(object):
    def __init__(self, phy, interface, driver, chipset):
        self.phy = phy
        self.interface = interface
        self.driver = driver
        self.chipset = chipset

    # Max length of fields.
    # Used for printing a table of interfaces.
    INTERFACE_LEN = 12
    PHY_LEN = 6
    DRIVER_LEN = 20
    CHIPSET_LEN = 30

class Airmon(Dependency):
    ''' Wrapper around the 'airmon-ng' program '''
    dependency_required = True
    dependency_name = 'airmon-ng'
    dependency_url = 'https://www.aircrack-ng.org/install.html'

    base_interface = None
    killed_network_manager = False

    # Drivers that need to be manually put into monitor mode
    BAD_DRIVERS = ['rtl8821au', 'brcmfmac']
    #see if_arp.h
    ARPHRD_ETHER = 1 #managed
    ARPHRD_IEEE80211_RADIOTAP = 803 #monitor

    def __init__(self):
        self.refresh()

    def refresh(self):
        ''' Get airmon-recognized interfaces '''
        self.interfaces = Airmon.get_interfaces()

    def get(self, index):
        ''' Gets interface at index (starts at 1) '''
        if type(index) is str:
            index = int(index)
        return self.interfaces[index - 1]


    @staticmethod
    def get_interfaces():
        '''Returns List of AirmonIface objects known by airmon-ng'''
        interfaces = []
        p = Process('airmon-ng')
        for line in p.stdout().split('\n'):
            # [PHY ]IFACE DRIVER CHIPSET
            airmon_re = re.compile(r'^(?:([^\t]*)\t+)?([^\t]*)\t+([^\t]*)\t+([^\t]*)$')
            matches = airmon_re.match(line)
            if not matches:
                continue

            phy, interface, driver, chipset = matches.groups()
            if phy == 'PHY' or phy == 'Interface':
                continue  # Header

            if len(interface.strip()) == 0:
                continue

            interfaces.append(AirmonIface(phy, interface, driver, chipset))

        return interfaces

    @staticmethod
    def start_bad_driver(iface):
        '''
        Manually put interface into monitor mode (no airmon-ng or vif).
        Fix for bad drivers like the rtl8812AU.
        '''
        Ifconfig.down(iface)
        Iwconfig.mode(iface, 'monitor')
        Ifconfig.up(iface)

        # /sys/class/net/wlan0/type
        iface_type_path = os.path.join('/sys/class/net', iface, 'type')
        if os.path.exists(iface_type_path):
            with open(iface_type_path, 'r') as f:
                if (int(f.read()) == Airmon.ARPHRD_IEEE80211_RADIOTAP):
                    return iface

        return None

    @staticmethod
    def stop_bad_driver(iface):
        '''
        Manually put interface into managed mode (no airmon-ng or vif).
        Fix for bad drivers like the rtl8812AU.
        '''
        Ifconfig.down(iface)
        Iwconfig.mode(iface, 'managed')
        Ifconfig.up(iface)

        # /sys/class/net/wlan0/type
        iface_type_path = os.path.join('/sys/class/net', iface, 'type')
        if os.path.exists(iface_type_path):
            with open(iface_type_path, 'r') as f:
                if (int(f.read()) == Airmon.ARPHRD_ETHER):
                    return iface

        return None

    @staticmethod
    def start(iface):
        '''
            Starts an interface (iface) in monitor mode
            Args:
                iface - The interface to start in monitor mode
                        Either an instance of AirmonIface object,
                        or the name of the interface (string).
            Returns:
                Name of the interface put into monitor mode.
            Throws:
                Exception - If an interface can't be put into monitor mode
        '''
        # Get interface name from input
        if type(iface) == AirmonIface:
            iface_name = iface.interface
            driver = iface.driver
        else:
            iface_name = iface
            driver = None

        # Remember this as the 'base' interface.
        Airmon.base_interface = iface_name

        airmon_output = Process(['airmon-ng', 'start', iface_name]).stdout()
        
        enabled_iface = Airmon._parse_airmon_start(airmon_output)

        if enabled_iface is None and driver in Airmon.BAD_DRIVERS:
            enabled_iface = Airmon.start_bad_driver(iface_name)

        monitor_interfaces = Iwconfig.get_interfaces(mode='Monitor')

        # Assert that there is an interface in monitor mode
        if len(monitor_interfaces) == 0:
            raise Exception('Cannot find any interfaces in Mode:Monitor')

        # Assert that the interface enabled by airmon-ng is in monitor mode
        if enabled_iface not in monitor_interfaces:
            raise Exception('Cannot find %s with Mode:Monitor' % enabled_iface)

        # No errors found; the device 'enabled_iface' was put into Mode:Monitor.
        return enabled_iface

    @staticmethod
    def _parse_airmon_start(airmon_output):
        '''Find the interface put into monitor mode (if any)'''

        # airmon-ng output: (mac80211 monitor mode vif enabled for [phy10]wlan0 on [phy10]wlan0mon)
        enabled_re = re.compile(r'.*\(mac80211 monitor mode (?:vif )?enabled (?:for [^ ]+ )?on (?:\[\w+\])?(\w+)\)?.*')

        for line in airmon_output.split('\n'):
            matches = enabled_re.match(line)
            if matches:
                return matches.group(1)

        return None


    @staticmethod
    def stop(iface):
        airmon_output = Process(['airmon-ng', 'stop', iface]).stdout()

        (disabled_iface, enabled_iface) = Airmon._parse_airmon_stop(airmon_output)

        if not disabled_iface and iface in Airmon.BAD_DRIVERS:
            disabled_iface = Airmon.stop_bad_driver(iface)

        return (disabled_iface, enabled_iface)


    @staticmethod
    def _parse_airmon_stop(airmon_output):
        '''Find the interface taken out of into monitor mode (if any)'''

        # airmon-ng 1.2rc2 output: (mac80211 monitor mode vif enabled for [phy10]wlan0 on [phy10]wlan0mon)
        disabled_re = re.compile(r'\s*\(mac80211 monitor mode (?:vif )?disabled for (?:\[\w+\])?(\w+)\)\s*')

        # airmon-ng 1.2rc1 output: wlan0mon (removed)
        removed_re = re.compile(r'([a-zA-Z0-9]+).*\(removed\)')

        # Enabled interface: (mac80211 station mode vif enabled on [phy4]wlan0)
        enabled_re = re.compile(r'\s*\(mac80211 station mode (?:vif )?enabled on (?:\[\w+\])?(\w+)\)\s*')

        disabled_iface = None
        enabled_iface = None
        for line in airmon_output.split('\n'):
            matches = disabled_re.match(line)
            if matches:
                disabled_iface = matches.group(1)

            matches = removed_re.match(line)
            if matches:
                disabled_iface = matches.group(1)

            matches = enabled_re.match(line)
            if matches:
                enabled_iface = matches.group(1)

        return (disabled_iface, enabled_iface)

    @staticmethod
    def start_built_in_driver(iface):
        phy = iface.phy
        Process.call('iw phy %s interface add mon0 type monitor && ifconfig mon0 up' % phy)
        monitor_interfaces = Iwconfig.get_interfaces(mode='Monitor')
        if len(monitor_interfaces) >= 1:
            for interface in monitor_interfaces:
                if interface == 'mon0': return interface
        return None

    @staticmethod
    def ask():
        '''
        Asks user to define which wireless interface to use.
        Does not ask if:
            1. There is already an interface in monitor mode, or
            2. There is only one wireless interface (automatically selected).
        Puts selected device into Monitor Mode.
        '''

        Airmon.terminate_conflicting_processes()

        monitor_interfaces = Iwconfig.get_interfaces(mode='Monitor')
        if len(monitor_interfaces) == 1:
            # Assume we're using the device already in montior mode
            iface = monitor_interfaces[0]
            Airmon.base_interface = None
            return iface

        a = Airmon()
        count = len(a.interfaces)
        if count == 0:
            # No interfaces found
            raise Exception('airmon-ng did not find any wireless interfaces')

        # TODO: set static interface, no need to select
        if count == 1:
            # If there is only one wireless interface which is built-in wifi (brcmfmac driver), we will start bad driver since airmon-ng cannot start it properly
            # If there is only built-in wireless card, we will return None since it might cause a problem
            # iface = a.get(0)
            # iface.interface = Airmon.start_built_in_driver(iface)
            # return iface.interface
            return None
        else:
            # If there is more than one wireless interface, we will select an interface which is not a built-in one, since it is more powerful and consistent with airmon-ng
            for interface in a.interfaces:
                if interface.driver == 'brcmfmac':
                    continue
                else:
                    interface.interface = Airmon.start(interface)
                    return interface.interface
        # else:
            # Multiple interfaces found
        


        # if a.get(choice).interface in monitor_interfaces:
        #     pass
        # else:
        #     iface.interface = Airmon.start(iface)
        # return iface.interface


    @staticmethod
    def terminate_conflicting_processes():
        ''' Deletes conflicting processes reported by airmon-ng '''

        airmon_output = Process(['airmon-ng', 'check']).stdout()

        # Conflicting process IDs and names
        pid_pnames = []

        # 2272    dhclient
        # 2293    NetworkManager
        pid_pname_re = re.compile(r'^\s*(\d+)\s*([a-zA-Z0-9_\-]+)\s*$')
        for line in airmon_output.split('\n'):
            match = pid_pname_re.match(line)
            if match:
                pid = match.group(1)
                pname = match.group(2)
                pid_pnames.append( (pid, pname) )

        return

        # for pid, pname in pid_pnames:
        #     if pname == 'NetworkManager' and Process.exists('service'):
        #         Color.pl('{!} {O}stopping network-manager ({R}service network-manager stop{O})')
        #         # Can't just pkill network manager; it's a service
        #         Process(['service', 'network-manager', 'stop']).wait()
        #         Airmon.killed_network_manager = True
        #     elif pname == 'avahi-daemon' and Process.exists('service'):
        #         Color.pl('{!} {O}stopping avahi-daemon ({R}service avahi-daemon stop{O})')
        #         # Can't just pkill avahi-daemon; it's a service
        #         Process(['service', 'avahi-daemon', 'stop']).wait()
        #     else:
        #         Color.pl('{!} {R}Terminating {O}conflicting process {R}%s{O} (PID {R}%s{O})' % (pname, pid))
        #         try:
        #             os.kill(int(pid), signal.SIGTERM)
        #         except:
        #             pass


    @staticmethod
    def put_interface_up(iface):
        Ifconfig.up(iface)

    @staticmethod
    def start_network_manager():
        if Process.exists('service'):
            cmd = 'service network-manager start'
            proc = Process(cmd)
            (out, err) = proc.get_output()
            return

        if Process.exists('systemctl'):
            cmd = 'systemctl start NetworkManager'
            proc = Process(cmd)
            (out, err) = proc.get_output()
            return

if __name__ == '__main__':
    stdout = '''
Found 2 processes that could cause trouble.
If airodump-ng, aireplay-ng or airtun-ng stops working after
a short period of time, you may want to run 'airmon-ng check kill'
  PID Name
 5563 avahi-daemon
 5564 avahi-daemon
PHY	Interface	Driver		Chipset
phy0	wlx00c0ca4ecae0	rtl8187		Realtek Semiconductor Corp. RTL8187
Interface 15mon is too long for linux so it will be renamed to the old style (wlan#) name.
		(mac80211 monitor mode vif enabled on [phy0]wlan0mon
		(mac80211 station mode vif disabled for [phy0]wlx00c0ca4ecae0)
    '''
    start_iface = Airmon.start('wlan0')
    print('start_iface from stdout:', start_iface)
    Configuration.initialize(False)
    iface = Airmon.ask()
    (disabled_iface, enabled_iface) = Airmon.stop(iface)
    print('Disabled:', disabled_iface)
    print('Enabled:', enabled_iface)