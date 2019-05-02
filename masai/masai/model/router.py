#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

class WPSState:
    NONE, UNLOCKED, LOCKED, UNKNOWN = range(0, 4)


class Router(object):
    '''
        Holds details for a 'Target' aka Access Point (e.g. router).
    '''

    def __init__(self, fields):
        '''
            Initializes & stores target info based on fields.
            Args:
                Fields - List of strings
                INDEX KEY             EXAMPLE
                    0 BSSID           (00:1D:D5:9B:11:00)
                    1 First time seen (2015-05-27 19:28:43)
                    2 Last time seen  (2015-05-27 19:28:46)
                    3 channel         (6)
                    4 Speed           (54)
                    5 Privacy         (WPA2)
                    6 Cipher          (CCMP TKIP)
                    7 Authentication  (PSK)
                    8 Power           (-62)
                    9 beacons         (2)
                    10 # IV           (0)
                    11 LAN IP         (0.  0.  0.  0)
                    12 ID-length      (9)
                    13 ESSID          (HOME-ABCD)
                    14 Key            ()
        '''
        if type(fields) is list:
            self.bssid      =     fields[0].strip()
            self.channel    =     fields[3].strip()

            self.encryption =     fields[5].strip()
            if 'WPA' in self.encryption:
                self.encryption = 'WPA'
            elif 'WEP' in self.encryption:
                self.encryption = 'WEP'
            if len(self.encryption) > 4:
                self.encryption = self.encryption[0:4].strip()

            self.power      = int(fields[8].strip())
            if self.power < 0:
                self.power += 100

            self.beacons    = int(fields[9].strip())
            self.ivs        = int(fields[10].strip())

            self.essid_known = True
            self.essid_len   = int(fields[12].strip())
            self.essid       =     fields[13]
            if self.essid == '\\x00' * self.essid_len or \
                    self.essid == 'x00' * self.essid_len or \
                    self.essid.strip() == '':
                # Don't display '\x00...' for hidden ESSIDs
                self.essid = None # '(%s)' % self.bssid
                self.essid_known = False


        elif type(fields) is dict:
            self.bssid = fields['BSSID']
            self.channel = fields['CHAN']
            self.encryption = fields['SECURITY']
            if 'WPA' in self.encryption:
               self.encryption = 'WPA'
            elif 'WEP' in self.encryption:
                self.encryption = 'WEP'

            if len(self.encryption) > 4:
                self.encryption = self.encryption[0:4].strip()
            
            self.beacons    = 0
            self.ivs        = 0

            self.power = int(fields['SIGNAL'])
            self.essid_known = True
            self.essid_len = int(len(fields['SSID']))
            self.essid = fields['SSID']
            if self.essid == '\\x00' * self.essid_len or \
                    self.essid == 'x00' * self.essid_len or \
                    self.essid.strip() == '':
                # Don't display '\x00...' for hidden ESSIDs
                self.essid = None # '(%s)' % self.bssid
                self.essid_known = False

        self.wps = WPSState.UNKNOWN
        self.decloaked = False
        self.clients = []
        self.validate()

    def validate(self):
        ''' Checks that the target is valid. '''
        if self.channel == '-1':
            raise Exception('Ignoring target with Negative-One (-1) channel')

        # Filter broadcast/multicast BSSIDs, see https://github.com/derv82/wifite2/issues/32
        bssid_broadcast = re.compile(r'^(ff:ff:ff:ff:ff:ff|00:00:00:00:00:00)$', re.IGNORECASE)
        if bssid_broadcast.match(self.bssid):
            raise Exception('Ignoring target with Broadcast BSSID (%s)' % self.bssid)

        bssid_multicast = re.compile(r'^(01:00:5e|01:80:c2|33:33)', re.IGNORECASE)
        if bssid_multicast.match(self.bssid):
            raise Exception('Ignoring target with Multicast BSSID (%s)' % self.bssid)

    def to_str(self, show_bssid=False):
        '''
            *Colored* string representation of this Target.
            Specifically formatted for the 'scanning' table view.
        '''

        max_essid_len = 24
        essid = self.essid if self.essid_known else '(%s)' % self.bssid
        # Trim ESSID (router name) if needed
        if len(essid) > max_essid_len:
            essid = essid[0:max_essid_len-3] + '...'
        else:
            essid = essid.rjust(max_essid_len)

        if self.essid_known:
            # Known ESSID
            essid = '%s' % essid
        else:
            # Unknown ESSID
            essid = '%s' % essid

        # Add a '*' if we decloaked the ESSID
        decloaked_char = '*' if self.decloaked else ' '
        essid += '%s' % decloaked_char

        if show_bssid:
            bssid = '%s  ' % self.bssid
        else:
            bssid = ''

        channel_color = ''
        if int(self.channel) > 14:
            channel_color = ''
        channel = '%s%s' % (channel_color, str(self.channel).rjust(3))

        encryption = self.encryption.rjust(4)
        if 'WEP' in encryption:
            encryption = '%s' % encryption
        elif 'WPA' in encryption:
            encryption = '%s' % encryption

        power = '%sdb' % str(self.power).rjust(3)
        power = '%s' % power

        if self.wps == WPSState.UNLOCKED:
            wps = ' yes'
        elif self.wps == WPSState.NONE:
            wps = '  no'
        elif self.wps == WPSState.LOCKED:
            wps = 'lock'
        elif self.wps == WPSState.UNKNOWN:
            wps = ' n/a'

        clients = '       '
        if len(self.clients) > 0:
            clients = '  ' + str(len(self.clients))

        result = '%s  %s%s  %s  %s  %s  %s' % (
                essid, bssid, channel, encryption, power, wps, clients)
        result += ''
        return result


if __name__ == '__main__':
    fields = 'AA:BB:CC:DD:EE:FF,2015-05-27 19:28:44,2015-05-27 19:28:46,1,54,WPA2,CCMP TKIP,PSK,-58,2,0,0.0.0.0,9,HOME-ABCD,'.split(',')
    t = Router(fields)
    t.clients.append('asdf')
    t.clients.append('asdf')
    print(t.to_str())