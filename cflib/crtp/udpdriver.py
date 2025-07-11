#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#     ||          ____  _ __
#  +------+      / __ )(_) /_______________ _____  ___
#  | 0xBC |     / __  / / __/ ___/ ___/ __ `/_  / / _ \
#  +------+    / /_/ / / /_/ /__/ /  / /_/ / / /_/  __/
#   ||  ||    /_____/_/\__/\___/_/   \__,_/ /___/\___/
#
#  Copyright (C) 2011-2013 Bitcraze AB
#
#  Crazyflie Nano Quadcopter Client
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
""" CRTP UDP Driver. Work either with the UDP server or with an UDP device
See udpserver.py for the protocol"""
import queue
import re
import socket
import struct
import threading
from urllib.parse import urlparse
import logging

from .crtpdriver import CRTPDriver
from .crtpstack import CRTPPacket
from .exceptions import WrongUriType

__author__ = 'Bitcraze AB'
__all__ = ['UdpDriver']

logger = logging.getLogger(__name__)


ping_header = "p"
data_header = "d"

class UdpDriver(CRTPDriver):

    def __init__(self):
        self.needs_resending = False
        logger.info('Initialized UDP driver.')

    def connect(self, uri, linkQualityCallback, linkErrorCallback):
        if not re.search('^udp://', uri):
            raise WrongUriType('Not an UDP URI')

        parse = urlparse(uri)

        self.in_queue = queue.Queue()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addr = (parse.hostname, parse.port)
        self.socket.connect(self.addr)

        self._thread = _UdpDriverThread(self.socket, self.in_queue, linkErrorCallback)
        self._thread.start()

        self.send_raw_packet(b'\xF3')

    def receive_packet(self, time=0):
        if time == 0:
            try:
                return self.in_queue.get(False)
            except queue.Empty:
                return None
        elif time < 0:
            try:
                return self.in_queue.get(True)
            except queue.Empty:
                return None
        else:
            try:
                return self.in_queue.get(True, time)
            except queue.Empty:
                return None

    def send_packet(self, pk):
        raw = (pk.header,) + struct.unpack('B' * len(pk.data), pk.data)
        # raw = struct.unpack('B', data_header.encode('utf-8')) + (pk.header,) + struct.unpack('B' * len(pk.data), pk.data)
        data = struct.pack('B' * len(raw), *raw)
        self.send_raw_packet(data)
    
    def send_ping_packet(self):
        self.socket.send(ping_header.encode('utf-8'))
    
    def send_raw_packet(self, pk):
        self.socket.send(pk)

    def close(self):
        """ Close the link. """
        # Stop the comm thread
        self._thread.stop()
        self.send_raw_packet(b'\xF4')
        try:
            self.socket.close()
            self.socket = None
        except Exception as e:
            print(e)
            logger.error('Could not close {}'.format(e))
            pass
        print('UdpDriver closed')

    def get_name(self):
        return 'udp'

    def scan_interface(self, address):
        uris = []
        for port in range(19850,19854):
            try:
                address = '0.0.0.0'
                print(f'Attempting connection on {address}:{port}')
                uri = 'udp://' + address + ':' + str(port)
                parse = urlparse(uri)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                addr = (parse.hostname, parse.port)
                sock.connect(addr)
                # sock.send(ping_header.encode('utf-8'))
                # packet = sock.recv(0)
                print('Got response from {address}:{port}'.format(address=address, port=port))
                sock.shutdown(2)
                uris += [[uri, '']]
            except socket.error as e:
                uri = []
                # print('UDP socket not found')
                print(e)
        # uri = [['udp://0.0.0.0:19850', '']]
        return uris
    
class _UdpDriverThread(threading.Thread):
    """
    Udp receiver thread used to read data from the
    Socket. """

    def __init__(self, socket: socket.socket, inQueue: queue, link_error_callback):
        threading.Thread.__init__(self)
        self._socket = socket
        self._in_queue = inQueue
        self._link_error_callback = link_error_callback
        self._sp = False
    
    def stop(self):
        """ Stop the thread """
        self._sp = True
        try:
            self.join()
        except Exception:
            pass

    def run(self):
        """ Run the receiver thread """

        while (True):
            if (self._sp):
                break
            try:
                packet = self._socket.recv(1024)
                data = struct.unpack('B' * len(packet), packet)
                if len(data) > 0:
                    # if data[0] == data_header:
                    pk = CRTPPacket(header=data[0], 
                                    data=data[1:])
                    self._in_queue.put(pk)
            except queue.Empty:
                pass  # This is ok
            except Exception as e:
                import traceback                      

                self._link_error_callback(
                    'Error communicating with the Crazyflie\n'
                    'Exception:%s\n\n%s' % (e,
                                            traceback.format_exc()))
