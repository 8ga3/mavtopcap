#!/usr/bin/env python

# Copyright 2022, 8ga3
# Released under the GNU GPL version 3 or later

'''
convert a MAVLink tlog file to a Wireshark pcap file
'''
from __future__ import print_function

import os
import struct
from pymavlink import mavutil

# Helper class for writing pcap files
class pcap(object):
    """
       Used under the terms of GNU GPL v3.
       Original author: Neale Pickett
       see http://dirtbags.net/py-pcap.html
    """
    _MAGIC = 0xA1B2C3D4
    def __init__(self, stream, mode='rb', snaplen=65535, linktype=1):
        try:
            self.stream = open(stream, mode)
        except TypeError:
            self.stream = stream
        try:
            # Try reading
            hdr = self.stream.read(24)
        except IOError:
            hdr = None

        if hdr:
            # We're in read mode
            self._endian = None
            for endian in '<>':
                (self.magic,) = struct.unpack(endian + 'I', hdr[:4])
                if self.magic == pcap._MAGIC:
                    self._endian = endian
                    break
            if not self._endian:
                raise IOError('Not a pcap file')
            (self.magic, version_major, version_minor,
             self.thiszone, self.sigfigs,
             self.snaplen, self.linktype) = struct.unpack(self._endian + 'IHHIIII', hdr)
            if (version_major, version_minor) != (2, 4):
                raise IOError('Cannot handle file version %d.%d' % (version_major,
                                                                    version_minor))
        else:
            # We're in write mode
            self._endian = '='
            self.magic = pcap._MAGIC
            version_major = 2
            version_minor = 4
            self.thiszone = 0
            self.sigfigs = 0
            self.snaplen = snaplen
            self.linktype = linktype
            hdr = struct.pack(self._endian + 'IHHIIII',
                              self.magic, version_major, version_minor,
                              self.thiszone, self.sigfigs,
                              self.snaplen, self.linktype)
            self.stream.write(hdr)
        self.version = (version_major, version_minor)

    def read(self):
        hdr = self.stream.read(16)
        if not hdr:
            return
        (tv_sec, tv_usec, caplen, length) = struct.unpack(self._endian + 'IIII', hdr)
        datum = self.stream.read(caplen)
        return ((tv_sec, tv_usec, length), datum)

    def write(self, packet):
        (header, datum) = packet
        (tv_sec, tv_usec, length) = header
        hdr = struct.pack(self._endian + 'IIII', tv_sec, tv_usec, length, len(datum))
        self.stream.write(hdr)
        self.stream.write(datum)
        # self.stream.write(datum.encode())

    def __iter__(self):
        while True:
            r = self.read()
            if not r:
                break
            yield r

def convert_mav2pcap(input_filename, output_filename):
    mlog = mavutil.mavlink_connection(input_filename, zero_time_base=True)
    pcap_file = pcap(output_filename, mode='wb', linktype=147)

    while True:
        m = mlog.recv_match()
        if m is None:
            break

        if m.get_type() == 'BAD_DATA':
            continue

        mtype = m.get_type()
        # FMT  https://ardupilot.org/copter/docs/logmessages.html#fmt
        # PARM https://ardupilot.org/copter/docs/logmessages.html#parm
        if mtype in ['FMT', 'PARM']:
            continue

        timestamp = m._timestamp
        sec = int(timestamp)
        usec = int((timestamp - sec) * 1e6)

        data = m.get_msgbuf()

        pcap_header = (sec, usec, len(data))
        pcap_file.write((pcap_header, data))

def build_filename(filename, pre='', ext=''):
    (head, tail) = os.path.split(filename)
    basename = '.'.join(tail.split('.')[:-1])
    output_filename = pre + basename + ext

    if head is not None:
        output_filename = os.path.join(head, output_filename)

    return output_filename


if __name__ == '__main__':
    from argparse import ArgumentParser, FileType
    parser = ArgumentParser(description=__doc__)

    parser.add_argument('-p', '--pre', metavar='prefix', default='', help='file name prefix')
    parser.add_argument('input_files', metavar='input_files', nargs='+')
    args = parser.parse_args()


    for input_filename in args.input_files:
        output_filename = build_filename(input_filename, pre=args.pre, ext='.pcap')
        print("Creating %s" % output_filename)
        convert_mav2pcap(input_filename, output_filename)
