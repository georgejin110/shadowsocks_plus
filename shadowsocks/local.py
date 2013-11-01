#!/usr/bin/env python

# Copyright (c) 2013 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import with_statement
import sys
if sys.version_info < (2, 6):
    import simplejson as json
else:
    import json

try:
    import gevent
    import gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    print >>sys.stderr, 'warning: gevent not found, using threading instead'

import socket
import select
import SocketServer
import struct
import os
import logging
import getopt
import encrypt
import utils


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent

def recv_all(sock):
    data = ''
    while True:
        d = sock.recv(4096)
        data += d
        if d.endswith('\r\n\r\n') or len(d)<=0:
            break
    return data

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True


class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote, addr, init_send):
        try:
            fdset = [sock, remote]

            if init_send:
                data = self.encrypt(init_send)
                result = send_all(remote, data)
                if result < len(data):
                    raise Exception('failed to send all data')

            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    d = sock.recv(4096)
                    data = self.encrypt(d)
                    if len(data) <= 0:
                        break
                    result = send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote in r:
                    data = self.decrypt(remote.recv(4096))
                    if len(data) <= 0:
                        break
                    result = send_all(sock, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            logging.info('--close: %s', addr)
            sock.close()
            remote.close()

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.encryptor.decrypt(data)

    def send_encrypt(self, sock, data):
        sock.send(self.encrypt(data))

    def get_host_port(self, d, p):
        host = None
        for k, v in [kv.split(': ') for kv in d.split('\r\n') if kv and ': ' in kv]:
            if k=='Host':
                host = v
        if not host:
            logging.error(d)
        if ':' in host:
            addr, port = host.split(':')
        else:
            addr, port = host, p
        port = (int(port), )
        addr_to_send = '\x03'+chr(len(addr))+addr+struct.pack('>H', port[0])
        return addr, port, addr_to_send

    def handle(self):
        try:
            self.encryptor = encrypt.Encryptor(KEY, METHOD)
            sock = self.connection
            d = sock.recv(262)

            reply = init_send = None
            if d.startswith('CONNECT '):
                addr, port, addr_to_send = self.get_host_port(d, '443')
                reply = 'HTTP/1.1 200 OK\r\n\r\n'
            elif d.startswith('GET ') or d.startswith('POST') or d.startswith('HEAD'):
                d = d+recv_all(sock)
                addr, port, addr_to_send = self.get_host_port(d, '80')
                d = d.replace('Proxy-Connection:', 'Connection:')
                init_send = d
            else:
                sock.send("\x05\x00")
                data = self.rfile.read(4) or '\x00' * 4
                mode = ord(data[1])
                if mode != 1:
                    logging.warn('mode != 1')
                    logging.warn(d)
                    return
                addrtype = ord(data[3])
                addr_to_send = data[3]
                if addrtype == 1:
                    addr_ip = self.rfile.read(4)
                    addr = socket.inet_ntoa(addr_ip)
                    addr_to_send += addr_ip
                elif addrtype == 3:
                    addr_len = self.rfile.read(1)
                    addr = self.rfile.read(ord(addr_len))
                    addr_to_send += addr_len + addr
                elif addrtype == 4:
                    addr_ip = self.rfile.read(16)
                    addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
                    addr_to_send += addr_ip
                else:
                    logging.warn('addr_type not support')
                    # not support
                    return
                addr_port = self.rfile.read(2)
                addr_to_send += addr_port
                port = struct.unpack('>H', addr_port)
                reply = "\x05\x00\x00\x01"
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)

            try:
                if reply:
                    self.wfile.write(reply)
                # reply immediately
                remote = socket.create_connection((SERVER, REMOTE_PORT))
                self.send_encrypt(remote, addr_to_send)
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.warn(e)
                return
            self.handle_tcp(sock, remote, (addr, port[0]), init_send)
        except socket.error, e:
            logging.warn(e)


def main():
    global SERVER, REMOTE_PORT, PORT, KEY, METHOD, LOCAL, IPv6
    
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    # fix py2exe
    if hasattr(sys, "frozen") and sys.frozen in \
            ("windows_exe", "console_exe"):
        p = os.path.dirname(os.path.abspath(sys.executable))
        os.chdir(p)
    version = ''
    try:
        import pkg_resources
        version = pkg_resources.get_distribution('shadowsocks').version
    except:
        pass
    print 'shadowsocks %s' % version

    KEY = None
    METHOD = None
    LOCAL = ''
    IPv6 = False
    
    config_path = utils.find_config()
    optlist, args = getopt.getopt(sys.argv[1:], 's:b:p:k:l:m:c:6')
    for key, value in optlist:
        if key == '-c':
            config_path = value

    if config_path:
        logging.info('loading config from %s' % config_path)
        with open(config_path, 'rb') as f:
            config = json.load(f)
    else:
        config = {}

    optlist, args = getopt.getopt(sys.argv[1:], 's:b:p:k:l:m:c:6')
    for key, value in optlist:
        if key == '-p':
            config['server_port'] = int(value)
        elif key == '-k':
            config['password'] = value
        elif key == '-l':
            config['local_port'] = int(value)
        elif key == '-s':
            config['server'] = value
        elif key == '-m':
            config['method'] = value
        elif key == '-b':
            config['local'] = value
        elif key == '-6':
            IPv6 = True

    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']
    METHOD = config.get('method', None)
    LOCAL = config.get('local', '')

    if not KEY and not config_path:
        sys.exit('config not specified, please read https://github.com/clowwindy/shadowsocks')

    utils.check_config(config)
        
    encrypt.init_table(KEY, METHOD)

    try:
        if IPv6:
            ThreadingTCPServer.address_family = socket.AF_INET6
        server = ThreadingTCPServer((LOCAL, PORT), Socks5Server)
        logging.info("starting local at %s:%d" % tuple(server.server_address[:2]))
        server.serve_forever()
    except socket.error, e:
        logging.error(e)
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)
        
if __name__ == '__main__':
    main()
