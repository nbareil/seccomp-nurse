#! /usr/bin/env python

import struct, os
import logging

import vfs

mainlog = logging.getLogger("trusted")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
mainlog.addHandler(console_handler)
sandboxlog = logging.getLogger("sandbox.action")
tubelog = logging.getLogger("sandbox.tube")
tubelog.addHandler(console_handler)
sandboxlog.addHandler(console_handler)

mainlog.setLevel(-1)
tubelog.setLevel(-1)
sandboxlog.setLevel(-1)

class Memory:
    def __init__(self, regs):
        (self.eax, self.ebx, 
         self.ecx, self.edx,
         self.esi, self.edi,
         self.ebp) = regs

    @staticmethod
    def parse(raw):
        return Memory(struct.unpack('7I', raw))

    def __repr__(self):
        return 'eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x ebp=%x' % (self.eax, self.ebx, 
                                                                     self.ecx, self.edx,
                                                                     self.esi, self.edi,
                                                                     self.ebp)

DO_SYSCALL  = 1
PEEK_ASCIIZ = 2
PEEK_MEMORY = 3
POKE_MEMORY = 4
RETVAL      = 5
NATIVE_EXIT = 6

class SandboxedProcess:
    def __init__(self, fd=-1):
        self.fd = os.fdopen(fd, 'w+')
        self.vfs = vfs.VfsManager(root='/var', nextfd=fd+1)

    def syscall_request(self):
        tubelog.debug('syscall request ringing...')
        msg = self.fd.read(7*4)
        tubelog.debug('>>> msg received: %s' % msg.encode('hex'))
        mm = Memory.parse(msg)
        tubelog.debug('>>> %s' % mm)

        if mm.eax == 5:
            self.open(mm)

        elif mm.eax == 0xfc:
            self.exit(mm.ebx)

    def open(self, reg):
        u_ptr = reg.ebx
        u_perms = reg.ecx
        u_mode  = reg.edx
        filename = self.peek_asciiz(u_ptr)
        sandboxlog.debug('open("%s", %x, %x)' % (filename, u_perms, u_mode))
        (fd, errno) = self.vfs.open(filename, u_perms, u_mode)
        if isinstance(fd, file):
            ret = fd.fileno()
        else:
            ret = fd
        sandboxlog.debug('*** fd=%s errno=%x' % (fd, errno))
        self.op_retval(ret, errno)

    def op_retval(self, ret, errno=0):
        tubelog.debug('<<< op_retval(%d, %d)' % (ret,errno))
        self.write(struct.pack('IiI', RETVAL, ret, errno))

    def peek_asciiz(self, ptr):
        tubelog.debug('<<< peek_asciiz(%#x)' % ptr)
        self.write(struct.pack('II', PEEK_ASCIIZ, ptr))
        buf = self.fd.read(4)
        nbytes = struct.unpack('I', buf)[0]
        tubelog.debug('*** Waiting for %d bytes' % nbytes)
        buf = self.fd.read(nbytes)
        tubelog.debug('>>> ' + buf)
        return buf

    def exit(self, status):
        tubelog.debug('<<< native_exit(%x)' % status)
        self.write(struct.pack('II', NATIVE_EXIT, status))

    def write(self, buf, forceflush=True):
        ret = self.fd.write(buf)
        if forceflush:
            self.fd.flush()
        return ret

    def read(self, nbytes):
        return self.fd.read(nbytes)
    
class TrustedProcess:
    def __init__(self):
        self.sandbox = SandboxedProcess(fd=3)
        self.untrustedfd = 3

    def dispatcher(self, rawtype):
        msgtype = struct.unpack('I', rawtype)[0]
        tubelog.debug('dispatching msgtype=%x' % msgtype)

        if msgtype == DO_SYSCALL:
            self.sandbox.syscall_request()

    def run(self):
        tubelog.debug('running')
        while True:
            mainlog.debug('select_loop')
            if not self.sandbox.vfs.select_loop(self.untrustedfd):
                raise Exception('Select_loop failed!')
            buf = os.read(self.untrustedfd, 4)
            if not buf:
                break
            self.dispatcher(buf)

if __name__ == '__main__':
    tp = TrustedProcess()
    tp.run()
