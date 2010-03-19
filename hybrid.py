#! /usr/bin/env python

import mmap, os, struct
import logging

from syscalls import *
from errno import *
from trustedthread import TrustedThread
import security

lvl = logging.DEBUG
logging.basicConfig(level=lvl,
                    format="%(name)15.15s %(levelname)5s: %(message)s")

mainlog    = logging.getLogger("trusted")
sandboxlog = logging.getLogger("sandbox.action")
tubelog    = logging.getLogger("sandbox.tube")

THREAD_FD = 3
CONTROL_FD = 4
SHMEM_SIZE = 0x100
SHMEM_FILENAME = '/dev/shm/seccompnurse'

class Memory:
    def __init__(self, eax=0, ebx=0, ecx=0, edx=0, esi=0, edi=0, ebp=0):
        (self.eax, self.ebx,
         self.ecx, self.edx,
         self.esi, self.edi,
         self.ebp) = (eax, ebx, ecx, edx, esi, edi, ebp)

    @staticmethod
    def parse(raw):
        regs = struct.unpack('7I', raw)
        return Memory(*regs)

    def pack(self):
        return struct.pack('7I', 
                           self.eax, self.ebx,
                           self.ecx, self.edx,
                           self.esi, self.edi,
                           self.ebp)

    def aslist(self):
        return [self.eax, self.ebx,
                self.ecx, self.edx,
                self.esi, self.edi,
                self.ebp]

    def __repr__(self):
        return 'eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x ebp=%x' % (self.eax, self.ebx, 
                                                                     self.ecx, self.edx,
                                                                     self.esi, self.edi,
                                                                     self.ebp)

syscalls_table = {}
def syscall(nr, argc):
    def _syscall(func):
        def __syscall(*args, **kwargs):
            arguments = list(args[1:__syscall.argc+1])
            sandboxlog.info('+++ %s(%s)' % (__syscall.name, ','.join(map(str, map(hex, arguments)))))
            return func(*args, **kwargs)
        __syscall.nr   = nr
        __syscall.argc = argc
        __syscall.name = syscallnr2human[nr][2:]
        syscalls_table[nr] = __syscall
        return __syscall
    return _syscall

DO_SYSCALL  = 1
PEEK_ASCIIZ = 2
PEEK_MEMORY = 3
POKE_MEMORY = 4
RETVAL      = 5
NATIVE_EXIT = 6
PROTECTED_AREA = 7
RAISE_TRAP  = 8

class HybridSandbox:
    def __init__(self):
        self.control = os.fdopen(CONTROL_FD, 'w+', 0)
        shmem = self.shmem_open()
        self.trustedthread = TrustedThread(THREAD_FD, shmem)
        self.security = security.SecurityManager()

    def shmem_open(self):
        self.shmemfd = open(SHMEM_FILENAME, 'w+')
        self.shmemfd.truncate(SHMEM_SIZE)
        return mmap.mmap(self.shmemfd.fileno(), 0)

    def syscall_request(self):
        sandboxlog.debug('syscall request ringing...')
        msg = self.control.read(7*4)
        mm = Memory.parse(msg)
        sandboxlog.debug('>>> %s' % mm)
        return self.do(mm)

    def do(self, mm):
        if not mm.eax in syscalls_table:
            sandboxlog.error('syscall %s [nr=%#x] not implemented' % (syscallnr2human.get(mm.eax, ('???')), mm.eax))
            return -1
        func = syscalls_table.get(mm.eax)
        registers = mm.aslist()[1:func.argc+1]
        return func(self, *registers)

    @syscall(NR_open, 3)
    def open(self, filename_ptr, perms, mode):
        if not self.security.is_valid(filename_ptr):
            return -1
        filename = self.peek_asciiz(filename_ptr)
        if not self.security.open(filename, perms, mode):
            return -1
        args = Memory(eax=NR_open,
                      ebx=filename,
                      ecx = perms,
                      edx = mode)
        ret = self.trustedthread.delegate(args)
        if ret < 0x80000000:
            self.security.register_descriptor(ret, filename)
        return ret

    @syscall(NR_close, 1)
    def close(self, fd):
        if not self.security.close(fd):
            return -1
        args = Memory(eax=NR_close,
                      ebx=fd)
        ret = self.trustedthread.delegate(args)
        if ret == 0:
            self.security.unregister_descriptor(fd)
        return ret

    @syscall(NR_access, 2)
    def access(self, path_ptr, mode):
        if not self.security.is_valid(path_ptr):
            return -1
        path = self.peek_asciiz(path_ptr)
        self.security.access(path, mode)
        args = Memory(eax=NR_access,
                      ebx=path,
                      ecx=mode)
        ret = self.trustedthread.delegate(args)
        return ret

    @syscall(NR_lseek, 3)
    def lseek(self, fd, offset, whence):
        if not self.security.lseek(fd, offset, whence):
            return -1
        args = Memory(eax=NR_lseek,
                      ebx=fd,
                      ecx=offset,
                      edx=whence)
        return self.trustedthread.delegate(args)

    @syscall(NRllseek, 5)
    def llseek(self, fd, offset_high, offset_low, result, whence):
        if not self.security.llseek(fd, offset_high, offset_low, result, whence):
            return -1
        args = Memory(eax=NR_lseek,
                      ebx=fd,
                      ecx=offset_high,
                      edx=offset_low,
                      esi=result,
                      edi=whence)
        return self.trustedthread.delegate(args)

    @syscall(NR_stat64, 2)
    def stat64(self, path_ptr, addr):
        if not self.security.is_valid(path_ptr):
            return -1
        path = self.peek_asciiz(path_ptr)
        self.security.stat64(path, addr)
        args = Memory(eax=NR_stat64,
                      ebx=path,
                      ecx=addr)
        return self.trustedthread.delegate(args)

    @syscall(NR_fstat64, 2)
    def fstat64(self, fd, ptr):
        if not self.security.fstat(fd, ptr):
            return -1
        args = Memory(eax=NR_fstat64,
                      ebx=fd,
                      ecx=ptr)
        return self.trustedthread.delegate(args)

    @syscall(NR_mmap2, 6)
    def mmap2(self, addr, length, prot, flags, fd, pgoffset):
        return self.mmap(addr, length, prot, flags, fd, pgoffset << 12)

    @syscall(NR_mmap, 6)
    def mmap(self, addr, length, prot, flags, fd, offset):
        if not self.security.mmap(addr, length, prot, flags, fd, offset):
            return -1
        args = Memory(eax=NR_mmap,
                      ebx=addr,
                      ecx=length,
                      edx=prot,
                      esi=flags,
                      edi=fd,
                      ebp=offset)
        return self.trustedthread.delegate(args)

    @syscall(NR_brk, 1)
    def brk(self, addr):
        if not self.security.brk(addr):
            return -1
        args = Memory(eax=NR_brk, ebx=addr)
        return self.trustedthread.delegate(args)

    @syscall(NR_munmap, 2)
    def munmap(self, addr, length):
        if not self.security.munmap(addr, length):
            return -1
        args = Memory(eax=NR_munmap,
                      ebx=addr,
                      ecx=length)
        return self.trustedthread.delegate(args)

    def op_retval(self, ret, errno=0):
        tubelog.debug('<<< op_retval(%#x, %d)' % (ret,errno))
        self.control.write(struct.pack('III', RETVAL, ret & 0xffffffff, errno))
        return ret

    def raisetrap(self):
        self.control.write(struct.pack('I', RAISE_TRAP))

    def peek_asciiz(self, ptr):
        tubelog.debug('<<< peek_asciiz(%#x)' % ptr)
        self.control.write(struct.pack('II', PEEK_ASCIIZ, ptr))
        buf = self.control.read(4)
        nbytes = struct.unpack('I', buf)[0]
        tubelog.debug('    Waiting for %d bytes' % nbytes)
        buf = self.control.read(nbytes)
        tubelog.debug('>>> ' + buf)
        return buf

    def poke_memory(self, addr, buf):
        length = len(buf)
        tubelog.debug('<<< poke_memory(%#x, "...") len=%d' % (addr, length))
        self.control.write(struct.pack('III', POKE_MEMORY, addr, length))
        written=0
        while written < length:
            written += self.control.write(buf[written:])

    def dispatcher(self, rawtype):
        msgtype = struct.unpack('I', rawtype)[0]
        if msgtype == DO_SYSCALL:
            ret = self.syscall_request()
            self.op_retval(ret)
        else:
            tubelog.error('Unknown message type: %#x' % msgtype)

    def run(self):
        while True:
            buf = os.read(CONTROL_FD, 4)
            if not buf:
                break
            self.dispatcher(buf)

if __name__ == '__main__':
    sandbox = HybridSandbox()
    sandbox.run()

