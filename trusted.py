#! /usr/bin/env python

import struct, os
import logging

import vfs, vm

mainlog = logging.getLogger("trusted")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(name)15.15s %(levelname)5s: %(message)s"))
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
GET_MEMORY_POOL  = 7

class SandboxedProcess:
    def __init__(self, fd=-1):
        self.fd  = os.fdopen(fd, 'w+')
        self.vfs = vfs.VfsManager(root='/', nextfd=fd+1)
        self.vm  = vm.VirtualMemory(0x1000)

    def syscall_request(self):
        sandboxlog.info('syscall request ringing...')
        msg = self.fd.read(7*4)
        mm = Memory.parse(msg)
        sandboxlog.debug('>>> %s' % mm)

        if mm.eax == 5:
            self.open(mm)
        elif mm.eax == 6:
            self.close(mm.ebx)
        elif mm.eax == 0x5b:
            self.munmap(mm.ebx, mm.ecx)
        elif mm.eax == 0xc5:
            self.fstat(mm.ebx, mm.ecx)
        elif mm.eax == 0xc0:
            self.mmap(mm.ebx, mm.ecx, mm.edx, mm.esi, mm.edi, mm.ebp)
        elif mm.eax == 0xfc:
            self.exit(mm.ebx)

    def open(self, reg):
        u_ptr = reg.ebx
        u_perms = reg.ecx
        u_mode  = reg.edx
        filename = self.peek_asciiz(u_ptr)
        sandboxlog.debug('+++ open("%s", %x, %x)' % (filename, u_perms, u_mode))
        (fd, errno) = self.vfs.open(filename, u_perms, u_mode)
        if isinstance(fd, file):
            ret = fd.fileno()
        else:
            ret = fd
        self.op_retval(ret, errno)

    def op_retval(self, ret, errno=0):
        tubelog.debug('<<< op_retval(%#x, %d)' % (ret,errno))
        self.write(struct.pack('III', RETVAL, ret, errno))

    def peek_asciiz(self, ptr):
        tubelog.debug('<<< peek_asciiz(%#x)' % ptr)
        self.write(struct.pack('II', PEEK_ASCIIZ, ptr))
        buf = self.fd.read(4)
        nbytes = struct.unpack('I', buf)[0]
        tubelog.debug('    Waiting for %d bytes' % nbytes)
        buf = self.fd.read(nbytes)
        tubelog.debug('>>> ' + buf)
        return buf

    def poke_memory(self, addr, buf):
        length = len(buf)
        tubelog.debug('<<< poke_memory(%#x, "...") len=%d' % (addr, length))
        self.write(struct.pack('III', POKE_MEMORY, addr, length))
        self.write(buf)

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

    def fstat(self, fd, addr):
        sandboxlog.info('+++ fstat(%d, %#8x)' % (fd, addr))
        ## XXX: Check if fd is open
        (ret, st, errno) = self.vfs.fstat(fd)
        st_buf = struct.pack('Q xxxx IIIIIQ xxxx III QQQ xxxxxxxx', 
                             st.st_dev, st.st_ino,   st.st_mode, st.st_nlink, st.st_uid, 
                             st.st_gid, st.st_rdev, st.st_size, st.st_blksize, st.st_blocks,
                             st.st_atime, st.st_mtime, st.st_ctime)

        tubelog.debug('<<< stat buffer')
        self.poke_memory(addr, st_buf)
        self.op_retval(ret, errno)

    def mmap(self, addr, length, prot, flags, fd, offset):
        fd = ~((fd + 1) & 0xffffffff)
        sandboxlog.info('+++ mmap(%#x, %#x, %#x, %#x, %#d, %d)' % 
                        (addr, length, prot, flags, fd, offset))

        # if not self.security.mmap(addr, length, prot, flags, fd, offset):
        #     raise SecurityViolation("mmap denied")

        ## XXX: Check if fd is owned by the sandbox
        ## XXX: Offset must be page aligned

        if not self.vm.pool:
            self.vm.set_pool_addr(self.get_memory_pool())
        addr = self.vm.new_mapping(addr, length, prot, flags)
        if fd >= 0:
            os.lseek(fd, offset, os.SEEK_SET)
            self.poke_memory(addr, os.read(fd, length))
        self.op_retval(int(addr & 0xffffffff), 0)

    def munmap(self, addr, length):
        sandboxlog.info('+++ munmap(%#x, %d)' % (addr, length))
        self.vm.release_mapping(addr, length)
        self.op_retval(0, 0)

    def get_memory_pool(self):
        tubelog.debug('<<< memory_pool_addr')
        self.write(struct.pack('I', GET_MEMORY_POOL))
        addr = struct.unpack('I', self.read(4))[0]
        tubelog.info('>>> memory pool is at %x' % addr)
        return addr

    def close(self, fd):
        sandboxlog.info('+++ close(%d)' % fd)
        (ret, errno) = self.vfs.close(fd)
        return self.op_retval(ret, errno)

class TrustedProcess:
    def __init__(self):
        self.sandbox = SandboxedProcess(fd=3)
        self.untrustedfd = 3

    def dispatcher(self, rawtype):
        msgtype = struct.unpack('I', rawtype)[0]
        if msgtype == DO_SYSCALL:
            self.sandbox.syscall_request()
        elif msgtype == MEMORY_POOL:
            self.sandbox.set_memory_pool()
        else:
            tubelog.error('Unknown message type: %#x' % msgtype)

    def run(self):
        while True:
            if not self.sandbox.vfs.select_loop(self.untrustedfd):
                raise Exception('Select_loop failed!')
            buf = os.read(self.untrustedfd, 4)
            if not buf:
                break
            self.dispatcher(buf)

if __name__ == '__main__':
    tp = TrustedProcess()
    tp.run()
