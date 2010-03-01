#! /usr/bin/env python

import struct, os, sys
import logging
from errno import *

import vfs, vm

lvl = logging.DEBUG
logging.basicConfig(level=lvl,
                    format="%(name)15.15s %(levelname)5s: %(message)s")

mainlog    = logging.getLogger("trusted")
sandboxlog = logging.getLogger("sandbox.action")
tubelog    = logging.getLogger("sandbox.tube")

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
GET_MEMORY_POOL = 7

class SandboxedProcess:
    def __init__(self, fd, nfd):
        self.fd  = os.fdopen(fd, 'w+')
        self.vfs = vfs.VfsManager(fd+1, fd+1+nfd, root='/')
        self.vm  = vm.VirtualMemory(0x01000000)

    def syscall_request(self):
        sandboxlog.info('syscall request ringing...')
        msg = self.fd.read(7*4)
        mm = Memory.parse(msg)
        sandboxlog.debug('>>> %s' % mm)


        if mm.eax == 3:
            self.sys_read(mm.ebx, mm.ecx, mm.edx)
        elif mm.eax == 3:
            self.sys_write(mm.ebx, mm.ecx, mm.edx)
        elif mm.eax == 5:
            self.open(mm)
        elif mm.eax == 6:
            self.close(mm.ebx)
        elif mm.eax == 0x5b:
            self.munmap(mm.ebx, mm.ecx)
        elif mm.eax == 0xc5:
            self.fstat64(mm.ebx, mm.ecx)
        elif mm.eax == 0xc0:
            self.mmap(mm.ebx, mm.ecx, mm.edx, mm.esi, mm.edi, mm.ebp)
        elif mm.eax == 0xfc:
            self.exit(mm.ebx)
        else:
            self.op_retval(-1, ENOSYS) # Function not implemented

    def open(self, reg):
        u_ptr = reg.ebx
        u_perms = reg.ecx
        u_mode  = reg.edx
        filename = self.peek_asciiz(u_ptr)
        sandboxlog.debug('+++ open("%s", %x, %#x)' % (filename, u_perms, u_mode))
        (ret, errno) = self.vfs.open(filename, u_perms, u_mode)
        self.op_retval(ret, errno)

    def op_retval(self, ret, errno=0):
        tubelog.debug('<<< op_retval(%#x, %d)' % (ret,errno))
        self.write(struct.pack('III', RETVAL, ret & 0xffffffff, errno))
        
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

    def sys_write(self, fd, addr, buflen):
        pass

    def sys_read(self, fd, addr, buflen):
        tubelog.debug('+++ read(%d, %#x, %d)' % (fd, addr, buflen))
        if self.vfs.is_at_eof(fd):
            self.op_retval(0, 0)
        else:
            buf = self.vfs.read_handler(fd, buflen)
            self.poke_memory(addr, buf)
            self.op_retval(len(buf), 0)

    def read(self, nbytes):
        return self.fd.read(nbytes)

    def fstat(self, fd, addr):
        pass

    def fstat64(self, fd, addr):
        sandboxlog.info('+++ fstat64(%d, %#8x)' % (fd, addr))
        ## XXX: Check if fd is open
        (ret, st, errno) = self.vfs.fstat(fd)
        if st:
            st_buf = struct.pack(
                #        #  struct stat64 {
                'Q'    + #     unsigned long long      st_dev;
                'xxxx' + #     unsigned char   __pad0[4];
                'L'    + #     unsigned long   __st_ino;
                'I'    + #     unsigned int    st_mode;
                'I'    + #     unsigned int    st_nlink;
                'L'    + #     unsigned long   st_uid;
                'L'    + #     unsigned long   st_gid;
                'Q'    + #     unsigned long long      st_rdev;
                'xxxx' + #     unsigned char   __pad3[4];
                'q'    + #     long long       st_size;
                'L'    + #     unsigned long   st_blksize;
                'Q'    + #     unsigned long long      st_blocks;
                'L'    + #     unsigned long   st_atime;
                'L'    + #     unsigned long   st_atime_nsec;
                'L'    + #     unsigned long   st_mtime;
                'I'    + #     unsigned int    st_mtime_nsec;
                'L'    + #     unsigned long   st_ctime;
                'L'    + #     unsigned long   st_ctime_nsec;
                'Q',     #     unsigned long long      st_ino;
                         #  };
                st.st_dev, st.st_ino,
                st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
                st.st_rdev, st.st_size,
                st.st_blksize,
                st.st_blocks,
                int(st.st_atime), 0, int(st.st_mtime), 0, int(st.st_ctime), 0, st.st_ino)
            #tubelog.debug('<<< stat buffer %s...' % st_buf.encode('hex'))
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

        if not self.vm.mm:
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
        numdescriptors = int(sys.argv[1])
        self.master_socket = 4
        self.sandbox = SandboxedProcess(self.master_socket, numdescriptors)

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
            if not self.sandbox.vfs.bridge.run(self.master_socket):
                raise Exception('Select_loop failed!')
            buf = os.read(self.master_socket, 4)
            if not buf:
                break
            self.dispatcher(buf)

if __name__ == '__main__':
    tp = TrustedProcess()
    tp.run()
