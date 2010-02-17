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
        self.vfs = vfs.VfsManager(root='/', nextfd=fd+1)

    def syscall_request(self):
        tubelog.debug('syscall request ringing...')
        msg = self.fd.read(7*4)
        tubelog.debug('>>> msg received: %s' % msg.encode('hex'))
        mm = Memory.parse(msg)
        tubelog.debug('>>> %s' % mm)

        if mm.eax == 5:
            self.open(mm)
        elif mm.eax == 0xc5:
            self.fstat(mm.ebx, mm.ecx)
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


    def poke_memory(self, addr, buf):
        length = len(buf)
        tubelog.debug('<<< poke_memory(%#x, "%s") len=%d' % (addr, buf.encode('hex'), length))
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
        ## XXX: Check if fd is open
        (ret, st, errno) = self.vfs.fstat(fd)

	# $ pahole a.out
	# struct stat {
	#        __dev_t                    st_dev;               /*     0     8 */
	#        short unsigned int         __pad1;               /*     8     2 */
	#  
	#        /* XXX 2 bytes hole, try to pack */
	#  
	#        __ino_t                    st_ino;               /*    12     4 */
	#        __mode_t                   st_mode;              /*    16     4 */
	#        __nlink_t                  st_nlink;             /*    20     4 */
	#        __uid_t                    st_uid;               /*    24     4 */
	#        __gid_t                    st_gid;               /*    28     4 */
	#        __dev_t                    st_rdev;              /*    32     8 */
	#        short unsigned int         __pad2;               /*    40     2 */
	#  
	#        /* XXX 2 bytes hole, try to pack */
	#  
	#        __off_t                    st_size;              /*    44     4 */
	#        __blksize_t                st_blksize;           /*    48     4 */
	#        __blkcnt_t                 st_blocks;            /*    52     4 */
	#        struct timespec            st_atim;              /*    56     8 */
	#        /* --- cacheline 1 boundary (64 bytes) --- */
	#        struct timespec            st_mtim;              /*    64     8 */
	#        struct timespec            st_ctim;              /*    72     8 */
	#        long unsigned int          __unused4;            /*    80     4 */
	#        long unsigned int          __unused5;            /*    84     4 */
	#  
	#        /* size: 88, cachelines: 2 */
	#        /* sum members: 84, holes: 2, sum holes: 4 */
	#        /* last cacheline: 24 bytes */
	# };	/* definitions: 1 */
	#  
	# struct timespec {
	#        __time_t                   tv_sec;               /*     0     4 */
	#        long int                   tv_nsec;              /*     4     4 */
	#  
	#        /* size: 8, cachelines: 1 */
	#        /* last cacheline: 8 bytes */
	# };	/* definitions: 1 */

        st_buf = struct.pack('Q xxxx IIIIIQ xxxx III QQQ xxxxxxxx', 
                             st.st_dev, st.st_ino,   st.st_mode, st.st_nlink, st.st_uid, 
                             st.st_gid, st.st_rdev, st.st_size, st.st_blksize, st.st_blocks,
                             st.st_atime, st.st_mtime, st.st_ctime)

        tubelog.debug('<<< stat buffer')
        self.poke_memory(addr, st_buf)
        self.op_retval(ret, errno)
    
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
