#! /usr/bin/env python

import sys
import inspect
import mmap, os, struct
import logging

import constants
import sizeof
import syscalls
from errno import *
from trustedthread import TrustedThread
import security


THREAD_FD = 3
CONTROL_FD = 4
SHMEM_SIZE = 1800
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
def syscall(nr):
    def _syscall(func):
        (args, varargs, keywords, defaults) = inspect.getargspec(func)
        argc = len(args) - 1
        def __syscall(*args, **kwargs):
            arguments = list(args[1:__syscall.argc+1])
            sandboxlog.info('+++ %s(%s)' % (__syscall.name, ','.join(map(str, map(hex, arguments)))))
            return func(*args, **kwargs)
        __syscall.nr   = getattr(syscalls, nr)
        __syscall.argc = argc
        __syscall.name = syscalls.syscallnr2human[__syscall.nr][2:]
        syscalls_table[__syscall.nr] = __syscall
        return __syscall
    return _syscall


mux_syscall_tables = {}
def mux_syscall(nr, val, muxer=1):
    def _syscall(func):
        (args, varargs, keywords, defaults) = inspect.getargspec(func)
        def __syscall(*args, **kwargs):
            sandboxlog.info('++++++ %s(%s)' % (val[4:].lower(), ', '.join(map(str, map(hex, args[1:])))))
            return func(*args, **kwargs)
        __syscall.argc = len(args) - 1
        __syscall.name = val[4:].lower()
        __syscall.nr = getattr(syscalls, nr)
        mux_syscall_tables[__syscall.nr] = mux_syscall_tables.get(__syscall.nr, {})
        mux_syscall_tables[__syscall.nr][getattr(constants, val)] = __syscall
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
        self.trustedthread = TrustedThread(sys.argv[1], THREAD_FD, shmem)
        memory_mappings = self.trustedthread.get_protected_sections()
        self.security = security.SecurityManager(memory_mappings)

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
            sandboxlog.error('syscall %s [nr=%#x] not implemented' % (syscalls.syscallnr2human.get(mm.eax, ('???')), mm.eax))
            return 0
        func = syscalls_table.get(mm.eax)
        registers = mm.aslist()[1:func.argc+1]
        return func(self, *registers)

    @syscall('NR_open')
    def open(self, filename_ptr, perms, mode):
        if not self.security.is_valid(filename_ptr):
            return -1
        filename = self.peek_asciiz(filename_ptr)
        if not self.security.open(filename, perms, mode):
            return -1
        args = Memory(eax=syscalls.NR_open,
                      ebx=filename,
                      ecx = perms,
                      edx = mode)
        ret = self.trustedthread.delegate(args)
        if ret < 0x80000000:
            self.security.register_descriptor(ret, filename)
        return ret

    @syscall('NR_close')
    def close(self, fd):
        if not self.security.close(fd):
            return -1
        args = Memory(eax=syscalls.NR_close,
                      ebx=fd)
        ret = self.trustedthread.delegate(args)
        if ret == 0:
            self.security.unregister_descriptor(fd)
        return ret

    @syscall('NR_access')
    def access(self, path_ptr, mode):
        if not self.security.is_valid(path_ptr):
            return (-1, EACCES)
        path = self.peek_asciiz(path_ptr)
        if not self.security.access(path, mode):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_access,
                      ebx=path,
                      ecx=mode)
        return self.trustedthread.delegate(args)

    @syscall('NR_getcwd')
    def getcwd(self, path_ptr):
        if not self.security.getcwd(path_ptr):
            return (0, EFAULT)
        args = Memory(eax=syscalls.NR_getcwd, ebx=path_ptr)
        return self.trustedthread.delegate(args)

    @syscall('NR_getpgrp')
    def getpgrp(self):
        if not self.security.getpgrp():
            return (-1, EPERM)
        args = Memory(eax=syscalls.NR_getpgrp)
        return self.trustedthread.delegate(args)

    @syscall('NR_getpid')
    def getpid(self):
        return int(self.trustedthread.pid)

    @syscall('NR_gettimeofday')
    def gettimeofday(self, tv_ptr, tz_ptr):
        if not self.security.gettimeofday(tv_ptr, tz_ptr):
            return (-1, EPERM)
        args = Memory(eax=syscalls.NR_gettimeofday, ebx=tv_ptr, ecx=tz_ptr)
        return self.trustedthread.delegate(args)

    @syscall('NR_exit')
    def exit(self, val):
        args = Memory(eax=syscalls.NR_exit_group, ebx=val)
        sandboxlog.info('EXIT')
        self.control.write(struct.pack('II', NATIVE_EXIT, val))
        self.control.flush()
        self.trustedthread.delegate(args, willexit=True)
        sys.exit(val)

    @syscall('NR_ioctl')
    def ioctl(self, fd, request):
        sandboxlog.debug('ioctl(%d, %#x)' % (fd, request))
        ## we should eventually support some ioctl but for the moment
        ## let's simulate a success :)
        return 0

    @syscall('NR_lseek')
    def lseek(self, fd, offset, whence):
        if not self.security.lseek(fd, offset, whence):
            return (-1, EBADF)
        args = Memory(eax=syscalls.NR_lseek,
                      ebx=fd,
                      ecx=offset,
                      edx=whence)
        return self.trustedthread.delegate(args)

    @syscall('NRllseek')
    def llseek(self, fd, offset_high, offset_low, result, whence):
        if not self.security.llseek(fd, offset_high, offset_low, result, whence):
            return (-1, EBADF)
        args = Memory(eax=syscalls.NRllseek,
                      ebx=fd,
                      ecx=offset_high,
                      edx=offset_low,
                      esi=result,
                      edi=whence)
        return self.trustedthread.delegate(args)

    @syscall('NR_readlink')
    def readlink(self, path_ptr):
        if not self.security.readlink(path_ptr):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_readlink, ebx=path_ptr)
        return self.trustedthread.delegate(args)

    @syscall('NR_stat64')
    def stat64(self, path_ptr, addr):
        if not self.security.is_valid(path_ptr):
            return (-1, EACCES)
        path = self.peek_asciiz(path_ptr)
        if not self.security.stat64(path, addr):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_stat64,
                      ebx=path,
                      ecx=addr)
        return self.trustedthread.delegate(args)

    @syscall('NR_fstat64')
    def fstat64(self, fd, ptr):
        if not self.security.fstat(fd, ptr):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_fstat64,
                      ebx=fd,
                      ecx=ptr)
        return self.trustedthread.delegate(args)

    @syscall('NR_mmap2')
    def mmap2(self, addr, length, prot, flags, fd, pgoffset):
        if not self.security.mmap2(addr, length, prot, flags, fd, pgoffset):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_mmap2,
                      ebx=addr,
                      ecx=length,
                      edx=prot,
                      esi=flags,
                      edi=fd,
                      ebp=pgoffset)
        return self.trustedthread.delegate(args)

    @syscall('NR_mmap')
    def mmap(self, addr, length, prot, flags, fd, offset):
        if not self.security.mmap(addr, length, prot, flags, fd, offset):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_mmap,
                      ebx=addr,
                      ecx=length,
                      edx=prot,
                      esi=flags,
                      edi=fd,
                      ebp=offset)
        return self.trustedthread.delegate(args)

    @syscall('NR_brk')
    def brk(self, addr):
        if not self.security.brk(addr):
            return (-1, ENOMEM)
        args = Memory(eax=syscalls.NR_brk, ebx=addr)
        return self.trustedthread.delegate(args)

    @syscall('NR_ugetrlimit')
    def ugetrlimit(self, ptr):
        if not self.security.ugetrlimit(ptr):
            return (-1, EPERM)
        args = Memory(eax=syscalls.NR_ugetrlimit, ebx=ptr)
        return self.trustedthread.delegate(args)

    @syscall('NR_munmap')
    def munmap(self, addr, length):
        if not self.security.munmap(addr, length):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_munmap,
                      ebx=addr,
                      ecx=length)
        return self.trustedthread.delegate(args)

    @syscall('NR_rt_sigaction')
    def rt_sigaction(self, signum, ptr, oldptr):
        ## signals will never be supported so we cross our fingers and
        ## let the caller believe the syscall succeed
        return 0

    @syscall('NR_sigaction')
    def sigaction(self, signum, ptr, oldptr):
        ## signals will never be supported so we cross our fingers and
        ## let the caller believe the syscall succeed
        return 0

    @mux_syscall('NR_socketcall', 'SYS_SOCKET')
    def _socket(self, domain, type, protocol):
        if not self.security.socket(domain, type, protocol):
            return (-1, EACCESS)
        args = Memory(eax=syscalls.NR_socketcall,
                      ebx=constants.SYS_SOCKET,
                      ecx=struct.pack('3I', domain, type, protocol))
        return self.trustedthread.delegate(args)

    @mux_syscall('NR_socketcall', 'SYS_CONNECT')
    def _connect(self, sockfd, addr_ptr, addrlen):
        if not self.security.connect(sockfd, addr_ptr, addrlen):
            return (-1, EACCESS)
        tubelog.debug(hex(addr_ptr))
        addr = self.peek_memory(addr_ptr, addrlen)
        ptr  = self.trustedthread.push_volatile(addr)
        structure = struct.pack('III', sockfd, ptr, addrlen)
        args = Memory(eax=syscalls.NR_socketcall,
                      ebx=constants.SYS_CONNECT,
                      ecx=structure)
        return self.trustedthread.delegate(args)

    @mux_syscall('NR_socketcall', 'SYS_RECVMSG')
    def _recvmsg(self, sockfd, ptr, flags):
        if not self.security.is_valid(ptr, sizeof.sockaddr):
            return (-1, EACCESS)
        buf = self.peek_memory(ptr, 28) # XXX sizeof(struct msghdr)
        if not self.security.recvmsg(sockfd, buf, flags):
            return (-1, EACCESS)
        ptr = self.trustedthread.push_volatile(buf)
        structure = struct.pack('III', sockfd, ptr, flags)
        args = Memory(eax=syscalls.NR_socketcall,
                      ebx=constants.SYS_RECVMSG,
                      ecx=structure)
        return self.trustedthread.delegate(args)

    @mux_syscall('NR_socketcall', 'SYS_SENDTO')
    def _sendto(self, sockfd, ptr, buflen, flags):
        if not self.security.is_valid(ptr, buflen):
            return (-1, EACCESS)
        buf = self.peek_memory(ptr, buflen)
        if not self.security.sendto(sockfd, buf, flags):
            return (-1, EACCESS)
        ptr = self.trustedthread.push_volatile(buf)
        structure = struct.pack('IIII', sockfd, ptr, buflen, flags)
        args = Memory(eax=syscalls.NR_socketcall,
                      ebx=constants.SYS_SENDTO,
                      ecx=structure)
        return self.trustedthread.delegate(args)

    @mux_syscall('NR_socketcall', 'SYS_BIND')
    def _bind(self, sockfd, ptr, addrlen):
        if not self.security.is_valid(ptr, addrlen):
            return (-1, EACCESS)
        addr = self.peek_memory(ptr, addrlen)
        if not self.security.bind(sockfd, addr):
            return (-1, EACCESS)
        ptr = self.trustedthread.push_volatile(addr)
        structure = struct.pack('III', sockfd, ptr, addrlen)
        args = Memory(eax=syscalls.NR_socketcall,
                      ebx=constants.SYS_BIND,
                      ecx=structure)
        return self.trustedthread.delegate(args)

    @mux_syscall('NR_socketcall', 'SYS_GETSOCKNAME')
    def _getsockname(self, sockfd, ptr, addrlen):
        if not self.security.getsockname(sockfd, ptr, addrlen):
            return (-1, EACCES)
        structure = struct.pack('III', sockfd, ptr, addrlen)
        args = Memory(eax=syscalls.NR_socketcall,
                      ebx=constants.SYS_GETSOCKNAME,
                      ecx=structure)
        return self.trustedthread.delegate(args)

    @mux_syscall('NR_socketcall', 'SYS_SOCKETPAIR')
    def _socketpair(self, domain, type, protocol, fdpair_ptr):
        if not (self.security.is_valid(fdpair_ptr, 8)
                and self.security.socket(domain, type, protocol)):
            return (-1, EACCES)
        structure = struct.pack('IIII', domain, type, protocol, fdpair_ptr)
        args = Memory(eax=syscalls.NR_socketcall,
                      ebx=constants.SYS_SOCKETPAIR,
                      ecx=structure)
        return self.trustedthread.delegate(args)

    @mux_syscall('NR_socketcall', 'SYS_LISTEN')
    def _listen(self, sockfd, backlog):
        structure = struct.pack('II', sockfd, backlog)
        args = Memory(eax=syscalls.NR_socketcall,
                      ebx=constants.SYS_LISTEN,
                      ecx=structure)
        return self.trustedthread.delegate(args)

    @mux_syscall('NR_socketcall', 'SYS_ACCEPT')
    def _accept(self, sockfd, sockadr_ptr, addrlen_ptr):
        if not self.security.is_valid(addrlen_ptr):
            return (-1, EACCES)
        addrlen = struct.unpack('I', self.peek_memory(addrlen_ptr, 4))[0]
        if not self.security.is_valid(sockadr_ptr, addrlen):
            return (-1, EACCES)
        structure = struct.pack('III', sockfd, sockadr_ptr, addrlen_ptr)
        args = Memory(eax=syscalls.NR_socketcall,
                      ebx=constants.SYS_ACCEPT,
                      ecx=structure)
        return self.trustedthread.delegate(args)

    @syscall('NR_socketcall')
    def socketcall(self, call, ptr):
        if call not in mux_syscall_tables[syscalls.NR_socketcall]:
            sandboxlog.error('socketcall(call=#%d) not implemented *************************************************************' % call)
            return 0
        func = mux_syscall_tables[syscalls.NR_socketcall][call]
        structsize = 4*func.argc
        if not self.security.is_valid(ptr, structsize):
            return (-1, EACCES)
        buf = self.peek_memory(ptr, structsize)
        args = struct.unpack('L'*func.argc, buf)
        return func(self, *args)

    @syscall('NR_time')
    def time(self, time_ptr):
        if not self.security.time(time_ptr):
            return (-1, EFAULT)
        args = Memory(eax=syscalls.NR_time, ebx=time_ptr)
        return self.trustedthread.delegate(args)

    @syscall('NR_times')
    def times(self, bufptr):
        if not self.security.times(bufptr):
            return (-1, EPERM)
        args = Memory(eax=syscalls.NR_times, ebx=tms_ptr)
        return self.trustedthread.delegate(args)

    @syscall('NR_getuid32')
    def getuid32(self):
        return 1000

    @syscall('NR_geteuid32')
    def geteuid32(self):
        return 1000

    @syscall('NR_getgid32')
    def getgid32(self):
        return 1000

    @syscall('NR_getegid32')
    def getegid32(self):
        return 1000

    @syscall('NR_epoll_create')
    def epoll_create(self, size):
        if not self.security.epoll_create(size):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_epoll_create,
                      ebx=size)
        return self.trustedthread.delegate(args)

    @syscall('NR_fcntl64')
    def fcntl64(self, fd, cmd, args_list):
        if not self.security.fcntl64(fd, cmd, args_list):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_fcntl64,
                      ebx=fd,
                      ecx=cmd,
                      edx=args_list)
        return self.trustedthread.delegate(args)

    @syscall('NR_epoll_ctl')
    def epoll_ctl(self, epollfd, op, fd, event_ptr):
        if not self.security.is_valid(event_ptr, sizeof.event):
            return (-1, EACCES)
        event = self.peek_memory(event_ptr, sizeof.event)
        args = Memory(eax=syscalls.NR_epoll_ctl,
                      ebx=epollfd,
                      ecx=op,
                      edx=fd,
                      esi=event)
        return self.trustedthread.delegate(args)

    @syscall('NR_epoll_wait')
    def epoll_wait(self, epollfd, event_ptr, max_events, timeout):
        if not self.security.is_valid(event_ptr, sizeof.event):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_epoll_wait,
                      ebx=epollfd,
                      ecx=event_ptr,
                      edx=max_events,
                      esi=timeout)
        return self.trustedthread.delegate(args)

    @syscall('NR_eventfd2')
    def eventfd2(self, initval, flags):
        args = Memory(eax=syscalls.NR_eventfd2,
                      ebx=initval,
                      ecx=flags)
        return self.trustedthread.delegate(args)

    @syscall('NR_readv')
    def readv(self, fd, iovptr, iovcnt):
        iovs = self.get_iov(iovptr, iovcnt)
        s = ''.join(iovs)
        args = Memory(eax=syscalls.NR_readv,
                      ebx=fd,
                      ecx=s,
                      edx=len(iovs))
        return self.trustedthread.delegate(args)

    @syscall('NR_writev')
    def writev(self, fd, iovptr, iovcnt):
        iovs = self.get_iov(iovptr, iovcnt)
        s = ''.join(iovs)
        args = Memory(eax=syscalls.NR_writev,
                      ebx=fd,
                      ecx=s,
                      edx=len(iovs))
        return self.trustedthread.delegate(args)

    @syscall('NR_sendfile')
    def sendfile(self, outfd, infd, offset_ptr, count):
        if not self.security.sendfile(outfd, infd, offset_ptr, count):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_sendfile,
                      ebx=outfd,
                      ecx=infd,
                      edx=offset_ptr,
                      esi=count)
        return self.trustedthread.delegate(args)

    @syscall('NR_getdents')
    def getdents(self, fd, dirp_ptr, count):
        if not self.security.is_valid(dirp_ptr, sizeof.linux_dirent):
            return (-1, EACCES)
        args = Memory(eax=syscalls.NR_getdents,
                      ebx=fd,
                      ecx=dirp_ptr,
                      edx=count)
        return self.trustedthread.delegate(args)

    def op_retval(self, ret, errno=0):
        tubelog.debug('<<< op_retval(%#x, %d)' % (ret,errno))
        self.control.write(struct.pack('III', RETVAL, ret & 0xffffffff, errno))
        return ret

    def raisetrap(self):
        self.control.write(struct.pack('I', RAISE_TRAP))

    def get_iov(self, ptr, count):
        array=[]
        while count > 0:
            iov = self.peek_memory(ptr, sizeof.iovec)
            iov_base, iov_len = struct.unpack('II', iov)
            if self.security.is_valid(iov_base, iov_len):
                array.append(iov)
            count -= 1
            ptr += sizeof.iovec
        return array

    def peek_asciiz(self, ptr):
        tubelog.debug('<<< peek_asciiz(%#x)' % ptr)
        self.control.write(struct.pack('II', PEEK_ASCIIZ, ptr))
        buf = self.control.read(4)
        nbytes = struct.unpack('I', buf)[0]
        tubelog.debug('    Waiting for %d bytes' % nbytes)
        buf = self.control.read(nbytes)
        tubelog.debug('>>> ' + buf)
        return buf

    def peek_memory(self, ptr, length):
        tubelog.debug('<<< peek_memory(%#x, %d)' % (ptr, length))
        self.control.write(struct.pack('III', PEEK_MEMORY, ptr, length))
        buf = self.control.read(length)
        tubelog.debug('>>> ' + buf.encode('hex'))
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
            if type(ret) is tuple:
                ret,errno=ret
            else:
                errno=0
            self.op_retval(ret, errno)
        else:
            tubelog.error('Unknown message type: %#x' % msgtype)

    def run(self):
        while True:
            buf = os.read(CONTROL_FD, 4)
            if not buf:
                break
            self.dispatcher(buf)

if __name__ == '__main__':
    lvl = os.environ.get('SECCOMP_NURSE_LOGLEVEL', '').upper()
    if lvl in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        lvl = getattr(logging, lvl)
    else:
        lvl = logging.ERROR
    logging.basicConfig(level=lvl,
                        format="%(name)15.15s %(levelname)5s: %(message)s")
    mainlog    = logging.getLogger("trusted")
    sandboxlog = logging.getLogger("sandbox.action")
    tubelog    = logging.getLogger("sandbox.tube")

    sandbox = HybridSandbox()
    try:
        sandbox.run()
    except KeyboardInterrupt:
        # kill all processes of my session group and myself
        os.kill(0, 9)

