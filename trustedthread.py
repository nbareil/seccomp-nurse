#! /usr/bin/env python

import os, struct

## mimics the sharepoint structure in inject.h
SPACE_SIZE=512
OFFSET_OF_SPACE           = 0
OFFSET_OF_SYSCALL_DROPBOX = OFFSET_OF_SPACE+SPACE_SIZE
OFFSET_OF_JUNK            = OFFSET_OF_SYSCALL_DROPBOX + 28
OFFSET_OF_RETARRAY        = OFFSET_OF_JUNK + 4
OFFSET_OF_SIGSET          = OFFSET_OF_RETARRAY+256
END_STRUCTURE             = OFFSET_OF_SIGSET+32*4

def range2tuple(s):
    return map(lambda x: int(x, 16), s.split('-'))

class TrustedThread(object):
    def __init__(self, pid, fd, mapping):
        self.pid = pid
        self.freespace_start = 0
        self.mapping=mapping
        self.fill_retbytes()
        self.thread  = os.fdopen(fd, 'w+')
        sharespace = struct.unpack('I', self.thread.read(4))[0]
        self.ro_area = (sharespace, sharespace+END_STRUCTURE)

    def fill_retbytes(self):
        self.mapping[OFFSET_OF_RETARRAY:OFFSET_OF_RETARRAY+256] = struct.pack('256B', *range(0, 256))
        self.mapping[OFFSET_OF_SIGSET:OFFSET_OF_SIGSET+4] = struct.pack('I', 0x7fffffff)
        self.mapping[OFFSET_OF_SIGSET+4:OFFSET_OF_SIGSET+8] = struct.pack('I', 0xfffffffe)
        self.mapping[OFFSET_OF_SIGSET+8:OFFSET_OF_SIGSET+8+4*30] = '\xff'*(4*30)

    def delegate(self, mm, willexit=False):
        for name in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']:
            value = getattr(mm, name)
            if isinstance(value, str):
                ptr = self.push_volatile(value)
                setattr(mm, name, ptr)
        self.push_registers(mm)
        self.wakeup()
        if not willexit:
            ret = struct.unpack('I', self.thread.read(4))[0]
            self.forget()            
            return ret

    def mappings(self):
        maps=[]
        for line in open('/proc/' + self.pid + '/maps', 'r'):
            fields = filter(lambda x: x, line[:-1].split(' '))
            (memrange, perms, offset, dev, inode) = fields[:5]
            name = (' '.join(fields[5:]) if len(fields) > 5 else '')
            maps.append([name, memrange, perms, inode])
        return maps

    def get_protected_sections(self):
        sandboxedapp = os.readlink('/proc/' + self.pid + '/exe')
        for mm in self.mappings():
            if mm[0] == sandboxedapp:
                return (self.ro_area, range2tuple(mm[1]))

    def push_registers(self, mm):
        raw = mm.pack()
        ptr=OFFSET_OF_SYSCALL_DROPBOX
        self.mapping[ptr:ptr+len(raw)] = raw

    def wakeup(self):
        self.thread.write('PING')
        self.thread.flush()

    def push_volatile(self, value):
        start = self.freespace_start
        end   = start + len(value)
        if end-start > self.mapping.size():
            raise Exception('Not enought memory to store value argument')
        self.mapping[start:end] = value
        self.freespace_start = end
        return start+self.ro_area[0]

    def forget(self):
        """
        syscall has been performed, we can now "free" the memory.

        """
        self.freespace_start = 0
        self.mapping[:OFFSET_OF_JUNK] = '\x00'*OFFSET_OF_JUNK
