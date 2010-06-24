#! /usr/bin/env python

import os, struct

REGISTERS_DROPBOX_LEN = 7*4

def range2tuple(s):
    return map(lambda x: int(x, 16), s.split('-'))

class TrustedThread(object):
    def __init__(self, pid, fd, mapping):
        self.pid = pid
        self.mapping = mapping
        self.freespace_start = REGISTERS_DROPBOX_LEN
        self.thread  = os.fdopen(fd, 'w+')
        mm_start = struct.unpack('I', self.thread.read(4))[0]
        mm_end   = struct.unpack('I', self.thread.read(4))[0]
        self.ro_area = (mm_start, mm_end)

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
        self.mapping[:len(raw)] = raw

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
        self.freespace_start = REGISTERS_DROPBOX_LEN
        self.mapping[:] = '\x00'*self.mapping.size()
