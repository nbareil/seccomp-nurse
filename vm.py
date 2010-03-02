#! /usr/bin/env python

class MemoryException(Exception):
    pass

THRESHOLD_FRAGMENTATION_NEEDED=4096*1024

class Chunk:
    def __init__(self, addr, size, status):
        self.size   = size
        self.addr   = addr
        self.next   = None
        self.prev   = None
        self.status = status

    def find_freechunk(self, size):
        if self.status == 'F' and self.size >= size:
            if self.size - size >= THRESHOLD_FRAGMENTATION_NEEDED:
                c = self.splitme(size)
                if c.next and c.next.is_free():
                    c.merge()
            self.status = 'A'
            return self
        else:
            if self.next:
                return self.next.find_freechunk(size)
        return None

    def splitme(self, size, withstatus='F'):
        new = Chunk(self.addr+size, self.size-size, withstatus)
        self.size = size
        new.next = self.next
        self.next = new
        return new

    def merge(self):
        c = self.next
        while c and c.is_free():
            self.size += c.size
            c = c.next
        self.next = c

    def free(self, addr, length):
        self.status = 'F'
        if self.size != length:
            raise MemoryException('Unmapping of partial chunk is not implemented')
        self.merge()

    def is_free(self):
        return self.status == 'F'

    def contains(self, addr):
        return self.addr <= addr < (self.addr+self.size)

    def __repr__(self):
        return 'Chunk addr=%#x size=%dM status=%c has_next=%s' % (self.addr,
                                                                 self.size/1024/1024,
                                                                 self.status,
                                                                 self.next != None)

class MemoryManager(object):
    def __init__(self, addr, size):
        # if size % 4096 != 0:
        #    raise MemoryException('Size not page-aligned')
        self.pool = Chunk(addr, size, 'F')

    def allocate(self, chunksize):
        # if chunksize % 4096 != 0:
        #     raise MemoryException('Size not page-aligned')
        chunk = self.pool.find_freechunk(chunksize)
        return chunk

    def free(self, addr, length):
        current = self.pool
        while current:
            if current.contains(addr):
                current.free(addr, length)
            current = current.next

    def show(self):
        chunk = self.pool
        while chunk:
            print chunk
            chunk = chunk.next

class VirtualMemory:
    def __init__(self, size):
        self.mm   = None
        self.size = size

    def new_mapping(self, addr, length, prot, flags):
        if not self.mm:
            raise MemoryException('Memory not initialized yet')
        chunk = self.mm.allocate(length)
        return chunk.addr

    def release_mapping(self, addr, length):
        pass

    def set_pool_addr(self, addr):
        self.mm = MemoryManager(addr, self.size)
