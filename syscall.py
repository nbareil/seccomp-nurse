import string

class SyscallParameter(object):
    def __init__(self, vartype, name, writable=False, pointer=False):
        self.vartype = vartype
        self.name    = name
        self.writable = writable
        self.pointer  = pointer

    def __repr__(self):
        return '%s / %s;' % (self.vartype, self.name)


    def to_py(self):
        s= "%s('%s', '%s'" % (self.__class__.__name__, self.vartype, self.name)    
        if self.writable:
            s += ', writable=True'
        if self.pointer:
            s += ', pointer=True'
        return s+ ')'

__param_registers = [ 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp' ]

class ParametersManager(object):
    def __init__(self, params=[]):
        self.params = params

    def add(self, p):
        if len(self.params) >= len(__param_registers):
            raise Exception('Too many parameters, this is not implemented!')
        return self.params.append(p)

    def 

# class SyscallMetaClass(type):
#     args = None

#     def __new__(meta, name, bases, attr):
#         return type.__new__(meta, name, bases, attrs)


class Syscall(object):
    def __init__(self, name, arguments, nr=-1):
        self.name = name
        self.args = arguments
        self.nr   = nr

    @staticmethod
    def parse(prototypes):
        if not prototypes.startswith('SYSCALL_DEFINE'):
            raise Exception('Invalid prototype')

        n = int(prototypes[14])
        params = map(string.strip, prototypes[16:-1].split(','))
        syscallname = params[0]
        i=1
        args=[]
        while i < n*2:
            args.append(SyscallParameter(params[i], 
                                         params[i+1],
                                         pointer='*' in params[i]))
            i+=2
        return Syscall(syscallname, args)

    def __getattr__(self, attr):
        if attr in self.args


    def __repr__(self):
        return '''
class Syscall_%s(Syscall):
	name = "%s"
	nr   = %d
	args = [ %s ]''' % (self.name, self.name,
                            self.nr,
                            ',\n\t\t '.join(map(lambda x: x.to_py(),
                                                self.args)))


if __name__ == '__main__':
    s='SYSCALL_DEFINE5(osf_getsysinfo, unsigned long, op, void __user *, buffer,unsigned long, nbytes, int __user *, start, void __user *, arg)'
    print
    print Syscall.parse(s)
