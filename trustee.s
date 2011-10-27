        .section .text

/**
 * wait_for_trigger() - wait for order
 *
 * This routine is blocking on a read() on the control socket, when
 * 4 bytes are read, this is the signal that the syscall drop box is
 * ready and can be executed.
 *
 * We don't care about the incoming bytes, this is just a "signal",
 * that is why we provide NULL to read(). See commit e0055906f1e
 *
 */
wait_for_trigger:

loop_read:
        movl $3, %ebx
        mov  $0, %ecx
        movl $4, %edx
        movl $3, %eax
        int $0x80           /* read(3, NULL, 4) */

        cmpl $0, %eax
        jle out

        jmp execute_syscall
execute_syscall_end:
        jmp loop_read

out:
        jmp fatal

/**
 * execute_syscall() - execute syscall written in shared area
 *
 * %eax to %edi registers values are extracted from the protected
 * area 'syscall_dropbox' which is only writable by the trusted
 * process.
 *
 */
execute_syscall:
        movd %mm1, %edi
        movl  0(%edi), %eax
        movl  4(%edi), %ebx
        movl  8(%edi), %ecx
        movl 12(%edi), %edx
        movl 16(%edi), %esi
        movl 24(%edi), %ebp
        movl 20(%edi), %edi
        int $0x80

        movl %eax, %esi
        movl $4, %edi

loop_end:
        cmp $0, %edi
        jle real_end
        
        movl $4, %eax
        movl $3, %ebx
        mov %esi, %edx
        andl $0xff, %edx
        movd %mm2, %ecx
        leal 0(%ecx, %edx, 1), %ecx
        movl $1, %edx
        shrl $8, %esi
        int $0x80
        decl %edi
        jmp loop_end
        
real_end:
        jmp execute_syscall_end


/**
 * disable_signals() - block all signals
 *
 */
disable_signals:
        movl $126, %eax         /* __NR_sigprocmask */
        movl $0, %ebx           /* how = SIG_BLOCK */
        movd %mm2, %edx
        lea 256(%edx), %ecx     /* set */
        movl $0, %edx           /* oldset = NULL */
        int $0x80
        test %eax, %eax
        jnz fatal
        movl $175, %eax         /* __NR_rt_sigprocmask */
        movd %mm2, %edx
        lea 256(%edx), %ecx     /* set */
        movl $0, %edx           /* oldset = NULL */
        movl $8, %esi           /* sigsetsize=sizeof(sigset_t) */
        int $0x80
        test %eax, %eax
        jnz fatal
        jmp go_wait

/**
 * trustee() - companion thread
 *
 */
        .global trustee
trustee:
        jmp disable_signals
go_wait:
        jmp wait_for_trigger

fatal:
        movl $252, %eax
        movl $1, %ebx
        int $0x80
infinite:
        jmp infinite
