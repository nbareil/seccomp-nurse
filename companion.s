        .section .text

        .global range_start
        .global range_end
        .global junk_zone
        .global syscall_dropbox
        .global retarray

/**
 * wait_for_trigger() - wait for order
 *
 * This routine is blocking on a read() on the control socket, when
 * 4 bytes are read, this is the signal that the syscall drop box is
 * ready and can be executed.
 *
 * The buffer where bytes are written is the junk zone, theses bytes
 * are undefined and must be ignored.
 *
 */
wait_for_trigger:

loop_read:
        movl $3, %ebx
        movl $junk_zone, %ecx
        movl $4, %edx           ; JUNK_SIZE=4
        movl $3, %eax
        int $0x80

        cmpl $0, %eax
        jle out

        call execute_syscall
        jmp loop_read

out:
        int3
        ret

/**
 * execute_syscall() - execute syscall written in shared area
 *
 * %eax to %edi registers values are extracted from the protected
 * area 'syscall_dropbox' which is only writable by the trusted
 * process.
 *
 */
execute_syscall:
        mov syscall_dropbox, %edi
        movl  0(%edi), %eax
        movl  4(%edi), %ebx
        movl  8(%edi), %ecx
        movl 12(%edi), %edx
        movl 16(%edi), %esi
        movl 20(%edi), %edi
        int $0x80

        movl %eax, %esi
        movl $4, %edi

loop_ret:
        cmp $0, %edi
        jle real_ret
        
        mov %esi, %edx
        andl $0xff, %edx
        movl $4, %eax
        movl $3, %ebx
        lea retarray(%edx), %ecx
        movl $1, %edx
        shrl $8, %esi
        int $0x80
        decl %edi
        jmp loop_ret
        
real_ret:
        ret

/**
 * companion_routine() - companion thread
 *
 */
        .global companion_routine
companion_routine:
        movl range_start, %eax
        call wait_for_trigger
        ret
