.text

.type xclone, "function"
.type xmmap, "function"
.type xsyscall3, "function"

.globl xclone
.globl xmmap
.globl xsyscall3

#include <sys/syscall.h>

/*
** EBP+8  SYSCALL_NR
** EBP+12 ARG1
** EBP+16 ARG2
** EBP+20 ARG3
*/
xsyscall3:
        push    %ebp
        mov     %esp, %ebp
        push    %ebx
        push    %ecx
        mov      8(%ebp), %eax
        mov     12(%ebp), %ebx
        mov     16(%ebp), %ecx
        mov     20(%ebp), %edx
        int     $0x80
        pop     %ecx
        pop     %ebx
        pop     %ebp
        ret

/*
** EBP+8  fn
** EBP+12 child_stack
** EBP+16 flags
** EBP+20 arg
*/
xclone:
        push    %ebp
        mov     %esp, %ebp
        push    %ebx
        push    %ecx
        push    %esi
        push    %edi

        mov     20(%ebp), %edx
        mov     16(%ebp), %ebx
        mov     12(%ebp), %ecx
        sub     $4, %ecx
        mov     8(%ebp), %eax
        mov     %eax, (%ecx)
        mov     $SYS_clone, %eax
        xor     %esi, %esi
        xor     %edi, %edi
        int     $0x80
        test    %eax, %eax
        jnz     __daron
__gamin:
        pop     %eax
        jmp     *%eax
__daron:
        pop     %edi
        pop     %esi
        pop     %ecx
        pop     %ebx
        pop     %ebp
        ret

/*
** EBP+8  addr
** EBP+12 length
** EBP+16 prot
** EBP+20 flags
** EBP+24 fd
** EBP+28 offset
*/
xmmap:
        push    %ebp
        mov     %esp, %ebp

        push    %ebx
        push    %ecx
        push    %esi
        push    %edi

        mov     8(%ebp),  %ebx
        mov     12(%ebp), %ecx
        mov     16(%ebp), %edx
        mov     20(%ebp), %esi
        mov     24(%ebp), %edi
        mov     28(%ebp), %ebp
        mov     $SYS_mmap2, %eax
        int     $0x80
        pop     %edi
        pop     %esi
        pop     %ecx
        pop     %ebx
        pop     %ebp
        ret
