.global _main
.section .text

_main:

push    %ebp
mov     %esp,%ebp

# Your code here
movl	$11, %eax
pushl	$0x0068732F
pushl	$0x6E69622F
movl	%esp, %ebx
movl	$0x0, %ecx
movl	$0x0, %edx
int	$0x80

leave
ret
