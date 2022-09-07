.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here
pushl	$0x0
pushl	$0x646F6F66
pushl	$0x6C6F6F63
movl	%esp, %eax
pushl	$0xc105ed
movl	%esp, %ecx
pushl	%eax
pushl	%ecx
pushl	$0xacce55ed
call	practice

leave
ret
