.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here
pushl $0xc001f00d
pushl $0x00c105ed
pushl $0xacce55ed
call practice

leave
ret
