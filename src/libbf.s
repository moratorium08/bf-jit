.intel_syntax noprefix
.global bf_read_fun
bf_read_fun:
	xor rax, rax
	xor rdi, rdi
	mov rsi, rbx
	mov rdx, 1
	syscall
    ret
.global bf_write_fun
bf_write_fun:
	mov rax, 1
	mov rdi, 1
	mov rsi, rbx
	mov rdx, 1
	syscall
    ret
