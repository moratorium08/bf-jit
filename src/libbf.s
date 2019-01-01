.intel_syntax noprefix
.global bf_read_fun
bf_read_fun:
	push r10
	push r11
	push rbx
	push rcx
	xor rax, rax
	xor rdi, rdi
	mov rsi, rbx
	mov rdx, 1
	syscall
	pop rcx
	pop rbx
	pop r11
	pop r10
    ret
.global bf_write_fun
bf_write_fun:
	push r10
	push r11
	push rbx
	push rcx
	mov rax, 1
	mov rdi, 1
	mov rsi, rbx
	mov rdx, 1
	syscall
	pop rcx
	pop rbx
	pop r11
	pop r10
    ret
