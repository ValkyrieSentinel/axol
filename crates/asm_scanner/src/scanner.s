.intel_syntax noprefix
.global scan_pattern_asm
.text

# Arguments:
# RDI = buffer pointer
# RSI = buffer length
# RDX = pattern pointer
# RCX = pattern length
# Returns: RAX = offset if found, -1 if not found
scan_pattern_asm:
    push rbx
    push r12
    push r13

    mov r8, rdi
    mov r12, rsi
    mov r13, rcx

.L_outer_loop:
    cmp r12, r13
    jl .L_not_found

    mov r9, rdi
    mov r10, rdx
    mov rcx, r13

.L_inner_loop:
    mov al, byte ptr [r9]
    mov bl, byte ptr [r10]
    cmp al, bl
    jne .L_next_position
    inc r9
    inc r10
    dec rcx
    jnz .L_inner_loop

    mov rax, rdi
    sub rax, r8
    jmp .L_done

.L_next_position:
    inc rdi
    dec r12
    jmp .L_outer_loop

.L_not_found:
    mov rax, -1

.L_done:
    pop r13
    pop r12
    pop rbx
    ret