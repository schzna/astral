.intel_syntax noprefix
.globl main
main:
        mov rax, 42
        mov eax, 42

        mov rax, rax
        mov rax, rbx
        mov rax, rcx
        mov rax, rdx
        mov rbx, rax
        mov rbx, rbx
        mov rbx, rcx
        mov rbx, rdx

        mov ebx, edx
        mov rbx, rdx
        mov r15, r14

        mov eax, eax
        mov eax, ebx
        mov eax, ecx
        mov eax, edx

        mov eax, [eax+ebx*4]
        mov [eax+ecx*4], eax
        add [eax+ecx*4], eax
        add [eax+ecx*4+4], eax
        mov [ebx], 0x10
        ret

