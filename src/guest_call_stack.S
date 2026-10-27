#ifndef _WIN32
.text
.globl nba16_guest_call_void_on_stack
nba16_guest_call_void_on_stack:
#ifdef _WIN32
    # Windows x64 host ABI: RCX=function, RDX=guest stack top.
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %rdi
    pushq %rsi
    pushq %r12
    pushq %r13
    subq $184, %rsp
    movdqu %xmm6, -48(%rbp)
    movdqu %xmm7, -64(%rbp)
    movdqu %xmm8, -80(%rbp)
    movdqu %xmm9, -96(%rbp)
    movdqu %xmm10, -112(%rbp)
    movdqu %xmm11, -128(%rbp)
    movdqu %xmm12, -144(%rbp)
    movdqu %xmm13, -160(%rbp)
    movdqu %xmm14, -176(%rbp)
    movdqu %xmm15, -192(%rbp)
    movq %rcx, %r12
    movq %rdx, %r13
#else
    # System V host ABI: RDI=function, RSI=guest stack top.
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    movq %rdi, %r12
    movq %rsi, %r13
#endif
    andq $-16, %r13
    movq %r13, %rsp
    call *%r12
#ifdef _WIN32
    movdqu -48(%rbp), %xmm6
    movdqu -64(%rbp), %xmm7
    movdqu -80(%rbp), %xmm8
    movdqu -96(%rbp), %xmm9
    movdqu -112(%rbp), %xmm10
    movdqu -128(%rbp), %xmm11
    movdqu -144(%rbp), %xmm12
    movdqu -160(%rbp), %xmm13
    movdqu -176(%rbp), %xmm14
    movdqu -192(%rbp), %xmm15
    leaq -40(%rbp), %rsp
    popq %r13
    popq %r12
    popq %rsi
    popq %rdi
    popq %rbx
#else
    leaq -24(%rbp), %rsp
    popq %r13
    popq %r12
    popq %rbx
#endif
    popq %rbp
    ret
#else
.text
.globl nba16_guest_jump_to_entry
nba16_guest_jump_to_entry:
    # Windows x64 host ABI: RCX=entry, RDX=params, R8=exit,
    # R9=argv, fifth argument=argc, sixth argument=stack top.
    pushq %rbp
    movq %rsp, %rbp
    movq %rcx, %r10
    movq %rdx, %rdi
    movq %r8, %rsi
    movq 56(%rbp), %r11
    andq $-16, %r11
    movq %r11, %rsp
    call *%r10
    movq %rbp, %rsp
    popq %rbp
    ret
#endif
