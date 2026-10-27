.text
.globl nba16_guest_sysctl_syscall_thunk
.def nba16_guest_sysctl_syscall_thunk; .scl 2; .type 32; .endef
nba16_guest_sysctl_syscall_thunk:
    movq (%rsp), %rax
    movq %rax, nba16_guest_sysctl_guest_caller(%rip)
    movq 8(%rsp), %rax
    movq %rax, nba16_guest_sysctl_actual_caller(%rip)
    subq $8, %rsp
    callq nba16_guest_sysctl_dispatch
    movq %rax, nba16_guest_sysctl_syscall_last_rax(%rip)
    addq $8, %rsp
    testq %rax, %rax
    js 1f
    clc
    retq
1:
    negl %eax
    stc
    retq

.globl nba16_guest_virtual_query_thunk
.def nba16_guest_virtual_query_thunk; .scl 2; .type 32; .endef
nba16_guest_virtual_query_thunk:
    movq (%rsp), %rax
    movq %rax, nba16_guest_virtual_query_guest_caller(%rip)
    movq 16(%rsp), %rax
    movq %rax, nba16_guest_virtual_query_parent_caller(%rip)
    subq $8, %rsp
    callq guest_virtual_query
    addq $8, %rsp
    testl %eax, %eax
    js 2f
    clc
    retq
2:
    negl %eax
    stc
    retq
