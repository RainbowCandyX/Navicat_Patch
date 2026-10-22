OPTION CASEMAP:NONE

EXTERN ResolveWinmmExport:PROC

.code

ProxyDispatch PROC FRAME
    sub rsp, 0A8h
    .allocstack 0A8h
    .endprolog
    mov [rsp+20h], rcx
    mov [rsp+28h], rdx
    mov [rsp+30h], r8
    mov [rsp+38h], r9
    mov [rsp+40h], rax
    mov [rsp+48h], r10
    movdqu [rsp+60h], xmm0
    movdqu [rsp+70h], xmm1
    movdqu [rsp+80h], xmm2
    movdqu [rsp+90h], xmm3
    mov ecx, r11d
    call ResolveWinmmExport
    mov [rsp+50h], rax
    mov rcx, [rsp+20h]
    mov rdx, [rsp+28h]
    mov r8, [rsp+30h]
    mov r9, [rsp+38h]
    mov rax, [rsp+40h]
    mov r10, [rsp+48h]
    movdqu xmm0, [rsp+60h]
    movdqu xmm1, [rsp+70h]
    movdqu xmm2, [rsp+80h]
    movdqu xmm3, [rsp+90h]
    mov r11, [rsp+50h]
    add rsp, 0A8h
    jmp r11
ProxyDispatch ENDP

CREATE_EXPORT MACRO ordinal:REQ
    PUBLIC ProxyOrdinal_&ordinal
    ProxyOrdinal_&ordinal PROC
        mov r11d, ordinal
        jmp ProxyDispatch
    ProxyOrdinal_&ordinal ENDP
ENDM

exportOrdinal = 2
REPT 181
    CREATE_EXPORT %exportOrdinal
    exportOrdinal = exportOrdinal + 1
ENDM

END
