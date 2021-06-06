#ifndef INCLUDED_X86_HEADER
#define INCLUDED_X86_HEADER

#include "code.h"
#include <stdbool.h>
#include <stddef.h>

#define none -1

#define bitsize_border8 128
#define bitsize_border16 32768
#define bitsize_border32 2147483648
#define bitsize_border64 9223372036854775808

typedef enum
{
    b8,
    b16,
    b32,
    b64
} bit_size;

//corresponding integers are Reg Field

typedef enum
{
    al,
    cl,
    dl,
    bl,
    ah,
    ch,
    dh,
    bh,
    spl = 12,
    bpl,
    sil,
    dil
} reg8_type;

typedef enum
{
    r8l,
    r9l,
    r10l,
    r11l,
    r12l,
    r13l,
    r14l,
    r15l
} reg8a_type;

typedef enum
{
    ax,
    cx,
    dx,
    bx,
    sp,
    bp,
    si,
    di,
    u_sp = 12,
    u_bp,
    u_si,
    u_di
} reg16_type;

typedef enum
{
    r8w,
    r9w,
    r10w,
    r11w,
    r12w,
    r13w,
    r14w,
    r15w
} reg16a_type;

typedef enum
{
    eax,
    ecx,
    edx,
    ebx,
    esp,
    ebp,
    esi,
    edi,
    u_esp = 12,
    u_ebp,
    u_esi,
    u_edi
} reg32_type;

typedef enum
{
    r8d,
    r9d,
    r10d,
    r11d,
    r12d,
    r13d,
    r14d,
    r15d
} reg32a_type;

typedef enum
{
    rax,
    rcx,
    rdx,
    rbx,
    rsp,
    rbp,
    rsi,
    rdi,
    r8,
    r9,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15
} reg64_type;

//segment registers

typedef enum
{
    es,
    cs,
    ss,
    ds,
    fs,
    gs
} sreg_type;

typedef char imm8_type;
typedef short imm16_type;
typedef int imm32_type;
typedef long long imm64_type;

bit_size size_imm(long long imm)
{
    if (-bitsize_border8 <= imm && imm < bitsize_border8)
    {
        return b8;
    }
    if (-bitsize_border16 <= imm && imm < bitsize_border16)
    {
        return b16;
    }
    if (-bitsize_border32 <= imm && imm < bitsize_border32)
    {
        return b32;
    }
    return b64;
}

typedef struct
{
    reg16_type base, index;
    imm16_type disp;
} eff_addr16;

typedef struct
{
    reg32_type base, index;
    imm32_type disp;
    int scale;
} eff_addr32;

typedef struct
{
    reg64_type base, index;
    imm64_type disp;
    int scale;
} eff_addr64;

typedef enum
{
    imm8,
    imm16,
    imm32,
    imm64,
    reg8,
    reg16,
    reg32,
    reg64,
    rm8,
    rm16,
    rm32,
    rm64,
    m,
    m8,
    m16,
    m32,
    m64,
    m16c16,
    m16c32,
    m16c64,
    m16a16,
    m16a32,
    m16a64,
    m32a32,
    sreg,
    moff8,
    moff16,
    moff32,
    moff64,
    rel8,
    rel16,
    rel32,
    ptr16c16,
    ptr16c32,
    r_al,
    r_ax,
    r_eax,
    r_rax
} operand_indicator;

typedef enum
{
    oprand_address,
    oprand_imm,
    oprand_reg
} operand_type;

typedef enum
{
    opcode_add
} opecode_type;

typedef union
{
    reg8_type r8;
    reg8a_type r8a;
    reg16_type r16;
    reg16a_type r16a;
    reg32_type r32;
    reg32a_type r32a;
    reg64_type r64;
} reg_union;

typedef union
{
    imm8_type imm8;
    imm16_type imm16;
    imm32_type imm32;
    imm64_type imm64;
} immediate;

typedef struct
{
    reg_union entity;
    bit_size size;
    bit_size mode;
} registerr;

typedef struct
{
    int scale;
    registerr base, index;
    long long addr;
    bool absolute;
} address;

typedef union
{
    address addr;
    immediate imm;
    registerr reg;
} operand_union;

typedef struct
{
    operand_union entity;
    operand_type type;
} operand;

typedef struct
{
    operand array[2];
    size_t num;
} operands;

typedef struct
{
    int size;
    operand_indicator form1, form2;
} operands_format;

operands_format no = {.size = 0, .form1 = none, .form2 = none};
operands_format x86fmt_al_imm8 = {.size = 2, .form1 = r_al, .form2 = imm8};

typedef struct
{
    bool sib, modrm, disp, imm;
} inst_format;

bool x86_match_oprand(operand_indicator form, operand oprand)
{
    return false;
}

bool x86_match_oprands(operands_format form, operands oprands)
{
    return false;
}

typedef struct
{
    inst_format fmt;
    bytes code;
} pair_opcode_fmt;

pair_opcode_fmt x86_encode_opcode(opecode_type opcode, operands oprands)
{
    pair_opcode_fmt res;
    res.fmt.disp = false;
    res.fmt.imm = false;
    res.fmt.modrm = false;
    res.fmt.sib = false;

    if (opcode == opcode_add)
    {
        if (x86_match_oprands(x86fmt_al_imm8, oprands))
        {
            res.code = make_bytes_one(0x04);
            res.fmt.imm = true;
        }
    }
    return res;
}

bytes x86_gen_modrm(opecode_type opcode, operands oprands)
{
    return make_bytes(0, 0);
}

bytes x86_gen_sib(opecode_type opcode, operands oprands)
{
    return make_bytes(0, 0);
}

bytes x86_encode_imm(long long imm)
{
    return make_bytes(0, 0);
}

bytes x86_assemble(opecode_type opcode, operands oprands)
{
    bytes res;
    pair_opcode_fmt inst_info = x86_encode_opcode(opcode, oprands);
    if (inst_info.fmt.modrm)
    {
        res = join_bytes(res, x86_gen_modrm(opcode, oprands));
    }
    if (inst_info.fmt.sib)
    {
        res = join_bytes(res, x86_gen_sib(opcode, oprands));
    }
    if (inst_info.fmt.disp)
    {
    }
    if (inst_info.fmt.imm)
    {
        res = join_bytes(res, x86_encode_imm(oprands.array[0].type));
    }
    return res;
}

#endif