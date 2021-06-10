#ifndef INCLUDED_X86_HEADER
#define INCLUDED_X86_HEADER

#include "code.h"
#include <stdbool.h>
#include <stddef.h>

#define none -1

#define bitsize_border8 256
#define bitsize_border16 65536
#define bitsize_border32 4294967296
#define bitsize_border64 18446744073709551616

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
    if (imm < bitsize_border8)
    {
        return b8;
    }
    if (imm < bitsize_border16)
    {
        return b16;
    }
    if (imm < bitsize_border32)
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
    opcode_aaa,
    opcode_aad,
    opcode_aam,
    opcode_aas,
    opcode_adc,
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
} imm_union;

typedef struct
{
    imm_union entity;
    bit_size size;
} immediate;

typedef struct
{
    reg_union entity;
    bit_size size;
    bool additional;
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

operand x86_make_operand_imm(bit_size size, long long val)
{
    operand res;
    res.type = oprand_imm;
    res.entity.imm.size = size;
    res.entity.imm.entity.imm64 = val;
    return res;
}

operand x86_make_operand_reg8(reg8_type reg)
{
    operand res;
    res.type = oprand_reg;
    res.entity.reg.size = b8;
    res.entity.reg.entity.r8 = reg;
    res.entity.reg.additional = false;
    return res;
}

operand x86_make_operand_reg8a(reg8a_type reg)
{
    operand res;
    res.type = oprand_reg;
    res.entity.reg.size = b8;
    res.entity.reg.entity.r8a = reg;
    res.entity.reg.additional = true;
    return res;
}

operand x86_make_operand_reg16(reg16_type reg)
{
    operand res;
    res.type = oprand_reg;
    res.entity.reg.size = b16;
    res.entity.reg.entity.r16 = reg;
    res.entity.reg.additional = false;
    return res;
}

operand x86_make_operand_reg16a(reg16a_type reg)
{
    operand res;
    res.type = oprand_reg;
    res.entity.reg.size = b16;
    res.entity.reg.entity.r16a = reg;
    res.entity.reg.additional = true;
    return res;
}

operand x86_make_operand_reg32(reg32_type reg)
{
    operand res;
    res.type = oprand_reg;
    res.entity.reg.size = b32;
    res.entity.reg.entity.r32 = reg;
    res.entity.reg.additional = false;
    return res;
}

operand x86_make_operand_reg32a(reg32a_type reg)
{
    operand res;
    res.type = oprand_reg;
    res.entity.reg.size = b32;
    res.entity.reg.entity.r32a = reg;
    res.entity.reg.additional = true;
    return res;
}

operand x86_make_operand_reg64(reg64_type reg)
{
    operand res;
    res.type = oprand_reg;
    res.entity.reg.size = b64;
    res.entity.reg.entity.r64 = reg;
    res.entity.reg.additional = true;
    return res;
}

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

operands_format x86fmt_no = {.size = 0, .form1 = none, .form2 = none};
operands_format x86fmt_al_imm8 = {.size = 2, .form1 = r_al, .form2 = imm8};
operands_format x86fmt_ax_imm16 = {.size = 2, .form1 = r_ax, .form2 = imm16};
operands_format x86fmt_eax_imm32 = {.size = 2, .form1 = r_eax, .form2 = imm32};
operands_format x86fmt_rax_imm64 = {.size = 2, .form1 = r_rax, .form2 = imm64};
operands_format x86fmt_imm8 = {.size = 1, .form1 = imm8};

typedef struct
{
    bool sib, modrm, disp;
    int addr_i, imm_i, reg_i;
    bit_size imm_type;
} inst_format;

bool x86_match_oprand(operand_indicator form, operand oprand)
{
    if (oprand.type == oprand_reg)
    {
        switch (oprand.entity.reg.size)
        {
        case b8:
            break;
        case b16:
            break;
        case b32:
            if (oprand.entity.reg.entity.r32 == eax && form == r_eax)
                return true;
            return form == reg32 || form == rm32;
            break;
        case b64:
            break;
        default:
            break;
        }
    }
    if (oprand.type == oprand_imm)
    {
        switch (size_imm(oprand.entity.imm.entity.imm64))
        {
        case b8:
            return form == imm8;
            break;
        case b16:
            return form == imm16 || form == imm8;
            break;
        case b32:
            return form == imm32 || form == imm16 || form == imm8;
            break;
        case b64:
            return form == imm64 || form == imm32 || form == imm16 || form == imm8;
            break;
        default:
            break;
        }
    }
    return false;
}

bool x86_match_oprands(operands_format form, operands oprands)
{
    if (form.size == oprands.num)
    {
        if (oprands.num == 0)
        {
            return true;
        }
        if (oprands.num == 1)
        {
            return x86_match_oprand(form.form1, oprands.array[0]);
        }
        else if (oprands.num == 2)
        {
            return x86_match_oprand(form.form1, oprands.array[0]) && x86_match_oprand(form.form2, oprands.array[1]);
        }
    }
    return false;
}

operands x86_make_operands_no()
{
    operands ops;
    ops.num = 0;
    return ops;
}

operands x86_make_operands_one(operand oprand)
{
    operands ops;
    ops.num = 1;
    ops.array[0] = oprand;
    return ops;
}

operands x86_make_operands_two(operand oprand1, operand oprand2)
{
    operands ops;
    ops.num = 2;
    ops.array[0] = oprand1;
    ops.array[1] = oprand2;
    return ops;
}

typedef struct
{
    inst_format fmt;
    bytes code;
} pair_opcode_fmt;

pair_opcode_fmt x86_encode_opcode(bit_size mode, opecode_type opcode, operands oprands)
{
    pair_opcode_fmt res;
    res.fmt.disp = false;
    res.fmt.imm_type = none;
    res.fmt.modrm = false;
    res.fmt.sib = false;

    if (opcode == opcode_aaa)
    {
        res.code = make_bytes_one(0x37);
    }
    else if (opcode == opcode_aad)
    {
        if (x86_match_oprands(x86fmt_imm8, oprands))
        {
            res.code = make_bytes_one(0xd5);
            res.fmt.imm_i = 0;
            res.fmt.imm_type = b8;
        }
        if (x86_match_oprands(x86fmt_no, oprands))
        {
            res.code = make_bytes_two(0xd5, 0x0a);
        }
    }
    else if (opcode == opcode_aam)
    {
        if (x86_match_oprands(x86fmt_no, oprands))
        {
            res.code = make_bytes_two(0xd4, 0x0a);
        }
        if (x86_match_oprands(x86fmt_imm8, oprands))
        {
            res.code = make_bytes_one(0xd4);
            res.fmt.imm_i = 0;
            res.fmt.imm_type = b8;
        }
    }
    else if (opcode == opcode_aas)
    {
        if (x86_match_oprands(x86fmt_no, oprands))
        {
            res.code = make_bytes_one(0x3f);
        }
    }
    else if (opcode == opcode_adc)
    {
        if (x86_match_oprands(x86fmt_al_imm8, oprands))
        {
            res.code = make_bytes_one(0x14);
            res.fmt.imm_type = b8;
            res.fmt.imm_i = 1;
        }
        if (x86_match_oprands(x86fmt_ax_imm16, oprands))
        {
            res.code = make_bytes_two(0x66, 0x15);
            res.fmt.imm_type = b16;
            res.fmt.imm_i = 1;
        }
        if (x86_match_oprands(x86fmt_eax_imm32, oprands))
        {
            res.code = make_bytes_one(0x15);
            res.fmt.imm_type = b32;
            res.fmt.imm_i = 1;
        }
        if (x86_match_oprands(x86fmt_rax_imm64, oprands))
        {
            res.code = make_bytes_two(0x48, 0x15);
            res.fmt.imm_type = b64;
            res.fmt.imm_i = 1;
        }
    }
    else if (opcode == opcode_add)
    {
        if (x86_match_oprands(x86fmt_al_imm8, oprands))
        {
            res.code = make_bytes_one(0x04);
            res.fmt.imm_i = 1;
            res.fmt.imm_type = b8;
        }
        if (x86_match_oprands(x86fmt_ax_imm16, oprands))
        {
            res.code = make_bytes_two(0x66, 0x05);
            res.fmt.imm_i = 1;
            res.fmt.imm_type = b16;
        }
        if (x86_match_oprands(x86fmt_eax_imm32, oprands))
        {
            res.code = make_bytes_one(0x05);
            res.fmt.imm_i = 1;
            res.fmt.imm_type = b32;
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

bytes x86_encode_imm(immediate imme, bit_size size)
{
    bytes res = make_bytes(0, 0);
    long long imm = 0;
    if (size == b8)
    {
        imm = imme.entity.imm8;
        res.len = 1;
        res.pointer = (byte *)calloc(sizeof(byte), 1);
        res.pointer[0] = imm & 0xff;
        return res;
    }
    if (size == b16)
    {
        imm = imme.entity.imm16;
        res.len = 2;
        res.pointer = (byte *)calloc(sizeof(byte), 2);
        res.pointer[0] = imm & 0x00ff;
        res.pointer[1] = (imm & 0xff00) / 0x100;
        return res;
    }
    if (size == b32)
    {
        imm = imme.entity.imm32;
        res.len = 4;
        res.pointer = (byte *)calloc(sizeof(byte), 4);
        res.pointer[3] = imm & 0x000000ff;
        res.pointer[2] = (imm & 0x0000ff00) / 0x100;
        res.pointer[1] = (imm & 0x00ff0000) / 0x10000;
        res.pointer[0] = (imm & 0xff000000) / 0x1000000;
        return res;
    }
    if (size == b64)
    {
        imm = imme.entity.imm64;
        res.len = 4;
        res.pointer = (byte *)calloc(sizeof(byte), 8);
        res.pointer[0] = imm & 0x000000ff;
        res.pointer[1] = imm & 0x0000ff00 / 0x100;
        res.pointer[2] = imm & 0x00ff0000 / 0x10000;
        res.pointer[3] = imm & 0xff000000 / 0x1000000;
        res.pointer[4] = imm & 0x000000ff00000000 / 0x100000000;
        res.pointer[5] = imm & 0x0000ff0000000000 / 0x10000000000;
        res.pointer[6] = imm & 0x00ff000000000000 / 0x1000000000000;
        res.pointer[7] = imm & 0xff00000000000000 / 0x100000000000000;
        return res;
    }
    return res;
}

bytes x86_assemble(bit_size mode, opecode_type opcode, operands oprands)
{
    bytes res;
    pair_opcode_fmt inst_info = x86_encode_opcode(mode, opcode, oprands);
    res = inst_info.code;
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
    if (inst_info.fmt.imm_type >= 0 && inst_info.fmt.imm_i >= 0 && inst_info.fmt.imm_i <= 1)
    {
        res = join_bytes(res, x86_encode_imm(oprands.array[inst_info.fmt.imm_i].entity.imm, inst_info.fmt.imm_type));
    }
    return res;
}

#endif