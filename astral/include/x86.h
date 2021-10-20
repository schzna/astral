#ifndef INCLUDED_X86_HEADER
#define INCLUDED_X86_HEADER

#include "code.h"
#include "error.h"
#include <stdbool.h>
#include <stddef.h>

#define none (bit_size)(-1)

#define bitsize_border8 256
#define bitsize_border16 65536
#define bitsize_border32 4294967296

//assembler mode
typedef enum
{
    x32,
    compatibility,
    x64
} mode_type;

//bit size type
typedef enum
{
    b8,
    b16,
    b32,
    b64
} bit_size;

//register type
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
    //
    ax,
    cx,
    dx,
    bx,
    sp,
    bp,
    si,
    di,
    //
    eax,
    ecx,
    edx,
    ebx,
    esp,
    ebp,
    esi,
    edi,
    //
    rax,
    rcx,
    rdx,
    rbx,
    rsp,
    rbp,
    rsi,
    rdi,
    //
    r8l,
    r9l,
    r10l,
    r11l,
    r12l,
    r13l,
    r14l,
    r15l,
    //
    r8w,
    r9w,
    r10w,
    r11w,
    r12w,
    r13w,
    r14w,
    r15w,
    //
    r8d,
    r9d,
    r10d,
    r11d,
    r12d,
    r13d,
    r14d,
    r15d,
    //
    r8,
    r9,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,
    //
    spl = 68,
    bpl,
    sil,
    dil,
    //
    u_sp = 76,
    u_bp,
    u_si,
    u_di,
    //
    u_esp = 84,
    u_ebp,
    u_esi,
    u_edi,
    //
    es,
    cs,
    ss,
    ds,
    fs,
    gs
} reg;

//alias for immediate size types
typedef char imm8_type;
typedef short imm16_type;
typedef int imm32_type;
typedef long long imm64_type;

//judge compatibility between the form and an immediate value
bool match_size_imm(long long imm, bit_size size)
{
    switch (size)
    {
    case b8:
        return (imm < bitsize_border8);
    case b16:
        return (imm < bitsize_border16);
    case b32:
        return (imm < bitsize_border32);
    case b64:
        return true;
    }
    return false;
}

//operand indicator type
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

//operand type
typedef enum
{
    oprand_address,
    oprand_imm,
    oprand_reg
} operand_type;

//mnemonics
typedef enum
{
    opcode_aaa,
    opcode_aad,
    opcode_aam,
    opcode_aas,
    opcode_adc,
    opcode_add
} opecode_type;

//immediate entity
typedef union
{
    imm8_type imm8;
    imm16_type imm16;
    imm32_type imm32;
    imm64_type imm64;
} imm_union;

//immediate type
typedef struct
{
    imm_union entity;
    bit_size size;
} immediate;

//used for generating modr/m
int value_reg(reg r)
{
    return ((int)r) % 8;
}

//size of register
bit_size size_reg(reg r)
{
    if (r % 32 < 8)
    {
        return b8;
    }
    if (r % 32 < 16)
    {
        return b16;
    }
    if (r % 32 < 24)
    {
        return b32;
    }
    if (r % 32 < 32)
    {
        return b64;
    }
    return none;
}

//validate a register variable
void valid_reg(reg r)
{
    if (!(0 <= r && r < 94))
    {
        error_msg(global_error, "regsiter is not valid");
    }
}

//address type
typedef struct
{
    int scale;
    reg base, index;
    long long addr; // if absolute this is an absolute addr, otherwise this is a displacement
    bool absolute;
} address;

bit_size size_addr(address addr)
{
    return size_reg(addr.base);
}

bool match_addr_one(address addr, reg r)
{
    return (addr.base == r);
}

bool match_addr_two(address addr, reg r1, reg r2)
{
    return (addr.base == r1 && addr.index == r2) || (addr.base == r2 && addr.index == r1);
}

bool match_addr_full(address addr, reg base, reg index, int scale)
{
    return (addr.base == base && addr.index == index && addr.scale == scale);
}

void valid_addr(address addr)
{
    if (addr.base != (reg)none && addr.index != (reg)none)
    {
        if (size_reg(addr.base) != size_reg(addr.index))
        {
            error_msg(global_error, "invalid effective");
        }
        if (!(addr.scale == 1 || addr.scale == 2 || addr.scale == 4 || addr.scale == 8))
        {
            error_msg(global_error, "invalid scale");
        }
    }
}

typedef union
{
    address addr;
    immediate imm;
    reg r;
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

operand x86_make_operand_reg(reg r)
{
    operand res;
    res.type = oprand_reg;
    res.entity.r = r;
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

operands_format x86fmt_no = {.size = 0, .form1 = (operand_indicator)none, .form2 = (operand_indicator)none};

operands_format x86fmt_al_imm8 = {.size = 2, .form1 = r_al, .form2 = imm8};
operands_format x86fmt_ax_imm16 = {.size = 2, .form1 = r_ax, .form2 = imm16};
operands_format x86fmt_eax_imm32 = {.size = 2, .form1 = r_eax, .form2 = imm32};
operands_format x86fmt_rax_imm64 = {.size = 2, .form1 = r_rax, .form2 = imm64};
operands_format x86fmt_rax_imm32 = {.size = 2, .form1 = r_rax, .form2 = imm32};

operands_format x86fmt_imm8 = {.size = 1, .form1 = imm8};

operands_format x86fmt_rm8_imm8 = {.size = 2, .form1 = rm8, .form2 = imm8};
operands_format x86fmt_rm16_imm16 = {.size = 2, .form1 = rm16, .form2 = imm16};
operands_format x86fmt_rm32_imm32 = {.size = 2, .form1 = rm32, .form2 = imm32};
operands_format x86fmt_rm64_imm64 = {.size = 2, .form1 = rm64, .form2 = imm64};
operands_format x86fmt_rm64_imm32 = {.size = 2, .form1 = rm64, .form2 = imm32};

operands_format x86fmt_rm16_imm8 = {.size = 2, .form1 = rm16, .form2 = imm8};
operands_format x86fmt_rm32_imm8 = {.size = 2, .form1 = rm32, .form2 = imm8};
operands_format x86fmt_rm64_imm8 = {.size = 2, .form1 = rm64, .form2 = imm8};

operands_format x86fmt_rm8_r8 = {.size = 2, .form1 = rm8, .form2 = reg8};
operands_format x86fmt_rm16_r16 = {.size = 2, .form1 = rm16, .form2 = reg16};
operands_format x86fmt_rm32_r32 = {.size = 2, .form1 = rm32, .form2 = reg32};
operands_format x86fmt_rm64_r64 = {.size = 2, .form1 = rm64, .form2 = reg64};

operands_format x86fmt_r8_rm8 = {.size = 2, .form1 = reg8, .form2 = rm8};
operands_format x86fmt_r16_rm16 = {.size = 2, .form1 = reg16, .form2 = rm16};
operands_format x86fmt_r32_rm32 = {.size = 2, .form1 = reg32, .form2 = rm32};
operands_format x86fmt_r64_rm64 = {.size = 2, .form1 = reg64, .form2 = rm64};

typedef struct
{
    bool sib;
    bool modrm;
    int rm_i, imm_i, reg_i;
    bit_size imm_type;
    int digit;
} inst_info;

bool x86_match_oprand(operand_indicator form, operand oprand)
{
    if (oprand.type == oprand_reg)
    {
        switch (size_reg(oprand.entity.r))
        {
        case b8:
            if (oprand.entity.r == al && form == r_al)
                return true;
            return (form == rm8 || form == reg8);
            break;
        case b16:
            if (oprand.entity.r == ax && form == r_ax)
                return true;
            return (form == rm16 || form == reg16);
            break;
        case b32:
            if (oprand.entity.r == eax && form == r_eax)
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
        switch (form)
        {
        case imm8:
            return match_size_imm(oprand.entity.imm.entity.imm64, b8);
        case imm16:
            return match_size_imm(oprand.entity.imm.entity.imm64, b16);
        case imm32:
            return match_size_imm(oprand.entity.imm.entity.imm64, b32);
        case imm64:
            return match_size_imm(oprand.entity.imm.entity.imm64, b64);
        default:
            break;
        }
    }
    if (oprand.type == oprand_address)
    {
        switch (size_addr(oprand.entity.addr))
        {
        case b8:
            return form == rm8 || form == m8;
            break;
        case b16:
            return form == rm16 || form == m16;
            break;
        case b32:
            return form == rm32 || form == m32;
            break;
        case b64:
            return form == rm64 || form == m64;
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
    inst_info fmt;
    bytes code;
} pair_code_fmt;

pair_code_fmt x86_encode_opcode(mode_type mode, opecode_type opcode, operands oprands)
{
    pair_code_fmt res;
    res.fmt.imm_type = none;
    res.fmt.sib = false;
    res.fmt.reg_i = -1;
    res.fmt.rm_i = -1;
    res.fmt.digit = -1;
    res.fmt.modrm = true;

    bool flag_x64 = false;
    bool flag_comp = false;

    bool matched = false;

    if (opcode == opcode_aaa)
    {
        if (x86_match_oprands(x86fmt_no, oprands))
        {
            matched = true;
            flag_comp = true;
            res.code = make_bytes_one(0x37);
        }
    }
    else if (opcode == opcode_aad)
    {
        if (x86_match_oprands(x86fmt_imm8, oprands))
        {
            matched = true;
            flag_comp = true;
            res.code = make_bytes_one(0xd5);
            res.fmt.imm_i = 0;
            res.fmt.imm_type = b8;
        }
        else if (x86_match_oprands(x86fmt_no, oprands))
        {
            matched = true;
            flag_comp = true;
            res.code = make_bytes_two(0xd5, 0x0a);
        }
    }
    else if (opcode == opcode_aam)
    {
        if (x86_match_oprands(x86fmt_no, oprands))
        {
            matched = true;
            flag_comp = true;
            res.code = make_bytes_two(0xd4, 0x0a);
        }
        else if (x86_match_oprands(x86fmt_imm8, oprands))
        {
            matched = true;
            flag_comp = true;
            res.code = make_bytes_one(0xd4);
            res.fmt.imm_i = 0;
            res.fmt.imm_type = b8;
        }
    }
    else if (opcode == opcode_aas)
    {
        if (x86_match_oprands(x86fmt_no, oprands))
        {
            matched = true;
            flag_comp = true;
            res.code = make_bytes_one(0x3f);
        }
    }
    else if (opcode == opcode_adc)
    {
        if (x86_match_oprands(x86fmt_al_imm8, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x14);
            res.fmt.imm_type = b8;
            res.fmt.imm_i = 1;
            res.fmt.reg_i = 0;
            res.fmt.modrm = false;
        }
        else if (x86_match_oprands(x86fmt_ax_imm16, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_two(0x66, 0x15);
            res.fmt.imm_type = b16;
            res.fmt.imm_i = 1;
            res.fmt.reg_i = 0;
        }
        else if (x86_match_oprands(x86fmt_eax_imm32, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x15);
            res.fmt.imm_type = b32;
            res.fmt.imm_i = 1;
            res.fmt.reg_i = 0;
        }
        else if (x86_match_oprands(x86fmt_rax_imm32, oprands))
        {
            matched = true;
            flag_comp = false;
            flag_x64 = true;
            res.code = make_bytes_two(0x48, 0x15);
            res.fmt.imm_type = b64;
            res.fmt.imm_i = 1;
            res.fmt.reg_i = 0;
        }
        else if (x86_match_oprands(x86fmt_rm8_imm8, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x80);
            res.fmt.imm_type = b8;
            res.fmt.imm_i = 1;
            res.fmt.rm_i = 0;
            res.fmt.digit = 2;
        }
        else if (x86_match_oprands(x86fmt_rm16_imm16, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x81);
            res.fmt.imm_type = b16;
            res.fmt.imm_i = 1;
            res.fmt.rm_i = 0;
            res.fmt.digit = 2;
        }
        else if (x86_match_oprands(x86fmt_rm32_imm32, oprands))
        {

            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x81);
            res.fmt.imm_type = b32;
            res.fmt.imm_i = 1;
            res.fmt.rm_i = 0;
            res.fmt.digit = 2;
        }
        else if (x86_match_oprands(x86fmt_rm64_imm32, oprands))
        {
            matched = true;
            flag_comp = false;
            flag_x64 = true;
            res.code = make_bytes_two(0x48, 0x81);
            res.fmt.imm_type = b64;
            res.fmt.imm_i = 1;
            res.fmt.rm_i = 0;
            res.fmt.digit = 2;
        }
        else if (x86_match_oprands(x86fmt_rm8_r8, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x10);
            res.fmt.imm_type = b8;
            res.fmt.rm_i = 0;
            res.fmt.reg_i = 1;
        }
        else if (x86_match_oprands(x86fmt_rm16_r16, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x11);
            res.fmt.imm_type = b16;
            res.fmt.rm_i = 0;
            res.fmt.reg_i = 1;
        }
        else if (x86_match_oprands(x86fmt_rm32_r32, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x11);
            res.fmt.imm_type = b32;
            res.fmt.rm_i = 0;
            res.fmt.reg_i = 1;
        }
        else if (x86_match_oprands(x86fmt_rm64_r64, oprands))
        {
            matched = true;
            flag_comp = false;
            flag_x64 = true;
            res.code = make_bytes_two(0x48, 0x11);
            res.fmt.imm_type = b64;
            res.fmt.rm_i = 0;
            res.fmt.reg_i = 1;
        }
        else if (!matched && x86_match_oprands(x86fmt_r8_rm8, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x12);
            res.fmt.imm_type = b8;
            res.fmt.rm_i = 0;
            res.fmt.reg_i = 1;
        }
        else if (!matched && x86_match_oprands(x86fmt_r16_rm16, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x13);
            res.fmt.imm_type = b16;
            res.fmt.rm_i = 0;
            res.fmt.reg_i = 1;
        }
        else if (!matched && x86_match_oprands(x86fmt_r32_rm32, oprands))
        {
            matched = true;
            flag_comp = true;
            flag_x64 = true;
            res.code = make_bytes_one(0x13);
            res.fmt.imm_type = b32;
            res.fmt.rm_i = 0;
            res.fmt.reg_i = 1;
        }
        else if (!matched && x86_match_oprands(x86fmt_r64_rm64, oprands))
        {
            matched = true;
            flag_comp = false;
            flag_x64 = true;
            res.code = make_bytes_two(0x48, 0x13);
            res.fmt.imm_type = b64;
            res.fmt.rm_i = 0;
            res.fmt.reg_i = 1;
        }
    }
    else if (opcode == opcode_add)
    {
        if (x86_match_oprands(x86fmt_al_imm8, oprands))
        {
            matched = true;
            res.code = make_bytes_one(0x04);
            res.fmt.imm_i = 1;
            res.fmt.imm_type = b8;
        }
        if (x86_match_oprands(x86fmt_ax_imm16, oprands))
        {
            matched = true;
            res.code = make_bytes_two(0x66, 0x05);
            res.fmt.imm_i = 1;
            res.fmt.imm_type = b16;
        }
        if (x86_match_oprands(x86fmt_eax_imm32, oprands))
        {
            matched = true;
            res.code = make_bytes_one(0x05);
            res.fmt.imm_i = 1;
            res.fmt.imm_type = b32;
        }
    }
    if (!matched)
    {
        error_msg(global_error, "format error.");
    }
    if (mode == x64 && !flag_x64)
    {
        error_msg(global_error, "this instruction is not supported in 64bit-mode.");
    }
    if (mode == compatibility && !flag_comp)
    {
        error_msg(global_error, "this instruction is not supported in compatibility-mode.");
    }
    return res;
}

pair_code_fmt x86_gen_modrm(inst_info fmt, operands oprands)
{
    pair_code_fmt res;
    res.fmt = fmt;
    operand r = oprands.array[fmt.reg_i];
    operand rm = oprands.array[fmt.rm_i];
    byte b = 0;
    b += ((fmt.digit == -1) ? value_reg(r.entity.r) : fmt.digit) * 8;

    if (rm.type == oprand_reg)
    {
        valid_reg(rm.entity.r);
        if (size_reg(rm.entity.r) != size_reg(r.entity.r))
        {
            error_msg(global_error, "Different size of 2 registers");
        }
        b += 0b11000000;
        b += ((fmt.digit == -1) ? value_reg(rm.entity.r) : fmt.digit);
    }
    else
    {
        valid_addr(rm.entity.addr);
        if (size_addr(rm.entity.addr) != size_reg(r.entity.r))
        {
            error_msg(global_error, "the size of effective address differs from the size of register");
        }
        address addr = rm.entity.addr;
        switch (size_addr(addr))
        {
        case b16:
            if (match_addr_two(addr, bx, si))
            {
                b += 0;
            }
            if (match_addr_two(addr, bx, di))
            {
                b += 1;
            }
            if (match_addr_two(addr, bp, si))
            {
                b += 2;
            }
            if (match_addr_two(addr, bp, di))
            {
                b += 3;
            }
            if (match_addr_one(addr, si))
            {
                b += 4;
            }
            if (match_addr_one(addr, di))
            {
                b += 5;
            }
            if (match_addr_one(addr, bp))
            {
                b += 6;
            }
            if (match_addr_one(addr, bp))
            {
                b += 7;
            }

            if (match_size_imm(addr.addr, b8))
            {
                b += 0x40;
            }
            if (match_size_imm(addr.addr, b16))
            {
                b += 0x80;
            }
            break;
        case b32:
            if (addr.index == -1)
            {
                b += value_reg(addr.base);
            }
            else
            {
                res.fmt.sib = true;
                b += 4;
            }

            if (match_size_imm(addr.addr, b8))
            {
                b += 0x40;
            }
            if (match_size_imm(addr.addr, b32))
            {
                b += 0x80;
            }
            break;
        default:
            break;
        }
    }
    res.code = make_bytes_one(b);
    return res;
}

bytes x86_gen_sib(address addr)
{
    byte res = 0;
    if (addr.scale == 2)
    {
        res += 0x40;
    }
    if (addr.scale == 4)
    {
        res += 0x80;
    }
    if (addr.scale == 8)
    {
        res += 0xc0;
    }
    res += value_reg(addr.index) * 8;
    res += value_reg(addr.base);
    return make_bytes_one(res);
}

bytes x86_encode_imm(immediate imme, bit_size size)
{
    bytes res = make_bytes(0, 0);
    long long imm = 0;
    if (size == b8)
    {
        imm = imme.entity.imm8;
        res = join_bytes(res, make_bytes_one(imm & 0xff));
        return res;
    }
    if (size == b16)
    {
        imm = imme.entity.imm16;
        res = join_bytes(res, make_bytes_two(imm & 0xff, (imm & 0xff00) / 0x100));
        return res;
    }
    if (size == b32)
    {
        imm = imme.entity.imm32;
        res = join_bytes(res, make_bytes_two(
            imm & 0x000000ff,
            (imm & 0x0000ff00) / 0x100
        ));
        res = join_bytes(res, make_bytes_two(
            (imm & 0x00ff0000) / 0x10000,
            (imm & 0xff000000) / 0x1000000
        ));
        
        return res;
    }
    if (size == b64)
    {
        imm = imme.entity.imm64;
        res.len = 4;
        res = join_bytes(res, make_bytes_two(
            imm & 0x000000ff,
            (imm & 0x0000ff00) / 0x100
        ));
        res = join_bytes(res, make_bytes_two(
            (imm & 0x00ff0000) / 0x10000,
            (imm & 0xff000000) / 0x1000000
        ));
        res = join_bytes(res, make_bytes_two(
            imm & 0x000000ff00000000 / 0x100000000,
            imm & 0x0000ff0000000000 / 0x10000000000
        ));
        res = join_bytes(res, make_bytes_two(
            imm & 0x00ff000000000000 / 0x1000000000000,
            imm & 0xff00000000000000 / 0x100000000000000
        ));
        
        return res;
    }
    return res;
}

bytes x86_encode_oprands(inst_info fmt, operands oprands)
{
    bool initialized = false;
    pair_code_fmt info;
    info.fmt = fmt;
    info.code = make_bytes(0, 0);

    if ((fmt.reg_i >= 0 || fmt.rm_i >= 0) && fmt.modrm)
    {
        info = x86_gen_modrm(fmt, oprands);
    }
    if (info.fmt.sib)
    {
        if (!initialized)
        {
            initialized = true;
            info.code = x86_gen_sib(oprands.array[fmt.rm_i].entity.addr);
        }
        else
        {
            info.code = join_bytes(info.code, x86_gen_sib(oprands.array[fmt.rm_i].entity.addr));
        }
    }
    if (fmt.imm_i >= 0 && fmt.imm_i <= 1)
    {
        if (!initialized)
        {
            initialized = true;
            info.code = x86_encode_imm(oprands.array[fmt.imm_i].entity.imm, fmt.imm_type);
        }
        else
        {
            info.code = join_bytes(info.code, x86_encode_imm(oprands.array[fmt.imm_i].entity.imm, fmt.imm_type));
        }
    }
    return info.code;
}

bytes x86_assemble(mode_type mode, opecode_type opcode, operands oprands)
{
    pair_code_fmt inst_info = x86_encode_opcode(mode, opcode, oprands);
    inst_info.code = join_bytes(inst_info.code, x86_encode_oprands(inst_info.fmt, oprands));

    return inst_info.code;
}

#endif