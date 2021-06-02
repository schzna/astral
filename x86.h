#include <string.h>

typedef enum
{
    CD_SYSCALL,
    CD_MOV,
    CD_ADD,
    CD_SUB,
    CD_IMUL,
    CD_DIV,
    CD_PUSH,
    CD_POP,
    CD_RET,
    CD_CQO,
    CD_MOVZB,
    CD_SETE,
    CD_SETL,
    CD_SETLE,
    CD_SETNE
} x86_opecode_kind;

typedef enum
{
    OR_REG,
    OR_IMM,
    OR_MEM
} x86_operand_type;

typedef enum
{
    REG_NONE,

    REG_RAX,
    REG_EAX,
    REG_AX,
    REG_AL,

    REG_RBX,
    REG_EBX,
    REG_BX,
    REG_BL,

    REG_RCX,
    REG_ECX,
    REG_CX,
    REG_CL,

    REG_RDX,
    REG_EDX,
    REG_DX,
    REG_DL,

    REG_RSI,
    REG_ESI,
    REG_SI,
    REG_SIL,

    REG_RDI,
    REG_EDI,
    REG_DI,
    REG_DIL,

    REG_RBP,
    REG_EBP,
    REG_BP,
    REG_BPL,

    REG_RSP,
    REG_ESP,
    REG_SP,
    REG_SPL,

    REG_R8,
    REG_R8D,
    REG_R8W,
    REG_R8B,

    REG_R9,
    REG_R9D,
    REG_R9W,
    REG_R9B,

    REG_R10,
    REG_R10D,
    REG_R10W,
    REG_R10B,

    REG_R11,
    REG_R11D,
    REG_R11W,
    REG_R11B,

    REG_R12,
    REG_R12D,
    REG_R12W,
    REG_R12B,

    REG_R13,
    REG_R13D,
    REG_R13W,
    REG_R13B,

    REG_R14,
    REG_R14D,
    REG_R14W,
    REG_R14B,

    REG_R15,
    REG_R15D,
    REG_R15W,
    REG_R15B,

    REG_AH,
    REG_BH,
    REG_CH,
    REG_DH,

} x86_register_type;

typedef enum
{
    RS_NONE,
    RS_8,
    RS_16,
    RS_32,
    RS_64,
} x86_size;

typedef enum
{
    PF_NONE,
    PF_REX
} x86_prefix_type;

typedef enum
{
    LP_NONE,
    LP_OPOVR,
    LP_ADROVR
} x86_legacy_prefix_type;

x86_size x86_size_reg(x86_register_type reg)
{
    bool is_16 = reg == REG_AX;
    is_16 = is_16 || reg == REG_BX;
    is_16 = is_16 || reg == REG_CX;
    is_16 = is_16 || reg == REG_DX;
    is_16 = is_16 || reg == REG_SI;
    is_16 = is_16 || reg == REG_DI;
    is_16 = is_16 || reg == REG_SP;
    is_16 = is_16 || reg == REG_BP;

    bool is_32 = reg == REG_EAX;
    is_32 = is_32 || reg == REG_EBX;
    is_32 = is_32 || reg == REG_ECX;
    is_32 = is_32 || reg == REG_EDX;
    is_32 = is_32 || reg == REG_ESI;
    is_32 = is_32 || reg == REG_EDI;
    is_32 = is_32 || reg == REG_ESP;
    is_32 = is_32 || reg == REG_EBP;

    bool is_64 = reg == REG_RAX;
    is_64 = is_64 || reg == REG_RBX;
    is_64 = is_64 || reg == REG_RCX;
    is_64 = is_64 || reg == REG_RDX;
    is_64 = is_64 || reg == REG_RSI;
    is_64 = is_64 || reg == REG_RDI;
    is_64 = is_64 || reg == REG_RSP;
    is_64 = is_64 || reg == REG_RBP;

    if (is_16)
        return RS_16;
    if (is_32)
        return RS_32;
    if (is_64)
        return RS_64;
    return RS_NONE;
}

int x86_index_reg(x86_register_type reg)
{
    if (reg == REG_AL || reg == REG_AX || reg == REG_EAX || reg == REG_RAX)
    {
        return 0;
    }
    if (reg == REG_CL || reg == REG_CX || reg == REG_ECX || reg == REG_RCX)
    {
        return 1;
    }
    if (reg == REG_DL || reg == REG_DX || reg == REG_EDX || reg == REG_RDX)
    {
        return 2;
    }
    if (reg == REG_BL || reg == REG_BX || reg == REG_EBX || reg == REG_RBX)
    {
        return 3;
    }
    if (reg == REG_AH || reg == REG_SP || reg == REG_ESP || reg == REG_RSP)
    {
        return 4;
    }
    if (reg == REG_CH || reg == REG_BP || reg == REG_EBP || reg == REG_RBP)
    {
        return 5;
    }
    if (reg == REG_DH || reg == REG_SI || reg == REG_ESI || reg == REG_RSI)
    {
        return 6;
    }
    if (reg == REG_BH || reg == REG_DI || reg == REG_EDI || reg == REG_RDI)
    {
        return 7;
    }
    return -1;
}

typedef struct
{
    x86_operand_type type;
    x86_register_type reg;
    bool sib;
    long imm;
    x86_register_type base, index;
    int scale;
    int displacement;
} x86_operand;

x86_size x86_size_imm(long imm)
{
    x86_size res;
    if (imm > 0xffffffff)
        res = RS_64;
    else if (imm > 0xffff)
        res = RS_32;
    else if (imm > 0xff)
        res = RS_16;
    else
        res = RS_8;
    return res;
}

x86_size x86_size_oprand(x86_operand oprand)
{
    x86_size res = RS_NONE;
    switch (oprand.type)
    {
    case OR_IMM:
        res = x86_size_imm(oprand.imm);
        break;
    case OR_MEM:
        break;
    case OR_REG:
        res = x86_size_reg(oprand.reg);
        break;
    default:
        break;
    }
    return res;
}

bool x86_meet_size(x86_size target, x86_size demand)
{
    return (int)target < (int)demand;
}

typedef enum
{
    OP_NONE = -1,
    OP_0,
    OP_1,
    OP_2,
    OP_3,
    OP_4,
    OP_5,
    OP_6,
    OP_7,
    OP_R,
    OP_RD
} x86_operand_option;

#define REX_W 8
#define REX_R 4
#define REX_X 2
#define REX_B 1

typedef struct
{
    x86_prefix_type prefix;
    int rex_flag;
    x86_legacy_prefix_type legacy_prefix;
    char opcode[3];
    int opcode_size;
    int sib;
    x86_size size_imm;
    x86_operand_option option;
} x86_inst_type;

#define PP_MEM_IF(oprand, _base, _index, _scale, _disp) (oprand.base == _base && oprand.index == _index && oprand.scale == _scale && oprand.displacement == _disp)

int x86_index_mem(x86_operand oprand)
{
    int res = -1;
    if (oprand.type == OR_MEM)
    {
        if (oprand.base == REG_BX && oprand.index == REG_SI)
        {
            res = 0;
        }
        else if (oprand.base == REG_BX && oprand.index == REG_DI)
        {
            res = 1;
        }
        else if (oprand.base == REG_BP && oprand.index == REG_SI)
        {
            res = 2;
        }
        else if (oprand.base == REG_BP && oprand.index == REG_DI)
        {
            res = 3;
        }
        else if (oprand.base == REG_SI && oprand.index == REG_NONE)
        {
            res = 4;
        }
        else if (oprand.base == REG_DI && oprand.index == REG_NONE)
        {
            res = 5;
        }
        else if (oprand.base == REG_NONE && oprand.index == REG_NONE && (x86_meet_size(x86_size_imm(oprand.displacement), RS_16)))
        {
            res = 6;
        }
        else if (oprand.base == REG_BX && oprand.index == REG_NONE)
        {
            res = 7;
        }
    }
    return res;
}

char x86_modrm(x86_size mode, x86_operand oprand1, x86_operand_option opt, x86_operand oprand2)
{
    char res = 0;
    switch (oprand1.type)
    {
    case OR_REG:
        res += 0xc0;
        res += x86_index_reg(oprand1.reg);
        break;
    case OR_MEM:
        if (PP_MEM_IF(oprand1, REG_BX, REG_SI, 1, 0))
        {
        }
        break;
    default:
        break;
    }
    switch (oprand2.type)
    {
    case OR_REG:
        res += x86_index_reg(oprand2.reg) * 0x0f;
        break;
    case OR_MEM:
        break;
    case OR_IMM:
        char regfield = (char)opt;
        res += regfield * 0x0f;
        break;
    default:
        break;
    }
    return res;
}

typedef struct
{
    char *code;
    int len;
} code_kind;

code_kind x86_assemble(x86_size mode, x86_opecode_kind opcode, x86_operand oprand1, x86_operand oprand2)
{
    x86_inst_type inst;
    code_kind res;
    res.code = calloc(sizeof(char), 14);
    int index = 0;
    inst.prefix = PF_NONE;
    inst.rex_flag = 0;
    inst.opcode_size = 1;
    switch (opcode)
    {
    case CD_MOV:
        if (oprand1.type == OR_REG && oprand2.type == OR_IMM)
        {
            switch (x86_size_reg(oprand1.reg))
            {
            case RS_8:
                inst.opcode[0] = 0xb0 + x86_index_reg(oprand1.reg);
                inst.option = OP_RD;
                inst.size_imm = RS_8;
                break;
            case RS_16:
                inst.opcode[0] = 0xb8 + x86_index_reg(oprand1.reg);
                inst.legacy_prefix = LP_ADROVR;
                inst.option = OP_RD;
                inst.size_imm = RS_16;
                break;
            case RS_32:
                inst.opcode[0] = 0xb8 + x86_index_reg(oprand1.reg);
                inst.option = OP_RD;
                inst.size_imm = RS_32;
                break;
            case RS_64:
                inst.prefix = PF_REX;
                inst.opcode[0] = 0xc7;
                inst.option = OP_0;
                inst.rex_flag += REX_W;
                inst.size_imm = RS_32;
                break;
            default:
                break;
            }
        }
        if (oprand1.type == OR_REG && oprand2.type == OR_REG)
        {
            switch (x86_size_reg(oprand1.reg))
            {
            case RS_8:
                inst.opcode[0] = 0xb0 + x86_index_reg(oprand1.reg);
                inst.option = OP_RD;
                break;
            case RS_16:
                inst.opcode[0] = 0xb8 + x86_index_reg(oprand1.reg);
                inst.legacy_prefix = LP_ADROVR;
                inst.option = OP_RD;
                break;
            case RS_32:
                inst.opcode[0] = 0xb8 + x86_index_reg(oprand1.reg);
                inst.option = OP_RD;
                break;
            case RS_64:
                inst.prefix = PF_REX;
                inst.opcode[0] = 0xc7;
                inst.option = OP_0;
                inst.rex_flag += REX_W;
                break;
            default:
                break;
            }
        }
        break;
    case CD_SYSCALL:
        inst.legacy_prefix = LP_NONE;
        inst.opcode[0] = 0x0f;
        inst.opcode[1] = 0x05;
        inst.opcode_size = 2;
        inst.option = OP_NONE;
        break;
    default:
        break;
    }

    switch (inst.legacy_prefix)
    {
    case LP_ADROVR:
        res.code[index++] = 0x66;
        break;
    case LP_OPOVR:
        res.code[index++] = 0x67;
        break;
    default:
        break;
    }

    switch (inst.prefix)
    {
    case PF_REX:
        res.code[index++] = 0x40 + inst.rex_flag;
        break;
    default:
        break;
    }

    for (size_t i = 0; i < inst.opcode_size; i++)
    {
        res.code[index++] = inst.opcode[i];
    }

    if (inst.option != OP_NONE)
    {
        if (inst.option != OP_RD)
        {
            res.code[index++] = x86_modrm(mode, oprand1, inst.option, oprand2);
        }

        if (inst.sib > 0)
        {
        }

        if (oprand2.type == OR_IMM)
        {
            long mask = 0xff;
            int power = 1;
            int bytes = 1;
            switch (inst.size_imm)
            {
            case RS_8:
                bytes = 1;
                break;
            case RS_16:
                bytes = 2;
                break;
            case RS_32:
                bytes = 4;
                break;
            case RS_64:
                bytes = 8;
                break;
            default:
                bytes = 0;
                break;
            }
            for (size_t i = 0; i < bytes; i++)
            {
                res.code[index++] = (oprand2.imm & mask) / power;
                mask *= 0x100;
                power *= 0x100;
            }
        }
    }

    res.len = index;

    return res;
}

x86_operand x86_oprand_from_reg(x86_register_type reg)
{
    x86_operand res;
    res.type = OR_REG;
    res.reg = reg;
    return res;
}

x86_operand x86_oprand_from_imm(long imm)
{
    x86_operand res;
    res.type = OR_IMM;
    res.imm = imm;
    return res;
}

x86_operand none;