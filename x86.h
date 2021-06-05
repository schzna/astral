
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
    r8,
    r16,
    r32,
    r64,
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
    ptr16c32
} operand_type;

typedef enum
{
    mov
} opecode_type;

typedef enum
{
    en_ZO,
    en_RM,
    en_MR,
    en_MI,
    en_I,
    en_A,
    en_B,
    en_C,
    en_RVM
} encode_type;

/*  opecode_reader
    opecode -> oprand_checker

    operand_checker
    operand x operand -> encode_type

    modrm_generator
    operand x operand -> byte

    sib_generator
    operand x operand -> byte

    imm_adjuster
    long long -> imm

    encoding_reader
    encode_type -> coder

    operand_coder
    operand x operand x mode -> *byte

    opecode_coder
    opecode x mode -> *byte
*/
