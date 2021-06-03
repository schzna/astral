
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
} reg8;

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
} reg8_a;

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
} reg16;

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
} reg16_a;

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
} reg32;

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
} reg32_a;

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
} reg64;

//segment registers

typedef enum
{
    es,
    cs,
    ss,
    ds,
    fs,
    gs
} sreg;

typedef char imm8;
typedef short imm16;
typedef int imm32;
typedef long long imm64;

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
    reg16 base, index;
    imm16 disp;
} eff_addr16;

typedef struct
{
    reg32 base, index;
    imm32 disp;
    int scale;
} eff_addr32;

typedef struct
{
    reg64 base, index;
    imm64 disp;
    int scale;
} eff_addr64;