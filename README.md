# astral

none

## design

    opecode_reader
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
