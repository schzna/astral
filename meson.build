project('astral', 'c')

includes = include_directories('astral')

executable('astral', 'astral/src/astral.c', include_directories : includes)
t1 = executable('test_size_imm', 'astral/tests/test_size_imm.c', include_directories : includes)

t2 = executable('test_simpleasm', 'astral/tests/test_simpleasm.c', include_directories : includes)

t3 = executable('test_code', 'astral/tests/test_code.c', include_directories : includes)

t4 = executable('test_inst', 'astral/tests/test_inst.c', include_directories : includes)

t5 = executable('test_make_imm', 'astral/tests/test_make_imm.c', include_directories : includes)

t6 = executable('test_encode_imm', 'astral/tests/test_encode_imm.c', include_directories : includes)

t7 = executable('test_match', 'astral/tests/test_match.c', include_directories : includes)

test('size_num test', t1)
test('add eax, imm32 test', t2)
test('code.h test', t3)
test('instructions test', t4)
test('make_imm test', t5)
test('encode imm test', t6)
test('match test', t7)