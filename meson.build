project('astral', 'c')

includes = include_directories('astral')

executable('astral', 'astral/src/astral.c', include_directories : includes)
t1 = executable('test_size_imm', 'astral/tests/test_size_imm.c', include_directories : includes)

t2 = executable('test_simpleasm', 'astral/tests/test_simpleasm.c', include_directories : includes)

t3 = executable('test_code', 'astral/tests/test_code.c', include_directories : includes)

test('size_num test', t1)
test('add ax, imm16 test', t2)
test('code.h test', t3)