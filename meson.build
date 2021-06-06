project('astral', 'c')

includes = include_directories('astral')

executable('astral', 'astral/src/astral.c', include_directories : includes)
e = executable('test_size_imm', 'astral/tests/test_size_imm.c', include_directories : includes)

test('size_num test', e)