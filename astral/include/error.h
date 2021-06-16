#ifndef INCLUDED_CODE_H
#define INCLUDED_CODE_H
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct
{
    const char *msg;
} error_info;

typedef struct
{
    bool initialized;
    error_info *info;
    size_t capacity, size;
} error_bundle;

void init_error_bundle(error_bundle *errors)
{
    errors->initialized = true;
    errors->capacity = 10;
    errors->size = 0;
    errors->info = (error_info *)calloc(sizeof(error_info), errors->capacity);
}

void push_error(error_bundle *dest, error_info eri)
{
    if (!dest->initialized)
    {
        init_error_bundle(dest);
    }
    if (dest->size >= dest->capacity)
    {
        dest->capacity += 5;
        dest->info = (error_info *)realloc(dest->info, sizeof(error_info) * dest->capacity);
    }
    dest->info[dest->size++] = eri;
}

void error_msg(error_bundle *dest, const char *msg)
{
    error_info eri;
    eri.msg = msg;

    push_error(dest, eri);
}

void print_error(const error_bundle *errors)
{
    for (size_t i = 0; i < errors->size; i++)
    {
        fprintf(stderr, "%.50s\n", errors->info[i].msg);
    }
}

void clear_error(error_bundle *errors)
{
    free(errors->info);
    init_error_bundle(errors);
}

error_bundle global_error_entity = {
    .initialized = false};

error_bundle *global_error = &global_error_entity;

#endif