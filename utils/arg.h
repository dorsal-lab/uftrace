#ifndef UFTRACE_ARG_H
#define UFTRACE_ARG_H

#include <sys/types.h>

#include "utils/symbol.h"
#include "utils/fstack.h"

void print_json_escaped_char(char **args, size_t *len, const char c);
void format_argspec_string(char *output, struct symtabs *symtabs,
						   struct uftrace_mmap *map, void *data,
						   struct list_head *specs, size_t len,
						   enum argspec_string_bits str_mode);

#endif // UFTRACE_ARG_H
