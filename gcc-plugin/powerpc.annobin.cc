/* powerpc64le.annobin - PowerPC64 specific parts of the annobin plugin.
   Copyright (c) 2017 - 2021 Red Hat.
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "annobin-global.h"
#include "annobin.h"

static int saved_tls_size;

int
annobin_save_target_specific_information (void)
{
  return 0;
}

unsigned int
annobin_get_target_pointer_size (void)
{
  return 64;
}

signed int
annobin_target_start_symbol_bias (void)
{
  /* We set the address of the start symbol to be the current address plus four.
     That way this symbol will not be confused for a file start/function start
     symbol.  This is especially important on the PowerPC target as that
     generates synthetic symbols for function entry points, but only if there
     is no real symbol for that address.  The value of four is used so that
     the annobin symbol will not appear in the middle of an instruction, which
     can confuse the disassembler.  */

  return 4;
}

void
annobin_record_global_target_notes (annobin_function_info * info)
{
  if (!annobin_is_64bit)
    ice ("PowerPC: The annobin plugin thinks that it is compiling for a 32-bit target");

  saved_tls_size = GET_INT_OPTION_BY_NAME (rs6000_tls_size);

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, saved_tls_size,
			       "numeric: ABI: TLS size", true /* Is OPEN.  */, info);
  annobin_inform (INFORM_VERBOSE, "PowerPC: Recording global TLS size of %d", saved_tls_size);
}

void
annobin_target_specific_function_notes (annobin_function_info * info, bool force)
{
  int val = GET_INT_OPTION_BY_NAME (rs6000_tls_size);

  if (!force && saved_tls_size == val)
    return;

  annobin_inform (INFORM_VERBOSE, "PowerPC: Record TLS size of %d for %s", val, info->func_name);

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, val,
			       "numeric: ABI: TLS size", false /* Is not OPEN.  */, info);
  /* We no longer need to include the start/end symbols in any
     further notes that we generate.  */
  info->start_sym = info->end_sym = NULL;
}
