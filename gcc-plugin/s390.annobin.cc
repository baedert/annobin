/* s390.annobin.cc - S390X specific parts of the annobin plugin.
   Copyright (c) 2019-2021 Red Hat.
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

signed int
annobin_target_start_symbol_bias (void)
{
  return 0;
}

unsigned int
annobin_get_target_pointer_size (void)
{
  // Note - testing POINTER_SIZE is unreliable.
  return GET_INT_OPTION_BY_NAME (target_flags) & MASK_64BIT ? 64 : 32;
}

int
annobin_save_target_specific_information (void)
{
  return 0;
}

void
annobin_record_global_target_notes (annobin_function_info * info ATTRIBUTE_UNUSED)
{
}

void
annobin_target_specific_function_notes (annobin_function_info * info ATTRIBUTE_UNUSED,
					bool force ATTRIBUTE_UNUSED)
{
}
