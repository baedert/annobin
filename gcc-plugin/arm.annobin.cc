/* dummy.annobin - Empty target specific parts of the annobin plugin.
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
  /* Disable the use of section groups (by default) for the ARM.
     The problem is that the ARM gcc backend can create unwind sections
     that are associated with code sections, but which do not get put
     into the section groups.  So a relocateable link will combine these
     unwind sections together, but not the associated code sections (since
     they are part of a group) and so the unwind info becomes corrupt.  */
  annobin_attach_type = none;
  return 0;
}

unsigned int
annobin_get_target_pointer_size (void)
{
  return 32;
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

