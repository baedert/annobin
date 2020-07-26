/* dummy.annobin - Empty target specific parts of the annobin plugin.
   Copyright (c) 2019-2020 Red Hat.
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

/* The target specific part of the plugin must prodive the
   following four functions:

   annobin_save_target_specific_information - Called during plugin_init()
   annobin_target_start_symbol_bias         - Called during plugin_init()
   annobin_record_global_target_notes       - Called during PLUGIN_START_UNIT
   annobin_get_target_pointer_size          - Called during PLUGIN_START_UNIT
   annobin_target_specific_function_notes   - Called during PLUGIN_ALL_PASSES_START
   annobin_target_specific_loader_notes     - Called during PLUGIN_FINISH_UNIT.  */

signed int
annobin_target_start_symbol_bias (void)
{
  return 0;
}

unsigned int
annobin_get_target_pointer_size (void)
{
  // FIXME: Testing POINTER_SIZE may not be reliable.
  return POINTER_SIZE;
}

int
annobin_save_target_specific_information (void)
{
  return 0;
}

void
annobin_record_global_target_notes (const char * sec)
{
}

void
annobin_target_specific_function_notes (const char * aname, const char * aname_end, const char * sec_name, bool force)
{
}

void
annobin_target_specific_loader_notes (void)
{
}
