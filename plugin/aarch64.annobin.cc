/* aarch64.annobin - AArch64 specific parts of the annobin plugin.
   Copyright (c) 2017 - 2019 Red Hat.
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "annobin.h"

/* For AArch64 we do not bother recording the ABI, since this is already
   encoded in the binary.  Instead we record the TLS dialect...  */
static signed int saved_tls_dialect = -1;

signed int
annobin_target_start_symbol_bias (void)
{
  return 0;
}

void
annobin_save_target_specific_information (void)
{
}

void
annobin_record_global_target_notes (const char * sec)
{
  if (!annobin_is_64bit)
    annobin_inform (0, "ICE: Should be 64-bit target");

  saved_tls_dialect = aarch64_tls_dialect;

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, saved_tls_dialect,
			       "numeric: ABI: TLS dialect", NULL, NULL, OPEN, sec);
  annobin_inform (1, "Recording global TLS dialect of %d", saved_tls_dialect);
}

void
annobin_target_specific_function_notes (const char * aname, const char * aname_end, const char * sec_name, bool force)
{
  if (!force && saved_tls_dialect == aarch64_tls_dialect)
    return;

  annobin_inform (1, "recording TLS dialect of %d for %s",
		  aarch64_tls_dialect, current_function_name ());

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, aarch64_tls_dialect,
			       "numeric: ABI: TLS dialect", aname, aname_end,
			       FUNC, sec_name);
}

typedef struct
{
  Elf32_Word    pr_type;
  Elf32_Word    pr_datasz;
  Elf64_Xword   pr_data;
} Elf64_loader_note;

void
annobin_target_specific_loader_notes (void)
{
  char   buffer [1024]; /* FIXME: Is this enough ?  */
  char * ptr;

  if (! annobin_enable_stack_size_notes)
    return;

  annobin_inform (1, "Creating notes for the dynamic loader");

  ptr = buffer;

  Elf64_loader_note note64;

  note64.pr_type   = GNU_PROPERTY_STACK_SIZE;
  note64.pr_datasz = sizeof (note64.pr_data);
  note64.pr_data   = annobin_max_stack_size;
  memcpy (ptr, & note64, sizeof note64);
  ptr += sizeof (note64);

  annobin_output_note ("GNU", 4, true, "Loader notes", buffer, NULL, ptr - buffer,
		       false, NT_GNU_PROPERTY_TYPE_0, NOTE_GNU_PROPERTY_SECTION_NAME);
  fflush (asm_out_file);
}
