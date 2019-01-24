/* powerpc64le.annobin - PowerPC64 specific parts of the annobin plugin.
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

static int saved_tls_size;

void
annobin_save_target_specific_information (void)
{
  ;
}

signed int
annobin_target_start_symbol_bias (void)
{
  /* We set the address of the start symbol to be the current address plus two.
     That way this symbol will not be confused for a file start/function start
     symbol.  This is especially important on the PowerPC target as that
     generates synthetic symbols for function entry points, but only if there
     is no real symbol for that address.  */

  return 2;
}

void
annobin_record_global_target_notes (const char * sec)
{
  if (!annobin_is_64bit)
    annobin_inform (0, "ICE: Should be 64-bit target");

  saved_tls_size = rs6000_tls_size;

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, saved_tls_size,
			       "numeric: ABI: TLS size", NULL, NULL, OPEN, sec);
  annobin_inform (1, "Recording global TLS size of %d", saved_tls_size);
}

void
annobin_target_specific_function_notes (const char * aname, const char * aname_end, const char * sec_name, bool force)
{
  if (!force && saved_tls_size == rs6000_tls_size)
    return;

  annobin_inform (1, "Record TLS size of %d for %s",
		  rs6000_tls_size, aname);

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, rs6000_tls_size,
			       "numeric: ABI: TLS size", aname, aname_end, FUNC, sec_name);
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

