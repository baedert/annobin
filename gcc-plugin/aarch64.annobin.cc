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

#include "annobin-global.h"
#include "annobin.h"

/* For AArch64 we do not bother recording the ABI, since this is already
   encoded in the binary.  Instead we record the TLS dialect...  */
static signed int saved_tls_dialect = -1;

#ifdef aarch64_branch_protection_string
static const char * saved_branch_protection_string;
#endif

signed int
annobin_target_start_symbol_bias (void)
{
  return 0;
}

int
annobin_save_target_specific_information (void)
{
  return 0;
}

void
annobin_record_global_target_notes (const char * sec)
{
  // annobin_is_64bit is computed from a flag bit inside aarch64_abi.
  if (!annobin_is_64bit)
    annobin_inform (INFORM_ALWAYS, "AArch64: The annobin plugin is out of date with respect to gcc");

  saved_tls_dialect = aarch64_tls_dialect;

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, saved_tls_dialect,
			       "numeric: ABI: TLS dialect", NULL, NULL, OPEN, sec);
  annobin_inform (INFORM_VERBOSE, "AArch64: Recording global TLS dialect of %d", saved_tls_dialect);

#ifdef aarch64_branch_protection_string
  saved_branch_protection_string = aarch64_branch_protection_string;

  char buffer [128];
  const char * sbps = saved_branch_protection_string;
  if (sbps == NULL)
    sbps = "default";

  annobin_inform (INFORM_VERBOSE, "AArch64: Recording global AArch64 branch protection of '%s'", sbps);
  unsigned len = snprintf (buffer, sizeof buffer - 1, "GA%cbranch_protection:%s",
			   GNU_BUILD_ATTRIBUTE_TYPE_STRING, sbps);
  annobin_output_static_note (buffer, len + 1, true, "string: -mbranch-protection status",
			      NULL, NULL, OPEN, sec);
#endif
}

void
annobin_target_specific_function_notes (const char * aname, const char * aname_end, const char * sec_name, bool force)
{
  if (force || saved_tls_dialect != aarch64_tls_dialect)
    {
      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, aarch64_tls_dialect,
				   "numeric: ABI: TLS dialect", aname, aname_end,
				   FUNC, sec_name);
      annobin_inform (INFORM_VERBOSE, "AArch64: Recording TLS dialect of %d for %s",
		      aarch64_tls_dialect, current_function_name ());

    }

#ifdef aarch64_branch_protection_string
  if (force || saved_branch_protection_string != aarch64_branch_protection_string)
    {
      char buffer [128];
      const char * abps = aarch64_branch_protection_string;
      if (abps == NULL)
	abps = "default";

      annobin_inform (INFORM_VERBOSE, "AArch64: Recording AArch64 branch protection of '%s' for function '%s'",
		      abps, aname);

      unsigned len = snprintf (buffer, sizeof buffer - 1, "GA%cbranch_protection:%s",
			       GNU_BUILD_ATTRIBUTE_TYPE_STRING, abps);
      annobin_output_static_note (buffer, len + 1, true, "string: -mbranch-protection status",
				  aname, aname_end, FUNC, sec_name);
    }
#endif
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

  annobin_inform (INFORM_VERBOSE, "AArch64: Creating notes for the dynamic loader");

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