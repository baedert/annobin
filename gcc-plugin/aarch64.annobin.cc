/* aarch64.annobin - AArch64 specific parts of the annobin plugin.
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

unsigned int
annobin_get_target_pointer_size (void)
{
  // FIXME: We do not currently support ILP32 mode.
  return 64;
}

void
annobin_record_global_target_notes (annobin_function_info * info)
{
  saved_tls_dialect = GET_INT_OPTION_BY_INDEX (OPT_mtls_dialect_);

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, saved_tls_dialect,
			       "numeric: ABI: TLS dialect",
			       true /* Is OPEN.  */, info);
  annobin_inform (INFORM_VERBOSE, "AArch64: Recording global TLS dialect of %d", saved_tls_dialect);

#ifdef aarch64_branch_protection_string
  saved_branch_protection_string = GET_STR_OPTION_BY_INDEX (OPT_mbranch_protection_);

  char buffer [128];
  const char * sbps = saved_branch_protection_string;
  if (sbps == NULL)
    sbps = "default";

  annobin_inform (INFORM_VERBOSE, "AArch64: Recording global AArch64 branch protection of '%s'", sbps);
  unsigned len = snprintf (buffer, sizeof buffer - 1, "GA%cbranch_protection:%s",
			   GNU_BUILD_ATTRIBUTE_TYPE_STRING, sbps);
  annobin_output_note (buffer, len + 1, true, "string: -mbranch-protection status",
		       true /* Is OPEN.  */, info);
#endif
}

void
annobin_target_specific_function_notes (annobin_function_info * info, bool force)
{
  signed int val = GET_INT_OPTION_BY_INDEX (OPT_mtls_dialect_);

  if (force || saved_tls_dialect != val)
    {
      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, val,
				   "numeric: ABI: TLS dialect",
				   false /* Is not OPEN.  */, info);
      annobin_inform (INFORM_VERBOSE, "AArch64: Recording TLS dialect of %d for %s",
		      val, info->func_name);

      /* We no longer need to include the start/end symbols in any
	 further notes that we genenerate.  */
      info->start_sym = info->end_sym = NULL;
    }

#ifdef aarch64_branch_protection_string
  const char * abps = GET_STR_OPTION_BY_INDEX (OPT_mbranch_protection_);
  
  if (force || saved_branch_protection_string != abps)
    {
      char buffer [128];
      if (abps == NULL)
	abps = "default";

      annobin_inform (INFORM_VERBOSE, "AArch64: Recording AArch64 branch protection of '%s' for function '%s'",
		      abps, info->func_name);

      unsigned len = snprintf (buffer, sizeof buffer - 1, "GA%cbranch_protection:%s",
			       GNU_BUILD_ATTRIBUTE_TYPE_STRING, abps);
      annobin_output_note (buffer, len + 1, true /* The name is ASCII.  */,
			   "string: -mbranch-protection status",
			   false /* Is not OPEN.  */, info);

      /* We no longer need to include the start/end symbols in any
	 further notes that we genenerate.  */
      info->start_sym = info->end_sym = NULL;
    }
#endif
}
