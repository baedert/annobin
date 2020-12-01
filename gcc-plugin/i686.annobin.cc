/* x86_64.annobin - x86_64 specific parts of the annobin plugin.
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

#define GNU_PROPERTY_X86_ISA_1_USED		0xc0000000
#define GNU_PROPERTY_X86_ISA_1_NEEDED		0xc0000001

#define GNU_PROPERTY_X86_ISA_1_486           (1U << 0)
#define GNU_PROPERTY_X86_ISA_1_586           (1U << 1)
#define GNU_PROPERTY_X86_ISA_1_686           (1U << 2)
#define GNU_PROPERTY_X86_ISA_1_SSE           (1U << 3)
#define GNU_PROPERTY_X86_ISA_1_SSE2          (1U << 4)
#define GNU_PROPERTY_X86_ISA_1_SSE3          (1U << 5)
#define GNU_PROPERTY_X86_ISA_1_SSSE3         (1U << 6)
#define GNU_PROPERTY_X86_ISA_1_SSE4_1        (1U << 7)
#define GNU_PROPERTY_X86_ISA_1_SSE4_2        (1U << 8)
#define GNU_PROPERTY_X86_ISA_1_AVX           (1U << 9)
#define GNU_PROPERTY_X86_ISA_1_AVX2          (1U << 10)
#define GNU_PROPERTY_X86_ISA_1_AVX512F       (1U << 11)
#define GNU_PROPERTY_X86_ISA_1_AVX512CD      (1U << 12)
#define GNU_PROPERTY_X86_ISA_1_AVX512ER      (1U << 13)
#define GNU_PROPERTY_X86_ISA_1_AVX512PF      (1U << 14)
#define GNU_PROPERTY_X86_ISA_1_AVX512VL      (1U << 15)
#define GNU_PROPERTY_X86_ISA_1_AVX512DQ      (1U << 16)
#define GNU_PROPERTY_X86_ISA_1_AVX512BW      (1U << 17)

static unsigned long  global_x86_isa = 0;
static unsigned long  min_x86_isa = 0;
static unsigned long  max_x86_isa = 0;
static unsigned long  global_stack_realign = 0;

signed int
annobin_target_start_symbol_bias (void)
{
  return 0;
}

unsigned int
annobin_get_target_pointer_size (void)
{
  // Note: testing POINTER_SIZE is unreliable reliable as it ultimately uses information in global_options.
  return 32;
}

int
annobin_save_target_specific_information (void)
{
  return 0;
}

void
annobin_record_global_target_notes (annobin_function_info * info)
{
  /* Note - most, but not all, bits in the ix86_isa_flags variable
     are significant for purposes of ABI compatibility.  We do not
     bother to filter out any bits however, as we prefer to leave
     it to the consumer to decide what is significant.  */
  min_x86_isa = max_x86_isa = global_x86_isa = GET_INT_OPTION_BY_NAME (ix86_isa_flags);

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, global_x86_isa,
			       "numeric: ABI", true /* Is OPEN.  */, info);
  annobin_inform (INFORM_VERBOSE, "x86_64: Record global isa of %lx", global_x86_isa);

  
  global_stack_realign = GET_INT_OPTION_BY_NAME (ix86_force_align_arg_pointer);

  char buffer [128];
  unsigned len = sprintf (buffer, "GA%cstack_realign", global_stack_realign ? BOOL_T : BOOL_F);
  annobin_output_note (buffer, len + 1, true /* The name is ASCII.  */,
		       "bool: -mstackrealign status",
		       true /* Is OPEN.  */, info);
  annobin_inform (INFORM_VERBOSE, "x86_64: Record global stack realign setting of %s",
		  global_stack_realign ? "false" : "true");
}

void
annobin_target_specific_function_notes (annobin_function_info * info, bool force)
{
  unsigned long val;

  val = GET_INT_OPTION_BY_NAME (ix86_isa_flags);
  if (force || val != global_x86_isa)
    {
      annobin_inform (INFORM_VERBOSE, "x86_64: Record ISA value of %lx for %s",
		      val, info->func_name);

      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, val,
				   "numeric: ABI", false /* Is not OPEN.  */, info);

      if (val < min_x86_isa)
	min_x86_isa = val;
      if (val > max_x86_isa)
	max_x86_isa = val;

      /* We no longer need to include the start/end symbols in any
	 further notes that we generate.  */
      info->start_sym = info->end_sym = NULL;
    }

  val = GET_INT_OPTION_BY_NAME (ix86_force_align_arg_pointer);
  if (force || val != global_stack_realign)
    {
      char buffer [128];
      unsigned len = sprintf (buffer, "GA%cstack_realign", val ? BOOL_T : BOOL_F);

      annobin_inform (INFORM_VERBOSE, "x86_64: Record function specific stack realign setting of %s for %s",
		      val ? "false" : "true", info->func_name);
      annobin_output_note (buffer, len + 1, true /* The name is ASCII.  */,
			   "bool: -mstackrealign status",
			   false /* Is not OPEN */, info);

      /* We no longer need to include the start/end symbols in any
	 further notes that we generate.  */
      info->start_sym = info->end_sym = NULL;
    }
}
