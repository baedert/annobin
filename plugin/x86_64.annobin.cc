/* x86_64.annobin - x86_64 specific parts of the annobin plugin.
   Copyright (c) 2017 - 2018 Red Hat.
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
static int            global_stack_realign = 0;

#ifdef flag_cet
static int                     global_cet = -1;
static int                     global_set_switch = -1;
static unsigned HOST_WIDE_INT  global_ibt = 0;
static unsigned HOST_WIDE_INT  global_shstk = 0;
#endif

signed int
annobin_target_start_symbol_bias (void)
{
  return 0;
}

void
annobin_save_target_specific_information (void)
{
}

#ifdef flag_cet
static void
record_cet_note (const char * start, const char * end, int type)
{
  char buffer [128];
  unsigned len = sprintf (buffer, "GA%ccet status", NUMERIC);

  /* We bias the values by 1 so that we do not get confused by a zero value.  */
  buffer[++len] = flag_cet + 1;
  buffer[++len] = flag_cet_switch + 1;
  buffer[++len] = (ix86_isa_flags2 & OPTION_MASK_ISA_IBT) ? 2 : 1;
  buffer[++len] = (ix86_isa_flags & OPTION_MASK_ISA_SHSTK) ? 2 : 1;
  buffer[++len] = 0;

  annobin_inform (1, "Record CET values of %d:%d:%lx:%lx",
		  flag_cet, flag_cet_switch,
		  ix86_isa_flags2 & OPTION_MASK_ISA_IBT,
		  ix86_isa_flags & OPTION_MASK_ISA_SHSTK);

  annobin_output_static_note (buffer, len + 1, false, "numeric: -mcet status",
			      start, end, type);
}
#endif

void
annobin_record_global_target_notes (void)
{
  /* Note - most, but not all, bits in the ix86_isa_flags variable
     are significant for purposes of ABI compatibility.  We do not
     bother to filter out any bits however, as we prefer to leave
     it to the consumer to decide what is significant.  */
  min_x86_isa = max_x86_isa = global_x86_isa = ix86_isa_flags;

  annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, global_x86_isa,
			       "numeric: ABI", NULL, NULL, OPEN);
  annobin_inform (1, "Record global isa of %lx", global_x86_isa);

  {
    global_stack_realign = ix86_force_align_arg_pointer;

    char buffer [128];
    unsigned len = sprintf (buffer, "GA%cstack_realign", global_stack_realign ? BOOL_T : BOOL_F);
    annobin_output_static_note (buffer, len + 1, true, "bool: -mstackrealign status",
				NULL, NULL, OPEN);
    annobin_inform (1, "Record global stack realign setting of %s", global_stack_realign ? "false" : "true");
  }
			       
#ifdef flag_cet
  global_cet = flag_cet;
  global_set_switch = flag_cet_switch;
  global_ibt = ix86_isa_flags2 & OPTION_MASK_ISA_IBT;
  global_shstk = ix86_isa_flags & OPTION_MASK_ISA_SHSTK;

  record_cet_note (NULL, NULL, OPEN);
#endif
}

void
annobin_target_specific_function_notes (const char * aname, const char * aname_end)
{
  if ((unsigned long) ix86_isa_flags != global_x86_isa)
    {
      annobin_inform (1, "ISA value has changed from %lx to %lx for %s",
		   global_x86_isa, ix86_isa_flags, aname);

      annobin_output_numeric_note (GNU_BUILD_ATTRIBUTE_ABI, ix86_isa_flags,
				   "numeric: ABI", aname, aname_end, FUNC);

      if ((unsigned long) ix86_isa_flags < min_x86_isa)
	min_x86_isa = ix86_isa_flags;
      if ((unsigned long) ix86_isa_flags > max_x86_isa)
	max_x86_isa = ix86_isa_flags;
    }

  if (ix86_force_align_arg_pointer != global_stack_realign)
    {
      char buffer [128];
      unsigned len = sprintf (buffer, "GA%cstack_realign", ix86_force_align_arg_pointer ? BOOL_T : BOOL_F);
      annobin_output_static_note (buffer, len + 1, true, "bool: -mstackrealign status",
				  aname, aname_end, FUNC);
      annobin_inform (1, "Record function specific stack realign setting of %s for %s",
		      ix86_force_align_arg_pointer ? "false" : "true", aname);
    }

#ifdef flag_cet
  if (global_cet != flag_cet)
    fprintf (stderr, "1\n");
  if (global_set_switch != flag_cet_switch)
    fprintf (stderr, "2\n");
  if (global_ibt != (ix86_isa_flags2 & OPTION_MASK_ISA_IBT))
    fprintf (stderr, "3\n");
  if (global_shstk != (ix86_isa_flags & OPTION_MASK_ISA_SHSTK))
    fprintf (stderr, "4\n");

  if ((global_cet != flag_cet)
      || (global_set_switch != flag_cet_switch)
      || (global_ibt != (ix86_isa_flags2 & OPTION_MASK_ISA_IBT))
      || (global_shstk != (ix86_isa_flags & OPTION_MASK_ISA_SHSTK)))
    {
      annobin_inform (1, "CET values have changed from %d:%d:%lx:%lx to %d:%d:%lx:%lx",
		      global_cet, global_set_switch, global_ibt, global_shstk,
		      flag_cet, flag_cet_switch,
		      (ix86_isa_flags2 & OPTION_MASK_ISA_IBT),
		      (ix86_isa_flags & OPTION_MASK_ISA_SHSTK));
	
      record_cet_note (aname, aname_end, FUNC);
    }
#endif
}

static unsigned int
convert_gcc_isa_to_gnu_property_isa (unsigned int isa)
{
  unsigned int result = 0;

  if (isa & OPTION_MASK_ISA_SSE)
    result |= GNU_PROPERTY_X86_ISA_1_SSE;
  if (isa & OPTION_MASK_ISA_SSE2)
    result |= GNU_PROPERTY_X86_ISA_1_SSE2;
  if (isa & OPTION_MASK_ISA_SSE3)
    result |= GNU_PROPERTY_X86_ISA_1_SSSE3;
  if (isa & OPTION_MASK_ISA_SSE4_1)
    result |= GNU_PROPERTY_X86_ISA_1_SSE4_1;
  if (isa & OPTION_MASK_ISA_SSE4_2)
    result |= GNU_PROPERTY_X86_ISA_1_SSE4_2;
  if (isa & OPTION_MASK_ISA_AVX)
    result |= GNU_PROPERTY_X86_ISA_1_AVX;
  if (isa & OPTION_MASK_ISA_AVX2)
    result |= GNU_PROPERTY_X86_ISA_1_AVX2;
#ifdef OPTION_MASK_ISA_AVX512F
  if (isa & OPTION_MASK_ISA_AVX512F)
    result |= GNU_PROPERTY_X86_ISA_1_AVX512F;
  if (isa & OPTION_MASK_ISA_AVX512CD)
    result |= GNU_PROPERTY_X86_ISA_1_AVX512CD;
  if (isa & OPTION_MASK_ISA_AVX512ER)
    result |= GNU_PROPERTY_X86_ISA_1_AVX512ER;
  if (isa & OPTION_MASK_ISA_AVX512PF)
    result |= GNU_PROPERTY_X86_ISA_1_AVX512PF;
  if (isa & OPTION_MASK_ISA_AVX512VL)
    result |= GNU_PROPERTY_X86_ISA_1_AVX512VL;
  if (isa & OPTION_MASK_ISA_AVX512DQ)
    result |= GNU_PROPERTY_X86_ISA_1_AVX512DQ;
  if (isa & OPTION_MASK_ISA_AVX512BW)
    result |= GNU_PROPERTY_X86_ISA_1_AVX512BW;
#endif
  return result;
}

typedef struct
{
  Elf32_Word   pr_type;
  Elf32_Word   pr_datasz;
  Elf32_Word   pr_data;
} Elf32_loader_note;

typedef struct
{
  Elf32_Word    pr_type;
  Elf32_Word    pr_datasz;
  Elf64_Xword   pr_data;
} Elf64_loader_note;

typedef struct
{
  Elf32_Word   pr_type;
  Elf32_Word   pr_datasz;
  Elf32_Word   pr_data;
  Elf32_Word   pr_pad;
} Elf64_32_loader_note;

void
annobin_target_specific_loader_notes (void)
{
  char   buffer [1024]; /* FIXME: Is this enough ?  */
  char * ptr;

  annobin_inform (1, "Creating notes for the dynamic loader");

  fprintf (asm_out_file, "\t.pushsection %s, \"a\", %%note\n", NOTE_GNU_PROPERTY_SECTION_NAME);
  fprintf (asm_out_file, "\t.balign 4\n");

  ptr = buffer;

  if (annobin_is_64bit)
    {
      Elf64_32_loader_note note32;

      note32.pr_datasz = sizeof (note32.pr_data);
      note32.pr_pad = 0;

      if (annobin_enable_stack_size_notes)
	{
	  Elf64_loader_note note64;

	  note64.pr_type   = GNU_PROPERTY_STACK_SIZE;
	  note64.pr_datasz = sizeof (note64.pr_data);
	  note64.pr_data   = annobin_max_stack_size;
	  memcpy (ptr, & note64, sizeof note64);
	  ptr += sizeof (note64);
	}

      note32.pr_type = GNU_PROPERTY_X86_ISA_1_USED;
      note32.pr_data = convert_gcc_isa_to_gnu_property_isa (max_x86_isa);
      memcpy (ptr, & note32, sizeof note32);
      ptr += sizeof (note32);

      note32.pr_type = GNU_PROPERTY_X86_ISA_1_NEEDED;
      note32.pr_data = convert_gcc_isa_to_gnu_property_isa (min_x86_isa);
      memcpy (ptr, & note32, sizeof note32);
      ptr += sizeof (note32);
    }
  else
    {
      Elf32_loader_note note32;

      note32.pr_datasz = sizeof (note32.pr_data);

      if (annobin_enable_stack_size_notes)
	{
	  note32.pr_type = GNU_PROPERTY_STACK_SIZE;
	  note32.pr_data = annobin_max_stack_size;
	  memcpy (ptr, & note32, sizeof note32);
	  ptr += sizeof (note32);
	}

      note32.pr_type = GNU_PROPERTY_X86_ISA_1_USED;
      note32.pr_data = convert_gcc_isa_to_gnu_property_isa (max_x86_isa);
      memcpy (ptr, & note32, sizeof note32);
      ptr += sizeof (note32);

      note32.pr_type = GNU_PROPERTY_X86_ISA_1_NEEDED;
      note32.pr_data = convert_gcc_isa_to_gnu_property_isa (min_x86_isa);
      memcpy (ptr, & note32, sizeof note32);
      ptr += sizeof (note32);
    }

  annobin_output_note ("GNU", 4, true, "Loader notes", buffer, NULL, ptr - buffer,
		       false, NT_GNU_PROPERTY_TYPE_0);

  fprintf (asm_out_file, "\t.popsection\n");
  fflush (asm_out_file);
}
