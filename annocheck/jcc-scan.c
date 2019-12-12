/* Detects the presence of potential JCC vulnerabilities in a binary.
   Copyright (c) 2019 Red Hat.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  You should have received a copy of the GNU General Public
  License along with this program; see the file COPYING3. If not,
  see <http://www.gnu.org/licenses/>.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "annobin-global.h"
#include "annocheck.h"
#include <bfd.h>
#include <dis-asm.h>

typedef struct disas_state
{
  char *        buffer;    /* Disassembly printing buffer.  */
  ulong         alloc;     /* Size of the printing buffer.  */
  ulong         pos;       /* Where we are in the printing buffer. */
} disas_state;

typedef struct insn_state
{
  bfd_byte *    code;	   /* Instruction buffer.  */
  ulong         size;      /* Size of instruction buffer.  */
  bfd_vma       code_base; /* Address of first instruction in the instruction buffer.  */
} insn_state;

static disas_state  disas;
static insn_state   insns;
static bool         disabled = false;
static int          e_type;
static uint         num_found;

static bool
start_file (annocheck_data * data)
{
  if (disabled)
    return false;

  num_found = 0;

  int  e_machine;

  if (data->is_32bit)
    {
      Elf32_Ehdr * hdr = elf32_getehdr (data->elf);

      e_type = hdr->e_type;
      e_machine = hdr->e_machine;
    }
  else
    {
      Elf64_Ehdr * hdr = elf64_getehdr (data->elf);

      e_type = hdr->e_type;
      e_machine = hdr->e_machine;
    }

  return (e_machine == EM_X86_64 || e_machine == EM_386);
}

static bool
interesting_sec (annocheck_data *     data,
		 annocheck_section *  sec)
{
  if (disabled)
    return false;

  /* For retpolines we want to scan code sections.  */
  if (sec->shdr.sh_type == SHT_PROGBITS
      && sec->shdr.sh_flags & SHF_EXECINSTR
      && sec->shdr.sh_size > 0)
    return true;

  /* We do not need any more information from the section,
     so there is no need to run the checker.  */
  return false;
}

static int ATTRIBUTE_PRINTF_2
x86_printf (void * stream, const char * format, ...) 
{
  size_t n;
  va_list args;

  while (1)
    {
      size_t space = disas.alloc - disas.pos;

      /* Attempt to print the instruction into the allocated buffer.  */
      va_start (args, format);
      n = vsnprintf (disas.buffer + disas.pos, space, format, args);
      va_end (args);

      if (space > n)
	break;

      /* If that failed, increase the buffer size and try again.  */
      disas.alloc = (disas.alloc + n) * 2;
      disas.buffer = (char *) xrealloc (disas.buffer, disas.alloc);
    }

  disas.pos += n;
  return n;
}

static int
x86_read_mem (bfd_vma addr, bfd_byte * buffer, unsigned len, struct disassemble_info * info)
{
  if (len == 0)
    return 1;
  if (addr >= insns.size)
    return 2;
  if ((addr + len) > insns.size)
    return 3;
  if ((addr + len) <= addr)
    return 4;

  memcpy (buffer, insns.code + addr, len);
  return 0;
}

static void
x86_mem_err (int status, bfd_vma addr, struct disassemble_info * info)
{
  einfo (ERROR, "x86 disasembler: memory err %d for addr %lx (offset %lx)",
	 status, insns.code_base + addr, addr);
}

static void
x86_addr (bfd_vma addr, struct disassemble_info * info)
{
  size_t space = disas.alloc - disas.pos;

  if (space < 16)
    {
      disas.alloc  = disas.alloc * 2 + 16;
      disas.buffer = (char *) xrealloc (disas.buffer, disas.alloc);
    }

  sprintf (disas.buffer + disas.pos, " &%#lx ", insns.code_base + addr);
  disas.pos += strlen (disas.buffer + disas.pos);
  return;
}

static bool
is_affected_insn (bfd_vma offset, uint len)
{
  /* Only jump type instructions are affected.  */
  if (strchr (disas.buffer, 'j') == NULL
      && strncmp (disas.buffer, "ret", 3) != 0
      && strncmp (disas.buffer, "call", 4) != 0)
    return false;

  /* The instruction has to cross or end on a 32-byte boundary.  */
  bfd_vma start = insns.code_base + offset;
  bfd_vma end   = start + len - 1;

  if ((end > start && ((start & ~0x1F) != (end & ~0x1F)))
      || (end & 0x1F) == 0x1F)
    return true;

  return false;
}

static bool
is_affected_fused_insn (bfd_vma prev_offset, uint prev_len)
{
  /* If the current instruction is a conditional jump and the previous instruction
     could be fused with it, and the previous instruction crossed or ended
     on a 32-byte boundary, then it can be affected too.  */
  if (disas.buffer[0] != 'j' || strncmp (disas.buffer, "jmp", 3) == 0)
    return false;

  bfd_vma start = insns.code_base + prev_offset;
  bfd_vma end   = start + prev_len - 1;

  if ((end > start && ((start & ~0x1F) != (end & ~0x1F)))
      || (end & 0x1F) == 0x1F)
    return true;

  return false;
}

static bool
is_fusable (void)
{
  static const char * fusable_insns[] =
    {
     "cmp", "test", "add", "sub", "and", "inc", "dec"
    };
  int i;

  for (i = 0; i < ARRAY_SIZE (fusable_insns); i++)
    if (strncmp (disas.buffer, fusable_insns[i], strlen (fusable_insns[1])) == 0)
      return true;
  return false;
}

static bool
check_sec (annocheck_data *     data,
	   annocheck_section *  sec)
{
  if (sec->data->d_size == 0)
    return true;

  if (sec->shdr.sh_type == SHT_PROGBITS
      && sec->shdr.sh_flags & SHF_EXECINSTR
      && sec->shdr.sh_size > 0)
    {
      bfd_vma           offset;
      bfd_vma           next_offset;
      bfd_vma           prev_offset = 0;
      int               prev_len = 0;
      bool              prev_is_fusable = false;
      disassemble_info  info;

      if (disas.alloc == 0)
	{
	  disas.alloc  = 128;
	  disas.buffer = xmalloc (disas.alloc);
	}

      memset (& insns, 0, sizeof insns);
      insns.code = (bfd_byte *) sec->data->d_buf;
      insns.size = sec->shdr.sh_size;
      insns.code_base = sec->shdr.sh_addr;

      /* Initialise the non-NULL fields in the disassembler info structure.  */
      init_disassemble_info (& info, stdout, x86_printf);
      info.application_data   = & insns;
      info.stream             = & insns;
      info.endian_code        = BFD_ENDIAN_LITTLE;
      info.read_memory_func   = x86_read_mem;
      info.memory_error_func  = x86_mem_err;
      info.arch               = bfd_arch_i386;
      info.mach               = bfd_mach_x86_64;
      info.print_address_func = x86_addr;
      disassemble_init_for_target (& info);
      
      /* Walk the instructions in this section.  */
      for (offset = 0; offset < sec->shdr.sh_size; offset = next_offset)
	{
	  extern int print_insn_i386 (bfd_vma, disassemble_info *);
	  int len;

	  disas.pos = 0;
	  disas.buffer[0] = 0;
	  len = print_insn_i386 (offset, & info);

	  if (len < 1)
	    {
	      einfo (INFO, "%s: %s: WARN: Unable to classify insn at addr %lx\n",
		     data->filename, sec->secname, insns.code_base + offset);
	      break;
	    }

	  if (is_affected_insn (offset, len))
	    {
	      einfo (VERBOSE, "%s: %s: %#lx: cache line crossed/hit, insn: %s\n",
		     data->filename, sec->secname, insns.code_base + offset,
		     disas.buffer);
	      ++ num_found;
	    }

	  if (prev_is_fusable && is_affected_fused_insn (prev_offset, prev_len))
	    {
	      einfo (VERBOSE, "%s: %s: %#lx: FUSED instructions cross cache line: %s\n",
		     data->filename, sec->secname, insns.code_base + offset,
		     disas.buffer);
	      ++ num_found;
	    }

	  einfo (VERBOSE2, "%s: %s: %lx: %s\n",
		 data->filename, sec->secname, insns.code_base + offset, disas.buffer);

	  prev_offset = offset;
	  prev_len    = len;
	  prev_is_fusable = is_fusable ();
	  next_offset = offset + len;
	}
    }
  
  return true;
}

static void
usage (void)
{
  einfo (INFO, "  Detects the presence of branch instructions that cross a 64-byte cache line boundary");
}

static bool
process_arg (const char * arg, const char ** argv, const uint argc, uint * next_indx)
{
  return false;
}

static void
version (void)
{
  einfo (INFO, "Version 1.0");
}

static bool
end_file (annocheck_data * data)
{
  if (disabled)
    return false;

  free (disas.buffer);

  if (num_found == 0)
    einfo (INFO, "%s: No potential vulnerabilities found", data->filename);
  else if (BE_VERBOSE)
    einfo (VERBOSE, "%s: %u potential vulnerabilities found", data->filename, num_found);
  else
    einfo (INFO, "%s: %u potential vulnerabilities found.  Rerun with --verbose to see where", data->filename, num_found);

  return num_found == 0;
}

struct checker jcc_checker = 
{
  "JCC Checker",
  start_file,
  interesting_sec,
  check_sec, 
  NULL, /* interesting_seg */
  NULL, /* check_seg */
  end_file,
  process_arg, /* process_arg  */
  usage,
  version,
  NULL, /* start_scan */
  NULL, /* end_scan */
  NULL /* internal */
};

static __attribute__((constructor)) void
register_checker (void) 
{
  if (! annocheck_add_checker (& jcc_checker, ANNOBIN_VERSION / 100))
    disabled = true;
}
