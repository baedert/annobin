/* Annocheck - A tool for checking security features of binares.
   Copyright (c) 2018 Red Hat.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#ifndef __EU_CHECKSEC_H__
#define __EU_CHECKSEC_H__

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <fcntl.h>
#include <ctype.h>

#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <dwarf.h>
#include <elfutils/libdw.h>

#include <libiberty.h>

#define PACKAGE                         "annocheck"

/* Values used by annobin notes.  */
#define GNU_BUILD_ATTRS_SECTION_NAME		".gnu.build.attributes"
#define NT_GNU_BUILD_ATTRIBUTE_OPEN		0x100
#define NT_GNU_BUILD_ATTRIBUTE_FUNC		0x101
#define GNU_BUILD_ATTRIBUTE_TYPE_NUMERIC	'*'
#define GNU_BUILD_ATTRIBUTE_TYPE_STRING		'$'
#define GNU_BUILD_ATTRIBUTE_TYPE_BOOL_TRUE	'+'
#define GNU_BUILD_ATTRIBUTE_TYPE_BOOL_FALSE	'!'

#define GNU_BUILD_ATTRIBUTE_VERSION		1
#define GNU_BUILD_ATTRIBUTE_STACK_PROT		2
#define GNU_BUILD_ATTRIBUTE_RELRO		3
#define GNU_BUILD_ATTRIBUTE_STACK_SIZE		4
#define GNU_BUILD_ATTRIBUTE_TOOL		5
#define GNU_BUILD_ATTRIBUTE_ABI			6
#define GNU_BUILD_ATTRIBUTE_PIC			7
#define GNU_BUILD_ATTRIBUTE_SHORT_ENUM		8


#define streq(a,b)	  (strcmp ((a), (b)) == 0)
#define strneq(a,b,n)	  (strncmp ((a), (b), (n)) == 0)
#define const_strneq(a,b) (strncmp ((a), (b), sizeof (b) - 1) == 0)

typedef unsigned char  uchar;
typedef unsigned int   uint;
typedef unsigned long  ulong;

typedef struct eu_checksec_data
{
  const char *         filename;
  const char *         full_filename;
  int                  fd;
  Elf *                elf;
  bool                 is_32bit;
  Elf_Data *           syms;
  Dwarf *              dwarf;
  bool                 dwarf_searched;
} eu_checksec_data;

typedef struct eu_checksec_section
{
  const char *         secname;
  Elf_Scn *            scn;
  Elf64_Shdr           shdr;
  Elf_Data *           data;
} eu_checksec_section;

typedef struct eu_checksec_segment
{
  GElf_Phdr *          phdr;
  uint                 number;
  Elf_Data *           data;
} eu_checksec_segment;

typedef struct checker
{
  const char * name;

  /* Called before starting the check of a file.
     Can be NULL.
     The section_headers and segment_headers fields will not have been initialised.  */
  void (* start) (eu_checksec_data * DATA);

  /* Called to see if the checker is interested in the particular section.
     Can be NULL.  If NULL, all sections are ignored.
     If FALSE is returned the section is not processed any further.
     Note - called even if there are segments in the file.
     Note - SECTION->data may not be initialised at this point.  */
  bool (* interesting_sec) (eu_checksec_data *     DATA,
			    eu_checksec_section *  SECTION);

  /* Called to check a section.
     If interesting_sec is not NULL, then this field cannot be NULL.
     If FALSE is returned the check is considered to have failed.
     Note - SECTION->data will be initialised at this point.  */
  bool (* check_sec) (eu_checksec_data *     DATA,
		      eu_checksec_section *  SECTION);

  /* Called before checking a segment.
     Can be NULL.  If NULL, all segments are ignored.
     If FALSE is returned the segment is not processed any further.
     Note - called even if there are sections in the file.
     The SEG->DATA field may not have beeen initialised.  */
  bool (* interesting_seg) (eu_checksec_data *    DATA,
			    eu_checksec_segment * SEG);

  /* Called to check a segment.
     If interesting_seg is not NULL, then this field cannot be NULL.
     If FALSE is returned the check is considered to have failed.
     the SEG->DATA field will have been initialised.  */
  bool (* check_seg) (eu_checksec_data *    DATA,
		      eu_checksec_segment * SEG);

  /* Called at the end of checking a file.
     Can be NULL.
     Returns a success/fail status for the entire scan.  */
  bool (* finish) (eu_checksec_data * DATA);

  /* Called to allow the callback a chance to handle its own command line arguments.
     Can be NULL.  */
  bool (* process_arg) (const char * ARG, const char ** ARGV, const uint ARGC, uint * NEXT_INDX);

  /* Called to add additional text to the --help output.
     Should include a short description of what the checker does.
     Can be NULL.
     Should use einfo to display its information.  */
  void (* usage) (void);

  /* Called to display the version of the checker.
     Can be NULL.
     Should use einfo to display its information.  */
  void (* version) (void);
  
  /* Pointer to internal data used by the checksec framework.
     This field should not be used by the checker.  */
  void * internal;

} checker;

#undef PTR

/* Type for the ELF note walker.  */
typedef bool (*  note_walker) (eu_checksec_data *     DATA,
			       eu_checksec_section *  SEC,
			       GElf_Nhdr *            NOTE,
			       size_t                 NAME_OFFSET,
			       size_t                 DESC_OFFSET,
			       void *                 PTR);

/* Walks over the notes in SECTION, applying FUNC to each.
   Stops if FUNC returns FALSE.
   Passes PTR to FUNC along with a pointer to the note and the offsets to the name and desc data fields.
   Returns FALSE if it could not walk the notes.  */
extern bool      eu_checksec_walk_notes (eu_checksec_data * DATA, eu_checksec_section * SEC, note_walker FUNC, void * PTR);

/* Type for the DWARF DIE walker.  */
typedef bool (*  dwarf_walker) (eu_checksec_data * DATA, Dwarf * DWARF, Dwarf_Die * DIE, void * PTR);

/* Walks over the DWARF DIEs in DATA, applying FUNC to each.
   Stops if FUNC returns FALSE.
   Passes PTR to FUNC along with a pointer to the DIE.
   Returns FALSE if it could not walk the debug information.  */
extern bool      eu_checksec_walk_dwarf (eu_checksec_data * DATA, dwarf_walker FUNC, void * PTR);

/* Called to register a checker.
   Returns FALSE if the checker could not be registered.
   Can be called from static constructors.
   The MAJOR version number is used to verify that the checker is compatible with the framework.  */
extern bool      eu_checksec_add_checker (struct checker * CHECKER, uint MAJOR);

/* Return the name of a symbol most appropriate for address START..END.
   Returns NULL if no symbol could be found.  */
extern const char *  eu_checksec_find_symbol_for_address_range
  (eu_checksec_data * DATA, eu_checksec_section * SEC, ulong START, ulong ADDR, bool PREFER_FUNC);

/* An enum controlling the behaviour of the einfo function:  */
typedef enum einfo_type
{
  WARN,		/* Issues a warning message.  */
  SYS_WARN,     /* Like WARN but also prints out errno.  */
  ERROR,        /* Issues an error message.  */
  SYS_ERROR,    /* Like ERROR but also prints out errno.  */
  FAIL,         /* Like ERROR but also calls abort().  */
  INFO,         /* Prints an informative message (on stdout).  */
  VERBOSE,      /* Like INFO but only generates the message if verbose is set.  */
  VERBOSE2,     /* Like VERBOSE but only generates the message if verbose was set twice.  */
  PARTIAL       /* Like INFO but no EOL required.  */
} einfo_type;

/* A printf like function for displaying text.  */
extern bool         einfo (einfo_type, const char *, ...) ATTRIBUTE_PRINTF(2, 3);

/* How informative we should be.  */
extern ulong        verbosity;

#define BE_VERY_VERBOSE  (verbosity > 1)
#define BE_VERBOSE       (verbosity > 0)
#define BE_QUIET         (verbosity == -1UL)

/* The version numbers of the checksec framework.  */
extern uint major_version;
extern uint minor_version;

#endif /* __EU_CHECKSEC_H__ */
