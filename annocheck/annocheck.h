/* Annocheck - A tool for checking security features of binares.
   Copyright (c) 2018 - 2019 Red Hat.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#ifndef __ANNOCHECK_H__
#define __ANNOCHECK_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

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
#include <demangle.h>

#define PACKAGE                         "annocheck"

typedef unsigned char  uchar;
typedef unsigned int   uint;
typedef unsigned long  ulong;

typedef struct annocheck_data
{
  const char *         filename;
  const char *         full_filename;
  int                  fd;
  Elf *                elf;
  bool                 is_32bit;
  Elf_Data *           syms;
  Dwarf *              dwarf;
  int                  dwarf_fd;
  bool                 dwarf_searched;
  const char *         dwarf_filename;
} annocheck_data;

typedef struct annocheck_section
{
  const char *         secname;
  Elf_Scn *            scn;
  Elf64_Shdr           shdr;
  Elf_Data *           data;
} annocheck_section;

typedef struct annocheck_segment
{
  GElf_Phdr *          phdr;
  uint                 number;
  Elf_Data *           data;
} annocheck_segment;

/* This is the structure used to communicate between the annocheck framework
   and the checker tools.  If this structure is changed (or the sub structures
   above) then increment the major_version value in global-annocheck.h  */

typedef struct checker
{
  /* Name of the checker.  Must be unique amoungst all registered checkers.  */
  const char * name;

  /* Called before starting the check of a file.
     Can be NULL.  If it is NULL, annocheck will act as if it had returned true.
     The section_headers and segment_headers fields will not have been initialised.
     Returns true if the checker wishes to examine the file and false if it does not.
     If false is returned the INTERESTING_xxx, CHECK_xxx, and END_FILE functions will
     not be called for that file.  */
  bool (* start_file) (annocheck_data * DATA);

  /* Called to see if the checker is interested in the particular section.
     Can be NULL.  If NULL, all sections are ignored.
     If FALSE is returned the section is not processed any further.
     Note - called even if there are segments in the file.
     Note - SECTION->data may not be initialised at this point.  */
  bool (* interesting_sec) (annocheck_data *     DATA,
			    annocheck_section *  SECTION);

  /* Called to check a section.
     If interesting_sec is not NULL and can return TRUE, then this field cannot be NULL.
     If FALSE is returned the check is considered to have failed.
     Note - SECTION->data will be initialised at this point.  */
  bool (* check_sec) (annocheck_data *     DATA,
		      annocheck_section *  SECTION);

  /* Called to see if the checker is interested in the particular segment.
     Can be NULL.  If NULL, all segments are ignored.
     If FALSE is returned the segment is not processed any further.
     Note - called even if there are sections in the file.
     The SEG->DATA field may not have beeen initialised.  */
  bool (* interesting_seg) (annocheck_data *    DATA,
			    annocheck_segment * SEG);

  /* Called to check a segment.
     If interesting_seg is not NULL and can return TRUE, then this field cannot be NULL.
     If FALSE is returned the check is considered to have failed.
     the SEG->DATA field will have been initialised.  */
  bool (* check_seg) (annocheck_data *    DATA,
		      annocheck_segment * SEG);

  /* Called at the end of checking a file.
     Can be NULL.
     Returns a success/fail status for the entirity of that file.  */
  bool (* end_file) (annocheck_data * DATA);

  /* Called to allow the callback a chance to handle its own command line arguments.
     Can be NULL.
     ARG is the command line argument to be processed.  It might not start with a '-'.
     ARGV is the array of command line arguments.  ARG == ARGV[(*NEXT_INDX) - 1].
     ARGC is the number of entries in ARGV.
     NEXT_INDEX contains the index of the next argument to be processed.  Can be
     incremented in order to skip paramters to ARG.  */
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

  /* Called at the start of a scan of a set of input files for a given recursion depth.
     Called after PROCESS_ARG has been invoked, if that function is not NULL.
     Can be NULL unless END_SCAN is defined.
     LEVEL is the recursion level for annocheck.  Level 0 is the top level.
     DATAFILE is the pathname of a file that can be used to pass data between iterations.
     The file is unique to each checker.  The same file is used at all recursion depths.  */
  void (* start_scan) (uint LEVEL, const char * DATAFILE);

  /* Called at the end of the scan of all of the input files at a given recursion depth.
     Can be NULL.
     LEVEL is the recursion level for annocheck.  Level 0 is the top level.
     DATAFILE is the pathname of a file that can be used to pass data between iterations.
     The file is unique to each checker.  The same file is used at all recursion depths.  */
  void (* end_scan) (uint LEVEL, const char * DATAFILE);

  /* Pointer to internal data used by the annocheck framework.
     This field should not be used by the checker.  */
  void * internal;

} checker;

#undef PTR

/* Type for the ELF note walker.  */
typedef bool (*  note_walker) (annocheck_data *     DATA,
			       annocheck_section *  SEC,
			       GElf_Nhdr *          NOTE,
			       size_t               NAME_OFFSET,
			       size_t               DESC_OFFSET,
			       void *               PTR);

/* Walks over the notes in SECTION, applying FNC to each.
   Stops if FUNC returns FALSE.
   Passes PTR to FNC along with a pointer to the note and the offsets to the name and desc data fields.
   Returns FALSE if it could not walk the notes.  */
extern bool annocheck_walk_notes (annocheck_data * DATA, annocheck_section * SEC, note_walker FNC, void * PTR);

/* Type for the DWARF DIE walker.  */
typedef bool (*  dwarf_walker) (annocheck_data * DATA, Dwarf * DWARF, Dwarf_Die * DIE, void * PTR);

/* Walks over the DWARF DIEs in DATA, applying FNC to each.
   Stops if FNC returns FALSE.
   Passes PTR to FUNC along with a pointer to the DIE.
   Returns FALSE if it could not walk the debug information.  */
extern bool annocheck_walk_dwarf (annocheck_data * DATA, dwarf_walker FNC, void * PTR);

/* Called to register a checker.
   Returns FALSE if the checker could not be registered.
   Can be called from static constructors.
   The MAJOR version number is used to verify that the checker is compatible with the framework.  */
extern bool annocheck_add_checker (struct checker * CHECKER, uint MAJOR);

/* Return the name of a symbol most appropriate for address START..END.
   Returns NULL if no symbol could be found.  */
extern const char *  annocheck_find_symbol_for_address_range
  (annocheck_data * DATA, annocheck_section * SEC, ulong START, ulong ADDR, bool PREFER_FUNC);

/* Return the name of a symbol most appropriate for address START..END.
   Returns NULL if no symbol could be found.
   If non-NULL SEC is examined first, if it is a symbol section.
   If a name is found, and the symbol's ELF type is available, return it in TYPE_RETURN.  */
extern const char *  annocheck_get_symbol_name_and_type
  (annocheck_data * DATA, annocheck_section * SEC, ulong START, ulong ADDR, bool PREFER_FUNC, uint * TYPE_RETURN);

/* Look for symbol NAME.
   Returns TRUE if found, FALSE otherwise.
   If found returns the symbol's value in VALUE_RETURN (if non-NULL)
   and the section index in SECTION_RETURN (again if non-NULL).  */
extern bool annocheck_find_symbol_by_name
  (annocheck_data * DATA, const char * NAME, ulong * VALUE_RETURN, uint * SECTION_RETURN);

/* Runs the given CHECKER over the sections and segments in FD.
   The filename associated with FD is assumed to be EXTRA_FILENAME.
   the filename associated with the file that prompted the need for these extra checks is ORIGINAL_FILENAME.  */
extern bool annocheck_process_extra_file (checker * CHECKER, const char * EXTRA_FILENAME, const char * ORIGINAL_FILENAME, int FD);

/* Functions used by LIBANNOCHECK to access annocheck features.  */
/* Add FILENAME to the list of files to process.  */
extern void add_file (const char * FILENAME);
/* Process the current list of files.  */
extern bool process_files (void);
/* Set the debug file path.  */
extern bool set_debug_file (const char *);


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

#endif /* __ANNOCHECK_H__ */
