/* annobin - a clang plugin for annotating the output binary file.
   Copyright (c) 2019 Red Hat.
   Created by Nick Clifton and Serge Guelton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/PreprocessorOptions.h"
#include "clang/Sema/SemaConsumer.h"
#include "llvm/Support/raw_ostream.h"

using namespace std;
using namespace clang;
using namespace llvm;

#include "annobin-global.h"
#include <string.h>
#include <ctype.h>


#define inform(FORMAT, ...)				    \
  do							    \
    {							    \
      fflush (stdout);					    \
      fprintf (stderr, "Annobin plugin for clang: ");	    \
      fprintf (stderr, FORMAT, ## __VA_ARGS__);		    \
      putc ('\n', stderr);				    \
    }							    \
  while (0)
  
#define verbose(FORMAT, ...)				    \
  do							    \
    {							    \
      if (be_verbose)					    \
	{						    \
          fflush (stdout);				    \
          fprintf (stderr, "Annobin plugin for clang: ");   \
          fprintf (stderr, FORMAT, ## __VA_ARGS__);	    \
          putc ('\n', stderr);				    \
	}						    \
    }							    \
  while (0)

#define ice(FORMAT, ...)				    \
  do							    \
    {							    \
      fflush (stdout);					    \
      fprintf (stderr, "Annobin plugin for clang: Internal Error: ");	    \
      fprintf (stderr, FORMAT, ## __VA_ARGS__);		    \
      putc ('\n', stderr);				    \
      exit (-1);					    \
    }							    \
  while (0)

namespace
{
  /* Version number.  NB: Keep the numeric and string versions in sync
     Also, keep in sync with the major_version and minor_version definitions
     in annocheck/annocheck.c.
     FIXME: This value should be defined in only one place...  */
  static unsigned int   annobin_version = 901;
  static const char *   version_string = "901";
  static bool           be_verbose = false;
  static bool           target_start_sym_bias = false;
  static const char *   annobin_current_file_start = "_annobin_current_file_start";
  static const char *   annobin_current_file_end   = "_annobin_current_file_end";
  
  class AnnobinConsumer : public ASTConsumer
  {
private:
    CompilerInstance& CI;

  public:
    AnnobinConsumer (CompilerInstance & CI) : CI (CI)
    {
    }

#define START_TEXT   "\
\t.pushsection .text\n\
\t.global _annobin_current_file_start\n\
\t.type   _annobin_current_file_start, STT_NOTYPE\n\
\t.equiv  _annobin_current_file_start, .text\n\
\t.size   _annobin_current_file_start, 0\n\
\t.pushsection .text.zzz\n\
\t.global _annobin_current_file_end\n			\
\t.type   _annobin_current_file_end, STT_NOTYPE\n\
\t.equiv  _annobin_current_file_end, .text.zzz\n\
\t.size   _annobin_current_file_end, 0\n\
\t.popsection\n"
    
    
    void
    HandleTranslationUnit (ASTContext & Context) override
    {
      verbose ("Generate start symbol");
      AddAsmText (Context, START_TEXT);
      
      char buf [64];

      verbose ("Generate version note");
      sprintf (buf, "%dL%d", SPEC_VERSION, annobin_version);
      OutputStringNote (Context,
			GNU_BUILD_ATTRIBUTE_VERSION, buf,
			"version note",
			annobin_current_file_start,
			annobin_current_file_end,
			GNU_BUILD_ATTRS_SECTION_NAME);

      verbose ("Generate run note");
      OutputStringNote (Context,
			GNU_BUILD_ATTRIBUTE_TOOL,
			"running clang 7.0.1",
			"tool note",
			annobin_current_file_start,
			annobin_current_file_end,
			GNU_BUILD_ATTRS_SECTION_NAME);
			
      verbose ("Generate build note");
      OutputStringNote (Context,
			GNU_BUILD_ATTRIBUTE_TOOL,
			"annobin clang 7.0.1",
			"tool note",
			annobin_current_file_start,
			annobin_current_file_end,
			GNU_BUILD_ATTRS_SECTION_NAME);
			
      CheckOptions (CI, Context);
    }

  private:

    void
    AddAsmText (ASTContext & Context, StringRef text)
    {
      auto* TU = Context.getTranslationUnitDecl ();

      // SG: this is an ultra trick :-)
      // First I'm creating a new FileScopeAsmDecl
      // and then I'm calling the whole **global** ASTconsumer on it.
      // This ends up calling all the consumers, including the backend one
      // and so the decl gets added in the right place.
      Decl* NewDecl = FileScopeAsmDecl::Create
	(Context,
	 TU,
	 clang::StringLiteral::Create (Context, text, clang::StringLiteral::Ascii,
				       /*Pascal*/ false,
				       Context.getConstantArrayType (Context.CharTy,
								     llvm::APInt(32, text.size() + 1),
								     clang::ArrayType::Normal,
								     /*IndexTypeQuals*/ 0
								     ),
				       SourceLocation()),
	 {},
	 {});

      CI.getASTConsumer().HandleTopLevelDecl (DeclGroupRef (NewDecl));
    }
    
    static void
    add_line_to_note (char * buffer, const char * text, const char * comment = NULL)
    {
      static char buf[12800];

      if (comment)
	sprintf (buf, "\t%s \t/* %s */\n", text, comment);
      else
	sprintf (buf, "\t%s\n", text);
      strcat (buffer, buf);
    }
    
    void
    OutputNote (ASTContext &  Context,
		const char *  name,
		unsigned      namesz,
		bool          name_is_string,
		const char *  name_description,
		unsigned int  type,
		const char *  start_symbol,
		const char *  end_symbol,
		const char *  section_name)
    {
      static char text_buffer[2560] = {0};
      static char buf[1280];
      static const int align = 4;
      
      sprintf (buf, ".pushsection %s, \"\", %%note", section_name);
      add_line_to_note (text_buffer, buf);
      sprintf (buf, ".balign %d", align);
      add_line_to_note (text_buffer, buf);

      if (name == NULL)
	{
	  if (namesz)
	    ice ("null name with non-zero size");

	  add_line_to_note (text_buffer, ".dc.l 0", "no name");
	}
      else if (name_is_string)
	{
	  char buf2[128];

	  if (strlen ((char *) name) != namesz - 1)
	    ice ("name string does not match name size");

	  sprintf (buf, ".dc.l %u", namesz);
	  sprintf (buf2, "size of name [= strlen (%s)]\n", name);
	  add_line_to_note (text_buffer, buf, buf2);
	}
      else
	{
	  sprintf (buf, ".dc.l %u", namesz);
	  add_line_to_note (text_buffer, buf, "size of name");
	}

      if (start_symbol != NULL)
	{
	  if (end_symbol == NULL)
	    ice ("start symbol without an end symbol");

	  add_line_to_note (text_buffer, ".dc.l 16", "description size [= 2 * sizeof (address)]");
	}
      else
	{
	  if (end_symbol != NULL)
	    ice ("end symbol without a start symbol");
	  add_line_to_note (text_buffer, ".dc.l 0", "no description");
	}

      sprintf (buf, ".dc.l %d", type);
      add_line_to_note (text_buffer, buf, "note type [256 = GLOBAL, 257 = FUNCTION]");

      if (name)
	{
	  if (name_is_string)
	    {
	      add_line_to_note (text_buffer, name, name_description);
	    }
	  else
	    {
	      sprintf (buf, ".dc.b");

	      int i;
	      for (i = 0; i < namesz; i++)
		{
		  sprintf (buf + strlen (buf), " %#x%c", ((unsigned char *) name)[i],
			   i < (namesz - 1) ? ',' : ' ');
		}

	      add_line_to_note (text_buffer, buf, name_description);
	    }

	  if (namesz % align)
	    {
	      sprintf (buf, ".dc.b");
	      while (namesz % align)
		{
		  namesz++;
		  if (namesz % align)
		    strcat (buf, " 0,");
		  else
		    strcat (buf, " 0");
		}
	      add_line_to_note (text_buffer, buf, "padding");
	    }
	}

      if (start_symbol)
	{
	  sprintf (buf, ".quad %s", (char *) start_symbol);
	  if (target_start_sym_bias)
	    {
	      /* We know that the annobin_current_filename symbol has been
		 biased in order to avoid conflicting with the function
		 name symbol for the first function in the file.  So reverse
		 that bias here.  */
	      if (start_symbol == annobin_current_file_start)
		sprintf (buf + strlen (buf), "- %d", target_start_sym_bias);
	    }

	  add_line_to_note (text_buffer, buf, "start symbol");

	  sprintf (buf, ".quad %s", (char *) end_symbol);
	  add_line_to_note (text_buffer, buf, "end symbol");
	}

      add_line_to_note (text_buffer, "\t.popsection\n\n");

      AddAsmText (Context, text_buffer);
    }

    void
    OutputStringNote (ASTContext &  Context,
		      const char    string_type,
		      const char *  string,
		      const char *  name_description,
		      const char *  start_symbol,
		      const char *  end_symbol,
		      const char *  section_name)
    {
      unsigned int len = strlen (string);
      char * buffer;

      buffer = (char *) malloc (len + 5);

      sprintf (buffer, "GA%c%c%s", GNU_BUILD_ATTRIBUTE_TYPE_STRING, string_type, string);

      /* Be kind to readers of the assembler source, and do
	 not put control characters into ascii strings.  */
      OutputNote (Context,
		  buffer, len + 5, isprint (string_type), name_description,
		  OPEN,
		  start_symbol, end_symbol, section_name);

      free (buffer);
    }

    void
    CheckOptions (CompilerInstance & CI, ASTContext & Context)
    {
      char buffer [128];
      const CodeGenOptions & CodeOpts = CI.getCodeGenOpts ();

      verbose ("Checking options..");
#if 1
      verbose ("Record cf-protection: (branch: %s) (return: %s)",
	       CodeOpts.CFProtectionBranch ? "on" : "off",
	       CodeOpts.CFProtectionReturn ? "on" : "off"
	       );
      unsigned len = sprintf (buffer, "GA%ccf_protection", NUMERIC);
      char val = 0;
      val += CodeOpts.CFProtectionBranch ? 1 : 0;
      val += CodeOpts.CFProtectionReturn ? 2 : 0;
      /* We bias the value by 1 so that we do not get confused by a zero value.  */
      val += 1;
      buffer[++len] = val;
      buffer[++len] = 0;

      OutputNote (Context, buffer, len + 1, false, "-fcf-protection status",
		  OPEN,
		  annobin_current_file_start, annobin_current_file_end,
		  GNU_BUILD_ATTRS_SECTION_NAME);
#endif
      
      // The -cfguard option is Windows only - so we ignore it.

#if 1
      verbose ("Record -O: %d", CodeOpts.OptimizationLevel);
      len = sprintf (buffer, "GA%cGOW", NUMERIC);
      val = CodeOpts.OptimizationLevel;
      if (val > 3)
	val = 3;
      buffer[++len] = 0x3;
      buffer[++len] = val << 1;
      buffer[++len] = 0;

      OutputNote (Context, buffer, len + 1, false, "Optimization Level",
		  OPEN,
		  annobin_current_file_start, annobin_current_file_end,
		  GNU_BUILD_ATTRS_SECTION_NAME);
#endif

#if CLANG_VERSION_MAJOR > 7
      verbose ("Record speculative load hardening: %s", CodeOpts.SpeculativeLoadHardening ? "on" : "off");

      len = sprintf (buffer, "GA%cSpecLoadHarden", NUMERIC);
      buffer[++len] = CodeOpts.SpeculativeLoadHardening ? 2 : 1;
      buffer[++len] = 0;

      OutputNote (Context, buffer, len + 1, false, "Speculative Load Hardening",
		  OPEN,
		  annobin_current_file_start, annobin_current_file_end,
		  GNU_BUILD_ATTRS_SECTION_NAME);
#endif
      
      const LangOptions & lang_opts = CI.getLangOpts ();
      if (lang_opts.ModuleFeatures.empty ())
	{
	  verbose ("No language module features");
	}
      else
	{
	  for (StringRef Feature : lang_opts.ModuleFeatures)
	    verbose ("Language module features: %s",  Feature.str().c_str());
	}

      verbose ("Setjmp exceptions: %u", lang_opts.SjLjExceptions);

      const PreprocessorOptions & pre_opts = CI.getPreprocessorOpts ();
      if (pre_opts.Macros.empty ())
	{
	  verbose ("No preprocessor macros");
	}
      else
	{
	  for (std::vector<std::pair<std::string, bool/*isUndef*/> >::const_iterator
		 i = pre_opts.Macros.begin (),
		 iEnd = pre_opts.Macros.end ();
	       i != iEnd; ++i)
	    {
	      if (! i->second)
		verbose ("Define: %s", i->first.c_str());
	    }
	}

      const clang::TargetOptions & targ_opts = CI.getTargetOpts ();
      if (targ_opts.FeaturesAsWritten.empty ())
	{
	  verbose ("No target options");
	}
      else
	{
	  for (unsigned i = targ_opts.FeaturesAsWritten.size(); i -- > 0;)
	    verbose ("Target feature: %s", targ_opts.FeaturesAsWritten[i].c_str());
	}
    }    
  };

  class AnnobinDummyConsumer : public SemaConsumer
  {
    CompilerInstance & Instance;

  public:
    AnnobinDummyConsumer (CompilerInstance & Instance) : Instance (Instance)
    {}

    void
    HandleTranslationUnit (ASTContext & Context) override
    {
    }
  };
  
  class AnnobinAction : public PluginASTAction
  {
  private:
    bool enabled = true;

  protected:
    std::unique_ptr<ASTConsumer>
    CreateASTConsumer (CompilerInstance& CI, llvm::StringRef) override
    {
      if (enabled)
	return std::make_unique<AnnobinConsumer>(CI);
      else
	return std::make_unique<AnnobinDummyConsumer>(CI);
    }

    // Automatically run the plugin
    PluginASTAction::ActionType 
    getActionType (void) override
    {
      return AddBeforeMainAction;
    }

    // We do not want the plugin to stop the compilation of the binary.
    bool
    usesPreprocessorOnly (void) const override
    {
      return false;
    }

    // Handle any options passed to the plugin.
    bool
    ParseArgs (const CompilerInstance & CI, const std::vector<std::string>& args) override
    {
      for (unsigned i = 0, e = args.size(); i < e; ++i)
	{
	  if (args[i] == "help")
	    inform ("supported options:\n\
  help      Display this message\n\
  disable   Disable the plugin\n\
  enable    Reenable the plugin if it has been disabled\n\
  version   Displays the version number\n\
  verbose   Produce descriptive messages whilst working");
	  else if (args[i] == "disable")
	    enabled = false;
	  else if (args[i] == "enable")
	    enabled = true;
	  else if (args[i] == "version")
	    inform ("version %s", version_string);
	  else if (args[i] == "verbose")
	    be_verbose = true;
	  else
	    inform ("error: unknown option: %s", args[i].c_str());
	}

      return true;
    }
  };
}

static FrontendPluginRegistry::Add<AnnobinAction>
X("annobin", "annotate binary output");
