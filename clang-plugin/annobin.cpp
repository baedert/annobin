/* annobin - a clang plugin for annotating the output binary file.
   Copyright (c) 2019, 2020 Red Hat.
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
#include "clang/Basic/Version.h"
#include "clang/Basic/TargetInfo.h"

using namespace std;
using namespace clang;
using namespace llvm;

#include "annobin-global.h"
#include <cstring>
#include <cctype>
#include <cstdarg>
#include <sstream>

namespace
{
  static const unsigned int   annobin_version = ANNOBIN_VERSION;
  bool                        be_verbose = false;

  // Helper functions used throughout this file.
  template<class... Tys>
  char *
  concat (Tys const&... args)
  {
    std::ostringstream oss;

    (void) std::initializer_list<int>{((oss << args), 1)...};
    return strdup (oss.str().c_str());
  }

  static inline void
  inform (char const fmt[], ...)
  {
    va_list args;

    va_start (args, fmt);
    fflush (stdout);
    fprintf (stderr, "Annobin: ");
    vfprintf (stderr, fmt, args);
    fputc ('\n', stderr);
    va_end (args);
  }

  static inline void
  verbose (char const fmt[], ...)
  {
    if (! be_verbose)
      return;

    va_list args;

    va_start (args, fmt);
    fflush (stdout);
    fprintf (stderr, "Annobin: ");
    vfprintf (stderr, fmt, args);
    fputc ('\n', stderr);
    va_end (args);
  }

  static inline void
  ice (char const fmt[], ...)
  {
    va_list args;

    va_start (args, fmt);
    fflush (stdout);
    fprintf (stderr, "Annobin: Internal Error: ");
    vfprintf (stderr, fmt , args);
    fputc ('\n', stderr);
    va_end (args);
    exit (EXIT_FAILURE);
  }

  class AnnobinConsumer : public ASTConsumer
  {
private:
    CompilerInstance& CI;
    unsigned int      target_start_sym_bias = 0;
    bool              is_32bit = false;
    char const*       annobin_current_file_start = nullptr;
    char const*       annobin_current_file_end = nullptr;

  public:
    AnnobinConsumer (CompilerInstance & CI) : CI (CI)
    {
    }
    
    void
    HandleTranslationUnit (ASTContext & Context) override
    {
      static char buf [6400];  // FIXME: Use a dynmically allocated buffer.

      is_32bit = Context.getTargetInfo().getPointerWidth(0) == 32;

      SourceManager & src = Context.getSourceManager ();
      std::string filename = src.getFilename (src.getLocForStartOfFile (src.getMainFileID ())).str ().c_str ();

      convert_to_valid_symbol_name (filename);
      verbose ("Generate start and end symbols based on: %s", filename.c_str());
      annobin_current_file_start = concat ("_annobin_", filename, "_start");
      annobin_current_file_end   = concat ("_annobin_", filename, "_end");

      static const char START_TEXT[] = "\
\t.pushsection .text\n\
\t.hidden %s\n\
\t.type   %s, STT_NOTYPE\n\
\t.equiv  %s, .text + %d\n\
\t.size   %s, 0\n\
\t.pushsection .text.zzz\n\
\t.hidden %s\n\
\t.type   %s, STT_NOTYPE\n\
\t.equiv  %s, .text.zzz\n\
\t.size   %s, 0\n\
\t.popsection\n";
      sprintf (buf, START_TEXT,
	       annobin_current_file_start, annobin_current_file_start, annobin_current_file_start,
	       target_start_sym_bias, annobin_current_file_start,
	       annobin_current_file_end, annobin_current_file_end, annobin_current_file_end, annobin_current_file_end);

      AddAsmText (Context, buf);

      sprintf (buf, "%d%c%d", SPEC_VERSION, ANNOBIN_TOOL_ID_CLANG, annobin_version);
      OutputStringNote (Context,
			GNU_BUILD_ATTRIBUTE_VERSION, buf,
			"version note");

      sprintf (buf, "running on %s", getClangFullVersion ().c_str ());
      OutputStringNote (Context, GNU_BUILD_ATTRIBUTE_TOOL,
			buf, "tool note (running on)");
			
      sprintf (buf, "annobin built by clang version %s", CLANG_VERSION_STRING);
      OutputStringNote (Context, GNU_BUILD_ATTRIBUTE_TOOL,
			buf, "tool note (plugin built by)");

      // FIXME: Since we are using documented clang API functions
      // we assume that a version mistmatch bewteen the plugin builder
      // and the plugin consumer does not matter.  Check this...

      CheckOptions (CI, Context);
    }

  private:

    void
    convert_to_valid_symbol_name (std::string& name)
    {
      for( auto & c : name)
	if (!isalnum (c))
	  c = '_';
    }
    
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
								     llvm::APInt (32, text.size () + 1),
#if CLANG_VERSION_MAJOR > 8
								     nullptr,
#endif								     
								     clang::ArrayType::Normal,
								     /*IndexTypeQuals*/ 0),
				       SourceLocation ()),
	 {},
	 {});

      CI.getASTConsumer ().HandleTopLevelDecl (DeclGroupRef (NewDecl));
    }
    
    static void
    add_line_to_note (std::ostringstream & buffer, const char * text, const char * comment = nullptr)
    {
      buffer << '\t' << text;
      if (comment)
        buffer << " \t/* " << comment << " */";
      buffer << '\n';
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
      std::ostringstream text_buffer;
      static char buf[1280];  // FIXME: We should be using a dynamically allocated buffer.
      static const int align = 4;  // FIXME: 8-byte align for 64-bit notes ?

      sprintf (buf, ".pushsection %s, \"\", %%note", section_name);
      add_line_to_note (text_buffer, buf);
      sprintf (buf, ".balign %d", align);
      add_line_to_note (text_buffer, buf);

      if (name == nullptr)
	{
	  if (namesz)
	    ice ("null name with non-zero size");

	  add_line_to_note (text_buffer, ".dc.l 0", "no name");
	}
      else if (name_is_string)
	{
	  char buf2[128];  // FIXME: This should be dynamic and extendable.

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

	  if (is_32bit)
	    add_line_to_note (text_buffer, ".dc.l 8", "description size [= 2 * sizeof (address)]");
	  else
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

	      for (unsigned i = 0; i < namesz; i++)
		sprintf (buf + strlen (buf), " %#x%c", ((unsigned char *) name)[i],
			 i < (namesz - 1) ? ',' : ' ');

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
	  sprintf (buf, "%s %s", is_32bit ? ".dc.l" : ".quad", (char *) start_symbol);
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

	  sprintf (buf, "%s %s", is_32bit ? ".dc.l" : ".quad", (char *) end_symbol);
	  add_line_to_note (text_buffer, buf, "end symbol");
	}

      add_line_to_note (text_buffer, "\t.popsection\n\n");

      AddAsmText (Context, text_buffer.str());
    }

    void
    OutputStringNote (ASTContext &  Context,
		      const char    string_type,
		      const char *  string,
		      const char *  name_description)
    {
      unsigned int len = strlen (string);
      char * buffer;

      buffer = (char *) malloc (len + 5);

      sprintf (buffer, "GA%c%c%s", STRING, string_type, string);

      verbose ("Record %s as '%s'", name_description, string);
      /* Be kind to readers of the assembler source, and do
	 not put control characters into ascii strings.  */
      OutputNote (Context,
		  buffer, len + 5, isprint (string_type), name_description,
		  OPEN, annobin_current_file_start, annobin_current_file_end,
		  GNU_BUILD_ATTRS_SECTION_NAME);

      free (buffer);
    }

    void
    OutputNumericNote (ASTContext &  Context,
		       const char *  numeric_name,
		       unsigned int  val,
		       const char *  name_description)
    {
      char buffer [128];  // FIXME: This should be dynamic and extendable.
      unsigned len = sprintf (buffer, "GA%c%s", NUMERIC, numeric_name);
      char last_byte = 0;

      // For non-alphabetic names, we do not need, or want, the terminating
      // NUL at the end of the string.
      if (! isprint (numeric_name[0]))
	--len;

      verbose ("Record %s value of %u", name_description, val);
	
      do
	{
	  last_byte = buffer[++len] = val & 0xff;
	  val >>= 8;
	}
      while (val);

      if (last_byte != 0)
	buffer[++len] = 0;

      OutputNote (Context, buffer, len + 1, false, name_description,
		  OPEN, annobin_current_file_start, annobin_current_file_end,
		  GNU_BUILD_ATTRS_SECTION_NAME);
    }

    void
    CheckOptions (CompilerInstance & CI, ASTContext & Context)
    {
      const CodeGenOptions & CodeOpts = CI.getCodeGenOpts ();

      unsigned int val = 0;
      val += CodeOpts.CFProtectionBranch ? 1 : 0;
      val += CodeOpts.CFProtectionReturn ? 2 : 0;
      // We bias the value by 1 so that we do not get confused by a zero value.
      val += 1;
      OutputNumericNote (Context, "cf_protection", val, "Control Flow protection");
      
      // The -cfguard option is Windows only - so we ignore it.

      val = CodeOpts.OptimizationLevel;
      if (val > 3)
	val = 3;
      // The optimization level occupies bits 9..11 of the GOW value.
      val <<= 9;
      // FIXME: The value of Context.getDiagnostics().getEnableAllWarnings() does
      // not appear to be valid in clang v9 onwards. :-(
      if (Context.getDiagnostics().getEnableAllWarnings())
	val |= (1 << 14);
      verbose ("Optimization = %d, Wall = %d", CodeOpts.OptimizationLevel, Context.getDiagnostics().getEnableAllWarnings());
      OutputNumericNote (Context, "GOW", val, "Optimization Level and Wall");

#if CLANG_VERSION_MAJOR > 7
      val = CodeOpts.SpeculativeLoadHardening ? 2 : 1;
      OutputNumericNote (Context, "SpecLoadHarden", val, "Speculative Load Hardening");
#endif
      
      const LangOptions & lang_opts = CI.getLangOpts ();

      switch (lang_opts.getStackProtector())
	{
	case clang::LangOptions::SSPStrong: val = 2; break;
	case clang::LangOptions::SSPOff: val = 0; break;
	case clang::LangOptions::SSPOn: val = 1; break;
	default: val = 0; break;
	}
	  
      char stack_prot[2] = {GNU_BUILD_ATTRIBUTE_STACK_PROT, 0};
      OutputNumericNote (Context, stack_prot, val, "Stack Protection");

      val = lang_opts.Sanitize.has (clang::SanitizerKind::SafeStack);
      OutputNumericNote (Context, "sanitize_safe_stack", val, "Sanitize Safe Stack");

      val = lang_opts.Sanitize.has (clang::SanitizerKind::CFICastStrict) ? 1 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFIDerivedCast) ? 2 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFIICall) ? 4 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFIMFCall) ? 8 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFIUnrelatedCast) ? 16 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFINVCall) ? 32 : 0;
      val += lang_opts.Sanitize.has (clang::SanitizerKind::CFIVCall) ? 64 : 0;
      OutputNumericNote (Context, "sanitize_cfi", val, "Sanitize Control Flow Integrity");

      if (lang_opts.PIE)
	val = 4;
      else if (lang_opts.PICLevel > 0)
	val = 2;
      else
	val = 0;
      char pic[2] = {GNU_BUILD_ATTRIBUTE_PIC, 0};
      OutputNumericNote (Context, pic, val, "PIE");
            
#if 0 // Placeholder code for when we need to record preprocessor options
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
#endif

#if 0 // Placeholder code for when we need to record target specific options.
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
#endif
    }    
  };

  class AnnobinDummyConsumer : public SemaConsumer
  {
    CompilerInstance & Instance;

  public:
    AnnobinDummyConsumer (CompilerInstance & Instance) : Instance (Instance)
    {}

    void
    HandleTranslationUnit (ASTContext &) override
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
    ParseArgs (const CompilerInstance & , const std::vector<std::string>& args) override
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
	    inform ("Annobin plugin version: %u", annobin_version);
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
