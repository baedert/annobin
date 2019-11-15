/* annobin - a clang plugin for annotating the output binary file.
   Copyright (c) 2019 Red Hat.
   Created by Nick Clifton.

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
#include "clang/Sema/Sema.h"
#include "llvm/Support/raw_ostream.h"
using namespace clang;

namespace
{
  /* Version number.  NB: Keep the numeric and string versions in sync
     Also, keep in sync with the major_version and minor_version definitions
     in annocheck/annocheck.c.
     FIXME: This value should be defined in only one place...  */
  static unsigned int   annobin_version = 901;
  static const char *   version_string = "901";

  static bool be_verbose = false;

  static void
  ainfo (const char * format, va_list args)
  {
    fflush (stdout);

    fprintf (stderr, "Annobin plugin for clang: ");

    vfprintf (stderr, format, args);

    putc ('\n', stderr);
  }
  
  static void
  inform (const char * format, ...)
  {
    va_list args;

    va_start (args, format);
    ainfo (format, args);
    va_end (args);
  }

  // FIXME: Find a C++ way of encoding this function.
  static void
  verbose (const char * format, ...)
  {
    if (! be_verbose)
      return;

    va_list args;

    va_start (args, format);
    ainfo (format, args);
    va_end (args);
  }

  class AnnobinConsumer : public ASTConsumer
  {
    CompilerInstance& Instance;

  public:
    AnnobinConsumer (CompilerInstance& Instance) : Instance (Instance)
    {
    }

    bool
    HandleTopLevelDecl (DeclGroupRef DGR) override
    {
      return true;
    }

    void
    HandleTranslationUnit (ASTContext& Context) override
    {
      CheckOptions (Instance);
    }

  private:
    void
    CheckOptions (CompilerInstance& CI)
    {
      const CodeGenOptions& CodeOpts = CI.getCodeGenOpts ();

      verbose ("cf-protection: %s", CodeOpts.CFProtectionReturn ? "on" : "off");

      
      const LangOptions& lang_opts = CI.getLangOpts ();
      if (lang_opts.ModuleFeatures.empty ())
	{
	  verbose ("No language module features");
	}
      else
	{
	  for (StringRef Feature : lang_opts.ModuleFeatures)
	    verbose ("Language module features: %s",  Feature.str().c_str());
	}

      verbose ("setjmp exceptions: %s", lang_opts.SjLjExceptions);

      const PreprocessorOptions &pre_opts = CI.getPreprocessorOpts ();
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

      const TargetOptions &targ_opts = CI.getTargetOpts ();
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

  class AnnobinDummyConsumer : public ASTConsumer
  {
    CompilerInstance& Instance;

  public:
    AnnobinDummyConsumer (CompilerInstance& Instance) : Instance (Instance)
    {}

    bool
    HandleTopLevelDecl (DeclGroupRef DGR) override
    {
      return true;
    }

    void
    HandleTranslationUnit (ASTContext& Context) override
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
	return llvm::make_unique<AnnobinConsumer>(CI);
      else
	return llvm::make_unique<AnnobinDummyConsumer>(CI);
    }

    // Automatically run the plugin
    PluginASTAction::ActionType 
    getActionType (void) override
    {
      return AddAfterMainAction;
    }

    // We do not want the plugin to stop the compilation of the binary.
    bool
    usesPreprocessorOnly (void) const override
    {
      return false;
    }

    // Handle any options passed to the plugin.
    bool
    ParseArgs (const CompilerInstance& CI, const std::vector<std::string>& args) override
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
