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

#define NOTE_TEXT "\
  	.pushsection .gnu.build.attributes, \"\", %note\n\
	.balign 4\n\
\n\
	.dc.l 8\n\
	.dc.l 16\n\
	.dc.l 0x100\n\
	.asciz \"GA$3c1\"\n\
	.8byte 0x100  /* note_1_start */\n\
	.8byte 0x102  /* note_1_end */\n\
\n\
	.dc.l 12\n\
	.dc.l 0\n\
	.dc.l 0x100\n\
	.asciz \"GA$clang++\"\n\
\n\
	.popsection"

namespace
{
  /* Version number.  NB: Keep the numeric and string versions in sync
     Also, keep in sync with the major_version and minor_version definitions
     in annocheck/annocheck.c.
     FIXME: This value should be defined in only one place...  */
  static unsigned int   annobin_version = 901;
  static const char *   version_string = "901";
  static bool           be_verbose = false;

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
  
  class AnnobinConsumer : public ASTConsumer
  {
private:
    CompilerInstance& CI;

  public:
    AnnobinConsumer (CompilerInstance & CI) : CI (CI)
    {
    }

    void
    HandleTranslationUnit (ASTContext & Context) override
    {
      CheckOptions (CI);
      auto* TU = Context.getTranslationUnitDecl ();

      StringRef Key = NOTE_TEXT;
      // SG: this is an ultra trick :-)
      // first I'm creating a new FileScopeAsmDecl
      // and then I'm calling the whole **global** ASTconsumer on it
      // this ends up calling all the consumer, including the backend on
      // and so the decl gets added in the right place.
      Decl* NewDecl = FileScopeAsmDecl::Create
	(Context,
	 TU,
	 clang::StringLiteral::Create
	 (Context, NOTE_TEXT, clang::StringLiteral::Ascii,
	  /*Pascal*/ false,
	  Context.getConstantArrayType (Context.CharTy,
					llvm::APInt(32, Key.size() + 1),
					clang::ArrayType::Normal,
					/*IndexTypeQuals*/ 0
					),
	  SourceLocation()),
	 {},
	 {});

      CI.getASTConsumer().HandleTopLevelDecl(DeclGroupRef(NewDecl));
    }

  private:

    void
    CheckOptions (CompilerInstance & CI)
    {
      const CodeGenOptions & CodeOpts = CI.getCodeGenOpts ();

      verbose ("cf-protection: %s", CodeOpts.CFProtectionReturn ? "on" : "off");

      
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

      verbose ("setjmp exceptions: %u", lang_opts.SjLjExceptions);

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
