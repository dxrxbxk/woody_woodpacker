# -- M A K E F I L E -----------------------------------------------------------

###############################################################################
#        ▁▁▁▁▁▁▁▁  ▁▁▁▁▁▁▁▁  ▁▁▁▁ ▁▁▁  ▁▁▁▁▁▁▁▁                               #
#       ╱        ╲╱        ╲╱    ╱   ╲╱        ╲    language: makefile        #
#      ╱         ╱         ╱         ╱         ╱    author:   @tutur          #
#     ╱         ╱         ╱        ▁╱       ▁▁╱     created: 2020-05-01       #
#     ╲▁▁╱▁▁╱▁▁╱╲▁▁▁╱▁▁▁▁╱╲▁▁▁▁╱▁▁▁╱╲▁▁▁▁▁▁▁▁╱      updated: 2020-05-01       #
#                                                                             #
###############################################################################

# -- S E T T I N G S ----------------------------------------------------------

# set default target
.DEFAULT_GOAL := all

# use one shell for all commands
.ONESHELL:

# delete intermediate files on error
#.DELETE_ON_ERROR:

# silent mode
#.SILENT:

# set shell program
override SHELL := $(shell which zsh)

# set shell flags
.SHELLFLAGS := -d -f -c -e -o pipefail -u

# set make flags
override MAKEFLAGS += --warn-undefined-variables --no-builtin-rules

# -- O P E R A T I N G  S Y S T E M -------------------------------------------

override THREAD    := $(shell nproc)




# -- D I R E C T O R I E S ----------------------------------------------------

# source directory
override SRCDIR := src

# include directory
override INCDIR := inc

# build directory
override BLDDIR := build

# object directory
override OBJDIR := $(BLDDIR)/object

# dependency directory
override DEPDIR := $(BLDDIR)/dependency

# json directory
override JSNDIR := $(BLDDIR)/json

# current directory
override ROOT := $(shell pwd)



# -- T A R G E T S ------------------------------------------------------------

# project name
override PROJECT := woody_woodpacker

# main executable
override NAME := $(PROJECT)

# hook script
override HOOK := $(ROOT)/.git/hooks/pre-commit

# compile command database
override CMDDB := compile_commands.json

# -- S O U R C E S ------------------------------------------------------------

# get all source files
override SRC := $(shell find $(SRCDIR) -type f -name "*.c")

# get all header files
override HDR := $(shell find $(INCDIR) -type f -name "*.h")

# get all header directories
override HDRDIR := $(sort $(dir $(HDR)))

# pattern substitution for object files
override OBJ := $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o,    $(SRC))

# pattern substitution for dependency files
override DEP := $(patsubst $(OBJDIR)/%.o,   $(DEPDIR)/%.d,    $(OBJ))

override JSN := $(patsubst $(SRCDIR)/%.c,   $(JSNDIR)/%.json, $(SRC))


override HIR := $(sort $(dir $(SRC)))
override OBJHIR := $(HIR:$(SRCDIR)/%=$(OBJDIR)/%)
override DEPHIR := $(HIR:$(SRCDIR)/%=$(DEPDIR)/%)
override JSNHIR := $(HIR:$(SRCDIR)/%=$(JSNDIR)/%)



# -- C O M P I L E R  S E T T I N G S -----------------------------------------

# make directory if not exists
override MKDIR := mkdir -pv

# remove recursively force
override RM := rm -rfv

# leaks detection program
override VALGRIND := $(shell which valgrind)

# valgrind flags
override VFLAGS := valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --track-fds=yes

# compiler
override CXX := $(shell which clang)

# compiler standard
override STD := -std=c89 -m64

# compiler optimization
override OPT := -O3
#--g3 -gdwarf-4

# compiler flags
override CXXFLAGS := -Wall -Wextra -Werror -Wpedantic -Wno-unused -Wno-unused-variable -Wno-unused-parameter

# dependency flags
override DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.d

# compile command flag
override CMPFLAG = -MJ $(JSNDIR)/$*.json

# all include subdirs with -I prefix
override INCLUDES := $(addprefix -I, $(HDRDIR))

DEF ?=

override DEFINES := $(addprefix -D, $(DEF))

override LIBS := -lc


# -- P H O N Y  T A R G E T S -------------------------------------------------

.PHONY: all clean fclean re obj logger leaks


# -- M A I N  T A R G E T S ---------------------------------------------------

all: obj $(NAME) $(CMDDB)


# -- E X E C U T A B L E  T A R G E T -------------------------------------------

$(NAME): $(OBJ)
	@echo "  linking -> \x1b[34m"$@"\x1b[0m"
	@$(CXX) $(LIBS) $^ -o $@;


# -- C O M P I L A T I O N ------------------------------------------------------

# self call with threads
obj:
	@$(MAKE) --silent -j$(THREAD) $(OBJ)

-include $(DEP)

$(OBJDIR)/%.o : $(SRCDIR)/%.c Makefile | $(OBJHIR) $(DEPHIR) $(JSNHIR)
	@echo "compiling -> \x1b[33m"$(<F)"\x1b[0m"
	@$(CXX) $(STD) $(OPT) $(CXXFLAGS) $(DEFINES) $(CMPFLAG) $(DEPFLAGS) $(INCLUDES) -c $< -o $@

$(CMDDB) : $(JSN)
	@echo "[\n"$$(cat $(JSN) | sed '$$s/,\s*$$//')"\n]" | jq > $@


# -- D I R E C T O R I E S  C R E A T I O N -------------------------------------

$(OBJHIR) $(DEPHIR) $(JSNHIR):
	@$(MKDIR) $@

# -- C L E A N I N G ------------------------------------------------------------

clean:
	@$(RM) $(BLDDIR) $(CMDDB)


fclean: clean
	@$(RM) $(NAME)


# -- R E C O M P I L E --------------------------------------------------------

re: fclean all


leaks: all
	$(VALGRIND) $(VFLAGS) ./$(NAME) 8080 pass

logger:
	@echo "     mode -> \x1b[36m"IRC_LOGGER"\x1b[0m"
	@$(MAKE) --silent re DEF=IRC_LOGGER

$(HOOK):
	ln -s $(ROOT)/config/pre-commit $@
