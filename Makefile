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

# set shell program
override SHELL := $(shell which sh)

# set shell flags
.SHELLFLAGS := -c

# set make flags
override MAKEFLAGS += --warn-undefined-variables --no-builtin-rules

# -- D I R E C T O R I E S ----------------------------------------------------

# source directory
override src_dir := $(CURDIR)/src

# include directory
override inc_dir := $(CURDIR)/inc


# -- T A R G E T S ------------------------------------------------------------

# project name
override project := woody_woodpacker

# main executable
override name := $(project)

# compile command database
override cmddb := compile_commands.json

# -- S O U R C E S ------------------------------------------------------------

# get all source files
override srcs := $(shell find $(src_dir) -type f -name "*.c")

# object files
override objs := $(srcs:%.c=%.o)

# dependency files
override deps := $(objs:%.o=%.d)



# -- C O M P I L E R  S E T T I N G S -----------------------------------------

# compiler
override cc := $(shell which clang)

# compiler standard
override std := -std=gnu99 -m64

# compiler optimization
override opt := -O3

#debug
override dbg := -g -gdwarf-4 -fsanitize=address

def ?= VERBOSE DEBUG

override defines := $(addprefix -D, $(def))

# compiler flags
override cflags := $(std) $(opt) $(dbg) $(defines) -I$(inc_dir) \
					-Wall -Wextra -Werror -Wpedantic \
					-Wno-unused -Wno-unused-variable -Wno-unused-parameter

override ldflags := -lasan

# dependency flags
override depflags = -MT $@ -MMD -MP -MF $*.d






# -- M A I N  T A R G E T S ---------------------------------------------------

all: $(name) $(cmddb)

$(name): $(objs)
	@$(cc) $^ -o $@ $(ldflags)
	echo "  linking -> \033[34m"$@"\033[0m"

-include $(deps)
%.o : %.c Makefile
	@$(cc) $(cflags) $(depflags) -c $< -o $@
	echo "compiling -> \033[33m"$(<F)"\033[0m"

$(cmddb): $(srcs) Makefile
	$(call generate_compile_commands)


clean:
	@rm -rvf $(objs) $(deps) $(cmddb) '.cache'

fclean: clean
	@rm -vf $(name) woody

re: fclean all


# -- P H O N Y  T A R G E T S -------------------------------------------------

.PHONY: all clean fclean re


# -- F U N C T I O N S --------------------------------------------------------

define generate_compile_commands
	@echo '[' > $@
	for file in $(srcs); do
		echo '\t{\n\t\t"directory": "'$(CURDIR)'",' >> $@
		echo '\t\t"file": "'$$file'",' >> $@
		echo '\t\t"output": "'$${file%.c}'.o",' >> $@
		echo '\t\t"arguments": [' >> $@
		echo '\t\t\t"$(cc)",' >> $@
		for flag in $(cflags); do
			echo '\t\t\t"'$$flag'",' >> $@
		done
		echo '\t\t\t"-c",\n\t\t\t"'$$file'",' >> $@
		echo '\t\t\t"-o",\n\t\t\t"'$${file%.c}'.o"\n\t\t]\n\t},' >> $@
	done
	truncate -s -2 $@
	echo '\n]' >> $@
endef
