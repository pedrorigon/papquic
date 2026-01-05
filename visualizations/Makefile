SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

PY ?= python3

MODE := $(if $(mode),$(mode),all)
VIZ_LANG := $(language)
CSV := $(csv)
ARGS := $(args)

EN_FLAG :=
ifeq ($(VIZ_LANG),english)
EN_FLAG := --english
endif

SCRIPTS := $(notdir $(basename $(wildcard scripts/*.py)))

ifeq ($(strip $(SCRIPTS)),)
ifneq ($(filter run help list,$(MAKECMDGOALS)),)
else
$(error No scripts found in scripts/)
endif
endif

.PHONY: help list run
.SILENT: run list help

help:
	scripts='$(strip $(SCRIPTS))'

	if [ -n "$$scripts" ]; then
		echo "Usage: make + command"
		modes="all"
		for s in $$scripts; do modes="$$modes , $$s"; done
		echo "    • command = { list , help , run }:"
		echo "        - command = { list }: List all available scripts"
		echo "        - command = { help }: Show this help message"
		echo "        - command = { run + [flags | Empty] }: Execute the script(s) with the flags:"
		echo "    • flags : <flag-name>=<value> | Empty"
		echo "        - mode = { $${modes} } | Empty"
		echo "        - language = { english } | Empty"
		echo "        - csv = { path } | Empty"
		echo
	fi
	echo "Available mode(s):"
	if [ -z "$$scripts" ]; then
		echo "    - mode = { None }"
		echo "    👉  No modes available!"
		echo "    👉  Cannot run without available modes!"
	else
		out="all"; sep=" , "
		for s in $$scripts; do out="$$out$$sep$$s"; done
		echo "    - mode = { $$out }"
		echo
		echo "Empty Flag Case:"
		echo "    • Default Flags:"
		echo "        - language = { portuguese }"
		echo "        - csv = { data/<script-data-name>/<data-name>.csv }"
		echo "        - mode = { all }"
		echo
		echo "Flags Constraints:"
		echo "    • Syntax = [ <flag-name> is valid if ( condition ) ]"
		echo "        - csv is valid if ( mode != ( { all } | Empty ) )"
		echo
		echo "All Execution Scenarios:"
		echo "    • Per-mode Execution Scenarios:"
		echo "        - mode = { all } | Empty"
		echo "            make run"
		echo "            make run language=english"
		echo "            make run mode=all"
		echo "            make run mode=all language=english"
		echo
		for s in $$scripts; do
			echo "        - mode = { $$s }"
			echo "            make run mode=$$s"
			echo "            make run mode=$$s language=english"
			echo "            make run mode=$$s csv=path/to.csv"
			echo
		done
	fi

list:
	scripts='$(strip $(SCRIPTS))'
	echo "Available mode(s):"
	if [ -z "$$scripts" ]; then
		echo "    - mode = { None }"
		echo "    👉  No modes available!"
		echo "    👉  Cannot run without available modes!"
	else
		out="all"; sep=" , "
		for s in $$scripts; do out="$$out$$sep$$s"; done
		echo "  mode = { $$out }"
	fi

run:
	mode='$(MODE)'
	csv='$(CSV)'

	if [ -z "$(strip $(SCRIPTS))" ]; then
		echo "Available mode(s):"
		echo "    - mode = { None }"
		echo "    👉  No modes available!"
		echo "    👉  Cannot run without available modes!"
	fi
	
	if [ "$$mode" = "all" ]; then
		if [ -n "$$csv" ]; then
			echo "Error: mode=all does not accept csv=..."
			exit 1
		fi
		for s in $(SCRIPTS); do
			echo ">> Running $$s"
			$(PY) "scripts/$$s.py" $(EN_FLAG) $(ARGS) || exit $$?
		done
	else
		script="scripts/$$mode.py"
		if [ ! -f "$$script" ]; then
			echo "Error: unknown script '$(MODE)'. Available: $(SCRIPTS) or 'all'"
			exit 1
		fi
		if [ -n "$$csv" ]; then
			$(PY) "$$script" "$$csv" $(EN_FLAG) $(ARGS)
		else
			$(PY) "$$script" $(EN_FLAG) $(ARGS)
		fi
	fi
