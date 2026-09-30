# Lupaxa makefile-skills project wrapper
# Copy this file to your project root as Makefile.
#
# Library development (this repo): set MAKEFILES_MODE=library and
# MAKEFILES_DIR=. before including, or use the root Makefile.
#
# Consumer knobs live in makefiles.config (created by make init).
# Precedence: CLI / environment > makefiles.config > defaults below.

MAKEFILES_DIR    ?= .makefiles
MAKEFILES_CONFIG ?= makefiles.config

# Resolve loader: installed clone, else same-repo library checkout.
MF_CONFIG_LOADER := $(firstword \
  $(wildcard $(MAKEFILES_DIR)/skills/load-makefiles-config) \
  $(wildcard skills/load-makefiles-config))

# Staging file for parsed assignments (always outside the sparse clone).
_MF_CFG_MK := /tmp/mf-cfg-$(shell printf '%s' '$(CURDIR)' | cksum | awk '{print $$1}').mk

# SYNC WITH skills/load-makefiles-config — key map and errors must match.
# No single quotes: this body is wrapped in bash -c '…'.
define mf_config_fallback_sh
cfg="$$1"; [ -f "$$cfg" ] || exit 0; lineno=0; while IFS= read -r line || [ -n "$$line" ]; do lineno=$$((lineno+1)); line="$${line%%\#*}"; line=$$(printf %s "$$line" | sed -e "s/^[[:space:]]*//" -e "s/[[:space:]]*$$//"); [ -z "$$line" ] && continue; case "$$line" in *=*) ;; *) echo "ERROR: $$cfg:$$lineno: expected key = value (got: $$line)" >&2; exit 2;; esac; key="$${line%%=*}"; val="$${line#*=}"; key=$$(printf %s "$$key" | sed -e "s/[[:space:]]*$$//"); val=$$(printf %s "$$val" | sed -e "s/^[[:space:]]*//" -e "s/[[:space:]]*$$//"); case "$$key" in skills) mv=SKILLS;; ref) mv=MAKEFILES_REF;; transport) mv=MAKEFILES_TRANSPORT;; repo_ssh) mv=MAKEFILES_REPO_SSH;; repo_http) mv=MAKEFILES_REPO_HTTP;; custom_dir) mv=MAKEFILES_CUSTOM_DIR;; update_wrapper) mv=MAKEFILES_UPDATE_WRAPPER;; *) echo "ERROR: $$cfg:$$lineno: unknown key $$key" >&2; exit 2;; esac; printf "%s ?= %s\n" "$$mv" "$$val"; done < "$$cfg"
endef

# Load config before defaults so ?= from loader + later defaults give CLI/env > config > defaults.
ifneq ($(MF_CONFIG_LOADER),)
_MF_CFG_RC := $(shell "$(MF_CONFIG_LOADER)" "$(MAKEFILES_CONFIG)" >"$(_MF_CFG_MK)" 2>"$(_MF_CFG_MK).err"; echo $$?)
else ifneq ($(wildcard $(MAKEFILES_CONFIG)),)
_MF_CFG_RC := $(shell bash -c '$(mf_config_fallback_sh)' bash "$(MAKEFILES_CONFIG)" >"$(_MF_CFG_MK)" 2>"$(_MF_CFG_MK).err"; echo $$?)
else
_MF_CFG_RC :=
endif

ifneq ($(_MF_CFG_RC),)
ifeq ($(_MF_CFG_RC),0)
-include $(_MF_CFG_MK)
else
$(error Failed to load $(MAKEFILES_CONFIG). $(shell cat "$(_MF_CFG_MK).err" 2>/dev/null | tr '\n' ' '))
endif
endif

SKILLS         ?=
MAKEFILES_REF  ?= head
MAKEFILES_MODE ?= consumer

MAKEFILES_CUSTOM_DIR ?= .makefiles-custom
MAKEFILES_UPDATE_WRAPPER ?= yes

# Transport: ssh | https | http
MAKEFILES_TRANSPORT ?= https
MAKEFILES_REPO_SSH  ?= git@github.com:lupaxa-developers-toolbox/makefile-skills.git
MAKEFILES_REPO_HTTP ?= https://github.com/lupaxa-developers-toolbox/makefile-skills.git

ifeq ($(MAKEFILES_TRANSPORT),ssh)
MAKEFILES_REPO ?= $(MAKEFILES_REPO_SSH)
else ifneq ($(filter $(MAKEFILES_TRANSPORT),https http),)
MAKEFILES_REPO ?= $(MAKEFILES_REPO_HTTP)
else
$(error MAKEFILES_TRANSPORT must be ssh, https, or http (got '$(MAKEFILES_TRANSPORT)'))
endif

.DEFAULT_GOAL := help

.PHONY: init install update help doctor version bump-patch bump-patch-dev bump-minor-dev bump-major-dev bump-patch-rc bump-minor-rc bump-major-rc bump-dev bump-minor bump-major bump-rc release bump-final draft-tag show-version-flow status completion completion-path print-targets _makefiles-checkout

# Quiet lifecycle status (cyan when colour enabled).
define mf_lifecycle_msg
mf_lifecycle_say() { \
	_msg="$$1"; \
	if [ -n "$${NO_COLOR:-}" ]; then \
		printf '%s\n' "$$_msg"; \
	else \
		case "$${FORCE_COLOR:-}" in \
			""|0|[Ff][Aa][Ll][Ss][Ee]|[Nn][Oo]) \
				if [ -t 1 ]; then _c=1; else _c=0; fi ;; \
			*) _c=1 ;; \
		esac; \
		if [ "$$_c" -eq 1 ]; then \
			printf '\033[96m%s\033[0m\n' "$$_msg"; \
		else \
			printf '%s\n' "$$_msg"; \
		fi; \
	fi; \
}; \
mf_git_quiet() { \
	_mf_err="$$(mktemp)"; \
	"$$@" >"$$_mf_err" 2>&1; \
	_mf_rc=$$?; \
	if [ "$$_mf_rc" -eq 0 ]; then \
		rm -f "$$_mf_err"; \
		return 0; \
	fi; \
	cat "$$_mf_err" >&2; \
	rm -f "$$_mf_err"; \
	return "$$_mf_rc"; \
};
endef

# -----------------------------------------------------------------------------
# Lifecycle
# -----------------------------------------------------------------------------

ifeq ($(MAKEFILES_MODE),library)

init install:
	@echo "This repository hosts the skills library under skills/."
	@echo "No clone is required. Consumers should copy templates/Makefile."

update:
	@echo "Library mode: update skills with git in this repository (not make update)."

else

init install:
	@set -e; \
	$(mf_lifecycle_msg) \
	if [ -e "$(MAKEFILES_DIR)" ]; then \
		echo "ERROR: $(MAKEFILES_DIR) already exists. Use 'make update' or remove it first." >&2; \
		exit 2; \
	fi; \
	mf_lifecycle_say "==> Cloning skills from $(MAKEFILES_REPO) into $(MAKEFILES_DIR)"; \
	if ! mf_git_quiet git clone -q --filter=blob:none --no-checkout "$(MAKEFILES_REPO)" "$(MAKEFILES_DIR)" \
		|| ! $(MAKE) --no-print-directory _makefiles-checkout; then \
		echo "==> Removing incomplete $(MAKEFILES_DIR) so 'make init' can be retried" >&2; \
		rm -rf "$(MAKEFILES_DIR)"; \
		exit 2; \
	fi

update:
	@set -e; \
	$(mf_lifecycle_msg) \
	if [ ! -d "$(MAKEFILES_DIR)/.git" ]; then \
		echo "ERROR: $(MAKEFILES_DIR) is not a git clone. Run: make init" >&2; \
		exit 2; \
	fi; \
	mf_lifecycle_say "==> Updating makefile skills in $(MAKEFILES_DIR) (ref=$(MAKEFILES_REF))"; \
	mf_git_quiet git -C "$(MAKEFILES_DIR)" fetch -q --tags origin; \
	mf_git_quiet git -C "$(MAKEFILES_DIR)" fetch -q origin; \
	$(MAKE) --no-print-directory _makefiles-checkout; \
	_mf_uw="$(MAKEFILES_UPDATE_WRAPPER)"; \
	case "$${_mf_uw}" in \
		""|yes|YES|true|TRUE|1) _mf_do_wrap=1 ;; \
		no|NO|false|FALSE|0) _mf_do_wrap=0 ;; \
		*) echo "ERROR: update_wrapper must be yes/no (got '$$_mf_uw')" >&2; exit 2 ;; \
	esac; \
	if [ "$$_mf_do_wrap" -eq 1 ]; then \
		mf_lifecycle_say "==> Refreshing Makefile from $(MAKEFILES_DIR)/templates/Makefile"; \
		cp "$(MAKEFILES_DIR)/templates/Makefile" Makefile; \
	fi

.PHONY: _makefiles-checkout
_makefiles-checkout:
	@set -e; \
	$(mf_lifecycle_msg) \
	mf_git_quiet git -C "$(MAKEFILES_DIR)" sparse-checkout init --no-cone; \
	mf_git_quiet git -C "$(MAKEFILES_DIR)" sparse-checkout set --no-cone \
		'/skills/**' '/templates/Makefile' '/templates/makefiles.config'; \
	if [ "$(MAKEFILES_REF)" = "head" ]; then \
		mf_git_quiet git -C "$(MAKEFILES_DIR)" checkout -q -B master origin/master; \
	else \
		mf_git_quiet git -C "$(MAKEFILES_DIR)" checkout -q -f "$(MAKEFILES_REF)"; \
	fi; \
	mf_git_quiet git -C "$(MAKEFILES_DIR)" sparse-checkout reapply; \
	if [ ! -f "$(MAKEFILES_DIR)/skills/versioning.mk" ]; then \
		short_sha="$$(git -C "$(MAKEFILES_DIR)" rev-parse --short HEAD 2>/dev/null || echo unknown)"; \
		echo "ERROR: $(MAKEFILES_DIR)/skills/versioning.mk not found after checking out MAKEFILES_REF=$(MAKEFILES_REF) (commit $$short_sha)." >&2; \
		echo "This ref does not look like a valid makefile-skills checkout." >&2; \
		exit 2; \
	fi; \
	extra="$$(find "$(MAKEFILES_DIR)" -mindepth 1 -maxdepth 1 ! -name .git ! -name skills ! -name templates -print)"; \
	if [ -n "$$extra" ]; then \
		echo "ERROR: sparse checkout leaked non-skills paths into $(MAKEFILES_DIR):" >&2; \
		printf '%s\n' "$$extra" >&2; \
		echo "Expected only skills/ and templates/. Check git sparse-checkout support and retry." >&2; \
		exit 2; \
	fi; \
	if [ ! -f "$(MAKEFILES_CONFIG)" ]; then \
		mf_lifecycle_say "==> Creating $(MAKEFILES_CONFIG) from template"; \
		cp "$(MAKEFILES_DIR)/templates/makefiles.config" "$(MAKEFILES_CONFIG)"; \
	fi; \
	mf_lifecycle_say "==> makefile skills at $$(git -C "$(MAKEFILES_DIR)" rev-parse --short HEAD) ($(MAKEFILES_REF)) [skills/ + templates/]"

endif

# -----------------------------------------------------------------------------
# Help / missing-skills guards
# -----------------------------------------------------------------------------

help:
	$(call mf_help_header,$(or $(PROJECT_NAME),$(notdir $(CURDIR))) Makefile)
	@echo
	$(call mf_help_header,Lifecycle:)
ifeq ($(MAKEFILES_MODE),library)
	$(call mf_help_line,init / install,(library mode — skills/ is this repository))
	$(call mf_help_line,update,(library mode — use git in this repository))
else
	$(call mf_help_line,init / install,Clone skills/ + templates/ into $(MAKEFILES_DIR) (sparse))
	$(call mf_help_line,update,Refresh skills to MAKEFILES_REF ($(MAKEFILES_REF));)
	$(call mf_help_cont,also refreshes ./Makefile unless update_wrapper=no)
	$(call mf_help_line,config,$(MAKEFILES_CONFIG) (init creates; update never overwrites))
endif
	$(call mf_help_line,completion,Print bash completion script)
	$(call mf_help_line,transport,$(MAKEFILES_TRANSPORT) -> $(MAKEFILES_REPO))
	@echo
	@if [ ! -f "$(MAKEFILES_DIR)/skills/versioning.mk" ]; then \
		$(mf_color_prelude) \
		mf_color_init; \
		mf_title "Status:"; \
		printf '  %s%-*s%s %s\n' "$$MF_GREEN" $(MF_HELP_CMD_WIDTH) "status" "$$MF_RESET" "Show project, version, Git, and enabled-skill status"; \
		printf '  %s%-*s%s %s\n' "$$MF_GREEN" $(MF_HELP_CMD_WIDTH) "doctor" "$$MF_RESET" "Run all doctors (lifecycle + versioning + enabled skills)"; \
		echo; \
		echo "Skills not installed. Run: make init"; \
		echo; \
	else \
		$(MAKE) --no-print-directory help-versioning; \
		for s in $(SKILLS); do \
			$(MAKE) --no-print-directory help-$$s; \
		done; \
	fi

# doctor / status come from skills/versioning.mk once installed.
ifeq ($(wildcard $(MAKEFILES_DIR)/skills/versioning.mk),)
doctor version bump-patch bump-minor bump-major bump-dev bump-patch-dev bump-minor-dev bump-major-dev bump-rc bump-patch-rc bump-minor-rc bump-major-rc release bump-final draft-tag show-version-flow status:
	@echo "ERROR: makefile skills not installed. Run: make init" >&2
	@exit 2
endif

# Bash completion for make targets (including skill includes).
# Usage: eval "$(make -s completion)"   or   source "$(make -s completion-path)"
completion:
	@completion_file="$(MAKEFILES_DIR)/skills/completion/bash"; \
	if [ ! -f "$$completion_file" ]; then \
		echo "ERROR: completion script not found: $$completion_file" >&2; \
		echo "Run: make init (or use library mode with skills/ present)" >&2; \
		exit 2; \
	fi; \
	cat "$$completion_file"

completion-path:
	@completion_file="$(MAKEFILES_DIR)/skills/completion/bash"; \
	if [ ! -f "$$completion_file" ]; then \
		echo "ERROR: completion script not found: $$completion_file" >&2; \
		exit 2; \
	fi; \
	printf '%s\n' "$$completion_file"

# Targets for shell completion (excludes private _* helpers).
print-targets:
	@$(MAKE) -pRrq : 2>/dev/null | awk -F: '/^[a-zA-Z0-9][^\#\/\t=]*:([^=]|$$)/ { \
		split($$1, names, / /); \
		for (i in names) { \
			n = names[i]; \
			if (n ~ /^[a-zA-Z0-9]/ && n !~ /^_/ && n != "Makefile" && n !~ /\//) print n; \
		} \
	}' | sort -u

# -----------------------------------------------------------------------------
# Skills includes
# -----------------------------------------------------------------------------

-include $(MAKEFILES_DIR)/skills/versioning.mk
$(foreach s,$(SKILLS),$(eval -include $(MAKEFILES_DIR)/skills/$(s).mk))
-include $(MAKEFILES_CUSTOM_DIR)/*.mk

# Plain-text stubs so `make help` works before skills are installed (no versioning.mk yet).
ifeq ($(origin mf_color_prelude),undefined)
define mf_color_prelude
mf_color_init() { \
	if [ -n "$${NO_COLOR:-}" ]; then \
		MF_C=0; \
	else \
		case "$${FORCE_COLOR:-}" in \
			""|0|[Ff][Aa][Ll][Ss][Ee]|[Nn][Oo]) \
				if [ -t 1 ]; then MF_C=1; else MF_C=0; fi ;; \
			*) MF_C=1 ;; \
		esac; \
	fi; \
	if [ "$$MF_C" -eq 1 ]; then \
		MF_GREEN=$$(printf '\033[32m'); \
		MF_CYAN=$$(printf '\033[96m'); \
		MF_RESET=$$(printf '\033[0m'); \
	else \
		MF_GREEN=; MF_CYAN=; MF_RESET=; \
	fi; \
}; \
mf_title() { printf '%s%s%s\n' "$$MF_CYAN" "$$1" "$$MF_RESET"; };
endef
define mf_help_header
@$(mf_color_prelude) \
mf_color_init; \
mf_title "$(1)"
endef
MF_HELP_CMD_WIDTH ?= 22
define mf_help_line
@$(mf_color_prelude) \
mf_color_init; \
printf '  %s%-*s%s %s\n' "$$MF_GREEN" $(MF_HELP_CMD_WIDTH) "$(1)" "$$MF_RESET" "$(2)"
endef
define mf_help_cont
@printf '  %-*s %s\n' $(MF_HELP_CMD_WIDTH) "" "$(1)"
endef
endif
# CI-friendly aliases (reusable-python-makefile-ci expects these names)
# -----------------------------------------------------------------------------
# .makefiles/ is gitignored, so CI (and fresh clones) must init before the
# python-* targets from makefile-skills exist. Each alias re-invokes $(MAKE)
# so includes are re-read after init.

.PHONY: ensure-skills install-dev install-test lint check format test

ensure-skills:
	@if [ ! -f "$(MAKEFILES_DIR)/skills/versioning.mk" ]; then \
		if [ -e "$(MAKEFILES_DIR)" ]; then \
			echo "==> Removing incomplete $(MAKEFILES_DIR) before init" >&2; \
			rm -rf "$(MAKEFILES_DIR)"; \
		fi; \
		$(MAKE) --no-print-directory init; \
	fi

install-dev: ensure-skills
	@$(MAKE) --no-print-directory python-install-dev

install-test: ensure-skills
	@$(MAKE) --no-print-directory python-install-test

lint: ensure-skills
	@$(MAKE) --no-print-directory python-lint

check: ensure-skills
	@$(MAKE) --no-print-directory python-check

format: ensure-skills
	@$(MAKE) --no-print-directory python-format

test: ensure-skills
	@$(MAKE) --no-print-directory python-test
