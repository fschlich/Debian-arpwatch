#!/usr/bin/make -f
# Separate tarball/patch build system by Adam Heath <doogie@debian.org>
# Modified by Ben Collins <bcollins@debian.org>

SHELL		:= /bin/bash -e
SOURCE_DIR	:= build-tree
STAMP_DIR	:= stampdir
PATCH_DIR	:= debian/patches

patched		:= $(STAMP_DIR)/patch
unpacked	:= $(STAMP_DIR)/unpack

ifdef TAR_DIR
  BUILD_TREE	:= $(SOURCE_DIR)/$(TAR_DIR)
else
  BUILD_TREE	:= $(SOURCE_DIR)
endif

dh_mak_deps := $(shell DH_COMPAT=$(DH_COMPAT) perl debian/scripts/dh_split makedeps)
dh_gen_deps := $(shell DH_COMPAT=$(DH_COMPAT) perl debian/scripts/dh_split gendeps)

$(dh_mak_deps): $(dh_gen_deps)
	perl debian/scripts/dh_split

setup: $(dh_mak_deps)
	dh_testdir
	@-up-scripts
	$(MAKE) -f debian/rules $(unpacked) $(patched)

$(patched)/: $(STAMP_DIR)/created $(unpacked)
	test -d $(STAMP_DIR)/patches || mkdir -p $(STAMP_DIR)/patches
	@if [ -d "$(PATCH_DIR)" ]; then \
	  mkdir -p $(STAMP_DIR)/log/patches; \
	  for f in `(cd $(PATCH_DIR); find -type f ! -name 'chk-*') | sort | \
	      sed s,'./',,g`; do \
	    stampfile=$(STAMP_DIR)/patches/$$f; \
	    log=$(STAMP_DIR)/log/patches/$$f; \
	    if [ ! -e $$stampfile ]; then \
	      echo -n "Applying patch $(PATCH_DIR)/$$f ... "; \
	      if $(SHELL) debian/scripts/file2cat $(PATCH_DIR)/$$f | \
		(cd $(BUILD_TREE);patch -p1 --no-backup-if-mismatch) > $$log 2>&1; then \
		echo successful.; \
		touch $$stampfile; \
	      else \
		echo "failed! (check $$log for reason)"; \
		exit 1; \
	      fi; \
	    else \
	      echo Already applied $(PATCH_DIR)/$$f.; \
	    fi; \
	  done; \
	fi
	touch $@

$(unpacked): $(STAMP_DIR)/created
	mkdir -p $(STAMP_DIR)/sources $(SOURCE_DIR) $(STAMP_DIR)/log/sources
	@for f in `find . -type f -maxdepth 1 -name \*.tgz -o -name \*.tar.gz -o \
		-name \*.tar.bz -o -name \*.tar.bz2 | sort | sed s,'./',,g`; do \
	  stampfile=$(STAMP_DIR)/sources/`basename $$f`; \
	  log=$(STAMP_DIR)/log/sources/`basename $$f`; \
	  if [ ! -e $$stampfile ]; then \
	    echo -n "Extracting source $$f ... "; \
	    if $(SHELL) debian/scripts/file2cat $$f | \
		(cd $(SOURCE_DIR); tar xv) > $$log 2>&1; then \
	      echo successful.; \
	      touch $$stampfile; \
	    else \
	      echo failed!; \
	      exit 1; \
	    fi; \
	  else \
	    echo Already unpacked $$f.; \
	  fi; \
	done
	touch $@

make_patch:
	mv $(BUILD_TREE) $(BUILD_TREE).new
	rm -rf $(STAMP_DIR)
	$(MAKE) -f debian/rules $(unpacked) $(patched)
ifndef TAR_DIR
	diff -urN $(BUILD_TREE) $(BUILD_TREE).new > new.diff
else
	(cd $(SOURCE_DIR) && diff -urN $(TAR_DIR) $(TAR_DIR).new || true) > new.diff
endif
	rm -rf $(BUILD_TREE)
	mv $(BUILD_TREE).new $(BUILD_TREE)
	@echo; ls -l new.diff

$(STAMP_DIR)/created:
	test -d $(STAMP_DIR) || mkdir $(STAMP_DIR)
	touch $(STAMP_DIR)/created
