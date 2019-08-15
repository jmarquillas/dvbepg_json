#!/usr/bin/make -f

#Perhaps you want a line like this instead. I've not used autoconf yet
#CFLAGS=-Wall -O2 -I/usr/src/dvb-kernel/linux/include/
CFLAGS=-Wall -O0 -g

dvb_text := dvb_text.o
dvb_text := dvb_text_iconv.o

dvbepg_json:	dvbepg_json.o crc32.o lookup.o dvb_info_tables.o $(dvb_text) langidents.o
dvbepg_json.o:  dvbepg_json.h si_tables.h
lookup.o:	dvbepg_json.h
dvb_info_tables.o:	dvbepg_json.h
langidents.o:	langidents.c dvbepg_json.h

# langidents.c is generated
empty:=
space:= $(empty) $(empty)
findxslt=$(firstword $(wildcard $(addsuffix /$(1),$(subst :,$(space),$(PATH)))))
XSLTPROC := $(call findxslt,xsltproc)
XALAN := $(call findxslt,xalan)

ifeq ($(shell test -f iso_639.tab ; echo $$?),0)
langidents.c: iso_639.tab iso_639.awk
	awk -f iso_639.awk $< > $@
else ifeq ($(shell test -f iso_639.xml ; echo $$?),0)
langidents.c: iso_639.xml iso_639.xsl
ifneq ($(XSLTPROC),)
	xsltproc iso_639.xsl $< > $@
else ifneq ($(XALAN),)
	xalan -xsl iso_639.xsl -in $< -out $@
else
	$(error Missing XSLT transformer)
endif
else
	$(error Missing iso_639 tables)
endif

tags: $(wildcard *.[ch])
	ctags $^

.PHONY: clean
clean:
	$(RM) *.o dvbepg_json
	$(RM) langidents.c
	$(RM) *~ *.bak *.orig

.PHONY: distclean
distclean: clean
	$(RM) tags

.PHONY: tar
tar: $(PWD)
	tar -c -f ../$(<F).tar.gz -z -h -C .. -v \
		--exclude=*.o --exclude=tags --exclude=.gdbinit \
		--exclude=langidents.c --exclude=dvbepg_json/dvbepg_json \
		--exclude=test --exclude=patches --exclude=.*.swp \
		--exclude=*~ --exclude=*.bak --exclude=*.orig \
		--exclude=.svn \
		$(<F)
