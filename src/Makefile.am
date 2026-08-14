# hydra/src/Makefile.am - Add Nmap integration

# Add Nmap source file
hydra_SOURCES += hydra-nmap.c

# Check for libxml2 (required for Nmap XML parsing)
AM_CPPFLAGS += @XML2_CFLAGS@
hydra_LDADD += @XML2_LIBS@

# Conditional Nmap support
if HAVE_NMAP
    AM_CFLAGS += -DHAVE_NMAP
    hydra_SOURCES += hydra-nmap.c
endif
