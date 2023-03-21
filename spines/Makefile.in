.PHONY: all clean distclean mrproper veryclean install uninstallall uninstall

SUBDIRS=stdutil libspread-util libspines daemon testprogs controlprogs
INSTALLSUBDIRS=stdutil libspread-util libspines daemon testprogs controlprogs

all: $(SUBDIRS) 
	for dir in $(SUBDIRS); do \
		( $(MAKE) -C $$dir); \
	done

clean:
	for dir in $(SUBDIRS); do \
		( $(MAKE) -C $$dir clean); \
	done

distclean: 
	for dir in $(SUBDIRS); do \
		( $(MAKE) -C $$dir distclean); \
	done
	rm -f config.*
	rm -rf autom4te.cache
	rm -f Makefile Makefile.general

mrproper: distclean

veryclean: distclean
	rm -f configure

install: $(INSTALLSUBDIRS) 
	for dir in $(INSTALLSUBDIRS); do \
		( $(MAKE) -C $$dir install); \
	done

uninstallall:   uninstall
	for dir in $(INSTALLSUBDIRS); do \
		( $(MAKE) -C $$dir uninstallall); \
	done

uninstall: 
	for dir in $(INSTALLSUBDIRS); do \
		( $(MAKE) -C $$dir uninstall); \
	done
