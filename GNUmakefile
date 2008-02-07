have-gnulib-files := $(shell test -f gnulib.mk && test -f maint.mk && echo yes)
ifneq ($(have-gnulib-files),yes)
gnulib.mk:
	ln -s build-aux/GNUmakefile gnulib.mk || cp build-aux/GNUmakefile gnulib.mk
	ln -s build-aux/maint.mk maint.mk || cp build-aux/maint.mk maint.mk
	mv build-aux/config.rpath build-aux/config.rpath-
endif

-include gnulib.mk
