have-gnulib-files := $(shell test -f gnulib.mk && test -f maint.mk && echo yes)
ifneq ($(have-gnulib-files),yes)
gnulib.mk:
	ln -s build-aux/GNUmakefile gnulib.mk || cp build-aux/GNUmakefile gnulib.mk
	ln -s build-aux/maint.mk maint.mk || cp build-aux/maint.mk maint.mk
endif

-include gnulib.mk
