# Kernel Hook Module for Trend Micro ServerProtect for Linux  
# Copyright (C) 2007 Trend Micro Incorporated.                

#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
# 


ifeq "$(KERNEL)" "2.4"
USRINCDIR	= /usr/include

IFLAGS	= -I/usr/src/linux/include -I/usr/include -I../include -I../../common/include

ifeq "$(DIST)" "SuSE"
	CC = gcc -DSuSE
endif

ifeq "$(PLATFORM)" "S390"
        CC += -DS390
endif

ifeq "$(DIST)" "RedHat"
        ifeq "$(PLATFORM)" "NAS"
                CC = gcc -DRedHat -DNAS
        else
	ifeq "$(DISTV)" "RedHat8"
                CC = gcc3 -DRedHat -D$(DISTV)	
	else
	ifeq "$(DISTV)" "RedHat9"
                CC = gcc3 -DRedHat -D$(DISTV)
        else
			ifeq "$(DISTV)" ""
				CC = gcc -DRedHat
			else
				CC = gcc -DRedHat -D$(DISTV)
			endif
	endif
	endif
        endif
endif

ifeq "$(DIST)" "Miracle"
	CC = gcc -DMiracle -D$(DISTV)
endif

ifeq "$(DIST)" "Debian"
	CC = gcc -DDebian
endif

ifeq "$(DIST)" "United"
	CC = gcc -DUnited
endif

ifeq "$(DIST)" "Turbo"
        CC = gcc -DTurbo
endif

ifeq "$(PLATFORM)" "S390"
        AFLAGS	= -D__ASSEMBLY__ -D__KERNEL__
        DEPS	= execve_entry.o modreg.o modops.o hookops.o misc.o knldeps.o
else
        DEPS    = modreg.o modops.o hookops.o misc.o knldeps.o
endif


CFLAGS	= -D__KERNEL__ -DMODULE -O -Wall $(IFLAGS)


VER	= $(shell awk -F\" '/REL/ {print $$2}' $($USRINCDIR)/linux/version.h)

OBJS	= splxmod.o

ifeq "$(PLATFORM)" "S390"
.S.o:
	$(CC) $(AFLAGS) -traditional -c $< -o $*.o
endif

all:	$(OBJS)

splxmod.o: $(DEPS)
	$(LD) -r $^ -o splxmod-$(KERNEL_VERSION).$(ARCH).o

install:        
	install -d /lib/modules/$(VER)/misc
	install -c $(OBJS) /lib/modules/$(VER)/misc

output:
	strip -g $(OBJS)
	install -c $(OBJS) ../../../output

clean:
	rm -f *.o *~ core *.bak *.bz2

else  ## for kernel version 2.6.x

KERNEL_SRC = /usr/src/linux
SUBDIR = $(shell pwd)
DATE = $(shell date +"%F   %T")

all: modules
	@mv splxmod.ko splxmod-$(KERNEL_VERSION).`uname -m`.o

obj-m := splxmod.o
ifeq "$(DIST_ARCH)" "X86_64"
	ifeq "$(KERNEL)" "2.6"
		splxmod-objs := x86_64_execve_entry.o knldeps.o modreg.o modops.o hook_x86_64.o misc.o ia32_execve_entry.o hook_ia32.o hook_lsm.o
	else
		splxmod-objs := knldeps.o modreg.o modops.o hook_x86_64.o misc.o hook_ia32.o hook_lsm.o
	endif
else
splxmod-objs := knldeps.o modreg.o modops.o hookops.o misc.o
endif
ifeq "$(DISTV)" ""
EXTRA_CFLAGS += -I$(MODULE_SRC)/../include -I$(MODULE_SRC)/../../common/include -D$(DIST)
else
EXTRA_CFLAGS += -I$(MODULE_SRC)/../include -I$(MODULE_SRC)/../../common/include -D$(DIST) -D$(DISTV)
endif

modules:
	@if [ -f /etc/asianux-release ] ; then \
        grep "Trinity" /etc/asianux-release > /dev/null 2>&1 ; \
        if [ "$$?" = "0" ] ; then \
            OS="ASIANUX2" ; \
        else \
            grep "Quartet" /etc/asianux-release > /dev/null 2>&1 ; \
            if [ "$$?" = "0" ] ; then \
                OS="ASIANUX3" ; \
            else \
                OS="OTHER"; \
            fi; \
        fi; \
	elif [ -f /etc/redhat-release ] ; then \
	grep "Nahant" /etc/redhat-release > /dev/null 2>&1 ; \
	if [ "$$?" = "0" ] ; then \
	    OS="RHEL4" ; \
	else \
	    grep "Tikanga" /etc/redhat-release > /dev/null 2>&1 ; \
	    if [ "$$?" = "0" ] ; then \
		OS="RHEL5" ; \
	    else \
		grep "CentOS release 4" /etc/redhat-release > /dev/null 2>&1 ; \
		if [ "$$?" = "0" ] ; then \
		   OS="CentOS4"; \
		else \
		   grep "CentOS release 5" /etc/redhat-release > /dev/null 2>&1 ; \
		   if [ "$$?" = "0" ] ; then \
		       OS="CentOS5"; \
		   else \
		       grep "Santiago" /etc/redhat-release > /dev/null 2>&1 ; \
		       if [ "$$?" = "0" ] ; then \
		           OS="RHEL6" ; \
		       else \
		           grep "CentOS Linux release 6" /etc/redhat-release > /dev/null 2>&1 ; \
		           if [ "$$?" = "0" ] ; then \
		               OS="CentOS6"; \
		           else \
			           OS="OTHER"; \
			       fi; \
			   fi; \
		   fi; \
		fi; \
	    fi; \
	fi; \
	elif [ -f /etc/SuSE-release ] ; then \
	grep "11" /etc/SuSE-release > /dev/null 2>&1 ; \
	if [ "$$?" = "0" ] ; then \
		OS="SUSE11" ; \
	else \
		grep "10" /etc/SuSE-release> /dev/null 2>&1 ; \
		if [ "$$?" = "0" ] ; then \
		    OS="SUSE10"; \
		else \
		    OS="OTHER" ; \
		fi; \
	fi; \
	fi; \
	(sed -e "s/@@OS@@/$${OS}/" -e "s/@@DATE@@/$(DATE)/" -e "s/@@ARCH@@/$(DIST_ARCH)/" $(MODULE_SRC)/../include/splxmodinfo.spec > $(MODULE_SRC)/../include/splxmodinfo.h) ; \
	$(MAKE) -C $(KERNEL_SRC) SUBDIRS=$(SUBDIR) modules

.PHONY: clean
clean:
	@rm -rf  .tmp_versions .*.o.d .*.o.cmd .*.cmd *.mod.c *.mod.o $(obj-m) $(splxmod-objs) *.o Module.symvers modules.order

endif
