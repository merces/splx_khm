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

SUBDIRS = bin

RedHat_DIST_PATH = \/etc\/redhat-release
SuSE_DIST_PATH = \/etc\/SuSE-release
Turbo_DIST_PATH = \/etc\/turbolinux-release
Miracle_DIST_PATH = \/etc\/miraclelinux-release \/etc\/redflag-release
Debian_DIST_PATH = \/etc\/debian_version
United_DIST_PATH = \/etc\/UnitedLinux-release
DIST=RedHat

.PHONY: all
all: module

.PHONY: module
module:
	@version=`uname -r`; \
	if [ "`echo $$version | grep debug -`" != "" ] ; then \
		echo -e "Unable to build the KHM on a debug kernel. Please use a non-debug kernel." ; \
		exit 0; \
	fi; \
	arch=`uname -m`; \
	VERSION=`echo $$version |  awk '{split($$0,release,"-");print release[1]}' | awk '{split($$0,release,".");print release[1]"."release[2]"."release[3]}'` ; \
	PL=`echo $$VERSION | awk '{split($$0,release,".");print release[3]}'` ; \
	MV=`echo $$VERSION | awk '{split($$0,release,".");print release[1]}'` ; \
	if [ "`echo $$version | grep xen -`" = "" ] ; then \
		XEN="" ; \
	else \
		XEN="xen." ; \
	fi; \
	if [ "$$arch" = "x86_64" ] ; then \
		echo -e "Kernel VERSION = $$VERSION" ; \
		if [ "$$MV" = "2" ]; then \
			echo "Copy files"; \
			if [ -f bin/kernel/x86_64_execve_entry.$$VERSION.$${XEN}S ] ; then \
			( cp -f bin/kernel/x86_64_execve_entry.$$VERSION.$${XEN}S bin/x86_64_execve_entry.S ) ;  \
			( cp -f bin/kernel/ia32_execve_entry.$$VERSION.S bin/ia32_execve_entry.S ) ;  \
			else \
			echo -e "Unable to locate the required source file. Follow the procedure in the INSTALL file to create the bin/kernel/x86_64_execve_entry.$$VERSION.$${XEN}S and bin/kernel/ia32_execve_entry.$$VERSION.$${XEN}S file." ; \
			exit 1; \
			fi; \
		fi; \
		arch=X86_64 ; \
		if [ "$$PL" -eq "18" ] ; then \
			if [ "$$XEN" = "" ] ; then \
			PHYSBASE=`grep " phys_base" /boot/System.map-$$version | cut -d " " -f 1` ; \
				if [ "$${PHYSBASE}" = "" ] ; then \
					echo "Unable to locate phys_base symbol in System.map. " ; \
					echo "Please check the INSTALL file for troubleshooting."; \
					exit 1; \
				else \
					sed -i -e "s/^#define PHYS_BASE.*\$$/#define PHYS_BASE 0x$${PHYSBASE}/" bin/modreg.c ; \
				fi; \
			fi; \
			CPAA=`grep " change_page_attr_addr" /boot/System.map-$$version | cut -d " " -f 1` ; \
			if [ "$${CPAA}" = "" ] ; then \
				echo "Unable to locate change_page_attr_addr symbol in System.map. " ; \
				echo "Please check the INSTALL file for troubleshooting."; \
				exit 1; \
			else \
				sed -i -e "s/^#define CHANGE_PAGE_ATTR_ADDR.*\$$/#define CHANGE_PAGE_ATTR_ADDR 0x$${CPAA}/" bin/modreg.c ; \
			fi; \
		fi; \
	else \
		arch=I686 ; \
	fi; \
	kernel_source="/lib/modules/$$version/source"; \
	if [ -n "$(ls -A $$kernel_source/include/linux/)" -a -d "$$kernel_source/include/linux/" ] ; then \
		kernel_source="/usr/src/linux-$$version" ; \
	    if [ -n "$(ls -A $$kernel_source/include/linux/)" -a -d "$$kernel_source/include/linux/" ] ; then \
	      kernel_source="/usr/src/linux" ; \
	      if [ -n "$(ls -A $$kernel_source/include/linux/)" -a -d "$$kernel_source/include/linux/" ] ; then \
	        echo -ne "Unable to locate the Linux kernel source. \nPlease put your configured kernel source in /usr/src/linux-$$version \n"; \
			exit 0 ; \
	      fi ; \
	    fi ; \
	fi ;\
	kernel_obj="/lib/modules/$$version/build"; \
	if [ -n "$( ls -A $$kernel_obj/include/linux/)" -a -d "$$kernel_obj/include/linux/" ] ; then \
		kernel_obj="/usr/src/linux-$$version" ; \
			if [ -n "$( ls -A $$kernel_obj/include/linux/)" -a -d "$$kernel_obj/include/linux/" ] ; then \
	      kernel_obj="/usr/src/kernels/$$version" ; \
	      	if [ -n "$( ls -A $$kernel_obj/include/linux/)" -a -d "$$kernel_obj/include/linux/" ] ; then \
						kernel_obj="/usr/src/linux" ; \
							if [ -n "$( ls -A $$kernel_obj/include/linux/)" -a -d "$$kernel_obj/include/linux/" ] ; then \
		          echo -ne "Unable to locate the Linux kernel object files or kernel source is not \nconfigured. \nPlease put your configured kernel source in /usr/src/linux-$$version \n"; \
				exit 0 ; \
				  fi; \
	      fi ; \
	    fi ; \
	fi ;\
	target=`echo $@`; \
	list='$(SUBDIRS)'; \
	if [ $$MV = "2" ]; then \
		for subdir in $$list; do \
			echo "Making $$target in $$subdir"; \
			(cd $$subdir && $(MAKE) PL=$$PL KERNEL=2.6 MODULE_SRC=$(shell pwd)/bin KERNEL_VERSION=$$version DIST_ARCH=$$arch DIST=$(DIST) KERNEL_SRC=$$kernel_obj) ; \
		done; \
	else \
		for subdir in $$list; do \
			echo "Making $$target in $$subdir"; \
			(cd $$subdir && $(MAKE) PL=$$PL KERNEL=3 MODULE_SRC=$(shell pwd)/bin KERNEL_VERSION=$$version DIST_ARCH=$$arch DIST=$(DIST) KERNEL_SRC=$$kernel_obj) ; \
		done; \
	fi; \

.PHONY: clean
clean:
	@target=`echo $@`; \
	list='$(SUBDIRS)'; for subdir in $$list; do \
		echo "Making $$target in $$subdir"; \
		(cd $$subdir && $(MAKE) $$target) ; \
	done; \

.PHONY: test
test:
	@./test.sh ;  \
	if [ $$? = "0" ] ; then \
		echo "" ; \
	else \
	echo "\033[31;1mTest unsuccessful.\033[0m" ; \
	fi;

.PHONY: install
install:
	@version=`uname -r`; arch=`uname -m`; \
	if [ -f bin/splxmod-$$version.$$arch.o ] ; then \
		echo -n "Copying bin/splxmod-$$version.$$arch.o ... " ; \
		if [ -f /opt/TrendMicro/SProtectLinux/SPLX.module/splxmod-$$version.$$arch.o ] ; then \
			mv -f /opt/TrendMicro/SProtectLinux/SPLX.module/splxmod-$$version.$$arch.o /opt/TrendMicro/SProtectLinux/SPLX.module/splxmod-$$version.$$arch.o.bak ; \
		fi ; \
		cp -rf bin/splxmod-$$version.$$arch.o /opt/TrendMicro/SProtectLinux/SPLX.module ; \
		echo "OK" ; \
	else \
		echo "Unable to locate KHM. Please build the KHM before installing it." ; \
	fi;
