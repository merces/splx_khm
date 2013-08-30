#! /bin/bash

#
# Kernel Hook Module for Trend Micro ServerProtect for Linux
# Copyright (C) 2007 Trend Micro Incroporated.
#
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
#

# Test will only do on suitable platform
VERSION=`uname -r 2> /dev/null`
if [ "${VERSION}" = "" ] ; then
	VERSION=`cat /proc/sys/kernel/osrelease 2> /dev/null`
	if [ "${VERSION}" = "" ] ; then
		echo "Unable to determine the running kernel version."
		exit 1
	fi;
fi;

ARCH=`uname -m 2> /dev/null`
if [ "${ARCH}" = "" ] ; then
	echo "Unable to determine the running kernel architecture."
	exit 1
fi;

# add by errik to check the release type
if [ -f /etc/redhat-release ]; then
    DIST=RedHat
elif [ -f /etc/asianux-release ]; then
    DIST=RedHat
elif [ -f /etc/SuSE-release ]; then
    DIST=SuSE
elif [ -f /etc/debian_version ]; then
    DIST=Debian
else
    echo "This package only supports RedHat, SuSE, Asianux and Debian\n"
    exit 1
fi
# add end

FAIL_FLAG=0

# Prompt
echo "Test Program for Kernel Hook Module"
echo "======================="
echo "Kernel Version: ${VERSION}"
echo "Architecture:   ${ARCH}"
echo "KHM file:       splxmod-${VERSION}.${ARCH}.o"
echo

# Test for root
echo -n "Obtaining current user ID... ";
USERID=`id -u`
echo ${USERID}
if [ ${USERID} -ne 0 ] ; then
	echo "You must be logged in as root to perform this test." 
	exit 1
fi;

# Display warning message
echo
echo "!! Warning !!"
echo "You are about to start testing the Kernel Hook Module (KHM)."
echo "This test program will insert the KHM file (shown above) into the Linux kernel."
echo "This operation may cause your system to stop responding (hang) or kenrnel panic."
echo 
while [ "$agreed" = "" ] ; do
	echo -n "Do you want to continue? (yes or no) "
	read reply leftover
	case $reply in
		n* | N*)
			echo "KHM test aborted."
			exit 1
			;;
		y* | Y*)
			agreed=1
			;;
	esac
done	
echo
	
# Find module file
echo -n "Finding module file... ";
if [ -f bin/splxmod-${VERSION}.${ARCH}.o ] ; then 
	echo "found"
else 
	echo "not found"
	echo "Unable to locate the KHM file: bin/splxmod-${VERSION}.${ARCH}.o"
	exit 1
fi; 

# Try to do insmod
echo -n "Finding System.map file... "
if [ -a /boot/System.map-${VERSION} ]; then
	echo "found"
	echo -n "Obtaining sys_call_table address... "
	SCT_ADDR=`grep " sys_call_table" /boot/System.map-${VERSION} \
        | cut -d " " -f 1`
	if [ "${SCT_ADDR}" = "" ]; then
		echo "not found"
		echo "Unable to locate sys_call_table symbol in System.map."
		exit 1
	else
		echo ${SCT_ADDR}
	fi
	echo -n "Obtaining do_execve address... "
	EXEC_ADDR=`grep " do_execve$" /boot/System.map-${VERSION} \
        | cut -d " " -f 1`
	if [ "${EXEC_ADDR}" = "" ]; then
		echo "not found"
		echo "Unable to locate do_execve symbol in System.map."
		exit 1
	else
		echo ${EXEC_ADDR}
	fi

	if [ "${ARCH}" = "x86_64" ] ; then
		echo -n "Obtaining int_ret_from_sys_call address... "
		RET_ADDR=`grep " int_ret_from_sys_call" /boot/System.map-${VERSION} \
        | cut -d " " -f 1`
		if [ "${RET_ADDR}" = "" ]; then
			echo "not found"
			echo "Unable to obtain int_ret_from_sys_call symbol in System.map."
			exit 1
		else
			echo ${RET_ADDR}
		fi;
                echo -n "Obtaining ia32_sys_call_table address... "
                IA32_SCT_ADDR=`grep " ia32_sys_call_table" /boot/System.map-${VERSION} \
        | cut -d " " -f 1`
                if [ "${IA32_SCT_ADDR}" = "IA32_SCT_ADDR" ]; then
                        echo "not found"
                        echo "Unable to obtain ia32_sys_call_table symbol in System.map."
                        exit 1
                else
                        echo ${IA32_SCT_ADDR}
                fi;
                echo -n "Obtaining compat_do_execve address... "
                IA32_EXEC_ADDR=`grep " compat_do_execve" /boot/System.map-${VERSION} \
        | cut -d " " -f 1`
                if [ "${IA32_EXEC_ADDR}" = "" ]; then
                        echo "not found"
                        echo "Unable to obtain compat_do_execve symbol in System.map."
                        exit 1
                else
                        echo ${IA32_EXEC_ADDR}
                fi;




	fi;
else
	echo "not found"
	echo "Unable to locate /boot/System.map-${VERSION} file."
	exit 1
fi;

echo -n "Locating any duplicated KHM in kernel... "
MOD=`lsmod | grep splxmod`
if [ "${MOD}" = "" ]; then
	echo "not found"
	echo -n "Inserting KHM into kernel... "
	if [ "${ARCH}" = "x86_64" ] ; then
		insmod bin/splxmod-${VERSION}.${ARCH}.o splxmod_addr=0x${SCT_ADDR} splxmod_debug=2 splxmod_execve_addr=0x${EXEC_ADDR} splxmod_ret_addr=0x${RET_ADDR} splxmod_ia32_addr=0x${IA32_SCT_ADDR} splxmod_compat_do_execve_addr=0x${IA32_EXEC_ADDR} > /dev/null 2>&1
	else
		insmod bin/splxmod-${VERSION}.${ARCH}.o splxmod_addr=0x${SCT_ADDR} splxmod_debug=2 splxmod_execve_addr=0x${EXEC_ADDR} > /dev/null 2>&1
	fi;
	if [ $? = "0" ] ; then
		echo "success"
	else
		echo "failed"
		echo "Unable to insert KHM into kernel."
		exit 1
	fi;
else
	echo "found"
	echo "Please stop SPLX services to remove the KHM from kernel before testing."
	exit 1
fi;

# Try to do hook operation

echo -n "Creating SPLX device node... "
rm -rf /dev/splxdev
mknod --mode=640 /dev/splxdev c `grep splxdev /proc/devices  | cut -d " " -f 1` 0
if [ $? = "0" ] ; then
	echo "success"
else
	echo "failed"
	echo "Unable to create SPLX device node."
	FAIL_FLAG=1
fi;

if [ "$FAIL_FLAG" = "0" ] ; then
	echo -n "Running test program... "
	dmesg -c > /dev/null
	./testhelper.${DIST}.${ARCH} > /dev/null 2>&1
	if [ $? = "0" ] ; then
		echo "success"
		echo -n "Testing system call hook operation: 'open'... "
		TEST_VALUE=`dmesg | grep "hooked __NR_open"`
		if [ "${TEST_VALUE}" = "" ]; then
			echo "failed"
			FAIL_FLAG=1
		else
			echo "success"
		fi;
		echo -n "Testing system call hook operation: 'close'... "
		TEST_VALUE=`dmesg | grep "hooked __NR_close"`
		if [ "${TEST_VALUE}" = "" ]; then
			echo "failed"
			FAIL_FLAG=1
		else
			echo "success"
		fi;
		echo -n "Testing system call hook operation: 'execve'... "
		TEST_VALUE=`dmesg | grep "hooked __NR_execve"`
		if [ "${TEST_VALUE}" = "" ]; then
			echo "failed"
			error_message=`dmesg | grep "\[Fatal\]"`
			echo  "$error_message"
			FAIL_FLAG=1
		else
			echo "success"
		fi;
	else
		echo "failed"
		echo "Unable to operate on SPLX device."
		FAIL_FLAG=1
	fi;
fi;

# Try to rmmod
echo -n "Removing KHM from kernel... "
rmmod splxmod > /dev/null
if [ $? = "0" ] ; then
	echo "success"
else
	echo "failed"
	echo "Unable to remove KHM from kernel."
	FAIL_FLAG=1
fi;

# Test success
if [ "$FAIL_FLAG" = "0" ] ; then
	echo 
	echo -ne "\033[32;1mTest successful.\033[0m\n"
	echo -ne "You can type \"make install\" to install the KHM on your Linux system.\n"
	echo -ne "To test whether KHM is installed and working properly, please enable\n"
	echo -ne "real-time scan and test with an EICAR test file.\n"
	exit 0
else
	exit 1
fi;
