/* Kernel Hook Module for Trend Micro ServerProtect for Linux  */
/* Copyright (C) 2012 Trend Micro Incorporated.                */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * 
 */

#ifndef SPLXMOD_INFO_H
#define SPLXMOD_INFO_H
#define RHEL6
#define I686

/* for ioctl(SIOCGETKHMINFO) */
#ifdef SuSE
#define DIST "SuSE"
#elif defined (CentOS)
#define DIST "CentOS"
#elif defined (S390)
#define DIST "SLES/S390"
#elif defined (RedHat)
#define DIST "RedHat"
#elif defined (Miracle)
#define DIST "Miracle"
#elif defined (Debian)
#define DIST "Debian"
#elif defined (United)
#define DIST "United"
#elif defined (Turbo)
#define DIST "Turbo"
#endif
#define PLATFORM "i686-smp"
#define INTERFACE_VERSION 3
#define RELEASE 1

/* for modinfo */
#ifdef RHEL4
#define MODINFO_DISTV "Red Hat(TM) Enterprise/Desktop Linux 4"
#elif defined (CentOS4)
#define MODINFO_DISTV "CentOS release 4"
#elif defined (CentOS5)
#define MODINFO_DISTV "CentOS release 5"
#elif defined (CentOS6)
#define MODINFO_DISTV "CentOS release 6"
#elif defined (SUSE10)
#define MODINFO_DISTV "SUSE(TM) Linux Enterprise Server/Desktop 10"
#elif defined (SUSE11)
#define MODINFO_DISTV "SUSE(TM) Linux Enterprise Server/Desktop 11"
#elif defined (RHEL5)
#define MODINFO_DISTV "Red Hat(TM) Enterprise Linux Server/Client 5"
#elif defined (RHEL6)
#define MODINFO_DISTV "Red Hat(TM) Enterprise Linux Server/Client 6"
#elif defined (ASIANUX2)
#define MODINFO_DISTV "Asianux 2.0"
#elif defined (ASIANUX3)
#define MODINFO_DISTV "Asianux Server 3"
#else 
#define MODINFO_DISTV "Other Linux"
#endif
#define DRIVER_AUTHOR "Trend Micro ServerProtect for Linux User"
#define DRIVER_DESC "Kernel Hooking Module for ServerProtect for Linux (User Build) \n\t\tversion 3.0.1.0010      2013-03-15   16:33:28\n\t\t" MODINFO_DISTV " I686"

#endif
