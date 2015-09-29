/*
 * Copyright (C) 2013 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <stdarg.h>
#include <sys/mman.h>

#include <stdlib.h>

#include <common/log.h>

#include "torsocks.h"

/* syscall(2) */
TSOCKS_LIBC_DECL(syscall, LIBC_SYSCALL_RET_TYPE, LIBC_SYSCALL_SIG)

#if (defined(__linux__) || defined(__darwin__) || (defined(__FreeBSD_kernel__) && defined(__i386__)) || defined(__NetBSD__))
#endif /* __linux__, __darwin__, __FreeBSD_kernel__, __i386__, __NetBSD__ */

// TODO https://github.com/gregose/syscall-table/blob/master/gen_syscalls.py
// the CASE macro below takes an identifier and tries to parse it as an int.
// if undefined, return (-1). Note that the || at the end requires a 0 ending
#define STRINGIFY(a) #a
#define ISNUM(a,i) (STRINGIFY(a)[i] <= 0x39 && STRINGIFY(a)[i] >= 0x30)
#define NUMERIFY(a,i) (ISNUM(a,i) \
                       ? (STRINGIFY(a)[i] & 0xf) : -1 )
#define CASE(a) \
  (ISNUM(a,2) \
  ? (NUMERIFY(a,0) * 100 + (NUMERIFY(a,1) * 10) + NUMERIFY(a,2)) \
  : (ISNUM(a,1) \
    ? (NUMERIFY(a,0) * 10 +  NUMERIFY(a,1)) \
    : NUMERIFY(a,0))) ||

/*
 * Torsocks call for syscall(2)
 */
LIBC_SYSCALL_RET_TYPE tsocks_syscall(int number, va_list args)
{
  // TODO SEE: http://syscalls.kernelgrok.com/ for syscall info
  long arg1, arg2, arg3, arg4, arg5, arg6;

  if(
    CASE(SYS_getpid)
    CASE(SYS_sync)
    CASE(SYS_pause)
    CASE(SYS_getppid)
    CASE(SYS_getpgrp)
    CASE(SYS_setsid)
    CASE(SYS_getuid)
    CASE(SYS_getgid)
    CASE(SYS_geteuid)
    CASE(SYS_getgid)
    CASE(SYS_geteuid)
    CASE(SYS_getegid)
    CASE(SYS_gettid)
    CASE(SYS_inotify_init)
    0
  ) return tsocks_libc_syscall(number);

  arg1 = va_arg(args, long);

  if(
    CASE(SYS_eventfd)
    CASE(SYS_inotify_init1)
    CASE(SYS_epoll_create1)
    CASE(SYS_inotify_add_watch)
    0
  )	return tsocks_libc_syscall(number, arg1);

  switch(number){
#if defined(__linux__)
  case TSOCKS_NR_CLOSE:
    // Handle close syscall to be called with tsocks call.
    return tsocks_close(arg1); // int fd
    break;
#endif // __linux__
  }

  arg2 = va_arg(args, long);

  switch(number){
    case TSOCKS_NR_LISTEN:
      return tsocks_listen(arg1, arg2);
      break;
  }

  if(
    CASE(SYS_tkill)
    CASE(SYS_epoll_ctl)
    CASE(SYS_eventfd2)
    CASE(TSOCKS_NR_MUNMAP)
    0
  ) return tsocks_libc_syscall(number, arg1, arg2);

  arg3 = va_arg(args, long);
  switch(number){
    case TSOCKS_NR_SOCKET:
    // Handle socket syscall to go through Tor.
    // domain, type, socket
      return tsocks_socket(arg1, arg2, arg3);
		  break;
	  case TSOCKS_NR_CONNECT:
    //Handle connect syscall to go through Tor. int sockfd; const struct sockaddr *addr; 	socklen_t addrlen;
      return tsocks_connect(arg1, (const struct sockaddr *) arg2, arg3);
      break;
    case TSOCKS_NR_ACCEPT:
      return tsocks_accept(arg1 /*sockfd*/, (struct sockaddr *) arg2 /*addr*/, (socklen_t *) arg3 /*addrlen*/);
      break;
    case TSOCKS_NR_GETPEERNAME:
      return tsocks_getpeername(arg1 /*sockfd*/, (struct sockaddr *) arg2 /*addr*/, (socklen_t *) arg3 /*addrlen*/);
      break;
    case TSOCKS_NR_RECVMSG:
      return tsocks_recvmsg(arg1 /*sockfd*/, (struct msghdr *) arg2 /*msg*/, arg3 /*flags*/);
      break;
  }

  if(
    CASE(SYS_getrandom)
    CASE(SYS_inotify_add_watch)
    CASE(SYS_getxattr)
    CASE(SYS_lgetxattr)
    0
  ) return tsocks_libc_syscall(number, arg1, arg2, arg3);

  arg4 = va_arg(args, long);
  if(
    CASE(SYS_epoll_wait)
    0
  )
  switch(number){
  #if defined(__linux__)
    case TSOCKS_NR_ACCEPT4:
      return tsocks_accept4(arg1 /*sockfd*/, (struct sockaddr *) arg2 /*addr*/, (socklen_t *) arg3 /*addrlen*/, arg4 /*flags*/);
      break;
  #endif // __linux__
  }

  arg5 = va_arg(args, long);
  if(
    CASE(SYS_epoll_pwait)
    0
  ) return tsocks_libc_syscall(number, arg1, arg2, arg3, arg4, arg5);

  arg6 = va_arg(args, long);
  if(number == TSOCKS_NR_MMAP){
#if (defined(__NetBSD__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) && defined(__x86_64)
		 // On an 64 bit *BSD system, __syscall(2) should be used for mmap().
		 // This is NOT suppose to happen but for protection we deny that call.
      errno = ENOSYS;
      return (-1);
#else
		/*
		 * The mmap/munmap syscall are handled here for a very specific case so
		 * buckle up here for the explanation :).
		 *
		 * Considering an application that handles its own memory using a
		 * malloc(2) hook for instance *AND* mmap() is called with syscall(),
		 * we have to route the call to the libc in order to complete the
		 * syscall() symbol lookup.
		 *
		 * The lookup process of the libdl (using dlsym(3)) calls at some point
		 * malloc for a temporary buffer so we end up in this torsocks wrapper
		 * when mmap() is called to create a new memory region for the
		 * application (remember the malloc hook). When getting here, the libc
		 * syscall() symbol is NOT yet populated because we are in the lookup
		 * code path. For this, we directly call mmap/munmap using the libc so
		 * the lookup can be completed.
		 *
		 * This crazy situation is present in Mozilla Firefox which handles its
		 * own memory using mmap() called by syscall(). Same for munmap().
		 */
#endif /* __NetBSD__, __FreeBSD__, __FreeBSD_kernel__, __x86_64 ^-- ELSE CASE */
  }
  if(
    CASE(SYS_mmap)
    CASE(SYS_futex)
    0
  ) return tsocks_libc_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6);
     /* Handle futex(2) syscall.
     * This assumes Linux 2.6.7 or later, as that is when 'val3' was
     * added to futex(2).  Kernel versions prior to that are what I -TODO TAKE LSD, GET RID OF "I"-
     * would consider historic.
     * TODO meanwhile 2.4 is still common in embedded systems, so this should be fixed TODO */

  WARN("[syscall] Unsupported syscall number %ld. Denying the call",
				number);
  errno = ENOSYS;
  return (-1);
}

/*
 * Libc hijacked symbol syscall(2).
 */
//TODO #ifdef USE_SECCOMP
LIBC_SYSCALL_DECL
{
  va_list args;

	if (!tsocks_libc_syscall) {
		tsocks_initialize();
		tsocks_libc_syscall= tsocks_find_libc_symbol(
				LIBC_SYSCALL_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

  // TODO consider merging these two functions
	return tsocks_syscall(number, args);
}
//TODO #endif // ifndef USE_SECCOMP

/* Only used for *BSD systems. */
#if (defined(__NetBSD__) || defined(__FreeBSD__))

/* __syscall(2) */
TSOCKS_LIBC_DECL(__syscall, LIBC___SYSCALL_RET_TYPE, LIBC___SYSCALL_SIG)

LIBC___SYSCALL_RET_TYPE tsocks___syscall(quad_t number, va_list args)
{
	LIBC_SYSCALL_RET_TYPE ret;

	switch (number) {
	case TSOCKS_NR_MMAP:
		/*
		 * Please see the mmap comment in the syscall() function to understand
		 * why mmap is being hijacked.
		 */
    // TODO this is BSD-style mmap:
    return (LIBC___SYSCALL_RET_TYPE) mmap((void *) arg1 /*addr*/, (size_t) arg2 /*len*/, arg3 /*prot*/, arg4 /*flags*/, arg5 /*fd*/, (off_t) arg6 /*offset*/);
		break;
	default:
		/*
		 * Because of the design of syscall(), we can't pass a va_list to it so
		 * we are constraint to use a whitelist scheme and denying the rest.
		 */
		WARN("[syscall] Unsupported __syscall number %ld. Denying the call",
				number);
		ret = -1;
		errno = ENOSYS;
		break;
	}

	return ret;
}

LIBC___SYSCALL_DECL
{
	LIBC___SYSCALL_RET_TYPE ret;
	va_list args;

	va_start(args, number);
	ret = tsocks___syscall(number, args);
	va_end(args);

	return ret;
}

#endif /* __NetBSD__, __FreeBSD__ */
