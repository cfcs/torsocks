/*
 * Copyright (C) 2000-2008 - Shaun Clowes <delius@progsoc.org>
 * 				 2008-2011 - Robert Hogan <robert@roberthogan.net>
 * 				 	  2013 - David Goulet <dgoulet@ev0ke.net>
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

#ifndef TORSOCKS_H
#define TORSOCKS_H

#include <common/compat.h>
#include <common/config-file.h>
#include <string.h>


void tsocks_seccomp_init(void);
#ifdef USE_SECCOMP
#include <seccomp.h>
#endif // USE_SECCOMP

/*
 * This defines a function pointer to the original libc call of "name" so the
 * libc call outside of torsocks can be used. These are declared for each
 * symbol torsocks hijacked.
 */
#define TSOCKS_LIBC_DECL(name, type, sig) \
	type (*tsocks_libc_##name)(sig);
#define TSOCKS_DECL(name, type, sig) \
	extern type tsocks_##name(sig);

#if (defined(__GLIBC__) || defined(__FreeBSD__) || defined(__darwin__) || defined(__NetBSD__))

/* connect(2) */
#include <sys/types.h>
#include <sys/socket.h>

#define LIBC_CONNECT_NAME connect
#define LIBC_CONNECT_NAME_STR XSTR(LIBC_CONNECT_NAME)
#define LIBC_CONNECT_RET_TYPE int
#define LIBC_CONNECT_SIG \
	int sockfd, const struct sockaddr *addr, socklen_t addrlen
#define LIBC_CONNECT_ARGS \
	sockfd, addr, addrlen

/* socket(2) */
#define LIBC_SOCKET_NAME socket
#define LIBC_SOCKET_NAME_STR XSTR(LIBC_SOCKET_NAME)
#define LIBC_SOCKET_RET_TYPE int
#define LIBC_SOCKET_SIG \
	int domain, int type, int protocol
#define LIBC_SOCKET_ARGS \
	domain, type, protocol

/* socketpair(2) */
#define LIBC_SOCKETPAIR_NAME socketpair
#define LIBC_SOCKETPAIR_NAME_STR XSTR(LIBC_SOCKETPAIR_NAME)
#define LIBC_SOCKETPAIR_RET_TYPE int
#define LIBC_SOCKETPAIR_SIG \
	int domain, int type, int protocol, int sv[2]
#define LIBC_SOCKETPAIR_ARGS \
	domain, type, protocol, sv

/* open(2) */
#include <fcntl.h>
#include <sys/stat.h>

#define LIBC_OPEN_NAME open
#define LIBC_OPEN_NAME_STR XSTR(LIBC_OPEN_NAME)
#define LIBC_OPEN_RET_TYPE int
#define LIBC_OPEN_SIG const char *file, int oflag, ...
#define LIBC_OPEN_ARGS file, oflag, mode

/* close(2) */
#include <unistd.h>

#define LIBC_CLOSE_NAME close
#define LIBC_CLOSE_NAME_STR XSTR(LIBC_CLOSE_NAME)
#define LIBC_CLOSE_RET_TYPE int
#define LIBC_CLOSE_SIG int fd
#define LIBC_CLOSE_ARGS fd

/* shutdown(2) */
#include <sys/socket.h>

#define LIBC_SHUTDOWN_NAME shutdown
#define LIBC_SHUTDOWN_NAME_STR XSTR(LIBC_SHUTDOWN_NAME)
#define LIBC_SHUTDOWN_RET_TYPE int
#define LIBC_SHUTDOWN_SIG int sockfd, int how
#define LIBC_SHUTDOWN_ARGS sockfd, how

/* fopen(3) */
#include <stdio.h>

#define LIBC_FOPEN_NAME fopen
#define LIBC_FOPEN_NAME_STR XSTR(LIBC_FOPEN_NAME)
#define LIBC_FOPEN_RET_TYPE FILE *
#define LIBC_FOPEN_SIG const char *path, const char *mode
#define LIBC_FOPEN_ARGS path, mode

/* fdopen(3) */
#include <stdio.h>

#define LIBC_FDOPEN_NAME fdopen
#define LIBC_FDOPEN_NAME_STR XSTR(LIBC_FDOPEN_NAME)
#define LIBC_FDOPEN_RET_TYPE FILE *
#define LIBC_FDOPEN_SIG int fd, const char *mode
#define LIBC_FDOPEN_ARGS fd, mode

/* freopen(3) */
#include <stdio.h>

#define LIBC_FREOPEN_NAME freopen
#define LIBC_FREOPEN_NAME_STR XSTR(LIBC_FREOPEN_NAME)
#define LIBC_FREOPEN_RET_TYPE FILE *
#define LIBC_FREOPEN_SIG const char *path, const char *mode, FILE *stream
#define LIBC_FREOPEN_ARGS path, mode, stream

/* fclose(3) */
#include <stdio.h>

#define LIBC_FCLOSE_NAME fclose
#define LIBC_FCLOSE_NAME_STR XSTR(LIBC_FCLOSE_NAME)
#define LIBC_FCLOSE_RET_TYPE int
#define LIBC_FCLOSE_SIG FILE *fp
#define LIBC_FCLOSE_ARGS fp

/* dup(2) */
#include <unistd.h>

#define LIBC_DUP_NAME dup
#define LIBC_DUP_NAME_STR XSTR(LIBC_DUP_NAME)
#define LIBC_DUP_RET_TYPE int
#define LIBC_DUP_SIG int oldfd
#define LIBC_DUP_ARGS oldfd

/* dup2(2) */
#include <unistd.h>

#define LIBC_DUP2_NAME dup2
#define LIBC_DUP2_NAME_STR XSTR(LIBC_DUP2_NAME)
#define LIBC_DUP2_RET_TYPE int
#define LIBC_DUP2_SIG int oldfd, int newfd
#define LIBC_DUP2_ARGS oldfd, newfd

/* gethostbyname(3) - DEPRECATED in glibc. */
#include <netdb.h>

/*
 * The man page specifies that this call can return a pointers to static data
 * meaning that the caller needs to copy the returned data and not forced to
 * use free(). So, we use static memory here to mimic the libc call and avoid
 * memory leaks. This also void the need of hijacking freehostent(3).
 */
extern struct hostent tsocks_he;
extern char *tsocks_he_addr_list[2];
extern char tsocks_he_addr[INET_ADDRSTRLEN];
extern char tsocks_he_name[255];

#define LIBC_GETHOSTBYNAME_NAME gethostbyname
#define LIBC_GETHOSTBYNAME_NAME_STR XSTR(LIBC_GETHOSTBYNAME_NAME)
#define LIBC_GETHOSTBYNAME_RET_TYPE struct hostent *
#define LIBC_GETHOSTBYNAME_SIG const char *name
#define LIBC_GETHOSTBYNAME_ARGS name

/* gethostbyname2(3) - GNU extension to avoid static data. */
#define LIBC_GETHOSTBYNAME2_NAME gethostbyname2
#define LIBC_GETHOSTBYNAME2_NAME_STR XSTR(LIBC_GETHOSTBYNAME2_NAME)
#define LIBC_GETHOSTBYNAME2_RET_TYPE struct hostent *
#define LIBC_GETHOSTBYNAME2_SIG const char *name, int af
#define LIBC_GETHOSTBYNAME2_ARGS name, af

/* GNU extension. Reentrant version. */
#define LIBC_GETHOSTBYNAME_R_NAME gethostbyname_r
#define LIBC_GETHOSTBYNAME_R_NAME_STR XSTR(LIBC_GETHOSTBYNAME_R_NAME)
#define LIBC_GETHOSTBYNAME_R_RET_TYPE int
#define LIBC_GETHOSTBYNAME_R_SIG const char *name, \
	struct hostent *hret, char *buf, size_t buflen, \
	struct hostent **result, int *h_errnop
#define LIBC_GETHOSTBYNAME_R_ARGS name, hret, buf, \
	buflen, result, h_errnop

/* GNU extension. Reentrant version 2. */
#define LIBC_GETHOSTBYNAME2_R_NAME gethostbyname2_r
#define LIBC_GETHOSTBYNAME2_R_NAME_STR XSTR(LIBC_GETHOSTBYNAME2_R_NAME)
#define LIBC_GETHOSTBYNAME2_R_RET_TYPE int
#define LIBC_GETHOSTBYNAME2_R_SIG const char *name, int af, \
	struct hostent *hret, char *buf, size_t buflen, \
struct hostent **result, int *h_errnop
#define LIBC_GETHOSTBYNAME2_R_ARGS name, af, hret, buf, \
	buflen, result, h_errnop

/* gethostbyaddr(3) - DEPRECATED in glibc. */
#include <sys/socket.h>

#define LIBC_GETHOSTBYADDR_NAME gethostbyaddr
#define LIBC_GETHOSTBYADDR_NAME_STR XSTR(LIBC_GETHOSTBYADDR_NAME)
#define LIBC_GETHOSTBYADDR_RET_TYPE struct hostent *
#define LIBC_GETHOSTBYADDR_SIG const void *addr, socklen_t len, int type
#define LIBC_GETHOSTBYADDR_ARGS addr, len, type

/* GNU extension. Reentrant version. */
#define LIBC_GETHOSTBYADDR_R_NAME gethostbyaddr_r
#define LIBC_GETHOSTBYADDR_R_NAME_STR XSTR(LIBC_GETHOSTBYADDR_R_NAME)
#define LIBC_GETHOSTBYADDR_R_RET_TYPE int
#define LIBC_GETHOSTBYADDR_R_SIG const void *addr, socklen_t len, int type, \
	struct hostent *hret, char *buf, size_t buflen, \
	struct hostent **result, int *h_errnop
#define LIBC_GETHOSTBYADDR_R_ARGS addr, len, type, hret, buf, \
	buflen, result, h_errnop

/* getaddrinfo(3) */
#include <netdb.h>

#define LIBC_GETADDRINFO_NAME getaddrinfo
#define LIBC_GETADDRINFO_NAME_STR XSTR(LIBC_GETADDRINFO_NAME)
#define LIBC_GETADDRINFO_RET_TYPE int
#define LIBC_GETADDRINFO_SIG \
	const char *node, const char *service, const struct addrinfo *hints,\
	struct addrinfo **res
#define LIBC_GETADDRINFO_ARGS  node, service, hints, res

/* getpeername(2) */
#include <sys/socket.h>

#define LIBC_GETPEERNAME_NAME getpeername
#define LIBC_GETPEERNAME_NAME_STR XSTR(LIBC_GETPEERNAME_NAME)
#define LIBC_GETPEERNAME_RET_TYPE int
#define LIBC_GETPEERNAME_SIG \
	int sockfd, struct sockaddr *addr, socklen_t *addrlen
#define LIBC_GETPEERNAME_ARGS  sockfd, addr, addrlen

/* read(2) */
#define LIBC_READ_NAME read
#define LIBC_READ_NAME_STR XSTR(LIBC_READ_NAME)
#define LIBC_READ_RET_TYPE ssize_t
#define LIBC_READ_SIG \
	int fd, void *buf, size_t count
#define LIBC_READ_ARGS \
	fd, buf, count

/* readv(2) */
#define LIBC_READV_NAME readv
#define LIBC_READV_NAME_STR XSTR(LIBC_READV_NAME)
#define LIBC_READV_RET_TYPE ssize_t
#define LIBC_READV_SIG \
	int fd, const struct iovec *iov, int iovcnt
#define LIBC_READV_ARGS \
	fd, iov, iovcnt

/* recv(2) */
#define LIBC_RECV_NAME recv
#define LIBC_RECV_NAME_STR XSTR(LIBC_RECV_NAME)
#define LIBC_RECV_RET_TYPE ssize_t
#define LIBC_RECV_SIG \
	int sockfd, void *buf, size_t len, int flags
#define LIBC_RECV_ARGS \
	sockfd, buf, len, flags

/* recvmsg(2) */
#define LIBC_RECVMSG_NAME recvmsg
#define LIBC_RECVMSG_NAME_STR XSTR(LIBC_RECVMSG_NAME)
#define LIBC_RECVMSG_RET_TYPE ssize_t
#define LIBC_RECVMSG_SIG \
	int sockfd, struct msghdr *msg, int flags
#define LIBC_RECVMSG_ARGS \
	sockfd, msg, flags

/* recvfrom(2) */
#define LIBC_RECVFROM_NAME recvfrom
#define LIBC_RECVFROM_NAME_STR XSTR(LIBC_RECVFROM_NAME)
#define LIBC_RECVFROM_RET_TYPE ssize_t
#define LIBC_RECVFROM_SIG \
	int sockfd, void *buf, size_t len, int flags, \
	struct sockaddr *src_addr, socklen_t *addrlen
#define LIBC_RECVFROM_ARGS \
	sockfd, buf, len, flags, src_addr, addrlen

/* write(2) */
#define LIBC_WRITE_NAME write
#define LIBC_WRITE_NAME_STR XSTR(LIBC_WRITE_NAME)
#define LIBC_WRITE_RET_TYPE ssize_t
#define LIBC_WRITE_SIG \
	int fd, const void *buf, size_t count
#define LIBC_WRITE_ARGS \
	fd, buf, count

/* writev(2) */
#define LIBC_WRITEV_NAME writev
#define LIBC_WRITEV_NAME_STR XSTR(LIBC_WRITEV_NAME)
#define LIBC_WRITEV_RET_TYPE ssize_t
#define LIBC_WRITEV_SIG \
	int fd, const struct iovec *iov, int iovcnt
#define LIBC_WRITEV_ARGS \
	fd, iov, iovcnt

/* send(2) */
#define LIBC_SEND_NAME send
#define LIBC_SEND_NAME_STR XSTR(LIBC_SEND_NAME)
#define LIBC_SEND_RET_TYPE ssize_t
#define LIBC_SEND_SIG \
	int sockfd, const void *buf, size_t len, int flags
#define LIBC_SEND_ARGS \
	sockfd, buf, len, flags

/* sendmsg(2) */
#define LIBC_SENDMSG_NAME sendmsg
#define LIBC_SENDMSG_NAME_STR XSTR(LIBC_SENDMSG_NAME)
#define LIBC_SENDMSG_RET_TYPE ssize_t
#define LIBC_SENDMSG_SIG \
	int sockfd, const struct msghdr *msg, int flags
#define LIBC_SENDMSG_ARGS \
	sockfd, msg, flags

/* sendto(2) */
#define LIBC_SENDTO_NAME sendto
#define LIBC_SENDTO_NAME_STR XSTR(LIBC_SENDTO_NAME)
#define LIBC_SENDTO_RET_TYPE ssize_t
#define LIBC_SENDTO_SIG \
	int sockfd, const void *buf, size_t len, int flags,\
	const struct sockaddr *dest_addr, socklen_t addrlen
#define LIBC_SENDTO_ARGS \
	sockfd, buf, len, flags, dest_addr, addrlen

/* accept(2) */
#define LIBC_ACCEPT_NAME accept
#define LIBC_ACCEPT_NAME_STR XSTR(LIBC_ACCEPT_NAME)
#define LIBC_ACCEPT_RET_TYPE int
#define LIBC_ACCEPT_SIG \
	int sockfd, struct sockaddr *addr, socklen_t *addrlen
#define LIBC_ACCEPT_ARGS sockfd, addr, addrlen

/* listen(2) */
#define LIBC_LISTEN_NAME listen
#define LIBC_LISTEN_NAME_STR XSTR(LIBC_LISTEN_NAME)
#define LIBC_LISTEN_RET_TYPE int
#define LIBC_LISTEN_SIG \
	int sockfd, int backlog
#define LIBC_LISTEN_ARGS sockfd, backlog

/* select(2) */
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#define LIBC_SELECT_NAME select
#define LIBC_SELECT_NAME_STR XSTR(LIBC_SELECT_NAME)
#define LIBC_SELECT_RET_TYPE int
#define LIBC_SELECT_SIG \
        int nfds, fd_set *readfds, fd_set *writefds, \
        fd_set *exceptfds, struct timeval *timeout
#define LIBC_SELECT_ARGS nfds, readfds, writefds, exceptfds, timeout

#define LIBC_PSELECT_NAME pselect
#define LIBC_PSELECT_NAME_STR XSTR(LIBC_PSELECT_NAME)
#define LIBC_PSELECT_RET_TYPE int
#define LIBC_PSELECT_SIG \
        int nfds, fd_set *readfds, fd_set *writefds, \
        fd_set *exceptfds, const struct timespec *timeout, \
        const sigset_t *sigmask
#define LIBC_PSELECT_ARGS nfds, readfds, writefds, exceptfds, timeout, sigmask

/* poll(2) */
#if (defined(__linux__))
#define _GNU_SOURCE
#endif
#include <poll.h>
#define LIBC_POLL_NAME poll
#define LIBC_POLL_NAME_STR XSTR(LIBC_POLL_NAME)
#define LIBC_POLL_RET_TYPE int
#define LIBC_POLL_SIG \
        struct pollfd *fds, nfds_t nfds, int timeout
#define LIBC_POLL_ARGS fds, nfds, timeout

#else
#error "OS not supported."
#endif /* __GLIBC__ , __FreeBSD__, __darwin__, __NetBSD__ */

#if (defined(__linux__))

#define _GNU_SOURCE

/* syscall(2) */
#define LIBC_SYSCALL_NAME syscall
#define LIBC_SYSCALL_NAME_STR XSTR(LIBC_SYSCALL_NAME)
#define LIBC_SYSCALL_RET_TYPE long int
#define LIBC_SYSCALL_SIG long int number, ...
#define LIBC_SYSCALL_ARGS number

/* accept4(2) */
#define LIBC_ACCEPT4_NAME accept4
#define LIBC_ACCEPT4_NAME_STR XSTR(LIBC_ACCEPT4_NAME)
#define LIBC_ACCEPT4_RET_TYPE int
#define LIBC_ACCEPT4_SIG \
	int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags
#define LIBC_ACCEPT4_ARGS sockfd, addr, addrlen, flags

/* dup3(2) */
#include <unistd.h>
#include <fcntl.h>

#define LIBC_DUP3_NAME dup3
#define LIBC_DUP3_NAME_STR XSTR(LIBC_DUP3_NAME)
#define LIBC_DUP3_RET_TYPE int
#define LIBC_DUP3_SIG int oldfd, int newfd, int flags
#define LIBC_DUP3_ARGS oldfd, newfd, flags

/* gethostbyname(3) - DEPRECATED in glibc. */
#include <netdb.h>


/* ppoll(2) */
#define _GNU_SOURCE
#include <poll.h>

#define LIBC_PPOLL_NAME ppoll
#define LIBC_PPOLL_NAME_STR XSTR(LIBC_PPOLL_NAME)
#define LIBC_PPOLL_RET_TYPE int
#define LIBC_PPOLL_SIG \
        struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, \
	const sigset_t *sigmask
#define LIBC_PPOLL_ARGS fds, nfds, timeout_ts, sigmask

/* epoll_create(2) */
#include <sys/epoll.h>
#define LIBC_EPOLL_CREATE_NAME epoll_create
#define LIBC_EPOLL_CREATE_NAME_STR XSTR(LIBC_EPOLL_CREATE_NAME)
#define LIBC_EPOLL_CREATE_RET_TYPE int
#define LIBC_EPOLL_CREATE_SIG int size
#define LIBC_EPOLL_CREATE_ARGS size

#define LIBC_EPOLL_CREATE1_NAME epoll_create1
#define LIBC_EPOLL_CREATE1_NAME_STR XSTR(LIBC_EPOLL_CREATE1_NAME)
#define LIBC_EPOLL_CREATE1_RET_TYPE int
#define LIBC_EPOLL_CREATE1_SIG int flags
#define LIBC_EPOLL_CREATE1_ARGS flags

/* epoll_ctl(2) */
#include <sys/epoll.h>
#define LIBC_EPOLL_CTL_NAME epoll_ctl
#define LIBC_EPOLL_CTL_NAME_STR XSTR(LIBC_EPOLL_CTL_NAME)
#define LIBC_EPOLL_CTL_RET_TYPE int
#define LIBC_EPOLL_CTL_SIG int epfd, int op, int fd, struct epoll_event *event
#define LIBC_EPOLL_CTL_ARGS epfd, op, fd, event

/* epoll_wait(2) */
#include <sys/epoll.h>
#define LIBC_EPOLL_WAIT_NAME epoll_wait
#define LIBC_EPOLL_WAIT_NAME_STR XSTR(LIBC_EPOLL_WAIT_NAME) 
#define LIBC_EPOLL_WAIT_RET_TYPE int
#define LIBC_EPOLL_WAIT_SIG int epfd, struct epoll_event *events, int maxevents, \
			int timeout
#define LIBC_EPOLL_WAIT_ARGS epfd, events, maxevents, timeout

#define LIBC_EPOLL_PWAIT_NAME epoll_pwait
#define LIBC_EPOLL_PWAIT_NAME_STR XSTR(LIBC_EPOLL_PWAIT_NAME) 
#define LIBC_EPOLL_PWAIT_RET_TYPE int
#define LIBC_EPOLL_PWAIT_SIG int epfd, struct epoll_event *events, int maxevents, \
			int timeout, const sigset_t *sigmask
#define LIBC_EPOLL_PWAIT_ARGS epfd, events, maxevents, timeout, sigmask

#endif /* __linux__ */

#if (defined(__FreeBSD__) || defined(__darwin__) || defined(__NetBSD__))

/* syscall(2) */
#define LIBC_SYSCALL_NAME syscall
#define LIBC_SYSCALL_NAME_STR XSTR(LIBC_SYSCALL_NAME)
#define LIBC_SYSCALL_RET_TYPE int
#define LIBC_SYSCALL_SIG int number, ...
#define LIBC_SYSCALL_ARGS number

#endif /* __FreeBSD__, __darwin__, __NetBSD__ */

#if defined(__GLIBC__) && defined(__FreeBSD_kernel__)

/* syscall(2) */
#define LIBC_SYSCALL_NAME syscall
#define LIBC_SYSCALL_NAME_STR XSTR(LIBC_SYSCALL_NAME)
#define LIBC_SYSCALL_RET_TYPE long int
#define LIBC_SYSCALL_SIG long int number, ...
#define LIBC_SYSCALL_ARGS number

#endif /* __GLIBC__ && __FreeBSD_kernel__ */

/* __syscall(2) */
#if defined(__FreeBSD__)

#define LIBC___SYSCALL_NAME __syscall
#define LIBC___SYSCALL_NAME_STR XSTR(LIBC___SYSCALL_NAME)
#define LIBC___SYSCALL_RET_TYPE off_t
#define LIBC___SYSCALL_SIG quad_t number, ...
#define LIBC___SYSCALL_ARGS number

#elif defined(__NetBSD__)

#define LIBC___SYSCALL_NAME __syscall
#define LIBC___SYSCALL_NAME_STR XSTR(LIBC___SYSCALL_NAME)
#define LIBC___SYSCALL_RET_TYPE quad_t
#define LIBC___SYSCALL_SIG quad_t number, ...
#define LIBC___SYSCALL_ARGS number

#endif /* __FreeBSD__, __NetBSD__ */

/*
 * The following defines are libc function declarations using the macros
 * defined above on a per OS basis.
 */

/* connect(2) */
extern TSOCKS_LIBC_DECL(connect, LIBC_CONNECT_RET_TYPE, LIBC_CONNECT_SIG)
TSOCKS_DECL(connect, LIBC_CONNECT_RET_TYPE, LIBC_CONNECT_SIG)
#define LIBC_CONNECT_DECL \
	LIBC_CONNECT_RET_TYPE LIBC_CONNECT_NAME(LIBC_CONNECT_SIG)

/* read(2) */
extern TSOCKS_LIBC_DECL(read, LIBC_READ_RET_TYPE, LIBC_READ_SIG)
TSOCKS_DECL(read, LIBC_READ_RET_TYPE, LIBC_READ_SIG)
#define LIBC_READ_DECL \
		LIBC_READ_RET_TYPE LIBC_READ_NAME(LIBC_READ_SIG)

/* readv(2) */
extern TSOCKS_LIBC_DECL(readv, LIBC_READV_RET_TYPE, LIBC_READV_SIG)
TSOCKS_DECL(readv, LIBC_READV_RET_TYPE, LIBC_READV_SIG)
#define LIBC_READV_DECL \
		LIBC_READV_RET_TYPE LIBC_READV_NAME(LIBC_READV_SIG)

/* recv(2) */
extern TSOCKS_LIBC_DECL(recv, LIBC_RECV_RET_TYPE, LIBC_RECV_SIG)
TSOCKS_DECL(recv, LIBC_RECV_RET_TYPE, LIBC_RECV_SIG)
#define LIBC_RECV_DECL \
		LIBC_RECV_RET_TYPE LIBC_RECV_NAME(LIBC_RECV_SIG)

/* recvmsg(2) */
extern TSOCKS_LIBC_DECL(recvmsg, LIBC_RECVMSG_RET_TYPE, LIBC_RECVMSG_SIG)
TSOCKS_DECL(recvmsg, LIBC_RECVMSG_RET_TYPE, LIBC_RECVMSG_SIG)
#define LIBC_RECVMSG_DECL \
		LIBC_RECVMSG_RET_TYPE LIBC_RECVMSG_NAME(LIBC_RECVMSG_SIG)

/* recvfrom(2) */
extern TSOCKS_LIBC_DECL(recvfrom, LIBC_RECVFROM_RET_TYPE, LIBC_RECVFROM_SIG)
TSOCKS_DECL(recvfrom, LIBC_RECVFROM_RET_TYPE, LIBC_RECVFROM_SIG)
#define LIBC_RECVFROM_DECL \
		LIBC_RECVFROM_RET_TYPE LIBC_RECVFROM_NAME(LIBC_RECVFROM_SIG)

/* write(2) */
extern TSOCKS_LIBC_DECL(write, LIBC_WRITE_RET_TYPE, LIBC_WRITE_SIG)
TSOCKS_DECL(write, LIBC_WRITE_RET_TYPE, LIBC_WRITE_SIG)
#define LIBC_WRITE_DECL \
		LIBC_WRITE_RET_TYPE LIBC_WRITE_NAME(LIBC_WRITE_SIG)

/* writev(2) */
extern TSOCKS_LIBC_DECL(writev, LIBC_WRITEV_RET_TYPE, LIBC_WRITEV_SIG)
TSOCKS_DECL(writev, LIBC_WRITEV_RET_TYPE, LIBC_WRITEV_SIG)
#define LIBC_WRITEV_DECL \
		LIBC_WRITEV_RET_TYPE LIBC_WRITEV_NAME(LIBC_WRITEV_SIG)

/* send(2) */
extern TSOCKS_LIBC_DECL(send, LIBC_SEND_RET_TYPE, LIBC_SEND_SIG)
TSOCKS_DECL(send, LIBC_SEND_RET_TYPE, LIBC_SEND_SIG)
#define LIBC_SEND_DECL \
		LIBC_SEND_RET_TYPE LIBC_SEND_NAME(LIBC_SEND_SIG)

/* sendmsg(2) */
extern TSOCKS_LIBC_DECL(sendmsg, LIBC_SENDMSG_RET_TYPE, LIBC_SENDMSG_SIG)
TSOCKS_DECL(sendmsg, LIBC_SENDMSG_RET_TYPE, LIBC_SENDMSG_SIG)
#define LIBC_SENDMSG_DECL \
		LIBC_SENDMSG_RET_TYPE LIBC_SENDMSG_NAME(LIBC_SENDMSG_SIG)

/* sendto(2) */
extern TSOCKS_LIBC_DECL(sendto, LIBC_SENDTO_RET_TYPE, LIBC_SENDTO_SIG)
TSOCKS_DECL(sendto, LIBC_SENDTO_RET_TYPE, LIBC_SENDTO_SIG)
#define LIBC_SENDTO_DECL \
		LIBC_SENDTO_RET_TYPE LIBC_SENDTO_NAME(LIBC_SENDTO_SIG)

/* socket(2) */
extern TSOCKS_LIBC_DECL(socket, LIBC_SOCKET_RET_TYPE, LIBC_SOCKET_SIG)
TSOCKS_DECL(socket, LIBC_SOCKET_RET_TYPE, LIBC_SOCKET_SIG)
#define LIBC_SOCKET_DECL \
		LIBC_SOCKET_RET_TYPE LIBC_SOCKET_NAME(LIBC_SOCKET_SIG)

/* socketpair(2) */
extern TSOCKS_LIBC_DECL(socketpair, LIBC_SOCKETPAIR_RET_TYPE, LIBC_SOCKETPAIR_SIG)
TSOCKS_DECL(socketpair, LIBC_SOCKETPAIR_RET_TYPE, LIBC_SOCKETPAIR_SIG)
#define LIBC_SOCKETPAIR_DECL \
		LIBC_SOCKETPAIR_RET_TYPE LIBC_SOCKETPAIR_NAME(LIBC_SOCKETPAIR_SIG)

/* syscall(2) */
extern TSOCKS_LIBC_DECL(syscall, LIBC_SYSCALL_RET_TYPE, LIBC_SYSCALL_SIG)
#define LIBC_SYSCALL_DECL \
		LIBC_SYSCALL_RET_TYPE LIBC_SYSCALL_NAME(LIBC_SYSCALL_SIG)

/* __syscall(2) */
#if (defined(__FreeBSD__) || defined(__NetBSD__))
extern TSOCKS_LIBC_DECL(__syscall, LIBC___SYSCALL_RET_TYPE, LIBC___SYSCALL_SIG)
#define LIBC___SYSCALL_DECL \
		LIBC___SYSCALL_RET_TYPE LIBC___SYSCALL_NAME(LIBC___SYSCALL_SIG)
#endif /* __FreeBSD__, __NetBSD__ */

/* open(2) */
extern TSOCKS_LIBC_DECL(open, LIBC_OPEN_RET_TYPE, LIBC_OPEN_SIG)
TSOCKS_DECL(open, LIBC_OPEN_RET_TYPE, LIBC_OPEN_SIG)
#define LIBC_OPEN_DECL \
		LIBC_OPEN_RET_TYPE LIBC_OPEN_NAME(LIBC_OPEN_SIG)

/* close(2) */
extern TSOCKS_LIBC_DECL(close, LIBC_CLOSE_RET_TYPE, LIBC_CLOSE_SIG)
TSOCKS_DECL(close, LIBC_CLOSE_RET_TYPE, LIBC_CLOSE_SIG)
#define LIBC_CLOSE_DECL \
		LIBC_CLOSE_RET_TYPE LIBC_CLOSE_NAME(LIBC_CLOSE_SIG)

/* shutdown(2) */
extern TSOCKS_LIBC_DECL(shutdown, LIBC_SHUTDOWN_RET_TYPE, LIBC_SHUTDOWN_SIG)
TSOCKS_DECL(shutdown, LIBC_SHUTDOWN_RET_TYPE, LIBC_SHUTDOWN_SIG)
#define LIBC_SHUTDOWN_DECL \
		LIBC_SHUTDOWN_RET_TYPE LIBC_SHUTDOWN_NAME(LIBC_SHUTDOWN_SIG)

/* fopen(3) */
extern TSOCKS_LIBC_DECL(fopen, LIBC_FOPEN_RET_TYPE, LIBC_FOPEN_SIG)
TSOCKS_DECL(fopen, LIBC_FOPEN_RET_TYPE, LIBC_FOPEN_SIG)
#define LIBC_FOPEN_DECL \
		LIBC_FOPEN_RET_TYPE LIBC_FOPEN_NAME(LIBC_FOPEN_SIG)

/* fdopen(3) */
extern TSOCKS_LIBC_DECL(fdopen, LIBC_FDOPEN_RET_TYPE, LIBC_FDOPEN_SIG)
TSOCKS_DECL(fdopen, LIBC_FDOPEN_RET_TYPE, LIBC_FDOPEN_SIG)
#define LIBC_FDOPEN_DECL \
		LIBC_FDOPEN_RET_TYPE LIBC_FDOPEN_NAME(LIBC_FDOPEN_SIG)

/* freopen(3) */
extern TSOCKS_LIBC_DECL(freopen, LIBC_FREOPEN_RET_TYPE, LIBC_FREOPEN_SIG)
TSOCKS_DECL(freopen, LIBC_FREOPEN_RET_TYPE, LIBC_FREOPEN_SIG)
#define LIBC_FREOPEN_DECL \
		LIBC_FREOPEN_RET_TYPE LIBC_FREOPEN_NAME(LIBC_FREOPEN_SIG)

/* fclose(3) */
extern TSOCKS_LIBC_DECL(fclose, LIBC_FCLOSE_RET_TYPE, LIBC_FCLOSE_SIG)
TSOCKS_DECL(fclose, LIBC_FCLOSE_RET_TYPE, LIBC_FCLOSE_SIG)
#define LIBC_FCLOSE_DECL \
		LIBC_FCLOSE_RET_TYPE LIBC_FCLOSE_NAME(LIBC_FCLOSE_SIG)

/* dup(2) */
extern TSOCKS_LIBC_DECL(dup, LIBC_DUP_RET_TYPE, LIBC_DUP_SIG)
TSOCKS_DECL(dup, LIBC_DUP_RET_TYPE, LIBC_DUP_SIG)
#define LIBC_DUP_DECL \
		LIBC_DUP_RET_TYPE LIBC_DUP_NAME(LIBC_DUP_SIG)

/* dup2(2) */
extern TSOCKS_LIBC_DECL(dup2, LIBC_DUP2_RET_TYPE, LIBC_DUP2_SIG)
TSOCKS_DECL(dup2, LIBC_DUP2_RET_TYPE, LIBC_DUP2_SIG)
#define LIBC_DUP2_DECL \
		LIBC_DUP2_RET_TYPE LIBC_DUP2_NAME(LIBC_DUP2_SIG)

/* gethostbyname(3) */
extern TSOCKS_LIBC_DECL(gethostbyname, LIBC_GETHOSTBYNAME_RET_TYPE,
		LIBC_GETHOSTBYNAME_SIG)
#define LIBC_GETHOSTBYNAME_DECL LIBC_GETHOSTBYNAME_RET_TYPE \
		LIBC_GETHOSTBYNAME_NAME(LIBC_GETHOSTBYNAME_SIG)

/* gethostbyname_r(3) */
extern TSOCKS_LIBC_DECL(gethostbyname_r, LIBC_GETHOSTBYNAME_R_RET_TYPE,
		LIBC_GETHOSTBYNAME_R_SIG)
#define LIBC_GETHOSTBYNAME_R_DECL LIBC_GETHOSTBYNAME_R_RET_TYPE \
		LIBC_GETHOSTBYNAME_R_NAME(LIBC_GETHOSTBYNAME_R_SIG)

/* gethostbyname2(3) */
extern TSOCKS_LIBC_DECL(gethostbyname2, LIBC_GETHOSTBYNAME2_RET_TYPE,
		LIBC_GETHOSTBYNAME2_SIG)
#define LIBC_GETHOSTBYNAME2_DECL LIBC_GETHOSTBYNAME2_RET_TYPE \
		LIBC_GETHOSTBYNAME2_NAME(LIBC_GETHOSTBYNAME2_SIG)

/* gethostbyname2_r(3) */
extern TSOCKS_LIBC_DECL(gethostbyname2_r, LIBC_GETHOSTBYNAME2_R_RET_TYPE,
		LIBC_GETHOSTBYNAME2_R_SIG)
#define LIBC_GETHOSTBYNAME2_R_DECL LIBC_GETHOSTBYNAME2_R_RET_TYPE \
		LIBC_GETHOSTBYNAME2_R_NAME(LIBC_GETHOSTBYNAME2_R_SIG)

/* gethostbyaddr(3) */
extern TSOCKS_LIBC_DECL(gethostbyaddr, LIBC_GETHOSTBYADDR_RET_TYPE,
		LIBC_GETHOSTBYADDR_SIG)
#define LIBC_GETHOSTBYADDR_DECL LIBC_GETHOSTBYADDR_RET_TYPE \
		LIBC_GETHOSTBYADDR_NAME(LIBC_GETHOSTBYADDR_SIG)

/* gethostbyaddr_r(3) */
extern TSOCKS_LIBC_DECL(gethostbyaddr_r, LIBC_GETHOSTBYADDR_R_RET_TYPE,
		LIBC_GETHOSTBYADDR_R_SIG)
#define LIBC_GETHOSTBYADDR_R_DECL LIBC_GETHOSTBYADDR_R_RET_TYPE \
		LIBC_GETHOSTBYADDR_R_NAME(LIBC_GETHOSTBYADDR_R_SIG)

/* getaddrinfo(3) */
extern TSOCKS_LIBC_DECL(getaddrinfo, LIBC_GETADDRINFO_RET_TYPE,
		LIBC_GETADDRINFO_SIG)
#define LIBC_GETADDRINFO_DECL LIBC_GETADDRINFO_RET_TYPE \
		LIBC_GETADDRINFO_NAME(LIBC_GETADDRINFO_SIG)

/* getpeername(2) */
extern TSOCKS_LIBC_DECL(getpeername, LIBC_GETPEERNAME_RET_TYPE,
		LIBC_GETPEERNAME_SIG)
TSOCKS_DECL(getpeername, LIBC_GETPEERNAME_RET_TYPE, LIBC_GETPEERNAME_SIG)
#define LIBC_GETPEERNAME_DECL LIBC_GETPEERNAME_RET_TYPE \
		LIBC_GETPEERNAME_NAME(LIBC_GETPEERNAME_SIG)

/* accept(2) */
extern TSOCKS_LIBC_DECL(accept, LIBC_ACCEPT_RET_TYPE, LIBC_ACCEPT_SIG)
TSOCKS_DECL(accept, LIBC_ACCEPT_RET_TYPE, LIBC_ACCEPT_SIG)
#define LIBC_ACCEPT_DECL LIBC_ACCEPT_RET_TYPE \
		LIBC_ACCEPT_NAME(LIBC_ACCEPT_SIG)

/* accept4(2) */
#if (defined(__linux__))
extern TSOCKS_LIBC_DECL(accept4, LIBC_ACCEPT4_RET_TYPE, LIBC_ACCEPT4_SIG)
TSOCKS_DECL(accept4, LIBC_ACCEPT4_RET_TYPE, LIBC_ACCEPT4_SIG)
#define LIBC_ACCEPT4_DECL LIBC_ACCEPT4_RET_TYPE \
		LIBC_ACCEPT4_NAME(LIBC_ACCEPT4_SIG)
#endif

/* dup3(2) */
#if (defined(__linux__))
extern TSOCKS_LIBC_DECL(dup3, LIBC_DUP3_RET_TYPE, LIBC_DUP3_SIG)
TSOCKS_DECL(dup3, LIBC_DUP3_RET_TYPE, LIBC_DUP3_SIG)
#define LIBC_DUP3_DECL \
		LIBC_DUP3_RET_TYPE LIBC_DUP3_NAME(LIBC_DUP3_SIG)
#endif

/* listen(2) */
extern TSOCKS_LIBC_DECL(listen, LIBC_LISTEN_RET_TYPE, LIBC_LISTEN_SIG)
TSOCKS_DECL(listen, LIBC_LISTEN_RET_TYPE, LIBC_LISTEN_SIG)
#define LIBC_LISTEN_DECL LIBC_LISTEN_RET_TYPE \
		LIBC_LISTEN_NAME(LIBC_LISTEN_SIG)

/* select(2) */
extern TSOCKS_LIBC_DECL(select, LIBC_SELECT_RET_TYPE, LIBC_SELECT_SIG)
TSOCKS_DECL(select, LIBC_SELECT_RET_TYPE, LIBC_SELECT_SIG)
#define LIBC_SELECT_DECL LIBC_SELECT_RET_TYPE \
		LIBC_SELECT_NAME(LIBC_SELECT_SIG)

/* pselect(2) */
extern TSOCKS_LIBC_DECL(pselect, LIBC_PSELECT_RET_TYPE, LIBC_PSELECT_SIG)
TSOCKS_DECL(pselect, LIBC_PSELECT_RET_TYPE, LIBC_PSELECT_SIG)
#define LIBC_PSELECT_DECL LIBC_PSELECT_RET_TYPE \
		LIBC_PSELECT_NAME(LIBC_PSELECT_SIG)

/* poll(2) */
extern TSOCKS_LIBC_DECL(poll, LIBC_POLL_RET_TYPE, LIBC_POLL_SIG)
TSOCKS_DECL(poll, LIBC_POLL_RET_TYPE, LIBC_POLL_SIG)
#define LIBC_POLL_DECL LIBC_POLL_RET_TYPE \
		LIBC_POLL_NAME(LIBC_POLL_SIG)

/* ppoll(2) */
#if (defined(__linux__))
extern TSOCKS_LIBC_DECL(ppoll, LIBC_PPOLL_RET_TYPE, LIBC_PPOLL_SIG)
TSOCKS_DECL(ppoll, LIBC_PPOLL_RET_TYPE, LIBC_PPOLL_SIG)
#define LIBC_PPOLL_DECL LIBC_PPOLL_RET_TYPE \
		LIBC_PPOLL_NAME(LIBC_PPOLL_SIG)
#endif

/* epoll_create(2) */
#if (defined(__linux__))
extern TSOCKS_LIBC_DECL(epoll_create, LIBC_EPOLL_CREATE_RET_TYPE, LIBC_EPOLL_CREATE_SIG)
TSOCKS_DECL(epoll_create, LIBC_EPOLL_CREATE_RET_TYPE, LIBC_EPOLL_CREATE_SIG)
#define LIBC_EPOLL_CREATE_DECL LIBC_EPOLL_CREATE_RET_TYPE \
		LIBC_EPOLL_CREATE_NAME(LIBC_EPOLL_CREATE_SIG)

extern TSOCKS_LIBC_DECL(epoll_create1, LIBC_EPOLL_CREATE1_RET_TYPE, LIBC_EPOLL_CREATE1_SIG)
TSOCKS_DECL(epoll_create1, LIBC_EPOLL_CREATE1_RET_TYPE, LIBC_EPOLL_CREATE1_SIG)
#define LIBC_EPOLL_CREATE1_DECL LIBC_EPOLL_CREATE1_RET_TYPE \
		LIBC_EPOLL_CREATE1_NAME(LIBC_EPOLL_CREATE1_SIG)
#endif

/* epoll_ctl(2) */
#if (defined(__linux__))
extern TSOCKS_LIBC_DECL(epoll_ctl, LIBC_EPOLL_CTL_RET_TYPE, LIBC_EPOLL_CTL_SIG)
TSOCKS_DECL(epoll_ctl, LIBC_EPOLL_CTL_RET_TYPE, LIBC_EPOLL_CTL_SIG)
#define LIBC_EPOLL_CTL_DECL LIBC_EPOLL_CTL_RET_TYPE \
		LIBC_EPOLL_CTL_NAME(LIBC_EPOLL_CTL_SIG)
#endif

/* epoll_wait(2) */
#if (defined(__linux__))
extern TSOCKS_LIBC_DECL(epoll_wait, LIBC_EPOLL_WAIT_RET_TYPE, LIBC_EPOLL_WAIT_SIG)
TSOCKS_DECL(epoll_wait, LIBC_EPOLL_WAIT_RET_TYPE, LIBC_EPOLL_WAIT_SIG)
#define LIBC_EPOLL_WAIT_DECL LIBC_EPOLL_WAIT_RET_TYPE \
		LIBC_EPOLL_WAIT_NAME(LIBC_EPOLL_WAIT_SIG)

extern TSOCKS_LIBC_DECL(epoll_pwait, LIBC_EPOLL_PWAIT_RET_TYPE, LIBC_EPOLL_PWAIT_SIG)
TSOCKS_DECL(epoll_pwait, LIBC_EPOLL_PWAIT_RET_TYPE, LIBC_EPOLL_PWAIT_SIG)
#define LIBC_EPOLL_PWAIT_DECL LIBC_EPOLL_PWAIT_RET_TYPE \
		LIBC_EPOLL_PWAIT_NAME(LIBC_EPOLL_PWAIT_SIG)
#endif


/*
 * Those are actions to do during the lookup process of libc symbols. For
 * instance the connect(2) syscall is essential to Torsocks so the function
 * call exits if not found.
 */
enum tsocks_sym_action {
	TSOCKS_SYM_DO_NOTHING		= 0,
	TSOCKS_SYM_EXIT_NOT_FOUND	= 1,
};

/* Global configuration. Initialized once in the library constructor. */
extern struct configuration tsocks_config;

/* Global pool for .onion address. Initialized once in the constructor. */
extern struct onion_pool tsocks_onion_pool;

extern unsigned int tsocks_cleaned_up;

int tsocks_connect_to_tor(struct connection *conn);
void *tsocks_find_libc_symbol(const char *symbol,
		enum tsocks_sym_action action);
int tsocks_tor_resolve(int af, const char *hostname, void *ip_addr);
int tsocks_tor_resolve_ptr(const char *addr, char **ip, int af);
void tsocks_initialize(void);
void tsocks_cleanup(void);

#endif /* TORSOCKS_H */
