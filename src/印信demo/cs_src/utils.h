#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

//#define HAS_SYSLOG
#ifndef HAS_SYSLOG
#include <syslog.h>
#define LOG_ERR		3
#define LOG_WARNING	4

#define LOG_INFO	6
#define LOG_DEBUG	7

#endif

extern int use_syslog;
extern int use_tty;

#define TIME_FORMAT "%F %T"

#define USE_TTY()                        \
    do {                                 \
        use_tty = isatty(STDERR_FILENO); \
    } while (0)

#define USE_SYSLOG(_ident, _cond)                               \
    do {                                                        \
        if (!use_syslog && (_cond)) {                           \
            use_syslog = 1;                                     \
        }                                                       \
        if (use_syslog) {                                       \
            openlog((_ident), LOG_CONS | LOG_PID, LOG_DAEMON);  \
        }                                                       \
    } while (0)

#define LOG_I(format, ...)                                                        \
    do {                                                                         \
        if (use_syslog) {                                                        \
            syslog(LOG_INFO, format, ## __VA_ARGS__);                            \
        } else {                                                                 \
            time_t now = time(NULL);                                             \
            char timestr[20];                                                    \
            strftime(timestr, 20, TIME_FORMAT, localtime(&now));                 \
            if (use_tty) {                                                       \
                fprintf(stdout, "\e[01;32m %s INFO: \e[0m" format "\n", timestr, \
                        ## __VA_ARGS__);                                         \
                fflush(stdout);                                                  \
            } else {                                                             \
                fprintf(stdout, " %s INFO: " format "\n", timestr,               \
                        ## __VA_ARGS__);                                         \
                fflush(stdout);                                                  \
            }                                                                    \
        }                                                                        \
    }while (0)
//#define log_i(fmt, ...) LOG_I(fmt, __VA_ARGS__)
#define log_i(...) LOG_I(__VA_ARGS__)

#define LOG_E(format, ...)                                                         \
    do {                                                                          \
        if (use_syslog) {                                                         \
            syslog(LOG_ERR, format, ## __VA_ARGS__);                              \
        } else {                                                                  \
            time_t now = time(NULL);                                              \
            char timestr[20];                                                     \
            strftime(timestr, 20, TIME_FORMAT, localtime(&now));                  \
            if (use_tty) {                                                        \
                fprintf(stderr, "\e[01;35m %s ERROR: \e[0m" format "\n", timestr, \
                        ## __VA_ARGS__);                                          \
                fflush(stderr);                                                   \
            } else {                                                              \
                fprintf(stderr, " %s ERROR: " format "\n", timestr,               \
                        ## __VA_ARGS__);                                          \
                fflush(stderr);                                                   \
            }                                                                     \
        }                                                                         \
	} while (0)
//#define log_e(fmt, ...) LOG_E(fmt, __VA_ARGS__ )
#define log_e(...) LOG_E(__VA_ARGS__)

/** Notice: audit information
 */ 
//#define LOGD(...) xxx(LOG_NOTICE, __func__, __FILE__, __LINE__, __VA_ARGS__);
#define LOG_AUDIT(format, ...)                                                    \
    do {                                                                          \
        if (use_syslog) {                                                         \
            syslog(LOG_NOTICE, format, ## __VA_ARGS__);                           \
        } else {                                                                  \
            time_t now = time(NULL);                                              \
            char timestr[20];                                                     \
            strftime(timestr, 20, TIME_FORMAT, localtime(&now));                  \
            if (use_tty) {                                                        \
                fprintf(stderr, "\e[01;32m %s AUDIT: \e[0m" format "\n", timestr, \
                        ## __VA_ARGS__);                                          \
                fflush(stderr);                                                   \
            } else {                                                              \
                fprintf(stderr, " %s AUDIT: " format "\n", timestr,               \
                        ## __VA_ARGS__);                                          \
                fflush(stderr);                                                   \
            }                                                                     \
        }                                                                         \
	} while (0)
#define log_audit(fmt, ...) LOG_AUDIT(ftm, __VA_ARGS__)

/**
 */ 
#define LOG_D(format, ...)                                                        \
    do {                                                                         \
        if (use_syslog) {                                                        \
            syslog(LOG_DEBUG, format, ## __VA_ARGS__);                            \
        } else {                                                                 \
            time_t now = time(NULL);                                             \
            char timestr[20];                                                    \
            strftime(timestr, 20, TIME_FORMAT, localtime(&now));                 \
            fprintf(stdout, " %s DEBUG: " format "\n", timestr,               \
                        ## __VA_ARGS__);                                         \
            fflush(stdout);                                                  \
        }                                                                    \
    }while (0)
#define log_d(...) LOG_D(__VA_ARGS__)

/** blue */
#define LOGB(format, ...) \
	do {\
		fprintf(stdout, "\e[01;32m " format "\e[0m\n", ## __VA_ARGS__); \
		fflush(stdout); \
	} while(0)

/** yellow */
#define LOGY(format, ...) \
	do {\
		fprintf(stdout, "\e[01;35m " format "\e[0m\n", ## __VA_ARGS__); \
		fflush(stdout);\
	} while(0)

/** CCM: Comprehensive Cipher module 
 *  Error code table 
 */
/** linux system errno: 保持和linux操作系统的错误码名字一致 
 */
#if 0
#define EPERM        1  /* Operation not permitted */
#define ENOENT       2  /* No such file or directory */
#define ESRCH        3  /* No such process */
#define EINTR        4  /* Interrupted system call */
#define EIO      5  /* I/O error */
#define ENXIO        6  /* No such device or address */
#define E2BIG        7  /* Argument list too long */
#define ENOEXEC      8  /* Exec format error */
#define EBADF        9  /* Bad file number */
#define ECHILD      10  /* No child processes */
#define EAGAIN      11  /* Try again */
#define ENOMEM      12  /* Out of memory */
#define EACCES      13  /* Permission denied */
#define EFAULT      14  /* Bad address */
#define ENOTBLK     15  /* Block device required */
#define EBUSY       16  /* Device or resource busy */
#define EEXIST      17  /* File exists */
#define EXDEV       18  /* Cross-device link */
#define ENODEV      19  /* No such device */
#define ENOTDIR     20  /* Not a directory */
#define EISDIR      21  /* Is a directory */
#define EINVAL      22  /* Invalid argument */
#define ENFILE      23  /* File table overflow */
#define EMFILE      24  /* Too many open files */
#define ENOTTY      25  /* Not a typewriter */
#define ETXTBSY     26  /* Text file busy */
#define EFBIG       27  /* File too large */
#define ENOSPC      28  /* No space left on device */
#define ESPIPE      29  /* Illegal seek */
#define EROFS       30  /* Read-only file system */
#define EMLINK      31  /* Too many links */
#define EPIPE       32  /* Broken pipe */
#define EDOM        33  /* Math argument out of domain of func */
#define ERANGE      34  /* Math result not representable */
#endif

#define CCM_OK		 0
#define CCM_ERR		-1
#define CCM_EACCES	-2	/* */
#define CCM_EINVAL	-3	/* Parameter error */
#define CCM_EFAULT	-4	/* Bad address, Null pointer */
#define CCM_ELEN	-5	/* Data length error */
#define CCM_ECONF	-6	/* Invalid configure item */
#define	CCM_ERANDOM -7	/* Random number */
#define CCM_EMEM	-8	/* Null pointer, malloc etc.*/
#define CCM_RETRY	-10

#define INT_DIGITS 19           /* enough for 64 bit integer */

//#define MIN(a, b)	((a)<=(b) ? (a) : (b))

#define P_LIKELY(expr)		__builtin_expect((expr), 1)
#define P_UNLIKELY(expr)	__builtin_expect((expr), 0)

/* byte-order */
#define SWAP_UINT16(__u16) \
    (((((uint16_t) __u16) & 0xff00u) >> 8) | \
     ((((uint16_t) __u16) & 0x00ffu) << 8))

#define SWAP_UINT32(__u32) \
    (((((uint32_t) __u32) & 0xff000000u) >> 24) | \
     ((((uint32_t) __u32) & 0x00ff0000u) >>  8) | \
     ((((uint32_t) __u32) & 0x0000ff00u) <<  8) | \
     ((((uint32_t) __u32) & 0x000000ffu) << 24))

#define SWAP_UINT64(__u64) \
    (((((uint64_t) __u64) & UINT64_C(0xff00000000000000)) >> 56) | \
     ((((uint64_t) __u64) & UINT64_C(0x00ff000000000000)) >> 40) | \
     ((((uint64_t) __u64) & UINT64_C(0x0000ff0000000000)) >> 24) | \
     ((((uint64_t) __u64) & UINT64_C(0x000000ff00000000)) >>  8) | \
     ((((uint64_t) __u64) & UINT64_C(0x00000000ff000000)) <<  8) | \
     ((((uint64_t) __u64) & UINT64_C(0x0000000000ff0000)) << 24) | \
     ((((uint64_t) __u64) & UINT64_C(0x000000000000ff00)) << 40) | \
     ((((uint64_t) __u64) & UINT64_C(0x00000000000000ff)) << 56))

/** uintptr_t in <stdint.h>
 */ 
#define _ALIGN(addr, align) ((void *)(((uintptr_t)(addr)+(align) - 1) & \
														~(uintptr_t)((align)-1)))
/**
 */ 
#define IPV4_STR_LEN (sizeof "xxx.xxx.xxx.xxx")
#define IPV6_STR_LEN (sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
#define IP_STR_LEN  IPV6_STR_LEN

#define HOSTNAME_MAXLEN	256 /* FQCN <= 255 characters*/
#define PORT_STR_MAXLEN 6   /* PORT < 65536 */
#define SOCKET_BUF_SIZE (16 * 1024 - 1) // 16383 Byte, equals to the max chunk size

void hex_dump(const char *prompt, unsigned char *data, int len);
void hexdiff_dump(const char* prompt, unsigned char* data, int len, 
									   unsigned char* data2);
void hexstr_dump(const char* name, unsigned char* buff, int len);
void ascii_dump(const char* name, char* str, int len);

void bin2hex(unsigned char* bin, int blen, char* hex);
void hex2bin(const char* hex, int hlen, unsigned char* bin);

void reverse_array(unsigned char* array, int num);

//void usage(void);
void daemonize(const char *path);
int set_nofile(int nofile);

char *conf_get_default(void);
int get_mptcp(int enable);

/** Soft integrity validate.
 */ 
int sm3_hash_file(const char* pname, unsigned char* digest); /** Program name */

bool integrity_check(const char *cfname);	/* Configure file name */

/**
 */ 
void fatal(const char *fmt, ...);
uint32_t random_uint32(void);

uint64_t g_time_ms(void);

size_t g_strlcpy(char *dst, const char *src, const size_t len);
int g_snprintf(char *str, size_t size, int *len, const char *fmt, ...);
long long g_strtonum(const char *str, int base, long long min, long long max, int *err);
uint64_t g_strtonum64(const char *str, int sign, int *err);
double g_strtodouble(const char *str, long double min, long double max, int *err);
int g_split_string(char *input, const char *delim, char **out, size_t ele);

#endif // _UTILS_H
