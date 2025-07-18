#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>

#include <limits.h>	// LONG_MAX
#include <ctype.h>	// isdigit()
#include <errno.h>
#include <stdarg.h>

#include "utils.h"

#if defined(HAS_SYSLOG)
int use_syslog = 1;
int use_ttyp = 0;
#else
int use_syslog = 0;
int use_tty = 1;
#endif

static void __print_line(unsigned char* buff, int offset, int llen) {

	int i;

    printf("%08X |", offset);

    for (i = 0; i < llen; i++) {	// line length
        if (i > 0 && i % 4 == 0) {
            printf(" ");
        }
        printf(" %02X", buff[i]);	// hexadecimal
    }

    printf(" | ");

    for ( i = 0; i < llen; i++) {
        if (buff[i] > 31 && buff[i] < 127) {
            printf("%c", buff[i]);	// ASCii
        } else {
            printf(".");
        }
    }

    printf("\n");
}

static void __print_diff_line(unsigned char* buff, unsigned char* buff2, 
												int offset, int llen) {
	int i;

    printf("%08X |", offset);

    for (i = 0; i < llen; i++) {	// line length
        if (i > 0 && i % 4 == 0) {
            printf(" ");
        }
		if ( buff[i] != buff2[i])
			printf(" \e[01;32m%02X\e[0m", buff[i]);	// hexadecimal
		else
			printf(" %02X", buff[i]);	
    }
    printf("\n");
}

/* */
void hex_dump(const char *prompt, unsigned char *data, int len) {

#define LINE_LEN	16
	int i, lines, rd;
	int off;

	if (prompt != NULL)
		printf("[%s] [length = %d]\n", prompt, len);
	
	lines = len / LINE_LEN;
	rd	  = len % LINE_LEN;
	for (i = 0; i < lines; i++) {		// whole lines
		off = i * LINE_LEN;
		__print_line(data + off, off, LINE_LEN);
	}
	if (rd) {							// remainder
		off = i * LINE_LEN;
		__print_line(data + off, off, rd);
	}
	fflush(stdout);

#undef LINE_LEN
}


void hexdiff_dump(const char* prompt, unsigned char* data,  int len,
									   unsigned char* data2){

#define LINE_LEN	20	
	int i, lines, rd;
	int off;

	if (prompt != NULL)
		printf("[%s] [length = %d]\n", prompt, len);
	
	lines = len / LINE_LEN;
	rd	  = len % LINE_LEN;
	for (i = 0; i < lines; i++) {		// whole lines
		off = i * LINE_LEN;
		__print_diff_line(data + off, data2 + off, off, LINE_LEN);
	}
	if (rd) {							// remainder
		off = i * LINE_LEN;
		__print_diff_line(data + off, data2 + off, off, rd);
	}
	fflush(stdout);

#undef LINE_LEN
}

void hexstr_dump(const char* name, unsigned char* buff, int len) {
	
	if (len == 0) {
		printf("%s:%d[ ]\n", name, len);
		return;
	}
	
	printf("%s:%d[", name, len);
	int i;
	for (i = 0; i < len - 1; i++) {
		if (i !=0 && !(i % 16))
			printf("\n0x%02X,", buff[i]);
		else 
			printf("0x%02X,", buff[i]);
	}

	printf("0x%02X]\n", buff[i]);
}

void ascii_dump(const char* name, char* str, int len) {
	
	if (len == 0) {
		printf("%s:%d[ ]\n", name, len);
		return;
	}

	printf("%s:%d[", name, len);
	int i;
	for (i = 0; i < len-1; i++) {
		if ( str[i] < 32 || str[i] > 126) 
			printf("-");
		else
			printf("%c", str[i]);
	}
	
	if ( str[i] < 32 || str[i] > 126) 
		printf("-]\n");
	else
		printf("%c]\n", str[i]);
}

void bin2hex(unsigned char* bin, int blen, char* hex) {

	static char table[] = {'0','1','2','3','4','5','6','7',
						   '8','9','A','B','C','D','E','F'};
	//int len = blen;
	if (bin == NULL || hex == NULL) {
		LOG_E("bin2hex, parameter is null pointer\n");	
		return;
	}
    while (blen--) {
        *( hex + 2*blen + 1 ) = table[(*(bin + blen) ) & 0x0F];
        *( hex + 2*blen)      = table[(*(bin + blen) ) >> 4];
    }
}

void hex2bin(const char* hex, int hlen, unsigned char* bin) {

	char *p1, *p2;

	if (hex == NULL || bin == NULL || hlen % 2) {
		LOG_E("bin2hex, parameter is null pointer\n");	
		return;
	}

	while (hlen--) {
        p2 = (char* )(hex + hlen);
        p1 = p2 + 1;
        *(bin + hlen / 2) = ( (*p1 > '9' ? *p1 + 9 : *p1) & 0x0f ) | 
							( (*p2 > '9' ? *p2 + 9 : *p2) << 4 ); 
    }
}

void reverse_array(unsigned char* array, int num) {

    int half = num / 2;
    unsigned char tmp;

    for (int j = 0; j < half; j++) {
		tmp = array[j];
		array[j] = array[num - 1 - j];  
		array[num - 1 - j] = tmp;
	} 
}


void
daemonize(const char *path) {

    pid_t pid, sid;		/* Our process ID and Session ID */

    pid = fork();		
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then we can exit the parent process. */
    if (pid > 0) {
        FILE *pidfile = fopen(path, "w");
        if (pidfile == NULL) {
           fprintf(stderr, "Invalid pid file\n");
		   exit(EXIT_FAILURE);
        }

        fprintf(pidfile, "%d", (int)pid);
        fclose(pidfile);
        exit(EXIT_SUCCESS);
    }
    umask(0);		/* Change the file mode mask */
    				/* Open any logs here */
    sid = setsid();			/* Create a new SID for the child process */

    if (sid < 0) {
        exit(EXIT_FAILURE); /* Log the failure */
    }

    if ((chdir("/")) < 0) { /* Change the current working directory */
        exit(EXIT_FAILURE);
    }

    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null > 0) {
        dup2(dev_null, STDOUT_FILENO);	/* Redirect to null device  */
        dup2(dev_null, STDERR_FILENO);
    } else {
        close(STDOUT_FILENO);			/* Close STDOUT, STDERR */
        close(STDERR_FILENO);
    }
    close(STDIN_FILENO);				/* Close STDIN */
}

/** 
 * Number of file process can open 
 */
int set_nofile(int nofile) {	

	/* set both soft and hard limit */
    struct rlimit limit = {(rlim_t)nofile, (rlim_t)nofile }; 

    if (nofile <= 0) {
        LOG_E("nofile must be greater than 0\n");
		return -1;
    }

    if (setrlimit(RLIMIT_NOFILE, &limit) < 0) {
        if (errno == EPERM) {
            LOG_E("insufficient permission to change NOFILE?");
            return -1;
        } else if (errno == EINVAL) {
            LOG_E("invalid nofile, decrease nofile and try again");
            return -1;
        } else {
            LOG_E("setrlimit failed: %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}

char* conf_get_default(void) {

    static char sysconf[] = "/etc/ccm/config.json";
    static char *userconf = NULL;
    static int buf_size   = 0;
    char *conf_home;

    conf_home = getenv("XDG_CONFIG_HOME");

    /* Memory of userconf only gets allocated once, and will not be
	 * freed. It is used as static buffer.
	 */ 
    if (!conf_home) {
        if (buf_size == 0) {
            buf_size = 50 + strlen(getenv("HOME"));
            userconf = (char *)malloc(buf_size);
        }
        snprintf(userconf, buf_size, "%s%s", getenv("HOME"),
                 							"/.config/ccm/config.json");
    } else {
        if (buf_size == 0) {
            buf_size = 50 + strlen(conf_home);
            userconf = (char *)malloc(buf_size);
        }
        snprintf(userconf, buf_size, "%s%s", conf_home, "/ccm/config.json");
    }

    // Check if the user-specific config exists.
    if (access(userconf, F_OK) != -1)
        return userconf;

    // If not, fall back to the system-wide config.
    free(userconf);
    return sysconf;
}

int get_mptcp(int enable) {

    const char oldpath[] = "/proc/sys/net/mptcp/mptcp_enabled";

    if (enable) {
        if (access(oldpath, F_OK) != -1) // if kernel has out-of-tree MPTCP support.
            return 1;
        return -1;						 // Otherwise, just use IPPROTO_MPTCP.
    }
    return 0;
}

#include <sys/random.h>
u_int32_t random_uint32(void)
{
	ssize_t		ret;
	u_int32_t	val;

	if ((ret = getrandom(&val, sizeof(val), 0)) == -1){
		log_e("getrandom(): %s", strerror(errno));
		return -1;
	}

	if ((size_t)ret != sizeof(val)) {
		log_e("getrandom() %zd != %zu", ret, sizeof(val));
		return -1;
	}
	return (val);
}

#if 1
static void __log(const char *fmt, va_list args)
{
	char buf[2048];

	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	log_e("fatal: %s", buf);

	//if (ccm_worker != NULL && worker->id == WORKER_KEYMGR)
		//ccm_keymgr_cleanup(1);
}

void fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	__log(fmt, args);
	va_end(args);

	exit(1);
}

u_int64_t g_time_ms(void)
{
	struct timespec	ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	return ((u_int64_t)(ts.tv_sec * 1000 + (ts.tv_nsec / 1000000)));
}

size_t g_strlcpy(char *dst, const char *src, const size_t len)
{
	char		*d = dst;
	const char	*s = src;
	const char	*end = dst + len - 1;

	if (len == 0)
		fatal("kore_strlcpy: len == 0");

	while ((*d = *s) != '\0') {
		if (d == end) {
			*d = '\0';
			break;
		}

		d++;
		s++;
	}

	while (*s != '\0')
		s++;

	return (s - src);
}

int g_snprintf(char *str, size_t size, int *len, const char *fmt, ...)
{
	int		l;
	va_list	args;

	va_start(args, fmt);
	l = vsnprintf(str, size, fmt, args);
	va_end(args);

	if (l == -1 || (size_t)l >= size)
		return (CCM_ERR);

	if (len != NULL)
		*len = l;

	return (CCM_OK);
}

long long g_strtonum(const char *str, int base, long long min, long long max, int *err)
{
	long long	l;
	char		*ep;

	if (min > max) {
		*err = CCM_ERR;
		return (0);
	}

	errno = 0;
	l = strtoll(str, &ep, base);
	if (errno != 0 || str == ep || *ep != '\0') {
		*err = CCM_ERR;
		return (0);
	}

	if (l < min) {
		*err = CCM_ERR;
		return (0);
	}

	if (l > max) {
		*err = CCM_ERR;
		return (0);
	}

	*err = CCM_OK;
	return (l);
}

u_int64_t g_strtonum64(const char *str, int sign, int *err)
{
	u_int64_t	l;
	long long	ll;
	char		*ep;
	int		check;

	l = 0;
	check = 1;

	ll = strtoll(str, &ep, 10);
	if ((errno == EINVAL || errno == ERANGE) &&
	    (ll == LLONG_MIN || ll == LLONG_MAX)) {
		if (sign) {
			*err = CCM_ERR;
			return (0);
		}

		check = 0;
	}

	if (!sign) {
		l = strtoull(str, &ep, 10);
		if ((errno == EINVAL || errno == ERANGE) && l == ULONG_MAX) {
			*err = CCM_ERR;
			return (0);
		}

		if (check && ll < 0) {
			*err = CCM_ERR;
			return (0);
		}
	}

	if (str == ep || *ep != '\0') {
		*err = CCM_ERR;
		return (0);
	}

	*err = CCM_OK;
	return ((sign) ? (u_int64_t)ll : l);
}

double g_strtodouble(const char *str, long double min, long double max, int *err)
{
	double		d;
	char		*ep;

	if (min > max) {
		*err = CCM_ERR;
		return (0);
	}

	errno = 0;
	d = strtod(str, &ep);
	if (errno == ERANGE || str == ep || *ep != '\0') {
		*err = CCM_ERR;
		return (0);
	}

	if (d < min) {
		*err = CCM_ERR;
		return (0);
	}

	if (d > max) {
		*err = CCM_ERR;
		return (0);
	}

	*err = CCM_OK;
	return (d);
}

int g_split_string(char *input, const char *delim, char **out, size_t ele)
{
	int		count;
	char**	ap;

	if (ele == 0)
		return (0);

	count = 0;
	for (ap = out; ap < &out[ele - 1] &&
	    (*ap = strsep(&input, delim)) != NULL;) {
		if (**ap != '\0') {
			ap++;
			count++;
		}
	}

	*ap = NULL;
	return (count);
}
#endif
