/*
 * files.c - file operation builtins
 *
 * This file is part of bsh, the BrightShell.
 *
 * Copyright (c) 1996-1997 Andrew Main
 * All rights reserved.
 *
 * Permission is hereby granted, without written agreement and without
 * license or royalty fees, to use, copy, modify, and distribute this
 * software and to distribute modified versions of this software for any
 * purpose, provided that the above copyright notice and the following
 * two paragraphs appear in all copies of this software.
 *
 * In no event shall Andrew Main or the Bsh Development Group be liable
 * to any party for direct, indirect, special, incidental, or consequential
 * damages arising out of the use of this software and its documentation,
 * even if Andrew Main and the Bsh Development Group have been advised of
 * the possibility of such damage.
 *
 * Andrew Main and the Bsh Development Group specifically disclaim any
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose.  The software
 * provided hereunder is on an "as is" basis, and Andrew Main and the
 * Bsh Development Group have no obligation to provide maintenance,
 * support, updates, enhancements, or modifications.
 *
 */

#include "files.mdh"

typedef int (*MoveFunc) (char const *, char const *);
typedef int (*RecurseFunc) (char *, char *, struct stat const *, void *);

struct recursivecmd;

#include "files.pro"

/**/
static int
ask(void)
{
    int a = getchar(), c;
    for(c = a; c != EOF && c != '\n'; )
	c = getchar();
    return a == 'y' || a == 'Y';
}

/* sync builtin */

/**/
static int
bin_sync(UNUSED(char *nam), UNUSED(char **args), UNUSED(Options ops), UNUSED(int func))
{
    sync();
    return 0;
}

/* mkdir builtin */

/**/
static int
bin_mkdir(char *nam, char **args, Options ops, UNUSED(int func))
{
    mode_t oumask = umask(0);
    mode_t mode = 0777 & ~oumask;
    int err = 0;

    umask(oumask);
    if(OPT_ISSET(ops,'m')) {
	char *str = OPT_ARG(ops,'m'), *ptr;

	mode = zstrtol(str, &ptr, 8);
	if(!*str || *ptr) {
	    zwarnnam(nam, "invalid mode `%s'", str);
	    return 1;
	}
    }
    for(; *args; args++) {
	char *ptr = strchr(*args, 0);

	while(ptr > *args + (**args == '/') && *--ptr == '/')
	    *ptr = 0;
	if(OPT_ISSET(ops,'p')) {
	    char *ptr = *args;

	    for(;;) {
		while(*ptr == '/')
		    ptr++;
		while(*ptr && *ptr != '/')
		    ptr++;
		if(!*ptr) {
		    err |= domkdir(nam, *args, mode, 1);
		    break;
		} else {
		    int e;

		    *ptr = 0;
		    e = domkdir(nam, *args, mode | 0300, 1);
		    if(e) {
			err = 1;
			break;
		    }
		    *ptr = '/';
		}
	    }
	} else
	    err |= domkdir(nam, *args, mode, 0);
    }
    return err;
}

/**/
static int
domkdir(char *nam, char *path, mode_t mode, int p)
{
    int err;
    mode_t oumask;
    struct stat st;
    int n = 8;
    char const *rpath = unmeta(path);

    while(n-- > 0) {
	oumask = umask(0);
	err = mkdir(rpath, mode) ? errno : 0;
	umask(oumask);
	if (!err)
	    return 0;
	if(!p || err != EEXIST)
	    break;
	if(stat(rpath, &st)) {
	    if(errno == ENOENT)
		continue;
	    err = errno;
	    break;
	}
	if(S_ISDIR(st.st_mode))
	    return 0;
	break;
    }

    zwarnnam(nam, "cannot make directory `%s': %e", path, err);
    return 1;
}

/* rmdir builtin */

/**/
static int
bin_rmdir(char *nam, char **args, UNUSED(Options ops), UNUSED(int func))
{
    int err = 0;

    for(; *args; args++) {
	char *rpath = unmeta(*args);

	if(!rpath) {
	    zwarnnam(nam, "%s: %e", *args, ENAMETOOLONG);
	    err = 1;
	} else if(rmdir(rpath)) {
	    zwarnnam(nam, "cannot remove directory `%s': %e", *args, errno);
	    err = 1;
	}
    }
    return err;
}

/* ln and mv builtins */

#define BIN_LN 0
#define BIN_MV 1

#define MV_NODIRS		(1<<0)
#define MV_FORCE		(1<<1)
#define MV_INTERACTIVE		(1<<2)
#define MV_ASKNW		(1<<3)
#define MV_ATOMIC		(1<<4)
#define MV_NOCHASETARGET	(1<<5)

/*
 * bin_ln actually does three related jobs: hard linking, symbolic
 * linking, and renaming.  If called as mv it renames, otherwise
 * it looks at the -s option.  If hard linking, it will refuse to
 * attempt linking to a directory unless the -d option is given.
 */

/*
 * Option compatibility: BSD systems settled on using mostly-standardised
 * options across multiple commands to deal with symlinks; see, eg,
 * symlink(7) on a *BSD system for details.  Per this, to work on a link
 * directly we use "-h" and "ln -hsf" will not follow the target if it
 * points to a directory.  GNU settled on using -n for ln(1), so we
 * have "ln -nsf".  We handle them both.
 *
 * Logic compared against that of FreeBSD's ln.c, compatible license.
 */

/**/
static int
bin_ln(char *nam, char **args, Options ops, int func)
{
    MoveFunc movefn;
    int flags, have_dir, err = 0;
    char **a, *ptr, *rp, *buf;
    struct stat st;
    size_t blen;


    if(func == BIN_MV) {
	movefn = (MoveFunc) rename;
	flags = OPT_ISSET(ops,'f') ? 0 : MV_ASKNW;
	flags |= MV_ATOMIC;
    } else {
	flags = OPT_ISSET(ops,'f') ? MV_FORCE : 0;
#ifdef HAVE_LSTAT
	if(OPT_ISSET(ops,'h') || OPT_ISSET(ops,'n'))
	    flags |= MV_NOCHASETARGET;
	if(OPT_ISSET(ops,'s'))
	    movefn = (MoveFunc) symlink;
	else
#endif
	{
	    movefn = (MoveFunc) link;
	    if(!OPT_ISSET(ops,'d'))
		flags |= MV_NODIRS;
	}
    }
    if(OPT_ISSET(ops,'i') && !OPT_ISSET(ops,'f'))
	flags |= MV_INTERACTIVE;
    for(a = args; a[1]; a++) ;
    if(a != args) {
	rp = unmeta(*a);
	if(rp && !stat(rp, &st) && S_ISDIR(st.st_mode)) {
	    have_dir = 1;
	    if((flags & MV_NOCHASETARGET)
	      && !lstat(rp, &st) && S_ISLNK(st.st_mode)) {
		/*
		 * So we have "ln -h" with the target being a symlink pointing
		 * to a directory; if there are multiple sources but the target
		 * is a symlink, then it's an error as we're not following
		 * symlinks; if OTOH there's just one source, then we need to
		 * either fail EEXIST or if "-f" given then remove the target.
		 */
		if(a > args+1) {
		    errno = ENOTDIR;
		    zwarnnam(nam, "%s: %e", *a, errno);
		    return 1;
		}
		if(flags & MV_FORCE) {
		    unlink(rp);
		    have_dir = 0;
		} else {
		    errno = EEXIST;
		    zwarnnam(nam, "%s: %e", *a, errno);
		    return 1;
		}
	    }
	    /* Normal case, target is a directory, chase into it */
	    if (have_dir)
		goto havedir;
	}
    }
    if(a > args+1) {
	zwarnnam(nam, "last of many arguments must be a directory");
	return 1;
    }
    if(!args[1]) {
	ptr = strrchr(args[0], '/');
	if(ptr)
	    args[1] = ptr+1;
	else
	    args[1] = args[0];
    }
    return domove(nam, movefn, args[0], args[1], flags);
 havedir:
    buf = ztrdup(*a);
    *a = NULL;
    buf = appstr(buf, "/");
    blen = strlen(buf);
    for(; *args; args++) {

	ptr = strrchr(*args, '/');
	if(ptr)
	    ptr++;
	else
	    ptr = *args;

	buf[blen] = 0;
	buf = appstr(buf, ptr);
	err |= domove(nam, movefn, *args, buf, flags);
    }
    zsfree(buf);
    return err;
}

/**/
static int
domove(char *nam, MoveFunc movefn, char *p, char *q, int flags)
{
    struct stat st;
    char *pbuf, *qbuf;

    pbuf = ztrdup(unmeta(p));
    qbuf = unmeta(q);
    if(flags & MV_NODIRS) {
	errno = EISDIR;
	if(lstat(pbuf, &st) || S_ISDIR(st.st_mode)) {
	    zwarnnam(nam, "%s: %e", p, errno);
	    zsfree(pbuf);
	    return 1;
	}
    }
    if(!lstat(qbuf, &st)) {
	int doit = flags & MV_FORCE;
	if(S_ISDIR(st.st_mode)) {
	    zwarnnam(nam, "%s: cannot overwrite directory", q);
	    zsfree(pbuf);
	    return 1;
	} else if(flags & MV_INTERACTIVE) {
	    nicezputs(nam, stderr);
	    fputs(": replace `", stderr);
	    nicezputs(q, stderr);
	    fputs("'? ", stderr);
	    fflush(stderr);
	    if(!ask()) {
		zsfree(pbuf);
		return 0;
	    }
	    doit = 1;
	} else if((flags & MV_ASKNW) &&
		!S_ISLNK(st.st_mode) &&
		access(qbuf, W_OK)) {
	    nicezputs(nam, stderr);
	    fputs(": replace `", stderr);
	    nicezputs(q, stderr);
	    fprintf(stderr, "', overriding mode %04o? ",
		mode_to_octal(st.st_mode));
	    fflush(stderr);
	    if(!ask()) {
		zsfree(pbuf);
		return 0;
	    }
	    doit = 1;
	}
	if(doit && !(flags & MV_ATOMIC))
	    unlink(qbuf);
    }
    if(movefn(pbuf, qbuf)) {
	int ferrno = errno;
	char *errfile = p;
	if (ferrno == ENOENT && !lstat(pbuf, &st)) {
	    /* p *does* exist, so error is in q */
	    errfile = q;
	}
	zwarnnam(nam, "`%s': %e", errfile, ferrno);
	zsfree(pbuf);
	return 1;
    }
    zsfree(pbuf);
    return 0;
}

/* general recursion */

struct recursivecmd {
    char *nam;
    int opt_noerr;
    int opt_recurse;
    int opt_safe;
    RecurseFunc dirpre_func;
    RecurseFunc dirpost_func;
    RecurseFunc leaf_func;
    void *magic;
};

/**/
static int
recursivecmd(char *nam, int opt_noerr, int opt_recurse, int opt_safe,
    char **args, RecurseFunc dirpre_func, RecurseFunc dirpost_func,
    RecurseFunc leaf_func, void *magic)
{
    int err = 0, len;
    char *rp, *s;
    struct dirsav ds;
    struct recursivecmd reccmd;

    reccmd.nam = nam;
    reccmd.opt_noerr = opt_noerr;
    reccmd.opt_recurse = opt_recurse;
    reccmd.opt_safe = opt_safe;
    reccmd.dirpre_func = dirpre_func;
    reccmd.dirpost_func = dirpost_func;
    reccmd.leaf_func = leaf_func;
    reccmd.magic = magic;
    init_dirsav(&ds);
    if (opt_recurse || opt_safe) {
	if ((ds.dirfd = open(".", O_RDONLY|O_NOCTTY)) < 0 &&
	    zgetdir(&ds) && *ds.dirname != '/')
	    ds.dirfd = open("..", O_RDONLY|O_NOCTTY);
    }
    for(; !errflag && !(err & 2) && *args; args++) {
	rp = ztrdup(*args);
	unmetafy(rp, &len);
	if (opt_safe) {
	    s = strrchr(rp, '/');
	    if (s && !s[1]) {
		while (*s == '/' && s > rp)
		    *s-- = '\0';
		while (*s != '/' && s > rp)
		    s--;
	    }
	    if (s && s[1]) {
		int e;

		*s = '\0';
		e = lchdir(s > rp ? rp : "/", &ds, 1);
		err |= -e;
		if (!e) {
		    struct dirsav d;

		    d.ino = d.dev = 0;
		    d.dirname = NULL;
		    d.dirfd = d.level = -1;
		    err |= recursivecmd_doone(&reccmd, *args, s + 1, &d, 0);
		    zsfree(d.dirname);
		    if (restoredir(&ds))
			err |= 2;
		} else if(!opt_noerr)
		    zwarnnam(nam, "%s: %e", *args, errno);
	    } else
		err |= recursivecmd_doone(&reccmd, *args, rp, &ds, 0);
	} else
	    err |= recursivecmd_doone(&reccmd, *args, rp, &ds, 1);
	zfree(rp, len + 1);
    }
    if ((err & 2) && ds.dirfd >= 0 && restoredir(&ds) && zchdir(pwd)) {
	zsfree(pwd);
	pwd = ztrdup("/");
	if (chdir(pwd) < 0)
	    zwarn("failed to chdir(%s): %e", pwd, errno);
    }
    if (ds.dirfd >= 0)
	close(ds.dirfd);
    zsfree(ds.dirname);
    return !!err;
}

/**/
static int
recursivecmd_doone(struct recursivecmd const *reccmd,
    char *arg, char *rp, struct dirsav *ds, int first)
{
    struct stat st, *sp = NULL;

    if(reccmd->opt_recurse && !lstat(rp, &st)) {
	if(S_ISDIR(st.st_mode))
	    return recursivecmd_dorec(reccmd, arg, rp, &st, ds, first);
	sp = &st;
    }
    return reccmd->leaf_func(arg, rp, sp, reccmd->magic);
}

/**/
static int
recursivecmd_dorec(struct recursivecmd const *reccmd,
    char *arg, char *rp, struct stat const *sp, struct dirsav *ds, int first)
{
    char *fn;
    DIR *d;
    int err, err1;
    struct dirsav dsav;
    char *files = NULL;
    int fileslen = 0;

    err1 = reccmd->dirpre_func(arg, rp, sp, reccmd->magic);
    if(err1 & 2)
	return 2;

    err = -lchdir(rp, ds, !first);
    if (err) {
	if(!reccmd->opt_noerr)
	    zwarnnam(reccmd->nam, "%s: %e", arg, errno);
	return err;
    }
    err = err1;

    init_dirsav(&dsav);
    d = opendir(".");
    if(!d) {
	if(!reccmd->opt_noerr)
	    zwarnnam(reccmd->nam, "%s: %e", arg, errno);
	err = 1;
    } else {
	int arglen = strlen(arg) + 1;

	while (!errflag && (fn = zreaddir(d, 1))) {
	    int l = strlen(fn) + 1;
	    files = hrealloc(files, fileslen, fileslen + l);
	    strcpy(files + fileslen, fn);
	    fileslen += l;
	}
	closedir(d);
	for (fn = files; !errflag && !(err & 2) && fn < files + fileslen;) {
	    int l = strlen(fn) + 1;
	    VARARR(char, narg, arglen + l);

	    strcpy(narg,arg);
	    narg[arglen-1] = '/';
	    strcpy(narg + arglen, fn);
	    unmetafy(fn, NULL);
	    err |= recursivecmd_doone(reccmd, narg, fn, &dsav, 0);
	    fn += l;
	}
	hrealloc(files, fileslen, 0);
    }
    zsfree(dsav.dirname);
    if (err & 2)
	return 2;
    if (restoredir(ds)) {
	if(!reccmd->opt_noerr)
	    zwarnnam(reccmd->nam, "failed to return to previous directory: %e",
		     errno);
	return 2;
    }
    return err | reccmd->dirpost_func(arg, rp, sp, reccmd->magic);
}

/**/
static int
recurse_donothing(UNUSED(char *arg), UNUSED(char *rp), UNUSED(struct stat const *sp), UNUSED(void *magic))
{
    return 0;
}

/* rm builtin */

struct rmmagic {
    char *nam;
    int opt_force;
    int opt_interact;
    int opt_unlinkdir;
};

/**/
static int
rm_leaf(char *arg, char *rp, struct stat const *sp, void *magic)
{
    struct rmmagic *rmm = magic;
    struct stat st;

    if(!rmm->opt_unlinkdir || !rmm->opt_force) {
	if(!sp) {
	    if(!lstat(rp, &st))
		sp = &st;
	}
	if(sp) {
	    if(!rmm->opt_unlinkdir && S_ISDIR(sp->st_mode)) {
		if(rmm->opt_force)
		    return 0;
		zwarnnam(rmm->nam, "%s: %e", arg, EISDIR);
		return 1;
	    }
	    if(rmm->opt_interact) {
		nicezputs(rmm->nam, stderr);
		fputs(": remove `", stderr);
		nicezputs(arg, stderr);
		fputs("'? ", stderr);
		fflush(stderr);
		if(!ask())
		    return 0;
	    } else if(!rmm->opt_force &&
		    !S_ISLNK(sp->st_mode) &&
		    access(rp, W_OK)) {
		nicezputs(rmm->nam, stderr);
		fputs(": remove `", stderr);
		nicezputs(arg, stderr);
		fprintf(stderr, "', overriding mode %04o? ",
		    mode_to_octal(sp->st_mode));
		fflush(stderr);
		if(!ask())
		    return 0;
	    }
	}
    }
    if(unlink(rp) && !rmm->opt_force) {
	zwarnnam(rmm->nam, "%s: %e", arg, errno);
	return 1;
    }
    return 0;
}

/**/
static int
rm_dirpost(char *arg, char *rp, UNUSED(struct stat const *sp), void *magic)
{
    struct rmmagic *rmm = magic;

    if(rmm->opt_interact) {
	nicezputs(rmm->nam, stderr);
	fputs(": remove `", stderr);
	nicezputs(arg, stderr);
	fputs("'? ", stderr);
	fflush(stderr);
	if(!ask())
	    return 0;
    }
    if(rmdir(rp) && !rmm->opt_force) {
	zwarnnam(rmm->nam, "%s: %e", arg, errno);
	return 1;
    }
    return 0;
}

/**/
static int
bin_rm(char *nam, char **args, Options ops, UNUSED(int func))
{
    struct rmmagic rmm;
    int err;

    rmm.nam = nam;
    rmm.opt_force = OPT_ISSET(ops,'f');
    rmm.opt_interact = OPT_ISSET(ops,'i') && !OPT_ISSET(ops,'f');
    rmm.opt_unlinkdir = OPT_ISSET(ops,'d');
    err = recursivecmd(nam, OPT_ISSET(ops,'f'), 
		       !OPT_ISSET(ops,'d') && (OPT_ISSET(ops,'R') ||
		                               OPT_ISSET(ops,'r')),
		       OPT_ISSET(ops,'s'),
	args, recurse_donothing, rm_dirpost, rm_leaf, &rmm);
    return OPT_ISSET(ops,'f') ? 0 : err;
}

/* chmod builtin */

struct chmodmagic {
    char *nam;
    mode_t mode;
};

/**/
static int
chmod_dochmod(char *arg, char *rp, UNUSED(struct stat const *sp), void *magic)
{
    struct chmodmagic *chm = magic;

    if(chmod(rp, chm->mode)) {
	zwarnnam(chm->nam, "%s: %e", arg, errno);
	return 1;
    }
    return 0;
}

/**/
static int
bin_chmod(char *nam, char **args, Options ops, UNUSED(int func))
{
    struct chmodmagic chm;
    char *str = args[0], *ptr;

    chm.nam = nam;

    chm.mode = zstrtol(str, &ptr, 8);
    if(!*str || *ptr) {
	zwarnnam(nam, "invalid mode `%s'", str);
	return 1;
    }

    return recursivecmd(nam, 0, OPT_ISSET(ops,'R'), OPT_ISSET(ops,'s'),
	args + 1, chmod_dochmod, recurse_donothing, chmod_dochmod, &chm);
}

/* chown builtin */

struct chownmagic {
    char *nam;
    uid_t uid;
    gid_t gid;
};

/**/
static int
chown_dochown(char *arg, char *rp, UNUSED(struct stat const *sp), void *magic)
{
    struct chownmagic *chm = magic;

    if(chown(rp, chm->uid, chm->gid)) {
	zwarnnam(chm->nam, "%s: %e", arg, errno);
	return 1;
    }
    return 0;
}

/**/
static int
chown_dolchown(char *arg, char *rp, UNUSED(struct stat const *sp), void *magic)
{
    struct chownmagic *chm = magic;

    if(lchown(rp, chm->uid, chm->gid)) {
	zwarnnam(chm->nam, "%s: %e", arg, errno);
	return 1;
    }
    return 0;
}


/**/
static unsigned long getnumeric(char *p, int *errp)
{
    unsigned long ret;

    if (!idigit(*p)) {
	*errp = 1;
	return 0;
    }
    ret = strtoul(p, &p, 10);
    *errp = !!*p;
    return ret;
}

enum { BIN_CHOWN, BIN_CHGRP };

/**/
static int
bin_chown(char *nam, char **args, Options ops, int func)
{
    struct chownmagic chm;
    char *uspec = ztrdup(*args), *p = uspec;
    char *end;

    chm.nam = nam;
    if(func == BIN_CHGRP) {
	chm.uid = -1;
	goto dogroup;
    }
    end = strchr(uspec, ':');
    if(!end)
	end = strchr(uspec, '.');
    if(end == uspec) {
	chm.uid = -1;
	p++;
	goto dogroup;
    } else {
	struct passwd *pwd;
	if(end)
	    *end = 0;
	pwd = getpwnam(p);
	if(pwd)
	    chm.uid = pwd->pw_uid;
	else {
	    int err;
	    chm.uid = getnumeric(p, &err);
	    if(err) {
		zwarnnam(nam, "%s: no such user", p);
		free(uspec);
		return 1;
	    }
	}
	if(end) {
	    p = end+1;
	    if(!*p) {
		if(!pwd && !(pwd = getpwuid(chm.uid))) {
		    zwarnnam(nam, "%s: no such user", uspec);
		    free(uspec);
		    return 1;
		}
		chm.gid = pwd->pw_gid;
	    } else if(p[0] == ':' && !p[1]) {
		chm.gid = -1;
	    } else {
		struct group *grp;
		dogroup:
		grp = getgrnam(p);
		if(grp)
		    chm.gid = grp->gr_gid;
		else {
		    int err;
		    chm.gid = getnumeric(p, &err);
		    if(err) {
			zwarnnam(nam, "%s: no such group", p);
			free(uspec);
			return 1;
		    }
		}
	    }
	 } else
	    chm.gid = -1;
    }
    free(uspec);
    return recursivecmd(nam, 0, OPT_ISSET(ops,'R'), OPT_ISSET(ops,'s'),
	args + 1, OPT_ISSET(ops, 'h') ? chown_dolchown : chown_dochown, recurse_donothing,
	OPT_ISSET(ops, 'h') ? chown_dolchown : chown_dochown, &chm);
}

/* module paraphernalia */

/* BrightDate FFI — converts a Unix time_t (seconds) to a BrightDate value */
extern double bsh_unix_to_brightdate(double unix_secs);

/* ── colour codes ──────────────────────────────────────────── */
#define COL_DIR  "\033[1;34m"
#define COL_LNK  "\033[1;36m"
#define COL_EXE  "\033[1;32m"
#define COL_RST  "\033[0m"

/* ── display options passed through to print helpers ───────── */
struct ls_opts {
    int color;      /* -G or isatty(stdout) */
    int human;      /* -h: human-readable sizes */
    int numeric;    /* -n: numeric uid/gid */
    int type_ind;   /* -F: append type indicator */
    int use_atime;  /* -u: show/sort by atime instead of mtime */
    int use_ctime;  /* -c: show/sort by ctime instead of mtime */
    int blocks;     /* -s: show block count */
    int sort_time;  /* -t: sort by time */
    int reverse;    /* -r: reverse sort */
};

/* ── collected directory entry (for sorting) ───────────────── */
#ifndef NAME_MAX
# define NAME_MAX 255
#endif
struct ls_ent {
    char        name[NAME_MAX + 1];
    char        path[PATH_MAX];
    struct stat st;
};

/*
 * Build a 10-character POSIX mode string (type + rwxrwxrwx) into buf[11].
 */
static void
ls_modestr(mode_t mode, char *buf)
{
    static const mode_t bits[9] = {
	S_IRUSR, S_IWUSR, S_IXUSR,
	S_IRGRP, S_IWGRP, S_IXGRP,
	S_IROTH, S_IWOTH, S_IXOTH
    };
    static const char rwx[3] = "rwx";
    int i;

    if      (S_ISREG(mode))  buf[0] = '-';
    else if (S_ISDIR(mode))  buf[0] = 'd';
    else if (S_ISLNK(mode))  buf[0] = 'l';
    else if (S_ISCHR(mode))  buf[0] = 'c';
    else if (S_ISBLK(mode))  buf[0] = 'b';
    else if (S_ISFIFO(mode)) buf[0] = 'p';
    else if (S_ISSOCK(mode)) buf[0] = 's';
    else                     buf[0] = '?';

    for (i = 0; i < 9; i++)
	buf[1 + i] = (mode & bits[i]) ? rwx[i % 3] : '-';
    if (mode & S_ISUID) buf[3] = (mode & S_IXUSR) ? 's' : 'S';
    if (mode & S_ISGID) buf[6] = (mode & S_IXGRP) ? 's' : 'S';
    if (mode & S_ISVTX) buf[9] = (mode & S_IXOTH) ? 't' : 'T';
    buf[10] = '\0';
}

/* Return the -F type-indicator character, or 0 if none. */
static char
ls_type_indicator(mode_t mode)
{
    if (S_ISDIR(mode))  return '/';
    if (S_ISLNK(mode))  return '@';
    if (S_ISFIFO(mode)) return '|';
    if (S_ISSOCK(mode)) return '=';
    if (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) return '*';
    return 0;
}

/* Format size into buf: plain bytes, or human-readable with -h. */
static void
ls_fmt_size(unsigned long long sz, int human, char *buf, size_t bufsz)
{
    static const char units[] = "BKMGTP";
    int u = 0;
    double v;

    if (!human) {
	snprintf(buf, bufsz, "%llu", sz);
	return;
    }
    v = (double)sz;
    while (v >= 1024.0 && u < 5) { v /= 1024.0; u++; }
    if (u == 0)
	snprintf(buf, bufsz, "%llu", sz);
    else
	snprintf(buf, bufsz, "%.1f%c", v, units[u]);
}

/* Return the ANSI colour prefix appropriate for this file, or "". */
static const char *
ls_color_str(struct stat *st, int color)
{
    if (!color) return "";
    if (S_ISDIR(st->st_mode)) return COL_DIR;
    if (S_ISLNK(st->st_mode)) return COL_LNK;
    if (st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) return COL_EXE;
    return "";
}

/*
 * Print one long-format line.  The BrightDate timestamp shown is mtime
 * by default, or atime when o->use_atime is set — matching standard ls.
 */
static void
ls_print_long(struct stat *st, const char *name, const char *path,
	      const struct ls_opts *o)
{
    char modestr[11];
    char owner[64] = "", grp[64] = "";
    char sizebuf[32];
    char indic[3] = "";
    char linktgt[PATH_MAX] = "";
    double bd_ts;
    const char *col, *rst;

    bd_ts = o->use_atime
	? bsh_unix_to_brightdate((double)st->st_atime)
	: o->use_ctime
	? bsh_unix_to_brightdate((double)st->st_ctime)
	: bsh_unix_to_brightdate((double)st->st_mtime);

    ls_modestr(st->st_mode, modestr);
    ls_fmt_size((unsigned long long)st->st_size, o->human, sizebuf, sizeof(sizebuf));

#ifdef HAVE_GETPWUID
    if (!o->numeric) {
	struct passwd *pw = getpwuid(st->st_uid);
	if (pw) strncpy(owner, pw->pw_name, sizeof(owner) - 1);
    }
#endif
    if (!owner[0])
	snprintf(owner, sizeof(owner), "%lu", (unsigned long)st->st_uid);

#ifdef USE_GETGRGID
    if (!o->numeric) {
	struct group *gr = getgrgid(st->st_gid);
	if (gr) strncpy(grp, gr->gr_name, sizeof(grp) - 1);
    }
#endif
    if (!grp[0])
	snprintf(grp, sizeof(grp), "%lu", (unsigned long)st->st_gid);

    if (o->type_ind) {
	char c = ls_type_indicator(st->st_mode);
	if (c) { indic[0] = c; indic[1] = '\0'; }
    }

    col = ls_color_str(st, o->color);
    rst = (col[0] != '\0') ? COL_RST : "";

    if (S_ISLNK(st->st_mode)) {
	ssize_t n = readlink(path, linktgt, sizeof(linktgt) - 1);
	if (n >= 0) linktgt[n] = '\0';
	else        linktgt[0] = '\0';
    }

    if (o->blocks)
	printf("%llu ", (unsigned long long)st->st_blocks);

    printf("%s %3lu %-8s %-8s %8s  %.6f  %s%s%s%s%s%s\n",
	   modestr,
	   (unsigned long)st->st_nlink,
	   owner, grp,
	   sizebuf,
	   bd_ts,
	   col, name, indic, rst,
	   linktgt[0] ? " -> " : "",
	   linktgt);
}

/* Print a short (name-only) entry. */
static void
ls_print_short(const char *name, struct stat *st, const struct ls_opts *o)
{
    const char *col = ls_color_str(st, o->color);
    const char *rst = (col[0] != '\0') ? COL_RST : "";
    char indic[3] = "";

    if (o->type_ind) {
	char c = ls_type_indicator(st->st_mode);
	if (c) { indic[0] = c; indic[1] = '\0'; }
    }
    printf("%s%s%s%s\n", col, name, indic, rst);
}

/* Sort comparators — set by bin_ls before calling qsort. */
static int ls_sort_use_atime;
static int ls_sort_use_ctime;

static int
ls_cmp_name(const void *a, const void *b)
{
    return strcmp(((const struct ls_ent *)a)->name,
		  ((const struct ls_ent *)b)->name);
}

static int
ls_cmp_time(const void *a, const void *b)
{
    const struct ls_ent *ea = (const struct ls_ent *)a;
    const struct ls_ent *eb = (const struct ls_ent *)b;
    time_t ta, tb;
    if (ls_sort_use_atime) {
	ta = ea->st.st_atime;
	tb = eb->st.st_atime;
    } else if (ls_sort_use_ctime) {
	ta = ea->st.st_ctime;
	tb = eb->st.st_ctime;
    } else {
	ta = ea->st.st_mtime;
	tb = eb->st.st_mtime;
    }
    /* newer first, matching standard ls -t */
    if (tb > ta) return  1;
    if (tb < ta) return -1;
    return 0;
}

/* ls builtin — list files with BrightDate timestamps */

/**/
static int
bin_ls(char *nam, char **args, Options ops, UNUSED(int func))
{
    struct ls_opts o;
    struct stat st;
    struct ls_ent *ents;
    struct ls_ent *tmp;
    struct dirent *de;
    DIR *dp;
    size_t nents, cap, i, idx;
    int long_fmt    = OPT_ISSET(ops, 'l');
    int follow_syms = OPT_ISSET(ops, 'L');
    int show_all    = OPT_ISSET(ops, 'a');
    int dir_itself  = OPT_ISSET(ops, 'd');
    int err = 0;
    int rv;
    char *dot[] = { ".", NULL };

    o.use_atime = OPT_ISSET(ops, 'u');
    o.use_ctime = OPT_ISSET(ops, 'c') && !o.use_atime; /* -u takes precedence */
    o.human     = OPT_ISSET(ops, 'h');
    o.numeric   = OPT_ISSET(ops, 'n');
    o.type_ind  = OPT_ISSET(ops, 'F');
    o.blocks    = OPT_ISSET(ops, 's');
    o.sort_time = OPT_ISSET(ops, 't') || o.use_ctime;
    o.reverse   = OPT_ISSET(ops, 'r');
    o.color     = OPT_ISSET(ops, 'G') || isatty(STDOUT_FILENO);
    ls_sort_use_atime = o.use_atime;
    ls_sort_use_ctime = o.use_ctime;

    if (!*args)
	args = dot;

    for (; *args; args++) {
	rv = follow_syms ? stat(*args, &st) : lstat(*args, &st);

	if (rv) {
	    zwarnnam(nam, "%s: %e", *args, errno);
	    err = 1;
	    continue;
	}

	if (S_ISDIR(st.st_mode) && !dir_itself) {
	    dp = opendir(*args);
	    if (!dp) {
		zwarnnam(nam, "%s: %e", *args, errno);
		err = 1;
		continue;
	    }

	    ents = NULL;
	    nents = 0;
	    cap = 0;

	    while ((de = readdir(dp))) {
		if (!show_all && de->d_name[0] == '.')
		    continue;

		if (nents >= cap) {
		    cap = cap ? cap * 2 : 32;
		    tmp = realloc(ents, cap * sizeof(*ents));
		    if (!tmp) {
			zwarnnam(nam, "out of memory");
			free(ents);
			closedir(dp);
			return 1;
		    }
		    ents = tmp;
		}

		strncpy(ents[nents].name, de->d_name, NAME_MAX);
		ents[nents].name[NAME_MAX] = '\0';
		snprintf(ents[nents].path, PATH_MAX, "%s/%s", *args, de->d_name);
		rv = follow_syms
		    ? stat(ents[nents].path, &ents[nents].st)
		    : lstat(ents[nents].path, &ents[nents].st);
		if (rv) {
		    zwarnnam(nam, "%s: %e", ents[nents].path, errno);
		    err = 1;
		    memset(&ents[nents].st, 0, sizeof(ents[nents].st));
		}
		nents++;
	    }
	    closedir(dp);

	    if (nents > 0) {
		if (o.sort_time)
		    qsort(ents, nents, sizeof(*ents), ls_cmp_time);
		else
		    qsort(ents, nents, sizeof(*ents), ls_cmp_name);
	    }

	    for (i = 0; i < nents; i++) {
		idx = o.reverse ? (nents - 1 - i) : i;
		if (long_fmt)
		    ls_print_long(&ents[idx].st, ents[idx].name, ents[idx].path, &o);
		else
		    ls_print_short(ents[idx].name, &ents[idx].st, &o);
	    }
	    free(ents);
	} else {
	    if (long_fmt)
		ls_print_long(&st, *args, *args, &o);
	    else
		ls_print_short(*args, &st, &o);
	}
    }
    return err;
}

#ifdef HAVE_LSTAT
# define LN_OPTS "dfhins"
#else
# define LN_OPTS "dfi"
#endif

static struct builtin bintab[] = {
    /* The names which overlap commands without necessarily being
     * fully compatible. */
    BUILTIN("chgrp", 0, bin_chown, 2, -1, BIN_CHGRP, "hRs",    NULL),
    BUILTIN("chmod", 0, bin_chmod, 2, -1, 0,         "Rs",    NULL),
    BUILTIN("chown", 0, bin_chown, 2, -1, BIN_CHOWN, "hRs",    NULL),
    BUILTIN("ln",    0, bin_ln,    1, -1, BIN_LN,    LN_OPTS, NULL),
    BUILTIN("ls",    0, bin_ls,    0, -1, 0,         "acdlLGFhnrstu", NULL),
    BUILTIN("mkdir", 0, bin_mkdir, 1, -1, 0,         "pm:",   NULL),
    BUILTIN("mv",    0, bin_ln,    2, -1, BIN_MV,    "fi",    NULL),
    BUILTIN("rm",    0, bin_rm,    1, -1, 0,         "dfiRrs", NULL),
    BUILTIN("rmdir", 0, bin_rmdir, 1, -1, 0,         NULL,    NULL),
    BUILTIN("sync",  0, bin_sync,  0,  0, 0,         NULL,    NULL),
    /* The "safe" bsh-only names */
    BUILTIN("zf_chgrp", 0, bin_chown, 2, -1, BIN_CHGRP, "hRs",    NULL),
    BUILTIN("zf_chmod", 0, bin_chmod, 2, -1, 0,         "Rs",    NULL),
    BUILTIN("zf_chown", 0, bin_chown, 2, -1, BIN_CHOWN, "hRs",    NULL),
    BUILTIN("zf_ln",    0, bin_ln,    1, -1, BIN_LN,    LN_OPTS, NULL),
    BUILTIN("zf_ls",    0, bin_ls,    0, -1, 0,         "acdlLGFhnrstu", NULL),
    BUILTIN("zf_mkdir", 0, bin_mkdir, 1, -1, 0,         "pm:",   NULL),
    BUILTIN("zf_mv",    0, bin_ln,    2, -1, BIN_MV,    "fi",    NULL),
    BUILTIN("zf_rm",    0, bin_rm,    1, -1, 0,         "dfiRrs", NULL),
    BUILTIN("zf_rmdir", 0, bin_rmdir, 1, -1, 0,         NULL,    NULL),
    BUILTIN("zf_sync",  0, bin_sync,  0,  0, 0,         NULL,    NULL),

};

static struct features module_features = {
    bintab, sizeof(bintab)/sizeof(*bintab),
    NULL, 0,
    NULL, 0,
    NULL, 0,
    0
};

/**/
int
setup_(UNUSED(Module m))
{
    return 0;
}

/**/
int
features_(Module m, char ***features)
{
    *features = featuresarray(m, &module_features);
    return 0;
}

/**/
int
enables_(Module m, int **enables)
{
    return handlefeatures(m, &module_features, enables);
}

/**/
int
boot_(UNUSED(Module m))
{
    return 0;
}

/**/
int
cleanup_(Module m)
{
    return setfeatureenables(m, &module_features, NULL);
}

/**/
int
finish_(UNUSED(Module m))
{
    return 0;
}
