/*
 * brightdate.c - builtin commands bdate, btime, buptime, bcal, bwatch
 *
 * These builtins delegate to the brightdate-rust staticlib via C FFI.
 */

#include "brightdate.mdh"
#include "brightdate.pro"

extern int bsh_bdate(int argc, const char **argv);
extern int bsh_btime(int argc, const char **argv);
extern int bsh_buptime(int argc, const char **argv);
extern int bsh_bcal(int argc, const char **argv);
extern int bsh_bwatch(int argc, const char **argv);

/*
 * Build an argv array with name prepended and call the Rust function.
 * The bsh shell module calling convention passes name and then the
 * remaining arguments without argv[0], so we reconstruct a conventional
 * argc/argv pair for the Rust side.
 */
static int
call_rust(char *name, char **argv, int (*fn)(int, const char **))
{
    int argc = 1;
    char **p;
    const char **ffi_argv;
    int i;

    for (p = argv; *p; p++)
	argc++;

    ffi_argv = (const char **)zhalloc((argc + 1) * sizeof(char *));
    ffi_argv[0] = name;
    for (i = 1; i < argc; i++)
	ffi_argv[i] = argv[i - 1];
    ffi_argv[argc] = NULL;

    return fn(argc, ffi_argv);
}

/**/
static int
bin_bdate(char *name, char **argv, UNUSED(Options ops), UNUSED(int func))
{
    return call_rust(name, argv, bsh_bdate);
}

/**/
static int
bin_btime(char *name, char **argv, UNUSED(Options ops), UNUSED(int func))
{
    return call_rust(name, argv, bsh_btime);
}

/**/
static int
bin_buptime(char *name, char **argv, UNUSED(Options ops), UNUSED(int func))
{
    return call_rust(name, argv, bsh_buptime);
}

/**/
static int
bin_bcal(char *name, char **argv, UNUSED(Options ops), UNUSED(int func))
{
    return call_rust(name, argv, bsh_bcal);
}

/**/
static int
bin_bwatch(char *name, char **argv, UNUSED(Options ops), UNUSED(int func))
{
    return call_rust(name, argv, bsh_bwatch);
}

static struct builtin bintab[] = {
    BUILTIN("bdate",   0, bin_bdate,   0, -1, 0, NULL, NULL),
    BUILTIN("btime",   0, bin_btime,   0, -1, 0, NULL, NULL),
    BUILTIN("buptime", 0, bin_buptime, 0,  0, 0, NULL, NULL),
    BUILTIN("bcal",    0, bin_bcal,    0, -1, 0, NULL, NULL),
    BUILTIN("bwatch",  0, bin_bwatch,  1, -1, 0, NULL, NULL),
    /* canonical names shadow external commands */
    BUILTIN("date",    0, bin_bdate,   0, -1, 0, NULL, NULL),
    BUILTIN("time",    0, bin_btime,   1, -1, 0, NULL, NULL),
    BUILTIN("uptime",  0, bin_buptime, 0,  0, 0, NULL, NULL),
    BUILTIN("cal",     0, bin_bcal,    0, -1, 0, NULL, NULL),
    BUILTIN("watch",   0, bin_bwatch,  1, -1, 0, NULL, NULL),
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
