#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#elif defined __GNUC__
#define alloca __builtin_alloca
#elif defined _AIX
#define alloca __alloca
#elif defined _MSC_VER
#include <malloc.h>
#define alloca _alloca
#else
#include <stddef.h>
#ifdef  __cplusplus
extern "C"
#endif
void *alloca(size_t);
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#else
#define gettext(x) (x)
#define dgettext(domain, x) (x)
#endif

#define _(x) dgettext("ecore", x)

#ifdef _WIN32_WCE
#include <Evil.h>
#endif

#include "Ecore.h"
#include "Ecore_Getopt.h"

static const char *prog = NULL;
static char **argv = NULL;
static int argc = 0;
static int cols = 80;
static int helpcol = 80 / 3;

static void
_ecore_getopt_help_print_replace_program(FILE * fp,
					 const Ecore_Getopt *
					 parser __UNUSED__,
					 const char *text)
{
	do {
		const char *d = strchr(text, '%');

		if (!d) {
			fputs(text, fp);
			break;
		}

		if (fwrite(text, 1, d - text, fp) != (size_t) (d - text))
			return;
		d++;
		if (strncmp(d, "prog", sizeof("prog") - 1) == 0) {
			fputs(prog ? prog : "???", fp);
			d += sizeof("prog") - 1;
		} else {
			if (d[0] == '%')
				d++;
			fputc('%', fp);
		}

		text = d;
	}
	while (text[0] != '\0');

	fputc('\n', fp);
}

static void _ecore_getopt_version(FILE * fp, const Ecore_Getopt * parser)
{
	fputs(_("Version:"), fp);
	fputc(' ', fp);
	_ecore_getopt_help_print_replace_program(fp, parser,
						 parser->version);
}

static void
_ecore_getopt_help_usage(FILE * fp, const Ecore_Getopt * parser)
{
	fputs(_("Usage:"), fp);
	fputc(' ', fp);

	if (!parser->usage) {
		fprintf(fp, _("%s [options]\n"), prog);
		return;
	}

	_ecore_getopt_help_print_replace_program(fp, parser,
						 gettext(parser->usage));
}

static int
_ecore_getopt_help_line(FILE * fp, const int base, const int total,
			int used, const char *text, int len)
{
	int linebreak = 0;
	do {
		/* process line considering spaces (new line and tabs are spaces!) */
		while ((used < total) && (len > 0)) {
			const char *space = NULL;
			int i, todo;

			todo = total - used;
			if (todo > len)
				todo = len;

			for (i = 0; i < todo; i++)
				if (isspace(text[i])) {
					space = text + i;
					break;
				}

			if (space) {
				i = fwrite(text, 1, i, fp);
				i++;
				text += i;
				len -= i;
				used += i;

				if (linebreak) {
					linebreak = 0;
					continue;
				}

				if (space[0] == '\n')
					break;
				else if (space[0] == '\t') {
					int c;

					used--;
					c = ((used / 8) + 1) * 8;
					if (c < total) {
						for (; used < c; used++)
							fputc(' ', fp);
					} else {
						text--;
						len++;
						break;
					}
				} else if (used < total)
					fputc(space[0], fp);
			} else {
				i = fwrite(text, 1, i, fp);
				text += i;
				len -= i;
				used += i;
			}
			linebreak = 0;
		}
		if (len <= 0)
			break;
		linebreak = 1;
		fputc('\n', fp);
		for (used = 0; used < base; used++)
			fputc(' ', fp);
	}
	while (1);

	return used;
}

static void
_ecore_getopt_help_description(FILE * fp, const Ecore_Getopt * parser)
{
	const char *p, *prg, *ver;
	int used, prglen, verlen;

	p = gettext(parser->description);
	if (!p)
		return;

	fputc('\n', fp);

	prg = prog ? prog : "???";
	ver = parser->version ? parser->version : "???";

	prglen = strlen(prg);
	verlen = strlen(ver);

	used = 0;

	do {
		const char *d = strchr(p, '%');

		if (!d) {
			_ecore_getopt_help_line(fp, 0, cols, used, p,
						strlen(p));
			break;
		}

		used =
		    _ecore_getopt_help_line(fp, 0, cols, used, p, d - p);
		d++;
		if (strncmp(d, "prog", sizeof("prog") - 1) == 0) {
			used =
			    _ecore_getopt_help_line(fp, 0, cols, used, prg,
						    prglen);
			d += sizeof("prog") - 1;
		} else if (strncmp(d, "version", sizeof("version") - 1) ==
			   0) {
			used =
			    _ecore_getopt_help_line(fp, 0, cols, used, ver,
						    verlen);
			d += sizeof("version") - 1;
		} else {
			if (d[0] == '%')
				d++;
			used =
			    _ecore_getopt_help_line(fp, 0, cols, used, "%",
						    1);
		}

		p = d;
	}
	while (p[0] != '\0');

	fputs("\n\n", fp);
}

static void _ecore_getopt_copyright(FILE * fp, const Ecore_Getopt * parser)
{
	const char *txt = gettext(parser->copyright);
	fputs(_("Copyright:"), fp);
	fputs("\n   ", fp);
	_ecore_getopt_help_line(fp, 3, cols, 3, txt, strlen(txt));
	fputc('\n', fp);
}

static void _ecore_getopt_license(FILE * fp, const Ecore_Getopt * parser)
{
	const char *txt = gettext(parser->license);
	fputs(_("License:"), fp);
	fputs("\n   ", fp);
	_ecore_getopt_help_line(fp, 3, cols, 3, txt, strlen(txt));
	fputc('\n', fp);
}

static Ecore_Getopt_Desc_Arg_Requirement
_ecore_getopt_desc_arg_requirement(const Ecore_Getopt_Desc * desc)
{
	switch (desc->action) {
	case ECORE_GETOPT_ACTION_STORE:
		return desc->action_param.store.arg_req;
	case ECORE_GETOPT_ACTION_STORE_CONST:
		return ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO;
	case ECORE_GETOPT_ACTION_STORE_TRUE:
		return ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO;
	case ECORE_GETOPT_ACTION_STORE_FALSE:
		return ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO;
	case ECORE_GETOPT_ACTION_CHOICE:
		return ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES;
	case ECORE_GETOPT_ACTION_APPEND:
		return ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES;
	case ECORE_GETOPT_ACTION_COUNT:
		return ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO;
	case ECORE_GETOPT_ACTION_CALLBACK:
		return desc->action_param.callback.arg_req;
	case ECORE_GETOPT_ACTION_HELP:
		return ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO;
	case ECORE_GETOPT_ACTION_VERSION:
		return ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO;
	default:
		return ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO;
	}
}

static void
_ecore_getopt_help_desc_setup_metavar(const Ecore_Getopt_Desc * desc,
				      char *metavar, int *metavarlen,
				      int maxsize)
{
	if (desc->metavar) {
		const char *txt = gettext(desc->metavar);
		*metavarlen = strlen(txt);
		if (*metavarlen > maxsize - 1)
			*metavarlen = maxsize - 1;

		memcpy(metavar, txt, *metavarlen);
		metavar[*metavarlen] = '\0';
	} else if (desc->longname) {
		int i;

		*metavarlen = strlen(desc->longname);
		if (*metavarlen > maxsize - 1)
			*metavarlen = maxsize - 1;

		for (i = 0; i < *metavarlen; i++)
			metavar[i] = toupper(desc->longname[i]);
		metavar[i] = '\0';
	}
}

static int
_ecore_getopt_help_desc_show_arg(FILE * fp,
				 Ecore_Getopt_Desc_Arg_Requirement
				 requirement, const char *metavar,
				 int metavarlen)
{
	int used;

	if (requirement == ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO)
		return 0;

	used = 0;

	if (requirement == ECORE_GETOPT_DESC_ARG_REQUIREMENT_OPTIONAL) {
		fputc('[', fp);
		used++;
	}

	if (requirement != ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO) {
		fputc('=', fp);
		fputs(metavar, fp);
		used += metavarlen + 1;
	}

	if (requirement == ECORE_GETOPT_DESC_ARG_REQUIREMENT_OPTIONAL) {
		fputc(']', fp);
		used++;
	}

	return used;
}

static int
_ecore_getopt_help_desc_store(FILE * fp, const int base, const int total,
			      int used, const Ecore_Getopt_Desc * desc)
{
	const Ecore_Getopt_Desc_Store *store = &desc->action_param.store;
	char buf[64];
	const char *str;
	size_t len;

	fputc('\n', fp);
	for (used = 0; used < base; used++)
		fputc(' ', fp);

	switch (store->type) {
	case ECORE_GETOPT_TYPE_STR:
		str = "STR";
		len = sizeof("STR") - 1;
		break;
	case ECORE_GETOPT_TYPE_BOOL:
		str = "BOOL";
		len = sizeof("BOOL") - 1;
		break;
	case ECORE_GETOPT_TYPE_SHORT:
		str = "SHORT";
		len = sizeof("SHORT") - 1;
		break;
	case ECORE_GETOPT_TYPE_INT:
		str = "INT";
		len = sizeof("INT") - 1;
		break;
	case ECORE_GETOPT_TYPE_LONG:
		str = "LONG";
		len = sizeof("LONG") - 1;
		break;
	case ECORE_GETOPT_TYPE_USHORT:
		str = "USHORT";
		len = sizeof("USHORT") - 1;
		break;
	case ECORE_GETOPT_TYPE_UINT:
		str = "UINT";
		len = sizeof("UINT") - 1;
		break;
	case ECORE_GETOPT_TYPE_ULONG:
		str = "ULONG";
		len = sizeof("ULONG") - 1;
		break;
	case ECORE_GETOPT_TYPE_DOUBLE:
		str = "DOUBLE";
		len = sizeof("DOUBLE") - 1;
		break;
	default:
		str = "???";
		len = sizeof("???") - 1;
	}

	used = _ecore_getopt_help_line
	    (fp, base, total, used, _("Type: "), strlen(_("Type: ")));
	used = _ecore_getopt_help_line(fp, base, total, used, str, len);

	if (store->arg_req == ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES)
		goto end;

	used = _ecore_getopt_help_line
	    (fp, base, total, used, ". ", sizeof(". ") - 1);

	switch (store->type) {
	case ECORE_GETOPT_TYPE_STR:
		str = store->def.strv;
		len = str ? strlen(str) : 0;
		break;
	case ECORE_GETOPT_TYPE_BOOL:
		str = store->def.boolv ? "true" : "false";
		len = strlen(str);
		break;
	case ECORE_GETOPT_TYPE_SHORT:
		str = buf;
		len = snprintf(buf, sizeof(buf), "%hd", store->def.shortv);
		if (len > sizeof(buf) - 1)
			len = sizeof(buf) - 1;
		break;
	case ECORE_GETOPT_TYPE_INT:
		str = buf;
		len = snprintf(buf, sizeof(buf), "%d", store->def.intv);
		if (len > sizeof(buf) - 1)
			len = sizeof(buf) - 1;
		break;
	case ECORE_GETOPT_TYPE_LONG:
		str = buf;
		len = snprintf(buf, sizeof(buf), "%ld", store->def.longv);
		if (len > sizeof(buf) - 1)
			len = sizeof(buf) - 1;
		break;
	case ECORE_GETOPT_TYPE_USHORT:
		str = buf;
		len =
		    snprintf(buf, sizeof(buf), "%hu", store->def.ushortv);
		if (len > sizeof(buf) - 1)
			len = sizeof(buf) - 1;
		break;
	case ECORE_GETOPT_TYPE_UINT:
		str = buf;
		len = snprintf(buf, sizeof(buf), "%u", store->def.uintv);
		if (len > sizeof(buf) - 1)
			len = sizeof(buf) - 1;
		break;
	case ECORE_GETOPT_TYPE_ULONG:
		str = buf;
		len = snprintf(buf, sizeof(buf), "%lu", store->def.ulongv);
		if (len > sizeof(buf) - 1)
			len = sizeof(buf) - 1;
		break;
	case ECORE_GETOPT_TYPE_DOUBLE:
		str = buf;
		len = snprintf(buf, sizeof(buf), "%f", store->def.doublev);
		if (len > sizeof(buf) - 1)
			len = sizeof(buf) - 1;
		break;
	default:
		str = "???";
		len = sizeof("???") - 1;
	}

	used = _ecore_getopt_help_line
	    (fp, base, total, used, _("Default: "),
	     strlen(_("Default: ")));
	used = _ecore_getopt_help_line(fp, base, total, used, str, len);

      end:
	return _ecore_getopt_help_line(fp, base, total, used, ".", 1);
}

static int
_ecore_getopt_help_desc_choices(FILE * fp, const int base, const int total,
				int used, const Ecore_Getopt_Desc * desc)
{
	const char *const *itr;
	const char sep[] = ", ";
	const int seplen = sizeof(sep) - 1;

	if (used > 0) {
		fputc('\n', fp);
		used = 0;
	}
	for (; used < base; used++)
		fputc(' ', fp);

	used = _ecore_getopt_help_line
	    (fp, base, total, used, _("Choices: "),
	     strlen(_("Choices: ")));

	for (itr = desc->action_param.choices; *itr; itr++) {
		used = _ecore_getopt_help_line
		    (fp, base, total, used, *itr, strlen(*itr));
		if (itr[1])
			used =
			    _ecore_getopt_help_line(fp, base, total, used,
						    sep, seplen);
	}

	return _ecore_getopt_help_line(fp, base, total, used, ".", 1);
}

static void
_ecore_getopt_help_desc(FILE * fp, const Ecore_Getopt_Desc * desc)
{
	Ecore_Getopt_Desc_Arg_Requirement arg_req;
	char metavar[32] = "ARG";
	int metavarlen = 3;
	int used;

	arg_req = _ecore_getopt_desc_arg_requirement(desc);
	if (arg_req != ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO)
		_ecore_getopt_help_desc_setup_metavar
		    (desc, metavar, &metavarlen, sizeof(metavar));

	fputs("  ", fp);
	used = 2;

	if (desc->shortname) {
		fputc('-', fp);
		fputc(desc->shortname, fp);
		used += 2;
		used += _ecore_getopt_help_desc_show_arg
		    (fp, arg_req, metavar, metavarlen);
	}

	if (desc->shortname && desc->longname) {
		fputs(", ", fp);
		used += 2;
	}

	if (desc->longname) {
		int namelen = strlen(desc->longname);

		fputs("--", fp);
		fputs(desc->longname, fp);
		used += 2 + namelen;
		used += _ecore_getopt_help_desc_show_arg
		    (fp, arg_req, metavar, metavarlen);
	}

	if (!desc->help)
		goto end;

	if (used + 3 >= helpcol) {
		fputc('\n', fp);
		used = 0;
	}

	for (; used < helpcol; used++)
		fputc(' ', fp);

	used = _ecore_getopt_help_line
	    (fp, helpcol, cols, used, desc->help, strlen(desc->help));

	switch (desc->action) {
	case ECORE_GETOPT_ACTION_STORE:
		_ecore_getopt_help_desc_store(fp, helpcol, cols, used,
					      desc);
		break;
	case ECORE_GETOPT_ACTION_CHOICE:
		_ecore_getopt_help_desc_choices(fp, helpcol, cols, used,
						desc);
		break;
	default:
		break;
	}

      end:
	fputc('\n', fp);
}

static unsigned char
_ecore_getopt_desc_is_sentinel(const Ecore_Getopt_Desc * desc)
{
	return (desc->shortname == '\0') && (!desc->longname);
}

static void
_ecore_getopt_help_options(FILE * fp, const Ecore_Getopt * parser)
{
	const Ecore_Getopt_Desc *desc;

	fputs(_("Options:\n"), fp);

	for (desc = parser->descs; !_ecore_getopt_desc_is_sentinel(desc);
	     desc++)
		_ecore_getopt_help_desc(fp, desc);

	fputc('\n', fp);
}

/**
 * Show nicely formatted help message for the given parser.
 *
 * Message will be print to stderr.
 */
void ecore_getopt_help(FILE * fp, const Ecore_Getopt * parser)
{
	const char *var;

	if (!parser)
		return;

	if (argc < 1) {
		ecore_app_args_get(&argc, &argv);
		if ((argc > 0) && (argv[0]))
			prog = argv[0];
		else
			prog = parser->prog;
	}

	var = getenv("COLUMNS");
	if (var) {
		cols = atoi(var);
		if (cols < 20)
			cols = 20;

		helpcol = cols / 3;
	}

	_ecore_getopt_help_usage(fp, parser);
	_ecore_getopt_help_description(fp, parser);
	_ecore_getopt_help_options(fp, parser);
}

static const Ecore_Getopt_Desc *_ecore_getopt_parse_find_long(const
							      Ecore_Getopt
							      * parser,
							      const char
							      *name)
{
	const Ecore_Getopt_Desc *desc = parser->descs;
	const char *p = strchr(name, '=');
	int len = 0;

	if (p)
		len = p - name;

	for (; !_ecore_getopt_desc_is_sentinel(desc); desc++) {
		if (!desc->longname)
			continue;

		if (p) {
			if ((strncmp(name, desc->longname, len) == 0) &&
			    (desc->longname[len] == '\0'))
				return desc;
		} else {
			if (strcmp(name, desc->longname) == 0)
				return desc;
		}
	}

	return NULL;
}

static const Ecore_Getopt_Desc *_ecore_getopt_parse_find_short(const
							       Ecore_Getopt
							       * parser,
							       char name)
{
	const Ecore_Getopt_Desc *desc = parser->descs;
	for (; !_ecore_getopt_desc_is_sentinel(desc); desc++)
		if (name == desc->shortname)
			return desc;
	return NULL;
}

static int
_ecore_getopt_parse_find_nonargs_base(const Ecore_Getopt * parser,
				      int argc, char **argv)
{
	char **nonargs;
	int src, dst, used, base;

	nonargs = alloca(sizeof(char *) * argc);
	src = 1;
	dst = 1;
	used = 0;
	base = 0;
	while (src < argc) {
		const Ecore_Getopt_Desc *desc;
		Ecore_Getopt_Desc_Arg_Requirement arg_req;
		char *arg = argv[src];

		if (arg[0] != '-')
			goto found_nonarg;

		if (arg[1] == '-') {
			if (arg[2] == '\0') {	/* explicit end of options, "--" */
				base = 1;
				break;
			}
			desc =
			    _ecore_getopt_parse_find_long(parser, arg + 2);
		} else
			desc =
			    _ecore_getopt_parse_find_short(parser, arg[1]);

		if (!desc) {
			if (arg[1] == '-')
				fprintf(stderr,
					_("ERROR: unknown option --%s.\n"),
					arg + 2);
			else
				fprintf(stderr,
					_("ERROR: unknown option -%c.\n"),
					arg[1]);
			if (parser->strict) {
				memmove(argv + dst, nonargs,
					used * sizeof(char *));
				return -1;
			} else
				goto found_nonarg;
		}

		if (src != dst)
			argv[dst] = argv[src];
		src++;
		dst++;

		arg_req = _ecore_getopt_desc_arg_requirement(desc);
		if (arg_req == ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO)
			continue;

		if (strchr(arg, '='))
			continue;

		if ((src >= argc) || (argv[src][0] == '-'))
			continue;

		if (src != dst)
			argv[dst] = argv[src];
		src++;
		dst++;
		continue;

	      found_nonarg:
		nonargs[used] = arg;
		used++;
		src++;
	}

	if (!base)		/* '--' not found */
		base = dst;
	else {
		base = dst;
		if (src != dst)
			argv[dst] = argv[src];
		dst++;
	}

	memmove(argv + dst, nonargs, used * sizeof(char *));
	return base;
}

static void
_ecore_getopt_desc_print_error(const Ecore_Getopt_Desc * desc,
			       const char *fmt, ...)
{
	va_list ap;

	fputs(_("ERROR: "), stderr);

	if (desc->shortname) {
		fputc('-', stderr);
		fputc(desc->shortname, stderr);
	}

	if (desc->shortname && desc->longname)
		fputs(", ", stderr);

	if (desc->longname) {
		fputs("--", stderr);
		fputs(desc->longname, stderr);
	}

	fputs(": ", stderr);

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static unsigned char
_ecore_getopt_parse_bool(const char *str, unsigned char *v)
{
	if ((strcmp(str, "0") == 0) ||
	    (strcasecmp(str, "f") == 0) ||
	    (strcasecmp(str, "false") == 0) ||
	    (strcasecmp(str, "no") == 0) || (strcasecmp(str, "off") == 0)
	    ) {
		*v = 0;
		return 1;
	} else if ((strcmp(str, "1") == 0) ||
		   (strcasecmp(str, "t") == 0) ||
		   (strcasecmp(str, "true") == 0) ||
		   (strcasecmp(str, "yes") == 0) ||
		   (strcasecmp(str, "on") == 0)
	    ) {
		*v = 1;
		return 1;
	}

	return 0;
}

static unsigned char _ecore_getopt_parse_long(const char *str, long int *v)
{
	char *endptr = NULL;
	*v = strtol(str, &endptr, 0);
	return endptr > str;
}

static unsigned char _ecore_getopt_parse_double(const char *str, double *v)
{
	char *endptr = NULL;
	*v = strtod(str, &endptr);
	return endptr > str;
}

static unsigned char
_ecore_getopt_parse_store(const Ecore_Getopt * parser __UNUSED__,
			  const Ecore_Getopt_Desc * desc,
			  Ecore_Getopt_Value * value, const char *arg_val)
{
	const Ecore_Getopt_Desc_Store *store = &desc->action_param.store;
	long int v;
	double d;
	unsigned char b;

	if (!value->ptrp) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("value has no pointer set.\n"));
		return 0;
	}

	switch (store->arg_req) {
	case ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO:
		goto use_optional;
	case ECORE_GETOPT_DESC_ARG_REQUIREMENT_OPTIONAL:
		if (!arg_val)
			goto use_optional;
	case ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES:
		break;
	}

	switch (store->type) {
	case ECORE_GETOPT_TYPE_STR:
		*value->strp = (char *) arg_val;
		return 1;
	case ECORE_GETOPT_TYPE_BOOL:
		if (_ecore_getopt_parse_bool(arg_val, &b)) {
			*value->boolp = b;
			return 1;
		} else {
			_ecore_getopt_desc_print_error
			    (desc, _("unknown boolean value %s.\n"),
			     arg_val);
			return 0;
		}
	case ECORE_GETOPT_TYPE_SHORT:
		if (!_ecore_getopt_parse_long(arg_val, &v))
			goto error;
		*value->shortp = v;
		return 1;
	case ECORE_GETOPT_TYPE_INT:
		if (!_ecore_getopt_parse_long(arg_val, &v))
			goto error;
		*value->intp = v;
		return 1;
	case ECORE_GETOPT_TYPE_LONG:
		if (!_ecore_getopt_parse_long(arg_val, &v))
			goto error;
		*value->longp = v;
		return 1;
	case ECORE_GETOPT_TYPE_USHORT:
		if (!_ecore_getopt_parse_long(arg_val, &v))
			goto error;
		*value->ushortp = v;
		return 1;
	case ECORE_GETOPT_TYPE_UINT:
		if (!_ecore_getopt_parse_long(arg_val, &v))
			goto error;
		*value->uintp = v;
		return 1;
	case ECORE_GETOPT_TYPE_ULONG:
		if (!_ecore_getopt_parse_long(arg_val, &v))
			goto error;
		*value->ulongp = v;
		return 1;
	case ECORE_GETOPT_TYPE_DOUBLE:
		if (!_ecore_getopt_parse_double(arg_val, &d))
			goto error;
		*value->doublep = d;
		break;
	}

	return 1;

      error:
	_ecore_getopt_desc_print_error
	    (desc, _("invalid number format %s\n"), arg_val);
	return 0;

      use_optional:
	switch (store->type) {
	case ECORE_GETOPT_TYPE_STR:
		*value->strp = (char *) store->def.strv;
		break;
	case ECORE_GETOPT_TYPE_BOOL:
		*value->boolp = store->def.boolv;
		break;
	case ECORE_GETOPT_TYPE_SHORT:
		*value->shortp = store->def.shortv;
		break;
	case ECORE_GETOPT_TYPE_INT:
		*value->intp = store->def.intv;
		break;
	case ECORE_GETOPT_TYPE_LONG:
		*value->longp = store->def.longv;
		break;
	case ECORE_GETOPT_TYPE_USHORT:
		*value->ushortp = store->def.ushortv;
		break;
	case ECORE_GETOPT_TYPE_UINT:
		*value->uintp = store->def.uintv;
		break;
	case ECORE_GETOPT_TYPE_ULONG:
		*value->ulongp = store->def.ulongv;
		break;
	case ECORE_GETOPT_TYPE_DOUBLE:
		*value->doublep = store->def.doublev;
		break;
	}

	return 1;
}

static unsigned char
_ecore_getopt_parse_store_const(const Ecore_Getopt * parser __UNUSED__,
				const Ecore_Getopt_Desc * desc,
				Ecore_Getopt_Value * val,
				const char *arg_val __UNUSED__)
{
	if (!val->ptrp) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("value has no pointer set.\n"));
		return 0;
	}

	*val->ptrp = (void *) desc->action_param.store_const;
	return 1;
}

static unsigned char
_ecore_getopt_parse_store_true(const Ecore_Getopt * parser __UNUSED__,
			       const Ecore_Getopt_Desc * desc,
			       Ecore_Getopt_Value * val,
			       const char *arg_val __UNUSED__)
{
	if (!val->boolp) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("value has no pointer set.\n"));
		return 0;
	}
	*val->boolp = 1;
	return 1;
}

static unsigned char
_ecore_getopt_parse_store_false(const Ecore_Getopt * parser __UNUSED__,
				const Ecore_Getopt_Desc * desc,
				Ecore_Getopt_Value * val,
				const char *arg_val __UNUSED__)
{
	if (!val->boolp) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("value has no pointer set.\n"));
		return 0;
	}
	*val->boolp = 0;
	return 1;
}

static unsigned char
_ecore_getopt_parse_choice(const Ecore_Getopt * parser __UNUSED__,
			   const Ecore_Getopt_Desc * desc,
			   Ecore_Getopt_Value * val, const char *arg_val)
{
	const char *const *pchoice;

	if (!val->strp) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("value has no pointer set.\n"));
		return 0;
	}

	pchoice = desc->action_param.choices;
	for (; *pchoice; pchoice++)
		if (strcmp(*pchoice, arg_val) == 0) {
			*val->strp = (char *) *pchoice;
			return 1;
		}

	_ecore_getopt_desc_print_error
	    (desc, _("invalid choice \"%s\". Valid values are: "),
	     arg_val);

	pchoice = desc->action_param.choices;
	for (; *pchoice; pchoice++) {
		fputs(*pchoice, stderr);
		if (pchoice[1])
			fputs(", ", stderr);
	}

	fputs(".\n", stderr);
	return 0;
}

static unsigned char
_ecore_getopt_parse_append(const Ecore_Getopt * parser __UNUSED__,
			   const Ecore_Getopt_Desc * desc,
			   Ecore_Getopt_Value * val, const char *arg_val)
{
	void *data;
	long int v;
	double d;
	unsigned char b;

	if (!arg_val) {
		_ecore_getopt_desc_print_error
		    (desc, _("missing parameter to append.\n"));
		return 0;
	}

	if (!val->listp) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("value has no pointer set.\n"));
		return 0;
	}

	switch (desc->action_param.append_type) {
	case ECORE_GETOPT_TYPE_STR:
		data = strdup(arg_val);
		break;
	case ECORE_GETOPT_TYPE_BOOL:
		{
			if (_ecore_getopt_parse_bool(arg_val, &b)) {
				data = malloc(sizeof(unsigned char));
				if (data)
					*(unsigned char *) data = b;
			} else {
				_ecore_getopt_desc_print_error
				    (desc,
				     _("unknown boolean value %s.\n"),
				     arg_val);
				return 0;
			}
		}
		break;
	case ECORE_GETOPT_TYPE_SHORT:
		{
			if (!_ecore_getopt_parse_long(arg_val, &v))
				goto error;
			data = malloc(sizeof(short));
			if (data)
				*(short *) data = (short) v;
		}
		break;
	case ECORE_GETOPT_TYPE_INT:
		{
			if (!_ecore_getopt_parse_long(arg_val, &v))
				goto error;
			data = malloc(sizeof(int));
			if (data)
				*(int *) data = (int) v;
		}
		break;
	case ECORE_GETOPT_TYPE_LONG:
		{
			if (!_ecore_getopt_parse_long(arg_val, &v))
				goto error;
			data = malloc(sizeof(long));
			if (data)
				*(long *) data = v;
		}
		break;
	case ECORE_GETOPT_TYPE_USHORT:
		{
			if (!_ecore_getopt_parse_long(arg_val, &v))
				goto error;
			data = malloc(sizeof(unsigned short));
			if (data)
				*(unsigned short *) data =
				    (unsigned short) v;
		}
		break;
	case ECORE_GETOPT_TYPE_UINT:
		{
			if (!_ecore_getopt_parse_long(arg_val, &v))
				goto error;
			data = malloc(sizeof(unsigned int));
			if (data)
				*(unsigned int *) data = (unsigned int) v;
		}
		break;
	case ECORE_GETOPT_TYPE_ULONG:
		{
			if (!_ecore_getopt_parse_long(arg_val, &v))
				goto error;
			data = malloc(sizeof(unsigned long));
			if (data)
				*(unsigned long *) data = v;
		}
		break;
	case ECORE_GETOPT_TYPE_DOUBLE:
		{
			if (!_ecore_getopt_parse_double(arg_val, &d))
				goto error;
			data = malloc(sizeof(double));
			if (data)
				*(double *) data = d;
		}
		break;
	default:
		{
			_ecore_getopt_desc_print_error(desc,
						       _
						       ("could not parse value.\n"));
			return 0;
		}
	}

	*val->listp = eina_list_append(*val->listp, data);
	return 1;

      error:
	_ecore_getopt_desc_print_error
	    (desc, _("invalid number format %s\n"), arg_val);
	return 0;
}

static unsigned char
_ecore_getopt_parse_count(const Ecore_Getopt * parser __UNUSED__,
			  const Ecore_Getopt_Desc * desc,
			  Ecore_Getopt_Value * val,
			  const char *arg_val __UNUSED__)
{
	if (!val->intp) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("value has no pointer set.\n"));
		return 0;
	}

	(*val->intp)++;
	return 1;
}

static unsigned char
_ecore_getopt_parse_callback(const Ecore_Getopt * parser,
			     const Ecore_Getopt_Desc * desc,
			     Ecore_Getopt_Value * val, const char *arg_val)
{
	const Ecore_Getopt_Desc_Callback *cb =
	    &desc->action_param.callback;

	switch (cb->arg_req) {
	case ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO:
		arg_val = cb->def;
		break;
	case ECORE_GETOPT_DESC_ARG_REQUIREMENT_OPTIONAL:
		if (!arg_val)
			arg_val = cb->def;
		break;
	case ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES:
		break;
	}

	if (cb->arg_req != ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO) {
		if ((!arg_val) || (arg_val[0] == '\0')) {
			_ecore_getopt_desc_print_error(desc,
						       _
						       ("missing parameter.\n"));
			return 0;
		}

		if (!val->ptrp) {
			_ecore_getopt_desc_print_error
			    (desc, _("value has no pointer set.\n"));
			return 0;
		}
	}

	if (!cb->func) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("missing callback function!\n"));
		return 0;
	}

	return cb->func(parser, desc, arg_val, (void *) cb->data, val);
}

static unsigned char
_ecore_getopt_parse_help(const Ecore_Getopt * parser,
			 const Ecore_Getopt_Desc * desc __UNUSED__,
			 Ecore_Getopt_Value * val,
			 const char *arg_val __UNUSED__)
{
	if (val->boolp)
		(*val->boolp) = 1;
	ecore_getopt_help(stdout, parser);
	return 1;
}

static unsigned char
_ecore_getopt_parse_version(const Ecore_Getopt * parser,
			    const Ecore_Getopt_Desc * desc,
			    Ecore_Getopt_Value * val,
			    const char *arg_val __UNUSED__)
{
	if (val->boolp)
		(*val->boolp) = 1;
	if (!parser->version) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("no version was defined.\n"));
		return 0;
	}
	_ecore_getopt_version(stdout, parser);
	return 1;
}

static unsigned char
_ecore_getopt_parse_copyright(const Ecore_Getopt * parser,
			      const Ecore_Getopt_Desc * desc,
			      Ecore_Getopt_Value * val,
			      const char *arg_val __UNUSED__)
{
	if (val->boolp)
		(*val->boolp) = 1;
	if (!parser->copyright) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("no copyright was defined.\n"));
		return 0;
	}
	_ecore_getopt_copyright(stdout, parser);
	return 1;
}

static unsigned char
_ecore_getopt_parse_license(const Ecore_Getopt * parser,
			    const Ecore_Getopt_Desc * desc,
			    Ecore_Getopt_Value * val,
			    const char *arg_val __UNUSED__)
{
	if (val->boolp)
		(*val->boolp) = 1;
	if (!parser->license) {
		_ecore_getopt_desc_print_error(desc,
					       _
					       ("no license was defined.\n"));
		return 0;
	}
	_ecore_getopt_license(stdout, parser);
	return 1;
}

static unsigned char
_ecore_getopt_desc_handle(const Ecore_Getopt * parser,
			  const Ecore_Getopt_Desc * desc,
			  Ecore_Getopt_Value * value, const char *arg_val)
{
	switch (desc->action) {
	case ECORE_GETOPT_ACTION_STORE:
		return _ecore_getopt_parse_store(parser, desc, value,
						 arg_val);
	case ECORE_GETOPT_ACTION_STORE_CONST:
		return _ecore_getopt_parse_store_const(parser, desc, value,
						       arg_val);
	case ECORE_GETOPT_ACTION_STORE_TRUE:
		return _ecore_getopt_parse_store_true(parser, desc, value,
						      arg_val);
	case ECORE_GETOPT_ACTION_STORE_FALSE:
		return _ecore_getopt_parse_store_false(parser, desc, value,
						       arg_val);
	case ECORE_GETOPT_ACTION_CHOICE:
		return _ecore_getopt_parse_choice(parser, desc, value,
						  arg_val);
	case ECORE_GETOPT_ACTION_APPEND:
		return _ecore_getopt_parse_append(parser, desc, value,
						  arg_val);
	case ECORE_GETOPT_ACTION_COUNT:
		return _ecore_getopt_parse_count(parser, desc, value,
						 arg_val);
	case ECORE_GETOPT_ACTION_CALLBACK:
		return _ecore_getopt_parse_callback(parser, desc, value,
						    arg_val);
	case ECORE_GETOPT_ACTION_HELP:
		return _ecore_getopt_parse_help(parser, desc, value,
						arg_val);
	case ECORE_GETOPT_ACTION_VERSION:
		return _ecore_getopt_parse_version(parser, desc, value,
						   arg_val);
	case ECORE_GETOPT_ACTION_COPYRIGHT:
		return _ecore_getopt_parse_copyright(parser, desc, value,
						     arg_val);
	case ECORE_GETOPT_ACTION_LICENSE:
		return _ecore_getopt_parse_license(parser, desc, value,
						   arg_val);
	default:
		return 0;
	}
}

static unsigned char
_ecore_getopt_parse_arg_long(const Ecore_Getopt * parser,
			     Ecore_Getopt_Value * values,
			     int argc __UNUSED__, char **argv, int *idx,
			     int *nonargs, const char *arg)
{
	const Ecore_Getopt_Desc *desc;
	Ecore_Getopt_Desc_Arg_Requirement arg_req;
	const char *arg_val;
	int desc_idx;
	Ecore_Getopt_Value *value;
	unsigned char ret;

	desc = _ecore_getopt_parse_find_long(parser, arg);
	if (!desc) {
		fprintf(stderr,
			_("ERROR: unknown option --%s, ignored.\n"), arg);
		if (parser->strict)
			return 0;

		(*idx)++;
		return 1;
	}

	(*idx)++;

	arg_req = _ecore_getopt_desc_arg_requirement(desc);
	if (arg_req != ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO) {
		arg_val = strchr(arg, '=');
		if (arg_val)
			arg_val++;
		else {
			if ((*idx < *nonargs) && (argv[*idx][0] != '-')) {
				arg_val = argv[*idx];
				(*idx)++;
			} else
				arg_val = NULL;
		}

		if (arg_val && arg_val[0] == '\0')
			arg_val = NULL;

		if ((!arg_val)
		    && (arg_req ==
			ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES)) {
			fprintf(stderr,
				_
				("ERROR: option --%s requires an argument!\n"),
				arg);
			if (parser->strict)
				return 0;
			return 1;
		}
	} else
		arg_val = NULL;

	desc_idx = desc - parser->descs;
	value = values + desc_idx;
	ret = _ecore_getopt_desc_handle(parser, desc, value, arg_val);
	if ((!ret) && parser->strict)
		return 0;

	return 1;
}

static unsigned char
_ecore_getopt_parse_arg_short(const Ecore_Getopt * parser,
			      Ecore_Getopt_Value * values,
			      int argc __UNUSED__, char **argv, int *idx,
			      int *nonargs, const char *arg)
{
	int run = 1;
	while (run && (arg[0] != '\0')) {
		int opt = arg[0];
		const Ecore_Getopt_Desc *desc;
		Ecore_Getopt_Desc_Arg_Requirement arg_req;
		const char *arg_val;
		int desc_idx;
		Ecore_Getopt_Value *value;
		unsigned char ret;

		desc = _ecore_getopt_parse_find_short(parser, arg[0]);
		if (!desc) {
			fprintf
			    (stderr,
			     _("ERROR: unknown option -%c, ignored.\n"),
			     arg[0]);
			if (parser->strict)
				return 0;

			arg++;
			continue;
		}

		arg++;

		arg_req = _ecore_getopt_desc_arg_requirement(desc);
		if (arg_req != ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO) {
			(*idx)++;
			run = 0;

			if (arg[0] == '=')
				arg_val = arg + 1;
			else if (arg[0] != '\0')
				arg_val = arg;
			else {
				if ((*idx < *nonargs)
				    && (argv[*idx][0] != '-')) {
					arg_val = argv[*idx];
					(*idx)++;
				} else
					arg_val = NULL;
			}

			if (arg_val && arg_val[0] == '\0')
				arg_val = NULL;

			if ((!arg_val) &&
			    (arg_req ==
			     ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES)) {
				fprintf(stderr,
					_
					("ERROR: option -%c requires an argument!\n"),
					opt);
				if (parser->strict)
					return 0;
				return 1;
			}
		} else
			arg_val = NULL;

		desc_idx = desc - parser->descs;
		value = values + desc_idx;
		ret =
		    _ecore_getopt_desc_handle(parser, desc, value,
					      arg_val);
		if ((!ret) && parser->strict)
			return 0;
	}

	if (run)
		(*idx)++;

	return 1;
}

static unsigned char
_ecore_getopt_parse_arg(const Ecore_Getopt * parser,
			Ecore_Getopt_Value * values, int argc, char **argv,
			int *idx, int *nonargs)
{
	char *arg = argv[*idx];

	if (arg[0] != '-') {
		char **dst, **src, **src_end;

		dst = argv + *idx;
		src = dst + 1;
		src_end = src + *nonargs - *idx - 1;

		for (; src < src_end; src++, dst++)
			*dst = *src;

		*dst = arg;
		(*nonargs)--;
		return 1;
	}

	if (arg[1] == '-')
		return _ecore_getopt_parse_arg_long
		    (parser, values, argc, argv, idx, nonargs, arg + 2);
	else
		return _ecore_getopt_parse_arg_short
		    (parser, values, argc, argv, idx, nonargs, arg + 1);
}

static const Ecore_Getopt_Desc *_ecore_getopt_parse_find_short_other(const
								     Ecore_Getopt
								     *
								     parser,
								     const
								     Ecore_Getopt_Desc
								     *
								     orig)
{
	const Ecore_Getopt_Desc *desc = parser->descs;
	const char c = orig->shortname;

	for (; !_ecore_getopt_desc_is_sentinel(desc); desc++) {
		if (desc == orig)
			return NULL;

		if (c == desc->shortname)
			return desc;
	}

	return NULL;
}

static const Ecore_Getopt_Desc *_ecore_getopt_parse_find_long_other(const
								    Ecore_Getopt
								    *
								    parser,
								    const
								    Ecore_Getopt_Desc
								    * orig)
{
	const Ecore_Getopt_Desc *desc = parser->descs;
	const char *name = orig->longname;

	for (; !_ecore_getopt_desc_is_sentinel(desc); desc++) {
		if (desc == orig)
			return NULL;

		if (desc->longname && (strcmp(name, desc->longname) == 0))
			return desc;
	}

	return NULL;
}

/**
 * Check parser for duplicate entries, print them out.
 *
 * @return 1 if there are duplicates, 0 otherwise.
 */
unsigned char
ecore_getopt_parser_has_duplicates(const Ecore_Getopt * parser)
{
	const Ecore_Getopt_Desc *desc = parser->descs;
	for (; !_ecore_getopt_desc_is_sentinel(desc); desc++) {
		if (desc->shortname) {
			const Ecore_Getopt_Desc *other;
			other =
			    _ecore_getopt_parse_find_short_other(parser,
								 desc);
			if (other) {
				_ecore_getopt_desc_print_error
				    (desc,
				     "short name -%c already exists.",
				     desc->shortname);

				if (other->longname)
					fprintf(stderr,
						" Other is --%s.\n",
						other->longname);
				else
					fputc('\n', stderr);
				return 1;
			}
		}

		if (desc->longname) {
			const Ecore_Getopt_Desc *other;
			other =
			    _ecore_getopt_parse_find_long_other(parser,
								desc);
			if (other) {
				_ecore_getopt_desc_print_error
				    (desc,
				     "long name --%s already exists.",
				     desc->longname);

				if (other->shortname)
					fprintf(stderr, " Other is -%c.\n",
						other->shortname);
				else
					fputc('\n', stderr);
				return 1;
			}
		}
	}
	return 0;
}

static const Ecore_Getopt_Desc *_ecore_getopt_find_help(const Ecore_Getopt
							* parser)
{
	const Ecore_Getopt_Desc *desc = parser->descs;
	for (; !_ecore_getopt_desc_is_sentinel(desc); desc++)
		if (desc->action == ECORE_GETOPT_ACTION_HELP)
			return desc;
	return NULL;
}

/**
 * Parse command line parameters.
 *
 * Walks the command line parameters and parse them based on @a parser
 * description, doing actions based on @c parser->descs->action, like
 * showing help text, license, copyright, storing values in values and
 * so on.
 *
 * It is expected that values is of the same size than @c parser->descs,
 * options that do not need a value it will be left untouched.
 *
 * All values are expected to be initialized before use. Options with
 * action @c ECORE_GETOPT_ACTION_STORE and non required arguments
 * (others than @c ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES), are expected
 * to provide a value in @c def to be used.
 *
 * The following actions will store 1 on value as a boolean
 * (@c value->boolp) if it's not NULL to indicate these actions were executed:
 *   - @c ECORE_GETOPT_ACTION_HELP
 *   - @c ECORE_GETOPT_ACTION_VERSION
 *   - @c ECORE_GETOPT_ACTION_COPYRIGHT
 *   - @c ECORE_GETOPT_ACTION_LICENSE
 *
 * Just @c ECORE_GETOPT_ACTION_APPEND will allocate memory and thus
 * need to be freed. For consistency between all of appended subtypes,
 * @c eina_list->data will contain an allocated memory with the value,
 * that is, for @c ECORE_GETOPT_TYPE_STR it will contain a copy of the
 * argument, @c ECORE_GETOPT_TYPE_INT a pointer to an allocated
 * integer and so on.
 *
 * If parser is in strict mode (see @c Ecore_Getopt->strict), then any
 * error will abort parsing and -1 is returned. Otherwise it will try
 * to continue as far as possible.
 *
 * This function may reorder @a argv elements.
 *
 * Translation of help strings (description), metavar, usage, license
 * and copyright may be translated, standard/global gettext() call
 * will be applied on them if ecore was compiled with such support.
 *
 * @param parser description of how to work.
 * @param value where to store values, it is assumed that this is a vector
 *        of the same size as @c parser->descs. Values should be previously
 *        initialized.
 * @param argc how many elements in @a argv. If not provided it will be
 *        retrieved with ecore_app_args_get().
 * @param argv command line parameters.
 *
 * @return index of first non-option parameter or -1 on error.
 */
int
ecore_getopt_parse(const Ecore_Getopt * parser,
		   Ecore_Getopt_Value * values, int argc, char **argv)
{
	int i, nonargs;

	if (!parser) {
		fputs(_("ERROR: no parser provided.\n"), stderr);
		return -1;
	}
	if (!values) {
		fputs(_("ERROR: no values provided.\n"), stderr);
		return -1;
	}

	if ((argc < 1) || (!argv))
		ecore_app_args_get(&argc, &argv);

	if (argc < 1) {
		fputs(_("ERROR: no arguments provided.\n"), stderr);
		return -1;
	}

	if (argv[0])
		prog = argv[0];
	else
		prog = parser->prog;

	nonargs =
	    _ecore_getopt_parse_find_nonargs_base(parser, argc, argv);
	if (nonargs < 0)
		goto error;

	if (nonargs > argc)
		nonargs = argc;

	i = 1;
	while (i < nonargs)
		if (!_ecore_getopt_parse_arg
		    (parser, values, argc, argv, &i, &nonargs))
			goto error;

	return nonargs;

      error:
	{
		const Ecore_Getopt_Desc *help;
		fputs(_("ERROR: invalid options found."), stderr);

		help = _ecore_getopt_find_help(parser);
		if (!help)
			fputc('\n', stderr);
		else if (help->longname)
			fprintf(stderr, _(" See --%s.\n"), help->longname);
		else
			fprintf(stderr, _(" See -%c.\n"), help->shortname);
	}

	return -1;
}

/**
 * Utility to free list and nodes allocated by @a ECORE_GETOPT_ACTION_APPEND.
 *
 * @param list pointer to list to be freed.
 * @return always NULL, so you can easily make your list head NULL.
 */
Eina_List *ecore_getopt_list_free(Eina_List * list)
{
	void *data;

	EINA_LIST_FREE(list, data)
	    free(data);
	return NULL;
}

/**
 * Helper ecore_getopt callback to parse geometry (x:y:w:h).
 *
 * Storage must be a pointer to @c Eina_Rectangle and will be used to
 * store the four values passed in the given string.
 *
 * @c callback_data value is ignored, you can safely use @c NULL.
 */
unsigned char
ecore_getopt_callback_geometry_parse(const Ecore_Getopt *
				     parser __UNUSED__,
				     const Ecore_Getopt_Desc *
				     desc __UNUSED__, const char *str,
				     void *data __UNUSED__,
				     Ecore_Getopt_Value * storage)
{
	Eina_Rectangle *v = (Eina_Rectangle *) storage->ptrp;

	if (sscanf(str, "%d:%d:%d:%d", &v->x, &v->y, &v->w, &v->h) != 4) {
		fprintf(stderr,
			_("ERROR: incorrect geometry value '%s'\n"), str);
		return 0;
	}

	return 1;
}

/**
 * Helper ecore_getopt callback to parse geometry size (WxH).
 *
 * Storage must be a pointer to @c Eina_Rectangle and will be used to
 * store the two values passed in the given string and 0 in the x and y
 * fields.
 *
 * @c callback_data value is ignored, you can safely use @c NULL.
 */
unsigned char
ecore_getopt_callback_size_parse(const Ecore_Getopt * parser __UNUSED__,
				 const Ecore_Getopt_Desc * desc __UNUSED__,
				 const char *str, void *data __UNUSED__,
				 Ecore_Getopt_Value * storage)
{
	Eina_Rectangle *v = (Eina_Rectangle *) storage->ptrp;

	if (sscanf(str, "%dx%d", &v->w, &v->h) != 2) {
		fprintf(stderr, _("ERROR: incorrect size value '%s'\n"),
			str);
		return 0;
	}
	v->x = 0;
	v->y = 0;

	return 1;
}
