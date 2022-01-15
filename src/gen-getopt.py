#!/usr/bin/python
# Copyright (C) 2021 Daiki Ueno

# This file is part of GnuTLS.

# GnuTLS is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see
# <https://www.gnu.org/licenses/>.

from typing import Mapping, MutableMapping, MutableSequence, Sequence
from typing import TextIO, Union
import io
import os.path
import jsonopts
import sys

INDENT = '  '


def get_aliases(options) -> Mapping[str, Sequence[str]]:
    aliases: MutableMapping[str, MutableSequence[str]] = dict()
    for option in options:
        long_opt = option['long-option']
        key = option.get('aliases')
        if key:
            val = aliases.get(key, list())
            val.append(long_opt)
            aliases[key] = val
    return aliases


def get_chars(options) -> Mapping[str, Union[str, int]]:
    chars = dict()
    chars_counter = 1
    short_opts: MutableMapping[str, str] = dict()
    for option in options:
        long_opt = option['long-option']
        short_opt = option.get('short-option')
        # If the short option is already taken, do not register twice
        if short_opt and short_opt in short_opts:
            print((f'short option {short_opt} for {long_opt} is already '
                   f'taken by {short_opts[short_opt]}'),
                  file=sys.stderr)
            short_opt = None
        if short_opt:
            chars[long_opt] = short_opt
            short_opts[short_opt] = long_opt
        else:
            chars[long_opt] = chars_counter
            chars_counter += 1
        disable_prefix = option.get('disable-prefix')
        if disable_prefix:
            chars[f'{disable_prefix}{long_opt}'] = chars_counter
            chars_counter += 1
    return chars


def mangle(name: str) -> str:
    return ''.join([c if c in 'abcdefghijklmnopqrstuvwxyz0123456789_' else '_'
                    for c in name.lower()])


def format_long_opt(c: Union[str, int], long_opt: str, has_arg: str) -> str:
    if isinstance(c, str):
        return f"{INDENT}{{ \"{long_opt}\", {has_arg}, 0, '{c}' }},\n"
    else:
        return f'{INDENT}{{ "{long_opt}", {has_arg}, 0, CHAR_MAX + {c} }},\n'


def format_switch_case(c: Union[str, int], long_opt: str) -> str:
    if isinstance(c, str):
        return f"{INDENT*3}case '{c}':\n"
    else:
        return f'{INDENT*3}case CHAR_MAX + {c}: /* --{long_opt} */\n'


def gen_c(meta: Mapping[str, str],
          options: Sequence[Mapping[str, str]],
          aliases: Mapping[str, Sequence[str]],
          usage: str,
          outfile: TextIO):
    long_opts = io.StringIO()
    short_opts = list()
    switch_cases = io.StringIO()
    enable_statements = io.StringIO()
    constraint_statements = io.StringIO()
    has_list_arg = False
    has_number_arg = False

    chars = get_chars(options)

    prog_name = meta['prog-name']
    struct_name = f'{mangle(prog_name)}_opts'
    global_name = f'{mangle(prog_name)}Options'

    switch_cases.write(f"{INDENT*3}case '\\0': /* Long option.  */\n")
    switch_cases.write(f'{INDENT*4}break;\n')

    for option in options:
        long_opt = option['long-option']
        arg_type = option.get('arg-type')
        lower_opt = mangle(long_opt)
        upper_opt = lower_opt.upper()

        # aliases are handled differently
        if 'aliases' in option:
            continue

        if arg_type:
            if 'arg-optional' in option:
                has_arg = 'optional_argument'
            else:
                has_arg = 'required_argument'
        else:
            has_arg = 'no_argument'

        c = chars[long_opt]

        if isinstance(c, str):
            if arg_type:
                short_opts.append(c + ':')
            else:
                short_opts.append(c)

        long_opts.write(format_long_opt(c, long_opt, has_arg))
        switch_cases.write(format_switch_case(c, long_opt))

        for alias in aliases.get(long_opt, list()):
            c = chars[alias]
            long_opts.write(format_long_opt(c, alias, has_arg))
            switch_cases.write(format_switch_case(c, alias))

        switch_cases.write(f'{INDENT*4}opts->present.{lower_opt} = true;\n')

        if arg_type:
            if 'stack-arg' in option:
                has_list_arg = True
                switch_cases.write((
                    f'{INDENT*4}append_to_list (&opts->list.{lower_opt}, '
                    f'"{long_opt}", optarg);\n'
                ))
            else:
                switch_cases.write(
                    f'{INDENT*4}opts->arg.{lower_opt} = optarg;\n'
                )
                if arg_type == 'number':
                    has_number_arg = True
                    switch_cases.write((
                        f'{INDENT*4}opts->value.{lower_opt} = '
                        'parse_number(optarg);\n'
                    ))
        if 'enabled' in option or 'disabled' in option:
            switch_cases.write(
                f'{INDENT*4}opts->enabled.{lower_opt} = true;\n'
            )

        switch_cases.write(f'{INDENT*4}break;\n')

        if 'enabled' in option:
            enable_statements.write(
                f'{INDENT}opts->enabled.{lower_opt} = true;\n'
            )
        disable_prefix = option.get('disable-prefix')
        if disable_prefix:
            disable_opt = f'{disable_prefix}{long_opt}'
            c = chars[disable_opt]
            long_opts.write(format_long_opt(c, disable_opt, has_arg))
            switch_cases.write(format_switch_case(c, disable_opt))
            switch_cases.write(
                f'{INDENT*4}opts->present.{lower_opt} = true;\n'
            )
            switch_cases.write(
                f'{INDENT*4}opts->enabled.{lower_opt} = false;\n'
            )
            switch_cases.write(f'{INDENT*4}break;\n')

        conflict_opts = option.get('conflicts', '').split()
        for conflict_opt in conflict_opts:
            constraint_statements.write(f'''\
{INDENT}if (HAVE_OPT({upper_opt}) && HAVE_OPT({mangle(conflict_opt).upper()}))
{INDENT*2}{{
{INDENT*3}error (EXIT_FAILURE, 0, "the '%s' and '%s' options conflict",
{INDENT*3}       "{long_opt}", "{mangle(conflict_opt)}");
{INDENT*2}}}
''')
        require_opts = option.get('requires', '').split()
        for require_opt in require_opts:
            constraint_statements.write(f'''\
{INDENT}if (HAVE_OPT({upper_opt}) && !HAVE_OPT({mangle(require_opt).upper()}))
{INDENT*2}{{
{INDENT*3}error (EXIT_FAILURE, 0, "%s option requires the %s options",
{INDENT*3}       "{long_opt}", "{mangle(require_opt)}");
{INDENT*2}}}
''')
        arg_min = option.get('arg-min')
        if arg_min:
            constraint_statements.write(f'''\
{INDENT}if (HAVE_OPT({upper_opt}) && OPT_VALUE_{upper_opt} < {int(arg_min)})
{INDENT*2}{{
{INDENT*3}error (EXIT_FAILURE, 0, "%s option value %d is out of range.",
{INDENT*3}       "{long_opt}", opts->value.{lower_opt});
{INDENT*2}}}
''')
        arg_max = option.get('arg-max')
        if arg_max:
            constraint_statements.write(f'''\
{INDENT}if (HAVE_OPT({upper_opt}) && OPT_VALUE_{upper_opt} > {int(arg_max)})
{INDENT*2}{{
{INDENT*3}error (EXIT_FAILURE, 0, "%s option value %d is out of range",
{INDENT*3}       "{long_opt}", opts->value.{lower_opt});
{INDENT*2}}}
''')

    long_opts.write(f'{INDENT}{{ 0, 0, 0, 0 }}\n')

    switch_cases.write(f'{INDENT*3}default:\n')
    switch_cases.write(f'{INDENT*4}usage (stderr, EXIT_FAILURE);\n')
    switch_cases.write(f'{INDENT*4}break;\n')

    argument = meta.get('argument')
    if argument:
        if argument.startswith('[') and argument.endswith(']'):
            argument = argument[1:-1]
            argument_statement = ''
        else:
            argument_statement = f'''\
{INDENT}if (optind == argc)
{INDENT*2}{{
{INDENT*3}error (EXIT_FAILURE, 0, "Command line arguments required");
{INDENT*2}}}
'''
    else:
        argument_statement = f'''\
{INDENT}if (optind < argc)
{INDENT*2}{{
{INDENT*3}error (EXIT_FAILURE, 0, "Command line arguments are not allowed.");
{INDENT*2}}}
'''

    short_opts_concatenated = ''.join(sorted(short_opts))
    usage_stringified = '\n'.join([
        f'{INDENT*2}"{line}\\n"' for line in usage.split('\n')
    ])
    brief_version = jsonopts.version(meta, 'v')
    version = jsonopts.version(meta, 'c')
    full_version = jsonopts.version(meta, 'n')
    brief_version_stringified = '\n'.join([
        f'{INDENT*6}"{line}\\n"' for line in brief_version.split('\n')
    ])
    version_stringified = '\n'.join([
        f'{INDENT*6}"{line}\\n"' for line in version.split('\n')
    ])
    full_version_stringified = '\n'.join([
        f'{INDENT*6}"{line}\\n"' for line in full_version.split('\n')
    ])

    outfile.write(f'''\
/* This file is auto-generated from {meta['infile']}; do not edit */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "{meta['header']}"
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif /* !_WIN32 */
#include "xsize.h"

struct {struct_name} {global_name};

''')

    if has_list_arg:
        outfile.write(f'''\
static void
append_to_list (struct {mangle(prog_name)}_list *list,
                const char *name, const char *arg)
{{
{INDENT}const char **tmp;
{INDENT}size_t new_count = xsum (list->count, 1);

{INDENT}if (size_overflow_p (new_count))
{INDENT*2}error (EXIT_FAILURE, 0, "too many arguments for %s",
{INDENT*2}       name);

{INDENT}tmp = reallocarray (list->args, new_count, sizeof (char *));
{INDENT}if (!tmp)
{INDENT*2}error (EXIT_FAILURE, 0, "unable to allocate memory for %s",
{INDENT*2}       name);

{INDENT}list->args = tmp;
{INDENT}list->args[list->count] = optarg;
{INDENT}list->count = new_count;
}}

''')

    if has_number_arg:
        outfile.write(f'''\
static long
parse_number (const char *arg)
{{
{INDENT}char *endptr = NULL;
{INDENT}errno = 0;
{INDENT}long result;

{INDENT}if (strncmp (arg, "0x", 2) == 0)
{INDENT*2}result = strtol (arg + 2, &endptr, 16);
{INDENT}else if (strncmp (arg, "0", 1) == 0
{INDENT}         && strspn (arg, "012345678") == strlen (optarg))
{INDENT*2}result = strtol (arg + 1, &endptr, 8);
{INDENT}else
{INDENT*2}result = strtol (arg, &endptr, 10);

{INDENT}if (errno != 0 || (endptr && *endptr != '\\0'))
{INDENT*2}error (EXIT_FAILURE, errno, "'%s' is not a recognizable number.",
{INDENT*2}       arg);

{INDENT}return result;
}}

''')

    outfile.write(f'''\
/* Long options.  */
static const struct option long_options[] =
{{
{long_opts.getvalue()}
}};

int
optionProcess (struct {struct_name} *opts, int argc, char **argv)
{{
{INDENT}int opt;

{enable_statements.getvalue().rstrip()}
{INDENT}while ((opt = getopt_long (argc, argv, "{short_opts_concatenated}",
{INDENT}                           long_options, NULL)) != EOF)
{INDENT*2}switch (opt)
{INDENT*3}{{
{switch_cases.getvalue().rstrip()}
{INDENT*3}}}

{constraint_statements.getvalue().rstrip()}
{argument_statement}

{INDENT}if (HAVE_OPT(HELP))
{INDENT*2}{{
{INDENT*3}USAGE(0);
{INDENT*2}}}

{INDENT}if (HAVE_OPT(MORE_HELP))
#ifdef _WIN32
{INDENT*2}{{
{INDENT*3}USAGE(0);
{INDENT*2}}}
#else /* _WIN32 */
{INDENT*2}{{
{INDENT*3}pid_t pid;
{INDENT*3}int pfds[2];

{INDENT*3}if (pipe (pfds) < 0)
{INDENT*4}error (EXIT_FAILURE, errno, "pipe");

{INDENT*3}pid = fork ();
{INDENT*3}if (pid < 0)
{INDENT*4}error (EXIT_FAILURE, errno, "fork");

{INDENT*3}if (pid == 0)
{INDENT*4}{{
{INDENT*5}close (pfds[0]);
{INDENT*5}dup2 (pfds[1], STDOUT_FILENO);
{INDENT*5}close (pfds[1]);

{INDENT*5}usage (stdout, 0);
{INDENT*4}}}
{INDENT*3}else
{INDENT*4}{{
{INDENT*5}const char *args[2];
{INDENT*5}const char *envvar;

{INDENT*5}close (pfds[1]);
{INDENT*5}dup2 (pfds[0], STDIN_FILENO);
{INDENT*5}close (pfds[0]);

{INDENT*5}envvar = secure_getenv ("PAGER");
{INDENT*5}if (!envvar || *envvar == '\\0')
{INDENT*6}args[0] = "more";
{INDENT*5}else
{INDENT*6}args[0] = envvar;

{INDENT*5}args[1] = NULL;

{INDENT*5}execvp (args[0], (char * const *)args);

{INDENT*5}exit (EXIT_FAILURE);
{INDENT*4}}}
{INDENT*2}}}
#endif /* !_WIN32 */

{INDENT}if (HAVE_OPT(VERSION))
{INDENT*2}{{
{INDENT*3}if (!OPT_ARG_VERSION || !strcmp (OPT_ARG_VERSION, "c"))
{INDENT*4}{{
{INDENT*5}const char str[] =
{version_stringified};
{INDENT*5}fprintf (stdout, "%s", str);
{INDENT*5}exit(0);
{INDENT*4}}}
{INDENT*3}else if (!strcmp (OPT_ARG_VERSION, "v"))
{INDENT*4}{{
{INDENT*5}const char str[] =
{brief_version_stringified};
{INDENT*5}fprintf (stdout, "%s", str);
{INDENT*5}exit(0);
{INDENT*4}}}
{INDENT*3}else if (!strcmp (OPT_ARG_VERSION, "n"))
{INDENT*4}{{
{INDENT*5}const char str[] =
{full_version_stringified};
{INDENT*5}fprintf (stdout, "%s", str);
{INDENT*5}exit(0);
{INDENT*4}}}
{INDENT*3}else
{INDENT*4}{{
{INDENT*5}error (EXIT_FAILURE, 0,
{INDENT*5}       "version option argument 'a' invalid.  Use:\\n"
{INDENT*5}       "	'v' - version only\\n"
{INDENT*5}       "	'c' - version and copyright\\n"
{INDENT*5}       "	'n' - version and full copyright notice");
{INDENT*4}}}
{INDENT*2}}}

{INDENT}return optind;
}}

void
usage (FILE *out, int status)
{{
{INDENT}const char str[] =
{usage_stringified};
{INDENT}fprintf (out, "%s", str);
{INDENT}exit (status);
}}
''')


def gen_h(meta: Mapping[str, str],
          options: Sequence[Mapping[str, str]],
          aliases: Mapping[str, Sequence[str]],
          outfile: TextIO):
    struct_members_present = io.StringIO()
    struct_members_arg = io.StringIO()
    struct_members_value = io.StringIO()
    struct_members_enabled = io.StringIO()
    struct_members_list = io.StringIO()
    have_opts = io.StringIO()
    opt_args = io.StringIO()
    opt_values = io.StringIO()
    enabled_opts = io.StringIO()
    stackct_opts = io.StringIO()
    stacklst_opts = io.StringIO()

    prog_name = meta['prog-name']
    struct_name = f'{mangle(prog_name)}_opts'
    global_name = f'{mangle(prog_name)}Options'
    list_struct_name = f'{mangle(prog_name)}_list'

    for option in options:
        long_opt = option['long-option']
        arg_type = option.get('arg-type')
        lower_opt = mangle(long_opt)
        upper_opt = lower_opt.upper()

        # aliases are handled differently
        if 'aliases' in option:
            continue

        struct_members_present.write(f'{INDENT*2}bool {lower_opt};\n')

        if arg_type:
            if 'stack-arg' in option:
                struct_members_list.write(
                    f'{INDENT*2}struct {list_struct_name} {lower_opt};\n'
                )
                stackct_opts.write((
                    f'#define STACKCT_OPT_{upper_opt} '
                    f'{global_name}.list.{lower_opt}.count\n'
                ))
                stacklst_opts.write((
                    f'#define STACKLST_OPT_{upper_opt} '
                    f'{global_name}.list.{lower_opt}.args\n'
                ))
            else:
                struct_members_arg.write(
                    f'{INDENT*2}const char *{lower_opt};\n'
                )
                if arg_type == 'number':
                    struct_members_value.write(f'{INDENT*2}int {lower_opt};\n')
                    opt_values.write((
                        f'#define OPT_VALUE_{upper_opt} '
                        f'{global_name}.value.{lower_opt}\n'
                    ))

        if 'enabled' in option or 'disabled' in option:
            struct_members_enabled.write(f'{INDENT*2}bool {lower_opt};\n')
            enabled_opts.write((
                f'#define ENABLED_OPT_{upper_opt} '
                f'{global_name}.enabled.{lower_opt}\n'
            ))

        have_opts.write((
            f'#define HAVE_OPT_{upper_opt} '
            f'{global_name}.present.{lower_opt}\n'
        ))
        opt_args.write((
            f'#define OPT_ARG_{upper_opt} '
            f'{global_name}.arg.{lower_opt}\n'
        ))

    header_guard = f'{mangle(meta["header"]).upper()}_'

    outfile.write(f'''\
/* This file is auto-generated from {meta["infile"]}; do not edit */
#include <stdbool.h>
#include <stdio.h>

#ifndef {header_guard}
#define {header_guard} 1

struct {list_struct_name}
{{
{INDENT}const char **args;
{INDENT}unsigned int count;
}};

struct {struct_name}
{{
{INDENT}/* Options present in the command line */
{INDENT}struct
{INDENT}{{
{struct_members_present.getvalue().rstrip()}
{INDENT}}} present;

{INDENT}/* Option arguments in raw string form */
{INDENT}struct
{INDENT}{{
{struct_members_arg.getvalue().rstrip()}
{INDENT}}} arg;

{INDENT}/* Option arguments parsed as integer */
{INDENT}struct
{INDENT}{{
{struct_members_value.getvalue().rstrip()}
{INDENT}}} value;

{INDENT}/* Option arguments parsed as list */
{INDENT}struct
{INDENT}{{
{struct_members_list.getvalue().rstrip()}
{INDENT}}} list;

{INDENT}/* Option enablement status */
{INDENT}struct
{INDENT}{{
{struct_members_enabled.getvalue().rstrip()}
{INDENT}}} enabled;
}};

#define HAVE_OPT(name) HAVE_OPT_ ## name
#define OPT_ARG(name) OPT_ARG_ ## name
#define ENABLED_OPT(name) ENABLED_OPT_ ## name
#define STACKCT_OPT(name) STACKCT_OPT_ ## name
#define STACKLST_OPT(name) STACKLST_OPT_ ## name
#define USAGE(status) usage (stdout, (status))

{have_opts.getvalue()}
{opt_args.getvalue()}
{opt_values.getvalue()}
{enabled_opts.getvalue()}
{stackct_opts.getvalue()}
{stacklst_opts.getvalue()}

extern struct {struct_name} {global_name};
int optionProcess(struct {struct_name} *opts, int argc, char **argv);
void usage (FILE *out, int status);

#endif /* {header_guard} */
''')


def gen(infile: TextIO, meta: Mapping[str, str], c: TextIO, h: TextIO):
    sections = [jsonopts.Section.from_json(section)
                for section in json.load(args.json)]
    sections.append(jsonopts.Section.default())
    meta = {
        **meta,
        **sections[0].meta,
        **{
            'header': os.path.basename(h.name),
            'infile': os.path.basename(infile.name)
        }
    }
    options = [option for section in sections for option in section.options]
    aliases = get_aliases(options)
    usage = jsonopts.usage(meta, sections)
    gen_c(meta, options, aliases, usage, c)
    gen_h(meta, options, aliases, h)


if __name__ == '__main__':
    import argparse
    import json

    parser = argparse.ArgumentParser(description='generate getopt wrapper')
    parser.add_argument('json', type=argparse.FileType('r'))
    parser.add_argument('c', type=argparse.FileType('w'))
    parser.add_argument('h', type=argparse.FileType('w'))
    parser.add_argument('--bug-email', help='bug report email address')
    parser.add_argument('--copyright-year', help='copyright year')
    parser.add_argument('--copyright-holder', help='copyright holder')
    parser.add_argument('--license', help='license')
    parser.add_argument('--version', help='version')

    args = parser.parse_args()
    meta = dict()
    if args.bug_email:
        meta['bug-email'] = args.bug_email
    if args.copyright_year:
        meta['copyright-year'] = args.copyright_year
    if args.copyright_holder:
        meta['copyright-holder'] = args.copyright_holder
    if args.license:
        meta['license'] = args.license
    if args.version:
        meta['version'] = args.version

    gen(args.json, meta, args.c, args.h)
