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

from typing import Mapping, Optional, TextIO, Sequence
import datetime
import io
import re
import jsonopts


def gen_option_docs(meta: Mapping[str, str],
                    options: Sequence[Mapping[str, str]]) -> str:
    docs = io.StringIO()
    for option in options:
        long_opt = option['long-option']
        long_opt_escaped = long_opt.replace('-', '\\-')
        short_opt = option.get('short-option')
        detail = option.get('detail')
        desc = option.get('desc')
        disable_prefix = option.get('disable-prefix')
        if disable_prefix:
            disable_opt: Optional[str] = f'{disable_prefix}{long_opt}'
        else:
            disable_opt = None
        alias = option.get('aliases')
        if alias:
            docs.write(f'''\
.TP
.NOP \\f\\*[B-Font]\\-\\-{long_opt_escaped}\\f[]
This is an alias for the \\fI--{alias}\\fR option.
''')
            if 'deprecated' in option:
                docs.write('''\
.sp
.B
NOTE: THIS OPTION IS DEPRECATED
''')
            continue

        arg_type = option.get('arg-type')
        if arg_type:
            arg_name = option.get('arg-name', arg_type).lower()
            arg = f'\\f\\*[I-Font]{arg_name}\\f[]'
            long_arg = f'={arg}'
            short_arg = f' {arg}'
        else:
            long_arg = ''
            short_arg = ''
        formatted_options = list()
        if short_opt:
            formatted_options.append(
                f'\\f\\*[B-Font]\\-{short_opt}\\f[]{short_arg}'
            )
        formatted_options.append(
            f'\\f\\*[B-Font]\\-\\-{long_opt_escaped}\\f[]{long_arg}'
        )
        if disable_opt:
            disable_opt_escaped = disable_opt.replace('-', '\\-')
            formatted_options.append(
                f'\\f\\*[B-Font]\\-\\-{disable_opt_escaped}\\f[]'
            )
        docs.write(f'''\
.TP
.NOP {', '.join(formatted_options)}
''')
        if desc and desc[0].isupper():
            docs.write(f'{desc}.\n')
        if 'stack-arg' in option:
            docs.write(
                'This option may appear an unlimited number of times.\n'
            )
        if arg_type == 'number':
            docs.write(
                'This option takes an integer number as its argument.\n'
            )
            arg_min = option.get('arg-min')
            arg_max = option.get('arg-max')
            if arg_min and arg_max:
                docs.write(f'''\
The value of
\\f\\*[I-Font]{arg_name}\\f[]
is constrained to being:
.in +4
.nf
.na
in the range {arg_min} through {arg_max}
.fi
.in -4
''')
        conflict_opts = option.get('conflicts', '').split()
        if len(conflict_opts) > 0:
            docs.write(f'''\
This option must not appear in combination with any of the following options:
{', '.join(conflict_opts)}.
''')
        require_opts = option.get('requires', '').split()
        if len(require_opts) > 0:
            docs.write(f'''\
This option must appear in combination with the following options:
{', '.join(require_opts)}.
''')
        if disable_opt:
            disable_opt_escaped = disable_opt.replace('-', '\\-')
            docs.write((
                f'The \\fI{disable_opt_escaped}\\fP form '
                'will disable the option.\n'
            ))
        if 'enabled' in option:
            docs.write('This option is enabled by default.\n')
        if desc and desc[0].isupper():
            docs.write('.sp\n')
        if detail:
            docs.write(f'{text_to_man(detail)}\n')
        if 'deprecated' in option:
            docs.write('''\
.sp
.B
NOTE: THIS OPTION IS DEPRECATED
''')
    return docs.getvalue()


def text_to_man(s: str) -> str:
    s = re.sub(r'-', r'\\-', s)
    s = re.sub(r'(?m)^$', r'.sp', s)
    s = re.sub(r"``(.*)''", r'\\(lq\1\\(rq', s)
    return s


def texi_to_man(s: str) -> str:
    s = text_to_man(s)
    s = re.sub(r'@([{}@])', r'\1', s)
    s = re.sub(r'@code\{(.*?)\}', r'\\fB\1\\fP', s)
    s = re.sub(r'@file\{(.*?)\}', r'\\fI\1\\fP', s)
    s = re.sub(r'@subheading (.*)', r'''.br
\\fB\1\\fP
.br''', s)
    s = re.sub(r'@example', r'''.br
.in +4
.nf''', s)
    s = re.sub(r'@end example', r'''.in -4
.fi''', s)
    return s


def include(name: str, includes: Mapping[str, TextIO]) -> str:
    docs = io.StringIO()
    f = includes.get(name)
    if f:
        docs.write(texi_to_man(f.read().strip()))
    return docs.getvalue()


LICENSES = {
    'gpl3+': 'the GNU General Public License, version 3 or later',
}


def gen(infile: TextIO,
        meta: Mapping[str, str],
        includes: Mapping[str, TextIO],
        man: TextIO):
    sections = [jsonopts.Section.from_json(section)
                for section in json.load(args.json)]
    sections.append(jsonopts.Section.default())

    prog_name = sections[0].meta['prog-name']
    prog_title = sections[0].meta['prog-title']
    argument = sections[0].meta.get('argument')
    authors = meta.get('authors', 'AUTHORS')
    copyright_year = meta.get('copyright-year',
                              str(datetime.date.today().year))
    copyright_holder = meta.get('copyright-holder', 'COPYRIGHT HOLDER')
    license_text = LICENSES.get(meta['license'])
    version = meta.get('version', '')
    description = includes.get('description')
    if description:
        detail = texi_to_man(description.read())
    else:
        detail = sections[0].meta['detail']

    section_docs = io.StringIO()
    for section in sections:
        section_id = section.meta.get('id', '')
        if section_id:
            section_desc = section.meta['desc']
            option_docs = gen_option_docs(sections[0].meta, section.options)
            section_docs.write(f'''\
.SS "{section_desc}"
{option_docs}\
''')
        else:
            section_docs.write(gen_option_docs(sections[0].meta,
                                               section.options))

    formatted_date = datetime.date.today().strftime('%d %b %Y')
    detail_concatenated = '\n.sp\n'.join(detail.strip().split('\n\n'))
    man.write(f'''\
.de1 NOP
.  it 1 an-trap
.  if \\\\n[.$] \\,\\\\$*\\/
..
.ie t \\
.ds B-Font [CB]
.ds I-Font [CI]
.ds R-Font [CR]
.el \\
.ds B-Font B
.ds I-Font I
.ds R-Font R
.TH {prog_name} 1 "{formatted_date}" "{version}" "User Commands"
.SH NAME
\\f\\*[B-Font]{prog_name}\\fP
\\- {prog_title}
.SH SYNOPSIS
\\f\\*[B-Font]{prog_name}\\fP
.\\" Mixture of short (flag) options and long options
[\\f\\*[B-Font]\\-flags\\f[]]
[\\f\\*[B-Font]\\-flag\\f[] [\\f\\*[I-Font]value\\f[]]]
[\\f\\*[B-Font]\\-\\-option-name\\f[][[=| ]\\f\\*[I-Font]value\\f[]]]
''')
    if argument:
        man.write(f'''\
{argument}
.sp \\n(Ppu
.ne 2

Operands and options may be intermixed.  They will be reordered.
.sp \\n(Ppu
.ne 2
''')
    else:
        man.write('''\
.sp \\n(Ppu
.ne 2

All arguments must be options.
.sp \\n(Ppu
.ne 2
''')
    man.write(f'''\
.SH "DESCRIPTION"
{detail_concatenated}
.sp
.SH "OPTIONS"
{section_docs.getvalue()}
''')
    if 'files' in includes:
        man.write(f'''\
.SH FILES
{include('files', includes)}
''')
    if 'examples' in includes:
        man.write(f'''\
.sp
.SH EXAMPLES
{include('examples', includes)}
''')
    man.write('''\
.SH "EXIT STATUS"
One of the following exit values will be returned:
.TP
.NOP 0 " (EXIT_SUCCESS)"
Successful program execution.
.TP
.NOP 1 " (EXIT_FAILURE)"
The operation failed or the command syntax was not valid.
.PP
''')
    if 'see-also' in includes:
        man.write(f'''\
.SH "SEE ALSO"
{include('see-also', includes)}
''')
    man.write(f'''\
.SH "AUTHORS"
{authors}
.SH "COPYRIGHT"
Copyright (C) {copyright_year} {copyright_holder}
This program is released under the terms of {license_text}.
''')
    bug_email = meta.get('bug-email')
    if bug_email:
        man.write(f'''\
.SH "BUGS"
Please send bug reports to: {bug_email}
''')


if __name__ == '__main__':
    import argparse
    import json

    parser = argparse.ArgumentParser(description='generate man-page')
    parser.add_argument('json', type=argparse.FileType('r'))
    parser.add_argument('man', type=argparse.FileType('w'))
    parser.add_argument('--description', type=argparse.FileType('r'))
    parser.add_argument('--see-also', type=argparse.FileType('r'))
    parser.add_argument('--examples', type=argparse.FileType('r'))
    parser.add_argument('--files', type=argparse.FileType('r'))
    parser.add_argument('--authors', help='authors')
    parser.add_argument('--bug-email', help='bug report email address')
    parser.add_argument('--copyright-year', help='copyright year')
    parser.add_argument('--copyright-holder', help='copyright holder')
    parser.add_argument('--license', help='license')
    parser.add_argument('--version', help='version')

    args = parser.parse_args()
    includes = dict()
    if args.see_also:
        includes['see-also'] = args.see_also
    if args.examples:
        includes['examples'] = args.examples
    if args.files:
        includes['files'] = args.files
    if args.description:
        includes['description'] = args.description
    meta = dict()
    if args.authors:
        meta['authors'] = args.authors
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

    gen(args.json, meta, includes, args.man)
