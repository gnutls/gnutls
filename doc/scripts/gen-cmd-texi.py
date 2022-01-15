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

from typing import Mapping, Sequence, TextIO
import io
import jsonopts

HEADINGS = ['@heading', '@subheading', '@subsubheading']


def get_heading(level: int) -> str:
    return HEADINGS[min(level, len(HEADINGS)-1)]


SECTIONS = ['@section', '@subsection', '@subsubsection']


def get_section(level: int) -> str:
    return SECTIONS[min(level, len(SECTIONS)-1)]


def shift_headings(s: str, level: int) -> str:
    for (i, h) in reversed(list(enumerate(HEADINGS))):
        r = get_heading(level+i)
        s = s.replace(h, r)
    return s


def gen_option_docs(meta: Mapping[str, str],
                    level: int,
                    options: Sequence[Mapping[str, str]]) -> str:
    prog_name = meta['prog-name']
    docs = io.StringIO()
    for option in options:
        long_opt = option['long-option']
        short_opt = option.get('short-option')
        detail = option.get('detail')
        desc = option.get('desc')
        alias = option.get('aliases')
        if alias:
            docs.write(f'''\
{get_heading(level+1)} {long_opt} option.
@anchor{{{prog_name} {long_opt}}}

This is an alias for the @code{{{alias}}} option,
@pxref{{{prog_name} {alias}, the {alias} option documentation}}.

''')
            continue

        if not detail or not desc:
            continue
        if short_opt:
            docs.write(
                f'{get_heading(level+1)} {long_opt} option (-{short_opt}).\n'
            )
        else:
            docs.write(f'{get_heading(level+1)} {long_opt} option.\n')
        docs.write(f'''\
@anchor{{{prog_name} {long_opt}}}

This is the ``{desc.lower()}'' option.
''')
        arg_type = option.get('arg-type')
        if arg_type:
            arg_name = option.get('arg-name')
            if arg_name:
                docs.write((
                    f'This option takes a {arg_type} argument '
                    f'@file{{{arg_name}}}.\n'
                ))
            else:
                docs.write(f'This option takes a {arg_type} argument.\n')

        conflict_opts = option.get('conflicts', '').split()
        require_opts = option.get('requires', '').split()
        disable_prefix = option.get('disable-prefix')
        if len(conflict_opts) > 0 or len(require_opts) > 0 or \
           ('enabled' in option):
            docs.write('''
@noindent
This option has some usage constraints.  It:
@itemize @bullet
''')
            if len(conflict_opts) > 0:
                docs.write(f'''\
@item
must not appear in combination with any of the following options:
{', '.join(conflict_opts)}.
''')
            if len(require_opts) > 0:
                docs.write(f'''\
@item
must appear in combination with the following options:
{', '.join(require_opts)}.
''')
            if disable_prefix:
                docs.write(f'''\
@item
can be disabled with --{disable_prefix}{long_opt}.
''')
            if 'enabled' in option:
                docs.write('''\
@item
It is enabled by default.
''')
            docs.write('@end itemize\n\n')

        docs.write(f'''\
{detail}
''')
        if 'deprecated' in option:
            docs.write('\n@strong{NOTE}@strong{: THIS OPTION IS DEPRECATED}\n')

    return docs.getvalue()


LABELS = {
    'see-also': 'See Also',
    'examples': 'Examples',
    'files': 'Files'
}


def include(meta: Mapping[str, str],
            level: int,
            name: str,
            includes: Mapping[str, TextIO]) -> str:
    prog_name = meta['prog-name']
    docs = io.StringIO()
    f = includes.get(name)
    if f:
        docs.write(f'''\
@anchor{{{prog_name} {LABELS[name]}}}
{get_heading(level+2)} {prog_name} {LABELS[name]}
{shift_headings(f.read(), level)}\
''')
    return docs.getvalue()


def escape_texi(s: str) -> str:
    for c in ['@', '{', '}']:
        s = s.replace(c, f'@{c}')
    return s


def gen(infile: TextIO,
        level: int,
        section_node: bool,
        includes: Mapping[str, TextIO],
        texi: TextIO):
    sections = [jsonopts.Section.from_json(section)
                for section in json.load(args.json)]
    sections.append(jsonopts.Section.default())

    prog_name = sections[0].meta['prog-name']
    description = includes.get('description')
    if description:
        detail = description.read()
    else:
        detail = sections[0].meta['detail']

    section_docs = io.StringIO()
    for section in sections:
        section_id = section.meta.get('id', '')
        if section_id:
            section_desc = section.meta['desc']
            option_docs = gen_option_docs(sections[0].meta, level+1,
                                          section.options)
            section_docs.write(f'''\
@anchor{{{prog_name} {section_id}}}
{get_heading(level+1)} {section_id} options
{section_desc if section_desc.endswith('.') else section_desc + '.'}
{option_docs}\
''')
        else:
            section_docs.write(gen_option_docs(sections[0].meta, level,
                                               section.options))

    heading = get_section(level) if section_node else get_heading(level)
    texi.write(f'''\
@node {prog_name} Invocation
{heading} Invoking {prog_name}
@pindex {prog_name}

{detail}

@anchor{{{prog_name} usage}}
{get_heading(level+1)} {prog_name} help/usage (@option{{-?}})
@cindex {prog_name} help

The text printed is the same whether selected with the @code{{help}} option
(@option{{--help}}) or the @code{{more-help}} option \
(@option{{--more-help}}).  @code{{more-help}} will print
the usage text by passing it through a pager program.
@code{{more-help}} is disabled on platforms without a working
@code{{fork(2)}} function.  The @code{{PAGER}} environment variable is
used to select the program, defaulting to @file{{more}}.  Both will exit
with a status code of 0.

@exampleindent 0
@example
{escape_texi(jsonopts.usage(sections[0].meta, sections))}
@end example
@exampleindent 4

{section_docs.getvalue()}\
@anchor{{{prog_name} exit status}}
{get_heading(level+1)} {prog_name} exit status

One of the following exit values will be returned:
@table @samp
@item 0 (EXIT_SUCCESS)
Successful program execution.
@item 1 (EXIT_FAILURE)
The operation failed or the command syntax was not valid.
@end table
''')
    if 'see-also' in includes:
        texi.write(include(sections[0].meta, level, 'see-also', includes))
    if 'examples' in includes:
        texi.write(include(sections[0].meta, level, 'examples', includes))
    if 'files' in includes:
        texi.write(include(sections[0].meta, level, 'files', includes))


if __name__ == '__main__':
    import argparse
    import json

    parser = argparse.ArgumentParser(description='generate texinfo')
    parser.add_argument('json', type=argparse.FileType('r'))
    parser.add_argument('texi', type=argparse.FileType('w'))
    parser.add_argument('--description', type=argparse.FileType('r'))
    parser.add_argument('--see-also', type=argparse.FileType('r'))
    parser.add_argument('--examples', type=argparse.FileType('r'))
    parser.add_argument('--files', type=argparse.FileType('r'))
    parser.add_argument('--level', type=int, default=0)
    parser.add_argument('--section-node', action='store_true')

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
    gen(args.json, args.level, args.section_node, includes, args.texi)
