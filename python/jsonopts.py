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

from typing import Mapping, NamedTuple, Optional, Sequence
import datetime
import io
import textwrap


class Section(NamedTuple):
    meta: Mapping[str, str]
    options: Sequence[Mapping[str, str]]

    @classmethod
    def from_json(cls, json):
        return cls(meta=json['meta'], options=json['options'])

    @classmethod
    def default(cls):
        return DEFAULT_SECTION


# Default options
DEFAULT_SECTION = Section(
    meta={
        'desc': 'Version, usage and configuration options',
    },
    options=[{
        'long-option': 'version',
        'short-option': 'v',
        'arg-type': 'keyword',
        'arg-optional': '',
        'desc': 'output version information and exit',
        'detail': textwrap.fill(textwrap.dedent("""\
            Output version of program and exit.
            The default mode is `v', a simple version.
            The `c' mode will print copyright information and
            `n' will print the full copyright notice.\
        """), width=72, fix_sentence_endings=True)
    }, {
        'long-option': 'help',
        'short-option': 'h',
        'desc': 'display extended usage information and exit',
        'detail': 'Display usage information and exit.'
    }, {
        'long-option': 'more-help',
        'short-option': '!',
        'desc': 'extended usage information passed thru pager',
        'detail': 'Pass the extended usage information through a pager.'
    }]
)

ARG_TYPE_TO_VALUE = {
    'string': 'str',
    'number': 'num',
    'file': 'file',
    'keyword': 'arg',
}


def default_arg_name(s: str) -> str:
    return ARG_TYPE_TO_VALUE[s]


def usage(meta: Mapping[str, str], sections: Sequence[Section]) -> str:
    prog_name = sections[0].meta['prog-name']
    prog_title = sections[0].meta["prog-title"]
    out = io.StringIO()
    out.write(f'{prog_name} - {prog_title}\n')
    argument = sections[0].meta.get('argument', '')
    out.write(
        f'Usage:  {prog_name} '
        f'[ -<flag> [<val>] | --<name>[{{=| }}<val>] ]... {argument}\n'
    )
    for section in sections:
        desc = section.meta["desc"]
        out.write('\n')
        if desc != '':
            out.write(f'{desc}:\n\n')
        for option in section.options:
            if 'deprecated' in option:
                continue
            long_opt = option['long-option']
            short_opt = option.get('short-option')
            arg_type = option.get('arg-type')
            if short_opt:
                header = f'   -{short_opt}, --{long_opt}'
            else:
                header = f'       --{long_opt}'
            if arg_type:
                arg = ARG_TYPE_TO_VALUE.get(arg_type, 'arg')
                if 'arg-optional' in option:
                    header += f'[={arg}]'
                else:
                    header += f'={arg}'
            if len(header) < 30:
                header = header.ljust(30)
            elif arg_type:
                header += ' '
            else:
                header += '  '
            alias = option.get('aliases')
            if alias:
                option_desc = f"an alias for the '{alias}' option"
            else:
                option_desc = option['desc']
            out.write(f'{header}{option_desc}\n')
            conflict_opts = option.get('conflicts', '').split()
            if len(conflict_opts) == 1:
                out.write(
                    f"\t\t\t\t- prohibits the option '{conflict_opts[0]}'\n"
                )
            elif len(conflict_opts) > 1:
                conflict_opts_concatenated = '\n'.join([
                    f'\t\t\t\t{conflict_opt}' for conflict_opt in conflict_opts
                ])
                out.write(
                    '\t\t\t\t- prohibits these options:\n' +
                    conflict_opts_concatenated + '\n'
                )
            require_opts = option.get('requires', '').split()
            if len(require_opts) == 1:
                out.write(
                    f"\t\t\t\t- requires the option '{require_opts[0]}'\n"
                )
            elif len(require_opts) > 1:
                require_opts_concatenated = '\n'.join([
                    f'\t\t\t\t{require_opt}' for require_opt in require_opts
                ])
                out.write(
                    '\t\t\t\t- requires these options:\n' +
                    require_opts_concatenated + '\n'
                )
            file_exists = option.get('file-exists', 'no')
            if file_exists == 'yes':
                out.write('\t\t\t\t- file must pre-exist\n')
            disable_prefix = option.get('disable-prefix')
            if disable_prefix:
                out.write(
                    f"\t\t\t\t- disabled as '--{disable_prefix}{long_opt}'\n"
                )
            if 'enabled' in option:
                out.write('\t\t\t\t- enabled by default\n')
            if 'max' in option:
                max_count = option.get('max')
                assert max_count == 'NOLIMIT', \
                    f'max keyword with value {max_count} is not supported'
                out.write('\t\t\t\t- may appear multiple times\n')
            arg_min = option.get('arg-min')
            arg_max = option.get('arg-max')
            if arg_min and arg_max:
                out.write(
                    '\t\t\t\t- it must be in the range:\n'
                    f'\t\t\t\t  {int(arg_min)} to {int(arg_max)}\n'
                )
    out.write(textwrap.dedent('''
        Options are specified by doubled hyphens and their name or by a single
        hyphen and the flag character.
    '''))
    if 'argument' in sections[0].meta:
        out.write(('Operands and options may be intermixed.  '
                   'They will be reordered.\n'))
    out.write('\n' + sections[0].meta['detail'] + '\n')
    bug_email = meta.get('bug-email')
    if bug_email:
        out.write('\n' + f'Please send bug reports to:  <{bug_email}>' + '\n')
    return out.getvalue()


LICENSES = {
    'gpl3+': textwrap.dedent('''\
        This is free software. It is licensed for use, modification and
        redistribution under the terms of the GNU General Public License,
        version 3 or later <http://gnu.org/licenses/gpl.html>
    ''')
}
FULL_LICENSES = {
    'gpl3+': textwrap.dedent('''\
        This is free software. It is licensed for use, modification and
        redistribution under the terms of the GNU General Public License,
        version 3 or later <http://gnu.org/licenses/gpl.html>

        @prog_name@ is free software: you can redistribute it and/or
        modify it under the terms of the GNU General Public License
        as published by the Free Software Foundation,
        either version 3 of the License, or (at your option) any later version.

        @prog_name@ is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty
        of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
        See the GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
    ''')
}


def version(meta: Mapping[str, str], what='c') -> str:
    prog_name = meta['prog-name']
    version = meta.get('version', '0.0.0')
    license = meta.get('license', 'unknown')
    if license:
        license_text: Optional[str] = LICENSES[license]
        full_license_text: Optional[str] = FULL_LICENSES[license]
    else:
        license_text = None
        full_license_text = None
    copyright_year = meta.get('copyright-year',
                              str(datetime.date.today().year))
    copyright_holder = meta.get('copyright-holder', 'COPYRIGHT HOLDER')
    bug_email = meta.get('bug-email')

    out = io.StringIO()

    if what == 'v':
        out.write(f'{prog_name} {version}')
    elif what == 'c':
        out.write(textwrap.dedent(f'''\
            {prog_name} {version}
            Copyright (C) {copyright_year} {copyright_holder}
        '''))
        if license_text:
            out.write(license_text)
        if bug_email:
            out.write(textwrap.dedent(f'''\

                Please send bug reports to:  <{bug_email}>\
            '''))
    elif what == 'n':
        out.write(textwrap.dedent(f'''\
            {prog_name} {version}
            Copyright (C) {copyright_year} {copyright_holder}
        '''))
        if full_license_text:
            out.write(full_license_text.replace('@prog_name@', prog_name))
        if bug_email:
            out.write(textwrap.dedent(f'''\

                Please send bug reports to:  <{bug_email}>\
            '''))
    return out.getvalue()
