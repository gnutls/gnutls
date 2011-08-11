/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010 Free Software
 * Foundation, Inc.
 * Author: Nikos Mavrogiannopoulos, Simon Josefsson
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>

static void main_latex(void);
static int main_texinfo (void);

#define MAX_CODES 600

typedef struct
{
  char name[128];
  int error_index;
} error_name;


static int
compar (const void *_n1, const void *_n2)
{
  const error_name *n1 = (const error_name *) _n1,
    *n2 = (const error_name *) _n2;
  return strcmp (n1->name, n2->name);
}

static const char headers[] = "\\tablefirsthead{%\n"
	"\\hline\n"
	"\\multicolumn{1}{|c}{Error code} &\n"
	"\\multicolumn{1}{c|}{Description} \\\\\n"
	"\\hline}\n"
	"\\tablehead{%\n"
	"\\hline\n"
	"\\multicolumn{2}{|l|}{\\small\\sl continued from previous page}\\\\\n"
	"\\hline}\n"
	"\\tabletail{%\n"
	"\\hline\n"
	"\\multicolumn{2}{|r|}{\\small\\sl continued on next page}\\\\\n"
	"\\hline}\n"
	"\\tablelasttail{\\hline}\n"
	"\\bottomcaption{The error codes table}\n\n";

int
main (int argc, char *argv[])
{
  if (argc > 1)
    main_latex();
  else
    main_texinfo();
    
  return 0;
}

static int main_texinfo (void)
{
  int i, j;
  const char *desc;
  const char *_name;
  error_name names_to_sort[MAX_CODES];        /* up to MAX_CODES names  */

  printf ("@table @code\n");

  memset (names_to_sort, 0, sizeof (names_to_sort));
  j = 0;
  for (i = 0; i > -MAX_CODES; i--)
    {
      _name = gnutls_strerror_name (i);
      if (_name == NULL)
        continue;

      strcpy (names_to_sort[j].name, _name);
      names_to_sort[j].error_index = i;
      j++;
    }

  qsort (names_to_sort, j, sizeof (error_name), compar);

  for (i = 0; i < j; i++)
    {
      _name = names_to_sort[i].name;
      desc = gnutls_strerror (names_to_sort[i].error_index);
      if (desc == NULL || _name == NULL)
        continue;

      printf ("@item %s:\n%s\n\n", _name, desc);
    }

  printf ("@end table\n");

  return 0;
}

static char* escape_string( const char* str, char* buffer, int buffer_size)
{
int i = 0, j = 0;


while( str[i] != 0 && j <buffer_size - 1) {
   if (str[i]=='_') {
      buffer[j++] = '\\';
      buffer[j++] = '_';
   } else if (str[i]=='#') {
      buffer[j++] = '\\';
      buffer[j++] = '#';
   } else {
      buffer[j++] = str[i];
   }
   i++;
};

buffer[j] = 0;

return buffer;

}

static void main_latex(void)
{
int i, j;
static char buffer1[500];
static char buffer2[500];
const char* desc;
const char* _name;
error_name names_to_sort[MAX_CODES]; /* up to MAX_CODES names  */

puts( headers);

printf("\\begin{supertabular}{|p{.52\\linewidth}|p{.40\\linewidth}|}\n");

memset( names_to_sort, 0, sizeof(names_to_sort));
j=0;
for (i=0;i>-MAX_CODES;i--)
{
   _name = gnutls_strerror_name(i);
   if ( _name == NULL) continue;

   strcpy( names_to_sort[j].name, _name);
   names_to_sort[j].error_index = i;
   j++;
}

qsort( names_to_sort, j, sizeof(error_name), compar);

for (i=0;i<j;i++)
{
   _name = names_to_sort[i].name;
   desc = gnutls_strerror( names_to_sort[i].error_index);
   if (desc == NULL || _name == NULL) continue;

   printf( "{\\scriptsize{%s}} & %s", escape_string(_name, buffer1, sizeof(buffer1)), escape_string(desc, buffer2, sizeof(buffer2)));
   printf( "\\\\\n");
}

printf("\\end{supertabular}\n\n");

return;

}
