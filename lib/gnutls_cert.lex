/* scanner for DER encoded certificates */

/*
 *      Copyright (C) 2000 Tarun Upadhyay <tarun@ebprovider.com>
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

%{  
  /* C declarations block */
#define CHOP(C) ((c)&'\x7f')

  unsigned long size;
  unsigned long levels[64];
  int current = 0;
  unsigned long realsize;
  
  void parselen(void){
    int i;
    char c;
    printf("\tLEN: ");
    c = input();
    realsize = 2;
    if (c & '\x80') {
      printf("%d/", CHOP(c));
      realsize += CHOP(c);
      for (size=0, i = 0; i < CHOP(c); i++){
	size <<= 8;
	size += input();
      }
    }
    else
      size = c;
    realsize += size;
    printf("%d ", size);
  }

  void increaselevel(void){
    levels[current++] = realsize;
    levels[current] = 0;
  }

  void checklevel(void){
    levels[current] += realsize;
    if (levels[current] == levels[current-1])
  }
%}

%%

\x01 {
  printf("\nBOOLEAN");
  input();
  printf("%d ", input());
}

\x02 {
  int i;
  printf("\nINTEGER");
  parselen();
  for (i = 0; i < size; i++)
    printf("%x ", input());
  size = 0;
}

\x03 |
\x04 {
  int i;
  printf("\nBIT STRING");
  parselen();
  for (i = 0; i < size ; i++)
    printf("%x ", input());
  size = 0;
}

\x05 {
  printf("\nNULL");
  input();
}

\x06 {
  int i;
  printf("\nOID");
  parselen();
  for (i = 0; i < size ; i++)
    printf("%x.", input());
  size = 0;
}

\x13 |
\x16 {
  int i;
  printf("\nSTRING");
  parselen();
  for (i = 0; i < size ; i++)
    printf("%c", input());
  size = 0;
}

\x17 {
  char c;
  printf("\nUTC TIME");
  parselen();
  c = input();

  /* year */
  if (c <= '4')
    printf("20");
  else
    printf("19");
  printf("%c", c);
  printf("%c", input());
  
  /* month */
  printf("/%c", input());
  printf("%c", input());

  /* day */
  printf("/%c", input());
  printf("%c", input());

  /* hours */
  printf(" %c", input());
  printf("%c", input());

  /* minutes */
  printf(":%c", input());
  printf("%c", input());

  /* seconds */
  printf(":%c", input());
  printf("%c", input());

  input();
}

[\xa0-\xaf] {
  int i;
  printf("\nARRAY[%d]", yytext[0] & '\x07');
  parselen();
  increaselevel();
}

\x30 {
  printf("\nSEQUENCE");
  parselen();
  increaselevel();
}

\x31 {
  printf("\nSET");
  parselen();
  increaselevel();
}

%%

main (int argc, char ** argv){
  yyin = stdin;
  yylex();
  printf("\n");
}

