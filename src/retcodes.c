#include <stdio.h>
#include <gnutls/gnutls.h>

const char* _gnutls_strerror(int);

const char headers[] = "\\tablefirsthead{%\n"
	"\\hline\n"
	"\\multicolumn{1}{|c}{Error code} &\n"
	"\\multicolumn{1}{c|}{Description} \\\\\n"
	"\\hline}\n"
	"\\tablehead{%\n"
	"\\hline\n"
	"\\multicolumn{2}{|l|}{\\small\\sl continued from previous page}\\\\\n"
	"\\hline\n"
	"\\multicolumn{1}{|c}{Error code} &\n"
	"\\multicolumn{1}{c|}{Description} \\\\\n"
	"\\hline}\n"
	"\\tabletail{%\n"
	"\\hline\n"
	"\\multicolumn{2}{|r|}{\\small\\sl continued on next page}\\\\\n"
	"\\hline}\n"
	"\\tablelasttail{\\hline}\n"
	"\\bottomcaption{The error codes table}\n\n";


int main()
{
int i;
const char* desc;
const char* _name;

printf("\\chapter{Error codes and descriptions\\index{Error codes}}\\label{ap:error_codes}\n");

printf("\\begin{center}\n");

puts( headers);

printf("\\begin{supertabular}{|l|p{6cm}|}\n");

static char* escape_string( const char* str)
{
static char buffer[500];
int i = 0, j = 0;

while( str[i] != 0 && j < sizeof(buffer)) {
   if (str[i]=='_') {
      buffer[j++] = '\\';
      buffer[j++] = '_';
   } else {
      buffer[j++] = str[i];
   }
   i++;
};

buffer[j] = 0;

return buffer;

}

for (i=-1;i>-400;i--)
{
   _name = _gnutls_strerror(i);
   desc = gnutls_strerror(i);
   if (desc == NULL || _name == NULL) continue;

   printf( "{\\tiny{%s}} & %s", escape_string(_name), desc);
   printf( "\\\\\n");
}

printf("\\end{supertabular}\n\n");

printf("\\end{center}\n");

return 0;

}
