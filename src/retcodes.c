#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>

const char *_gnutls_strerror(int);

static const char headers[] = "\\tablefirsthead{%\n"
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

typedef struct {
    char name[128];
    int error_index;
} error_name;


static int compar(const void *_n1, const void *_n2)
{
    const error_name *n1 = (const error_name *) _n1,
	*n2 = (const error_name *) _n2;
    return strcmp(n1->name, n2->name);
}

static char *escape_string(const char *str)
{
    static char buffer[500];
    unsigned int i = 0, j = 0;


    while (str[i] != 0 && j < sizeof(buffer) - 1) {
	if (str[i] == '_') {
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

int main()
{
    int i, j;
    const char *desc;
    const char *_name;
    error_name names_to_sort[400];	/* up to 400 names  */

    printf
	("\\chapter{Error codes and descriptions\\index{Error codes}}\\label{ap:error_codes}\n");

    printf("\\begin{center}\n");

    puts(headers);

    printf("\\begin{supertabular}{|l|p{6cm}|}\n");

    memset(names_to_sort, 0, sizeof(names_to_sort));
    j = 0;
    for (i = 0; i > -400; i--) {
	_name = _gnutls_strerror(i);
	if (_name == NULL)
	    continue;

	strcpy(names_to_sort[j].name, _name);
	names_to_sort[j].error_index = i;
	j++;
    }

    qsort(names_to_sort, j, sizeof(error_name), compar);

    for (i = 0; i < j; i++) {
	_name = names_to_sort[i].name;
	desc = gnutls_strerror(names_to_sort[i].error_index);
	if (desc == NULL || _name == NULL)
	    continue;

	printf("{\\tiny{%s}} & %s", escape_string(_name), desc);
	printf("\\\\\n");
    }

    printf("\\end{supertabular}\n\n");

    printf("\\end{center}\n");

    return 0;

}
