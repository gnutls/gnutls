typedef struct {
    opaque *data;
    size_t size;
    int mmaped;
} strfile;

void _gnutls_strfile_free(strfile * x);
strfile _gnutls_file_to_str(const char *file);
