/* Taken from minip12
 */

#include <gcrypt.h>
#include <gnutls_errors.h>

int 
_pkcs12_string_to_key (int id, const char *salt, int salt_size, int iter, const char *pw,
               int req_keylen, unsigned char *keybuf)
{
  int rc, i, j;
  GcryMDHd md;
  GcryMPI num_b1 = NULL;
  int pwlen;
  unsigned char hash[20], buf_b[64], buf_i[128], *p;
  size_t cur_keylen;
  size_t n;

  cur_keylen = 0;
  pwlen = strlen (pw);
  if (pwlen > 63/2 || salt_size > 8)
    {
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Store salt and password in BUF_I */
  p = buf_i;
  for(i=0; i < 64; i++)
    *p++ = salt [i%8];
  for(i=j=0; i < 64; i += 2)
    {
      *p++ = 0;
      *p++ = pw[j];
      if (++j > pwlen) /* Note, that we include the trailing zero */
        j = 0;
    }

  for (;;)
    {
      md = gcry_md_open (GCRY_MD_SHA1, 0);
      if (!md)
        {
          return GNUTLS_E_DECRYPTION_FAILED;
        }
      for(i=0; i < 64; i++)
        gcry_md_putc (md, id);
      gcry_md_write (md, buf_i, 128);
      memcpy (hash, gcry_md_read (md, 0), 20);
      gcry_md_close (md);
      for (i=1; i < iter; i++)
        gcry_md_hash_buffer (GCRY_MD_SHA1, hash, hash, 20);

      for (i=0; i < 20 && cur_keylen < req_keylen; i++)
        keybuf[cur_keylen++] = hash[i];
      if (cur_keylen == req_keylen)
        {
          gcry_mpi_release (num_b1);
          return 0; /* ready */
        }
      
      /* need more bytes. */
      for(i=0; i < 64; i++)
        buf_b[i] = hash[i % 20];
      n = 64;
      rc = gcry_mpi_scan (&num_b1, GCRYMPI_FMT_USG, buf_b, &n);
      if (rc)
        {
          return GNUTLS_E_DECRYPTION_FAILED;
        }
      gcry_mpi_add_ui (num_b1, num_b1, 1);
      for (i=0; i < 128; i += 64)
        {
          GcryMPI num_ij;

          n = 64;
          rc = gcry_mpi_scan (&num_ij, GCRYMPI_FMT_USG, buf_i + i, &n);
          if (rc)
            {
              return GNUTLS_E_DECRYPTION_FAILED;
            }
          gcry_mpi_add (num_ij, num_ij, num_b1);
          gcry_mpi_clear_highbit (num_ij, 64*8);
          n = 64;
          rc = gcry_mpi_print (GCRYMPI_FMT_USG, buf_i + i, &n, num_ij);
          if (rc)
            {
              return GNUTLS_E_DECRYPTION_FAILED;
            }
          gcry_mpi_release (num_ij);
        }
    }
}
