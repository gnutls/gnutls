/*
 * Copyright (C) 2008, 2009 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* *INDENT-OFF* */

/* Triggers incorrect verification success on older versions */
static const char *cve_2008_4989_chain[] = {
  /* chain[0] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIB6zCCAVQCCQCgwnB/k0WZrDANBgkqhkiG9w0BAQUFADA9MQswCQYDVQQGEwJE\n"
  "RTEXMBUGA1UEChMOR05VIFRMUyBBdHRhY2sxFTATBgNVBAMTDGludGVybWVkaWF0\n"
  "ZTAeFw0wODExMDMxMjA1MDRaFw0wODEyMDMxMjA1MDRaMDcxCzAJBgNVBAYTAkRF\n"
  "MRcwFQYDVQQKEw5HTlUgVExTIEF0dGFjazEPMA0GA1UEAxMGc2VydmVyMIGfMA0G\n"
  "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKdL9g5ErMLOLRCjiomZlNLhy0moWGaKIW\n"
  "aX6vyUIfh8d6FcArHoKoqhmX7ckvod50sOYPojQesDpl7gVaQNA6Ntr1VCcuNPef\n"
  "UKWtEwL0Qu9JbPnUoIYd7mAaqVQgFp6W6yzV/dp63LH4XSdzBMhpZ/EU6vZoE8Sv\n"
  "VLdqj5r6jwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAH4QRR7sZEbjW00tXYk/3O/Z\n"
  "96AxJNg0F78W5B68gaJrLJ7DTE2RTglscuEq1+2Jyb4AIziwXpYqxgwcP91QpH97\n"
  "XfwdXIcyjYvVLHiKmkQj2zJTY7MeyiEQQ2it8VstZG2fYmi2EiMZIEnyJ2JJ7bA7\n"
  "bF7pG7Cg3oEHUM0H5KUU\n"
  "-----END CERTIFICATE-----\n",
  /* chain[1] (not signed by next cert) */
  "-----BEGIN CERTIFICATE-----\n"
  "MIICADCCAWmgAwIBAgIJAIZ4nkHQAqTFMA0GCSqGSIb3DQEBBQUAMDUxCzAJBgNV\n"
  "BAYTAkRFMRcwFQYDVQQKEw5HTlUgVExTIEF0dGFjazENMAsGA1UEAxMEcm9vdDAe\n"
  "Fw0wODExMDMxMjA0NDVaFw0wODEyMDMxMjA0NDVaMD0xCzAJBgNVBAYTAkRFMRcw\n"
  "FQYDVQQKEw5HTlUgVExTIEF0dGFjazEVMBMGA1UEAxMMaW50ZXJtZWRpYXRlMIGf\n"
  "MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDvBpW8sAhIuUmNvcBE6wv/q7MtM1Z9\n"
  "2I1SDL8eJ8I2nPg6BlCX+OIqNruynj8J7uPEQ04ZLwLxNXoyZa8057YFyrKLOvoj\n"
  "5IfBtidsLWYv6PO3qqHJXVvwGdS7PKMuUlsjucCRyXVgQ07ODF7piqoVFi9KD99w\n"
  "AU5+9plGrZNP/wIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUA\n"
  "A4GBAGPg+M+8MsB6zHN2o+jAtyqovrTTwmzVWEgfEH/aHC9+imGZRQ5lFNc2vdny\n"
  "AgaJ9/izO5S6Ibb5zUowN2WhoUJOVipuQa2m9AviOgheoU7tmANC9ylm/pRkKy/0\n"
  "n5UVzlKxDhRp/xBb7MWOw3KEQjiAf2Z3wCLcCPUqcJUdJC4v\n"
  "-----END CERTIFICATE-----\n",
  /* chain[2] (trusted CA cert) */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIEIDCCAwigAwIBAgIQNE7VVyDV7exJ9C/ON9srbTANBgkqhkiG9w0BAQUF\n"
  "ADCBqTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEoMCYG\n"
  "A1UECxMfQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcyBEaXZpc2lvbjE4MDYGA1UE\n"
  "CxMvKGMpIDIwMDYgdGhhd3RlLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNl\n"
  "IG9ubHkxHzAdBgNVBAMTFnRoYXd0ZSBQcmltYXJ5IFJvb3QgQ0EwHhcNMDYx\n"
  "MTE3MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCBqTELMAkGA1UEBhMCVVMxFTAT\n"
  "BgNVBAoTDHRoYXd0ZSwgSW5jLjEoMCYGA1UECxMfQ2VydGlmaWNhdGlvbiBT\n"
  "ZXJ2aWNlcyBEaXZpc2lvbjE4MDYGA1UECxMvKGMpIDIwMDYgdGhhd3RlLCBJ\n"
  "bmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxHzAdBgNVBAMTFnRoYXd0\n"
  "ZSBQcmltYXJ5IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
  "AoIBAQCsoPD7gFnUnMekz52hWXMJEEUMDSxuaPFsW0hoSVk3/AszGcJ3f8wQ\n"
  "LZU0HObrTQmnHNK4yZc2AreJ1CRfBsDMRJSUjQJib+ta3RGNKJpchJAQeg29\n"
  "dGYvajig4tVUROsdB58Hum/u6f1OCyn1PoSgAfGcq/gcfomk6KHYcWUNo1F7\n"
  "7rzSImANuVud37r8UVsLr5iy6S7pBOhih94ryNdOwUxkHt3Ph1i6Sk/KaAcd\n"
  "HJ1KxtUvkcx8cXIcxcBn6zL9yZJclNqFwJu/U30rCfSMnZEfl2pSy94JNqR3\n"
  "2HuHUETVPm4pafs5SSYeCaWAe0At6+gnhcn+Yf1+5nyXHdWdAgMBAAGjQjBA\n"
  "MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBR7\n"
  "W0XPr87Lev0xkhpqtvNG61dIUDANBgkqhkiG9w0BAQUFAAOCAQEAeRHAS7OR\n"
  "tvzw6WfUDW5FvlXok9LOAz/t2iWwHVfLHjp2oEzsUHboZHIMpKnxuIvW1oeE\n"
  "uzLlQRHAd9mzYJ3rG9XRbkREqaYB7FViHXe4XI5ISXycO1cRrK1zN44veFyQ\n"
  "aEfZYGDm/Ac9IiAXxPcW6cTYcvnIc3zfFi8VqT79aie2oetaupgf1eNNZAqd\n"
  "E8hhuvU5HIe6uL17In/2/qxAeeWsEG89jxt5dovEN7MhGITlNgDrYyCZuen+\n"
  "MwS7QcjBAvlEYyCegc5C09Y/LHbTY5xZ3Y+m4Q6gLkH3LpVHz7z9M/P2C2F+\n"
  "fpErgUfCJzDupxBdN49cOSvkBPB7jVaMaA==\n"
  "-----END CERTIFICATE-----\n",
  NULL
};

/* Chain length 3 ends with trusted v1 RSA-MD2 chain */
static const char *verisign_com_chain[] = {
  /* chain[0] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIGCDCCBPCgAwIBAgIQakrDGzEQ5utI8PxRo5oXHzANBgkqhkiG9w0BAQUFADCB\n"
  "vjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\n"
  "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2Ug\n"
  "YXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykwNjE4MDYGA1UEAxMv\n"
  "VmVyaVNpZ24gQ2xhc3MgMyBFeHRlbmRlZCBWYWxpZGF0aW9uIFNTTCBTR0MgQ0Ew\n"
  "HhcNMDcwNTA5MDAwMDAwWhcNMDkwNTA4MjM1OTU5WjCCAUAxEDAOBgNVBAUTBzI0\n"
  "OTc4ODYxEzARBgsrBgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMIRGVs\n"
  "YXdhcmUxCzAJBgNVBAYTAlVTMQ4wDAYDVQQRFAU5NDA0MzETMBEGA1UECBMKQ2Fs\n"
  "aWZvcm5pYTEWMBQGA1UEBxQNTW91bnRhaW4gVmlldzEiMCAGA1UECRQZNDg3IEVh\n"
  "c3QgTWlkZGxlZmllbGQgUm9hZDEXMBUGA1UEChQOVmVyaVNpZ24sIEluYy4xJTAj\n"
  "BgNVBAsUHFByb2R1Y3Rpb24gU2VjdXJpdHkgU2VydmljZXMxMzAxBgNVBAsUKlRl\n"
  "cm1zIG9mIHVzZSBhdCB3d3cudmVyaXNpZ24uY29tL3JwYSAoYykwNjEZMBcGA1UE\n"
  "AxQQd3d3LnZlcmlzaWduLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA\n"
  "xxA35ev879drgQCpENGRQ3ARaCPz/WneT9dtMe3qGNvzXQJs6cjm1Bx8XegyW1gB\n"
  "jJX5Zl4WWbr9wpAWZ1YyJ0bEyShIGmkU8fPfbcXYwSyWoWwvE5NRaUB2ztmfAVdv\n"
  "OaGMUKxny2Dnj3tAdaQ+FOeRDJJYg6K1hzczq/otOfsCAwEAAaOCAf8wggH7MAkG\n"
  "A1UdEwQCMAAwHQYDVR0OBBYEFPFaiZNVR0u6UfVO4MsWVfTXzDhnMAsGA1UdDwQE\n"
  "AwIFoDA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vRVZJbnRsLWNybC52ZXJpc2ln\n"
  "bi5jb20vRVZJbnRsMjAwNi5jcmwwRAYDVR0gBD0wOzA5BgtghkgBhvhFAQcXBjAq\n"
  "MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhMDQGA1Ud\n"
  "JQQtMCsGCCsGAQUFBwMBBggrBgEFBQcDAgYJYIZIAYb4QgQBBgorBgEEAYI3CgMD\n"
  "MB8GA1UdIwQYMBaAFE5DyB127zdTek/yWG+U8zji1b3fMHYGCCsGAQUFBwEBBGow\n"
  "aDArBggrBgEFBQcwAYYfaHR0cDovL0VWSW50bC1vY3NwLnZlcmlzaWduLmNvbTA5\n"
  "BggrBgEFBQcwAoYtaHR0cDovL0VWSW50bC1haWEudmVyaXNpZ24uY29tL0VWSW50\n"
  "bDIwMDYuY2VyMG0GCCsGAQUFBwEMBGEwX6FdoFswWTBXMFUWCWltYWdlL2dpZjAh\n"
  "MB8wBwYFKw4DAhoEFI/l0xqGrI2Oa8PPgGrUSBgsexkuMCUWI2h0dHA6Ly9sb2dv\n"
  "LnZlcmlzaWduLmNvbS92c2xvZ28uZ2lmMA0GCSqGSIb3DQEBBQUAA4IBAQBEueAg\n"
  "xZJrjGPKAZk1NT8VtTn0yi87i9XUnSOnkFkAuI3THDd+cWbNSUzc5uFJg42GhMK7\n"
  "S1Rojm8FHxESovLvimH/w111BKF9wNU2XSOb9KohfYq3GRiQG8O7v9JwIjjLepkc\n"
  "iyITx7sYiJ+kwZlrNBwN6TwVHrONg6NzyzSnxCg+XgKRbJu2PqEQb6uQVkYhb+Oq\n"
  "Vi9d4by9YqpnuXImSffQ0OZ/6s3Rl6vY08zIPqa6OVfjGs/H45ETblzezcUKpX0L\n"
  "cqnOwUB9dVuPhtlX3X/hgz/ROxz96NBwwzha58HUgfEfkVtm+piI6TTI7XxS/7Av\n"
  "nKMfhbyFQYPQ6J9g\n"
  "-----END CERTIFICATE-----\n",
  /* chain[1] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIGCjCCBPKgAwIBAgIQESoAbTflEG/WynzD77rMGDANBgkqhkiG9w0BAQUFADCB\n"
  "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\n"
  "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\n"
  "U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\n"
  "ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\n"
  "aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMTYxMTA3MjM1OTU5WjCBvjEL\n"
  "MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\n"
  "ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQg\n"
  "aHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykwNjE4MDYGA1UEAxMvVmVy\n"
  "aVNpZ24gQ2xhc3MgMyBFeHRlbmRlZCBWYWxpZGF0aW9uIFNTTCBTR0MgQ0EwggEi\n"
  "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9Voi6iDRkZM/NyrDu5xlzxXLZ\n"
  "u0W8taj/g74cA9vtibcuEBolvFXKQaGfC88ZXnC5XjlLnjEcX4euKqqoK6IbOxAj\n"
  "XxOx3QiMThTag4HjtYzjaO0kZ85Wtqybc5ZE24qMs9bwcZOO23FUSutzWWqPcFEs\n"
  "A5+X0cwRerxiDZUqyRx1V+n1x+q6hDXLx4VafuRN4RGXfQ4gNEXb8aIJ6+s9nriW\n"
  "Q140SwglHkMaotm3igE0PcP45a9PjP/NZfAjTsWXs1zakByChQ0GDcEitnsopAPD\n"
  "TFPRWLxyvAg5/KB2qKjpS26IPeOzMSWMcylIDjJ5Bu09Q/T25On8fb6OCNUfAgMB\n"
  "AAGjggH0MIIB8DAdBgNVHQ4EFgQUTkPIHXbvN1N6T/JYb5TzOOLVvd8wEgYDVR0T\n"
  "AQH/BAgwBgEB/wIBADA9BgNVHSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYc\n"
  "aHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL2NwczA9BgNVHR8ENjA0MDKgMKAuhixo\n"
  "dHRwOi8vRVZTZWN1cmUtY3JsLnZlcmlzaWduLmNvbS9wY2EzLWc1LmNybDAgBgNV\n"
  "HSUEGTAXBglghkgBhvhCBAEGCmCGSAGG+EUBCAEwDgYDVR0PAQH/BAQDAgEGMBEG\n"
  "CWCGSAGG+EIBAQQEAwIBBjBtBggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglpbWFn\n"
  "ZS9naWYwITAfMAcGBSsOAwIaBBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNodHRw\n"
  "Oi8vbG9nby52ZXJpc2lnbi5jb20vdnNsb2dvLmdpZjApBgNVHREEIjAgpB4wHDEa\n"
  "MBgGA1UEAxMRQ2xhc3MzQ0EyMDQ4LTEtNDgwPQYIKwYBBQUHAQEEMTAvMC0GCCsG\n"
  "AQUFBzABhiFodHRwOi8vRVZTZWN1cmUtb2NzcC52ZXJpc2lnbi5jb20wHwYDVR0j\n"
  "BBgwFoAUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJKoZIhvcNAQEFBQADggEBAFqi\n"
  "sb/rjdQ4qIBywtw4Lqyncfkro7tHu21pbxA2mIzHVi67vKtKm3rW8oKT4BT+is6D\n"
  "t4Pbk4errGV5Sf1XqbHOCR+6EBXECQ5i4/kKJdVkmPDyqA92Mn6R5hjuvOfa0E6N\n"
  "eLvincBZK8DOlQ0kDHLKNF5wIokrSrDxaIfz7kSNKEB3OW5IckUxXWs5DoYC6maZ\n"
  "kzEP32fepp+MnUzOcW86Ifa5ND/5btia9z7a84Ffelxtj3z2mXS3/+QXXe1hXqtI\n"
  "u5aNZkU5tBIK9nDpnHYiS2DpKhs0Sfei1GfAsSatE7rZhAHBq+GObXAWO3eskZq7\n"
  "Gh/aWKfkT8Fhrryi/ks=\n"
  "-----END CERTIFICATE-----\n",
  /* chain[2] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIE/zCCBGigAwIBAgIQY5Jrio9Agv2swDvTeCmmwDANBgkqhkiG9w0BAQUFADBf\n"
  "MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsT\n"
  "LkNsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw\n"
  "HhcNMDYxMTA4MDAwMDAwWhcNMjExMTA3MjM1OTU5WjCByjELMAkGA1UEBhMCVVMx\n"
  "FzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVz\n"
  "dCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAtIEZv\n"
  "ciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFzcyAz\n"
  "IFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzUwggEi\n"
  "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1nmAMqudLO07cfLw8\n"
  "RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbext0uz/o9+B1fs70Pb\n"
  "ZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIzSdhDY2pSS9KP6HBR\n"
  "TdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQGBO+QueQA5N06tRn/\n"
  "Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+rCpSx4/VBEnkjWNH\n"
  "iDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/NIeWiu5T6CUVAgMB\n"
  "AAGjggHKMIIBxjAPBgNVHRMBAf8EBTADAQH/MDEGA1UdHwQqMCgwJqAkoCKGIGh0\n"
  "dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTMuY3JsMA4GA1UdDwEB/wQEAwIBBjBt\n"
  "BggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglpbWFnZS9naWYwITAfMAcGBSsOAwIa\n"
  "BBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNodHRwOi8vbG9nby52ZXJpc2lnbi5j\n"
  "b20vdnNsb2dvLmdpZjA9BgNVHSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYc\n"
  "aHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL2NwczAdBgNVHQ4EFgQUf9Nlp8Ld7Lvw\n"
  "MAnzQzn6Aq8zMTMwgYAGA1UdIwR5MHehY6RhMF8xCzAJBgNVBAYTAlVTMRcwFQYD\n"
  "VQQKEw5WZXJpU2lnbiwgSW5jLjE3MDUGA1UECxMuQ2xhc3MgMyBQdWJsaWMgUHJp\n"
  "bWFyeSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eYIQcLrkHRDZKTS2OMp7A8y6vzAg\n"
  "BgNVHSUEGTAXBglghkgBhvhCBAEGCmCGSAGG+EUBCAEwDQYJKoZIhvcNAQEFBQAD\n"
  "gYEAUNfnArcMK6xK11/59ADJdeNqKOck4skH3qw6WCAYQxfrcn4eobTInOn5G3Gu\n"
  "39g6DapSHmBex2UtZSxvKnJVlWYQgE4P4wGoXdzV69YdCNssXNVVc59DYhDH05dZ\n"
  "P4sJH99fucYDkJjUgRUYw35ww0OFwKgUp3CxiizbXxCqEQc=\n"
  "-----END CERTIFICATE-----\n",
  /* chain[3] (CA) */
  "-----BEGIN CERTIFICATE-----\n"
  "MIICPDCCAaUCEHC65B0Q2Sk0tjjKewPMur8wDQYJKoZIhvcNAQECBQAwXzELMAkG\n"
  "A1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFz\n"
  "cyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTk2\n"
  "MDEyOTAwMDAwMFoXDTI4MDgwMTIzNTk1OVowXzELMAkGA1UEBhMCVVMxFzAVBgNV\n"
  "BAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFzcyAzIFB1YmxpYyBQcmlt\n"
  "YXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GN\n"
  "ADCBiQKBgQDJXFme8huKARS0EN8EQNvjV69qRUCPhAwL0TPZ2RHP7gJYHyX3KqhE\n"
  "BarsAx94f56TuZoAqiN91qyFomNFx3InzPRMxnVx0jnvT0Lwdd8KkMaOIG+YD/is\n"
  "I19wKTakyYbnsZogy1Olhec9vn2a/iRFM9x2Fe0PonFkTGUugWhFpwIDAQABMA0G\n"
  "CSqGSIb3DQEBAgUAA4GBALtMEivPLCYATxQT3ab7/AoRhIzzKBxnki98tsX63/Do\n"
  "lbwdj2wsqFHMc9ikwFPwTtYmwHYBV4GSXiHx0bH/59AhWM1pF+NEHJwZRDmJXNyc\n"
  "AA9WjQKZ7aKQRUzkuxCkPfAyAw7xzvjoyVGM5mKf5p/AfbdynMk2OmufTqj/ZA1k\n"
  "-----END CERTIFICATE-----\n",
  NULL
};

/* Chain length 2 ends with trusted v1 RSA-MD2 cert */
static const char *citibank_com_chain[] = {
  /* chain[0] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIENDCCA52gAwIBAgIQauOJMlH5Ob2tFZ6rJMBdjjANBgkqhkiG9w0BAQUFADCB\n"
  "ujEfMB0GA1UEChMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazEXMBUGA1UECxMOVmVy\n"
  "aVNpZ24sIEluYy4xMzAxBgNVBAsTKlZlcmlTaWduIEludGVybmF0aW9uYWwgU2Vy\n"
  "dmVyIENBIC0gQ2xhc3MgMzFJMEcGA1UECxNAd3d3LnZlcmlzaWduLmNvbS9DUFMg\n"
  "SW5jb3JwLmJ5IFJlZi4gTElBQklMSVRZIExURC4oYyk5NyBWZXJpU2lnbjAeFw0w\n"
  "ODA4MjkwMDAwMDBaFw0xMDA4MjkyMzU5NTlaMHgxCzAJBgNVBAYTAlVTMRMwEQYD\n"
  "VQQIEwpOZXcgSmVyc2V5MRIwEAYDVQQHFAlXZWVoYXdrZW4xEjAQBgNVBAoUCUNp\n"
  "dGlncm91cDERMA8GA1UECxQId2hnLW9hazYxGTAXBgNVBAMUEHd3dy5jaXRpYmFu\n"
  "ay5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALQJbSYtbndsIlslFveP\n"
  "IlVNE38HnUD56BHcwfvcb8rQItXeHzYmgOf/RgHPTKG3LEZOxKqM0QpcZtEJ6xwV\n"
  "cTG7Wjw/FrMisN8aO4JWaxe8dFGajstlEMxz43G5zlprb9jzjnbIvvcnz0ILikOQ\n"
  "qmcThopBTs1+d4j7w/yEJo1zAgMBAAGjggF6MIIBdjAJBgNVHRMEAjAAMAsGA1Ud\n"
  "DwQEAwIFoDBGBgNVHR8EPzA9MDugOaA3hjVodHRwOi8vY3JsLnZlcmlzaWduLmNv\n"
  "bS9DbGFzczNJbnRlcm5hdGlvbmFsU2VydmVyLmNybDBEBgNVHSAEPTA7MDkGC2CG\n"
  "SAGG+EUBBxcDMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LnZlcmlzaWduLmNv\n"
  "bS9ycGEwKAYDVR0lBCEwHwYJYIZIAYb4QgQBBggrBgEFBQcDAQYIKwYBBQUHAwIw\n"
  "NAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC52ZXJpc2ln\n"
  "bi5jb20wbgYIKwYBBQUHAQwEYjBgoV6gXDBaMFgwVhYJaW1hZ2UvZ2lmMCEwHzAH\n"
  "BgUrDgMCGgQUS2u5KJYGDLvQUjibKaxLB4shBRgwJhYkaHR0cDovL2xvZ28udmVy\n"
  "aXNpZ24uY29tL3ZzbG9nbzEuZ2lmMA0GCSqGSIb3DQEBBQUAA4GBAFDXKsxtWkoo\n"
  "HBkNjcCvcnjNAo3Pe+eOtLHb39e5qhkNQLPGA/1/7AofY9KmEtSV2LVGeuuJI4Pi\n"
  "Lg7fPl9Q0OE/oHJpj5JkObBP9Wo1vbrDR2nGWUlCRWm20rH81dTn7OcDxarwGWsR\n"
  "ewTCNmpKYaMx8Q1dyMYunHJApu+fbrHu\n"
  "-----END CERTIFICATE-----\n",
  /* chain[1] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDgzCCAuygAwIBAgIQJUuKhThCzONY+MXdriJupDANBgkqhkiG9w0BAQUFADBf\n"
  "MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsT\n"
  "LkNsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw\n"
  "HhcNOTcwNDE3MDAwMDAwWhcNMTExMDI0MjM1OTU5WjCBujEfMB0GA1UEChMWVmVy\n"
  "aVNpZ24gVHJ1c3QgTmV0d29yazEXMBUGA1UECxMOVmVyaVNpZ24sIEluYy4xMzAx\n"
  "BgNVBAsTKlZlcmlTaWduIEludGVybmF0aW9uYWwgU2VydmVyIENBIC0gQ2xhc3Mg\n"
  "MzFJMEcGA1UECxNAd3d3LnZlcmlzaWduLmNvbS9DUFMgSW5jb3JwLmJ5IFJlZi4g\n"
  "TElBQklMSVRZIExURC4oYyk5NyBWZXJpU2lnbjCBnzANBgkqhkiG9w0BAQEFAAOB\n"
  "jQAwgYkCgYEA2IKA6NYZAn0fhRg5JaJlK+G/1AXTvOY2O6rwTGxbtueqPHNFVbLx\n"
  "veqXQu2aNAoV1Klc9UAl3dkHwTKydWzEyruj/lYncUOqY/UwPpMo5frxCTvzt01O\n"
  "OfdcSVq4wR3Tsor+cDCVQsv+K1GLWjw6+SJPkLICp1OcTzTnqwSye28CAwEAAaOB\n"
  "4zCB4DAPBgNVHRMECDAGAQH/AgEAMEQGA1UdIAQ9MDswOQYLYIZIAYb4RQEHAQEw\n"
  "KjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL0NQUzA0BgNV\n"
  "HSUELTArBggrBgEFBQcDAQYIKwYBBQUHAwIGCWCGSAGG+EIEAQYKYIZIAYb4RQEI\n"
  "ATALBgNVHQ8EBAMCAQYwEQYJYIZIAYb4QgEBBAQDAgEGMDEGA1UdHwQqMCgwJqAk\n"
  "oCKGIGh0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTMuY3JsMA0GCSqGSIb3DQEB\n"
  "BQUAA4GBAAgB7ORolANC8XPxI6I63unx2sZUxCM+hurPajozq+qcBBQHNgYL+Yhv\n"
  "1RPuKSvD5HKNRO3RrCAJLeH24RkFOLA9D59/+J4C3IYChmFOJl9en5IeDCSk9dBw\n"
  "E88mw0M9SR2egi5SX7w+xmYpAY5Okiy8RnUDgqxz6dl+C2fvVFIa\n"
  "-----END CERTIFICATE-----\n",
  /* chain[2] (CA) */
  "-----BEGIN CERTIFICATE-----\n"
  "MIICPDCCAaUCEHC65B0Q2Sk0tjjKewPMur8wDQYJKoZIhvcNAQECBQAwXzELMAkG\n"
  "A1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFz\n"
  "cyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTk2\n"
  "MDEyOTAwMDAwMFoXDTI4MDgwMTIzNTk1OVowXzELMAkGA1UEBhMCVVMxFzAVBgNV\n"
  "BAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFzcyAzIFB1YmxpYyBQcmlt\n"
  "YXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GN\n"
  "ADCBiQKBgQDJXFme8huKARS0EN8EQNvjV69qRUCPhAwL0TPZ2RHP7gJYHyX3KqhE\n"
  "BarsAx94f56TuZoAqiN91qyFomNFx3InzPRMxnVx0jnvT0Lwdd8KkMaOIG+YD/is\n"
  "I19wKTakyYbnsZogy1Olhec9vn2a/iRFM9x2Fe0PonFkTGUugWhFpwIDAQABMA0G\n"
  "CSqGSIb3DQEBAgUAA4GBALtMEivPLCYATxQT3ab7/AoRhIzzKBxnki98tsX63/Do\n"
  "lbwdj2wsqFHMc9ikwFPwTtYmwHYBV4GSXiHx0bH/59AhWM1pF+NEHJwZRDmJXNyc\n"
  "AA9WjQKZ7aKQRUzkuxCkPfAyAw7xzvjoyVGM5mKf5p/AfbdynMk2OmufTqj/ZA1k\n"
  "-----END CERTIFICATE-----\n",
  NULL
};

/* Self-signed certificate */
static const char *pem_self_cert[] = {
  "-----BEGIN CERTIFICATE-----\n"
    "MIIDgjCCAmygAwIBAgIBADALBgkqhkiG9w0BAQUwSzELMAkGA1UEBhMCQlIxFDAS\n"
    "BgNVBAoTC01pbmFzIExpdnJlMSYwJAYDVQQDEx1UaGFkZXUgTGltYSBkZSBTb3V6\n"
    "YSBDYXNjYXJkbzAeFw0wODA1MzAxOTUzNDNaFw0wODExMjYxOTUzNDNaMEsxCzAJ\n"
    "BgNVBAYTAkJSMRQwEgYDVQQKEwtNaW5hcyBMaXZyZTEmMCQGA1UEAxMdVGhhZGV1\n"
    "IExpbWEgZGUgU291emEgQ2FzY2FyZG8wggEfMAsGCSqGSIb3DQEBAQOCAQ4AMIIB\n"
    "CQKCAQC4D934O6wrXJbMyu1w8gu6nN0aNUDGqrX9UgaB/4xVuYhPlhjH0z9Dqic9\n"
    "0pEZmyNCjQmzDSg/hnlY3fBG0i9Iel2oYn1UB4SdcJ2qGkLS87y2ZbMTS1oyMR7/\n"
    "y9l3WGEWqwgjIvOjGstcZo0rCIF8Qr21QGX22KWg2HXlMaZyA9bGtJ+L+x6f2hoo\n"
    "yIPCA30VMvIgHjOSPQJF3iJFE4Uxq1PQ65W91NyI6/bRKFOmFdCUJW8tqqvntYP8\n"
    "hEE08wGlKimFNv7CqZuRI8QuOnhZ7pBXkyvQpW8yHrORlOHxSjkNQKjddt92TCJb\n"
    "1q6eKv2CtCuDLgCuIy0Onr4U9n+hAgMBAAGjeDB2MA8GA1UdEwEB/wQFMAMBAf8w\n"
    "HgYDVR0RBBcwFYITbWFpbC5taW5hc2xpdnJlLm9yZzATBgNVHSUEDDAKBggrBgEF\n"
    "BQcDATAPBgNVHQ8BAf8EBQMDB6QAMB0GA1UdDgQWBBQ/5v42y0jBHUKEfqpPmr5a\n"
    "WsjCGjALBgkqhkiG9w0BAQUDggEBAC/WfO2yK3vM9bG0qFEj8sd0cWiapMhf5PtH\n"
    "jigcPb/OKqSFQVXpAdNiUclPRP79Ih3CuWiXfZ/CW0+k2Z8tyy6AnEQItWvoVh/b\n"
    "8lS7Ph/f9JUYHp2DtgsQWcNQbrUZOPFBu8J4MD6cDWG5Uxwl3YASg30ZdmMDNT8B\n"
    "HshYz0HUOAhYwVSI3J/f7LFhD5OpjSroHgE7wA9UJrerAp9f7e3e9D7kNQ8DlvLP\n"
    "kz6Jh+5M/xD3JO1yl+evaCp3LA+z4M2xiNvtzkAEgj3t6RaJ81Sh5XGiooDYZ14R\n"
    "DgEBYLTUfBYBPzoaahPEdG/f0kUjUBJ34fkBUSjJKURPTHJfDfA=\n"
    "-----END CERTIFICATE-----\n",
  NULL
};

/* Chain length 2, CA constraint FALSE in v3 CA cert)*/
static const char *thea_chain[] = {
  /* chain[0] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIC7DCCAlWgAwIBAgIBATANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJERTEM\n"
  "MAoGA1UECBMDUkxQMSAwHgYDVQQKExdUZWNobmlzY2hlIFVuaXZlcnNpdGFldDEb\n"
  "MBkGA1UECxMSRmFjaGJlcmVpY2ggUGh5c2lrMQswCQYDVQQDEwJDQTAeFw0wODA5\n"
  "MTExMDUyMDdaFw0xODA5MDkxMDUyMDdaMIGTMQswCQYDVQQGEwJERTEMMAoGA1UE\n"
  "CBMDUkxQMRcwFQYDVQQHEw5LYWlzZXJzbGF1dGVybjEgMB4GA1UEChMXVGVjaG5p\n"
  "c2NoZSBVbml2ZXJzaXRhZXQxGzAZBgNVBAsTEkZhY2hiZXJlaWNoIFBoeXNpazEe\n"
  "MBwGA1UEAxMVdGhlYS5waHlzaWsudW5pLWtsLmRlMIGfMA0GCSqGSIb3DQEBAQUA\n"
  "A4GNADCBiQKBgQC/gTUrXSeNvuRH+ibdR7zvlCGs+66C6tDaq14SpEDiY/FEw/S4\n"
  "mkhsHohiQkmqpcPJ0FONok7bvJryKZwwhGFHeESvvWjFVNIdxFgf6Jx2McKsRzBD\n"
  "nbgVNeK6bywh2L5WgOeckRm0vUxCwX+jWtETorNHSYnZI9smmBtJ1FIPkQIDAQAB\n"
  "o3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRl\n"
  "ZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUS0IiRshnnlH2bneYeCn6OkY9nZAwHwYD\n"
  "VR0jBBgwFoAU+rCwSUUzK53X9W5otZG4okyY/rswDQYJKoZIhvcNAQEFBQADgYEA\n"
  "g0f6XFxpUL2hncpQcnKorNYdOkZkZHiKqu2SINtla+IbLZFO4nVVO+LKt+RCo2o7\n"
  "tZIMLEU3aCeH5dgSEKQeyL5MPMg3MbA6ezjOBTkT/YgngzM4CMLOKcvAMLncfH/z\n"
  "GYBW1DXijIy1r/SxO0k9zy8OEtKeOOUO0GqQTWuTOOg=\n"
  "-----END CERTIFICATE-----\n",
  /* chain[1] (CA) */
  "-----BEGIN CERTIFICATE-----\n"
  "MIICvzCCAiigAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJERTEM\n"
  "MAoGA1UECBMDUkxQMSAwHgYDVQQKExdUZWNobmlzY2hlIFVuaXZlcnNpdGFldDEb\n"
  "MBkGA1UECxMSRmFjaGJlcmVpY2ggUGh5c2lrMQswCQYDVQQDEwJDQTAeFw0wODA5\n"
  "MTExMDQ3NDRaFw0xODA5MDkxMDQ3NDRaMGcxCzAJBgNVBAYTAkRFMQwwCgYDVQQI\n"
  "EwNSTFAxIDAeBgNVBAoTF1RlY2huaXNjaGUgVW5pdmVyc2l0YWV0MRswGQYDVQQL\n"
  "ExJGYWNoYmVyZWljaCBQaHlzaWsxCzAJBgNVBAMTAkNBMIGfMA0GCSqGSIb3DQEB\n"
  "AQUAA4GNADCBiQKBgQC76RbqsB5J+VvU1KbBCrkIL3lgY8BxgFvYF3HiHgxtCdqq\n"
  "BmRpAaDBcVAuEb1ihhP68181sYQ1UPMY+zwBwXVNSVvjeBba1JjGmagwPnJXOCay\n"
  "7Cw5orY8KB7U33neEOGrlz1EKQGVaPsr993wGD/7AmntuVuxrRVpzoDP5s0PIwID\n"
  "AQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVy\n"
  "YXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU+rCwSUUzK53X9W5otZG4okyY/rsw\n"
  "HwYDVR0jBBgwFoAU+rCwSUUzK53X9W5otZG4okyY/rswDQYJKoZIhvcNAQEFBQAD\n"
  "gYEAUT+LmosiDHGuLAZmY40obam0eexJzn/g++mDy3FMh3WmMBKSsfwFsFsQ4k7N\n"
  "lv1SCfTYeh2hpw/DQzkiYZUkcQI4mBR4hG5Zv56AfYQLGeLtN4VOOCMxguftvzv0\n"
  "kziQa2QW+VzVJqV1gpRCRT30Jaa9s4u6ipO9DT5N03F4CcI=\n"
  "-----END CERTIFICATE-----\n",
  NULL
};

/* Chain length 3 ends with trusted v1 RSA-MD2 cert, similar to
   verisign_com_chain above */
static const char *hbci_chain[] = {
  /* chain[0] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIEczCCA9ygAwIBAgIQeODCPg2RbK2r7/1KoWjWZzANBgkqhkiG9w0BAQUFADCB\n"
  "ujEfMB0GA1UEChMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazEXMBUGA1UECxMOVmVy\n"
  "aVNpZ24sIEluYy4xMzAxBgNVBAsTKlZlcmlTaWduIEludGVybmF0aW9uYWwgU2Vy\n"
  "dmVyIENBIC0gQ2xhc3MgMzFJMEcGA1UECxNAd3d3LnZlcmlzaWduLmNvbS9DUFMg\n"
  "SW5jb3JwLmJ5IFJlZi4gTElBQklMSVRZIExURC4oYyk5NyBWZXJpU2lnbjAeFw0w\n"
  "ODA2MTAwMDAwMDBaFw0wOTA3MzAyMzU5NTlaMIG2MQswCQYDVQQGEwJERTEPMA0G\n"
  "A1UECBMGSGVzc2VuMRowGAYDVQQHFBFGcmFua2Z1cnQgYW0gTWFpbjEsMCoGA1UE\n"
  "ChQjU3Bhcmthc3NlbiBJbmZvcm1hdGlrIEdtYkggJiBDby4gS0cxKTAnBgNVBAsU\n"
  "IFRlcm1zIG9mIHVzZSBhdCB3d3cudmVyaXNpZ24uY29tMSEwHwYDVQQDFBhoYmNp\n"
  "LXBpbnRhbi1ycC5zLWhiY2kuZGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n"
  "AK1CdQ9lqmChZWaRAInimuK7I36VImTuAVU0N6BIS4a2BbblkiekbVf15GVHGb6e\n"
  "QV06ANN6Nd8XIdfoxi3LoAs8sa+Ku7eoEsRFi/XIU96GgtFlxf3EsVA9RbGdtfer\n"
  "9iJGIBae2mJTlk+5LVg2EQr50PJlBuTgiYFc41xs9O2RAgMBAAGjggF6MIIBdjAJ\n"
  "BgNVHRMEAjAAMAsGA1UdDwQEAwIFoDBGBgNVHR8EPzA9MDugOaA3hjVodHRwOi8v\n"
  "Y3JsLnZlcmlzaWduLmNvbS9DbGFzczNJbnRlcm5hdGlvbmFsU2VydmVyLmNybDBE\n"
  "BgNVHSAEPTA7MDkGC2CGSAGG+EUBBxcDMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v\n"
  "d3d3LnZlcmlzaWduLmNvbS9ycGEwKAYDVR0lBCEwHwYJYIZIAYb4QgQBBggrBgEF\n"
  "BQcDAQYIKwYBBQUHAwIwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRw\n"
  "Oi8vb2NzcC52ZXJpc2lnbi5jb20wbgYIKwYBBQUHAQwEYjBgoV6gXDBaMFgwVhYJ\n"
  "aW1hZ2UvZ2lmMCEwHzAHBgUrDgMCGgQUS2u5KJYGDLvQUjibKaxLB4shBRgwJhYk\n"
  "aHR0cDovL2xvZ28udmVyaXNpZ24uY29tL3ZzbG9nbzEuZ2lmMA0GCSqGSIb3DQEB\n"
  "BQUAA4GBAJ03R0YAjYzlWm54gMSn6MqJi0mHdLCO2lk3CARwjbg7TEYAZvDsKqTd\n"
  "cRuhNk079BqrQ3QapffeN55SAVrc3mzHO54Nla4n5y6x3XIQXVvRjbJGwmWXsdvr\n"
  "W899F/pBEN30Tgdbmn7JR/iZlGhIJpY9Us1i7rwQhKYir9ZQBdj3\n"
  "-----END CERTIFICATE-----\n",
  /* chain[1] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDgzCCAuygAwIBAgIQJUuKhThCzONY+MXdriJupDANBgkqhkiG9w0BAQUFADBf\n"
  "MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsT\n"
  "LkNsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw\n"
  "HhcNOTcwNDE3MDAwMDAwWhcNMTExMDI0MjM1OTU5WjCBujEfMB0GA1UEChMWVmVy\n"
  "aVNpZ24gVHJ1c3QgTmV0d29yazEXMBUGA1UECxMOVmVyaVNpZ24sIEluYy4xMzAx\n"
  "BgNVBAsTKlZlcmlTaWduIEludGVybmF0aW9uYWwgU2VydmVyIENBIC0gQ2xhc3Mg\n"
  "MzFJMEcGA1UECxNAd3d3LnZlcmlzaWduLmNvbS9DUFMgSW5jb3JwLmJ5IFJlZi4g\n"
  "TElBQklMSVRZIExURC4oYyk5NyBWZXJpU2lnbjCBnzANBgkqhkiG9w0BAQEFAAOB\n"
  "jQAwgYkCgYEA2IKA6NYZAn0fhRg5JaJlK+G/1AXTvOY2O6rwTGxbtueqPHNFVbLx\n"
  "veqXQu2aNAoV1Klc9UAl3dkHwTKydWzEyruj/lYncUOqY/UwPpMo5frxCTvzt01O\n"
  "OfdcSVq4wR3Tsor+cDCVQsv+K1GLWjw6+SJPkLICp1OcTzTnqwSye28CAwEAAaOB\n"
  "4zCB4DAPBgNVHRMECDAGAQH/AgEAMEQGA1UdIAQ9MDswOQYLYIZIAYb4RQEHAQEw\n"
  "KjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL0NQUzA0BgNV\n"
  "HSUELTArBggrBgEFBQcDAQYIKwYBBQUHAwIGCWCGSAGG+EIEAQYKYIZIAYb4RQEI\n"
  "ATALBgNVHQ8EBAMCAQYwEQYJYIZIAYb4QgEBBAQDAgEGMDEGA1UdHwQqMCgwJqAk\n"
  "oCKGIGh0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTMuY3JsMA0GCSqGSIb3DQEB\n"
  "BQUAA4GBAAgB7ORolANC8XPxI6I63unx2sZUxCM+hurPajozq+qcBBQHNgYL+Yhv\n"
  "1RPuKSvD5HKNRO3RrCAJLeH24RkFOLA9D59/+J4C3IYChmFOJl9en5IeDCSk9dBw\n"
  "E88mw0M9SR2egi5SX7w+xmYpAY5Okiy8RnUDgqxz6dl+C2fvVFIa\n"
  "-----END CERTIFICATE-----\n",
  /* chain[2] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIICPDCCAaUCEHC65B0Q2Sk0tjjKewPMur8wDQYJKoZIhvcNAQECBQAwXzELMAkG\n"
  "A1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFz\n"
  "cyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTk2\n"
  "MDEyOTAwMDAwMFoXDTI4MDgwMTIzNTk1OVowXzELMAkGA1UEBhMCVVMxFzAVBgNV\n"
  "BAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFzcyAzIFB1YmxpYyBQcmlt\n"
  "YXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GN\n"
  "ADCBiQKBgQDJXFme8huKARS0EN8EQNvjV69qRUCPhAwL0TPZ2RHP7gJYHyX3KqhE\n"
  "BarsAx94f56TuZoAqiN91qyFomNFx3InzPRMxnVx0jnvT0Lwdd8KkMaOIG+YD/is\n"
  "I19wKTakyYbnsZogy1Olhec9vn2a/iRFM9x2Fe0PonFkTGUugWhFpwIDAQABMA0G\n"
  "CSqGSIb3DQEBAgUAA4GBALtMEivPLCYATxQT3ab7/AoRhIzzKBxnki98tsX63/Do\n"
  "lbwdj2wsqFHMc9ikwFPwTtYmwHYBV4GSXiHx0bH/59AhWM1pF+NEHJwZRDmJXNyc\n"
  "AA9WjQKZ7aKQRUzkuxCkPfAyAw7xzvjoyVGM5mKf5p/AfbdynMk2OmufTqj/ZA1k\n"
  "-----END CERTIFICATE-----\n",
  NULL
};

/* End-entity cert signed using RSA-MD5. */
static const char *mayfirst_chain[] = {
  /* chain[0] */
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDVTCCAr6gAwIBAgIDCHp1MA0GCSqGSIb3DQEBBAUAMFoxCzAJBgNVBAYTAlVT\n"
  "MRwwGgYDVQQKExNFcXVpZmF4IFNlY3VyZSBJbmMuMS0wKwYDVQQDEyRFcXVpZmF4\n"
  "IFNlY3VyZSBHbG9iYWwgZUJ1c2luZXNzIENBLTEwHhcNMDgwNTE5MDUyOTE5WhcN\n"
  "MDkxMDE5MDUyOTE5WjCBxDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFHN1cHBvcnQu\n"
  "bWF5Zmlyc3Qub3JnMRMwEQYDVQQLEwpHVDY5MDc5ODgwMTEwLwYDVQQLEyhTZWUg\n"
  "d3d3LnJhcGlkc3NsLmNvbS9yZXNvdXJjZXMvY3BzIChjKTA3MS8wLQYDVQQLEyZE\n"
  "b21haW4gQ29udHJvbCBWYWxpZGF0ZWQgLSBSYXBpZFNTTChSKTEdMBsGA1UEAxMU\n"
  "c3VwcG9ydC5tYXlmaXJzdC5vcmcwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n"
  "AN0TWIZwJ/hIfMHc08/bBMlzZ5WucJqEvxU/ZnxPo/H6V/m4v1iLpM2hip2c5cg0\n"
  "BcEMc/TBHQ1UEV8sb0Lh91kWfiMB1Sp+L2Fpz/wnhsivXC5j6jq9IcPqmOZOXBYX\n"
  "k04W1B6FKTvk9KrZJ0at2J44hp4SsAfWQI0eCKuas+R1AgMBAAGjgb0wgbowDgYD\n"
  "VR0PAQH/BAQDAgTwMB0GA1UdDgQWBBS0D4iuCxp35TLADTkINq2AhgTYVTA7BgNV\n"
  "HR8ENDAyMDCgLqAshipodHRwOi8vY3JsLmdlb3RydXN0LmNvbS9jcmxzL2dsb2Jh\n"
  "bGNhMS5jcmwwHwYDVR0jBBgwFoAUvqigdHJQa0S3ySPY+6j/s1draGwwHQYDVR0l\n"
  "BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcN\n"
  "AQEEBQADgYEAXNWYnrO1mZgBSCwPlWhVa2aOKGCFmehLIcAPEBN+8xhXuOeigYBm\n"
  "ic5ShCO583ttgHNCV3Y5dW9sNhv1US4vSb6soKjgUlG11fJKUqU8mwFKvbs7TUSq\n"
  "j6h+1uvlfFI34WzODjJloY4QSM7FmbnW+HCiFKYyvra3iUqjcl9AeR4=\n"
  "-----END CERTIFICATE-----\n",
  /* chain[1] (CA) */
  "-----BEGIN CERTIFICATE-----\n"
  "MIICkDCCAfmgAwIBAgIBATANBgkqhkiG9w0BAQQFADBaMQswCQYDVQQGEwJV\n"
  "UzEcMBoGA1UEChMTRXF1aWZheCBTZWN1cmUgSW5jLjEtMCsGA1UEAxMkRXF1\n"
  "aWZheCBTZWN1cmUgR2xvYmFsIGVCdXNpbmVzcyBDQS0xMB4XDTk5MDYyMTA0\n"
  "MDAwMFoXDTIwMDYyMTA0MDAwMFowWjELMAkGA1UEBhMCVVMxHDAaBgNVBAoT\n"
  "E0VxdWlmYXggU2VjdXJlIEluYy4xLTArBgNVBAMTJEVxdWlmYXggU2VjdXJl\n"
  "IEdsb2JhbCBlQnVzaW5lc3MgQ0EtMTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw\n"
  "gYkCgYEAuucXkAJlsTRVPEnCUdXfp9E3j9HngXNBUmCbnaEXJnitx7HoJpQy\n"
  "td4zjTov2/KaelpzmKNc6fuKcxtc58O/gGzNqfTWK8D3+ZmqY6KxRwIP1ORR\n"
  "OhI8bIpaVIRw28HFkM9yRcuoWcDNM50/o5brhTMhHD4ePmBudpxnhcXIw2EC\n"
  "AwEAAaNmMGQwEQYJYIZIAYb4QgEBBAQDAgAHMA8GA1UdEwEB/wQFMAMBAf8w\n"
  "HwYDVR0jBBgwFoAUvqigdHJQa0S3ySPY+6j/s1draGwwHQYDVR0OBBYEFL6o\n"
  "oHRyUGtEt8kj2Puo/7NXa2hsMA0GCSqGSIb3DQEBBAUAA4GBADDiAVGqx+pf\n"
  "2rnQZQ8w1j7aDRRJbpGTJxQx78T3LUX47Me/okENI7SS+RkAZ70Br83gcfxa\n"
  "z2TE4JaY0KNA4gGK7ycH8WUBikQtBmV1UsCGECAhX2xrD2yuCRyv8qIYNMR1\n"
  "pHMc8Y3c7635s3a0kr/clRAevsvIO1qEYBlWlKlV\n"
  "-----END CERTIFICATE-----\n",
  NULL
};

static struct
{
  const char *name;
  const char **chain;
  const char **ca;
  int verify_flags;
  int expected_verify_result;
} chains[] =
{
  { "CVE-2008-4989", cve_2008_4989_chain, &cve_2008_4989_chain[2],
    0, GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_INVALID },
  { "verisign.com v1 fail", verisign_com_chain, &verisign_com_chain[3],
    0, GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INVALID },
  { "verisign.com v1 ok", verisign_com_chain, &verisign_com_chain[3],
    GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT, 0 },
  { "citibank.com v1 fail", citibank_com_chain, &citibank_com_chain[2],
    0, GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INVALID },
  { "self signed", pem_self_cert, &pem_self_cert[0],
    0, 0 },
  { "ca=false", thea_chain, &thea_chain[1],
    GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT,
    GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INVALID },
  { "ca=false2", thea_chain, &thea_chain[1],
    0, GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INVALID },
  { "hbci v1 fail", hbci_chain, &hbci_chain[2],
    0, GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INVALID},
  { "hbci v1 ok", hbci_chain, &hbci_chain[2],
    GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT, 0 },
  { "rsa-md5 fail", mayfirst_chain, &mayfirst_chain[1],
    0, GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID },
  { "rsa-md5 not ok", mayfirst_chain, &mayfirst_chain[1],
    GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2,
    GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID },
  { "rsa-md5 ok", mayfirst_chain, &mayfirst_chain[1],
    GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5, 0 },
  { NULL, NULL, NULL, 0}
};
/* *INDENT-ON* */

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}

int
main (int argc, char *argv[])
{
  int exit_val = 0;
  size_t i;
  int ret;

  ret = gnutls_global_init ();
  if (ret != 0)
    {
      printf ("%d: %s\n", ret, gnutls_strerror (ret));
      return EXIT_FAILURE;
    }

  gnutls_global_set_log_function (tls_log_func);
  gnutls_global_set_log_level (4711);

  for (i = 0; chains[i].chain; i++)
    {
      unsigned int verify_status;
      gnutls_x509_crt_t certs[4];
      gnutls_x509_crt_t ca;
      gnutls_datum_t tmp;
      size_t j;

      printf ("Chain '%s' (%d)...\n", chains[i].name, i);

      for (j = 0; chains[i].chain[j]; j++)
	{
	  printf ("\tAdding certificate %d...", j);

	  ret = gnutls_x509_crt_init (&certs[j]);
	  if (ret < 0)
	    error (EXIT_FAILURE, 0, "gnutls_x509_crt_init[%d,%d]: %s", i, j,
		   gnutls_strerror (ret));

	  tmp.data = (char *) chains[i].chain[j];
	  tmp.size = strlen (chains[i].chain[j]);

	  ret = gnutls_x509_crt_import (certs[j], &tmp, GNUTLS_X509_FMT_PEM);
	  printf ("done\n");
	  if (ret < 0)
	    error (EXIT_FAILURE, 0, "gnutls_x509_crt_import[%d,%d]: %s", i, j,
		   gnutls_strerror (ret));
	}

      printf ("\tAdding CA certificate...");

      ret = gnutls_x509_crt_init (&ca);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "gnutls_x509_crt_init: %s",
	       gnutls_strerror (ret));

      tmp.data = (char *) *chains[i].ca;
      tmp.size = strlen (*chains[i].ca);

      ret = gnutls_x509_crt_import (ca, &tmp, GNUTLS_X509_FMT_PEM);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "gnutls_x509_crt_import: %s",
	       gnutls_strerror (ret));

      printf ("done\n");
      printf ("\tVerifying...");

      ret = gnutls_x509_crt_list_verify (certs, j,
					 &ca, 1, NULL, 0,
					 chains[i].verify_flags,
					 &verify_status);
      if (ret < 0)
	error (EXIT_FAILURE, 0, "gnutls_x509_crt_list_verify[%d,%d]: %s",
	       i, j, gnutls_strerror (ret));

      if (verify_status != chains[i].expected_verify_result)
	{
	  error (0, 0, "verify_status: %d expected: %d",
		 verify_status, chains[i].expected_verify_result);
	  exit_val = 1;
	}
      else
	printf ("done\n");
      printf ("\tCleanup...");

      gnutls_x509_crt_deinit (ca);
      for (j = 0; chains[i].chain[j]; j++)
	gnutls_x509_crt_deinit (certs[j]);

      printf ("done\n");
    }

  gnutls_global_deinit ();

  return exit_val;
}
