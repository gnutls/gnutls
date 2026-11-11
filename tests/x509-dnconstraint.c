/*
 * Copyright (C) 2026 Alexander Sosedkin
 *
 * Author: Alexander Sosedkin
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "utils.h"
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <stdbool.h>

/* Test that directoryName (DN) name constraints in a CA certificate
 * are enforced on the end certificate's DN names (RFC 5280 4.2.1.10).
 *
 * We cannot match DN names, so we fail closed:
 * a certificate with a DN name (a directoryName SAN, or a non-empty subject DN)
 * is rejected if the CA carries a DN constraint,
 * while a certificate with no DN name at all is accepted.
 */

void verify_leaf(const gnutls_x509_crt_t *, unsigned,
		 gnutls_x509_name_constraints_t, const char *, const char *,
		 unsigned, bool);
static const char _ca_excluded[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDaTCCAlGgAwIBAgIUMzvtL7UkeutCjWjLUFchyaVDVt4wDQYJKoZIhvcNAQEL\n"
	"BQAwODEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR8wHQYDVQQDDBZFeGFtcGxlIENB\n"
	"IEROIEV4Y2x1ZGVkMB4XDTI2MTExMTE3NDQzOFoXDTM2MTEwODE3NDQzOFowODEV\n"
	"MBMGA1UECgwMRXhhbXBsZSBJbmMuMR8wHQYDVQQDDBZFeGFtcGxlIENBIEROIEV4\n"
	"Y2x1ZGVkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo/uwU8F10Ln4\n"
	"yFgsLFyHp2cTea5kMnzTeLoiliKgmbpMQA1HNt0cwmwkOFDWCGVD3Kj789KT5p7B\n"
	"Ve95WbpBWFhWPAJq9mwhoA4rme/XaM1o2d97iLVJ3qXZ7GZYyd0hKqGaFfYLxoes\n"
	"xvlNJbNfoej7PmN1T2YeLMhHKCplFsXbpbXV0nrAu5LVOCS7bRKCUpF3NLkOW0oB\n"
	"4PrlHoY5aMkMLr5/ERMBWdc0utw+LWIedtAhnHOK+e1vLD8enDBJeVPTJTDHHd0S\n"
	"akO5AzYzn5LghTJW5cInQvLx1stWrpExMQYc88VnR0kszh6yObuKsTKihMPqLDPk\n"
	"cfCcfWv6NQIDAQABo2swaTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB\n"
	"BjAnBgNVHR4EIDAeoRwwGqQYMBYxFDASBgNVBAoMC2JhZC5leGFtcGxlMB0GA1Ud\n"
	"DgQWBBRAbNEdXZ8hnE4xhTmN5BZN93nHFDANBgkqhkiG9w0BAQsFAAOCAQEADCJu\n"
	"ZJXGslchxkUXjtJ2bV50eS5zJA26Ktl7bMVPoXvJSLen00oQKYVAg5/uSK+4gAMP\n"
	"MieuDN9VgLhmU8SJZt59YscuGMYMHQthJ6NBWxU+4RfW0RQdhk2exbTDz9c9+nDs\n"
	"rw3tesrU5CNsMxsCgkSgvgK/WNQXa2YyrDKz8qnZTHxoH+Tzv4LpIqBlMNJ2LCse\n"
	"ouxpGpmYvCBeXtTI1ER+7sAcDILjmWZ7WR1QCHaUPfvapNXlxW7t04LYIx/dDHYi\n"
	"RQ2fNYvoalSkaF+Sa+cUBzdKIcv0SqOTV1ZHGCCuaAY/eQZA8hjPwx9MpR+nG3rV\n"
	"rSAU6wn2w6vCbZu29A==\n"
	"-----END CERTIFICATE-----"
};
static const char _leaf_subject[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDQDCCAiigAwIBAgIUR8UaaaxZ9Foci93sHcvo1mOvT2UwDQYJKoZIhvcNAQEL\n"
	"BQAwODEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR8wHQYDVQQDDBZFeGFtcGxlIENB\n"
	"IEROIEV4Y2x1ZGVkMB4XDTI2MTExMTE3NDQzOFoXDTM2MTEwODE3NDQzOFowLTEU\n"
	"MBIGA1UECgwLYmFkLmV4YW1wbGUxFTATBgNVBAMMDGxlYWYtc3ViamVjdDCCASIw\n"
	"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOGuqcn5EnbxWDfr7CFw8FJJULno\n"
	"a7yiyb3jEIT60pXbjVt+yECDfYIC/1TTD/P/dAH9yB7d/k8b2ZDyDSSCMiWmgf/o\n"
	"8kH+9WMKZP/pu/r4P45zl98xzIplLdYp/8ObX//IvJ7+jXRFctqundhxhH52Iiov\n"
	"ayGWWHb3xzXs7XH3oJZVvDVvdMuEyr2nf8/It9+DlxjqJMzUJfjbjGc1YXEGpVYw\n"
	"it6NhB6NehX5+1LR8d+23DZRPW8OdU5QOwbXO7iwOev1eXz1J86xkqNWFrgTH057\n"
	"5U/m/SD4+XUu1OyOakAlXdaj6gEQDxOpMHyq6/YczacepM7qouGlA9spKakCAwEA\n"
	"AaNNMEswCQYDVR0TBAIwADAdBgNVHQ4EFgQURTfTHY/51HaM3TLy9EC7avEClRQw\n"
	"HwYDVR0jBBgwFoAUQGzRHV2fIZxOMYU5jeQWTfd5xxQwDQYJKoZIhvcNAQELBQAD\n"
	"ggEBAG6H56iABMo7ZTWyQ1y/cUYjNhRFfEDmBDboayWqMWl+5n98XB7Ry7ovUKdC\n"
	"9BXfR63I4R+sbimk0i2Xix5hUF1LXa68sXI8c8e73+uxZRFINN30Z9dbw3n2Yem2\n"
	"WqP8f2wnIKtRxUR7QuwlnwkOmTzdIw7Zrg2ePnIKGSzVEhT6o9RUlt+9Q9+jzPOw\n"
	"wGaGxnV33YP1aNlAn7D+HzhFzBBSY3Hy1LK6bCtoO/UWtAX4rQws/vcxqx/JuyNv\n"
	"6hzHhZf4i5KOn+Ummj+hUj9SVtEBfkZeQ+lRdbxZ6MjvOQE3oxbrc+WcIwob5gjQ\n"
	"xxYhwe3ObsGCaNHHpGomdKfdKiw=\n"
	"-----END CERTIFICATE-----"
};
static const char _leaf_san[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDTTCCAjWgAwIBAgIUR8UaaaxZ9Foci93sHcvo1mOvT2YwDQYJKoZIhvcNAQEL\n"
	"BQAwODEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR8wHQYDVQQDDBZFeGFtcGxlIENB\n"
	"IEROIEV4Y2x1ZGVkMB4XDTI2MTExMTE3NDQzOFoXDTM2MTEwODE3NDQzOFowADCC\n"
	"ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALLSQzUv1rIR6cNpkI5uOxg/\n"
	"xWglxmaDxjT1g8qE+gEXh1/dz3JoVHynPG6KBJGjKcBEbhj5m9mMP4CVDv6cJGWy\n"
	"GUrvuhU3Dl362Dqyfsdia3RYbRkViai/XjPkf4eOGxAHU+cQ+6NLOB9xRU6wwn0U\n"
	"wg7LqMqqYgy8g+7bnCqVYzyJIvnwHBM0b3IV7lucD273qb4gNfx0qN/sm4a6+ZYB\n"
	"+TGTL3jjgtKuATi8o1j9I/5L2dZ7gth/E4Yg2A2yduyYQgMrYKB3pb2u/VxRasHu\n"
	"pzdLLtC8c2R3n0XeXYklWE4DE+5Qup3W7TbPz6pNt2CWNlXjTIC7UpxAMmWBSBkC\n"
	"AwEAAaOBhjCBgzAJBgNVHRMEAjAAMDYGA1UdEQQvMC2kKzApMRQwEgYDVQQKDAti\n"
	"YWQuZXhhbXBsZTERMA8GA1UEAwwIbGVhZi1zYW4wHQYDVR0OBBYEFHdxvPCGovzs\n"
	"7pW3vhSqVtdIR8LFMB8GA1UdIwQYMBaAFEBs0R1dnyGcTjGFOY3kFk33eccUMA0G\n"
	"CSqGSIb3DQEBCwUAA4IBAQCEEiBnWTKBRFDP5ZmU2AS52o7V663SAuh/UtuV6oSY\n"
	"EYZAwNaA1EzmQxZm8jqacZ/FshhgASWrMSdLO0uQPybO7SeZvxb6oRmo6bQ+Hb6P\n"
	"fKQKNgDOq94owOXBkCDd8/9q0IkbAM0Le5qPb7uZfReWTpt7CIX5zDhrTBOUbrRn\n"
	"FDBB71hd0OQyYkq7mNt42/iaHMY00zDRtPIyKIZT40EDwGbdtkq0M4ACsaZb+Tgy\n"
	"buCNW8/cQyC4iFc+h+f18yfEaI+pKbvkh2So+85XNWbzcoO1Zq2FL8Qd6dXYtczm\n"
	"WJ5XArrYc9X6B+iFC2Pp+KJ93WBwqZ8svLi8nKv/RYPt\n"
	"-----END CERTIFICATE-----"
};
static const char _leaf_none[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDEzCCAfugAwIBAgIUR8UaaaxZ9Foci93sHcvo1mOvT2cwDQYJKoZIhvcNAQEL\n"
	"BQAwODEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR8wHQYDVQQDDBZFeGFtcGxlIENB\n"
	"IEROIEV4Y2x1ZGVkMB4XDTI2MTExMTE3NDQzOFoXDTM2MTEwODE3NDQzOFowADCC\n"
	"ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALh7GIy9rfs/Qr8J/pfaRW34\n"
	"HCGXgyU2QD6yFV/epqlUewou1fKWj+TTARuzen8I/K11KfnR9+N6hRKS1KQBRt/s\n"
	"ro9tG7o2uKxef4DdyJ2RwFeK32vzM/RvLlVnkYfHSnddGEs5CTpA2ony5cs5/yuh\n"
	"GDmuUf0actuNnWx2C4DiWMNMC+c2RUXhcb30TJ+24HvXvd6RAEaOhMG/HSpS33uV\n"
	"vjtNeQti98M2tC+7VOAVjkv1GCltu9jkEagOcTbGhrgj+++RQgoD2VKTvEIoL1L9\n"
	"WidZAhi7ag0qr9mXmQt93mMib6vh2bUmcOnXb2IR/DteMVs+n2gjus6aswatYUEC\n"
	"AwEAAaNNMEswCQYDVR0TBAIwADAdBgNVHQ4EFgQUwmLE3RJ37wq2rsJ+34/+1tGr\n"
	"bOgwHwYDVR0jBBgwFoAUQGzRHV2fIZxOMYU5jeQWTfd5xxQwDQYJKoZIhvcNAQEL\n"
	"BQADggEBABWGRMuaSZMhfpqJFhc2YKhF59VRN0xv8B/eA5EFy+kBUeUKNWz3ygxU\n"
	"OIdA4a0kGyMvJ1NOGi2CZ/BaGOJFsds+iZX6z72zI62I3uJsY6fkJfPa4RY2Gh99\n"
	"9RJcjrXx6bXcjXZVbMJj+QdjTgN+LiE63d0CFeu3I2fuJLUL5K5/izTToxBPAsWn\n"
	"SmDZPsnG8t8ck5YVwOYHyf7e0SDUC8GUErHh+op90P+ZplZAYLi0lSd2pl9UhQT2\n"
	"P9YrK/Qwux1PXTMJlMm/f5EZ/CkJdMoY7c9jebarRzfRkj9wUj6Vv0ha/8J6RGWc\n"
	"Y9o3tK8QzZaBW9KNeNWAzhqTTYZD/ac=\n"
	"-----END CERTIFICATE-----"
};
static const char _ca_permitted[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDazCCAlOgAwIBAgIUKOIhmaOGJJ0AuEl/koa8uQdjYRowDQYJKoZIhvcNAQEL\n"
	"BQAwOTEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMSAwHgYDVQQDDBdFeGFtcGxlIENB\n"
	"IEROIFBlcm1pdHRlZDAeFw0yNjExMTExODMzMjlaFw0zNjExMDgxODMzMjlaMDkx\n"
	"FTATBgNVBAoMDEV4YW1wbGUgSW5jLjEgMB4GA1UEAwwXRXhhbXBsZSBDQSBETiBQ\n"
	"ZXJtaXR0ZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoItvTyPaU\n"
	"3hemFACTbsq6JCePfwLakqzpU5O3E40yUaNUni164Z16+xPO5SdjwzcEJ67Mue3T\n"
	"Z07ZrUqe3UTsdzEoeY2RrDrLCG9IByy90jYriWiA+UvBBM8TIZagH11JmEsTc0ah\n"
	"DGgsOiAWpIyS21780oe5m4ojMd3NeOZPpF4waX67EJjEU9FAtEazKgWTR7jyfitL\n"
	"JgO3wmnFsym/iW3LyuTzXAIhBR+MyGcw/wAe3P+DyuyubQQcHQF87lkI8J3JRuCh\n"
	"duYOlOv8B6cGG0McuIwwATuQqtUa4g8qTS194UBEu8Ml6QdH0hOGE1R5OD2PCKjy\n"
	"h+RQZ1jRfPtJAgMBAAGjazBpMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD\n"
	"AgEGMCcGA1UdHgQgMB6gHDAapBgwFjEUMBIGA1UECgwLYmFkLmV4YW1wbGUwHQYD\n"
	"VR0OBBYEFMnFsp2qL/bIuN1yn+krywaoqX2FMA0GCSqGSIb3DQEBCwUAA4IBAQAC\n"
	"NwiB8bka4tMT7i4smPOyaJqutTDBh8N79RoFLoSiygvsq325dN7sEHrnd9b82po+\n"
	"ypIsLjI7iMfhVGYZgk2+NnO4MR6d8xuLXwmyoNV5ELjRKjHGYVJY7+nO8UHAKFSw\n"
	"qbL9StUA+wKYUGQFrpYcC5WvbqZMxHVnwONwg5OcwGogPKkaX5sNXcTeuyEaOa2L\n"
	"MjyPn+WxTXEbWNkQeSEwz3hh4wUEZvUFCiHvPVN921C+lmx3oHMOhRUGgmpttIpG\n"
	"Z9lt/1ebexM68dF2+vBBpBmphXVW4x/pC704NoxKJOTv+Pke13UQGFCm0ofwoDgx\n"
	"vz+KbIuZEMEVNK0bl9Cu\n"
	"-----END CERTIFICATE-----"
};
static const char _perm_leaf_subject[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDQTCCAimgAwIBAgIUOwgi8PBl82PB8rHe4HHogGqAFK0wDQYJKoZIhvcNAQEL\n"
	"BQAwOTEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMSAwHgYDVQQDDBdFeGFtcGxlIENB\n"
	"IEROIFBlcm1pdHRlZDAeFw0yNjExMTExODM1MzhaFw0zNjExMDgxODM1MzhaMC0x\n"
	"FDASBgNVBAoMC2JhZC5leGFtcGxlMRUwEwYDVQQDDAxsZWFmLXN1YmplY3QwggEi\n"
	"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4LMVAXGeOqiwurrbkL/o6UiGn\n"
	"8YIRr9H2X4WPX/ODO9txX1cBjOFaoay1C2ZRiKylQlwNQ3d3aptWfoAEyxN2LVqn\n"
	"Mbby31ygw3em4IQ0tr1AhXbBXwH1dgp3P7q/byWfKQelOwtJjGDw/YL6KjdCMldU\n"
	"64OOCvx3Y0RxzFl86QsHNbE6rGyWYU3jdUdAPqwqYV//gupr6ymY6i4IpQ07EAbg\n"
	"EZlt8x5J0QumY9qCeSBbWVIQk/tlwE3Dk5IgHdDqWRxYybdvJfaxchcoJ+jty3IZ\n"
	"n8TMyLH7qDbr3HowtkPrzKmTtxFUFIgcuaSuWVO4pbNIzpDFuJGEmU/ds77vAgMB\n"
	"AAGjTTBLMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFMXdBLVfY5Zi/eWH6gev+iTQI1u\n"
	"MB8GA1UdIwQYMBaAFMnFsp2qL/bIuN1yn+krywaoqX2FMA0GCSqGSIb3DQEBCwUA\n"
	"A4IBAQBGRk0FcWsZvAKylAigVt6l8Il4BNs9Mfye8H4sAUtx4682Cu5TgjCbrC9F\n"
	"SiCw6U60MJb2qmUUiRdzbof6cg7p6sS+NlPYl6zdj/XoWAAg0e2Fq+U95fHhB8Af\n"
	"TWWhWS0ccT45cr6eQGwbW6/0wFRgpBJx9mwes/9NhBRxOJAODWYhtgwWOYuiNpDm\n"
	"WxjkEJRRINNzhJUAZBEbWylMUnigqc+30a7MVq8QlUtrfTfgCC3bsSygq94xJrGF\n"
	"oPWojgOp6hSVfr4PeG8JR5Nmo+YTp5MuNtPsdxau92lIK3g6SfZTkzlynTW1NUEC\n"
	"TJEhOE2SluBw/yd0PQgrL5DQVKxd\n"
	"-----END CERTIFICATE-----"
};
static const char _perm_leaf_san[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDTjCCAjagAwIBAgIUOwgi8PBl82PB8rHe4HHogGqAFK4wDQYJKoZIhvcNAQEL\n"
	"BQAwOTEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMSAwHgYDVQQDDBdFeGFtcGxlIENB\n"
	"IEROIFBlcm1pdHRlZDAeFw0yNjExMTExODM1MzhaFw0zNjExMDgxODM1MzhaMAAw\n"
	"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEImeg2liXjiUI096Lu0HB\n"
	"xlRHPrfn2Uepqn/AfyUNVV8tAfDzA+iAsy4eXrKL/6Oke2tfVa7WAoiCujDl9xJy\n"
	"gi+1UMixYDyOxzBn5K/sUuy1oXWz1L2sZOv8GtXfkAqNUdGz2PsKxR2rZyuLcBXu\n"
	"zkzEOYHZLuQw8TjB1+6ZNOPAZyixrmuiaN88K/f2Y+Bsxd1i4qTc3bsaxaklswmR\n"
	"4+eKdvjHKFhfjF5OTRxEa4Rx7lg6cstCvoLQFO+RWvtgwQK+P7QokgZH4Mc16oMu\n"
	"WNX4X/YxQX2usbQXF1vJByWDmXmci3ZvtEp++vVstwy5rhJbXqu+64Iisp7cAuvT\n"
	"AgMBAAGjgYYwgYMwCQYDVR0TBAIwADA2BgNVHREELzAtpCswKTEUMBIGA1UECgwL\n"
	"YmFkLmV4YW1wbGUxETAPBgNVBAMMCGxlYWYtc2FuMB0GA1UdDgQWBBS368KjInRA\n"
	"BUTjSLAaRbC7QMBXGTAfBgNVHSMEGDAWgBTJxbKdqi/2yLjdcp/pK8sGqKl9hTAN\n"
	"BgkqhkiG9w0BAQsFAAOCAQEAYdgYckqxuk/x0iiFRQCEwMlOn24C7srHQwLdO7EK\n"
	"Cc6Bx4SG9H1ek4EScEzuinQYhEJ5YjblGmXFkfLJu3RP6h2yxhh5w/bQetiKt0Lm\n"
	"5aMx/Kc0F1alY/bgGfhmF9gzmiJQP517gWNsQnpiCkTWHwFtP4P59G+j5lm569AO\n"
	"zJu4kOY7EFZ0WqK39Ep9iA7GcPfcG5lqlRAQtZwJQ6dSVI6b1RJd8ypeXbvSuCD4\n"
	"UR9nHUg36RiOz5VOZ+ltk8D+I+2Xa3OO0uWL0P8Tj9UsBeY/+TXqBjGPchWPSjyo\n"
	"hVO4JHhOQfQKeprsGet3AKbqEuB1Wqyua7gVC8Ts1fyRLQ==\n"
	"-----END CERTIFICATE-----"
};
static const char _perm_leaf_none[] = {
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDFDCCAfygAwIBAgIUOwgi8PBl82PB8rHe4HHogGqAFK8wDQYJKoZIhvcNAQEL\n"
	"BQAwOTEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMSAwHgYDVQQDDBdFeGFtcGxlIENB\n"
	"IEROIFBlcm1pdHRlZDAeFw0yNjExMTExODM1MzhaFw0zNjExMDgxODM1MzhaMAAw\n"
	"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOEzx/w+sZAHAnDS2kAvcl\n"
	"hbsXAxT0HpfQPPXYYMPYx0LQzbIDHPZe0NIP6zNAZcpgNo6WqW4vXr+Cg2BuUL/A\n"
	"imB9BUzfI0aGO268E6JGCGY5cGy10rJ1gd8SNDe09FC1mcUY8W6GWMrZ/N0HMX5H\n"
	"nC0MdWAwpruLGfJK8GFj8rCSG9uoMrMMSIaR4dzIaT8gKSe/DfR0ikokXGV2lyBr\n"
	"vFNx2WWqEYt77zyXHfDKUuN5LuYhbDmMu4rWlrgbVrEDzzIFGJTb1DTuDUeNHSzJ\n"
	"QzZB0NmC3a7GAvv4Qrg9W9nU8Ezhtme2oL6IEO3PACup/JrituHblWsGCVWTAQqV\n"
	"AgMBAAGjTTBLMAkGA1UdEwQCMAAwHQYDVR0OBBYEFCQDS/U/LiNvmakjZZwkhJ+t\n"
	"dAjZMB8GA1UdIwQYMBaAFMnFsp2qL/bIuN1yn+krywaoqX2FMA0GCSqGSIb3DQEB\n"
	"CwUAA4IBAQCmwkfpjE9G0C6rahxa8AqymJXd0TnguOJa+Nw16B7KNYlAKNf6uw5p\n"
	"n7ZW8cRbjgojOXeAe0E8p2e7DUoTrz/SAJP5J5BpjrIZDFGxnQu4fh6u3ZWjMfkp\n"
	"FEp/oJwXkNYXlLMUAdU9XeIPCMbIDXdfxHU+5vtvo0tDFvVq7mQCbqwlOCLmL6U/\n"
	"Y1ccYxVOUJATgrwVcxBcSyXmweI3T0+vBEVA9Ov1hrioLzOQEQJYM82EyiG5RuKa\n"
	"g1ZYCT43yRZcmhP1kisdomGzXybBkt3Wx5GC5tnnVem86921gKLcVRW08a5J8W6L\n"
	"FH6jq2PwrHs/0xqd9M4PKN6/TxA59K+O\n"
	"-----END CERTIFICATE-----"
};

void verify_leaf(const gnutls_x509_crt_t *chain, unsigned chain_len,
		 gnutls_x509_name_constraints_t name_constraints,
		 const char *label, const char *cert_pem, unsigned san_type,
		 bool expect_pass)
{
	int ret;
	gnutls_x509_crt_t crt;
	gnutls_datum_t datum = { (void *)cert_pem, strlen(cert_pem) };
	unsigned status;
	bool violated;

	gnutls_x509_crt_init(&crt);

	ret = gnutls_x509_crt_import(crt, &datum, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("Error importing %s cert: %s\n", label,
		     gnutls_strerror(ret));

	ret = gnutls_x509_name_constraints_check_crt(name_constraints, san_type,
						     crt);

	if (expect_pass && ret <= 0)
		fail("Error %s leaf constraint rejected unexpectedly\n", label);
	else if (!expect_pass && ret > 0)
		fail("Error %s leaf constraint accepted unexpectedly\n", label);

	ret = gnutls_x509_crt_verify(crt, chain, chain_len,
				     GNUTLS_VERIFY_DISABLE_TIME_CHECKS,
				     &status);
	if (ret < 0)
		fail("Error %s certificate verify error: %s\n", label,
		     gnutls_strerror(ret));
	violated = status & GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE;

	if (expect_pass && violated)
		fail("Error %s certificate rejected unexpectedly\n", label);
	else if (!expect_pass && !violated)
		fail("Error %s certificate accepted unexpectedly\n", label);

	gnutls_x509_crt_deinit(crt);
}

void doit(void)
{
	int ret;
	unsigned int critical = 0;
	gnutls_x509_crt_t ca;
	gnutls_x509_crt_t chain[1];
	gnutls_datum_t ca_datum = { (void *)_ca_excluded,
				    sizeof(_ca_excluded) - 1 };

	global_init();

	gnutls_x509_crt_init(&ca);
	ret = gnutls_x509_crt_import(ca, &ca_datum, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("Error importing CA: %s\n", gnutls_strerror(ret));

	chain[0] = ca;

	gnutls_x509_name_constraints_t name_constraints = NULL;

	ret = gnutls_x509_name_constraints_init(&name_constraints);
	if (ret < 0)
		fail("Error initializing constraints structure: %s\n",
		     gnutls_strerror(ret));

	ret = gnutls_x509_crt_get_name_constraints(ca, name_constraints, 0,
						   &critical);
	if (ret < 0)
		fail("Error loading constraints\n");

	verify_leaf(chain, 1, name_constraints, "leaf-subject", _leaf_subject,
		    GNUTLS_SAN_DN, 0);
	verify_leaf(chain, 1, name_constraints, "leaf-san", _leaf_san,
		    GNUTLS_SAN_DN, 0);
	verify_leaf(chain, 1, name_constraints, "leaf-none", _leaf_none,
		    GNUTLS_SAN_DN, 1);

	gnutls_x509_crt_t ca_perm;
	gnutls_datum_t ca_perm_datum = { (void *)_ca_permitted,
					 sizeof(_ca_permitted) - 1 };
	gnutls_x509_name_constraints_t name_constraints_perm = NULL;

	gnutls_x509_crt_init(&ca_perm);
	ret = gnutls_x509_crt_import(ca_perm, &ca_perm_datum,
				     GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("Error importing CA: %s\n", gnutls_strerror(ret));

	chain[0] = ca_perm;

	ret = gnutls_x509_name_constraints_init(&name_constraints_perm);
	if (ret < 0)
		fail("Error initializing constraints structure: %s\n",
		     gnutls_strerror(ret));

	ret = gnutls_x509_crt_get_name_constraints(
		ca_perm, name_constraints_perm, 0, &critical);
	if (ret < 0)
		fail("Error loading constraints\n");

	verify_leaf(chain, 1, name_constraints_perm, "perm-leaf-subject",
		    _perm_leaf_subject, GNUTLS_SAN_DN, 0);
	verify_leaf(chain, 1, name_constraints_perm, "perm-leaf-san",
		    _perm_leaf_san, GNUTLS_SAN_DN, 0);
	verify_leaf(chain, 1, name_constraints_perm, "perm-leaf-none",
		    _perm_leaf_none, GNUTLS_SAN_DN, 1);

	gnutls_x509_name_constraints_deinit(name_constraints);
	gnutls_x509_name_constraints_deinit(name_constraints_perm);
	gnutls_x509_crt_deinit(ca);
	gnutls_x509_crt_deinit(ca_perm);

	success("DN constraint tests completed successfully\n");

	gnutls_global_deinit();
}
/* How the certs/keys above were generated:
$ openssl genrsa 2048 | tee ca-excluded.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCj+7BTwXXQufjI
WCwsXIenZxN5rmQyfNN4uiKWIqCZukxADUc23RzCbCQ4UNYIZUPcqPvz0pPmnsFV
73lZukFYWFY8Amr2bCGgDiuZ79dozWjZ33uItUnepdnsZljJ3SEqoZoV9gvGh6zG
+U0ls1+h6Ps+Y3VPZh4syEcoKmUWxdultdXSesC7ktU4JLttEoJSkXc0uQ5bSgHg
+uUehjloyQwuvn8REwFZ1zS63D4tYh520CGcc4r57W8sPx6cMEl5U9MlMMcd3RJq
Q7kDNjOfkuCFMlblwidC8vHWy1aukTExBhzzxWdHSSzOHrI5u4qxMqKEw+osM+Rx
8Jx9a/o1AgMBAAECggEAAdJ66d9ZOA3M/CrwqLiJgFx2nLBJqD73WZzV5A2z86lc
jgynuS4ZUvbBK0gIrNS1PZc6H4I8RwCGHPaZhlv5vGnU4XtUZXMbp4vow5/k6KL5
sowXcxQyozD8HDKh83JL202q6OoQRO8+hgKArzXQTvwICLAxvkVf+fbqxYE9GNTq
9Mk37xJhngRc6Z1mLspgY94guau3e2UkWpi2XjbWAe7p3I3qULPEOhvk2lhHO+3Q
q1OdvNyMcoVMAejJneYX1pGRCv8wHFRtO5Rtq90OB3xUE8ZEFSXfrTwQOY4NyFDT
4pY0INJcQBSA/82wpUP9S8vgV3X+qabyPwT3z0Z9QQKBgQDbPpqhqHlMydioac4n
mzkGBRj1cRbfgjIuPsVjzlscFQhDIekX52dBTpcFMc0ptZKd7fw3avmwSI0wAqB/
yRnLOBp4A9BGVYbB7+4UVcNfkyrz2+4zunb/5L2WVZbpQB5l5d4+VlteyM3KVv0G
BdWMo001kW9ek9tOqjY8PD4OQQKBgQC/eWmEYtekfaRnsde/QSzSbc4SOZdoXxHD
YScxXc5ouRvQtQe3nw1pb6hAUyQk1D653x2Jh/Bi4q4DJ5UetxFQD1cyVLTrdwiE
U28g7YXZOCIfxbUHKkEb579CJzQiExmy+vnrb864dF/DBwP8itqiSwBbV+y2mwg1
eUMXqp7W9QKBgQClJLnrLPD5k0zcRp5fnP9N9ob/UgjtoK9VwDiE3kook/sePivK
sqZHPgBpjELCuR9QUJPb1ntveqbG1CO7PWptdbwSTKUUZZXU/Xoy3QsGMd93wmDh
nAHI7K6Vz7CVz5NWI9jM0dWPRugkEnQSllBt2A/vWrYt4meeEH47zxDbQQKBgAwr
JiaQtY2xonIonkJ8XOHespr76ABtEk7tbLU5dfW31em0p5Hm3M5Xl0THQ+PHTVk4
scLczc0rBM4UhOiXz9TbtLnxIjJYtUTbnJNmJPyCEcEdKn0TFWI1nzUQEsMbnaV/
R8TLrUKRushFON6i4HQx+grUEqokPihP1ZC6ei/FAoGBAIENxf7YWiQofgEa9hPc
ukITuZMPBEegYBBNrmLHYtUXZNTvHz8CaDn1LXmRU21YftaZMm72W+nStXm5WdT7
edD0m3c8lKbCcrHNch6aWo8XlnprsgS6XRh6WmKKtmGxulMjwR4f1iskhTDWDkrS
S1xaAaXTV0GsPNACDgNUD4Va
-----END PRIVATE KEY-----
$ openssl req -new -key ca-excluded.key \
              -subj "/O=Example Inc./CN=Example CA DN Excluded" \
              -out ca-excluded.csr
$ openssl x509 -req -in ca-excluded.csr -signkey ca-excluded.key \
               -days 3650 -out ca-excluded.pem -extfile - <<EOF
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
nameConstraints = excluded;dirName:excl
[excl]
O = bad.example
EOF
$ cat ca-excluded.pem
-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIUMzvtL7UkeutCjWjLUFchyaVDVt4wDQYJKoZIhvcNAQEL
BQAwODEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR8wHQYDVQQDDBZFeGFtcGxlIENB
IEROIEV4Y2x1ZGVkMB4XDTI2MTExMTE3NDQzOFoXDTM2MTEwODE3NDQzOFowODEV
MBMGA1UECgwMRXhhbXBsZSBJbmMuMR8wHQYDVQQDDBZFeGFtcGxlIENBIEROIEV4
Y2x1ZGVkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo/uwU8F10Ln4
yFgsLFyHp2cTea5kMnzTeLoiliKgmbpMQA1HNt0cwmwkOFDWCGVD3Kj789KT5p7B
Ve95WbpBWFhWPAJq9mwhoA4rme/XaM1o2d97iLVJ3qXZ7GZYyd0hKqGaFfYLxoes
xvlNJbNfoej7PmN1T2YeLMhHKCplFsXbpbXV0nrAu5LVOCS7bRKCUpF3NLkOW0oB
4PrlHoY5aMkMLr5/ERMBWdc0utw+LWIedtAhnHOK+e1vLD8enDBJeVPTJTDHHd0S
akO5AzYzn5LghTJW5cInQvLx1stWrpExMQYc88VnR0kszh6yObuKsTKihMPqLDPk
cfCcfWv6NQIDAQABo2swaTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
BjAnBgNVHR4EIDAeoRwwGqQYMBYxFDASBgNVBAoMC2JhZC5leGFtcGxlMB0GA1Ud
DgQWBBRAbNEdXZ8hnE4xhTmN5BZN93nHFDANBgkqhkiG9w0BAQsFAAOCAQEADCJu
ZJXGslchxkUXjtJ2bV50eS5zJA26Ktl7bMVPoXvJSLen00oQKYVAg5/uSK+4gAMP
MieuDN9VgLhmU8SJZt59YscuGMYMHQthJ6NBWxU+4RfW0RQdhk2exbTDz9c9+nDs
rw3tesrU5CNsMxsCgkSgvgK/WNQXa2YyrDKz8qnZTHxoH+Tzv4LpIqBlMNJ2LCse
ouxpGpmYvCBeXtTI1ER+7sAcDILjmWZ7WR1QCHaUPfvapNXlxW7t04LYIx/dDHYi
RQ2fNYvoalSkaF+Sa+cUBzdKIcv0SqOTV1ZHGCCuaAY/eQZA8hjPwx9MpR+nG3rV
rSAU6wn2w6vCbZu29A==
-----END CERTIFICATE-----
$ openssl genrsa 2048 | tee leaf-subject.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDhrqnJ+RJ28Vg3
6+whcPBSSVC56Gu8osm94xCE+tKV241bfshAg32CAv9U0w/z/3QB/cge3f5PG9mQ
8g0kgjIlpoH/6PJB/vVjCmT/6bv6+D+Oc5ffMcyKZS3WKf/Dm1//yLye/o10RXLa
rp3YcYR+diIqL2shllh298c17O1x96CWVbw1b3TLhMq9p3/PyLffg5cY6iTM1CX4
24xnNWFxBqVWMIrejYQejXoV+ftS0fHfttw2UT1vDnVOUDsG1zu4sDnr9Xl89SfO
sZKjVha4Ex9Oe+VP5v0g+Pl1LtTsjmpAJV3Wo+oBEA8TqTB8quv2HM2nHqTO6qLh
pQPbKSmpAgMBAAECggEAATpjRH58/fq+T3IaO1DnRWl6SlpDEwoQDPCOC45X0deI
FuFUy8CvMB5SBJddWyxG44bdnkU5pmFCsQqZ4Ua0aQlLZG6tpfFE/7XVwB7BfU+o
6OEQx0mtiXV0Ro52njpE93b3yOTD6dwZtgSTquv43Sat2WK41Cq+xBnJ75Hkcu0N
ET2UCmEYF3Z4ZgjXAU/TJZl7vftOl9dT5aZCQSuSIArNlROIPJX7FWRjiphAcxrN
NU6IKMmhePqacdT2yzjuGScFkkhyhJhNnHKmWrdCRWGRlQoZTux2LWwQ0eZP1Vuo
GzXFeJTQpksmQsrUZhSuaWNWlRt6yC2g4Kb1tExbEQKBgQD4VhZ4LZFkC0s2I8d9
zdbxW840TgnYtg2mVNE2ao7ivANioAJAHlSwyRgRNIifoWo4jgmM3PmH9s3slNsL
vr/D6u7ACPo6SWEO0Nk0xCBmevjTRFxCkm4f6YdVhmdw8s2kbFVX46TqsbV72Maj
Uw4tuyrVETXpOqwh9zMXYbMOawKBgQDopZqRIxc9HD1Ig5d6Wrnu/Fv5Yx7ioTEJ
8jb+vIIfquNMQb0kU0O0JJL5HwP52okcYxd0UgiPZRyT11PbFzINFSElgx2if/sC
KEcRyUbTz9NB8omKlb+E/fu2nw+QEijV15aO0Rg8wTnN2lWXfNZ9+CelnbfxbFBT
MfOGmIZFOwKBgFMWQohM/rMRUEW57Nn7j6nLRI+deI/oQWLgR+tD9bCIpT1POdGI
FF/duE6xW/DEycxIQYu+t0I1YiqAl1Uzqed76AuaNVZhDLcvSyzrXcfL5wqQeanQ
YkYNFTmZMWzJ3+HeWSOBx8C6WnUoTzV/6WOFlswY6QeymLr4gUCWcJknAoGBAKix
VCfDexlLvcAz8wW8fbAl+wcVcZLBcQ6WPHxv8ibGQfTMgjqxyZj5ID1V2Qs2BE+6
Joqo5R4dIiCtdVebNSa5WISb00Q+aqMA06+49AuoWbYrCMKdnPbxN7EPGzjLgiK1
Ja2/PkTnk2OJ2qBy3BERfKYhe/yqHoCE6uGA/XN7AoGBALBtJ9K2JImUrsOfoETr
+zkrkbzjDIUb/ur7PMMPkTeamxT+H5sAvntvFvVNXQcoZ36DGUb3vhb1l8Pps/lU
D7+MRkMDSAzJUV0zkyq7ED1fj5+HzBRwIPVlTfLqQhzEsSygAtObEFeXLaWXHz0j
8K1/23Yu34ZQNuCHKPUVpuLU
-----END PRIVATE KEY-----
$ openssl req -new -key leaf-subject.key \
              -subj "/O=bad.example/CN=leaf-subject" -out leaf-subject.csr
$ openssl x509 -req -in leaf-subject.csr -CA ca-excluded.pem \
               -CAkey ca-excluded.key -CAcreateserial -days 3650 \
               -out leaf-subject.pem -extfile - <<EOF
basicConstraints=CA:FALSE
EOF
$ cat leaf-subject.pem
-----BEGIN CERTIFICATE-----
MIIDQDCCAiigAwIBAgIUR8UaaaxZ9Foci93sHcvo1mOvT2UwDQYJKoZIhvcNAQEL
BQAwODEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR8wHQYDVQQDDBZFeGFtcGxlIENB
IEROIEV4Y2x1ZGVkMB4XDTI2MTExMTE3NDQzOFoXDTM2MTEwODE3NDQzOFowLTEU
MBIGA1UECgwLYmFkLmV4YW1wbGUxFTATBgNVBAMMDGxlYWYtc3ViamVjdDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOGuqcn5EnbxWDfr7CFw8FJJULno
a7yiyb3jEIT60pXbjVt+yECDfYIC/1TTD/P/dAH9yB7d/k8b2ZDyDSSCMiWmgf/o
8kH+9WMKZP/pu/r4P45zl98xzIplLdYp/8ObX//IvJ7+jXRFctqundhxhH52Iiov
ayGWWHb3xzXs7XH3oJZVvDVvdMuEyr2nf8/It9+DlxjqJMzUJfjbjGc1YXEGpVYw
it6NhB6NehX5+1LR8d+23DZRPW8OdU5QOwbXO7iwOev1eXz1J86xkqNWFrgTH057
5U/m/SD4+XUu1OyOakAlXdaj6gEQDxOpMHyq6/YczacepM7qouGlA9spKakCAwEA
AaNNMEswCQYDVR0TBAIwADAdBgNVHQ4EFgQURTfTHY/51HaM3TLy9EC7avEClRQw
HwYDVR0jBBgwFoAUQGzRHV2fIZxOMYU5jeQWTfd5xxQwDQYJKoZIhvcNAQELBQAD
ggEBAG6H56iABMo7ZTWyQ1y/cUYjNhRFfEDmBDboayWqMWl+5n98XB7Ry7ovUKdC
9BXfR63I4R+sbimk0i2Xix5hUF1LXa68sXI8c8e73+uxZRFINN30Z9dbw3n2Yem2
WqP8f2wnIKtRxUR7QuwlnwkOmTzdIw7Zrg2ePnIKGSzVEhT6o9RUlt+9Q9+jzPOw
wGaGxnV33YP1aNlAn7D+HzhFzBBSY3Hy1LK6bCtoO/UWtAX4rQws/vcxqx/JuyNv
6hzHhZf4i5KOn+Ummj+hUj9SVtEBfkZeQ+lRdbxZ6MjvOQE3oxbrc+WcIwob5gjQ
xxYhwe3ObsGCaNHHpGomdKfdKiw=
-----END CERTIFICATE-----
$ openssl genrsa 2048 | tee leaf-san.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCy0kM1L9ayEenD
aZCObjsYP8VoJcZmg8Y09YPKhPoBF4df3c9yaFR8pzxuigSRoynARG4Y+ZvZjD+A
lQ7+nCRlshlK77oVNw5d+tg6sn7HYmt0WG0ZFYmov14z5H+HjhsQB1PnEPujSzgf
cUVOsMJ9FMIOy6jKqmIMvIPu25wqlWM8iSL58BwTNG9yFe5bnA9u96m+IDX8dKjf
7JuGuvmWAfkxky9444LSrgE4vKNY/SP+S9nWe4LYfxOGINgNsnbsmEIDK2Cgd6W9
rv1cUWrB7qc3Sy7QvHNkd59F3l2JJVhOAxPuULqd1u02z8+qTbdgljZV40yAu1Kc
QDJlgUgZAgMBAAECggEAGaVMHDmjKeClzO+72qF2ejDTJ++a96LYb0nyv724eSWd
taMDGF5cF5CIezXyF8z1tOxbedt6fYW+qbs27k8IbUlQlU2yO06tEc9i6XAl/IRh
8sqnwtwy5O+lG/4eSBuaR/81CkOGQ1ILV38QOIvjKLssZaDRsVckPr1ekogOapDK
cx9k+PgTOOd7/It8DvfiIHgHhL9Imfkz4D+ugPfbSmPhiY4h51eVQ5ejonscUF43
1hnBM2LDVPWfgfAd8EpVsEjFYCW3VcuZooibBuQiVqmSciwn4dA2CtVGJmiSJr91
AT0IGgB0foxsYt3iIS6zJA6ajy7B2xGhVwg4Ig82rQKBgQDuWQ1dCDqC85cCdsQr
hAhc1Qam3Hp3T661VRPL19lBu6BMMYxAg+hRcDnphcd2f7p1cDnEZpTiGjliaTB9
0ud10msPcqWtsleuA4EHkeL3JQcJvhYO/FFF6YTlWxXyHeEBEi/FxC8PK6eruGl6
NHoJUW7nDbJvi+p6D7CPdM3ODwKBgQDAEJ6NXPeWiVtTGxeRCmcUuffEMCZSJ+qy
tMbQe4e/XR07ODLapwsHPofVSsiKGEysGE8rAUPzCJpi0ZyaK8AxGqeAKjDJy5cX
ILhV82stSuyKxMYM9JU8RMrhCbtNqucyeNzGR1B5+9Cp6Yriynvi7saaDZ9xrLvO
zrRR9QyvVwKBgHv59DqE8jJ1VAIjFszvw43N/MTEgCsZVm3Z0A9Cui430xxu1V4l
fq0FrAns3SClNa6qblHbbevh6iFnR6LbFiwyBCAn6UfdMUBBcFcoqh8VsoB90GmB
EyFDYy4N3+9tXUE6XYEIF9ZTRcbLiInZS/UW15H1jO/6nj9Zc+RaxEY/AoGBAKAe
OtBHLPGG2WfTMjZsobsZvoEEUy4ysOsC4qx0D5ttmS0BkQPQNtV3P+6FReI6l9Dx
Ay8rAubdyTeQ4Cl3R+an/fRPOBVDcVaKpKKjKDq+N60IlsO+M5vnDevGHSyGye+9
6vAyC9lmIXNFi8++VsG9pjxQFxjBlGC42oNo84ZJAoGBANbNge/LGAmO6wM6lhFY
Un3AOMLQcyV9vi2KXX47aWDwVzVy6JKaFwEMm8NJ37S+KEfdTwBRew4aE51z+htS
CiqgbnTsRXU1lHBzLkQHCkPLd8D4hgYAey3FJLL+wXDq66rThlotNyHE0OFcC2B3
wZzicUdmrEHKuc+jp6bFWFjX
-----END PRIVATE KEY-----
$ openssl req -new -key leaf-san.key \
              -subj "/" -out leaf-san.csr
$ openssl x509 -req -in leaf-san.csr -CA ca-excluded.pem \
               -CAkey ca-excluded.key -CAcreateserial -days 3650 \
               -out leaf-san.pem -extfile - <<EOF
basicConstraints=CA:FALSE
subjectAltName = dirName:leafsan
[leafsan]
O = bad.example
CN = leaf-san
EOF
$ cat leaf-san.pem
-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIUR8UaaaxZ9Foci93sHcvo1mOvT2YwDQYJKoZIhvcNAQEL
BQAwODEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR8wHQYDVQQDDBZFeGFtcGxlIENB
IEROIEV4Y2x1ZGVkMB4XDTI2MTExMTE3NDQzOFoXDTM2MTEwODE3NDQzOFowADCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALLSQzUv1rIR6cNpkI5uOxg/
xWglxmaDxjT1g8qE+gEXh1/dz3JoVHynPG6KBJGjKcBEbhj5m9mMP4CVDv6cJGWy
GUrvuhU3Dl362Dqyfsdia3RYbRkViai/XjPkf4eOGxAHU+cQ+6NLOB9xRU6wwn0U
wg7LqMqqYgy8g+7bnCqVYzyJIvnwHBM0b3IV7lucD273qb4gNfx0qN/sm4a6+ZYB
+TGTL3jjgtKuATi8o1j9I/5L2dZ7gth/E4Yg2A2yduyYQgMrYKB3pb2u/VxRasHu
pzdLLtC8c2R3n0XeXYklWE4DE+5Qup3W7TbPz6pNt2CWNlXjTIC7UpxAMmWBSBkC
AwEAAaOBhjCBgzAJBgNVHRMEAjAAMDYGA1UdEQQvMC2kKzApMRQwEgYDVQQKDAti
YWQuZXhhbXBsZTERMA8GA1UEAwwIbGVhZi1zYW4wHQYDVR0OBBYEFHdxvPCGovzs
7pW3vhSqVtdIR8LFMB8GA1UdIwQYMBaAFEBs0R1dnyGcTjGFOY3kFk33eccUMA0G
CSqGSIb3DQEBCwUAA4IBAQCEEiBnWTKBRFDP5ZmU2AS52o7V663SAuh/UtuV6oSY
EYZAwNaA1EzmQxZm8jqacZ/FshhgASWrMSdLO0uQPybO7SeZvxb6oRmo6bQ+Hb6P
fKQKNgDOq94owOXBkCDd8/9q0IkbAM0Le5qPb7uZfReWTpt7CIX5zDhrTBOUbrRn
FDBB71hd0OQyYkq7mNt42/iaHMY00zDRtPIyKIZT40EDwGbdtkq0M4ACsaZb+Tgy
buCNW8/cQyC4iFc+h+f18yfEaI+pKbvkh2So+85XNWbzcoO1Zq2FL8Qd6dXYtczm
WJ5XArrYc9X6B+iFC2Pp+KJ93WBwqZ8svLi8nKv/RYPt
-----END CERTIFICATE-----
$ openssl genrsa 2048 | tee leaf-none.key
-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQC4exiMva37P0K/
Cf6X2kVt+Bwhl4MlNkA+shVf3qapVHsKLtXylo/k0wEbs3p/CPytdSn50ffjeoUS
ktSkAUbf7K6PbRu6NrisXn+A3cidkcBXit9r8zP0by5VZ5GHx0p3XRhLOQk6QNqJ
8uXLOf8roRg5rlH9GnLbjZ1sdguA4ljDTAvnNkVF4XG99EyftuB7173ekQBGjoTB
vx0qUt97lb47TXkLYvfDNrQvu1TgFY5L9RgpbbvY5BGoDnE2xoa4I/vvkUIKA9lS
k7xCKC9S/VonWQIYu2oNKq/Zl5kLfd5jIm+r4dm1JnDp129iEfw7XjFbPp9oI7rO
mrMGrWFBAgMBAAECgf8w7vsDbnrXuruCoaLD9CWXv3bfvvrvkL1OSnEHZK9ngBHL
6BOsg/5IZfJpJVoFjg6g+SJn9NV2R98v8JwxogE7Yc3H3tsMnP7sC7lTMYEGkmaD
OHV+MLFOVuzYeo0jh4n1QLX0zWhj6L4PI5hst1qseUCTxJEhRlSkRtZTVmgGGAs4
TdV9t6MJ6ta47tMrUPp2djTzcqfTMUdB1F7L6Ti1JFVCTqLPL66BsRAEvTTmck77
7MLzG8OD6yFFVJeZW2k3yPJXLkePA6rMy0GdWAp87f9QW+49SgyDzd6L71SbzrpZ
t/5RnD8VhxgXK8yu2v1fkNA9ZElGA3isVyX/OZkCgYEA6vm7k10bo7/mF3cavvUR
IobIVG1ZK9io33VD5XfHi/SUpGYitYhc81OfoVNIlJgEVUOycDUquTjActkf4HV7
CT1M41AyzFURhThQx3hKV/1OBzArke9mQH1LkB/vUhAslucBlP0N8QFP8JhcXF1t
rqZUB3hu2CCI9Gg988TFp5kCgYEAyPy/8GLt3sgI5XJBOBSKm3wBhWe82PYdDUHR
9JZ4yQ+/QYbmz1zc68ApKcgtqm/xEdwoZVwHxXGNhJJsHPGEAHe1IWLGwXxE9pJ7
Syn2XNJ8xHwZ8vwwDarkByktFd1Vs/4EObbmcAceryXmLdNxmvc1TezR+t7zcfvH
QvPQ7+kCgYA1tYeOk4Wx1Dc/vdW7OEEGZ1B7G9N6Fjfje+ZdGRffgbRIL6BXZif4
5nBia6r3bBfxdVvgEgcF91bl6YNDxxascfqVKsuxsPAkR08PiQtVOW0Qb45F+Tai
HwGam/IUC+ZlR8Aw0fbR0771+52A70oW1aX3XyvW8vjbBMjEY4HaYQKBgHB9Rc/9
DrVJr/D7aZVBqfIsDY3k6cVkug3ZcPE75o5hyeGa50PX7a3k9yTzbNufm4Ure1B/
mbngPBye9vOcGQ1J8o6lAij4rIB0q5z9920sQbiW3M8qZpq/srBvU1SRdI4w9Zx3
ybGZyoqs449ycHsTMTpT+ZI3hnmdOYE3hRFBAoGBAN7VBYGFyue/NWwMaFiIqr54
dI7RlqEiP+AceIfz22vg6BqRVDlIUwdqF6AxgAYq4dH6Np8OJjURLou3UJFsteTB
2utIyT/r3k1aniTrJhoCZ/nL1+AEzk5078sc5sdv54XBn36pmshFiwDk+PS+sMMw
Q80tNXW7iHWAEDaHJ02T
-----END PRIVATE KEY-----
$ openssl req -new -key leaf-none.key \
              -subj "/" -out leaf-none.csr
$ openssl x509 -req -in leaf-none.csr -CA ca-excluded.pem \
               -CAkey ca-excluded.key -CAcreateserial -days 3650 \
               -out leaf-none.pem -extfile - <<EOF
basicConstraints=CA:FALSE
EOF
$ cat leaf-none.pem
-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIUR8UaaaxZ9Foci93sHcvo1mOvT2cwDQYJKoZIhvcNAQEL
BQAwODEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMR8wHQYDVQQDDBZFeGFtcGxlIENB
IEROIEV4Y2x1ZGVkMB4XDTI2MTExMTE3NDQzOFoXDTM2MTEwODE3NDQzOFowADCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALh7GIy9rfs/Qr8J/pfaRW34
HCGXgyU2QD6yFV/epqlUewou1fKWj+TTARuzen8I/K11KfnR9+N6hRKS1KQBRt/s
ro9tG7o2uKxef4DdyJ2RwFeK32vzM/RvLlVnkYfHSnddGEs5CTpA2ony5cs5/yuh
GDmuUf0actuNnWx2C4DiWMNMC+c2RUXhcb30TJ+24HvXvd6RAEaOhMG/HSpS33uV
vjtNeQti98M2tC+7VOAVjkv1GCltu9jkEagOcTbGhrgj+++RQgoD2VKTvEIoL1L9
WidZAhi7ag0qr9mXmQt93mMib6vh2bUmcOnXb2IR/DteMVs+n2gjus6aswatYUEC
AwEAAaNNMEswCQYDVR0TBAIwADAdBgNVHQ4EFgQUwmLE3RJ37wq2rsJ+34/+1tGr
bOgwHwYDVR0jBBgwFoAUQGzRHV2fIZxOMYU5jeQWTfd5xxQwDQYJKoZIhvcNAQEL
BQADggEBABWGRMuaSZMhfpqJFhc2YKhF59VRN0xv8B/eA5EFy+kBUeUKNWz3ygxU
OIdA4a0kGyMvJ1NOGi2CZ/BaGOJFsds+iZX6z72zI62I3uJsY6fkJfPa4RY2Gh99
9RJcjrXx6bXcjXZVbMJj+QdjTgN+LiE63d0CFeu3I2fuJLUL5K5/izTToxBPAsWn
SmDZPsnG8t8ck5YVwOYHyf7e0SDUC8GUErHh+op90P+ZplZAYLi0lSd2pl9UhQT2
P9YrK/Qwux1PXTMJlMm/f5EZ/CkJdMoY7c9jebarRzfRkj9wUj6Vv0ha/8J6RGWc
Y9o3tK8QzZaBW9KNeNWAzhqTTYZD/ac=
-----END CERTIFICATE-----
$ openssl genrsa 2048 | tee ca-permitted.key
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCoItvTyPaU3hem
FACTbsq6JCePfwLakqzpU5O3E40yUaNUni164Z16+xPO5SdjwzcEJ67Mue3TZ07Z
rUqe3UTsdzEoeY2RrDrLCG9IByy90jYriWiA+UvBBM8TIZagH11JmEsTc0ahDGgs
OiAWpIyS21780oe5m4ojMd3NeOZPpF4waX67EJjEU9FAtEazKgWTR7jyfitLJgO3
wmnFsym/iW3LyuTzXAIhBR+MyGcw/wAe3P+DyuyubQQcHQF87lkI8J3JRuChduYO
lOv8B6cGG0McuIwwATuQqtUa4g8qTS194UBEu8Ml6QdH0hOGE1R5OD2PCKjyh+RQ
Z1jRfPtJAgMBAAECggEAFskelG10KUmN1+Z3C4PkumQi7lnul5NwFnDKoHFoXazd
nx6OmEwSDPQQw6WfeHAguRHtqPX7in5CG9LVvYDMEeW3Rj5u1pKKJzC97/t070aZ
K75D6NKgFwjhTTzsjkeh21Llvb2OEU4+odvAtIDZQh+zmDypwxgWmN1tqyZaw+kQ
UfbnecGza53idX4ew3BsAn2C19TrCigz5pzlaLRoJLUQOn5yIyfW8KX2QhAi3/OO
IR8PZIhlkFOzGwTkFwTLPk4F3lS0bASxmmqn96QBnh4M/u3bR7RNgn6GCn6udomn
DpyPSeoSPEhyGTF9XQcSNJqXGzSv1q/AmZI6mJr8HwKBgQDtbuGLDTsHVwzgFFHB
a+fCHZxwFH6mam0Bn+tw1/LdFtldzlkieOEdcjFCteoPVcT1i06SekjbgxmTBgAs
tUGOMaIGzvzGvuXK+mC9XmGffnyl1dr791hRJ5b4abyNJZC1cFu8qHZv0m+Q6CAq
Xur3IsxqzEKaJ5k1IzHnihgS1wKBgQC1SLzf1/DjWY2APqDNQ7VJeNMfyHzoMEjE
GR0kyA4DYpioxQ9HYf6oxc2YnL+A2x0KxegGWV706lIAo0cvUZJ38MPppiZz98cl
rtY/huSOOHbR0s9gPfm3q/ZuimpExpLx/9dZI5pz5r7Jlaaf4cfBHv+kEmfjfQTB
U4ywE5++3wKBgCTxTKyLCXUx6THwV2wl8vB0FQQnXDFee8l17XcoUoRt6rI6ygmg
Dz66psl/boSmTrf5zebimfV1p4QFuf860JFkTZaLnC78QtrbLDQqvDvJvXE8Hg94
Q8iUxVuvcAPyJVrluZBYEd2CO5OrWl3dWOfNBUtUrsQ3hxIKgNhK10YPAoGAQ2LD
Wo2hbFE4iQg+q65Ub/gqunDDBWgVVFdlfuuiUd3Pk0SU9lrV15SXZPg3M0W/mOaR
5fJIms+TJcuLxWoUAOONX4e0WX0sGLTRzRFuWfNhL4OmNEc1UPHqC5MGB4Ss0Kni
Oa9DVXvbRYGMS3gY0Y+dRTbWSTiKkPZmoHja848CgYEA4ZIjQpPhyTVvJYYgd907
6rnNr+8Z9pv5GBFnZw5NVQgSz2K9EUH3pfIMYZimaPAm2N2aoNz+JK80VHPhvkt2
3LlTjoBDP3szQhUTM2K4I2Cpzprhc12e9GpVncPhu8M4UUh1EXQ9Q+4CnAu1YwSg
ZHgPVJdJeir/ihQsQFWIV9E=
-----END PRIVATE KEY-----
$ openssl req -new -key ca-permitted.key \
              -subj "/O=Example Inc./CN=Example CA DN Permitted" \
              -out ca-permitted.csr
$ openssl x509 -req -in ca-permitted.csr -signkey ca-permitted.key \
               -days 3650 -out ca-permitted.pem -extfile - <<EOF
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
nameConstraints = permitted;dirName:perm
[perm]
O = bad.example
EOF
$ cat ca-permitted.pem
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUKOIhmaOGJJ0AuEl/koa8uQdjYRowDQYJKoZIhvcNAQEL
BQAwOTEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMSAwHgYDVQQDDBdFeGFtcGxlIENB
IEROIFBlcm1pdHRlZDAeFw0yNjExMTExODMzMjlaFw0zNjExMDgxODMzMjlaMDkx
FTATBgNVBAoMDEV4YW1wbGUgSW5jLjEgMB4GA1UEAwwXRXhhbXBsZSBDQSBETiBQ
ZXJtaXR0ZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoItvTyPaU
3hemFACTbsq6JCePfwLakqzpU5O3E40yUaNUni164Z16+xPO5SdjwzcEJ67Mue3T
Z07ZrUqe3UTsdzEoeY2RrDrLCG9IByy90jYriWiA+UvBBM8TIZagH11JmEsTc0ah
DGgsOiAWpIyS21780oe5m4ojMd3NeOZPpF4waX67EJjEU9FAtEazKgWTR7jyfitL
JgO3wmnFsym/iW3LyuTzXAIhBR+MyGcw/wAe3P+DyuyubQQcHQF87lkI8J3JRuCh
duYOlOv8B6cGG0McuIwwATuQqtUa4g8qTS194UBEu8Ml6QdH0hOGE1R5OD2PCKjy
h+RQZ1jRfPtJAgMBAAGjazBpMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgEGMCcGA1UdHgQgMB6gHDAapBgwFjEUMBIGA1UECgwLYmFkLmV4YW1wbGUwHQYD
VR0OBBYEFMnFsp2qL/bIuN1yn+krywaoqX2FMA0GCSqGSIb3DQEBCwUAA4IBAQAC
NwiB8bka4tMT7i4smPOyaJqutTDBh8N79RoFLoSiygvsq325dN7sEHrnd9b82po+
ypIsLjI7iMfhVGYZgk2+NnO4MR6d8xuLXwmyoNV5ELjRKjHGYVJY7+nO8UHAKFSw
qbL9StUA+wKYUGQFrpYcC5WvbqZMxHVnwONwg5OcwGogPKkaX5sNXcTeuyEaOa2L
MjyPn+WxTXEbWNkQeSEwz3hh4wUEZvUFCiHvPVN921C+lmx3oHMOhRUGgmpttIpG
Z9lt/1ebexM68dF2+vBBpBmphXVW4x/pC704NoxKJOTv+Pke13UQGFCm0ofwoDgx
vz+KbIuZEMEVNK0bl9Cu
-----END CERTIFICATE-----
$ openssl genrsa 2048 | tee perm-leaf-subject.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4LMVAXGeOqiwu
rrbkL/o6UiGn8YIRr9H2X4WPX/ODO9txX1cBjOFaoay1C2ZRiKylQlwNQ3d3aptW
foAEyxN2LVqnMbby31ygw3em4IQ0tr1AhXbBXwH1dgp3P7q/byWfKQelOwtJjGDw
/YL6KjdCMldU64OOCvx3Y0RxzFl86QsHNbE6rGyWYU3jdUdAPqwqYV//gupr6ymY
6i4IpQ07EAbgEZlt8x5J0QumY9qCeSBbWVIQk/tlwE3Dk5IgHdDqWRxYybdvJfax
chcoJ+jty3IZn8TMyLH7qDbr3HowtkPrzKmTtxFUFIgcuaSuWVO4pbNIzpDFuJGE
mU/ds77vAgMBAAECggEAFnTnDET4H44iWwLUrBgpg6j2D5tEB9IPYOIez++cKplG
1ZkRa8/4vmtOOrkMHc7zdicUQE3EqFvoWvCLvYnhcpxvHEnUi+KuUa/jzAY+OIs7
oj1j0Io8G+jrt8Seia8MwE5pbz020B38yAWxTb2OBVVMDr+0x8IRLKF++/01wCQY
+FbLMmDa+9Esj+4BRkmb+Tr46X+FWLTNJ8rCN8+lOe4R/Fx4sVimTS4DjX5Nb9lD
rLDonQBFXXuuI5zuBIu9EF14MjbgcqlGRSCHovpOT64jt/VmL3hfbHr5CDs+Lynh
OT5ybrnbRH8foT5mKzQa7nx06HsND4zsPFWuRnunQQKBgQDzKpahv+IXUle+mTPu
LvPWhfJ8lwsTHXycL4Jvu8X41mS1WOH3vZ0bSLRaVOdCQHJfcMUgjhMTBytpYZn9
v1pKyWg23lP+p9uvSscpSgc2SXnFJJ7eZupeR7g/uHcbcbwEiV3/zDze3oPDfMRe
X7KHDSTK1lQAMV4RGTeIYYRroQKBgQDB5SaGElG0rfm4xf4InZ0opyA8OpxVxwLB
a1SFe2yU50VJUCIsuyc35rx/Os9QZW+PCaKZkNPOI8tE9kR935oti7M1g7dHQe7Z
qiyN97G/bLjZ1h3zuqZlOzZ+GRXoS7W1ySZ/EdLfgbHTQOf/nc3IdEsCwDMTNAWM
hVV1NhegjwKBgCsWp9x/oPOa/rticGZLYZ/o2mAjb63ycqtGa+mar2j5rJzJ5Di/
G8DC8Fp1YwlFXD73P6cWJeEgSxwAVIY3SyunZtUaLm4YloAIUyRI3uBKws4hQBmO
yQbt1INOD6UIUVXIdaSnLz4a1eRlDnLeqEbwGE3tDrN+C/ohqsp65TkhAoGBALzZ
zGPZg+tPaGMntP3/RgtKfIMtMwf5Bh4NxA0e4etGNp3pht+6icBQ5FenmDTeF4Ji
CBU6kpG9G0bX9m4DU8/4uVvuJp0pAtLOhQbhsiaYZpMFkbbKnTcMLU80b7oJw7qD
aRNq8NDxKZpxJYY61Svg2Q6c1SJnEOCFHW9EeE7RAoGBALXLtPSMf5zfqpdOc2Ez
kD8FfOJVZCFgw+umDCPJ2WE3Qk1mIBr2wVferVQD7irz0HmH0wW1V7YqNPwA1MtL
jqp4+iMNpZ5eLSpbwUvyFWT1gmbFGsgx0AXZIADdDchEcrg+NREsRO5Zc4L4rVvm
Wd2Ga29Rf2KZCzFToKXwnKb1
-----END PRIVATE KEY-----
$ openssl req -new -key perm-leaf-subject.key \
              -subj "/O=bad.example/CN=leaf-subject" -out perm-leaf-subject.csr
$ openssl x509 -req -in perm-leaf-subject.csr -CA ca-permitted.pem \
               -CAkey ca-permitted.key -CAcreateserial -days 3650 \
               -out perm-leaf-subject.pem -extfile - <<EOF
basicConstraints=CA:FALSE
EOF
$ cat perm-leaf-subject.pem
-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgIUOwgi8PBl82PB8rHe4HHogGqAFK0wDQYJKoZIhvcNAQEL
BQAwOTEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMSAwHgYDVQQDDBdFeGFtcGxlIENB
IEROIFBlcm1pdHRlZDAeFw0yNjExMTExODM1MzhaFw0zNjExMDgxODM1MzhaMC0x
FDASBgNVBAoMC2JhZC5leGFtcGxlMRUwEwYDVQQDDAxsZWFmLXN1YmplY3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4LMVAXGeOqiwurrbkL/o6UiGn
8YIRr9H2X4WPX/ODO9txX1cBjOFaoay1C2ZRiKylQlwNQ3d3aptWfoAEyxN2LVqn
Mbby31ygw3em4IQ0tr1AhXbBXwH1dgp3P7q/byWfKQelOwtJjGDw/YL6KjdCMldU
64OOCvx3Y0RxzFl86QsHNbE6rGyWYU3jdUdAPqwqYV//gupr6ymY6i4IpQ07EAbg
EZlt8x5J0QumY9qCeSBbWVIQk/tlwE3Dk5IgHdDqWRxYybdvJfaxchcoJ+jty3IZ
n8TMyLH7qDbr3HowtkPrzKmTtxFUFIgcuaSuWVO4pbNIzpDFuJGEmU/ds77vAgMB
AAGjTTBLMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFMXdBLVfY5Zi/eWH6gev+iTQI1u
MB8GA1UdIwQYMBaAFMnFsp2qL/bIuN1yn+krywaoqX2FMA0GCSqGSIb3DQEBCwUA
A4IBAQBGRk0FcWsZvAKylAigVt6l8Il4BNs9Mfye8H4sAUtx4682Cu5TgjCbrC9F
SiCw6U60MJb2qmUUiRdzbof6cg7p6sS+NlPYl6zdj/XoWAAg0e2Fq+U95fHhB8Af
TWWhWS0ccT45cr6eQGwbW6/0wFRgpBJx9mwes/9NhBRxOJAODWYhtgwWOYuiNpDm
WxjkEJRRINNzhJUAZBEbWylMUnigqc+30a7MVq8QlUtrfTfgCC3bsSygq94xJrGF
oPWojgOp6hSVfr4PeG8JR5Nmo+YTp5MuNtPsdxau92lIK3g6SfZTkzlynTW1NUEC
TJEhOE2SluBw/yd0PQgrL5DQVKxd
-----END CERTIFICATE-----
$ openssl genrsa 2048 | tee perm-leaf-san.key
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEImeg2liXjiUI
096Lu0HBxlRHPrfn2Uepqn/AfyUNVV8tAfDzA+iAsy4eXrKL/6Oke2tfVa7WAoiC
ujDl9xJygi+1UMixYDyOxzBn5K/sUuy1oXWz1L2sZOv8GtXfkAqNUdGz2PsKxR2r
ZyuLcBXuzkzEOYHZLuQw8TjB1+6ZNOPAZyixrmuiaN88K/f2Y+Bsxd1i4qTc3bsa
xaklswmR4+eKdvjHKFhfjF5OTRxEa4Rx7lg6cstCvoLQFO+RWvtgwQK+P7QokgZH
4Mc16oMuWNX4X/YxQX2usbQXF1vJByWDmXmci3ZvtEp++vVstwy5rhJbXqu+64Ii
sp7cAuvTAgMBAAECggEABcdCglMS4edgLYuaA0fePuIKJzP9bkLQ562MQfswKxDL
n9ahmkDdOR10sfrCpXk/zixZeqxaXRe9NqZbPNgAnrsGW//0406DujkhssEVpcLA
ePSezenqN9ZpVW4WkWJiM5oOsY7zWafhB36GO+XVEsoLkCRmY1c/hdACU6oTvEbt
BXPZcbGuNZHhqg92T/j68fe6u1O1B14YOsYX/VxYJs0nkDZiaVp1D40csXM1I7k6
yZM4fhi1T0Za3SwWTTN+I/5xWwNlMOudmy9rMJrkPenp0XsqoBsvL8FghKigDy8g
qB6QWTawGC2RkRqgYNdkGTuvDvqw2FG8PKe4apmlEQKBgQDj/0xcD44+pC9ivVDs
OOH98M4Ksf4KrU/5t4VOFKYXOfJGm1C5l/GtBXLijwSIcnnYzZ29ecY+0i5VSyiV
hiT9vNH/5q+j/gm0DyrmsuwWO2mKu09qQb945rtdb71ikLPlujELPyG74rLng96B
piKwOUwKofpBODKFvDkGJPUIxwKBgQDcOUXMRQGWXfDS5bNF8QuMSGGxuOVnV3/O
vlKax+yNy91Ek/04lv5zSvYuxZua6M5jMgX5q3W8cEoZpAjmu+XWCcohx9FgDE05
MFqo+xt7iGt8AUUJg0nlNO1yA9od8g43/AAnwHN5Czhq8/qUF297wy7QDjp9HRsi
DnFJfcSwlQKBgG4+PuTw3J3rc8IxulROeO/6JRbE1ArDnL0pgPqtP1ZRvZVoelMT
Zld8H/3um4mCmOo9Gf3JSRONO7wgWGJcd7x9NamgGOOZ7YU0JFFiyIdDeRgM1CyT
2AqUvppCcnebcnEtY5OFlkEsL8eEWu2jsHg3bE5j3gb1LnC9/3C6JAV3AoGASZIA
lVtASoGboHkISQdb+kN8D6lbSgjbM7A1XGwJxN0kUHK4F52p585VLA7sCvZXbKAb
iusS7B7/Qk2gg6SmBblDg8GDWvkBG2fiAa3R4pUSg1zROXpYx2/FG1/aEEL7KQzQ
6HbMnNV4xZI4Vhz2K3xrOSpns8Bzfg8hHZIckXkCgYEAxqv0ngcnJVttBt2gLS6N
/yaF80hnA71Uj2/niIKvb3J1Zp6L8EnHEwDbyHtZ2WA66bP+RHPwpl83RbFRaIXN
bAFGV2QP58ud+CRj9Y/J2nyfLYxVTeEnfAZRyYZnX/dh9LuWS2VteOrlMZliupnp
I///Bf8+GuHfcrGSLbkMQj0=
-----END PRIVATE KEY-----
$ openssl req -new -key perm-leaf-san.key \
              -subj "/" -out perm-leaf-san.csr
$ openssl x509 -req -in perm-leaf-san.csr -CA ca-permitted.pem \
               -CAkey ca-permitted.key -CAcreateserial -days 3650 \
               -out perm-leaf-san.pem -extfile - <<EOF
basicConstraints=CA:FALSE
subjectAltName = dirName:leafsan
[leafsan]
O = bad.example
CN = leaf-san
EOF
$ cat perm-leaf-san.pem
-----BEGIN CERTIFICATE-----
MIIDTjCCAjagAwIBAgIUOwgi8PBl82PB8rHe4HHogGqAFK4wDQYJKoZIhvcNAQEL
BQAwOTEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMSAwHgYDVQQDDBdFeGFtcGxlIENB
IEROIFBlcm1pdHRlZDAeFw0yNjExMTExODM1MzhaFw0zNjExMDgxODM1MzhaMAAw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEImeg2liXjiUI096Lu0HB
xlRHPrfn2Uepqn/AfyUNVV8tAfDzA+iAsy4eXrKL/6Oke2tfVa7WAoiCujDl9xJy
gi+1UMixYDyOxzBn5K/sUuy1oXWz1L2sZOv8GtXfkAqNUdGz2PsKxR2rZyuLcBXu
zkzEOYHZLuQw8TjB1+6ZNOPAZyixrmuiaN88K/f2Y+Bsxd1i4qTc3bsaxaklswmR
4+eKdvjHKFhfjF5OTRxEa4Rx7lg6cstCvoLQFO+RWvtgwQK+P7QokgZH4Mc16oMu
WNX4X/YxQX2usbQXF1vJByWDmXmci3ZvtEp++vVstwy5rhJbXqu+64Iisp7cAuvT
AgMBAAGjgYYwgYMwCQYDVR0TBAIwADA2BgNVHREELzAtpCswKTEUMBIGA1UECgwL
YmFkLmV4YW1wbGUxETAPBgNVBAMMCGxlYWYtc2FuMB0GA1UdDgQWBBS368KjInRA
BUTjSLAaRbC7QMBXGTAfBgNVHSMEGDAWgBTJxbKdqi/2yLjdcp/pK8sGqKl9hTAN
BgkqhkiG9w0BAQsFAAOCAQEAYdgYckqxuk/x0iiFRQCEwMlOn24C7srHQwLdO7EK
Cc6Bx4SG9H1ek4EScEzuinQYhEJ5YjblGmXFkfLJu3RP6h2yxhh5w/bQetiKt0Lm
5aMx/Kc0F1alY/bgGfhmF9gzmiJQP517gWNsQnpiCkTWHwFtP4P59G+j5lm569AO
zJu4kOY7EFZ0WqK39Ep9iA7GcPfcG5lqlRAQtZwJQ6dSVI6b1RJd8ypeXbvSuCD4
UR9nHUg36RiOz5VOZ+ltk8D+I+2Xa3OO0uWL0P8Tj9UsBeY/+TXqBjGPchWPSjyo
hVO4JHhOQfQKeprsGet3AKbqEuB1Wqyua7gVC8Ts1fyRLQ==
-----END CERTIFICATE-----
$ openssl genrsa 2048 | tee perm-leaf-none.key
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDOEzx/w+sZAHAn
DS2kAvclhbsXAxT0HpfQPPXYYMPYx0LQzbIDHPZe0NIP6zNAZcpgNo6WqW4vXr+C
g2BuUL/AimB9BUzfI0aGO268E6JGCGY5cGy10rJ1gd8SNDe09FC1mcUY8W6GWMrZ
/N0HMX5HnC0MdWAwpruLGfJK8GFj8rCSG9uoMrMMSIaR4dzIaT8gKSe/DfR0ikok
XGV2lyBrvFNx2WWqEYt77zyXHfDKUuN5LuYhbDmMu4rWlrgbVrEDzzIFGJTb1DTu
DUeNHSzJQzZB0NmC3a7GAvv4Qrg9W9nU8Ezhtme2oL6IEO3PACup/JrituHblWsG
CVWTAQqVAgMBAAECggEAAVuBSAQsRC3Ldbsxl3ivh3wLur/Gv3VRVOO56Nl5hy/u
bqRHbZufIdb1TOAk2WIL3oaT4BLKPesKKII61eJkfCoZ/AJxB0oOGMWpppKCIwnC
7QW8Qy+NBMojHbvhuNu57/nmoV67XPL9YkjQoE+apqUba0J9eWr3v33sKZACZdKi
tAw2F/mdlzS7lmlYiscyikNMOKixUiJaGfnek/LtQ4ceSqmspa+u/n4bujWyAOKv
I4Orc+u9dkTkC981s/QUyJrrBTynG3W1EyIZ2gRaA9q0PU7bZd9h3K9m+aLhWj7b
mwTA8zpK/QOIxvI5YnShTy5DbTeFGKDcfvYPwKeGFwKBgQDvF4lNKNjzBZ+L4KWm
cFQum18huCtpZRdUdEtMvCEZl6X7jzmZcnNCqMQZlpv1Jynmc4c4FjhzM4apGqTJ
xTKIw1KdULhNG9AdUqP3Z/tS/PKJVgh8xqXRGRbeL0DYWrl1Bjp5GfJKcnYRWtOu
C8GJjOV8j0UWYxIFsZIP88WbIwKBgQDcpfjEHPc2jgdy3jlz4jqXRdlVGZ2WugNk
+mMyGRoLTYuRmITPYi2BtUeWzhbCitqyiqkujarcOZFwyfdIb4f/SIzuv9ZDDtFP
gNvzJrs98/nN01pbPDNHfJ0Xp4dtAUlagNBLOPHxrSyjhbb5gPAj6nbEBelHBjUL
p4MBW5Wa5wKBgQCkGX5mVBPbcM+ZnN11CAHvXzqDFTnOg9DoaU1JZJI/U4NbzmjV
NeWAKf82JNX0BCZRApgbWbzy7LmPFTdnOQ6/KXhpev6UBfPoPFFHvLmVswDwW/lF
Ur56boLwinQySsqhVF4LwlA24qrArJs/CNiUBP15aYgcnnC/MaozgrftCwKBgQDF
DdDiTEAXz7YlRwOmU7ch3DahQrQzpUJczyUB29sflwx7ZevOTg74FQ6vRrSa32k7
JIy9T7X04dDbGvQmE70wJvn+SwMudjBGQX2tZLy6Moa44/WBH31obYjaVDqlBg4d
robXdy7UOGVyUHu9zgIpAT86B1Fzpb5//wUHlGRCpwKBgQC62i3OPgiWKFNkmMBC
9mRFVm86a6SCcwBvipRzqYp47fDxtn3Yu7z0zWuNls56yNi6Wzpw4UGQaNsxi3vM
kUeMtR3Hv6DKf2Myedi04Ryw1LRgNr2B17NehDXF4UWFt2VK8Hj/2eVnB58wJVOK
KnLFGtdEM2I9JlOvgj8ORmORxg==
-----END PRIVATE KEY-----
$ openssl req -new -key perm-leaf-none.key \
              -subj "/" -out perm-leaf-none.csr
$ openssl x509 -req -in perm-leaf-none.csr -CA ca-permitted.pem \
               -CAkey ca-permitted.key -CAcreateserial -days 3650 \
               -out perm-leaf-none.pem -extfile - <<EOF
basicConstraints=CA:FALSE
EOF
$ cat perm-leaf-none.pem
-----BEGIN CERTIFICATE-----
MIIDFDCCAfygAwIBAgIUOwgi8PBl82PB8rHe4HHogGqAFK8wDQYJKoZIhvcNAQEL
BQAwOTEVMBMGA1UECgwMRXhhbXBsZSBJbmMuMSAwHgYDVQQDDBdFeGFtcGxlIENB
IEROIFBlcm1pdHRlZDAeFw0yNjExMTExODM1MzhaFw0zNjExMDgxODM1MzhaMAAw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOEzx/w+sZAHAnDS2kAvcl
hbsXAxT0HpfQPPXYYMPYx0LQzbIDHPZe0NIP6zNAZcpgNo6WqW4vXr+Cg2BuUL/A
imB9BUzfI0aGO268E6JGCGY5cGy10rJ1gd8SNDe09FC1mcUY8W6GWMrZ/N0HMX5H
nC0MdWAwpruLGfJK8GFj8rCSG9uoMrMMSIaR4dzIaT8gKSe/DfR0ikokXGV2lyBr
vFNx2WWqEYt77zyXHfDKUuN5LuYhbDmMu4rWlrgbVrEDzzIFGJTb1DTuDUeNHSzJ
QzZB0NmC3a7GAvv4Qrg9W9nU8Ezhtme2oL6IEO3PACup/JrituHblWsGCVWTAQqV
AgMBAAGjTTBLMAkGA1UdEwQCMAAwHQYDVR0OBBYEFCQDS/U/LiNvmakjZZwkhJ+t
dAjZMB8GA1UdIwQYMBaAFMnFsp2qL/bIuN1yn+krywaoqX2FMA0GCSqGSIb3DQEB
CwUAA4IBAQCmwkfpjE9G0C6rahxa8AqymJXd0TnguOJa+Nw16B7KNYlAKNf6uw5p
n7ZW8cRbjgojOXeAe0E8p2e7DUoTrz/SAJP5J5BpjrIZDFGxnQu4fh6u3ZWjMfkp
FEp/oJwXkNYXlLMUAdU9XeIPCMbIDXdfxHU+5vtvo0tDFvVq7mQCbqwlOCLmL6U/
Y1ccYxVOUJATgrwVcxBcSyXmweI3T0+vBEVA9Ov1hrioLzOQEQJYM82EyiG5RuKa
g1ZYCT43yRZcmhP1kisdomGzXybBkt3Wx5GC5tnnVem86921gKLcVRW08a5J8W6L
FH6jq2PwrHs/0xqd9M4PKN6/TxA59K+O
-----END CERTIFICATE-----

*/
