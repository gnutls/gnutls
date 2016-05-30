/*
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/x509-ext.h>
#include <assert.h>
#include "utils.h"

void doit(void)
{
	int ret;
	gnutls_x509_tlsfeatures_t feat;
	unsigned int out;
	gnutls_datum_t der;

	ret = global_init();
	if (ret < 0)
		fail("init %d\n", ret);

        /* init and write >1 features
         */
        assert(gnutls_x509_tlsfeatures_init(&feat) >= 0);

        assert(gnutls_x509_tlsfeatures_add(feat, 2) >= 0);
        assert(gnutls_x509_tlsfeatures_add(feat, 3) >= 0);
        assert(gnutls_x509_tlsfeatures_add(feat, 5) >= 0);
        assert(gnutls_x509_tlsfeatures_add(feat, 7) >= 0);
        assert(gnutls_x509_tlsfeatures_add(feat, 11) >= 0);

        assert(gnutls_x509_ext_export_tlsfeatures(feat, &der) >= 0);

        gnutls_x509_tlsfeatures_deinit(feat);

        /* re-load and read
         */
        assert(gnutls_x509_tlsfeatures_init(&feat) >= 0);

        assert(gnutls_x509_ext_import_tlsfeatures(&der, feat, 0) >= 0);

        assert(gnutls_x509_tlsfeatures_get(feat, 0, &out) >= 0);
        assert(out == 2);

        assert(gnutls_x509_tlsfeatures_get(feat, 1, &out) >= 0);
        assert(out == 3);

        assert(gnutls_x509_tlsfeatures_get(feat, 2, &out) >= 0);
        assert(out == 5);

        assert(gnutls_x509_tlsfeatures_get(feat, 3, &out) >= 0);
        assert(out == 7);

        assert(gnutls_x509_tlsfeatures_get(feat, 4, &out) >= 0);
        assert(out == 11);

        gnutls_x509_tlsfeatures_deinit(feat);
        gnutls_free(der.data);

        /* check whether no feature is acceptable */
        assert(gnutls_x509_tlsfeatures_init(&feat) >= 0);

        assert(gnutls_x509_ext_export_tlsfeatures(feat, &der) >= 0);

        gnutls_x509_tlsfeatures_deinit(feat);

        assert(gnutls_x509_tlsfeatures_init(&feat) >= 0);

        assert(gnutls_x509_ext_import_tlsfeatures(&der, feat, 0) >= 0);

        assert(gnutls_x509_tlsfeatures_get(feat, 0, &out) == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

        gnutls_x509_tlsfeatures_deinit(feat);
        gnutls_free(der.data);

	gnutls_global_deinit();
}

