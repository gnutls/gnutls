/*
 * Copyright (C) 2013 Red Hat
 *
 * Author: Nikos Mavrogiannopoulos
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef FIPS_H
# define FIPS_H

#include <gnutls_int.h>
#include <gnutls/gnutls.h>

typedef enum {
  FIPS_STATE_POWERON,
  FIPS_STATE_INIT,
  FIPS_STATE_SELFTEST,
  FIPS_STATE_OPERATIONAL,
  FIPS_STATE_ERROR,
  FIPS_STATE_SHUTDOWN
} gnutls_fips_state_t;

#ifdef ENABLE_FIPS140

/* do not access directly */
extern unsigned int _gnutls_fips_mode;

inline static 
void _gnutls_switch_fips_state(gnutls_fips_state_t state)
{
	_gnutls_fips_mode = state;
}

inline static gnutls_fips_state_t _gnutls_get_fips_state(void)
{
	return _gnutls_fips_mode;
}

int _gnutls_fips_perform_self_checks(void);
unsigned _gnutls_fips_mode_enabled(void);

# define FAIL_IF_FIPS_ERROR \
	if (_gnutls_get_fips_state() != FIPS_STATE_OPERATIONAL) return GNUTLS_E_LIB_IN_ERROR_STATE

void _gnutls_switch_fips_state(gnutls_fips_state_t state);

#else

# define _gnutls_switch_fips_state(x) 0
# define _gnutls_get_fips_state() STATE_OPERATIONAL
# define FAIL_IF_FIPS_ERROR 0
# define _gnutls_fips_perform_self_checks() 0
# define _gnutls_fips_mode_enabled() 0
#endif

#endif /* FIPS_H */
