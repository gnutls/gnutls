#include <defines.h>
#include <gnutls_int.h>

uint32 uint24touint32( uint24 num) {
uint32 ret=0;

	((uint8*)&ret)[1] = num.pint[0];
	((uint8*)&ret)[2] = num.pint[1];
	((uint8*)&ret)[3] = num.pint[2];
	return ret;
}
uint24 uint32touint24( uint32 num) {
uint24 ret;

	ret.pint[0] = ((uint8*)&num)[1];
	ret.pint[1] = ((uint8*)&num)[2];
	ret.pint[2] = ((uint8*)&num)[3];
	return ret;

}
