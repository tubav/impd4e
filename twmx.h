/* copyright Thomas Wang, Januar 1997
 * 
 * see http://www.concentric.net/~ttwang/tech/inthash.htm
 *
 */


#ifndef TWMX_H_
#define TWMX_H_
#include <inttypes.h>

uint32_t TWMXHash(uint8_t *data, uint32_t length, uint32_t initval);
#endif /*TWMX_H_*/
