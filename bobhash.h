/* By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.  You may use
 * this code any way you wish, private, educational, or commercial.
 * It's free.  See http://burtleburtle.net/bob/hash/evahash.html.
 * Use for hash table lookup, or anything where one collision in 2^^32
 * is acceptable.  Do NOT use for cryptographic purposes.
*/

#ifndef BOBHASH_H_
#define BOBHASH_H_

#include <inttypes.h>

//typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
//typedef  unsigned       char ub1;   /* unsigned 1-byte quantities */
typedef  uint32_t  ub4;   /* unsigned 4-byte quantities */
typedef  uint8_t   ub1;   /* unsigned 1-byte quantities */

uint32_t BOB_Hash(uint8_t *databuffer, uint16_t databufferlength, uint32_t tinitval);


#endif /*BOBHASH_H_*/

