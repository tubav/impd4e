/* copyright Thomas Wang, Januar 1997
 * 
 * see http://www.concentric.net/~ttwang/tech/inthash.htm
 *
 */


#include "twmx.h"

/* Thomas Wang's 32 bit Mix Function */

#define mix(key) \
{ \
  key += ~(key << 15); \
  key ^=  ((key & 0x7FFFFFFF) >> 10); \
  key +=  (key << 3); \
  key ^=  ((key & 0x7FFFFFFF) >> 6); \
  key += ~(key << 11); \
  key ^=  ((key & 0x7FFFFFFF) >> 16); \
}

#ifdef HASHES_BIG_ENDIAN
static
uint32_t TWMXHash(uint8_t *data, uint32_t length, uint32_t initval)
{
   uint8_t *k = data;
   uint32_t len = length;
   uint32_t key = initval;

  if (data == NULL) return 0;

   while (len >= 4)
   {
      key += (k[0] +((uint32_t)k[1]<<8) +((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
      mix(key);
      k += 4; len -= 4;
   }

   switch(len)              /* all the case statements fall through */
   {
   case 3 : key+=((uint32_t)k[2]<<16);
   case 2 : key+=((uint32_t)k[1]<<8);
   case 1 : key+=k[0];
     /* case 0: nothing left to add */
   }
   mix(key);

   return key;
}
#else

uint32_t TWMXHash(uint8_t *data, uint32_t length, uint32_t initval)
{
   uint8_t *k = data;
   uint32_t len = length;
   uint32_t key = initval;


   if ((long)k&3)
   {
      while (len >= 4)    /* unaligned */
      {
        key += (k[0] +((uint32_t)k[1]<<8) +((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
        mix(key);
        k += 4; len -= 4;
      }
   }
   else
   {
      while (len >= 4)    /* aligned */
      {
         key += *(uint32_t *)(k+0);
        mix(key);
         k += 4; len -= 4;
      }
   }

   switch(len)              /* all the case statements fall through */
   {
   case 3 : key+=((uint32_t)k[2]<<16);
   case 2 : key+=((uint32_t)k[1]<<8);
   case 1 : key+=k[0];
     /* case 0: nothing left to add */
   }
   mix(key);

   return key;
}
#endif
