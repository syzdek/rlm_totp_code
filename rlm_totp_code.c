/*
 *  FreeRADIUS TOTP Code Module
 *  Copyright (C) 2026 David M. Syzdek <david@syzdek.net>.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *
 *     3. Neither the name of the copyright holder nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file rlm_totp_code.c
 * @brief Generates TOTP codes for use in unlang
 *
 * @author David M. Syzdek <david@syzdek.net>
 *
 * @copyright 2026 David M. Syzdek <david@syzdek.net>
 */

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/dlist.h>
#include <freeradius-devel/rad_assert.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>

#ifdef HAVE_PTHREAD_H
#   include <pthread.h>
#endif // HAVE_PTHREAD_H

#ifdef HAVE_OPENSSL_EVP_H
#   include <openssl/hmac.h>
#   include <openssl/evp.h>
#   include <freeradius-devel/openssl3.h>
#endif // HAVE_OPENSSL_EVP_H


//////////////
//          //
//  Macros  //
//          //
//////////////
// MARK: - Macros

#ifndef HAVE_PTHREAD_H
#  define pthread_mutex_lock(_x)    rad_assert(_x == NULL)
#  define pthread_mutex_unlock(_x)  rad_assert(_x == NULL)
#endif // !HAVE_PTHREAD_H


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#define RLM_TOTP_CODE_EBASE32       -1
#define RLM_TOTP_CODE_EBUFSIZ       -2

#define RLM_TOTP_HMAC_SHA1          1
#define RLM_TOTP_HMAC_SHA256        256
#define RLM_TOTP_HMAC_SHA512        512

#ifdef EVP_MAX_MD_SIZE
#   define RLM_TOTP_DIGEST_LENGTH   EVP_MAX_MD_SIZE
#else
#   define RLM_TOTP_DIGEST_LENGTH   SHA1_DIGEST_LENGTH
#endif

//////////////////
//              //
//  Data Types  //
//              //
//////////////////
// MARK: - Data Types


typedef struct rlm_totp_code_t   rlm_totp_code_t;
typedef struct _totp_used        totp_used_t;


// modules's structure for the configuration variables
struct rlm_totp_code_t
{  char const *      name;                   //!< name of this instance */
   const char *      totp_hmacstr;           //!< name of HMAC cryptographic hash function
   uint32_t          totp_t0;                //!< Unix time to start counting time steps (default: 0)
   uint32_t          totp_x;                 //!< time step in seconds (default: 30 seconds)
   int32_t           totp_time_adjust;       //!< adjust current time by seconds
   uint32_t          digits_len;             //!< length of output TOTP code
   bool              allow_reuse;            //!< allow TOTP codes to be re-used
   bool              devel_debug;            //!< enable extra debug messages for developer
   int               totp_hmac;              //!< HMAC cryptographic hash function
   rbtree_t *        used_tree;
   fr_dlist_t        used_list;
#ifdef HAVE_PTHREAD_H
   pthread_mutex_t * mutex;
#endif // HAVE_PTHREAD_H
};


struct _totp_used
{  uint8_t *      key;
   size_t         keylen;
   time_t         last_interval_count;
   void *         instance;
   fr_dlist_t     dlist;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

static int
mod_bootstrap(
         CONF_SECTION *			         conf,
         void *                        instance );


static int
mod_detach(
         UNUSED void *                 instance );


static int
mod_instantiate(
         UNUSED CONF_SECTION *         conf,
         void *                        instance );


static rlm_rcode_t
mod_post_auth(
         void *                        instance,
         REQUEST *                     request)
         CC_HINT(nonnull);


extern ssize_t
totp_base32_decode(
         uint8_t *                     dst,
         size_t                        dstlen,
         const char *                  src,
         size_t                        srclen );


static ssize_t
totp_base32_verify(
         const char *                  src,
         size_t                        srclen );


static int
totp_calculate(
         int                           hmac_hash,
         uint64_t                      totp_t0,
         uint64_t                      totp_x,
         uint64_t                      totp_time,
         const uint8_t *               key,
         size_t                        key_len,
         unsigned                      digits,
         uint64_t *                    totp_tp );


static void
totp_hmac(
         UNUSED int                    hmac_hash,
         uint8_t *                     digest,
         unsigned *                    digest_lenp,
         const uint8_t *               data,
         size_t                        data_len,
         const uint8_t *               key,
         size_t                        key_len );


static int
totp_used_cmp(
         const void *                  ptr_a,
         const void *                  ptr_b );


static void
totp_used_free(
         void *                        ptr );


static ssize_t
totp_xlat_code(
         UNUSED void *                 instance,
         REQUEST *                     request,
         char const *                  fmt,
         char *                        out,
         size_t                        outlen,
         int                           hmac_hash );


static ssize_t
totp_xlat_code_default(
         void *                        instance,
         REQUEST *                     request,
         char const *                  fmt,
         char *                        out,
         size_t                        outlen );


/////////////////
//             //
//  Variables  //
//             //
/////////////////
// MARK: - Variables

// Map configuration file names to internal variables */
static const CONF_PARSER module_config[] =
{  {  "time_start",        FR_CONF_OFFSET(PW_TYPE_INTEGER,  rlm_totp_code_t, totp_t0),          "0" },
   {  "time_step",         FR_CONF_OFFSET(PW_TYPE_INTEGER,  rlm_totp_code_t, totp_x),           "30" },
   {  "time_adjustment",   FR_CONF_OFFSET(PW_TYPE_SIGNED,   rlm_totp_code_t, totp_time_adjust), "0" },
   {  "digits_len",        FR_CONF_OFFSET(PW_TYPE_INTEGER,  rlm_totp_code_t, digits_len),       "6" },
   {  "allow_reuse",       FR_CONF_OFFSET(PW_TYPE_BOOLEAN,  rlm_totp_code_t, allow_reuse),      "no" },
   {  "devel_debug",       FR_CONF_OFFSET(PW_TYPE_BOOLEAN,  rlm_totp_code_t, devel_debug),      "no" },
   {  "hmac_hash",         FR_CONF_OFFSET(PW_TYPE_STRING,   rlm_totp_code_t, totp_hmacstr),     "HmacSHA1" },
   CONF_PARSER_TERMINATOR
};


static const int8_t base32_map[256] =
{
//    This map cheats and interprets:
//       - the numeral zero as the letter "O" as in oscar
//       - the numeral one as the letter "L" as in lima
//       - the numeral eight as the letter "B" as in bravo
// 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
   14, 11, 26, 27, 28, 29, 30, 31,  1, -1, -1, -1, -1,  0, -1, -1, // 0x30
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x40
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x50
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x60
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1, // 0x70
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};


extern module_t rlm_totp_code;
module_t rlm_totp_code =
{
   .magic                  = RLM_MODULE_INIT,
   .name                   = "totp_code",
   .type                   = RLM_TYPE_THREAD_SAFE,
   .inst_size              = sizeof(rlm_totp_code_t),
   .config                 = module_config,
   .instantiate            = mod_instantiate,
   .bootstrap              = mod_bootstrap,
   .detach                 = mod_detach,
   .methods =
   {  [MOD_POST_AUTH]      = mod_post_auth
   },
};


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

int
mod_bootstrap(
         CONF_SECTION *                conf,
         void *                        instance )
{
   int                     rc;
   char                    xlat_name[MAX_STRING_LEN];
	rlm_totp_code_t *       inst;

   inst = instance;

   if ((inst->name = cf_section_name2(conf)) == NULL)
      inst->name = cf_section_name1(conf);

   // register xlat:totp_code
   rc = xlat_register(inst->name, totp_xlat_code_default, NULL, inst);
   if (rc != 0)
   {  ERROR("totp_code: failed to register xlat:%s", inst->name);
      return(-1);
   };

   return(0);
}


int
mod_detach(
         void *                        instance )
{
   rlm_totp_code_t *       inst;

   rad_assert(instance != NULL);

   inst = instance;

   // destroy and free mutex lock
#ifdef HAVE_PTHREAD_H
   if ((inst->mutex))
   {  pthread_mutex_destroy(inst->mutex);
      talloc_free_children(inst->mutex);
      inst->mutex = NULL;
   };
#endif // HAVE_PTHREAD_H

   if (inst->used_tree != NULL)
      rbtree_free(inst->used_tree);
   inst->used_tree = NULL;

   return(0);
}


int
mod_instantiate(
         UNUSED CONF_SECTION *         conf,
         void *                        instance )
{
   rlm_totp_code_t *       inst;

   rad_assert(instance != NULL);

   inst                    = instance;
   inst->mutex             = NULL;
   inst->used_tree   = NULL;

   // initialize mutex lock
   inst->mutex = NULL;
#ifdef HAVE_PTHREAD_H
   if ((inst->mutex = talloc_zero(instance, pthread_mutex_t)) == NULL)
   {  ERROR("totp_code: failed to allocate memory for mutex lock");
      return(-1);
   };
   pthread_mutex_init(inst->mutex, NULL);
#endif // HAVE_PTHREAD_H

   FR_INTEGER_BOUND_CHECK("time_step",    inst->totp_x,        >=, 5);
   FR_INTEGER_BOUND_CHECK("digits_len",   inst->digits_len,    >=, 1);
   FR_INTEGER_BOUND_CHECK("digits_len",   inst->digits_len,    <=, 9);

   if (!(strcasecmp(inst->totp_hmacstr, "HmacSHA1")))
      inst->totp_hmac = RLM_TOTP_HMAC_SHA1;
#ifdef HAVE_OPENSSL_EVP_H
   else if (!(strcasecmp(inst->totp_hmacstr, "sha1")))
      inst->totp_hmac = RLM_TOTP_HMAC_SHA1;
   else if (!(strcasecmp(inst->totp_hmacstr, "HmacSHA256")))
      inst->totp_hmac = RLM_TOTP_HMAC_SHA256;
   else if (!(strcasecmp(inst->totp_hmacstr, "sha256")))
      inst->totp_hmac = RLM_TOTP_HMAC_SHA256;
   else if (!(strcasecmp(inst->totp_hmacstr, "HmacSHA512")))
      inst->totp_hmac = RLM_TOTP_HMAC_SHA512;
   else if (!(strcasecmp(inst->totp_hmacstr, "sha512")))
      inst->totp_hmac = RLM_TOTP_HMAC_SHA512;
#endif // HAVE_OPENSSL_EVP_H
   else
   {  WARN("Ignoring \"hmac_hash = %s\", forcing to \"hmac_hash = SHA1\"", inst->totp_hmacstr);
      inst->totp_hmac = RLM_TOTP_HMAC_SHA1;
   };

   inst->used_tree = rbtree_create(instance, totp_used_cmp, totp_used_free, 0);
   if (inst->used_tree == NULL)
      return(-1);

   fr_dlist_entry_init(&inst->used_list);

   return(0);
}


rlm_rcode_t
mod_post_auth(
         void *                        instance,
         REQUEST *                     request)
{
   return(RLM_MODULE_NOOP);
}


ssize_t
totp_base32_decode(
         uint8_t *                     dst,
         size_t                        dstlen,
         const char *                  src,
         size_t                        srclen )
{
   size_t      datlen;
   size_t      pos;
   ssize_t     rc;

   rad_assert(dst != NULL);
   rad_assert(src != NULL);
   rad_assert(dstlen >  0);

   datlen = 0;

   // verifies encoded data
   if ((rc = totp_base32_verify(src, srclen)) < 0)
      return(rc);
   if ( (rc > (ssize_t)dstlen) && ((dst)) )
      return(RLM_TOTP_CODE_EBUFSIZ);

   // decodes base32 encoded data
   datlen = 0;
   for(pos = 0; (pos < srclen); pos++)
   {  // MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
      // MB is middle bits             (0x7E == 01111110 ~= MB)
      // LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)
      switch(pos%8)
      {  // byte 0
         case 1:
            dst[datlen]  = (base32_map[(uint8_t)src[pos-1]] << 3) & 0xF8; // 5 MSB
            dst[datlen] |= (base32_map[(uint8_t)src[pos-0]] >> 2) & 0x07; // 3 LSB
            datlen++;
            break;

         // byte 2
         case 2:
            if (src[pos] == '=')
               return((ssize_t)datlen);
            break;

         // byte 3
         case 3:
            dst[datlen]  = (base32_map[(uint8_t)src[pos-2]] << 6) & 0xC0; // 2 MSB
            dst[datlen] |= (base32_map[(uint8_t)src[pos-1]] << 1) & 0x3E; // 5  MB
            dst[datlen] |= (base32_map[(uint8_t)src[pos-0]] >> 4) & 0x01; // 1 LSB
            datlen++;
            break;

         // byte 4
         case 4:
            if (src[pos] == '=')
               return((ssize_t)datlen);
            dst[datlen]  = (base32_map[(uint8_t)src[pos-1]] << 4) & 0xF0; // 4 MSB
            dst[datlen] |= (base32_map[(uint8_t)src[pos-0]] >> 1) & 0x0F; // 4 LSB
            datlen++;
            break;

         // byte 5;
         case 5:
            if (src[pos] == '=')
               return((ssize_t)datlen);
            break;

         // byte 6
         case 6:
            dst[datlen]  = (base32_map[(uint8_t)src[pos-2]] << 7) & 0x80; // 1 MSB
            dst[datlen] |= (base32_map[(uint8_t)src[pos-1]] << 2) & 0x7C; // 5  MB
            dst[datlen] |= (base32_map[(uint8_t)src[pos-0]] >> 3) & 0x03; // 2 LSB
            datlen++;
            break;

         // byte 7
         case 7:
            if (src[pos] == '=')
               return((ssize_t)datlen);
            dst[datlen]  = (base32_map[(uint8_t)src[pos-1]] << 5) & 0xE0; // 3 MSB
            dst[datlen] |= (base32_map[(uint8_t)src[pos-0]] >> 0) & 0x1F; // 5 LSB
            datlen++;
            break;

         default:
            if (src[pos] == '=')
               return((ssize_t)datlen);
            break;
      };
   };

   return((ssize_t)datlen);
}


ssize_t
totp_base32_verify(
         const char *                  src,
         size_t                        srclen )
{
   size_t      datlen;
   size_t      pos;

   rad_assert(src != NULL);

   datlen = 0;

   // verifies encoded data
   for(pos = 0; (pos < srclen); pos++)
   {  // verify that data is valid character
      if (base32_map[(int8_t)src[pos]] == -1)
         return(RLM_TOTP_CODE_EBASE32);

      // verify correct use of padding
      if (src[pos] != '=')
         continue;
      datlen = pos;
      if ((pos % 8) < 2)
         return(RLM_TOTP_CODE_EBASE32);
      if ((pos + (8-(pos%8))) != srclen)
         return(RLM_TOTP_CODE_EBASE32);
      for(; (pos < srclen); pos++)
         if (src[pos] != '=')
            return(RLM_TOTP_CODE_EBASE32);
   };
   if (!(datlen))
      datlen = pos;

   // verify length of data without padding
   switch(datlen % 8)
   {  case 0:
      case 2:
      case 4:
      case 5:
      case 7:
         break;

      case 1:
      case 3:
      case 6:
      default:
         return(RLM_TOTP_CODE_EBASE32);
   };

   return((datlen * 5) / 8);
}


int
totp_calculate(
         int                           hmac_hash,
         uint64_t                      totp_t0,
         uint64_t                      totp_x,
         uint64_t                      totp_time,
         const uint8_t *               key,
         size_t                        key_len,
         unsigned                      digits,
         uint64_t *                    totp_tp )
{
   uint8_t        data[8];
   uint8_t        digest[RLM_TOTP_DIGEST_LENGTH];
   uint32_t       bin_code;
   uint64_t       totp_t;
   uint64_t       offset;
   unsigned       digest_len;
   unsigned       denominator;

   rad_assert(totp_t0 <= totp_time);

   // calculate interval count and copy into data buffer
   totp_t   = (totp_time-totp_t0) / totp_x;
   data[0]  = (totp_t >> 56) & 0xff;
   data[1]  = (totp_t >> 48) & 0xff;
   data[2]  = (totp_t >> 40) & 0xff;
   data[3]  = (totp_t >> 32) & 0xff;
   data[4]  = (totp_t >> 24) & 0xff;
   data[5]  = (totp_t >> 16) & 0xff;
   data[6]  = (totp_t >>  8) & 0xff;
   data[7]  =  totp_t        & 0xff;

   // calculate HMAC digest
   totp_hmac(hmac_hash, digest, &digest_len, data, sizeof(data), key, key_len);
   if (digest_len == 0)
      return(-1);

   // dynamically truncates hash
   offset   = digest[digest_len-1] & 0x0f;
   bin_code =  ((digest[offset+0] & 0x7f) << 24) |
               ((digest[offset+1] & 0xff) << 16) |
               ((digest[offset+2] & 0xff) <<  8) |
                (digest[offset+3] & 0xff);

   // truncates code to specific decimal digits
   for(denominator = 1; (digits > 0); digits--)
      denominator *= 10;

   if ((totp_tp))
      *totp_tp = totp_t;

   return((int)(bin_code % denominator));
}


void
totp_hmac(
         UNUSED int                    hmac_hash,
         uint8_t *                     digest,
         unsigned *                    digest_lenp,
         const uint8_t *               data,
         size_t                        data_len,
         const uint8_t *               key,
         size_t                        key_len )
{
#ifdef HAVE_OPENSSL_EVP_H
   unsigned char           md[RLM_TOTP_DIGEST_LENGTH];
   unsigned                md_len;
   const EVP_MD *          evp_md;
   uint8_t  *              hmac_result;
#endif // HAVE_OPENSSL_EVP_H

   rad_assert(digest       != NULL);
   rad_assert(data         != NULL);
   rad_assert(data_len     >= 0);
   rad_assert(key          != NULL);
   rad_assert(key_len      >= 0);

   memset(digest, 0, sizeof(RLM_TOTP_DIGEST_LENGTH));
   *digest_lenp = 0;

#ifndef HAVE_OPENSSL_EVP_H
   if (hmac_hash == RLM_TOTP_HMAC_SHA1)
   {  fr_hmac_sha1(digest, data, data_len, key, key_len);
      *digest_lenp = SHA1_DIGEST_LENGTH;
   };
#endif // !HAVE_OPENSSL_EVP_H

#ifdef HAVE_OPENSSL_EVP_H
   md_len      = RLM_TOTP_DIGEST_LENGTH;
   switch(hmac_hash)
   {  case RLM_TOTP_HMAC_SHA1:   evp_md = EVP_sha1();    break;
      case RLM_TOTP_HMAC_SHA256: evp_md = EVP_sha256();  break;
      case RLM_TOTP_HMAC_SHA512: evp_md = EVP_sha512();  break;
      default: return;
   };
   hmac_result = (uint8_t *)HMAC(evp_md, key, (int)key_len, (unsigned char *)data, data_len, md, &md_len);
   memcpy(digest, hmac_result, md_len);
   *digest_lenp = md_len;
#endif // HAVE_OPENSSL_EVP_H

   return;
}


int
totp_used_cmp(
         const void *                  ptr_a,
         const void *                  ptr_b )
{
   return(0);
}


void
totp_used_free(
         void *                        ptr )
{
   totp_used_t *        entry;
   rlm_totp_code_t *    inst;

   if (!(ptr))
      return;

   entry = (totp_used_t *)ptr;
   inst  = entry->instance;

   pthread_mutex_lock(inst->mutex);

   if ((entry->key))
      free(entry->key);
   free(entry);

   pthread_mutex_unlock(inst->mutex);

   return;
}


ssize_t
inline totp_xlat_code(
         UNUSED void *                 instance,
         REQUEST *                     request,
         char const *                  fmt,
         char *                        out,
         size_t                        outlen,
         int                           hmac_hash )
{
   int                     code;
   size_t                  pos;
   ssize_t                 base32_len;
   ssize_t                 key_len;
   uint8_t *               key;
   time_t                  totp_time;
   const char *            base32;
   char                    attr_name[MAX_STRING_LEN];
   const DICT_ATTR *       attr;
   VALUE_PAIR *            vp;
	rlm_totp_code_t *       inst;

   rad_assert(instance != NULL);
   rad_assert(request  != NULL);
   rad_assert(fmt      != NULL);

   inst = instance;

   key      = NULL;
   key_len  = 0;

   // retreieve current time
   totp_time  = time(NULL);
   totp_time += inst->totp_time_adjust;

   // skip leading white space
   while (isspace((uint8_t) *fmt))
      fmt++;

   // scanning for end of base32 encoded secret or attribute name
   for(pos = 0; ( (!(isspace(fmt[pos]))) && (fmt[pos] != '\0') ); pos++);
   base32     = fmt;
   base32_len = pos;

   // scanning for end of line
   fmt = &fmt[pos+1];
   for(pos = 0; ( (!(isspace(fmt[pos]))) && (fmt[pos] != '\0') ); pos++);
   if (fmt[pos] != '\0')
   {  REDEBUG("Invalid arguments passed to totp_code xlat");
      *out = '\0';
      return(-1);
   };

   // check for attribute reference instead of string
   if (base32[0] == '&')
   {  if (base32_len > (MAX_STRING_LEN-1))
      {  REDEBUG("Unable to parse attribute in totp_code xlat");
         *out = '\0';
         return(-1);
      };
      memcpy(attr_name, &base32[1], base32_len-1);
      attr_name[base32_len-1] = '\0';

      // lookup attribute in dictionary
      attr = dict_attrbyname(attr_name);
      if (!(attr))
      {  REDEBUG("Unknown referenced attribute in totp_code xlat");
         *out = '\0';
         return(-1);
      };
      if (attr->type!= PW_TYPE_STRING)
      {  REDEBUG("referenced attribute %s is not a string", attr_name);
         *out = '\0';
         return(-1);
      };

      // retrieve attribute from request
      vp = fr_pair_find_by_num(request->config, attr->attr, attr->vendor, TAG_ANY);
      if (!(vp))
      {  REDEBUG("referenced attribute %s is not set", attr_name);
         *out = '\0';
         return(-1);
      };

      switch(vp->da->type)
      {  case PW_TYPE_STRING:
            base32     = vp->data.strvalue;
            base32_len = vp->length;
            break;

         case PW_TYPE_OCTETS:
            key_len  = vp->length;
            if ((key = talloc_size(request, key_len+1)) == NULL)
            {  ERROR("totp_code: unable to allocate memory");
               *out = '\0';
               return(-1);
            };
            memcpy(key, vp->data.octets, key_len);
            key[key_len] = '\0';
            break;

         default:
            REDEBUG("referenced attribute is not string or octets");
            *out = '\0';
            return(-1);
      };
   };

   // decode base32 encoded string
   if (!(key))
   {  // verify base32 encoding
      if ((key_len = totp_base32_verify(base32, base32_len)) < 0)
      {  REDEBUG("invalid base32 encoded data passed to totp_code xlat");
         *out = '\0';
         return(-1);
      };

      // allocate memory and decode secret
      if ((key = talloc_size(request, key_len+1)) == NULL)
      {  ERROR("totp_code: unable to allocate memory");
         *out = '\0';
         return(-1);
      };
      totp_base32_decode(key, key_len, base32, base32_len);
      key[key_len] = '\0';
   };

   code = totp_calculate(hmac_hash, inst->totp_t0, inst->totp_x, totp_time, key, key_len, inst->digits_len, NULL);
   if ((inst->devel_debug))
   {  RDEBUG("rlm_totp_code: hmac_hash:      %i\n",  (int)hmac_hash);
      RDEBUG("rlm_totp_code: totp_time:      %u\n",  (unsigned)totp_time);
      RDEBUG("rlm_totp_code: inst->totp_t0:  %u\n",  (unsigned)inst->totp_t0);
      RDEBUG("rlm_totp_code: inst->totp_x:   %u\n",  (unsigned)inst->totp_x);
      RDEBUG("rlm_totp_code: key:            <binary>\n");
      RDEBUG("rlm_totp_code: key_len:        %u\n",  (unsigned)key_len);
      RDEBUG("rlm_totp_code: result:         %0*i\n",  inst->digits_len, code);
   };
   if (code < 0)
   {  *out = '\0';
      return(-1);
   };

   if ((size_t)snprintf(out, outlen, "%0*i" , (int)inst->digits_len, (int)code) >= outlen)
   {  REDEBUG("Insufficient space to write TOTP code");
      *out = '\0';
      return(-1);
   };

   return(0);
}


ssize_t
totp_xlat_code_default(
         void *                        instance,
         REQUEST *                     request,
         char const *                  fmt,
         char *                        out,
         size_t                        outlen )
{
   rlm_totp_code_t *    inst;
   inst = instance;
   return(totp_xlat_code(instance, request, fmt, out, outlen, inst->totp_hmac));
}


/* end of source */
