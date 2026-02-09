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
#define RLM_TOTP_HMAC_SHA224        224
#define RLM_TOTP_HMAC_SHA256        256
#define RLM_TOTP_HMAC_SHA384        384
#define RLM_TOTP_HMAC_SHA512        512

#define TOTP_SCOPE_CONTROL          0
#define TOTP_SCOPE_REPLY            1
#define TOTP_SCOPE_REQUEST          2

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


typedef struct rlm_totp_code_t      rlm_totp_code_t;
typedef struct _totp_algorithm      totp_algo_t;
typedef struct _totp_cache_entry    totp_cache_entry_t;
typedef struct _totp_params         totp_params_t;


// modules's structure for the configuration variables
struct rlm_totp_code_t
{  char const *            name;                   //!< name of this instance */
   const char *            totp_algo_str;          //!< name of HMAC cryptographic algorithm
   const char *            vsa_cache_key_name;     //!< name of VSA to use as the cache key
   const char *            vsa_time_offset_name;   //!< name of VSA which overrides totp_time_offset
   const char *            vsa_unix_time_name;     //!< name of VSA which overrides totp_t0
   const char *            vsa_time_step_name;     //!< name of VSA which overrides totp_x
   const char *            vsa_otp_length_name;    //!< name of VSA which overrides otp_length
   const char *            vsa_algorithm_name;     //!< name of VSA which overrides totp_algo
   const DICT_ATTR *       vsa_cache_key;          //!< dictionary entry for VSA to use as the cache key
   const DICT_ATTR *       vsa_time_offset;        //!< dictionary entry for VSA which overrides totp_time_offset
   const DICT_ATTR *       vsa_unix_time;          //!< dictionary entry for VSA which overrides totp_t0
   const DICT_ATTR *       vsa_time_step;          //!< dictionary entry for VSA which overrides totp_x
   const DICT_ATTR *       vsa_otp_length;         //!< dictionary entry for VSA which overrides otp_length
   const DICT_ATTR *       vsa_algorithm;          //!< dictionary entry for VSA which overrides totp_algo
   uint32_t                totp_t0;                //!< Unix time to start counting time steps (default: 0)
   uint32_t                totp_x;                 //!< time step in seconds (default: 30 seconds)
   int32_t                 totp_time_offset;       //!< adjust current time by seconds
   uint32_t                otp_length;             //!< length of output TOTP code
   bool                    allow_override;         //!< allow TOTP parameters to be overriden by RADIUS attributes
   bool                    allow_reuse;            //!< allow TOTP codes to be re-used
   bool                    devel_debug;            //!< enable extra debug messages for developer
   int                     totp_algo;              //!< HMAC cryptographic algorithm
   rbtree_t *              cache_tree;
   totp_cache_entry_t *    cache_list;
#ifdef HAVE_PTHREAD_H
   pthread_mutex_t *       mutex;
#endif // HAVE_PTHREAD_H
};


struct _totp_algorithm
{  const char *            name;
   int                     id;
};


struct _totp_cache_entry
{  uint8_t *               key;              //!< value of User-Name attribute
   size_t                  keylen;           //!< length of User-Name attribute
   time_t                  entry_expires;    //!< epoch time when last used code will expire
   totp_cache_entry_t *    prev;
   totp_cache_entry_t *    next;
};


struct _totp_params
{  uint64_t                totp_t0;          //!< Unix time to start counting time steps
   uint64_t                totp_x;           //!< time step in seconds
   uint64_t                totp_cur_unix;    //!< current Unix time
   uint64_t                totp_t;           //!< number of time steps since t0
   int64_t                 totp_time_offset; //!< amount of seconds to adjust .totp_cur_unix
   uint64_t                totp_algo;        //!< HMAC algorithm
   uint64_t                otp_length;       //!< requested length of One-Time-Password
   size_t                  key_len;          //!< length of HMAC key
   const uint8_t *         key;              //!< HAMC key
   char                    otp[16];
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


static int
totp_algorithm_id(
         const char *                  algo_name );


static const char *
totp_algorithm_name(
         int                           algo_id );


static ssize_t
totp_base32_decode(
         uint8_t *                     dst,
         size_t                        dstlen,
         const char *                  src,
         size_t                        srclen );


static ssize_t
totp_base32_verify(
         const char *                  src,
         size_t                        srclen );


static totp_cache_entry_t *
totp_cache_entry_alloc(
         void *                        ctx,
         const uint8_t *               key,
         size_t                        key_len,
         time_t                        expires );


static int
totp_calculate(
         totp_params_t *               params );


static void
totp_hmac(
         UNUSED int                    totp_algo,
         uint8_t *                     digest,
         unsigned *                    digest_lenp,
         const uint8_t *               data,
         size_t                        data_len,
         const uint8_t *               key,
         size_t                        key_len );


static VALUE_PAIR *
totp_request_vp_by_dict(
         UNUSED void *                 instance,
         REQUEST *                     request,
         const DICT_ATTR *             da,
         int                           scope );


static VALUE_PAIR *
totp_request_vp_by_name(
         UNUSED void *                 instance,
         REQUEST *                     request,
         const char *                  attrstr,
         size_t                        attrstr_len,
         int                           default_scope );


static int
totp_set_params(
         void *                        instance,
         REQUEST *                     request,
         totp_params_t *               params );


int
totp_set_params_integer(
         void *                        instance,
         REQUEST *                     request,
         const DICT_ATTR *             da,
         uint64_t *                    uintp );


int
totp_set_params_signed(
         void *                        instance,
         REQUEST *                     request,
         const DICT_ATTR *             da,
         int64_t *                     intp );


static void
totp_cache_cleanup(
         void *                        instance,
         time_t                        t );


static int
totp_cache_entry_cmp(
         const void *                  ptr_a,
         const void *                  ptr_b );


static void
totp_cache_entry_free(
         void *                        ptr );


static VALUE_PAIR *
totp_cache_entry_key(
         void *                        instance,
         REQUEST *                     request );


static void
totp_cache_entry_unlink(
         totp_cache_entry_t *          entry );


static int
totp_cache_update(
         void *                        instance,
         REQUEST *                     request,
         totp_params_t *               params );


static ssize_t
totp_xlat_code(
         UNUSED void *                 instance,
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

// Map configuration file names to internal variables
static const CONF_PARSER module_config[] =
{  {  "unix_time",         FR_CONF_OFFSET(PW_TYPE_INTEGER,  rlm_totp_code_t, totp_t0),                "0" },
   {  "time_step",         FR_CONF_OFFSET(PW_TYPE_INTEGER,  rlm_totp_code_t, totp_x),                 "30" },
   {  "time_offset",       FR_CONF_OFFSET(PW_TYPE_SIGNED,   rlm_totp_code_t, totp_time_offset),       "0" },
   {  "otp_length",        FR_CONF_OFFSET(PW_TYPE_INTEGER,  rlm_totp_code_t, otp_length),             "6" },
   {  "allow_reuse",       FR_CONF_OFFSET(PW_TYPE_BOOLEAN,  rlm_totp_code_t, allow_reuse),            "no" },
   {  "allow_override",    FR_CONF_OFFSET(PW_TYPE_BOOLEAN,  rlm_totp_code_t, allow_override),         "no" },
   {  "devel_debug",       FR_CONF_OFFSET(PW_TYPE_BOOLEAN,  rlm_totp_code_t, devel_debug),            "no" },
   {  "algorithm",         FR_CONF_OFFSET(PW_TYPE_STRING,   rlm_totp_code_t, totp_algo_str),          "sha1" },
   {  "vsa_cache_key",     FR_CONF_OFFSET(PW_TYPE_STRING,   rlm_totp_code_t, vsa_cache_key_name),     "User-Name" },
   {  "vsa_time_offset",   FR_CONF_OFFSET(PW_TYPE_STRING,   rlm_totp_code_t, vsa_time_offset_name),   "TOTP-Time-Offset" },
   {  "vsa_unix_time",     FR_CONF_OFFSET(PW_TYPE_STRING,   rlm_totp_code_t, vsa_unix_time_name),     NULL },
   {  "vsa_time_step",     FR_CONF_OFFSET(PW_TYPE_STRING,   rlm_totp_code_t, vsa_time_step_name),     NULL },
   {  "vsa_otp_length",    FR_CONF_OFFSET(PW_TYPE_STRING,   rlm_totp_code_t, vsa_otp_length_name),    NULL },
   {  "vsa_algorithm",     FR_CONF_OFFSET(PW_TYPE_STRING,   rlm_totp_code_t, vsa_algorithm_name),     NULL },
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


static totp_algo_t totp_algorithm_map[] =
{  {  .name = "sha1",   .id = RLM_TOTP_HMAC_SHA1 },
#ifdef HAVE_OPENSSL_EVP_H
   {  .name = "sha224", .id = RLM_TOTP_HMAC_SHA224 },
   {  .name = "sha256", .id = RLM_TOTP_HMAC_SHA256 },
   {  .name = "sha384", .id = RLM_TOTP_HMAC_SHA384 },
   {  .name = "sha512", .id = RLM_TOTP_HMAC_SHA512 },
#endif // HAVE_OPENSSL_EVP_H
   {  .name = NULL,     .id = 0 }
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
	rlm_totp_code_t *       inst;

   inst = instance;

   if ((inst->name = cf_section_name2(conf)) == NULL)
      inst->name = cf_section_name1(conf);

   // register xlat:totp_code
   rc = xlat_register(inst->name, totp_xlat_code, NULL, inst);
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

   if (inst->cache_tree != NULL)
      rbtree_free(inst->cache_tree);
   inst->cache_tree = NULL;

   return(0);
}


int
mod_instantiate(
         UNUSED CONF_SECTION *         conf,
         void *                        instance )
{
   rlm_totp_code_t *       inst;
   PW_TYPE                 type;
   const char *            vsa_name;

   rad_assert(instance != NULL);

   inst              = instance;
   inst->mutex       = NULL;
   inst->cache_tree  = NULL;
   inst->cache_list  = NULL;

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
   FR_INTEGER_BOUND_CHECK("otp_length",   inst->otp_length,    >=, 1);
   FR_INTEGER_BOUND_CHECK("otp_length",   inst->otp_length,    <=, 9);

   if ((inst->totp_algo = totp_algorithm_id(inst->totp_algo_str)) == -1)
   {  WARN("Ignoring \"algorithm = %s\", forcing to \"algorithm = SHA1\"", inst->totp_algo_str);
      inst->totp_algo = RLM_TOTP_HMAC_SHA1;
   };

   // lookup and verify VSA specified by config option vsa_cache_key
   if ((vsa_name = inst->vsa_cache_key_name) != NULL)
   {  if ((inst->vsa_cache_key = dict_attrbyname(vsa_name)) == NULL)
      {  ERROR("'%s' not found in dictionary", vsa_name);
         return(-1);
      };
   };

   // lookup and verify VSA specified by config option vsa_time_offset
   if ((vsa_name = inst->vsa_time_offset_name) != NULL)
   {  if ((inst->vsa_time_offset = dict_attrbyname(vsa_name)) == NULL)
      {  ERROR("'%s' not found in dictionary", vsa_name);
         return(-1);
      };
      type = inst->vsa_time_offset->type;
      if ( (type!= PW_TYPE_INTEGER) && (type!= PW_TYPE_INTEGER64) && (type != PW_TYPE_SIGNED) && (type != PW_TYPE_STRING) )
      {  ERROR("'%s' is not an integer or signed attribute", vsa_name);
         return(-1);
      };
   };

   // lookup and verify VSA specified by config option vsa_unix_time
   if ((vsa_name = inst->vsa_unix_time_name) != NULL)
   {  if ((inst->vsa_unix_time = dict_attrbyname(vsa_name)) == NULL)
      {  ERROR("'%s' not found in dictionary", vsa_name);
         return(-1);
      };
      type = inst->vsa_unix_time->type;
      if ( (type!= PW_TYPE_INTEGER) && (type!= PW_TYPE_INTEGER64) && (type != PW_TYPE_SIGNED) && (type != PW_TYPE_STRING) )
      {  ERROR("'%s' is not an integer or signed attribute", vsa_name);
         return(-1);
      };
   };

   // lookup and verify VSA specified by config option vsa_time_step
   if ((vsa_name = inst->vsa_time_step_name) != NULL)
   {  if ((inst->vsa_time_step = dict_attrbyname(vsa_name)) == NULL)
      {  ERROR("'%s' not found in dictionary", vsa_name);
         return(-1);
      };
      type = inst->vsa_time_step->type;
      if ( (type!= PW_TYPE_INTEGER) && (type!= PW_TYPE_INTEGER64) && (type != PW_TYPE_SIGNED) && (type != PW_TYPE_STRING) )
      {  ERROR("'%s' is not an integer or signed attribute", vsa_name);
         return(-1);
      };
   };

   // lookup and verify VSA specified by config option vsa_otp_length
   if ((vsa_name = inst->vsa_otp_length_name) != NULL)
   {  if ((inst->vsa_otp_length = dict_attrbyname(vsa_name)) == NULL)
      {  ERROR("'%s' not found in dictionary", vsa_name);
         return(-1);
      };
      type = inst->vsa_otp_length->type;
      if ( (type!= PW_TYPE_INTEGER) && (type!= PW_TYPE_INTEGER64) && (type != PW_TYPE_SIGNED) && (type != PW_TYPE_STRING) )
      {  ERROR("'%s' is not an integer or signed attribute", vsa_name);
         return(-1);
      };
   };

   // lookup and verify VSA specified by config option vsa_algorithm
   if ((vsa_name = inst->vsa_algorithm_name) != NULL)
   {  if ((inst->vsa_algorithm = dict_attrbyname(vsa_name)) == NULL)
      {  ERROR("'%s' not found in dictionary", vsa_name);
         return(-1);
      };
      type = inst->vsa_algorithm->type;
      if ( (type!= PW_TYPE_INTEGER) && (type!= PW_TYPE_INTEGER64) && (type != PW_TYPE_SIGNED) && (type != PW_TYPE_STRING) )
      {  ERROR("'%s' is not an integer or signed attribute", vsa_name);
         return(-1);
      };
   };

   // initialize cache and list
   if (!(inst->allow_reuse))
   {  inst->cache_tree = rbtree_create(instance, totp_cache_entry_cmp, totp_cache_entry_free, 0);
      if (inst->cache_tree == NULL)
         return(-1);
      inst->cache_list = talloc_size(instance, sizeof(totp_cache_entry_t));
      if (inst->cache_list == NULL)
      { rbtree_free(inst->cache_tree);
         return(-1);
      };
      memset(inst->cache_list, 0, sizeof(totp_cache_entry_t));
   };

   return(0);
}


rlm_rcode_t
mod_post_auth(
         void *                        instance,
         REQUEST *                     request)
{
   return(RLM_MODULE_NOOP);
}


int
totp_algorithm_id(
         const char *                  algo_name )
{
   int idx;
   if (!(strncasecmp(algo_name, "HMAC", 4)))
      algo_name = &algo_name[4];
   for(idx = 0; ((totp_algorithm_map[idx].name)); idx++)
      if (!(strcasecmp(algo_name, totp_algorithm_map[idx].name)))
         return(totp_algorithm_map[idx].id);
   return(-1);
}


const char *
totp_algorithm_name(
         int                           algo_id )
{
   int idx;
   for(idx = 0; ((totp_algorithm_map[idx].name)); idx++)
      if (totp_algorithm_map[idx].id == algo_id)
         return(totp_algorithm_map[idx].name);
   return("unknown");
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


totp_cache_entry_t *
totp_cache_entry_alloc(
         void *                        ctx,
         const uint8_t *               key,
         size_t                        key_len,
         time_t                        expires )
{
   totp_cache_entry_t *    entry;

   rad_assert(key != NULL);
   rad_assert(key_len > 0);

   if ((entry = talloc_size(ctx, sizeof(totp_cache_entry_t))) == NULL)
      return(NULL);
   memset(entry, 0, sizeof(totp_cache_entry_t));

   if ((entry->key = talloc_size(entry, (key_len+1))) == NULL)
   {  talloc_free(entry);
      return(NULL);
   };
   memcpy(entry->key, key, key_len);

   entry->key[key_len]  = '\0';
   entry->keylen        = key_len;
   entry->entry_expires = expires;

   return(entry);
}


int
totp_calculate(
         totp_params_t *               params )
{
   uint8_t        data[8];
   uint8_t        digest[RLM_TOTP_DIGEST_LENGTH];
   uint32_t       bin_code;
   uint64_t       offset;
   unsigned       digest_len;
   unsigned       denominator;
   unsigned       digits;
   unsigned       otp;

   rad_assert(params != NULL);

   if (params->totp_t0 > (params->totp_cur_unix + params->totp_time_offset))
      return(-1);

   // calculate interval count
   params->totp_t     = params->totp_cur_unix - params->totp_t0;
   params->totp_t    += params->totp_time_offset;
   params->totp_t    /= params->totp_x;

   // copy interval count into data buffer
   data[0]  = (params->totp_t >> 56) & 0xff;
   data[1]  = (params->totp_t >> 48) & 0xff;
   data[2]  = (params->totp_t >> 40) & 0xff;
   data[3]  = (params->totp_t >> 32) & 0xff;
   data[4]  = (params->totp_t >> 24) & 0xff;
   data[5]  = (params->totp_t >> 16) & 0xff;
   data[6]  = (params->totp_t >>  8) & 0xff;
   data[7]  =  params->totp_t        & 0xff;

   // calculate HMAC digest
   totp_hmac((int)params->totp_algo, digest, &digest_len, data, sizeof(data), params->key, params->key_len);
   if (digest_len == 0)
      return(-1);

   // dynamically truncates hash
   offset   = digest[digest_len-1] & 0x0f;
   bin_code =  ((digest[offset+0] & 0x7f) << 24) |
               ((digest[offset+1] & 0xff) << 16) |
               ((digest[offset+2] & 0xff) <<  8) |
                (digest[offset+3] & 0xff);

   // truncates code to specific decimal digits
   for(denominator = 1, digits = (unsigned)params->otp_length; (digits > 0); digits--)
      denominator *= 10;

   otp = bin_code % denominator;

   snprintf(params->otp, sizeof(params->otp), "%0*u", (int)params->otp_length, otp);

   return(otp);
}


void
totp_hmac(
         UNUSED int                    totp_algo,
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
   if (totp_algo == RLM_TOTP_HMAC_SHA1)
   {  fr_hmac_sha1(digest, data, data_len, key, key_len);
      *digest_lenp = SHA1_DIGEST_LENGTH;
   };
#endif // !HAVE_OPENSSL_EVP_H

#ifdef HAVE_OPENSSL_EVP_H
   md_len      = RLM_TOTP_DIGEST_LENGTH;
   switch(totp_algo)
   {  case RLM_TOTP_HMAC_SHA1:   evp_md = EVP_sha1();    break;
      case RLM_TOTP_HMAC_SHA224: evp_md = EVP_sha224();  break;
      case RLM_TOTP_HMAC_SHA256: evp_md = EVP_sha256();  break;
      case RLM_TOTP_HMAC_SHA384: evp_md = EVP_sha384();  break;
      case RLM_TOTP_HMAC_SHA512: evp_md = EVP_sha512();  break;
      default: return;
   };
   hmac_result = (uint8_t *)HMAC(evp_md, key, (int)key_len, (unsigned char *)data, data_len, md, &md_len);
   memcpy(digest, hmac_result, md_len);
   *digest_lenp = md_len;
#endif // HAVE_OPENSSL_EVP_H

   return;
}


VALUE_PAIR *
totp_request_vp_by_dict(
         UNUSED void *                 instance,
         REQUEST *                     request,
         const DICT_ATTR *             da,
         int                           scope )
{
   VALUE_PAIR *            vps;

   rad_assert(instance        != NULL);
   rad_assert(request         != NULL);

   if (da == NULL)
      return(NULL);

   switch(scope)
   {  case TOTP_SCOPE_CONTROL:   vps = request->config;      break;
      case TOTP_SCOPE_REPLY:     vps = request->reply->vps;  break;
      case TOTP_SCOPE_REQUEST:   vps = request->packet->vps; break;
      default:                   vps = request->config;      break;
   };

   return(fr_pair_find_by_num(vps, da->attr, da->vendor, TAG_ANY));
}


VALUE_PAIR *
totp_request_vp_by_name(
         UNUSED void *                 instance,
         REQUEST *                     request,
         const char *                  attr_str,
         size_t                        attr_str_len,
         int                           default_scope )
{
   char                    buffer[MAX_STRING_LEN];
   char *                  attr_scope;
   char *                  attr_name;
   const DICT_ATTR *       da;

   rad_assert(instance        != NULL);
   rad_assert(request         != NULL);
   rad_assert(attr_str        != NULL);
   rad_assert(attr_str_len    < sizeof(buffer));
   rad_assert(attr_str_len    > 0);

   // initialize variables
   memcpy(buffer, attr_str, attr_str_len);
   buffer[attr_str_len] = '\0';
   attr_scope           = NULL;
   attr_name            = NULL;

   // split attribute scope and attribute name
   if ((attr_name = strchr(buffer, ':')) != NULL)
   {  attr_name[0]   = '\0';
      attr_name      = &attr_name[1];
      attr_scope     = buffer;
   };
   if (attr_name == NULL)
      attr_name = buffer;

   // retrieve dictionary entry
   da = dict_attrbyname(attr_name);
   if (da == NULL)
      return(NULL);

   // set attribute scope
   if (attr_scope != NULL)
   {  if (!(strcasecmp(attr_scope, "control")))       default_scope = TOTP_SCOPE_CONTROL;
      else if (!(strcasecmp(attr_scope, "reply")))    default_scope = TOTP_SCOPE_REPLY;
      else if (!(strcasecmp(attr_scope, "request")))  default_scope = TOTP_SCOPE_REQUEST;
      else return(NULL);
   };

   return(totp_request_vp_by_dict(instance, request, da, default_scope));
}


int
totp_set_params(
         void *                        instance,
         REQUEST *                     request,
         totp_params_t *               params )
{
   VALUE_PAIR *         vp;
   rlm_totp_code_t *    inst;
   uint64_t             totp_algo;

   rad_assert(instance  != NULL);
   rad_assert(request   != NULL);
   rad_assert(params    != NULL);

   inst = instance;

   // set initial values from module instance
   memset(params, 0, sizeof(totp_params_t));
   params->totp_t0            = inst->totp_t0;
   params->totp_x             = inst->totp_x;
   params->totp_cur_unix      = time(NULL);
   params->totp_time_offset   = inst->totp_time_offset;
   params->totp_algo          = inst->totp_algo;
   params->otp_length         = inst->otp_length;

   if (inst->allow_override == false)
      return(0);

   totp_set_params_signed(instance, request, inst->vsa_time_offset, &params->totp_time_offset);
   totp_set_params_integer(instance, request, inst->vsa_unix_time,  &params->totp_t0);
   totp_set_params_integer(instance, request, inst->vsa_time_step,  &params->totp_x);
   totp_set_params_integer(instance, request, inst->vsa_otp_length, &params->otp_length);

   if (inst->vsa_algorithm != NULL)
   {  vp = totp_request_vp_by_dict(instance, request, inst->vsa_algorithm, TOTP_SCOPE_CONTROL);
      if ( (vp != NULL) && (vp->da->type == PW_TYPE_STRING) )
      {  totp_algo = totp_algorithm_id(vp->data.strvalue);
         if (totp_algo != 0)
            params->totp_algo = totp_algo;
      };
   };

   return(0);
}


int
totp_set_params_integer(
         void *                        instance,
         REQUEST *                     request,
         const DICT_ATTR *             da,
         uint64_t *                    uintp )
{
   VALUE_PAIR *         vp;
   unsigned long long   ulongval;
   char *               endptr;

   rad_assert(instance  != NULL);
   rad_assert(request   != NULL);
   rad_assert(uintp     != NULL);

   if (da == NULL)
      return(0);

   vp = totp_request_vp_by_dict(instance, request, da, TOTP_SCOPE_CONTROL);
   if (vp == NULL)
      return(0);

   switch(vp->da->type)
   {  case PW_TYPE_INTEGER:
         *uintp = (uint64_t)vp->data.integer;
         break;

      case PW_TYPE_INTEGER64:
         *uintp = (uint64_t)vp->data.integer64;
         break;

      case PW_TYPE_SHORT:
         *uintp = (uint64_t)vp->data.ushort;
         break;

      case PW_TYPE_SIGNED:
         *uintp = (uint64_t)vp->data.sinteger;
         break;

      case PW_TYPE_STRING:
         ulongval = strtoull(vp->data.strvalue, &endptr, 10);
         if ( (vp->data.strvalue == endptr) || (endptr[0] != '\0') )
            return(-1);
         *uintp = (uint64_t)ulongval;
         break;

      default:
         return(-1);
   };

   return(0);
}


int
totp_set_params_signed(
         void *                        instance,
         REQUEST *                     request,
         const DICT_ATTR *             da,
         int64_t *                     intp )
{
   VALUE_PAIR *         vp;
   unsigned long long   longval;
   char *               endptr;

   rad_assert(instance  != NULL);
   rad_assert(request   != NULL);
   rad_assert(intp      != NULL);

   if (da == NULL)
      return(0);

   vp = totp_request_vp_by_dict(instance, request, da, TOTP_SCOPE_CONTROL);
   if (vp == NULL)
      return(0);

   switch(vp->da->type)
   {  case PW_TYPE_INTEGER:
         *intp = (int64_t)vp->data.integer;
         break;

      case PW_TYPE_INTEGER64:
         *intp = (int64_t)vp->data.integer64;
         break;

      case PW_TYPE_SHORT:
         *intp = (int64_t)vp->data.ushort;
         break;

      case PW_TYPE_SIGNED:
         *intp = (int64_t)vp->data.sinteger;
         break;

      case PW_TYPE_STRING:
         longval = strtoll(vp->data.strvalue, &endptr, 10);
         if ( (vp->data.strvalue == endptr) || (endptr[0] != '\0') )
            return(-1);
         *intp = (int64_t)longval;
         break;

      default:
         return(-1);
   };

   return(0);
}


void
totp_cache_cleanup(
         void *                        instance,
         time_t                        t )
{
   rlm_totp_code_t *       inst;
   totp_cache_entry_t *    root;

   rad_assert(instance != NULL);

   inst  = instance;
   root  = inst->cache_list;

   while( (root->next != NULL) && (root->entry_expires < t) )
      rbtree_deletebydata(inst->cache_tree, root->next);

   return;
}


int
totp_cache_entry_cmp(
         const void *                  ptr_a,
         const void *                  ptr_b )
{
   int                        rc;
   size_t                     keylen;
   const totp_cache_entry_t * entry_a;
   const totp_cache_entry_t * entry_b;

   entry_a  = *((const void * const *)ptr_a);
   entry_b  = *((const void * const *)ptr_b);
   keylen   = (entry_a->keylen < entry_b->keylen)
            ?  entry_a->keylen
            :  entry_b->keylen;

   if ((rc = memcmp(entry_a->key, entry_b->key, keylen)) != 0)
      return(rc);
   if (entry_a->keylen == entry_b->keylen)
      return(0);
   return( (entry_a->keylen < entry_b->keylen) ? -1 : 1 );
}


void
totp_cache_entry_free(
         void *                        ptr )
{
   totp_cache_entry_t *        entry;

   if (!(ptr))
      return;
   entry = ptr;

   // removes from linked list
   totp_cache_entry_unlink(entry);

   if ((entry->key))
      free(entry->key);
   free(entry);

   return;
}


VALUE_PAIR *
totp_cache_entry_key(
         void *                        instance,
         REQUEST *                     request )
{
   rlm_totp_code_t *       inst;
   VALUE_PAIR *            vp;

   rad_assert(instance != NULL);

   inst = instance;

   vp = totp_request_vp_by_dict(instance, request, inst->vsa_cache_key, TOTP_SCOPE_REQUEST);
   if (vp == NULL)
      vp = totp_request_vp_by_dict(instance, request, inst->vsa_cache_key, TOTP_SCOPE_CONTROL);
   if (vp == NULL)
      vp = totp_request_vp_by_dict(instance, request, inst->vsa_cache_key, TOTP_SCOPE_REPLY);

   return(vp);
}


void
totp_cache_entry_unlink(
         totp_cache_entry_t *          entry )
{
   if (entry->prev != NULL)
      entry->prev->next = entry->next;
   entry->prev = NULL;

   if (entry->next != NULL)
      entry->next->prev = entry->prev;
   entry->next = NULL;

   return;
}


int
totp_cache_update(
         void *                        instance,
         REQUEST *                     request,
         totp_params_t *               params )
{
   rlm_totp_code_t *       inst;
   totp_cache_entry_t *    entry;
   totp_cache_entry_t *    result;
   VALUE_PAIR *            vp;
   uint64_t                expires;

   rad_assert(instance != NULL);
   rad_assert(request  != NULL);

   inst = instance;

   expires  = params->totp_cur_unix - params->totp_t0 + params->totp_time_offset;
   expires /= params->totp_x;
   expires--;
   expires *= params->totp_x;

   pthread_mutex_lock(inst->mutex);

   totp_cache_cleanup(instance, (time_t)expires);

   vp = totp_cache_entry_key(instance, request);
   if (vp == NULL)
   {  pthread_mutex_unlock(inst->mutex);
      return(-1);
   };

   entry = totp_cache_entry_alloc(instance, vp->data.octets, vp->length, 0);
   if (entry == NULL)
   {  REDEBUG2("unable to allocate memory for totp_cache_entry_t");
      pthread_mutex_unlock(inst->mutex);
      return(-1);
   };
   entry->entry_expires = expires + params->totp_x - 1;

   // update existing entry or add new entry
   result = rbtree_finddata(inst->cache_tree, entry);
   if (result != NULL)
   {  totp_cache_entry_unlink(result);
      result->entry_expires = entry->entry_expires;
      talloc_free(entry);
      entry = result;
   } else
   {  rbtree_insert(inst->cache_tree, entry);
   };

   // add entry to linked list
   if (inst->cache_list->prev != NULL)
   {  inst->cache_list->prev->next  = entry;
      entry->prev                   = inst->cache_list->prev;
   };
   entry->next                      = inst->cache_list;
   inst->cache_list->prev           = entry;

   pthread_mutex_unlock(inst->mutex);

   return(0);
}


ssize_t
totp_xlat_code(
         UNUSED void *                 instance,
         REQUEST *                     request,
         char const *                  fmt,
         char *                        out,
         size_t                        outlen )
{
   int                     rc;
   int                     code;
   size_t                  pos;
   ssize_t                 base32_len;
   ssize_t                 key_len;
   uint8_t *               key;
   const char *            base32;
   char                    attr_str[MAX_STRING_LEN];
   VALUE_PAIR *            vp;
	rlm_totp_code_t *       inst;
   totp_params_t           params;

   rad_assert(instance != NULL);
   rad_assert(request  != NULL);
   rad_assert(fmt      != NULL);

   inst = instance;

   key      = NULL;
   key_len  = 0;

   // determine TOTP parameters
   if ((rc = totp_set_params(instance, request, &params)) != 0)
   {  *out = '\0';
      return(-1);
   };

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
      memcpy(attr_str, &base32[1], base32_len-1);
      attr_str[base32_len-1] = '\0';

      // retrieve specified value pair
      vp = totp_request_vp_by_name(instance, request, attr_str, (base32_len-1), TOTP_SCOPE_CONTROL);
      if (!(vp))
      {  REDEBUG("referenced attribute '%s' is not set", attr_str);
         *out = '\0';
         return(-1);
      };

      // check data type
      if ( (vp->da->type != PW_TYPE_STRING) && (vp->da->type != PW_TYPE_OCTETS) )
      {  REDEBUG("%s is not a string or octets", attr_str);
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

   params.key     = key;
   params.key_len = key_len;

   code = totp_calculate(&params);
   if ((inst->devel_debug))
   {  RDEBUG("rlm_totp_code: totp_algo:         %s\n",  totp_algorithm_name((int)params.totp_algo));
      RDEBUG("rlm_totp_code: totp_time:         %u\n",  (unsigned)params.totp_cur_unix);
      RDEBUG("rlm_totp_code: totp_time_offset:  %i\n",  (int)params.totp_time_offset);
      RDEBUG("rlm_totp_code: inst->totp_t0:     %u\n",  (unsigned)params.totp_t0);
      RDEBUG("rlm_totp_code: inst->totp_x:      %u\n",  (unsigned)params.totp_x);
      RDEBUG("rlm_totp_code: inst->totp_t:      %u\n",  (unsigned)params.totp_t);
      RDEBUG("rlm_totp_code: key:               <binary>\n");
      RDEBUG("rlm_totp_code: key_len:           %u\n",  (unsigned)params.key_len);
      RDEBUG("rlm_totp_code: result:            %s\n",  params.otp);
      RDEBUG("rlm_totp_code: result_len:        %u\n",  (unsigned)params.otp_length);
   };
   if (code < 0)
   {  *out = '\0';
      return(-1);
   };

   if ((size_t)snprintf(out, outlen, "%s" , params.otp) >= outlen)
   {  REDEBUG("Insufficient space to write TOTP code");
      *out = '\0';
      return(-1);
   };

   return(0);
}


/* end of source */
