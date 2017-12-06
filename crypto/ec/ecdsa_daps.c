/*
 * Copyright (c) 2017 Graz University of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the ""Software""), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <openssl/ec.h>
#include <openssl/sha.h>
#include "daps.h"
#include <openssl/err.h>
#include <stdio.h>


DAPS_KEY* ecdsa_daps_key_new(int ecdsa_curve, int n) {
  if (n < 1) {
    return NULL;
  }

  DAPS_KEY* key = calloc(1, sizeof(*key));
  if (!key) {
    return NULL;
  }

  key->n = n;
  key->ecdsa_key = EC_KEY_new_by_curve_name(ecdsa_curve);
  if (!key->ecdsa_key) {
    goto err;
  }

  const EC_GROUP* group = EC_KEY_get0_group(key->ecdsa_key);

  key->h = EC_POINT_new(group);
  key->addresses = calloc(n, sizeof(address_encryption_t));
  if (!key->h || !key->addresses) {
    goto err;
  }

  for (int i = 0; i < n; ++i) {
    key->addresses[i].r = BN_new();
    key->addresses[i].rho = BN_new();
    key->addresses[i].C_1 = EC_POINT_new(group);
    key->addresses[i].C_2 = EC_POINT_new(group);

    if (!key->addresses[i].r || !key->addresses[i].rho || !key->addresses[i].C_1 || !key->addresses[i].C_2) {
      goto err;
    }
  }

  return key;

err:
  ecdsa_daps_key_free(key);

  return NULL;
}

void ecdsa_daps_key_free(DAPS_KEY* key) {
  if (!key) {
    return;
  }

  for (int i = 0; i < key->n && key->addresses; ++i) {
    EC_POINT_free(key->addresses[i].C_2);
    EC_POINT_free(key->addresses[i].C_1);
    BN_free(key->addresses[i].rho);
    BN_free(key->addresses[i].r);
  }

  free(key->addresses);
  EC_POINT_free(key->h);
  EC_KEY_free(key->ecdsa_key);
  free(key);
}

int ecdsa_daps_key_gen(DAPS_KEY* key) {
  BIGNUM* t = BN_new();
  if (!t) {
    goto err;
  }

  EC_KEY_precompute_mult(key->ecdsa_key, NULL);
  if (!ossl_ec_key_gen(key->ecdsa_key)) {
    goto err;
  }

  const EC_GROUP* group = EC_KEY_get0_group(key->ecdsa_key);
  const BIGNUM* order = EC_GROUP_get0_order(group);
  if (!BN_rand_range(t, order)) {
    goto err;
  }
  if (!EC_POINT_mul(group, key->h, t, NULL, NULL, NULL)) {
    goto err;
  }

  for (int i = 0; i < key->n; ++i) {
    if (!BN_rand_range(key->addresses[i].r, order) ||
        !BN_rand_range(key->addresses[i].rho, order)) {
      goto err;
    }

    if (!EC_POINT_mul(group, key->addresses[i].C_1, key->addresses[i].r, NULL, NULL, NULL) ||
        !EC_POINT_mul(group, key->addresses[i].C_2, key->addresses[i].rho, key->h, key->addresses[i].r, NULL)) {
      goto err;
    }
  }

  return 1;

err:
  return 0;
}

static int hash_message(unsigned char* digest, const unsigned char* address, unsigned int alen, const unsigned char* payload, unsigned int plen) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, "H2", 2);
  SHA256_Update(&ctx, address, alen);
  SHA256_Update(&ctx, payload, plen);
  SHA256_Final(digest, &ctx);
  return 1;
}

DAPS_SIG* DAPS_SIG_new(void) {
  DAPS_SIG* ret = calloc(1, sizeof(*ret));

  ret->z = BN_new();
  ret->pi.c = BN_new();
  ret->pi.s = BN_new();

  return ret;
}

void DAPS_SIG_free(DAPS_SIG* sig) {
  if (!sig) {
    return;
  }

  ECDSA_SIG_free(sig->ecdsa_sig);
  BN_free(sig->z);
  BN_free(sig->pi.s);
  BN_free(sig->pi.c);
  free(sig);
}

static void hash_EC_POINT(SHA256_CTX* ctx, const EC_GROUP* group, const EC_POINT* p, BN_CTX* bn_ctx) {
  const size_t len = EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bn_ctx);
  unsigned char buffer[len];
  EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED, buffer, len, bn_ctx);
  SHA256_Update(ctx, buffer, len);
}

static int eq_challenge(BIGNUM* c, EC_POINT* g1, EC_POINT* g2, EC_POINT* r1, EC_POINT* r2, EC_POINT* u1, EC_POINT* u2, const EC_GROUP* group, BN_CTX* bn_ctx)
{
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, "EQ", 2);

  size_t s = 4;
  EC_POINT* points[] = { r1, r2, u1, u2, NULL, NULL };
  if (g1 != NULL) {
    points[s++] = g1;
  }
  if (g2 != NULL) {
    points[s++] = g2;
  }
  EC_POINTs_make_affine(group, s, points, bn_ctx);

  // statement
  if (g1 != NULL) {
    hash_EC_POINT(&ctx, group, g1, bn_ctx);
  } else {
    SHA256_Update(&ctx, "g1", 2);
  }
  if (g2 != NULL) {
    hash_EC_POINT(&ctx, group, g2, bn_ctx);
  } else {
    SHA256_Update(&ctx, "g2", 2);
  }
  hash_EC_POINT(&ctx, group, u1, bn_ctx);
  hash_EC_POINT(&ctx, group, u2, bn_ctx);

  // commitment
  hash_EC_POINT(&ctx, group, r1, bn_ctx);
  hash_EC_POINT(&ctx, group, r2, bn_ctx);

  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256_Final(digest, &ctx);
  BN_bin2bn(digest, sizeof(digest), c);

  return 1;
}

static int eq_proof(equality_proof_t* pi, const BIGNUM* k, EC_POINT* g1, EC_POINT* u1, EC_POINT* g2, EC_POINT* u2, const EC_GROUP* group, BN_CTX* bn_ctx) {
  const BIGNUM* order = EC_GROUP_get0_order(group);
  int ok = 0;

  EC_POINT* r1 = NULL;
  EC_POINT* r2 = NULL;

  BIGNUM* r = BN_new();
  BIGNUM* t = BN_new();
  r1 = EC_POINT_new(group);
  r2 = EC_POINT_new(group);

  if (!r || !t || !r1 || !r2) {
    goto clean;
  }

  // r_i \gets g_i^r
  if (!BN_rand_range(r, order)) {
    goto clean;
  }
  if (g1 == NULL) {
    if (!EC_POINT_mul(group, r1, r, NULL, NULL, bn_ctx)) {
      goto clean;
    }
  } else {
    if (!EC_POINT_mul(group, r1, NULL, g1, r, bn_ctx)) {
      goto clean;
    }
  }
  if (!EC_POINT_mul(group, r2, NULL, g2, r, bn_ctx)) {
    goto clean;
  }

  if (!eq_challenge(pi->c, g1, g2, r1, r2, u1, u2, group, bn_ctx)) {
    goto clean;
  }

  // s \gets r - c*k
  if (!BN_mod_mul(t, pi->c, k, order, bn_ctx)) {
    goto clean;
  }
  if (!BN_mod_sub(pi->s, r, t, order, bn_ctx)) {
    goto clean;
  }

  ok = 1;

clean:
  EC_POINT_free(r2);
  EC_POINT_free(r1);

  BN_free(t);
  BN_free(r);

  return ok;
}

static int eq_verify(const equality_proof_t* pi, EC_POINT* g1, EC_POINT* u1, EC_POINT* g2, EC_POINT* u2, const EC_GROUP* group, BN_CTX* bn_ctx) {
  const EC_POINT* points1[] = { u1, g1 };
  const EC_POINT* points2[] = { u2, g2 };
  const BIGNUM* coeffs[] = { pi->c, pi->s };

  int ok = 0;

  EC_POINT* r1 = NULL;
  EC_POINT* r2 = NULL;

  BIGNUM* t = BN_new();
  r1 = EC_POINT_new(group);
  r2 = EC_POINT_new(group);

  if (!t || !r1 || !r2) {
    goto clean;
  }

  if (g1 == NULL) {
    if (!EC_POINT_mul(group, r1, pi->s, u1, pi->c, bn_ctx)) {
      goto clean;
    }
  } else {
    if (!EC_POINTs_mul(group, r1, NULL, 2, points1, coeffs, bn_ctx)) {
      goto clean;
    }
  }
  if (!EC_POINTs_mul(group, r2, NULL, 2, points2, coeffs, bn_ctx)) {
    goto clean;
  }

  if (!eq_challenge(t, g1, g2, r1, r2, u1, u2, group, bn_ctx)) {
    goto clean;
  }

  ok = BN_cmp(pi->c, t) == 0 ? 1 : 0;

clean:
  EC_POINT_free(r2);
  EC_POINT_free(r1);
  BN_free(t);

  return ok;
}

DAPS_SIG* ecdsa_daps_do_sign(int a, const unsigned char* payload, unsigned int plen, DAPS_KEY *dapskey) {
  BIGNUM* m = NULL;
  BIGNUM* t = NULL;
  BIGNUM* minv = NULL;
  BIGNUM* zminus = NULL;
  BN_CTX* bn_ctx = NULL;
  EC_POINT* C_2 = NULL;

  if (a < 0 || a >= dapskey->n) {
    return NULL;
  }

  DAPS_SIG* ret = DAPS_SIG_new();
  if (!ret) {
    return NULL;
  }

  const EC_GROUP* group = EC_KEY_get0_group(dapskey->ecdsa_key);
  const BIGNUM* order = EC_GROUP_get0_order(group);
  const BIGNUM* ecdsa_key = EC_KEY_get0_private_key(dapskey->ecdsa_key);

  unsigned char digest[SHA256_DIGEST_LENGTH];

  m = BN_new();
  t = BN_new();
  minv = BN_new();
  zminus = BN_new();

  bn_ctx = BN_CTX_new();
  C_2 = EC_POINT_new(group);
  if (!m || !t || !minv || !zminus || !C_2 || !bn_ctx) {
    goto clean;
  }

  if (!hash_message(digest, (const unsigned char*)&a, sizeof(a), payload, plen)) {
    goto clean;
  }

  BN_bin2bn(digest, sizeof(digest), m);

  // z = rho * m + x
  if (!BN_mod_mul(t, dapskey->addresses[a].rho, m, order, bn_ctx) ||
      !BN_mod_add(ret->z, t, ecdsa_key, order, bn_ctx)) {
    goto clean;
  }

  if (!BN_mod_inverse(minv, m, order, bn_ctx) ||
      !BN_mod_mul(t, ret->z, minv, order, bn_ctx) ||
      !BN_mod_sub(zminus, order, t, order, bn_ctx)) {
    goto clean;
  }

  // C' = C_2 * (pk_\Sigma * g^{-z})^{1/m}
  if (!EC_POINT_mul(group, C_2, zminus, EC_KEY_get0_public_key(dapskey->ecdsa_key), minv, bn_ctx) ||
      !EC_POINT_add(group, C_2, C_2, dapskey->addresses[a].C_2, bn_ctx)) {
    goto clean;
  }

  // compute EQ proof
  if (!eq_proof(&ret->pi, dapskey->addresses[a].r, NULL, dapskey->addresses[a].C_1, dapskey->h, C_2, group, bn_ctx)) {
    goto clean;
  }

  // compute ECDSA signature
  ret->ecdsa_sig = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, dapskey->ecdsa_key);

clean:
  EC_POINT_free(C_2);
  BN_CTX_free(bn_ctx);
  BN_free(zminus);
  BN_free(minv);
  BN_free(t);
  BN_free(m);

  if (!ret->ecdsa_sig) {
    DAPS_SIG_free(ret);
    ret = NULL;
  }

  return ret;
}

int ecdsa_daps_do_verify(int a, const unsigned char* payload, unsigned int plen, DAPS_KEY *dapskey, DAPS_SIG* sig) {
  BIGNUM* m = NULL;
  BIGNUM* t = NULL;
  BIGNUM* minv = NULL;
  BIGNUM* zminus = NULL;
  BN_CTX* bn_ctx = NULL;
  EC_POINT* C_2 = NULL;
  int ok = 0;

  if (a < 0 || a >= dapskey->n) {
    return 0;
  }

  const EC_GROUP* group = EC_KEY_get0_group(dapskey->ecdsa_key);
  const BIGNUM* order = EC_GROUP_get0_order(group);

  unsigned char digest[SHA256_DIGEST_LENGTH];

  m = BN_new();
  t = BN_new();
  minv = BN_new();
  zminus = BN_new();

  bn_ctx = BN_CTX_new();
  C_2 = EC_POINT_new(group);
  if (!m || !t || !minv || !zminus || !C_2 || !bn_ctx) {
    goto clean;
  }

  if (!hash_message(digest, (const unsigned char*)&a, sizeof(a), payload, plen)) {
    goto clean;
  }
  BN_bin2bn(digest, sizeof(digest), m);

  if (!BN_mod_inverse(minv, m, order, bn_ctx) ||
      !BN_mod_mul(t, sig->z, minv, order, bn_ctx) ||
      !BN_mod_sub(zminus, order, t, order, bn_ctx)) {
    goto clean;
  }

  // C' = C_2 * (pk_\Sigma * g^{-z})^{1/m}
  if (!EC_POINT_mul(group, C_2, zminus, EC_KEY_get0_public_key(dapskey->ecdsa_key), minv, bn_ctx) ||
      !EC_POINT_add(group, C_2, C_2, dapskey->addresses[a].C_2, bn_ctx)) {
    goto clean;
  }

  if (!ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, sig->ecdsa_sig, dapskey->ecdsa_key)) {
    printf("ecdsa!\n");
    goto clean;
  }


  if (!eq_verify(&sig->pi, NULL, dapskey->addresses[a].C_1, dapskey->h, C_2, group, bn_ctx)) {
    printf("eq!\n");
    goto clean;
  }

  ok = 1;

clean:
  EC_POINT_free(C_2);
  BN_CTX_free(bn_ctx);
  BN_free(zminus);
  BN_free(minv);
  BN_free(t);
  BN_free(m);

  return ok;
}
