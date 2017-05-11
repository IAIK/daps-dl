#ifndef CRYPTO_EC_DAPS_H
#define CRYPTO_EC_DAPS_H

#include "ec_lcl.h"

typedef struct equality_proof_st {
  BIGNUM* c;
  BIGNUM* s;
} equality_proof_t;

typedef struct address_encryption_st {
  BIGNUM* r;
  BIGNUM* rho;
  EC_POINT* C_1;
  EC_POINT* C_2;
} address_encryption_t;

struct daps_key_st {
  EC_KEY* ecdsa_key;
  EC_POINT* h;
  address_encryption_t* addresses;
  int n;
};

struct daps_sig_st {
  ECDSA_SIG* ecdsa_sig;

  BIGNUM* z;
  equality_proof_t pi;
};

#endif
