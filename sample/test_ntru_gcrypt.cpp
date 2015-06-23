/* test_ntru_gcrypt.cpp
 * Copyright (C) 2015, Security Innovation.
 * Author Zhenfei Zhang <zzhang@securityinnovation.com>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* This code is an example of using libgcrypt instantiated with NTRUEncrypt
 * For the latest version of the NTRUEncrypt specs, visit
 *  https://github.com/NTRUOpenSourceProject/NTRUEncrypt
 */

#include <iostream>
#include <gcrypt.h>

using namespace std;

#ifndef _MAX_NTRU_BUF_SIZE_
#define _MAX_NTRU_BUF_SIZE_ 4000
#endif

#define DEBUG

/* Dumps a buffer in hex to the screen for debugging */

void gcrypt_init();

int main() {

    gcrypt_init();
    gcry_error_t err = 0;
    gcry_sexp_t ntru_parms;
    gcry_sexp_t ntru_keypair;
    gcry_sexp_t data;
    gcry_sexp_t cipher;

    /*
     * Check if NTRU is avaliable
     */
    err = gcry_pk_test_algo (GCRY_PK_NTRU);
    if (err)
        cerr<<"NTRUEncrypt is not supported: "<<err<<endl;

    /*
     * initialization
     * (genkey(ntru(b256))), (genkey(ntru(n743))) = 256 bits security with dimension 743
     * (genkey(ntru(b192))), (genkey(ntru(n593))) = 192 bits security with dimension 593
     * (genkey(ntru(b128))), (genkey(ntru(n439))) = 128 bits security with dimension 439
     *
     */
    err = gcry_sexp_build(&ntru_parms, NULL, "(genkey(ntru(b128)))");

    /*
     * start key generation
     */
    err = gcry_pk_genkey(&ntru_keypair, ntru_parms);

    /*
     * parse key pair into pubk and privk
     */
    gcry_sexp_t pubk = gcry_sexp_find_token(ntru_keypair, "public-key", 0);
    gcry_sexp_t privk = gcry_sexp_find_token(ntru_keypair, "private-key", 0);

#ifdef  DEBUG
    /*
     * dump public key and private key
     */
    cerr<<"error in key gen ?: "<<err<<endl;
    gcry_sexp_dump (pubk);
    gcry_sexp_dump (privk);
#endif

    const unsigned char* msg = (const unsigned char*) "Hello SI. Let's encrypt";
    err =   gcry_sexp_build(&data, NULL, "(data (flags raw) (value %s))", msg);
    err +=  gcry_pk_encrypt(&cipher, data, pubk);

#ifdef  DEBUG
    /*
     * dump message and cipher
     */
    cerr<<"error in encryption? : "<<err<<endl;
    gcry_sexp_dump (data);
    gcry_sexp_dump (cipher);
#endif

    err = gcry_pk_decrypt(&data, cipher, privk);

#ifdef  DEBUG
    /*
     * dump recovered message
     */
    cerr<<"error in decryption? : "<<err<<endl;
    gcry_sexp_dump (data);
#endif

	cout << "Hello SI" << endl; // prints Hello SI

	return 0;
}

void gcrypt_init()
{
    /* Version check should be the very first call because it
       makes sure that important subsystems are intialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        cout<<GCRYPT_VERSION<<endl;
        printf("gcrypt: library version mismatch\n");
    }

    gcry_error_t err = 0;

    /* We don't want to see any warnings, e.g. because we have not yet
       parsed program options which might be used to suppress such
       warnings. */
    err = gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
       process might still be running with increased privileges and that
       the secure memory has not been intialized.  */

    /* Allocate a pool of 16k secure memory.  This make the secure memory
       available and also drops privileges where needed.  */
    err |= gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
       a problem with the secure memory. */
    err |= gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    err |= gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (err) {
        printf("gcrypt: failed initialization");
    }
}
