#ifndef HEADER_CRYPTO_RNG_WINDOWS
#define HEADER_CRYPTO_RNG_WINDOWS

#include "blob.hpp"
#include "module_crypto.hpp"
#include <windows.h>
#include <wincrypt.h>

//!! WARNING !!		Advapi32.lib must be linked		!! WARNING !!

class CRNGCryptoAPI : public CRNG{
	HCRYPTPROV hCryptProvider;
public:
	CRNGCryptoAPI() :CRNG(){
		int result = CryptAcquireContext(&this->hCryptProvider, NULL, NULL, PROV_RSA_FULL, NULL);
	}

	bool gen(const SWeakBlob& blob){
		bool result = (CryptGenRandom(hCryptProvider, blob.size, blob.p) == TRUE) ? true : false;
	}

	~CRNGCryptoAPI(){
		if (this->hCryptProvider){
			CryptReleaseContext(this->hCryptProvider, 0);
		}
	}
};

#endif