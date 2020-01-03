#ifndef HEADER_RSA_RNG_HELPER
#define HEADER_RSA_RNG_HELPER

#include "module_crypto.hpp"

class CRSARNGHelper{
	static CRNG* pRNG;
public:
	static void initRNG(CRNG& rng){
		pRNG = &rng;
	}

	static Blob genRandomBytes(TYPE_DWORD amountOfBytes){
		Blob resultBlob(amountOfBytes);
		pRNG->gen(SWeakBlob(&resultBlob[0], amountOfBytes));
		return resultBlob;
	}
};

#endif