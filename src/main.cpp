#include <iostream>

#include "rsa.hpp"
#include "module_crypto_rng_cryptoapi.hpp"

CRNG* CRSARNGHelper::pRNG;

int main(){
	CRSA rsa;
	CRNGCryptoAPI rng;
	CRSARNGHelper::initRNG(rng);
	rsa.linkRNGStuff(CRSARNGHelper::genRandomBytes);

	std::cout << "Generating keys..." << std::endl;
	rsa.genKeys(8);
	std::cout << "Keys generated" << std::endl;

	system("pause");
	return 0;
}