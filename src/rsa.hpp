#ifndef HEADER_RSA
#define HEADER_RSA

#include "bigint.hpp"
#include "types.hpp"
#include "blob.hpp"

#include "rsa_rng_helper.hpp"

/**
	\brief Class to work with RSA
 */
class CRSA{
	BigInt::CBigInt e,d,n;

	//Internal methods
	Blob (*pfnGenRandomBytes)(TYPE_DWORD amountOfBytes);
	bool CRSA::encryptDecrypt(const BigInt::CBigInt& tPar, const BigInt::CBigInt& ePar, const BigInt::CBigInt& nPar, BigInt::CBigInt& result);

public:
	bool CRSA::encrypt(const BigInt::CBigInt& m, BigInt::CBigInt& result);
	bool CRSA::decrypt(const BigInt::CBigInt& c, BigInt::CBigInt& result);

	bool CRSA::linkRNGStuff(Blob(*pfnGenRandomBytesPar)(TYPE_DWORD amountOfBytes));

	bool CRSA::genKeys(unsigned keyLength);

	//key data import/export stuff
	bool CRSA::importPublicKey(const BigInt::CBigInt& ePar, const BigInt::CBigInt& nPar);
	bool CRSA::importPrivateKey(const BigInt::CBigInt& dPar, const BigInt::CBigInt& nPar);
	bool CRSA::importKeys(const BigInt::CBigInt& ePar, const BigInt::CBigInt& dPar, const BigInt::CBigInt& nPar);
	bool CRSA::exportPublicKey(BigInt::CBigInt& ePar, BigInt::CBigInt& nPar);
	bool CRSA::exportPrivateKey(BigInt::CBigInt& dPar, BigInt::CBigInt& nPar);
	bool CRSA::exportKeys(BigInt::CBigInt& ePar, BigInt::CBigInt& dPar, BigInt::CBigInt& nPar);
};

bool checkIfPrime(const BigInt::CBigInt& n, Blob (*pfnGenRandomBytesPar)(TYPE_DWORD amountOfBytes));
BigInt::CBigInt genPrimeNumber(unsigned numberLength, Blob (*pfnGenRandomBytes)(unsigned));
BigInt::CBigInt getIntFromBuffer(TYPE_BYTE* pBuffer, TYPE_SIZE bufferSize);

inline TYPE_SIZE getDigitsAmount(const BigInt::CBigInt& n){
	return n.storage.size();
}
#endif
