#ifndef HEADER_CRYPTO
#define HEADER_CRYPTO

#include <memory>

#include "types.hpp"
#include "blob.hpp"

#include <cstdlib>
#include <ctime>

//CRNG must output random number of any length
class CRNG{
	SecureBlob seedBlob;
public:
	CRNG(const SWeakBlob& seedBlobPar = SWeakBlob()){
		this->seedBlob.reset(seedBlobPar);
	}

	bool resetSeed(const SWeakBlob& seedBlobPar){
		this->seedBlob.reset(seedBlobPar);
		return true;
	}

	//default RNG algorythm - linear kongruent generator
	virtual bool gen(SWeakBlob& blobPar){
		std::srand(std::time(0));
		auto fullRounds = blobPar.size / sizeof(int);
		TYPE_SIZE i = 0;
		for (; i < fullRounds; ++i){
			auto randBlock = rand();
			//save int
			for (TYPE_SIZE j = 0; j < sizeof(int); ++j){
				*(blobPar.p + i*sizeof(int)+j) = *((TYPE_BYTE*)&randBlock + j);
			}
		}
		//save remainder
		auto remainder = blobPar.size % sizeof(int);
		auto randBlock = rand();
		for (TYPE_SIZE j = 0; j < remainder; ++j){
			*(blobPar.p + i*sizeof(int)+j) = *((TYPE_BYTE*)&randBlock + j);
		}
		return true;
	}

	bool gen(TYPE_BYTE* p, TYPE_SIZE size){
		return this->gen(SWeakBlob(p, size));
	}

	bool genSecure(TYPE_SIZE keyLength, SecureBlob& resultSecureBlob){
		SWeakBlob wb;
		resultSecureBlob.data->resize(keyLength*sizeof(TYPE_BYTE));
		this->gen(&resultSecureBlob.data->operator[](0), resultSecureBlob.data->size());
		return true;
	}

	virtual bool resetState(){
		return true;
	}

	~CRNG() = default;
};

//functor can be used here
class CGenRandomBytes{
	bool(*pfnGen)(const SWeakBlob& wb);
public:
	CGenRandomBytes(bool(*pfnGenPar)(const SWeakBlob& wb)) :pfnGen(pfnGenPar){}

	Blob operator()(TYPE_SIZE amountOfBytes){
		Blob randomBytesBlob(amountOfBytes);
		SWeakBlob wb(&randomBytesBlob[0], randomBytesBlob.size());
		this->pfnGen(wb);
		return randomBytesBlob;
	}
};

//how to access key data? Friend classes
/** Replaced by SecureBlob in blob.hpp
class CKey{

protected:
friend class CCryptorIface;

std::shared_ptr<SBlob> keyBlob;

public:
CKey() = default;

//SBlob must be aggregate type or have appropriate constructor
CKey(SBlob& keyBlobPar): keyBlob(new SBlob{keyBlobPar.pBuffer, keyBlobPar.size},clearBlob){
//clear input keyBlob
keyBlobPar.pBuffer = nullptr;
keyBlobPar.size = 0;
}

CKey(const CKey& o) :keyBlob(o.keyBlob){}

CKey& operator=(const CKey& o){
this->keyBlob = o.keyBlob;
}

void resetKey(SBlob& keyBlobPar){
this->keyBlob.reset(new SBlob{ keyBlobPar.pBuffer, keyBlobPar.size }, clearBlob);
//clear input keyBlob
keyBlobPar.pBuffer = nullptr;
keyBlobPar.size = 0;
}
};
*/

class CCryptorIface{
protected:
	SecureBlob key;
	//bufferBlob and resultBufferBlob can be same blob
	virtual bool encrypt(const SWeakBlob& bufferBlob, const SWeakBlob& resultBufferBlob) = 0;
	virtual bool decrypt(const SWeakBlob& bufferBlob, const SWeakBlob& resultBufferBlob) = 0;

	//!!! ALERT !!! CLEAR OUTPUT BLOB !!! ALERT !!!
	//!!! ALERT !!! CLEAR OUTPUT BLOB !!! ALERT !!!
	//!!! ALERT !!! CLEAR OUTPUT BLOB !!! ALERT !!!
	bool getSecureBlobData(const SecureBlob& secureBLob, SWeakBlob& blobPar){
		blobPar.reset(&secureBLob.data->operator[](0), secureBLob.data->size());
		return true;
	}

public:
	CCryptorIface() = default;

	//!!! ALERT !!! CLEAR OUTPUT BLOB !!! ALERT !!!
	//!!! ALERT !!! CLEAR OUTPUT BLOB !!! ALERT !!!
	//!!! ALERT !!! CLEAR OUTPUT BLOB !!! ALERT !!!
	CCryptorIface(const SWeakBlob& keyBlobPar) :key(keyBlobPar){}

	CCryptorIface(const SecureBlob& keyBlobPar) :key(keyBlobPar){}

	/*
	bool genKey(TYPE_SIZE keyKength, CRNG* pRNG = nullptr, SBlob* pSeedBlob = nullptr){
	if (pRNG == nullptr){
	PRINT_DEBUG("Error: RNG not initialized")
	return false;
	}

	//CRNG
	SBlob keyBlob;
	keyBlob.pBuffer = new TYPE_BYTE[keyKength];
	keyBlob.size = keyKength;
	//gen key
	if (pSeedBlob){
	pRNG->reset(pSeedBlob);
	}
	pRNG->gen(keyBlob, pSeedBlob);
	//set key
	this->key->resetKey(keyBlob);
	clearBlob(&keyBlob);
	}
	*/

	void resetKey(const SWeakBlob& keyBlob){
		this->key.reset(keyBlob);
	}

	void resetKey(const SecureBlob& keyBlobPar){
		this->key = keyBlobPar;
	}

	void getKeyLength(TYPE_SIZE& keyLength){
		keyLength = this->key.data->size();
	}

	bool encryptBuffer(const SWeakBlob& bufferBlob){
		return this->encrypt(bufferBlob, bufferBlob);
	}

	bool decryptBuffer(const SWeakBlob& bufferBlob){
		return this->decrypt(bufferBlob, bufferBlob);
	}

	/*
	Some encryption modes like CBC mode require resetting
	*/
	virtual bool resetState(){
		return true;
	}
};

#endif
