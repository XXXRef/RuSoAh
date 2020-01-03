#include "rsa.hpp"
#include "types.hpp"

//====================================================================================================
//crypto
 bool CRSA::encryptDecrypt(const BigInt::CBigInt& tPar, const BigInt::CBigInt& ePar, const BigInt::CBigInt& nPar, BigInt::CBigInt& result){
	 result = BigInt::powMod(tPar,ePar,nPar);
	 return true;
}

//====================================================================================================
bool CRSA::encrypt(const BigInt::CBigInt& m, BigInt::CBigInt& result){
		//call encryptDecrypt
		return encryptDecrypt(m,this->e,this->n,result);
}

//====================================================================================================
bool CRSA::decrypt(const BigInt::CBigInt& c, BigInt::CBigInt& result){
	//call encryptDecrypt
	return encryptDecrypt(c, this->d, this->n, result);
}

//importing-exporting
//====================================================================================================
bool CRSA::importPublicKey(const BigInt::CBigInt& ePar, const BigInt::CBigInt& nPar){
		this->e=ePar;
		this->n=nPar;
		return true;
}

//====================================================================================================
bool CRSA::importPrivateKey(const BigInt::CBigInt& dPar, const BigInt::CBigInt& nPar){
		this->d = dPar;
		this->n = nPar;
		return true;
}

//====================================================================================================
bool CRSA::importKeys(const BigInt::CBigInt& ePar, const BigInt::CBigInt& dPar, const BigInt::CBigInt& nPar){
		this->e = ePar;
		this->d = dPar;
		this->n = nPar;
		return true;
}

//====================================================================================================
bool CRSA::exportPublicKey(BigInt::CBigInt& ePar, BigInt::CBigInt& nPar){
		ePar=this->e;
		nPar=this->n;
		return true;
}

//====================================================================================================
bool CRSA::exportPrivateKey(BigInt::CBigInt& dPar, BigInt::CBigInt& nPar){
		dPar = this->d;
		nPar = this->n;
		return true;
}

//====================================================================================================
bool CRSA::exportKeys(BigInt::CBigInt& ePar, BigInt::CBigInt& dPar, BigInt::CBigInt& nPar){
		ePar = this->e;
		dPar = this->d;
		nPar = this->n;
		return true;
}

//====================================================================================================
//init RNG
bool CRSA::linkRNGStuff(Blob(*pfnGenRandomBytesPar)(TYPE_DWORD amountOfBytes)){
	this->pfnGenRandomBytes = pfnGenRandomBytesPar;
	return true;
}

//RSA stuff
//====================================================================================================
bool CRSA::genKeys(unsigned keyLength){//key length in bytes
		//need usage of RNG callback
	/*
	BigInt::CBigInt p = CRSA::genPrimeNumber(keyLength/2);
	BigInt::CBigInt q = CRSA::genPrimeNumber(keyLength / 2);
	*/
	BigInt::CBigInt p = genPrimeNumber(keyLength / 2 - 1, this->pfnGenRandomBytes);
	BigInt::CBigInt q = genPrimeNumber(keyLength / 2 + 1, this->pfnGenRandomBytes);

	this->n=p*q;
	BigInt::CBigInt eulerFunctionValue = (p - BigInt::CBigInt("1"))*(q - BigInt::CBigInt("1"));
	this->e=BigInt::CBigInt("65537");
	//calculate d
	BigInt::CBigInt cryptoOven;
	getDiophantParams(this->e,eulerFunctionValue,this->d,cryptoOven);
	//if d<0
	if (this->d < BigInt::CBigInt()){
		this->d=eulerFunctionValue+this->d;
	}
	return true;
}

//====================================================================================================
/**
	Checks if number is prime by Miller-Rabin test
 */
bool checkIfPrime(const BigInt::CBigInt& n, Blob(*pfnGenRandomBytesPar)(TYPE_DWORD amountOfBytes)){
	//Check trivial cases
	if (n < BigInt::CBigInt("4") ){
		return true;
	}
	if (!n.isOdd()){
		return false;
	}
	
	//Calculate s,d
	//n-1=(2^s)*d
	BigInt::CBigInt s;
	BigInt::CBigInt d=n-BigInt::CBigInt("1");
	while (true){
		if (d.isOdd()){
			break;
		}
		d /= BigInt::CBigInt("2");
		++s;
	}

	TYPE_DWORD sourceDigitsAmount = n.storage.size();
//Determine amount of rounds
	//log2(x)=log2(10)*log10(x), log10(x)=<amount of digits in number>, log2(10)=3.321928094
	//TYPE_DWORD amountOfRounds = (3.321928094*(double)sourceDigitsAmount) + 1; // adding 1 to round double towards bigger natural number
	TYPE_DWORD amountOfRounds = 10;
//Main loop
	TYPE_DWORD i=0;
	while (i!=amountOfRounds){
	//Gen (a in (1,n))
		Blob randomBuffer = pfnGenRandomBytesPar(sizeof(TYPE_DWORD));
		//TYPE_DWORD witnessDigitsAmount=*((TYPE_DWORD*)&randomBuffer[0]) % (sourceDigitsAmount - 1);
		TYPE_DWORD witnessDigitsAmount = *((TYPE_DWORD*)&randomBuffer[0]) % (100000);
		witnessDigitsAmount/=3; // assume that 1 byte ~ 3 digits in integer
		if (!witnessDigitsAmount){
			witnessDigitsAmount=1;
		}
		randomBuffer = pfnGenRandomBytesPar(witnessDigitsAmount);
		if (witnessDigitsAmount != 1){
			randomBuffer[0] |= 0x80;
		}
		BigInt::CBigInt a = getIntFromBuffer(&randomBuffer[0], randomBuffer.size());
		if (a < BigInt::CBigInt("2")){
			continue;
		}

	//Check a^d=1(mod p)
		BigInt::CBigInt x = BigInt::powMod(a,d,n);
		if (x == BigInt::CBigInt("1") || x == n - BigInt::CBigInt("1")){
			//current a - primality witness; go to next round
			++i;
			continue;
		}
		
	//Check a^(2^r*d)=1(mod p)
		BigInt::CBigInt counter;
		--s;
		while (counter != s){
			x = BigInt::powMod(x, BigInt::CBigInt("2"),n);
			if (x == BigInt::CBigInt("1")){
				return false;
			}
			if (x == n-BigInt::CBigInt("1")){
				++i;
				continue;
			}
			++counter;
		}
		return false;
	}
	return true;
}

//====================================================================================================
BigInt::CBigInt genPrimeNumber(unsigned numberLength, Blob(*pfnGenRandomBytes)(TYPE_DWORD)){
//1. Gen random number
	//WARNING:
	//Its assumed that ovenBuffer is dynamically allocated in pfnGenRandomBytes
	//Also its necessary to safely delete buffer from random data after usage
	Blob ovenBuffer=pfnGenRandomBytes(numberLength);
	ovenBuffer[0]|=0x80;
	BigInt::CBigInt ovenInt = getIntFromBuffer(&ovenBuffer[0],numberLength);

//2. Make odd number
	if (!ovenInt.isOdd()){
		++ovenInt;
		/*
		WARNING:
		ovenInt may become bigger/smaller than desired number size bytes, if it happens we could gen another random number with length of number size in bytes
		*/
	}
//3. Gen prime number
	while (!checkIfPrime(ovenInt, pfnGenRandomBytes)){
		ovenInt += BigInt::CBigInt("2");
	}
	return ovenInt;
}

//====================================================================================================
BigInt::CBigInt getIntFromBuffer(TYPE_BYTE* pBuffer, TYPE_SIZE bufferSize){
	BigInt::CBigInt result;
	auto counter = bufferSize;
	BigInt::CBigInt power("1");
	while (counter!=0){
		--counter;
		TYPE_BYTE currentByte = pBuffer[counter];
		result += BigInt::CBigInt(std::string(1,(currentByte%16+'0')))*power;
		power *= BigInt::CBigInt("16");
		result += BigInt::CBigInt(std::string(1, (currentByte / 16 + '0')))*power;
		power *= BigInt::CBigInt("16");
	}
	return result;
}