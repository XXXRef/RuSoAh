#ifndef HEADER_BLOB //Fuck pragma ;)
#define HEADER_BLOB

#include <cstring>
#include <memory>
#include <vector>
#include <cstdint>

#include "types.hpp"

//---------------------------------------------------------------------  WeakBlob
struct SWeakBlob{
	TYPE_BYTE* p;
	TYPE_SIZE size;

	SWeakBlob(TYPE_BYTE* pPar = nullptr, TYPE_SIZE sizePar = 0)
		: p(pPar), size(sizePar)
	{}

	SWeakBlob(const SWeakBlob& blobPar) = default;

	SWeakBlob(SWeakBlob&& blobPar)
		: p(blobPar.p), size(blobPar.size){
		blobPar.p = nullptr;
		blobPar.size = 0;
	}

	SWeakBlob& operator=(const SWeakBlob& blobPar) = default;
	~SWeakBlob() = default;

	bool reset(TYPE_BYTE* pPar = nullptr, TYPE_SIZE sizePar = 0){
		this->p = pPar;
		this->size = sizePar;

		return true;
	}

	void erase(){
		std::memset(this->p, 0, this->size);
	}
};

//---------------------------------------------------------------------  Blob
using Blob = std::vector<TYPE_BYTE>;
//

inline void eraseBlob(const Blob& blob){
	std::memset((void*)&blob[0], 0, blob.size()*sizeof(TYPE_BYTE));
}
//---------------------------------------------------------------------  SSecureBlob
template <typename T> class CSecureAllocator : public std::allocator<T>{
public:
	typedef T* pointer;
	typedef size_t size_type;

	template<class T2> struct rebind{
		typedef CSecureAllocator<T2> other;
	};

	pointer allocate(size_type n, const void* hint = nullptr){
		return std::allocator<T>::allocate(n, hint);
	}

	void deallocate(pointer p, size_type n){
		//Erasing memory
		std::memset(p, 0, n*sizeof(T));
		return std::allocator<T>::deallocate(p, n);
	}

	CSecureAllocator() throw() : std::allocator<T>() {}
	CSecureAllocator(const CSecureAllocator &a) throw() : std::allocator<T>(a) { }
	template <class U> CSecureAllocator(const CSecureAllocator<U> &a) throw() : std::allocator<T>(a) { }
	~CSecureAllocator() throw() { }
};

template<class T> struct SSecureBlob{
	friend class CRNG;
	friend class CCryptorIface;

private:
	std::shared_ptr<std::vector<TYPE_BYTE, CSecureAllocator<TYPE_BYTE>>> data;

public:
	SSecureBlob(T* pPar = nullptr, TYPE_SIZE size = 0){
		if (!pPar || !size){
			this->data.reset(new std::vector<T, CSecureAllocator<T>>());
			return;
		}
		this->data.reset(new std::vector<T, CSecureAllocator<T>>(pPar, pPar + size));
	}

	SSecureBlob(const SWeakBlob& weakBlobPar) : SSecureBlob(weakBlobPar.p, weakBlobPar.size){}

	SSecureBlob(const SSecureBlob& blobPar) : data(blobPar.data){}

	SSecureBlob& operator=(const SSecureBlob& blobPar){
		this->data = blobPar.data;
		return *this;
	}

	bool reset(T* pPar = nullptr, TYPE_SIZE size = 0){
		if (!pPar || !size){
			this->data.reset(new std::vector<T, CSecureAllocator<T>>());
			return true;
		}
		data.reset(new std::vector<T, CSecureAllocator<T>>(pPar, pPar + size));
		return true;
	}

	bool reset(const SWeakBlob& weakBlob){
		if (!weakBlob.p || !weakBlob.size){
			this->data.reset(new std::vector<T, CSecureAllocator<T>>());
			return true;
		}
		data.reset(new std::vector<T, CSecureAllocator<T>>(weakBlob.p, weakBlob.p + weakBlob.size));
		return true;
	}

	//use only in critical situations!!!
	bool clone(SSecureBlob& outputBlob){
		*outputBlob.data = *this->data;
		return true;
	}
};

using SecureBlob = SSecureBlob<TYPE_BYTE>;

#endif