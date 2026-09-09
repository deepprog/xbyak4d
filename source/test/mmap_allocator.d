module mmap_allocator;

import core.stdc.stdio;
import core.stdc.stdlib;
import std.stdint;
import std.stdio;
import std.string;

import xbyak;
import xbyak_util;
import test.test_count;

version(X86)    version = XBYAK32;
version(X86_64) version = XBYAK64;

//version = XBYAK_USE_MMAP_ALLOCATOR;
//version = XBYAK_USE_MEMFD;

version(XBYAK64)
{

version(XBYAK_USE_MMAP_ALLOCATOR)
{
@("freeUnknownPointer")
unittest
{
	freeUnknownPointer();
}

void freeUnknownPointer()
{
	scope tc = TestCount(__FUNCTION__);
	class Code : CodeGenerator {
		this(ref TestCount tc)
		{
			MmapAllocator alloc = new MmapAllocator();
			uint8_t dummy = 0;
			tc.TEST_EXCEPTION!XError({ alloc.free(&dummy); });
		}
	}
	scope Code c = new Code(tc);
}

@("freeNullptr")
unittest
{
	freeNullptr();
}

void freeNullptr()
{
	scope tc = TestCount(__FUNCTION__);
	MmapAllocator alloc = new MmapAllocator();
	tc.TEST_NO_EXCEPTION({ alloc.free(null); });
}


@("doubleFree")
unittest
{
	doubleFree();
}

void doubleFree()
{
	scope tc = TestCount(__FUNCTION__);
	MmapAllocator alloc = new MmapAllocator();
	uint8_t* p = alloc.alloc(64);
	tc.TEST_NO_EXCEPTION({ alloc.free(p); });
	tc.TEST_EXCEPTION!XError({ alloc.free(p); });
}

@("freeOnlyElement")
unittest
{
	freeOnlyElement();
}

void freeOnlyElement()
{
	scope tc = TestCount(__FUNCTION__);
	MmapAllocator alloc = new MmapAllocator();
	uint8_t* p = alloc.alloc(64);
	tc.TEST_NO_EXCEPTION({ alloc.free(p); });
	tc.TEST_EXCEPTION!XError({ alloc.free(p); });
}

@("freeLastElement")
unittest
{
	freeLastElement();
}

void freeLastElement()
{
	scope tc = TestCount(__FUNCTION__);
	MmapAllocator alloc = new MmapAllocator();
	uint8_t* p0 = alloc.alloc(64);
	uint8_t* p1 = alloc.alloc(64);
	tc.TEST_NO_EXCEPTION({ alloc.free(p1); });
	tc.TEST_NO_EXCEPTION({ alloc.free(p0); });
	tc.TEST_EXCEPTION!XError({ alloc.free(p0); });
	tc.TEST_EXCEPTION!XError({ alloc.free(p1); });
}

@("freeNonLifoOrder")
unittest
{
	freeNonLifoOrder();
}

void freeNonLifoOrder()
{
	scope tc = TestCount(__FUNCTION__);
	MmapAllocator alloc = new MmapAllocator();
	uint8_t* p0 = alloc.alloc(64);
	uint8_t* p1 = alloc.alloc(64);
	uint8_t* p2 = alloc.alloc(64);
	tc.TEST_NO_EXCEPTION({ alloc.free(p0); });
	tc.TEST_NO_EXCEPTION({ alloc.free(p1); });
	tc.TEST_NO_EXCEPTION({ alloc.free(p2); });
	tc.TEST_EXCEPTION!XError({ alloc.free(p0); });
	tc.TEST_EXCEPTION!XError({ alloc.free(p1); });
	tc.TEST_EXCEPTION!XError({ alloc.free(p2); });
}

@("twoInstancesAreIsolated")
unittest
{
	twoInstancesAreIsolated();
}

void twoInstancesAreIsolated()
{
	scope tc = TestCount(__FUNCTION__);
	MmapAllocator a = new MmapAllocator();
	MmapAllocator b = new MmapAllocator();
	uint8_t* p = a.alloc(64);
	tc.TEST_EXCEPTION!XError({ b.free(p); });
	tc.TEST_NO_EXCEPTION({ a.free(p); });
}

	version(XBYAK_USE_MEMFD)
	{
		@("memfdSurvivorAfterSwap")
		unittest
		{
			memfdSurvivorAfterSwap();
		}

		void memfdSurvivorAfterSwap()
		{
			scope tc = TestCount(__FUNCTION__);
			MmapAllocator alloc = new MmapAllocator();
			uint8_t* p0 = alloc.alloc(64);
			uint8_t* p1 = alloc.alloc(64);
			tc.TEST_NO_EXCEPTION({ alloc.free(p0); });
			tc.TEST_NO_EXCEPTION({ alloc.free(p1); });
		}
	}

} // XBYAK_USE_MMAP_ALLOCATOR

} // XBYAK64
