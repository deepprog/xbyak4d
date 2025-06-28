module jmp;

import std.stdio;
import std.string;
import std.algorithm;
import std.stdint;
import std.exception;

import xbyak;
import test.test_count;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;


void putNop(CodeGenerator gen, int n)
{
	for (int i = 0; i < n; i++) {
		gen.nop();
	}
}

void diff(string a, string b)
{
	if (a == b) return;
	if (a.length != b.length) printf("size diff %d %d\n", cast(int)a.length, cast(int)b.length);
	for (size_t i = 0; i < min(a.length, b.length); i++) {
		if (a[i] != b[i]) {
			printf("diff %d(%04x) %02x %02x\n", cast(int)i, cast(int)i, a[i], b[i]);
		}
	}
}

void dump(string m)
{
	printf("size=%d\n     ", cast(int)m.length);
	for (int i = 0; i < 16; i++) {
		printf("%02x ", i);
	}
	printf("\n     ");
	for (int i = 0; i < 16; i++) {
		printf("---");
	}
	printf("\n");
	for (size_t i = 0; i < m.length; i++) {
		if ((i % 16) == 0) printf("%04x ", cast(int)(i / 16));
		printf("%02x ", m[i]);
		if ((i % 16) == 15) putchar('\n');
	}
	putchar('\n');
}

@("test1")
unittest
{
	writef("%s(%d) : ", __FILE__, __LINE__);
	test1();
}

void test1()
{
	class TestJmp : CodeGenerator {
	/*
	     4                                  X0:
	     5 00000004 EBFE                    jmp short X0
	     6
	     7                                  X1:
	     8 00000006 <res 00000001>          dummyX1 resb 1
	     9 00000007 EBFD                    jmp short X1
	    10
	    11                                  X126:
	    12 00000009 <res 0000007E>          dummyX126 resb 126
	    13 00000087 EB80                    jmp short X126
	    14
	    15                                  X127:
	    16 00000089 <res 0000007F>          dummyX127 resb 127
	    17 00000108 E97CFFFFFF              jmp near X127
	    18
	    19 0000010D EB00                    jmp short Y0
	    20                                  Y0:
	    21
	    22 0000010F EB01                    jmp short Y1
	    23 00000111 <res 00000001>          dummyY1 resb 1
	    24                                  Y1:
	    25
	    26 00000112 EB7F                    jmp short Y127
	    27 00000114 <res 0000007F>          dummyY127 resb 127
	    28                                  Y127:
	    29
	    30 00000193 E980000000              jmp near Y128
	    31 00000198 <res 00000080>          dummyY128 resb 128
	    32                                  Y128:
	*/
		this(int offset, bool isBack, bool isShort, bool useNewLabel)
		{
			if (useNewLabel) {
				Label label;
				if (isBack) {
					L(label);
					putNop(this, offset);
					jmp(label);
				} else {
					if (isShort) {
						jmp(label);
					} else {
						jmp(label, T_NEAR);
					}
					putNop(this, offset);
					L(label);
				}
			} else {
				if (isBack) {
					L("@@");
					putNop(this, offset);
					jmp("@b");
				} else {
					if (isShort) {
						jmp("@f");
					} else {
						jmp("@f", T_NEAR);
					}
					putNop(this, offset);
					L("@@");
				}
			}
		}
	}

	struct Tbl {
		int offset;
		bool isBack;
		bool isShort;
		int[] result;
		int size;
	}
	
	Tbl[] tbl =[ 
		Tbl( 0, true, true, [ 0xeb, 0xfe ], 2 ),
		Tbl( 1, true, true, [ 0xeb, 0xfd ], 2 ),
		Tbl( 126, true, true, [ 0xeb, 0x80 ], 2 ),
		Tbl( 127, true, false, [0xe9, 0x7c, 0xff, 0xff, 0xff ], 5 ),
		Tbl( 0, false, true, [ 0xeb, 0x00 ], 2 ),
		Tbl( 1, false, true, [ 0xeb, 0x01 ], 2 ),
		Tbl( 127, false, true, [ 0xeb, 0x7f ], 2 ),
		Tbl( 128, false, false, [ 0xe9, 0x80, 0x00, 0x00, 0x00 ], 5 )
	];

	TestCount tc;
	tc.reset();
	scope (exit) tc.end("test1");

	for (int i = 0; i < tbl.length; i++)
	{
		Tbl p = tbl[i];
		for (int k = 0; k < 2; k++)
		{
			scope TestJmp testjmp = new TestJmp(p.offset, p.isBack, p.isShort, k == 0);
			uint8_t* q = cast(uint8_t*) testjmp.getCode();
			if (p.isBack)
				q += p.offset; /* skip nop */
			for (int j = 0; j < p.size; j++)
			{
				tc.TEST_EQUAL(q[j], p.result[j]);
			}
		}
	}
}

@("testJmpCx")
unittest
{
	writef("%s(%d) : ", __FILE__, __LINE__);
	testJmpCx();
}

void testJmpCx()
{
	class TestJmpCx : CodeGenerator
	{
		this(void* p, bool useNewLabel)
		{
			super(16, p);

			if (useNewLabel)
			{
				Label lp;
				L(lp);
				version (XBYAK64)
				{
				/*
					67 E3 FD ; jecxz lp
					E3 FB    ; jrcxz lp
				*/
					jecxz(lp);
					jrcxz(lp);
				}
				else
				{
				/*
					E3FE   ; jecxz lp
					67E3FB ; jcxz lp
				*/
					jecxz(lp);
					jcxz(lp);
				}
			}
			else
			{
				inLocalLabel();
				L(".lp");
				version (XBYAK64)
				{
				/*
					67 E3 FD ; jecxz lp
					E3 FB    ; jrcxz lp
				*/
					jecxz(".lp");
					jrcxz(".lp");
				}
				else
				{
				/*
					E3FE   ; jecxz lp
					67E3FB ; jcxz lp
				*/
					jecxz(".lp");
					jcxz(".lp");
				}
				outLocalLabel();
			}
		}
	}

	struct Tbl
	{
		string p;
		size_t len;
	}

	version (XBYAK64)
	{
		Tbl tbl = Tbl("\x67\xe3\xfd\xe3\xfb", 5);
	}
	else
	{
		Tbl tbl = Tbl("\xe3\xfe\x67\xe3\xfb", 5);
	}

	TestCount tc;
	tc.reset();
	scope (exit) tc.end("testJmpCx");

	for (int j = 0; j < 2; j++)
	{
		char[16] buf;
		scope TestJmpCx code = new TestJmpCx(&buf, (j == 0));
		for (size_t i = 0; i < tbl.len; i++)
		{
			tc.TEST_EQUAL(buf[i], tbl.p[i]);
		}
	}
}

@("testloop")
unittest
{
	writef("%s(%d) : ", __FILE__, __LINE__);
	testloop();
}

void testloop()
{
	uint8_t[] ok = [
					// lp:
		0x31, 0xC0, // xor eax, eax
		0xE2, 0xFC, // loop lp
		0xE0, 0xFA, // loopne lp
		0xE1, 0xF8, // loope lp
	];

	class Code : CodeGenerator
	{
		this(bool useLabel)
		{
			if (useLabel)
			{
				Label lp = L();
				xor(eax, eax);
				loop(lp);
				loopne(lp);
				loope(lp);
			}
			else
			{
				L("@@");
				xor(eax, eax);
				loop("@b");
				loopne("@b");
				loope("@b");
			}
		}
	}

	TestCount tc;
	tc.reset();
	scope (exit) tc.end("testloop");

	scope code1 = new Code(false);
	tc.TEST_EQUAL(code1.getSize(), ok.length);
	auto buf1 = code1.getCode();
	for (size_t i = 0; i < ok.length; i++)
	{
		tc.TEST_EQUAL(buf1[i], ok[i]);
	}

	scope code2 = new Code(false);
	tc.TEST_EQUAL(code2.getSize(), ok.length);

	auto buf2 = code2.getCode();
	for (size_t i = 0; i < ok.length; i++)
	{
		tc.TEST_EQUAL(buf2[i], ok[i]);
	}
}

@("test2")
unittest
{
	writef("%s(%d) : ", __FILE__, __LINE__);
	test2();
}

void test2()
{
	class TestJmp2 : CodeGenerator
	{
	/*
	  1 00000000 90                      nop
	  2 00000001 90                      nop
	  3                              f1:
	  4 00000002 <res 0000007E>          dummyX1 resb 126
	  6 00000080 EB80                    jmp f1
	  7
	  8                              f2:
	  9 00000082 <res 0000007F>          dummyX2 resb 127
	 11 00000101 E97CFFFFFF              jmp f2
	 12
	 13
	 14 00000106 EB7F                    jmp f3
	 15 00000108 <res 0000007F>          dummyX3 resb 127
	 17                              f3:
	 18
	 19 00000187 E980000000              jmp f4
	 20 0000018C <res 00000080>          dummyX4 resb 128
	 22                              f4:
	*/
		this(void* p, bool useNewLabel)
		{
			super(8192, p);
			if(useNewLabel)
			{
				inLocalLabel();
				nop();
				nop();
			L(".f1");
				putNop(this, 126);
				jmp(".f1");
			L(".f2");
				putNop(this, 127);
				jmp(".f2", T_NEAR);

				jmp(".f3");
				putNop(this, 127);
			L(".f3");
				jmp(".f4", T_NEAR);
				putNop(this, 128);
			L(".f4");
				outLocalLabel();
	
			} else {
				nop();
				nop();
				Label f1, f2, f3, f4;
			L(f1);
				putNop(this, 126);
				jmp(f1);
			L(f2);
				putNop(this, 127);
				jmp(f2, T_NEAR);

				jmp(f3);
				putNop(this, 127);
			L(f3);
				jmp(f4, T_NEAR);
				putNop(this, 128);
			L(f4);
			}
		}
	}

	ubyte[1024] ok;
	ok[] = 0x90;
 
	ok[0x080] = 0xeb;
	ok[0x081] = 0x80;

	ok[0x101] = 0xe9;
	ok[0x102] = 0x7c;
	ok[0x103] = 0xff;
	ok[0x104] = 0xff;
	ok[0x105] = 0xff;

	ok[0x106] = 0xeb;
	ok[0x107] = 0x7f;

	ok[0x187] = 0xe9;
	ok[0x188] = 0x80;
	ok[0x189] = 0x00;
	ok[0x18a] = 0x00;
	ok[0x18b] = 0x00;

	TestCount tc;
	tc.reset();
	scope (exit) tc.end("test2");

	scope TestJmp2 c;
	c = new TestJmp2(null, true);
	c.ready();
	auto code = c.getCode();
	for (auto i = 0; i < c.getSize; i++)
	{
		tc.TEST_EQUAL(code[i], ok[i]);
	}

	c = new TestJmp2(AutoGrow, true);
	c.ready();
	code = c.getCode();
	for (auto i = 0; i < c.getSize; i++)
	{
		tc.TEST_EQUAL(code[i], ok[i]);
	}

	c = new TestJmp2(null, false);
	c.ready();
	code = c.getCode();
	for (auto i = 0; i < c.getSize; i++)
	{
		tc.TEST_EQUAL(code[i], ok[i]);
	}

	c = new TestJmp2(AutoGrow, false);
	c.ready();
	code = c.getCode();
	for (auto i = 0; i < c.getSize; i++)
	{
		tc.TEST_EQUAL(code[i], ok[i]);
	}
}

version(XBYAK32)
{
	int add5(int x) { return x + 5; }
	int add2(int x) { return x + 2; }
 
	@("test3")
	unittest
	{
		test3();
	}

	void test3(size_t line = __LINE__)
	{
		class Grow : CodeGenerator
		{
			this(int dummySize)
			{
				super(128, AutoGrow);

				mov(eax, 100);
				push(eax);
				call(&add5);
				add(esp, 4);
				
				push(eax);
				call(&add2);
				add(esp, 4);
				ret();
				for (int i = 0; i < dummySize; i++) {
					db(0);
				}
			}
		}

		TestCount tc;
		tc.reset();
		scope (exit)
		{
			writef("%s(%d) : ", __FILE__, line);
			tc.end("test3");
		}
		
		const size_t maxSize = 40_000;
		const size_t incSize = 10_000;

		for (size_t dummySize = 0; dummySize < maxSize; dummySize += incSize) {
			printf("dummySize=%d ", dummySize);
			scope Grow g = new Grow(dummySize);
			g.ready();
			
			auto f = cast(int function())g.getCode();
			auto x = f();
			
			int ok = 107;
			tc.TEST_EQUAL(x, ok);
			if(x == ok) printf("test3 OK: %d == %d\n", x, ok); 
			tc.TEST_EQUAL(x, ok);
		}
	}
}


uint8_t[4096 * 32] bufL;
uint8_t[4096 * 2] bufS;

class MyAllocator : Allocator
{
	override uint8_t* alloc(size_t size)
	{
		if (size < bufS.length) {
			printf("test use bufS(%d)\n", cast(int)size);
			return bufS.ptr;
		}
		if (size < bufL.length) {
			printf("test use bufL(%d)\n", cast(int)size);
			return bufL.ptr;
		}
		//fprintf(stderr, "no memory %d\n", cast(int)size);
		printf("no memory %d\n", cast(int)size);
		//exit(1);
		assert(0);
	}

	override void free(uint8_t* p)
	{
		return;
	}
}

@("test4")
unittest
{
	test4();
}

void test4(size_t line = __LINE__)
{
	class Test4 : CodeGenerator
	{
		this(int size, void* mode, bool useNewLabel, Allocator alloc)
		{
			super(size, mode, alloc);
			if (useNewLabel) {
				Label x;
				jmp(x);
				putNop(this, 10);
			L(x);
				ret();
			} else {
				inLocalLabel();
				jmp(".x");
				putNop(this, 10);
			L(".x");
				ret();
				outLocalLabel();
			}
		}
	}

	TestCount tc;
	tc.reset();
	scope (exit) 
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("test4");
	}
	
	MyAllocator myAlloc = new MyAllocator();
	
	for (int i = 0; i < 2; i++) {
		bool useNewLabel = i == 0;
	
		scope Test4 fc = new Test4(1024, null, useNewLabel, myAlloc);
		scope Test4 gc = new Test4(5, AutoGrow, !useNewLabel, myAlloc);
		gc.ready();

		auto fcode = fc.getCode();
		auto fsize = fc.getSize();
		auto gcode = gc.getCode();
		auto gsize = gc.getSize();
	
		tc.TEST_EQUAL(fsize, gsize);
		if(fsize != gsize)
		{
			writefln("Test4 NG fsize:%d != gsize:%d", fsize, gsize );
			assert(0);
		}
		
		for (auto j = 0; j < fsize; j++)
		{
			tc.TEST_EQUAL(fcode[j], gcode[j]);
		}
	}
}


version (OSX)
{}
else
{

	@("test5")
	unittest
	{
		test5();
	}

	void test5(size_t line = __LINE__)
	{
		MyAllocator myAlloc = new MyAllocator();

		class Test5 : CodeGenerator
		{
			this(int size, int count, void* mode)
			{
				super(size, mode, myAlloc);

				inLocalLabel();
				mov(ecx, count);
				xor(eax, eax);
				L(".lp");
				for (int i = 0; i < count; i++)
				{
					L(Label.toStr(i));
					add(eax, 1);
					int to = 0;
					if (i < count / 2)
					{
						to = count - 1 - i;
					}
					else
					{
						to = count - i;
					}
					if (i == count / 2)
					{
						jmp(".exit", T_NEAR);
					}
					else
					{
						jmp(Label.toStr(to), T_NEAR);
					}
				}
				L(".exit");
				sub(ecx, 1);
				jnz(".lp", T_NEAR);
				ret();
				outLocalLabel();
			}
		}

		TestCount tc;
		tc.reset();
		scope (exit)
		{
			writef("%s(%d) : ", __FILE__, line);
			tc.end("test5");
		}

		int count = 50;
		int ret;
		scope Test5 fc = new Test5(1024 * 64, count, null);
		fc.readyRE();
		auto fcode = fc.getCode();
		auto ffun = cast(int function()) fcode;
		ret = ffun();
		tc.TEST_EQUAL(ret, count * count);
		fc.readyRE();
		auto fm = fc.getCode();

		scope Test5 gc = new Test5(10, count, AutoGrow);
		gc.readyRE();
		auto gcode = gc.getCode();
		auto gfun = cast(int function()) gcode;
		ret = gfun();
		tc.TEST_EQUAL(ret, count * count);

		gc.readyRE();
		auto gm = gc.getCode();

		for (int i = 0; i < fc.getSize(); i++)
		{
			tc.TEST_EQUAL(fm[i], gm[i]);
		}
	}
}


size_t getValue(const uint8_t* p)
{
	size_t v = 0;
	for (size_t i = 0; i < size_t.sizeof; i++)
	{
		v |= cast(size_t)(p[i]) << (i * 8);
	}
	return v;
}

void checkAddr(ref TestCount tc, const uint8_t* p, size_t offset, size_t expect)
{
	size_t v = getValue(p + offset);
	tc.TEST_EQUAL(v, cast(size_t) p + expect);
}

@("MovLabel")
unittest
{
	MovLabel();
}

void MovLabel(size_t line = __LINE__)
{
	class MovLabelCode : CodeGenerator
	{
		this(bool grow, bool useNewLabel)
		{
			super(grow ? 128 : 4096, grow ? AutoGrow : null);

			version (XBYAK64)
			{
				Reg64 a = rax;
			}
			else
			{
				Reg32 a = eax;
			}

			if (useNewLabel)
			{
				nop(); // 0x90
				Label lp1;
				Label lp2;
				L(lp1);
				nop();
				mov(a, lp1); // 0xb8 + <4byte> / 0x48bb + <8byte>
				nop();
				mov(a, lp2); // 0xb8
				// force realloc if AutoGrow
				putNop(this, 256);
				nop();
				L(lp2);
			}
			else
			{
				inLocalLabel();
				nop(); // 0x90
				L(".lp1");
				nop();
				mov(a, ".lp1"); // 0xb8 + <4byte> / 0x48bb + <8byte>
				nop();
				mov(a, ".lp2"); // 0xb8
				// force realloc if AutoGrow
				putNop(this, 256);
				nop();
				L(".lp2");
				outLocalLabel();
			}
		}
	}

	struct PosOk
	{
		int pos;
		uint8_t ok;

		this(int pos, uint8_t ok)
		{
			this.pos = pos;
			this.ok = ok;
		}
	}

	version (XBYAK32)
	{
		PosOk[] pk = [
			PosOk(0x00, 0x90),
			// lp1:0x001
			PosOk(0x001, 0x90),
			PosOk(0x002, 0xb8),
			// 0x003
			PosOk(0x007, 0x90),
			PosOk(0x008, 0xb8),
			// 0x009
			PosOk(0x10d, 0x90),
			// lp2:0x10e
		];
	}

	version (XBYAK64)
	{
		PosOk[] pk = [
			PosOk(0x000, 0x90),
			// lp1:0x001
			PosOk(0x001, 0x90),
			PosOk(0x002, 0x48),
			PosOk(0x003, 0xb8),
			// 0x004
			PosOk(0x00c, 0x90),
			PosOk(0x00d, 0x48),
			PosOk(0x00e, 0xb8),
			// 0x00f
			PosOk(0x117, 0x90),
			// lp2:0x118
		];
	}

	TestCount tc;
	tc.reset();
	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("MovLabel");
	}

	for (int j = 0; j < 2; j++)
	{
		bool grow = j == 0;
		for (int k = 0; k < 2; k++)
		{
			bool useNewLabel = k == 0;
			scope MovLabelCode code = new MovLabelCode(grow, useNewLabel);
			if (grow)
				code.ready();
			auto p = code.getCode();
			for (size_t i = 0; i < pk.length; i++)
			{
				int pos = pk[i].pos;
				uint8_t x = p[pos];
				uint8_t ok = pk[i].ok;
				tc.TEST_EQUAL(x, ok);
			}
			
			version (XBYAK32)
			{
				tc.checkAddr(p, 0x03, 0x001);
				tc.checkAddr(p, 0x09, 0x10e);
			}

			version (XBYAK64)
			{
				tc.checkAddr(p, 0x04, 0x001);
				tc.checkAddr(p, 0x0f, 0x118);
			}
		}
	}
}


@("testMovLaberl2")
unittest
{
	testMovLabel2();
}

void testMovLabel2(size_t line = __LINE__)
{
	class MovLabel2Code : CodeGenerator
	{
		this()
		{
			super();
			version (XBYAK64)
			{
				Reg64 a = rax;
				Reg64 c = rcx;
			}
			else
			{
				Reg32 a = eax;
				Reg32 c = ecx;
			}

			xor(a, a);
			xor(c, c);
			jmp("in");
			ud2();
		L("@@"); // L1
			add(a, 2);
			mov(c, "@f");
			jmp(c); // goto L2
			ud2();
		L("in");
			mov(c, "@b");
			add(a, 1);
			jmp(c); // goto L1
			ud2();
		L("@@"); // L2
			add(a, 4);
			ret();
		}
	}

	TestCount tc;
	tc.reset();
	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("testMovLaberl2");
	}

	scope MovLabel2Code code = new MovLabel2Code();
	code.ready();
	auto fn = code.getCode!(int function());

	int ret = 0;
	ret = fn();
	tc.TEST_EQUAL(ret, 7);
}


@("testF_B")
unittest
{
	testF_B();
}

void testF_B(size_t line = __LINE__)
{
	class Code : CodeGenerator
	{
		int a;
		this(int type)
		{
			super();
			inLocalLabel();
			xor(eax, eax);
			switch(type)
			{
			case 0:
			L("@@");
				inc(eax);
				cmp(eax, 1);
				je("@b");
				break;
			case 1:
				test(eax, eax);
				jz("@f");
				ud2();
			L("@@");
				break;
			case 2:
			L("@@");
				inc(eax);
				cmp(eax, 1); // 1, 2
				je("@b");
				cmp(eax, 2); // 2, 3
				je("@b");
				break;
			case 3:
			L("@@");
				inc(eax);
				cmp(eax, 1); // 1, 2
				je("@b");
				cmp(eax, 2); // 2, 3
				je("@b");
				jmp("@f");
				ud2();
			L("@@");
				break;
			case 4:
			L("@@");
				inc(eax);
				cmp(eax, 1); // 1, 2
				je("@b");
				cmp(eax, 2); // 2, 3
				je("@b");
				jmp("@f");
				ud2();
			L("@@");
				inc(eax); // 4, 5
				cmp(eax, 4);
				je("@b");
				break;
			case 5:
			L("@@");
			L("@@");
				inc(eax);
				cmp(eax, 1);
				je("@b");
				break;
			case 6:
			L("@@");
			L("@@");
			L("@@");
				inc(eax);
				cmp(eax, 1);
				je("@b");
				break;
			case 7:
				jmp("@f");
			L("@@");
				inc(eax); // 1, 2
				cmp(eax, 1);
				je("@b");
				cmp(eax, 2);
				jne("@f"); // not jmp
				inc(eax); // 3
			L("@@");
				inc(eax); // 4, 5, 6
				cmp(eax, 4);
				je("@b");
				cmp(eax, 5);
				je("@b");
				jmp("@f");
				jmp("@f");
				jmp("@b");
			L("@@");
				break;
			default:
				assert(0);
			}
			ret();
			outLocalLabel();
		}
	}

	TestCount tc;
	tc.reset();
	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("testF_B");
	}

	int[] expectedTbl = [
		2, 0, 3, 3, 5, 2, 2, 6
	];

	for (size_t i = 0; i < expectedTbl.length; i++)
	{
		scope Code code = new Code(cast(int) i);
		auto fn = code.getCode!(int function());
		int ret = fn();
		tc.TEST_EQUAL(ret, expectedTbl[i]);
	}
}

@("test6")
unittest
{
	test6();
}

void test6(size_t line = __LINE__)
{
	class TestLocal : CodeGenerator
	{
		this(bool grow)
		{
			super(grow ? 128 : 4096, grow ? AutoGrow : null);
	
			xor(eax, eax);
			inLocalLabel();
			jmp("start0", T_NEAR);
			L(".back");
			inc(eax); // 8
			jmp(".next", T_NEAR);
			L("start2");
			inc(eax); // 7
			jmp(".back", T_NEAR);
				inLocalLabel();
				L(".back");
				inc(eax); // 5
				putNop(this, 128);
				jmp(".next", T_NEAR);
				L("start1");
				inc(eax); // 4
				jmp(".back", T_NEAR);
					inLocalLabel();
					L(".back");
					inc(eax); // 2
					jmp(".next", T_NEAR);
					L("start0");
					inc(eax); // 1
					jmp(".back", T_NEAR);
					L(".next");
					inc(eax); // 3
					jmp("start1", T_NEAR);
					outLocalLabel();
				L(".next");
				inc(eax); // 6
				jmp("start2", T_NEAR);
				outLocalLabel();
			L(".next");
			inc(eax); // 9
			jmp("start3", T_NEAR);
				inLocalLabel();
				L(".back");
				inc(eax); // 14
				jmp("exit", T_NEAR);
			L("start4");
				inc(eax); // 13
				jmp(".back", T_NEAR);
				outLocalLabel();
			L("start3");
				inc(eax); // 10
				inLocalLabel();
				jmp(".next", T_NEAR);
				L(".back");
				inc(eax); // 12
				jmp("start4", T_NEAR);
				L(".next");
				inc(eax); // 11
				jmp(".back", T_NEAR);
				outLocalLabel();
			outLocalLabel();
			L("exit");
			inc(eax); // 15
			ret();
		}
	}

	TestCount tc;
	tc.reset();
	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("test6");
	}

	for (int i = 0; i < 2; i++)
	{
		bool grow = i == 1;
		printf("test6 grow=%d\n", i);
		scope TestLocal code = new TestLocal(grow);
		if (grow) code.ready();
		auto f = code.getCode!(int function());
		int a = f();
		tc.TEST_EQUAL(a, 15);
	}
}

@("test_jcc")
unittest
{
	test_jcc();
}

void test_jcc(size_t line = __LINE__)
{
	class A : CodeGenerator
	{
		this()
		{
			add(eax, 5);
			ret();
		}
	}
	
	class B : CodeGenerator
	{
		this(bool grow, void* p)
		{
			super(grow ? 0 : 4096, grow ? AutoGrow : null);
			mov(eax, 1);
			add(eax, 2);
			jnz(p);
		}
	}

	TestCount tc;
	tc.reset();
	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("test_jcc");
	}

	scope A a = new A();
	void* p = cast(void*) a.getCode();

	for (int i = 0; i < 2; i++)
	{
		bool grow = i == 1;
		scope B b = new B(grow, p);
		if (grow)
		{
			b.readyRE();
		}
		auto f = b.getCode!(int function());
		//	b.dump();
		tc.TEST_EQUAL(f(), 8);
	}
}


@("testNewLabel")
unittest
{
	testNewLabel();
}

void testNewLabel(size_t line = __LINE__)
{
	class Code : CodeGenerator
	{
		this(bool grow)
		{
			super(grow ? 128 : 4096, grow ? AutoGrow : null);
		
			xor(eax, eax);
			{
				Label label1, label2, label3, label4;
				Label exit;
				jmp(label1, T_NEAR);
			L(label2);
				inc(eax); // 2
				jmp(label3, T_NEAR);
			L(label4);
				inc(eax); // 4
				jmp(exit, T_NEAR);
				putNop(this, 128);
			L(label3);
				inc(eax); // 3
				jmp(label4, T_NEAR);
			L(label1);
				inc(eax); // 1
				jmp(label2, T_NEAR);
			L(exit);
			}
			{
				Label label1, label2, label3, label4;
				Label exit;
				jmp(label1);
			L(label2);
				inc(eax); // 6
				jmp(label3);
			L(label4);
				inc(eax); // 8
				jmp(exit);
			L(label3);
				inc(eax); // 7
				jmp(label4);
			L(label1);
				inc(eax); // 5
				jmp(label2);
			L(exit);
			}
			Label callLabel;
			{	// eax == 8
				Label label1, label2;
			L(label1);
				inc(eax); // 9, 10, 11, 13
				cmp(eax, 9);
				je(label1);
				// 10, 11, 13
				inc(eax); // 11, 12, 13
				cmp(eax, 11);
				je(label1);
				// 12, 13
				cmp(eax, 12);
				je(label2);
				inc(eax); // 14
				cmp(eax, 14);
				je(label2);
				ud2();
			L(label2); // 14
				inc(eax); // 13, 15
				cmp(eax, 13);
				je(label1);
			}
			call(callLabel);
			ret();
		L(callLabel);
			inc(eax); // 16
			ret();
		}
	}

	TestCount tc;
	tc.reset();
	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("testNewLabel");
	}

	for (int i = 0; i < 2; i++)
	{
		bool grow = (i == 0 ? true : false);
		writeln("testNewLabel grow=", grow);
		scope Code code = new Code(grow);
		if (grow)
			code.ready();
		auto f = code.getCode!(int function());
		int r;
		r = f();
		tc.TEST_EQUAL(r, 16);
	}
}

@("returnLabel")
unittest
{
	returnLabel();
}

void returnLabel(size_t line = __LINE__)
{
	class Code : CodeGenerator
	{
		this()
		{
			super();
			xor(eax, eax);
		Label L1 = L();
			test(eax, eax);
		Label exit;
			jnz(exit);
			inc(eax); // 1
		Label L2;
			call(L2);
			jmp(L1);
		L(L2);
			inc(eax); // 2
			ret();
		L(exit);
			inc(eax); // 3
			ret();
		}
	}

	TestCount tc;
	tc.reset();
	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("returnLabel");
	}

	scope Code code = new Code();
	auto f = code.getCode!(int function());
	int r = f();
	tc.TEST_EQUAL(r, 3);
}


@("testAssige")
unittest
{
	testAssige();
}

void testAssige(size_t line = __LINE__)
{
	class Code : CodeGenerator
	{
		this(bool grow)
		{
			super(grow ? 128 : 4096, grow ? AutoGrow : null);
		
			xor(eax, eax);
			Label dst, src;
		L(src);
			inc(eax);
			cmp(eax, 1);
			je(dst);
			inc(eax); // 2, 3, 5
			cmp(eax, 5);
			putNop(this, 128);
			jne(dst, T_NEAR);
			ret();
		assignL(dst, src);
			// test of copy  label
			{
				Label sss = dst;
				{
					Label ttt;
					ttt = src;
				}
			}
		}
	}

	TestCount tc;
	tc.reset();
	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("testAssige");
	}

	for (int i = 0; i < 2; i++)
	{
		bool grow = (i == 0 ? true : false);
		writeln("testAssign grow=", grow);
		scope Code code = new Code(grow);
		if (grow)
		{
			writeln("grow:", grow);
			code.ready();
		}
		auto f = code.getCode!(int function());
		int ret = f();
		tc.TEST_EQUAL(ret, 5);
	}
}


@("doubleDefine")
unittest
{
	doubleDefine();
}

void doubleDefine(size_t line = __LINE__)
{
	class Code1 : CodeGenerator
	{
   		this()
		{
			super();
			Label label;
		L(label);
			// forbitten double L()
			assertThrown!XError( L(label) );
			writeln("OK 1:forbitten double L()");	
		}
	}			
		
	class Code2 : CodeGenerator
	{	
		this(ref TestCount tc)
		{
			super();
			Label label;
			jmp(label);
			
			tc.TEST_ASSERT( hasUndefinedLabel() );
		//	assert( hasUndefinedLabel() );

			writeln("OK 2:hasUndefinedLabel()");
		}
	}

	class Code3 : CodeGenerator
	{	
		this()
		{
			super();
			Label label1, label2;
		L(label1);
			jmp(label2);
			assignL(label2, label1);
			// forbitten double assignL
			
			assertThrown!XError( assignL(label2, label1) );
			writeln("OK 3:forbitten double assignL");
		}
	}

	class Code4 : CodeGenerator
	{	
		this()
		{
			super();
			Label label1, label2;
		L(label1);
			jmp(label2);
			// forbitten assignment to label1 set by L()
			assertThrown!XError( assignL(label1, label2) );
			writeln("OK 4:forbitten assignment to label1 set by L()");			
		}
	}

	TestCount tc;
	tc.reset();
	
	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("doubleDefine");
	}

	scope Code1 code1 = new Code1();
	auto f1 = code1.getCode();
	tc.set(true);

	scope Code2 code2 = new Code2(tc);
	auto f2 = code2.getCode();

	scope Code3 code3 = new Code3();
	auto f3 = code3.getCode();
	tc.set(true);

	scope Code4 code4 = new Code4();
	auto f4 = code4.getCode();
	tc.set(true);
}


class GetAddressCode1 : CodeGenerator
{	
	void test(ref TestCount tc)
	{
		Label L1, L2, L3;
		nop();
	L(L1);
		uint8_t* p1 = getCurr();
		tc.TEST_EQUAL(L1.getAddress(), p1);

		nop();
		jmp(L2);
		nop();
		jmp(L3);
	L(L2);
		tc.TEST_EQUAL(L2.getAddress(), getCurr());
		// L3 is not defined
		tc.TEST_EQUAL(L3.getAddress(), null);

		// L3 is set by L1
		assignL(L3, L1);
		tc.TEST_EQUAL(L3.getAddress(), p1);
	}
}


@("getAddress1")
unittest
{
	getAddress1();
}

void getAddress1(size_t line = __LINE__)
{
	TestCount tc;
	tc.reset();

	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("getAddress1");
	}	
	
	scope c = new GetAddressCode1();
	c.test(tc);
}

class CodeLabelTable : CodeGenerator
{
	enum { ret0 = 3 }
	enum { ret1 = 5 }
	enum { ret2 = 8 }
	
	this()
	{
		super();
version(XBYAK64)
{
	version(Win64)
	{
		Reg64 p0 = rcx;
		Reg64 a = rax;
	}
	version(Posix)
	{
		Reg64 p0 = rdi;
		Reg64 a = rax;
	}
}else{
		Reg32 p0 = edx;
		Reg32 a = eax;
		mov(edx, ptr [esp + 4]);
}
		Label labelTbl;
		Label L0, L1, L2;
		mov(a, labelTbl);
		jmp(ptr [a + p0 * (void*).sizeof]);
	L(labelTbl);
		putL(L0);
		putL(L1);
		putL(L2);
	L(L0);
		mov(a, ret0);
		ret();
	L(L1);
		mov(a, ret1);
		ret();
	L(L2);
		mov(a, ret2);
		ret();
	}
}

version (XBYAK64)
{

	@("LabelTable")
	unittest
	{
		LabelTable();
	}

	void LabelTable(size_t line = __LINE__)
	{
		TestCount tc;
		tc.reset();

		scope (exit)
		{
			writef("%s(%d) : ", __FILE__, line);
			tc.end("LabelTable");
		}

		scope c = new CodeLabelTable();
		auto fn = c.getCode!(int function(int));
		tc.TEST_EQUAL(fn(0), c.ret0);
		tc.TEST_EQUAL(fn(1), c.ret1);
		tc.TEST_EQUAL(fn(2), c.ret2);
	}

	class GetAddressCode2 : CodeGenerator
	{
		Label L1, L2, L3;
		size_t a1;
		size_t a3;
		this(int size)
		{
			super(size, size == 4096 ? null : AutoGrow);
			a1 = 0;
			a3 = 0;
			bool autoGrow = size != 4096;
			nop();
			L(L1);
			if (autoGrow)
			{
				auto tmp1 = L1.getAddress() == null;
				assert(tmp1);
			}
			a1 = getSize();
			nop();
			jmp(L2);
			if (autoGrow)
			{
				auto tmp2 = L2.getAddress() == null;
				assert(tmp2);
			}
			L(L3);
			a3 = getSize();
			if (autoGrow)
			{
				auto tmp3 = L3.getAddress() == null;
				assert(tmp3);
			}
			nop();
			assignL(L2, L1);
			if (autoGrow)
			{
				auto tmp4 = L2.getAddress() == null;
				assert(tmp4);
			}
		}
	}

	@("testGetAddressCode2")
	unittest
	{
		testGetAddressCode2();
	}

	void testGetAddressCode2(size_t line = __LINE__)
	{
		TestCount tc;
		tc.reset();

		scope (exit)
		{
			writef("%s(%d) : ", __FILE__, line);
			tc.end("testGetAddressCode2");
		}
		
		int[] sizeTbl = [
			2, 128, // grow
			4096 // not grow
		];

		foreach (int size; sizeTbl)
		{
			//	int size = sizeTbl[i];
			scope c = new GetAddressCode2(size);
			c.readyRE();
			uint8_t* p = c.getCode();

			tc.TEST_EQUAL(c.L1.getAddress(), p + c.a1);
			tc.TEST_EQUAL(c.L3.getAddress(), p + c.a3);
			tc.TEST_EQUAL(c.L2.getAddress(), p + c.a1);
		}
	}

	@("testrip")
	unittest
	{
		testrip();
	}

	void testrip(size_t line = __LINE__)
	{
		int[] a = [1, 10];
		int[] b = [100, 1000];
		class Code : CodeGenerator
		{
			this(ref int[] a, ref int[] b)
			{
				super();
				Label label1, label2;
				jmp("@f");
				L(label1);
				db(a[0], 4);
				db(a[1], 4);
				L("@@");
				mov(eax, ptr[rip + label1]); // a[0]
				mov(ecx, ptr[rip + label1 + 4]); // a[1]
				mov(edx, ptr[rip + label2 - 8 + 2 + 6]); // b[0]
				add(ecx, ptr[rip + 16 + label2 - 12]); // b[1]
				add(eax, ecx);
				add(eax, edx);
				ret();
				L(label2);
				db(b[0], 4);
				db(b[1], 4);

				// error
				assertThrown!XError(rip + label1 + label2);
			}
		}
		
		TestCount tc;
		tc.reset();

		scope (exit)
		{
			writef("%s(%d) : ", __FILE__, line);
			tc.end("testrip");
		}

		scope code = new Code(a, b);
		auto fn = code.getCode!(int function());
		int ret = fn();
		int sum = a[0] + a[1] + b[0] + b[1];
		tc.TEST_EQUAL(ret, sum);
	}

	int ret1234()
	{
		return 1234;
	}

	int ret9999()
	{
		return 9999;
	}

	@("rip_jmp")
	unittest
	{
		rip_jmp();
	}

	void rip_jmp(size_t line = __LINE__)
	{
		class Code : CodeGenerator
		{
			this()
			{
				Label label;
				xor(eax, eax);
				call(ptr[rip + label]);
				mov(ecx, eax);
				call(ptr[rip + label + 8]);
				add(eax, ecx);
				ret();
				L(label);
				db(cast(size_t)&ret1234, 8);
				db(cast(size_t)&ret9999, 8);
			}
		}

		TestCount tc;
		tc.reset();

		scope (exit)
		{
			writef("%s(%d) : ", __FILE__, line);
			tc.end("rip_jmp");
		}

		scope code = new Code();
		auto fn = code.getCode!(int function());
		int ret = fn();
		int sum = ret1234() + ret9999();
		tc.TEST_EQUAL(ret,  sum);
	}

	version (none)
	{

		@("rip_addr")
		unittest
		{
			writefln("%s(%d) : rip_addr", __FILE__, __LINE__);
			rip_addr();
		}

		void rip_addr(size_t line = __LINE__)
		{
			//	we can't assume |&x - &code| < 2GiB anymore
			static int x = 5;
			class Code : CodeGenerator
			{
				this()
				{
					//	super();
					mov(eax, 123);
					mov(ptr[rip + &x], eax);
					ret();
				}
			}

			scope code = new Code();
			auto fn = cast(void function()) code.getCode();
			writeln(x);
			fn();
			writeln(x);
			assert(x == 123);
		}
	}

	version (OSX)
	{}
	else
	{
		@("rip_addr_with_fixed_buf")
		unittest
		{
			rip_addr_with_fixed_buf();
		}

		void rip_addr_with_fixed_buf(size_t line = __LINE__)
		{
			align(4096) static uint8_t[8192] buf;
			uint8_t* p = buf.ptr + 4096;
			int* x0 = cast(int*) buf.ptr;
			int* x1 = x0 + 1;
			class Code : CodeGenerator
			{
				this()
				{
					super(4096, p);
					mov(eax, 123);
					mov(ptr[rip + x0], eax);
					mov(dword[rip + x1], 456);
					mov(byte_[rip + 1 + x1 + 3], 99);
					ret();
				}
			}

           	TestCount tc;
			tc.reset();

			scope (exit)
			{
				writef("%s(%d) : ", __FILE__, line);
				tc.end("rip_addr_with_fixed_buf");
			}

			scope code = new Code();
			code.setProtectModeRE();
			auto fn = code.getCode!(void function());
			fn();

			tc.TEST_EQUAL(*x0, 123);
			tc.TEST_EQUAL(*x1, 456);
			tc.TEST_EQUAL(buf[8], 99);
			code.setProtectModeRW();
		}
	}
}

class ReleaseTestCode : CodeGenerator
{
	this(ref Label L1, ref Label L2, ref Label L3)
	{
		super();
		L(L1);
		jmp(L1);
		L(L2);
		jmp(L3); // not assigned
	}
}

/*
	code must unlink label if code is destroyed
*/
@("release_label_after_code")
unittest
{
	release_label_after_code();
}

void release_label_after_code(size_t line = __LINE__)
{
	TestCount tc;
	tc.reset();

	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("release_label_after_code");
	}
	
	puts("---");
	{
		Label L1, L2, L3, L4, L5;
		{
		static if(false)
		{
			writeln("auto");
			auto code = new ReleaseTestCode(L1, L2, L3);
			scope (exit) destroy(code);
		}
		else
		{	
			writeln("scope");
			scope code = new ReleaseTestCode(L1, L2, L3);
		}

			tc.TEST_ASSERT(L1.getId > 0);
			tc.TEST_ASSERT(L1.getAddress() != null);
			tc.TEST_ASSERT(L2.getId > 0);
			tc.TEST_ASSERT(L2.getAddress() != null);
			tc.TEST_ASSERT(L3.getId > 0);
			tc.TEST_ASSERT(L3.getAddress() == null); // L3 is not assigned
			code.assignL(L4, L1);
			L5 = L1;
			writefln("id=%d %d %d %d %d", L1.getId(), L2.getId(), L3.getId(), L4.getId(), L5.getId());
		}
		puts("code is released");
		tc.TEST_ASSERT(L1.getId() == 0);
		tc.TEST_ASSERT(L1.getAddress() == null);
		tc.TEST_ASSERT(L2.getId() == 0);
		tc.TEST_ASSERT(L2.getAddress() == null);
//		tc.TEST_ASSERT(L3.getId() == 0); // L3 is not assigned so not cleared
		tc.TEST_ASSERT(L3.getAddress() == null);
		tc.TEST_ASSERT(L4.getId() == 0);
		tc.TEST_ASSERT(L4.getAddress() == null);
		tc.TEST_ASSERT(L5.getId() == 0);
		tc.TEST_ASSERT(L5.getAddress() == null);
		writef("id=%d %d %d %d %d\n", L1.getId(), L2.getId(), L3.getId(), L4.getId(), L5.getId());
	}
}


class JmpTypeCode : CodeGenerator
{
	void nops()
	{
		for (int i = 0; i < 130; i++) {
			nop();
		}
	}
	// return jmp code size
	size_t gen(bool pre, bool large, LabelType type)
	{
		Label label;
		if (pre) {
			L(label);
			if (large) nops();
			size_t pos = getSize();
			jmp(label, type);
			return getSize() - pos;
		} else {
			size_t pos = getSize();
			jmp(label, type);
			size_t size = getSize() - pos;
			if (large) nops();
			L(label);
			return size;
		}
	}
}

@("setDefaultJmpNEAR")
unittest
{
	setDefaultJmpNEAR();
}

void setDefaultJmpNEAR(size_t line = __LINE__)
{
	TestCount tc;
	tc.reset();

	scope (exit)
	{
		writef("%s(%d) : ", __FILE__, line);
		tc.end("setDefaultJmpNEAR");
	}
	
	alias LabelType = CodeGenerator.LabelType;

	struct TBL{
		bool pre;
		bool large;
		LabelType type;
		size_t expect1; // 0 means exception
		size_t expect2;
	}
	
	TBL[] tbl = 
	[
		TBL( false, false, T_SHORT, 2, 2 ),
		TBL( false, false, T_NEAR, 5, 5 ),
		TBL( false, true, T_SHORT, 0, 0 ),
		TBL( false, true, T_NEAR, 5, 5 ),

		TBL( true, false, T_SHORT, 2, 2 ),
		TBL( true, false, T_NEAR, 5, 5 ),
		TBL( true, true, T_SHORT, 0, 0 ),
		TBL( true, true, T_NEAR, 5, 5 ),

		TBL( false, false, T_AUTO, 2, 5 ),
		TBL( false, true, T_AUTO, 0, 5 ),
		TBL( true, false, T_AUTO, 2, 2 ),
		TBL( true, true, T_AUTO, 5, 5 )
	];

	JmpTypeCode code1 = new JmpTypeCode();
	JmpTypeCode code2 = new JmpTypeCode();
	code2.setDefaultJmpNEAR(true);

	for (size_t i = 0; i < tbl.length; i++) {
		code1 = new JmpTypeCode();
		code2 = new JmpTypeCode();
		code2.setDefaultJmpNEAR(true);
		// writeln("\ni:", i);
		if (tbl[i].expect1) {
			size_t size = code1.gen(tbl[i].pre, tbl[i].large, tbl[i].type);
			auto exp1 = tbl[i].expect1;
			// writeln("size:", size);
			// writeln("exp1:", exp1);
			assert(size == exp1);
		} else {
			bool ret = false;
			try {
				 code1.gen(tbl[i].pre, tbl[i].large, tbl[i].type);
			}
			catch (Exception e) {
        		// writeln("code1 catch");
				ret = true;
			}
			if (ret) assert(ret);
		}
		if (tbl[i].expect2) {
			size_t size = code2.gen(tbl[i].pre, tbl[i].large, tbl[i].type);
			auto exp2 = tbl[i].expect2;
			assert(size == exp2);
		} else {
			bool ret = false;
			try {
				 code2.gen(tbl[i].pre, tbl[i].large, tbl[i].type);
			}
			catch (Exception e) {
        		// writeln("code2 catch");
				ret = true;
     		}
			if (ret) assert(ret);
		}

		tc.set(true);
	}
}


@("ambiguousFarJmp")
unittest
{
	ambiguousFarJmp();
}

void ambiguousFarJmp(size_t line = __LINE__)
{
	class Code : CodeGenerator
	{
version(XBYAK32){
		void genJmp() { jmp(ptr[eax], T_FAR); }
		void genCall() { call(ptr[eax], T_FAR); }
}else{
		void genJmp() { jmp(ptr[rax], T_FAR); }
		void genCall() { call(ptr[rax], T_FAR); }
}
	}

	testCount_ = 0; 
	okCount_ = 0;
	ngCount_ = 0;

	scope code = new Code();
	testException!({ code.genJmp(); }, Exception);
	testException!({ code.genCall(); }, Exception);

	write(__FILE__, "(", line, ") testException:", testCount_);
    write(" OK:", okCount_);
    writeln(" NG:", ngCount_);

    if(ngCount_ != 0) {
        assert(0, "test error is ambiguousFarJmp");
    }
	writeln();
}

static testCount_ = 0; 
static okCount_ = 0;
static ngCount_ = 0;

void testException(alias statement, exception)(string file = __FILE__, size_t line = __LINE__)
{
    testCount_++;
    int ret_ = 0;
    try {
        statement();
        ret_ = 1;
    } catch (exception ex) {
        // ret_ = 0;
    } catch (Throwable t) {
        ret_ = 2;
    }

    if(ret_ == 0) {
        okCount_++;
        return;
    }

    if (ret_ != 0) {
        ngCount_++;
        writeln("testEXCEPTION: Failure in ", file, " line ", line);
        if (ret_ == 1) {
            writeln("test: no exception");
        } else {
            writeln("test: unexpected exception");
        }
    }
}