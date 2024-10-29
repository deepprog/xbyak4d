module jmp;

import std.stdio;
import std.string;
import std.algorithm;
import std.stdint;
import std.exception;

import xbyak;

version(X86)
{
	version = XBYAK32;
}

version(X86_64)
{
	version = XBYAK64;
}


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
unittest{
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
				Label label = new Label();
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


	for(int i = 0; i < tbl.length; i++) {
		Tbl p = tbl[i];
		for(int k = 0; k < 2; k++) {
			TestJmp testjmp = new TestJmp(p.offset, p.isBack, p.isShort, k == 0);
			uint8_t* q = cast(uint8_t*)testjmp.getCode();
			if (p.isBack) q += p.offset; /* skip nop */
			for (int j = 0; j < p.size; j++) {
				assert(q[j] == p.result[j]); 
			}
		}
	}	
}

@("testJmpCx")
unittest{
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
				Label lp = new Label();
			L(lp);
version(XBYAK64) {
				/*
					67 E3 FD ; jecxz lp
					E3 FB    ; jrcxz lp
				*/
				jecxz(lp);
				jrcxz(lp);
} else {
				/*
					E3FE   ; jecxz lp
					67E3FB ; jcxz lp
				*/
				jecxz(lp);
				jcxz(lp);
}
			} else {
				inLocalLabel();
			L(".lp");
version(XBYAK64) {
				/*
					67 E3 FD ; jecxz lp
					E3 FB    ; jrcxz lp
				*/
				jecxz(".lp");
				jrcxz(".lp");
} else {
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

version(XBYAK64) {
	Tbl tbl = Tbl("\x67\xe3\xfd\xe3\xfb", 5);
} else {
	Tbl tbl = Tbl("\xe3\xfe\x67\xe3\xfb", 5);
}
	
	for(int j = 0; j < 2; j++) {
		char[16] buf;
		TestJmpCx code = new TestJmpCx(&buf, (j == 0));
		for(size_t i = 0; i < tbl.len; i++)
		{
			assert(buf[i] == tbl.p[i]);
		}
	}
}

@("testloop")
unittest{
	testJmpCx();
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
	
	class Code : CodeGenerator {
		this(bool useLabel)
		{
			if (useLabel) {
 			Label lp = L();
				xor(eax, eax);
				loop(lp);
				loopne(lp);
				loope(lp);
			} else {
				L("@@");
				xor(eax, eax);
				loop("@b");
				loopne("@b");
				loope("@b");
			}
		}
	}
	
	Code code1 = new Code(false);
	auto bufSize = code1.getSize();
	if(bufSize != ok.length)
	{
		assert(0);
	}

	auto buf = code1.getCode();
	for(size_t i = 0; i < ok.length; i++)
	{
		if(buf[i] != ok[i])
		{
			assert(0);
		}
	}

	Code code2 = new Code(true);
	bufSize = code2.getSize();
	if(bufSize != ok.length)
	{
		assert(0);
	}

	buf = code2.getCode();
	for(size_t i = 0; i < ok.length; i++)
	{
		if(buf[i] != ok[i])
		{
			assert(0);
		}
	}
}

@("test2")
unittest{
	test2();
}

void test2()
{
	class TestJmp2 : CodeGenerator
	{
	/*
	  1 00000000 90                      nop
	  2 00000001 90                      nop
	  3                                  f1:
	  4 00000002 <res 0000007E>          dummyX1 resb 126
	  6 00000080 EB80                     jmp f1
	  7
	  8                                  f2:
	  9 00000082 <res 0000007F>          dummyX2 resb 127
	 11 00000101 E97CFFFFFF               jmp f2
	 12
	 13
	 14 00000106 EB7F                    jmp f3
	 15 00000108 <res 0000007F>          dummyX3 resb 127
	 17                                  f3:
	 18
	 19 00000187 E980000000              jmp f4
	 20 0000018C <res 00000080>          dummyX4 resb 128
	 22                                  f4:
	*/
		this(void* p, bool useNewLabel)
		{
			super(8192, p);
			if(useNewLabel) {
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
				Label f1 = new Label();
				Label f2 = new Label();
				Label f3 = new Label();
				Label f4 = new Label();
			//	, f2, f3, f4;
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

	char[1024] ok;
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
	
	TestJmp2 c;
	c = new TestJmp2(null, true);
	c.ready();
	auto code = c.getCode();
	for(auto i = 0; i < c.getSize; i++)
	{
		if(code[i] != ok[i])
		{
			printf("TestJmp2(null, true) NG: %X != %X\n", code[i], ok[i]); 
			assert(0);
		}
	}
	
	
 	c = new TestJmp2(AutoGrow, true);
	c.ready();
	code = c.getCode();
	for(auto i = 0; i < c.getSize; i++)
	{
    	if(code[i] != ok[i])
		{
			printf("TestJmp2(AutoGrow, true) NG: %X != %X\n", code[i], ok[i]); 
			assert(0);
		}
	}
		
	c = new TestJmp2(null, false);
	c.ready();
	code = c.getCode();
	for(auto i = 0; i < c.getSize; i++)
	{
    	if(code[i] != ok[i])
		{
			printf("TestJmp2(null, false) NG: %X != %X\n", code[i], ok[i]); 
			assert(0);
		}
	}

	c = new TestJmp2(AutoGrow, false);
	c.ready();
	code = c.getCode();
	for(auto i = 0; i < c.getSize; i++)
	{
    	if(code[i] != ok[i])
		{
			printf("TestJmp2(AutoGrow, false) NG: %X != %X\n", code[i], ok[i]); 
			assert(0);
		}
	}
}

version(XBYAK32)
{
	int add5(int x) { return x + 5; }
	int add2(int x) { return x + 2; }
 
@("test3")
unittest{
	test3();
}
	void test3()
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

		const size_t maxSize = 40_000;
		const size_t incSize = 10_000;

		for (size_t dummySize = 0; dummySize < maxSize; dummySize += incSize) {
			printf("dummySize=%d\n", dummySize);
			Grow g = new Grow(dummySize);
			g.ready();
			
			auto f = cast(int function())g.getCode();
			auto x = f();
			
			int ok = 107;
			if(x == ok) printf("test3 OK: %d == %d\n", x, ok); 
			if(x != ok) 
			{
				printf("test3 NG: %d != %d\n", x, ok); 
				assert(0);
			}
		}
	}
}


uint8_t[4096 * 32] bufL;
uint8_t[4096 * 2] bufS;

class MyAllocator : Allocator {
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
unittest{
	test4();
}

void test4()
{
	class Test4 : CodeGenerator
	{
		this(int size, void* mode, bool useNewLabel, Allocator alloc)
		{
			super(size, mode, alloc);
			if (useNewLabel) {
				Label x = new Label(); 
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

	MyAllocator myAlloc = new MyAllocator();
	
	for (int i = 0; i < 2; i++) {
		bool useNewLabel = i == 0;
	
		Test4 fc = new Test4(1024, null, useNewLabel, myAlloc);
		Test4 gc = new Test4(5, AutoGrow, !useNewLabel, myAlloc);
		gc.ready();

		auto fcode = fc.getCode();
		auto fsize = fc.getSize();
		auto gcode = gc.getCode();
		auto gsize = gc.getSize();
	
		if(fsize != gsize)
		{
			writefln("Test4 NG fsize:%d != gsize:%d", fsize, gsize );
			assert(0);
		}
		else
		{
			writefln("Test4 OK fsize:%d == gsize:%d", fsize, gsize );
		}
	}
}


version(OSX){}
else
{

@("test5")
unittest{
	test5();
}

void test5()
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
			for (int i = 0; i < count; i++) {
				L(Label.toStr(i));
				add(eax, 1);
				int to = 0;
				if (i < count / 2) {
					to = count - 1 - i;
				} else {
					to = count  - i;
				}
				if (i == count / 2) {
					jmp(".exit", T_NEAR);
				} else {
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

	int count = 50;
	int ret;
	Test5 fc = new Test5(1024 * 64, count, null);
	auto fcode = fc.getCode();
	auto ffun = cast(int function())fcode;
	ret = ffun();
	assert(ret == count * count);	
	writefln("Test5 fc:ok");
	
	auto fm = fc.getCode();
	
	Test5 gc=  new Test5(10, count, AutoGrow);
	gc.ready();
	auto gcode = gc.getCode();
	auto gfun = cast(int function())gcode;
	ret = gfun();
	assert(ret == count * count);
	writefln("Test5 gc:ok");
	
	auto gm = gc.getCode();
	
	for(int i = 0; i < fc.getSize; i++){
		if(fm[i] != gm[i])
		{
			writefln("Test5 NG: fm != gm: %d %d", fm[i], gm[i]);
			assert(0);
		}
	}
}
}


size_t getValue(const uint8_t* p)
{
	size_t v = 0;
	for (size_t i = 0; i < size_t.sizeof; i++) {
		v |= cast(size_t)(p[i]) << (i * 8);
	}
	return v;
}

void checkAddr(const uint8_t* p, size_t offset, size_t expect)
{
	size_t v = getValue(p + offset);
	assert(v == cast(size_t)p + expect);
}

@("MovLabel")
unittest{
	MovLabel();
}

void MovLabel()
{
	class MovLabelCode : CodeGenerator
	{
		this(bool grow, bool useNewLabel)
		{
			super(grow ? 128 : 4096, grow ? AutoGrow : null);

version(XBYAK64) {
			Reg64 a = rax;
} else {
			Reg32 a = eax;
}

			if (useNewLabel)
			{
				nop(); // 0x90
				Label lp1 = new Label();
				Label lp2 = new Label();
			L(lp1);
				nop();
				mov(a, lp1); // 0xb8 + <4byte> / 0x48bb + <8byte>
				nop();
				mov(a, lp2); // 0xb8
				// force realloc if AutoGrow
				putNop(this, 256);
				nop();
			L(lp2);
			} else {
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
 
version(XBYAK32)
{
	PosOk[] pk = [
		PosOk( 0x00, 0x90 ),
		// lp1:0x001
		PosOk( 0x001, 0x90 ),
		PosOk( 0x002, 0xb8 ),
		// 0x003
		PosOk( 0x007, 0x90 ),
		PosOk( 0x008, 0xb8 ),
		// 0x009
		PosOk( 0x10d, 0x90 ),
		// lp2:0x10e
	];
}

version(XBYAK64)
{
	PosOk[] pk = [
		PosOk( 0x000, 0x90 ),
		// lp1:0x001
		PosOk( 0x001, 0x90 ),
		PosOk( 0x002, 0x48 ),
		PosOk( 0x003, 0xb8 ),
		// 0x004
		PosOk( 0x00c, 0x90 ),
		PosOk( 0x00d, 0x48 ),
		PosOk( 0x00e, 0xb8 ),
		// 0x00f
		PosOk( 0x117, 0x90 ),
		// lp2:0x118
	];
}

	for (int j = 0; j < 2; j++) {
		bool grow = j == 0;
		for (int k = 0; k < 2; k++) {
			bool useNewLabel = k == 0;
			MovLabelCode code = new MovLabelCode(grow, useNewLabel);
			if (grow) code.ready();
			auto p = code.getCode();
			for (size_t i = 0; i < pk.length; i++) {
				int pos = pk[i].pos;
				uint8_t x = p[pos];
				uint8_t ok = pk[i].ok;
				assert(x == ok);
			}
version(XBYAK32)
{
			checkAddr(p, 0x03, 0x001);
			checkAddr(p, 0x09, 0x10e);
}

version(XBYAK64)
  {			checkAddr(p, 0x04, 0x001);
			checkAddr(p, 0x0f, 0x118);
}
		}
	}
}


@("testMovLaberl2")
unittest{
	testMovLabel2();
}

void testMovLabel2()
{
	class MovLabel2Code : CodeGenerator
	{
		this()
		{
			
version(XBYAK64){
			Reg64 a = rax;
			Reg64 c = rcx;
}else{
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

	MovLabel2Code code = new MovLabel2Code();
	code.ready();
	auto fn = cast(int function())code.getCode();
	
	int ret = 0;	
	ret = fn();
	ret.writeln;
	assert(ret == 7);
}



@("testF_B")
unittest{
	testF_B();
}

void testF_B()
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

	int[] expectedTbl = [
		2, 0, 3, 3, 5, 2, 2, 6
	];

	for (size_t i = 0; i < expectedTbl.length; i++) {
		Code code = new Code(cast(int)i);
		auto fn  = cast(int function())code.getCode();
		int ret = fn();
		bool bl = ret == expectedTbl[i];
		assert(bl);
	}
}

@("test6")
unittest{
	test6();
}

void test6()
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

	for (int i = 0; i < 2; i++) {
		bool grow = i == 1;
		printf("test6 grow=%d\n", i);
		TestLocal code = new TestLocal(grow);
		if (grow) code.ready();
		auto f = cast(int function())code.getCode();
		int a = f();
		assert(a == 15);
	}
}

@("test_jcc")
unittest{
	test_jcc();
}

void test_jcc()
{
	class A : CodeGenerator
	{
		int a;
		this()
		{
			add(eax, 5);
			ret();
		}
	}
	
	class B : CodeGenerator
	{
		int a;
		this(bool grow, void* p)
		{
			super(grow ? 0 : 4096, grow ? AutoGrow : null);
			mov(eax, 1);
			add(eax, 2);
			jnz(p);
		}
	}
	A a = new A();
	void* p = cast(void*)a.getCode();
	
	for (int i = 0; i < 2; i++)
	{
		bool grow = i == 1;
		B b = new B(grow, p);
		if (grow) {
			b.ready();
		}
		auto f = cast(int function())b.getCode();
		assert(f() ==  8);
	}
	
}


@("testNewLabel")
unittest{
	testNewLabel();
}

void testNewLabel()
{
	class Code : CodeGenerator
	{
		this(bool grow)
		{
			super(grow ? 128 : 4096, grow ? AutoGrow : null);
		
			xor(eax, eax);
			{
				Label label1 = new Label();
				Label label2 = new Label();
				Label label3 = new Label();
				Label label4 = new Label();
				Label exit = new Label();
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
				Label label1 = new Label();
				Label label2 = new Label();
				Label label3 = new Label();
				Label label4 = new Label();
				Label exit = new Label();
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
			Label callLabel = new Label();
			{	// eax == 8
				Label label1 = new Label();
				Label label2 = new Label();
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

	for (int i = 0; i < 2; i++) {
		bool grow = (i == 0 ? true : false);
		writeln("testNewLabel grow=", grow);
		Code code = new Code(grow);
		if (grow) code.ready();
		auto f = cast(int function())code.getCode();
		int r;
		r = f();
		assert (r == 16);
	}
}

@("returnLabel")
unittest{
	returnLabel();
}

void returnLabel()
{
	class Code : CodeGenerator
	{
		int a;
		this()
		{
			xor(eax, eax);
		Label L1 = new Label();
			test(eax, eax);
		Label exit = new Label();
			jnz(exit);
			inc(eax); // 1
		Label L2 = new Label();
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

	Code code = new Code();
	auto f = cast(int function())code.getCode();
	int r = f();
	assert(r == 3);
}


@("testAssige")
unittest{
	testAssige();
}

void testAssige()
{
	class Code : CodeGenerator
	{
		this(bool grow)
		{
			super(grow ? 128 : 4096, grow ? AutoGrow : null);
		
			xor(eax, eax);
			Label dst = new Label();
			Label src = new Label();
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
				Label sss = new Label(dst);
				{
					Label ttt;
					ttt = src;
				}
			}
		}
	}

	for (int i = 0; i < 2; i++) {
		bool grow = (i == 0 ? true : false);
		writeln("testAssign grow=", grow);
		Code code = new Code(grow);
		if (grow) {
			writeln("grow:", grow);
			code.ready();
		}
		auto f = cast(int function())code.getCode();
		int ret = f();
		assert(ret == 5);
    }
}


@("doubleDefine")
unittest{
	doubleDefine();
}

void doubleDefine()
{
	class Code1 : CodeGenerator
	{
   		this()
		{
			super();
			Label label = new Label();
		L(label);
			// forbitten double L()
			assertThrown!XError( L(label) );
			writeln("OK 1:forbitten double L()");	
		}
	}			
		
	class Code2 : CodeGenerator
	{	
		this()
		{
			super();
			Label label = new Label();
			jmp(label);
			
			assert( hasUndefinedLabel() );
			writeln("OK 2:hasUndefinedLabel()");
		}
	}

	class Code3 : CodeGenerator
	{	
		this()
		{
			Label label1 = new Label();
			Label label2 = new Label();	
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
			Label label1 = new Label();
			Label label2 = new Label();
		L(label1);
			jmp(label2);
			// forbitten assignment to label1 set by L()
			assertThrown!XError( assignL(label1, label2) );
			writeln("OK 4:forbitten assignment to label1 set by L()");			
		}
	}

	Code1 code1 = new Code1();
	Code2 code2 = new Code2();
	Code3 code3 = new Code3();
	Code4 code4 = new Code4();
}


class GetAddressCode1 : CodeGenerator
{	
	void test()
	{
		Label L1 = new Label();
		Label L2 = new Label();
		Label L3 = new Label();
		nop();
	L(L1);
		uint8_t* p1 = getCurr();
		bool eq1 = L1.getAddress() == p1;
		writeln(eq1);
		assert(eq1);

		nop();
		jmp(L2);
		nop();
		jmp(L3);
	L(L2);
		bool eq2 = L2.getAddress() == getCurr();
		writeln(eq2);
		assert(eq2);
	
		// L3 is not defined
		bool eq3 = L3.getAddress() == null;
		writeln(eq3);
		assert(eq3);

		// L3 is set by L1
		assignL(L3, L1);
		bool eq4 = L3.getAddress() == p1;
		writeln(eq4);
		assert(eq4);
	}
}


@("getAddress1")
unittest{
	getAddress1();
}

void getAddress1()
{
	GetAddressCode1 c = new GetAddressCode1();
	c.test();
}

version(unittest){}
else
{
void main()
{
	test1();
	testJmpCx();
	testJmpCx();
	test2();
version(XBYAK32){	
	test3();
}
	test4();
	test5();
	MovLabel();
	testMovLabel2();
	testF_B();
	test6();
	test_jcc();
	testNewLabel();
	returnLabel();
	testAssige();
	doubleDefine();
	getAddress1();
}
}