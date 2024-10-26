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
 