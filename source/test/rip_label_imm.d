module rip_label_imm;

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

/*
dump of vc
00000000003A0000 F3 0F C2 05 F1 00 00 00 00			cmpeqss xmm0,dword ptr [3A00FAh]
00000000003A0009 F7 05 E7 00 00 00 21 00 00 00		test dword ptr [3A00FAh],21h
00000000003A0013 0F BA 25 DF 00 00 00 03 			bt dword ptr [3A00FAh],3
00000000003A001B C4 E3 79 0D 05 D5 00 00 00 03		vblendpd xmm0,xmm0,xmmword ptr [3A00FAh],3
00000000003A0025 C4 E3 79 0F 05 CB 00 00 00 04		vpalignr xmm0,xmm0,xmmword ptr [3A00FAh],4
00000000003A002F C4 E3 7D 19 1D C1 00 00 00 0C		vextractf128 xmmword ptr [3A00FAh],ymm3,0Ch
00000000003A0039 C4 E3 75 46 05 B7 00 00 00 0D		vperm2i128 ymm0,ymm1,ymmword ptr [3A00FAh],0Dh
00000000003A0043 C4 E3 79 1D 15 AD 00 00 00 2C		vcvtps2ph mmword ptr [3A00FAh],xmm2,2Ch
00000000003A004D C7 05 A3 00 00 00 34 12 00 00		mov dword ptr [3A00FAh],1234h
00000000003A0057 C1 25 9C 00 00 00 03				shl dword ptr [3A00FAh],3
00000000003A005E D1 2D 96 00 00 00					shr dword ptr [3A00FAh],1
00000000003A0064 48 0F A4 05 8D 00 00 00 03			shld qword ptr [3A00FAh],rax,3
00000000003A006D 48 6B 05 85 00 00 00 15			imul rax,qword ptr [3A00FAh],15h
00000000003A0075 C4 E3 FB F0 05 7B 00 00 00 15		rorx rax,qword ptr [3A00FAh],15h
00000000003A007F F7 05 71 00 00 00 05 00 00 00		test dword ptr [3A00FAh],5
00000000003A0089 66 48 0F 3A 16 05 66 00 00 00 03 	pextrq qword ptr [3A00FAh],xmm0,3
00000000003A0094 66 48 0F 3A 22 15 5B 00 00 00 05 	pinsrq xmm2,qword ptr [3A00FAh],5
00000000003A009F 66 0F 3A 15 0D 51 00 00 00 04 		pextrw word ptr [3A00FAh],xmm1,4
00000000003A00A9 81 15 47 00 00 00 45 23 01 00 		adc dword ptr [3A00FAh],12345h
00000000003A00B3 0F BA 25 3F 00 00 00 34			bt dword ptr [3A00FAh],34h
00000000003A00BB 66 0F BA 3D 36 00 00 00 34			btc word ptr [3A00FAh],34h
00000000003A00C4 0F BA 35 2E 00 00 00 34			btr dword ptr [3A00FAh],34h
00000000003A00CC C1 15 27 00 00 00 04				rcl dword ptr [3A00FAh],4
00000000003A00D3 48 0F A4 05 1E 00 00 00 04			shld qword ptr [3A00FAh],rax,4
00000000003A00DC 0F 3A 0F 05 15 00 00 00 04			palignr mm0,mmword ptr [3A00FAh],4
00000000003A00E5 66 0F 3A DF 1D 0B 00 00 00 04		aeskeygenassist xmm3,xmmword ptr [3A00FAh],4
00000000003A00EF C4 E3 79 60 15 01 00 00 00 07		vpcmpestrm  xmm2,xmmword ptr [3A00FAh],7
00000000003A00F9 C3                   				ret
00000000003A00FA F0 DE BC 9A 78 56 34 12
*/


const uint8_t[] tbl = [
	0xF3, 0x0F, 0xC2, 0x05, 0xF1, 0x00, 0x00, 0x00, 0x00,		// cmpeqss xmm0,dword ptr [3A00FAh]
	0xF7, 0x05, 0xE7, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, // test dword ptr [3A00FAh],21h
	0x0F, 0xBA, 0x25, 0xDF, 0x00, 0x00, 0x00, 0x03, 			// bt dword ptr [3A00FAh],3
	0xC4, 0xE3, 0x79, 0x0D, 0x05, 0xD5, 0x00, 0x00, 0x00, 0x03,	// vblendpd xmm0 xmm0,xmmword ptr [3A00FAh],3
	0xC4, 0xE3, 0x79, 0x0F, 0x05, 0xCB, 0x00, 0x00, 0x00, 0x04,	// vpalignr xmm0 xmm0,xmmword ptr [3A00FAh],4
	0xC4, 0xE3, 0x7D, 0x19, 0x1D, 0xC1, 0x00, 0x00, 0x00, 0x0C,	//vextractf128 xmmword ptr [3A00FAh],ymm3,0Ch
	0xC4, 0xE3, 0x75, 0x46, 0x05, 0xB7, 0x00, 0x00, 0x00, 0x0D,	// vperm2i128 ymm0 ymm1,ymmword ptr [3A00FAh],0Dh
	0xC4, 0xE3, 0x79, 0x1D, 0x15, 0xAD, 0x00, 0x00, 0x00, 0x2C,	// vcvtps2ph mmword ptr [3A00FAh],xmm2,2Ch
	0xC7, 0x05, 0xA3, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,	// mov dword ptr [3A00FAh],1234h
	0xC1, 0x25, 0x9C, 0x00, 0x00, 0x00, 0x03,					// shl dword ptr [3A00FAh],3
	0xD1, 0x2D, 0x96, 0x00, 0x00, 0x00,							// shr dword ptr [3A00FAh],1
	0x48, 0x0F, 0xA4, 0x05, 0x8D, 0x00, 0x00, 0x00, 0x03,		// shld qword ptr [3A00FAh],rax,3
	0x48, 0x6B, 0x05, 0x85, 0x00, 0x00, 0x00, 0x15,				// imul rax,qword ptr [3A00FAh],15h
	0xC4, 0xE3, 0xFB, 0xF0, 0x05, 0x7B, 0x00, 0x00, 0x00, 0x15,	// rorx rax,qword ptr [3A00FAh],15h
	0xF7, 0x05, 0x71, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,	// test dword ptr [3A00FAh],5
	0x66, 0x48, 0x0F, 0x3A, 0x16, 0x05, 0x66, 0x00, 0x00, 0x00, 0x03,	// pextrq qword ptr [3A00FAh],xmm0,3
	0x66, 0x48, 0x0F, 0x3A, 0x22, 0x15, 0x5B, 0x00, 0x00, 0x00, 0x05,	// pinsrq xmm2,qword ptr [3A00FAh],5
	0x66, 0x0F, 0x3A, 0x15, 0x0D, 0x51, 0x00, 0x00, 0x00, 0x04,	// pextrw word ptr [3A00FAh],xmm1,4
	0x81, 0x15, 0x47, 0x00, 0x00, 0x00, 0x45, 0x23, 0x01, 0x00,	// adc dword ptr [3A00FAh],12345h
	0x0F, 0xBA, 0x25, 0x3F, 0x00, 0x00, 0x00, 0x34,				// bt dword ptr [3A00FAh],34h
	0x66, 0x0F, 0xBA, 0x3D, 0x36, 0x00, 0x00, 0x00, 0x34,		// btc word ptr [3A00FAh],34h
	0x0F, 0xBA, 0x35, 0x2E, 0x00, 0x00, 0x00, 0x34,				// btr dword ptr [3A00FAh],34h
	0xC1, 0x15, 0x27, 0x00, 0x00, 0x00, 0x04,					// rcl dword ptr [3A00FAh],4
	0x48, 0x0F, 0xA4, 0x05, 0x1E, 0x00, 0x00, 0x00, 0x04,		// shld qword ptr [3A00FAh],rax,4
	0x0F, 0x3A, 0x0F, 0x05, 0x15, 0x00, 0x00, 0x00, 0x04,		// palignr mm0,mmword ptr [3A00FAh],4
	0x66, 0x0F, 0x3A, 0xDF, 0x1D, 0x0B, 0x00, 0x00, 0x00, 0x04,	// aeskeygenassist xmm3,xmmword ptr [3A00FAh],4
	0xC4, 0xE3, 0x79, 0x60, 0x15, 0x01, 0x00, 0x00, 0x00, 0x07,	// vpcmpestrm  xmm2,xmmword ptr [3A00FAh],7
	0xC3,
	0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
];

class Code : CodeGenerator
{
	this()
	{
		super();
		Label label;
		cmpss(xmm0, ptr[rip + label], 0);
		test(dword[rip + label], 33);
		bt(dword[rip + label ], 3);
		vblendpd(xmm0, xmm0, dword[rip + label], 3);
		vpalignr(xmm0, xmm0, qword[rip + label], 4);
		vextractf128(dword[rip + label], ymm3, 12);
		vperm2i128(ymm0, ymm1, qword[rip + label], 13);
		vcvtps2ph(ptr[rip + label], xmm2, 44);
		mov(dword[rip + label], 0x1234);
		shl(dword[rip + label], 3);
		shr(dword[rip + label], 1);
		shld(qword[rip + label], rax, 3);
		imul(rax, qword[rip + label], 21);
		rorx(rax, qword[rip + label], 21);
		test(dword[rip + label], 5);
		pextrq(ptr[rip + label], xmm0, 3);
		pinsrq(xmm2, ptr[rip + label], 5);
		pextrw(ptr[rip + label], xmm1, 4);
		adc(dword[rip + label], 0x12345);
		bt(byte_[rip + label], 0x34);
		btc(word[rip + label], 0x34);
		btr(dword[rip + label], 0x34);
		rcl(dword[rip + label], 4);
		shld(qword[rip + label], rax, 4);
		palignr(mm0, ptr[rip + label], 4);
		aeskeygenassist(xmm3, ptr[rip + label], 4);
		vpcmpestrm(xmm2, ptr[rip + label], 7);
		ret();
	L(label);
		dq(0x123456789abcdef0uL);
	}
}

void dump(uint8_t* p, size_t n)
{
	for (int i = 0; i < n; i++) {
		printf("%02x ", p[i]);
		if ((i % 16) == 15) putchar('\n');
	}
	putchar('\n');
}

@("rip_label_imm")
unittest
{
	rip_label_imm();
}

void rip_label_imm()
{
	Code code = new Code();
	auto f = cast(void function()) code.getCode();
//	dump(code.getCode(), code.getSize());
//	f();
	
	const size_t n = tbl.length;
	assert(code.getSize() == n);
	auto ctbl = code.getCode();

	for(int i=0; i < n; i++)
	{
		assert(ctbl[i] == tbl[i]);
	}
}
