module avx10_test;

import std.stdio;
import std.string;
import std.stdint;
import xbyak;
import test.test_count;;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

version(XBYAK64)
{
// ymm with sae is not supported from avx10.2 rev 4.0.
	@("ymm_with_sae")
	unittest
	{
		ymm_with_sae();
	}

void ymm_with_sae(size_t line = __LINE__)
{
	TestCount tc;	
	tc.reset();
	scope (exit)
    {
        writef("%s(%d) : ", __FILE__, line);
        tc.end("ymm_with_sae");
    }

	class Code : CodeGenerator
	{
		this(ref TestCount tc)
		{   
			tc.TEST_EXCEPTION!Exception({ vaddpd(ymm1, ymm2, ymm3 | T_rn_sae); });
			tc.TEST_EXCEPTION!Exception({ vcvtph2ibs(xmm1, xmm31 | T_rd_sae); });
			tc.TEST_EXCEPTION!Exception({ vcvtph2ibs(ymm1, ymm31 | T_rd_sae); });
			tc.TEST_EXCEPTION!Exception({ vcvt2ps2phx(ymm1, ymm2, ymm3 | T_rd_sae); });
			tc.TEST_EXCEPTION!Exception({ vminmaxpd(ymm1, ymm2, ymm3 | T_sae, 1); });
			tc.TEST_EXCEPTION!Exception({ vminmaxph(ymm1, ymm2, ymm3 | T_sae, 2); });
			tc.TEST_EXCEPTION!Exception({ vminmaxps(ymm1, ymm2, ymm3 | T_sae, 3); });
			tc.TEST_EXCEPTION!Exception({ vcvtps2ibs(ym1, ym2|T_rd_sae); });
			tc.TEST_EXCEPTION!Exception({ vcvtps2ibs(xm1, xm2|T_rd_sae); });
		}
	}
	scope Code c = new Code(tc);
}


@("vmpsadbw")
unittest{
	vmpsadbw();
}

void vmpsadbw()
{
	class Code : CodeGenerator
	{
		this()
		{
			setDefaultEncodingAVX10();
			vmpsadbw(xm1, xm3, xm15, 3); // vex(avx)
			vmpsadbw(ym1, ym3, ptr[rax+128], 3); // vex(avx2)
			setDefaultEncodingAVX10(AVX10v2Encoding);
			vmpsadbw(ym1, ym3, ym15, 3); // evex(avx10.2)
			vmpsadbw(ym1, ym3, ptr[rax+128], 3); // evex(avx10.2)
		}
	}

	const uint8_t[] tbl = [
		0xc4, 0xc3, 0x61, 0x42, 0xcf, 0x03,
		0xc4, 0xe3, 0x65, 0x42, 0x88, 0x80, 0x00, 0x00, 0x00, 0x03,
		0x62, 0xd3, 0x66, 0x28, 0x42, 0xcf, 0x03,
		0x62, 0xf3, 0x66, 0x28, 0x42, 0x48, 0x04, 0x03,
	];

	scope Code c = new Code();
	const size_t n = tbl.length;
	assert(c.getSize() == n);
	auto ctbl = c.getCode();
	for(int i=0; i < n; i++)
	{
		assert(ctbl[i] == tbl[i]);
	}
}

}