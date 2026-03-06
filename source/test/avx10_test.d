module avx10_test;

import std.stdio;
import std.string;
import std.algorithm;
import std.stdint;
import std.exception;

import xbyak;
import test.test_count;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

version(XBYAK64)
{
	// ymm with sae is not supported from avx10.2 rev 4.0.
	@("ymm_with_sae")
	unittest{
		ymm_with_sae();
	}

	void ymm_with_sae()
	{
		scope tc = TestCount(__FUNCTION__);
		class Code : CodeGenerator
		{
			void genA() { vaddpd(ymm1, ymm2, ymm3 | T_rn_sae); }
			void genB() { vcvtph2ibs(xmm1, xmm31 | T_rd_sae); }

			void genD() { vcvtph2ibs(ymm1, ymm31 | T_rd_sae); }
			void genE() { vcvt2ps2phx(ymm1, ymm2, ymm3 | T_rd_sae); }
			void genF() { vminmaxpd(ymm1, ymm2, ymm3 | T_sae, 1); }
			void genG() { vminmaxph(ymm1, ymm2, ymm3 | T_sae, 2); }
			void genH() { vminmaxps(ymm1, ymm2, ymm3 | T_sae, 3); }
			void genI() { vcvtps2ibs(ym1, ym2|T_rd_sae); }
			void genJ() { vcvtps2ibs(xm1, xm2|T_rd_sae); }
		}

		scope code = new Code();
		tc.TEST_EXCEPTION!Exception({ code.genA(); });
		tc.TEST_EXCEPTION!Exception({ code.genB(); });

		tc.TEST_EXCEPTION!Exception({ code.genD(); });
		tc.TEST_EXCEPTION!Exception({ code.genE(); });
		tc.TEST_EXCEPTION!Exception({ code.genF(); });
		tc.TEST_EXCEPTION!Exception({ code.genG(); });
		tc.TEST_EXCEPTION!Exception({ code.genH(); });
		tc.TEST_EXCEPTION!Exception({ code.genI(); });
		tc.TEST_EXCEPTION!Exception({ code.genJ(); });
	}


	@("vmpsadbw")
	unittest{
		vmpsadbw();
	}

	void vmpsadbw()
	{
		scope tc = TestCount(__FUNCTION__);
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
		tc.TEST_EQUAL(c.getSize(), n);
		auto ctbl = c.getCode();
		for(int i=0; i < n; i++)
		{
			tc.TEST_EQUAL(ctbl[i], tbl[i]);
		}
	}

}