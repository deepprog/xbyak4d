module test_util;

import std.stdio;
import core.stdc.string;
import xbyak_util;

version(XBYAK_ONLY_CLASS_CPU)
{}
else
{
	import xbyak;
	class PopCountTest : CodeGenerator
	{
		this(const int n)
		{
			super(4096, DontSetProtectRWE);
			mov(eax, n);
			popcnt(eax, eax);
			ret();
		}
	}
}

void putCPUinfo(bool onlyCpuidFeature)
{
	Cpu cpu = new Cpu();
	writefln("vendor %s\n", cpu.has(Cpu.tINTEL) ? "intel" : "amd");
	
	struct Tbl
	{
		Cpu.Type type;
		const char* str;
	}
	
	Tbl[] tbl = [
		Tbl(Cpu.tMMX, "mmx" ),
		Tbl(Cpu.tMMX2, "mmx2" ),
		Tbl(Cpu.tCMOV, "cmov" ),
		Tbl(Cpu.tSSE, "sse" ),
		Tbl(Cpu.tSSE2, "sse2" ),
		Tbl(Cpu.tSSE3, "sse3" ),
		Tbl(Cpu.tSSSE3, "ssse3" ),
		Tbl(Cpu.tSSE41, "sse41" ),
		Tbl(Cpu.tSSE42, "sse42" ),
		Tbl(Cpu.tSSE4a, "sse4a" ),
		Tbl(Cpu.tPOPCNT, "popcnt" ),
		Tbl(Cpu.t3DN, "3dn" ),
		Tbl(Cpu.tE3DN, "e3dn" ),
		Tbl(Cpu.tAESNI, "aesni" ),
		Tbl(Cpu.tRDTSCP, "rdtscp" ),
		Tbl(Cpu.tXSAVE, "xsave(xgetvb)" ),
		Tbl(Cpu.tOSXSAVE, "osxsave" ),
		Tbl(Cpu.tPCLMULQDQ, "pclmulqdq" ),
		Tbl(Cpu.tAVX, "avx" ),
		Tbl(Cpu.tFMA, "fma" ),
		Tbl(Cpu.tAVX2, "avx2" ),
		Tbl(Cpu.tBMI1, "bmi1" ),
		Tbl(Cpu.tBMI2, "bmi2" ),
		Tbl(Cpu.tLZCNT, "lzcnt" ),
		Tbl(Cpu.tPREFETCHW, "prefetchw" ),
		Tbl(Cpu.tENHANCED_REP, "enh_rep" ),
		Tbl(Cpu.tRDRAND, "rdrand" ),
		Tbl(Cpu.tADX, "adx" ),
		Tbl(Cpu.tRDSEED, "rdseed" ),
		Tbl(Cpu.tSMAP, "smap" ),
		Tbl(Cpu.tHLE, "hle" ),
		Tbl(Cpu.tRTM, "rtm" ),
		Tbl(Cpu.tMPX, "mpx" ),
		Tbl(Cpu.tSHA, "sha" ),
		Tbl(Cpu.tPREFETCHWT1, "prefetchwt1" ),
		Tbl(Cpu.tF16C, "f16c" ),
		Tbl(Cpu.tMOVBE, "movbe" ),
		Tbl(Cpu.tAVX512F, "avx512f" ),
		Tbl(Cpu.tAVX512DQ, "avx512dq" ),
		Tbl(Cpu.tAVX512IFMA, "avx512_ifma" ),
		Tbl(Cpu.tAVX512PF, "avx512pf" ),
		Tbl(Cpu.tAVX512ER, "avx512er" ),
		Tbl(Cpu.tAVX512CD, "avx512cd" ),
		Tbl(Cpu.tAVX512BW, "avx512bw" ),
		Tbl(Cpu.tAVX512VL, "avx512vl" ),
		Tbl(Cpu.tAVX512VBMI, "avx512_vbmi" ),
		Tbl(Cpu.tAVX512_4VNNIW, "avx512_4vnniw" ),
		Tbl(Cpu.tAVX512_4FMAPS, "avx512_4fmaps" ),

		Tbl(Cpu.tAVX512_VBMI2, "avx512_vbmi2" ),
		Tbl(Cpu.tGFNI, "gfni" ),
		Tbl(Cpu.tVAES, "vaes" ),
		Tbl(Cpu.tVPCLMULQDQ, "vpclmulqdq" ),
		Tbl(Cpu.tAVX512_VNNI, "avx512_vnni" ),
		Tbl(Cpu.tAVX512_BITALG, "avx512_bitalg" ),
		Tbl(Cpu.tAVX512_VPOPCNTDQ, "avx512_vpopcntdq" ),
		Tbl(Cpu.tAVX512_BF16, "avx512_bf16" ),
		Tbl(Cpu.tAVX512_VP2INTERSECT, "avx512_vp2intersect" ),
		Tbl(Cpu.tAMX_TILE, "amx(tile)" ),
		Tbl(Cpu.tAMX_INT8, "amx(int8)" ),
		Tbl(Cpu.tAMX_BF16, "amx(bf16)" ),
		Tbl(Cpu.tAVX_VNNI, "avx_vnni" ),
		Tbl(Cpu.tAVX512_FP16, "avx512_fp16" ),
		Tbl(Cpu.tWAITPKG, "waitpkg" ),
		Tbl(Cpu.tCLFLUSHOPT, "clflushopt" ),
		Tbl(Cpu.tCLDEMOTE, "cldemote" ),
		Tbl(Cpu.tCLWB, "clwb" ),
		Tbl(Cpu.tMOVDIRI, "movdiri" ),
		Tbl(Cpu.tMOVDIR64B, "movdir64b" ),
		Tbl(Cpu.tUINTR, "uintr" ),
		Tbl(Cpu.tSERIALIZE, "serialize" ),
		Tbl(Cpu.tCLZERO, "clzero" ),
		Tbl(Cpu.tAMX_FP16, "amx_fp16" ),
		Tbl(Cpu.tAVX_VNNI_INT8, "avx_vnni_int8" ),
		Tbl(Cpu.tAVX_NE_CONVERT, "avx_ne_convert" ),
		Tbl(Cpu.tAVX_IFMA, "avx_ifma" ),
		Tbl(Cpu.tRAO_INT, "rao-int" ),
		Tbl(Cpu.tCMPCCXADD, "cmpccxadd" ),
		Tbl(Cpu.tPREFETCHITI, "prefetchiti" ),
		Tbl(Cpu.tSHA512, "sha512" ),
		Tbl(Cpu.tSM3, "sm3" ),
		Tbl(Cpu.tSM4, "sm4" ),
		Tbl(Cpu.tAVX_VNNI_INT16, "avx_vnni_int16" ),
		Tbl(Cpu.tAPX_F, "apx_f" ),
		Tbl(Cpu.tAVX10, "avx10" ),
		Tbl(Cpu.tAESKLE, "aeskle" ),
		Tbl(Cpu.tWIDE_KL, "wide_kl" ),
		Tbl(Cpu.tKEYLOCKER, "keylocker" ),
		Tbl(Cpu.tKEYLOCKER_WIDE, "keylocker_wide" ),
		Tbl(Cpu.tTSXLDTRK, "tsxldtrk" ),
		Tbl(Cpu.tAMX_FP8, "amx_fp8" ),
		Tbl(Cpu.tAMX_TRANSPOSE, "amx_transpose" ),
		Tbl(Cpu.tAMX_TF32, "amx_tf32" ),
		Tbl(Cpu.tAMX_AVX512, "amx_avx512" ),
		Tbl(Cpu.tAMX_MOVRS, "amx_movrs" ),
		Tbl(Cpu.tMOVRS, "movrs" ),
	];

	for (size_t i = 0; i < tbl.length; i++) {
		if (cpu.has(tbl[i].type)) printf(" %s", tbl[i].str);
	}
	printf("\n");
	if (onlyCpuidFeature) return;
	if (cpu.has(Cpu.tAVX10)) {
		printf("AVX10 version %d\n", cpu.getAVX10version());
	}

version(XBYAK_ONLY_CLASS_CPU)
{}
else
{
	if (cpu.has(Cpu.tPOPCNT)) {
		const int n = 0x12345678; // bitcount = 13
		const int ok = 13;
		PopCountTest code = new PopCountTest(n);
		code.setProtectModeRE();
		auto f = code.getCode!(int function())();
		int r = f();
		if (r == ok) {
			puts("popcnt ok");
		} else {
			printf("popcnt ng %d %d\n", r, ok);
		}
		code.setProtectModeRW();
	}
}

	/*
		                displayFamily displayModel
		Opteron 2376        10            4
		Core2 Duo T7100      6            F
		Core i3-2120T        6           2A
		Core i7-2600         6           2A
		Xeon X5650           6           2C
		Core i7-3517         6           3A
		Core i7-3930K        6           2D
	*/
	cpu.putFamily();
	for (uint i = 0; i < cpu.getDataCacheLevels(); i++) {
		printf("cache level=%u data cache size=%u cores sharing data cache=%u\n", i, cpu.getDataCacheSize(i), cpu.getCoresSharingDataCache(i));
	}
	printf("SmtLevel =%u\n", cpu.getNumCores(SmtLevel));
	printf("CoreLevel=%u\n", cpu.getNumCores(CoreLevel));
}

extern(C) int main(int argc, char** argv)
{
	bool onlyCpuidFeature = argc == 2 && strcmp(argv[1], "-cpuid") == 0;
	if (!onlyCpuidFeature) {
  version(XBYAK32)
  {
		puts("32bit");
  }
  else
  {
		puts("64bit");
  }
	}
	putCPUinfo(onlyCpuidFeature);
	return 0;
}
