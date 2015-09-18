module xbyak4d_cpuid;
import std.stdio;

alias ulong uint64;
enum  Type : uint64 {
	NONE          = 0,
	tMMX          = 1 << 0,     //mmx(), //amdMmx()
	tMMX2         = 1 << 1,
	tCMOV         = 1 << 2,     //hasCmov()
	tSSE          = 1 << 3,     //sse()
	tSSE2         = 1 << 4,     //sse2()
	tSSE3         = 1 << 5,     //sse3()
	tSSSE3        = 1 << 6,     //ssse3()
	tSSE41        = 1 << 7,     //sse41()
	tSSE42        = 1 << 8,     //sse42()
	tPOPCNT       = 1 << 9,     //hasPopcnt()
	tAESNI        = 1 << 10,    //aes()
	tSSE5         = 1 << 11,    //??
	tOSXSAVE      = 1 << 12,    //OSXSAVE_BIT
	tPCLMULQDQ    = 1 << 13,    //hasPclmulqdq()
	tAVX          = 1 << 14,    //avx()
	tFMA          = 1 << 15,    //fma()

	t3DN          = 1 << 16,    //amd3dnow()
	tE3DN         = 1 << 17,    //amd3dnowExt()
	tSSE4a        = 1 << 18,    //sse4a()
	tRDTSCP       = 1 << 19,    //RDTSCP_BIT
	tAVX2         = 1 << 20,    //avx2()
	tBMI1         = 1 << 21,    //andn, bextr, blsi, blsmsk, blsr, tzcnt //BMI1_BIT
	tBMI2         = 1 << 22,    //bzhi, mulx, pdep, pext, rorx, sarx, shlx, shrx //BMI2_BIT
	tLZCNT        = 1 << 23,    //hasLzcnt()

	tINTEL        = 1 << 24,
	tAMD          = 1 << 25,

	tENHANCED_REP = 1 << 26,            //enhanced rep movsb/stosb //ERMS_BIT
	tRDRAND       = 1 << 27,            //hasRdrand()
	tADX          = 1 << 28,            //adcx, adox //EAX=7 bit<<19
	tRDSEED       = 1 << 29,            //rdseed //hasRdseed()
	tSMAP         = 1 << 30,            //stac //EAX=7 bit<<20
	tHLE          = 1 << 31,            //xacquire, xrelease, xtest //hle()
	tRTM          = uint64(1) << 32,    //xbegin, xend, xabort //rtm()
	tF16C         = uint64(1) << 33,    //vcvtph2ps, vcvtps2ph //fp16c()
	tMOVBE        = uint64(1) << 34     //mobve //bit<22
}

class CpuId {
	uint64 type_;
	uint get32bitAsBE(string x)
	{
		return (x[0] | (x[1] << 8) | (x[2] << 16) | (x[3] << 24));
	}

	uint mask(int n)
	{
		return ((1U << n) - 1);
	}

	void setFamily()
	{
		uint data[4];

		data = getCpuid(1);
		stepping = data[0] & mask(4);
		model = (data[0] >> 4) & mask(4);
		family = (data[0] >> 8) & mask(4);
		// type = (data[0] >> 12) & mask(2);
		extModel = (data[0] >> 16) & mask(4);
		extFamily = (data[0] >> 20) & mask(8);
		if (family == 0x0f) {
			displayFamily = family + extFamily;
		}else {
			displayFamily = family;
		}
		if ((family == 6) || (family == 0x0f)) {
			displayModel = (extModel << 4) + model;
		}else {
			displayModel = model;
		}
	}

public:
	int model;
	int family;
	int stepping;
	int extModel;
	int extFamily;
	int displayFamily;      // family + extFamily
	int displayModel;       // model + extModel

	uint[4] getCpuid(uint eaxIn)
	{
		uint d1, d2, d3, d4;
		asm
		{
			mov EAX, eaxIn;
			cpuid;
			mov d1, EAX;
			mov d2, EBX;
			mov d3, ECX;
			mov d4, EDX;
		}
		return [d1, d2, d3, d4];
	}

	uint[4] getCpuidEx(uint eaxIn, uint ecxIn)
	{
		uint d1, d2, d3, d4;
		asm
		{
			mov EAX, eaxIn;
			mov ECX, ecxIn;
			cpuid;
			mov d1, EAX;
			mov d2, EBX;
			mov d3, ECX;
			mov d4, EDX;
		}
		return [d1, d2, d3, d4];
	}

	uint64 getXfeature()
	{
		uint d, a;
		asm
		{
			mov ECX, 0;
			xgetbv;
			mov d, EDX;
			mov a, EAX;
		}
		return (cast(uint64) d << 32 | a);
	}

	this()
	{
		type_ = Type.NONE;
		uint data[4];
		data = getCpuid(0);
		uint maxNum = data[0];
		string intel = "ntel";
		string amd = "cAMD";
		if (data[2] == get32bitAsBE(amd)) {
			type_ |= Type.tAMD;
			data = getCpuid(0x80000001);
			if (data[3] & (1U << 31)) {
				type_ |= Type.t3DN;
			}
			if (data[3] & (1U << 15)) {
				type_ |= Type.tCMOV;
			}
			if (data[3] & (1U << 30)) {
				type_ |= Type.tE3DN;
			}
			if (data[3] & (1U << 22)) {
				type_ |= Type.tMMX2;
			}
			if (data[3] & (1U << 27)) {
				type_ |= Type.tRDTSCP;
			}
		}
		if (data[2] == get32bitAsBE(intel)) {
			type_ |= Type.tINTEL;
			data = getCpuid(0x80000001);
			if (data[3] & (1U << 27)) {
				type_ |= Type.tRDTSCP;
			}
			if (data[2] & (1U << 5)) {
				type_ |= Type.tLZCNT;
			}
		}
		data = getCpuid(1);
		if (data[2] & (1U << 0)) {
			type_ |= Type.tSSE3;
		}
		if (data[2] & (1U << 9)) {
			type_ |= Type.tSSSE3;
		}
		if (data[2] & (1U << 19)) {
			type_ |= Type.tSSE41;
		}
		if (data[2] & (1U << 20)) {
			type_ |= Type.tSSE42;
		}
		if (data[2] & (1U << 22)) {
			type_ |= Type.tMOVBE;
		}
		if (data[2] & (1U << 23)) {
			type_ |= Type.tPOPCNT;
		}
		if (data[2] & (1U << 25)) {
			type_ |= Type.tAESNI;
		}
		if (data[2] & (1U << 1)) {
			type_ |= Type.tPCLMULQDQ;
		}
		if (data[2] & (1U << 27)) {
			type_ |= Type.tOSXSAVE;
		}
		if (data[2] & (1U << 30)) {
			type_ |= Type.tRDRAND;
		}
		if (data[2] & (1U << 29)) {
			type_ |= Type.tF16C;
		}

		if (data[3] & (1U << 15)) {
			type_ |= Type.tCMOV;
		}
		if (data[3] & (1U << 23)) {
			type_ |= Type.tMMX;
		}
		if (data[3] & (1U << 25)) {
			type_ |= Type.tMMX2 | Type.tSSE;
		}
		if (data[3] & (1U << 26)) {
			type_ |= Type.tSSE2;
		}

		if (type_ & Type.tOSXSAVE) {
			// check XFEATURE_ENABLED_MASK[2:1] = '11b'
			uint64 bv = getXfeature();
			if ((bv & 6) == 6) {
				if (data[2] & (1U << 28)) {
					type_ |= Type.tAVX;
				}
				if (data[2] & (1U << 12)) {
					type_ |= Type.tFMA;
				}
			}
		}
		if (maxNum >= 7) {
			data = getCpuidEx(7, 0);
			if (type_ & Type.tAVX && data[1] & 0x20) {
				type_ |= Type.tAVX2;
			}
			if (data[1] & (1U << 3)) {
				type_ |= Type.tBMI1;
			}
			if (data[1] & (1U << 8)) {
				type_ |= Type.tBMI2;
			}
			if (data[1] & (1U << 9)) {
				type_ |= Type.tENHANCED_REP;
			}
			if (data[1] & (1U << 18)) {
				type_ |= Type.tRDSEED;
			}
			if (data[1] & (1U << 19)) {
				type_ |= Type.tADX;
			}
			if (data[1] & (1U << 20)) {
				type_ |= Type.tSMAP;
			}
			if (data[1] & (1U << 4)) {
				type_ |= Type.tHLE;
			}
			if (data[1] & (1U << 11)) {
				type_ |= Type.tRTM;
			}
		}
		setFamily();
	}
	void putFamily()
	{
		writefln("family=%d, model=%X, stepping=%X, extFamily=%d, extModel=%X", family, model, stepping, extFamily, extModel);
		writefln("display:family=%X, model=%X", displayFamily, displayModel);
	}

	bool has(Type type)
	{
		return ((type & type_) != 0);
	}
}
