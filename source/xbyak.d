/**
 * xbyak for the D programming language
 * Version: 0.0940
 * Date: 2020/04/10
 * See_Also:
 * Copyright: Copyright (c) 2007 MITSUNARI Shigeo, Copyright deepprog 2019
 * License: <http://opensource.org/licenses/BSD-3-Clause>BSD-3-Clause</a>.
 * Authors: herumi, deepprog
 */

module xbyak;

version(X86)
{
	version = XBYAK32;
}

version(X86_64)
{
	version = XBYAK64;
}

//version = XBYAK_ENABLE_OMITTED_OPERAND;
//version = XBYAK_DISABLE_AVX512;

import std.stdio;
import std.array;
import std.string;
import std.algorithm;
import std.conv;

version (Windows)
{
	import core.sys.windows.windows;  // VirtualProtect
}

version (linux)
{
    import core.sys.posix.sys.mman;
}

size_t	DEFAULT_MAX_CODE_SIZE = 4096 * 8;
size_t	VERSION               = 0x0099;  // 0xABCD = A.BC(D)

alias uint64 = ulong ;
alias sint64 = long;
alias int32  = int;
alias uint32 = uint;
alias uint16 = ushort;
alias uint8  = ubyte;

// MIE_ALIGN
T MIE_PACK(T)(T x, T y, T z, T W)
{
	return x * 64 + y * 16 + z * 4 + w;
}

enum ERR
{
	NONE = 0,
	BAD_ADDRESSING,
	CODE_IS_TOO_BIG,
	BAD_SCALE,
	ESP_CANT_BE_INDEX,
	BAD_COMBINATION,
	BAD_SIZE_OF_REGISTER,
	IMM_IS_TOO_BIG,
	BAD_ALIGN,
	LABEL_IS_REDEFINED,
	LABEL_IS_TOO_FAR,
	LABEL_IS_NOT_FOUND,
	CODE_ISNOT_COPYABLE,
	BAD_PARAMETER,
	CANT_PROTECT,
	CANT_USE_64BIT_DISP,
	OFFSET_IS_TOO_BIG,
	MEM_SIZE_IS_NOT_SPECIFIED,
	BAD_MEM_SIZE,
	BAD_ST_COMBINATION,
	OVER_LOCAL_LABEL, // not used
	UNDER_LOCAL_LABEL,
	CANT_ALLOC,
	ONLY_T_NEAR_IS_SUPPORTED_IN_AUTO_GROW,
	BAD_PROTECT_MODE,
	BAD_PNUM,
	BAD_TNUM,
	BAD_VSIB_ADDRESSING,
	CANT_CONVERT,
	LABEL_ISNOT_SET_BY_L,
	LABEL_IS_ALREADY_SET_BY_L,
	BAD_LABEL_STR,
	MUNMAP,
	OPMASK_IS_ALREADY_SET,
	ROUNDING_IS_ALREADY_SET,
	K0_IS_INVALID,
	EVEX_IS_INVALID,
	SAE_IS_INVALID,
	ER_IS_INVALID,
	INVALID_BROADCAST,
	INVALID_OPMASK_WITH_MEMORY,
	INVALID_ZERO,
	INVALID_RIP_IN_AUTO_GROW,
	INVALID_MIB_ADDRESS,
	X2APIC_IS_NOT_SUPPORTED,
	INTERNAL	// Put it at last.
}

class XError : Exception
{
	int err_;
public:
	this(ERR err = ERR.NONE, string file = __FILE__, size_t line = __LINE__, Throwable next = null)
	{
		err_ = cast(int) err;
		if (err_ < 0 || err_ > ERR.INTERNAL)
		{
			err_ = ERR.INTERNAL;
		}
		super(this.what(), file, line, next);
	}

	int opCast(T : int)() const {
		return err_;
	}

	string what() const
	{
		string[] errTbl =
		[
			"none",
			"bad addressing",
			"code is too big",
			"bad scale",
			"esp can't be index",
			"bad combination",
			"bad size of register",
			"imm is too big",
			"bad align",
			"label is redefined",
			"label is too far",
			"label is not found",
			"code is not copyable",
			"bad parameter",
			"can't protect",
			"can't use 64bit disp(use (void*))",
			"offset is too big",
			"MEM size is not specified",
			"bad mem size",
			"bad st combination",
			"over local label",
			"under local label",
			"can't alloc",
			"T_SHORT is not supported in AutoGrow",
			"bad protect mode",
			"bad pNum",
			"bad tNum",
			"bad vsib addressing",
			"can't convert",
			"label is not set by L()",
			"label is already set by L()",
			"bad label string",
			"err munmap",
			"opmask is already set",
			"rounding is already set",
			"k0 is invalid",
			"evex is invalid",
			"sae(suppress all exceptions) is invalid",
			"er(embedded rounding) is invalid",
			"invalid broadcast",
			"invalid opmask with memory",
			"invalid zero",
			"invalid rip in AutoGrow",
			"invalid mib address",
			"x2APIC is not supported",
			"internal error"
		];

		assert(err_ <= ERR.INTERNAL);
		assert(ERR.INTERNAL + 1 == errTbl.length);
		return errTbl[err_];
	}
}

string ConvertErrorToString(XError err) {
	return err.what();
}

To CastTo(To, From)(From p)
{
	return cast(To) (p);
}

struct inner
{
	static :
	const size_t ALIGN_PAGE_SIZE = 4096;
	bool IsInDisp8(uint32 x)	{	return 0xFFFFFF80 <= x || x <= 0x7F; }
	bool IsInDisp16(uint32 x)	{	return 0xFFFF8000 <= x || x <= 0x7FFF;	}
	bool IsInInt32(uint64 x)    {	return (int32.min <= x) || (x <= int32.max); }

	uint32 VerifyInInt32(uint64 x)
	{
		version (XBYAK64)
		{
			if (!IsInInt32(x))	throw new XError(ERR.OFFSET_IS_TOO_BIG);
		}
		return cast(uint32)x;
	}

	enum LabelMode
	{
		LasIs, // as is
		Labs, // absolute
		LaddTop // (addr + top) for mov(reg, label) with AutoGrow
	}
}// inner


void* getAlignedAddress(void* addr, size_t alignedSize = 16)
{
	size_t mask = alignedSize - 1;
	return cast(void*) ((cast(size_t) addr + mask) & ~mask);
}

// custom allocator

class Allocator
{

version(Windows)
{
	uint8* alloc(size_t size)
	{
        size_t alignment = inner.ALIGN_PAGE_SIZE;
		static import core.memory;
        void* mp = core.memory.GC.malloc(size + alignment);    
        assert(mp);	
		SizeTbl[mp] = size + alignment;
		MemTbl[mp]  = getAlignedAddress(mp, alignment);
		return cast(uint8*)MemTbl[mp];
	}
	
	void free(uint8* p)
	{
		//core.memory.GC.free(MemTbl[p]);
	}
}

version(linux)
{
	uint8* alloc(size_t size)
	{
		const size_t alignedSizeM1 = inner.ALIGN_PAGE_SIZE - 1;
		size = (size + alignedSizeM1) & ~alignedSizeM1;
	
        const int mode = MAP_PRIVATE | MAP_ANON;
		const int prot = PROT_EXEC | PROT_READ | PROT_WRITE;
        void* mp = mmap(null, size, prot, mode, -1, 0);

		if (mp == MAP_FAILED) throw new XError(ERR.CANT_ALLOC);
		assert(mp);
        size_t alignment = inner.ALIGN_PAGE_SIZE;	
		SizeTbl[mp] = size + alignment;
		MemTbl[mp]  = getAlignedAddress(mp, alignment);
		return cast(uint8*)MemTbl[mp];
    	}
    
    void free(uint8 *p)
	{
		if(p == null) return;
		void* ret = MemTbl[p];
		size_t size  = SizeTbl[p];

		if (munmap(ret, size) < 0)
		{
			throw new XError(ERR.MUNMAP);
		}
		MemTbl.remove(p);
		SizeTbl.remove(p);
	}
}
	/* override to return false if you call protect() manually */
	bool useProtect() { return true; }
	
static:
	void*[void*] MemTbl;
	size_t[void*] SizeTbl;	
}


enum Kind
{
	NONE = 0,
	MEM = 1 << 0,
	REG = 1 << 1,
	MMX = 1 << 2,
	FPU = 1 << 3,
	XMM = 1 << 4,
	YMM = 1 << 5,
	ZMM = 1 << 6,
	OPMASK = 1 << 7,
	BNDREG = 1 << 8
}

public class Operand {
private:
	static const uint8 EXT8BIT = 0x20;
	uint idx_ = 6; // 0..31 + EXT8BIT = 1 if spl/bpl/sil/dil
	uint kind_=9;
	uint bit_=10;

protected:
	bool zero_= true;
	uint mask_=3;
	uint rounding_ = 3;
	void setIdx(int idx) { idx_ = idx; }

public:
	
version(XBYAK64){
	enum : int //Code
	{
        RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15,
		R8D = 8, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
		R8W = 8, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
		R8B = 8, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
		SPL = 4, BPL, SIL, DIL,
		EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
		AX  = 0, CX, DX, BX, SP, BP, SI, DI,
		AL  = 0, CL, DL, BL, AH, CH, DH, BH
	}
}

version(XBYAK32){
	enum : int //Code 
	{
		EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
		AX  = 0, CX, DX, BX, SP, BP, SI, DI,
		AL  = 0, CL, DL, BL, AH, CH, DH, BH
	}
}


	this()
	{
		idx_ = 0;
		kind_ = 0;
		bit_ = 0;
		zero_ = 0;
		mask_ = 0;
		rounding_ =0;
	}
	this(int idx, int kind, int bit =0, bool ext8bit = 0)
	{
		idx_ = cast(uint8)(idx | (ext8bit ? EXT8BIT : 0));
		kind_ = kind;
		bit_  = bit;
		zero_ = 0;
		mask_ = 0;
		rounding_ =0;
		assert((bit_ & (bit_ - 1)) == 0); // bit must be power of two
	}

	int getKind() const {	return kind_;	}
	int  getIdx () const {	return cast(int) idx_ & 15;}
	bool isNone () const {	return (kind_ == Kind.NONE); }
	bool isMMX  () const {	return isKind(Kind.MMX);}
	bool isXMM  () const {	return isKind(Kind.XMM);}
	bool isYMM  () const {	return isKind(Kind.YMM);}
	bool isZMM() const { return isKind(Kind.ZMM); }
	bool isXMEM() const { return isKind(Kind.XMM | Kind.MEM); }
	bool isYMEM() const { return isKind(Kind.YMM | Kind.MEM); }
	bool isZMEM() const { return isKind(Kind.ZMM | Kind.MEM); }
	bool isOPMASK() const { return isKind(Kind.OPMASK); }
	bool isBNDREG() const { return isKind(Kind.BNDREG); }
	bool isREG(int bit = 0) const {	return isKind(Kind.REG, bit);	}
	bool isMEM(int bit = 0) const {	return isKind(Kind.MEM, bit);	}
	bool isFPU  () const {	return isKind(Kind.FPU);}
	bool isExt8bit() const {	return (idx_ & EXT8BIT) != 0;	}
	bool isExtIdx() const { return (getIdx() & 8) != 0; }
	bool isExtIdx2() const { return (getIdx() & 16) != 0; }
	bool hasEvex() const { return isZMM() || isExtIdx2() || getOpmaskIdx() || getRounding(); }
	bool hasRex() const { return isExt8bit() || isREG(64) || isExtIdx(); }
	bool hasZero() const { return zero_; }
	int getOpmaskIdx() const { return mask_; }
	int getRounding() const { return rounding_; }
	
	void setKind(int kind)
	{
		if ((kind & (Kind.XMM | Kind.YMM | Kind.ZMM)) == 0) return;
		kind_ = kind;
		bit_ = kind == Kind.XMM ? 128 : kind == Kind.YMM ? 256 : 512;
	}
	// err if MMX/FPU/OPMASK/BNDREG
	void setBit(int bit)
	{
	if (bit != 8 && bit != 16 && bit != 32 && bit != 64 && bit != 128 && bit != 256 && bit != 512) goto ERR;
	if (isBit(bit)) return;
	if (isKind(Kind.MEM | Kind.OPMASK)) {
		this.bit_ = bit;
		return;
	}
	if (isKind(Kind.REG | Kind.XMM | Kind.YMM | Kind.ZMM)) {
		int idx = getIdx;
		// err if converting ah, bh, ch, dh
		if (isREG(8) && (4 <= idx && idx < 8) && !isExt8bit) goto ERR;
		int kind = Kind.REG;
		switch (bit)
		{
			case 8:
				if (idx >= 16) goto ERR;

	version(XBYAK32){
				if (idx >= 4) goto ERR;
	}else{
				if (4 <= idx && idx < 8) idx |= EXT8BIT;
	}
				break;
			case 16:
			case 32:
			case 64:
				if (idx >= 16) goto ERR;
				break;
			case 128: kind = Kind.XMM; break;
			case 256: kind = Kind.YMM; break;
			case 512: kind = Kind.ZMM; break;
			default:	break;
		}
		idx_ = idx;
		kind_ = kind;
		bit_ = bit;
		if (bit >= 128) return; // keep mask_ and rounding_
		mask_ = 0;
		rounding_ = 0;
		return;
	}
ERR:
	throw new XError(ERR.CANT_CONVERT);
}
		
	void setOpmaskIdx(int idx, bool ignore_idx0 = false)
	{
		if (!ignore_idx0 && idx == 0) throw new XError(ERR.K0_IS_INVALID);
		if (mask_) throw new XError(ERR.OPMASK_IS_ALREADY_SET);
		mask_ = idx;
	}
	void setRounding(int idx)
	{
		if (rounding_) throw new XError(ERR.ROUNDING_IS_ALREADY_SET);
		rounding_ = idx;
	}
	void setZero() { zero_ = true; }
	

// ah, ch, dh, bh?
	bool isHigh8bit() const
	{
		if (!isBit(8))	return false;
		if (isExt8bit()) return false;
		const int idx = getIdx();
		return Operand.AH <= idx && idx <= Operand.BH;
	}

// any bit is accetable if bit == 0
	bool isKind(int kind, uint32 bit = 0) const
	{
		return (kind == 0 || (kind_ & kind)) && (bit == 0 || (bit_ & bit)); // cf. you can set (8|16)
	}
	bool isBit(uint32 bit) const { return (bit_ & bit) != 0;	}
	uint32 getBit() const { return bit_;}


	override string toString() const
	{
		int idx = getIdx;
		if (kind_ == Kind.REG)
		{
			if (isExt8bit())
			{
				string[] tbl = [ "spl", "bpl", "sil", "dil" ];
				return tbl[idx - 4];
			}
	
			
			string[][] tbl = [
			        [ "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b" ],
			        [ "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" ],
			        [ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" ],
			        [ "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" ],
			];
			return tbl[bit_ == 8 ? 0 : bit_ == 16 ? 1 : bit_ == 32 ? 2 : 3][idx];
		}
		else if (isOPMASK)
		{
			string[] tbl = [ 
			"k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"];
			return tbl[idx];
		}
		else if (isZMM)
		{
			string[] tbl = [ 
			"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", 
			"10", "11", "12", "13", "14", "15" ,"16", "17", "18","19",
			"20", "21", "22", "23", "24", "25" ,"26", "27", "28","29",
			"30", "31" ];
			return "zmm" ~ tbl[idx];
		
		}
		else if (isYMM)
		{
			string[] tbl = [ 
			"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", 
			"10", "11", "12", "13", "14", "15" ,"16", "17", "18","19",
			"20", "21", "22", "23", "24", "25" ,"26", "27", "28","29",
			"30", "31" ];
			return "ymm" ~ tbl[idx];
		}
		else if (isXMM)
		{
			string[] tbl = [ 
			"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", 
			"10", "11", "12", "13", "14", "15" ,"16", "17", "18","19",
			"20", "21", "22", "23", "24", "25" ,"26", "27", "28","29",
			"30", "31" ];
			return "xmm" ~ tbl[idx];
		}
		else if (isMMX)
		{
			string[] tbl = [ "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7" ];
			return tbl[idx];
		}
		else if (isFPU)
		{
			string[] tbl = [ "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7" ];
			return tbl[idx];
		}
		else if (isBNDREG())
		{
			string[] tbl = [ "bnd0", "bnd1", "bnd2", "bnd3" ];
			return tbl[idx];
		}
		throw new XError(ERR.INTERNAL);
	}

	bool isEqualIfNotInherited(Operand rhs) const
	{
		return idx_ == rhs.idx_ && kind_ == rhs.kind_ && bit_ == rhs.bit_ && zero_ == rhs.zero_ && mask_ == rhs.mask_ && rounding_ == rhs.rounding_;
	}

	override bool opEquals(Object o) const
	{
		auto rhs = cast(Operand) o;
		if(rhs is null) return false;
			
		if (isMEM() && rhs.isMEM()) return this.getAddress() == rhs.getAddress();
		return isEqualIfNotInherited(rhs);
	}

	Address getAddress() const
	{
		assert(isMEM());
		Address ret = cast(Address)this;
		return ret;
	}
	
	Reg getReg()
	{
		assert(!isMEM());
		Reg ret = new Reg(this.getIdx(), this.kind_, this.bit_, this.isExt8bit() ) ;		////fix
		return ret;
	}	
}


public class Reg : Operand {
public:
	this(){}
	this(int idx, int kind, int bit = 0, bool ext8bit = false)
	{
		super(idx, kind, bit, ext8bit);
	}
	// convert to Reg8/Reg16/Reg32/Reg64/XMM/YMM/ZMM
	Reg changeBit(int bit)
	{
		this.setBit(bit);
		return this;
	}
	
	uint8 getRexW() const { return isREG(64) ? 8 : 0; }
	uint8 getRexR() const { return isExtIdx() ? 4 : 0; }
	uint8 getRexX() const { return isExtIdx() ? 2 : 0; }
	uint8 getRexB() const { return isExtIdx() ? 1 : 0; }
	uint8 getRex(Reg base = new Reg())
	{
		uint8 rex = this.getRexW() | this.getRexR() | base.getRexW() | base.getRexB();
		if (rex || this.isExt8bit() || base.isExt8bit()) rex |= 0x40;
		return rex;
	}

	Reg8 cvt8()
	{
		Reg r = this.changeBit(8); return new Reg8(r.getIdx, r.isExt8bit);
	}
	
	Reg16 cvt16()
	{
		return new Reg16(changeBit(16).getIdx());
	}

	Reg32 cvt32()
	{
		return new Reg32(changeBit(32).getIdx());
	}

	version (XBYAK64)
	{
		Reg64 cvt64()
		{
			return new Reg64(changeBit(64).getIdx());
		}
	}	
}


public class Reg8 : Reg {
public:
	
	this(int idx = 0, bool ext8bit = false)
	{
		super(idx, Kind.REG, 8, ext8bit);
	}
}

public class Reg16 : Reg {
public:
	this(int idx = 0)
	{
		super(idx, Kind.REG, 16);
	}
}

public class Mmx : Reg {
public:
	this(int idx = 0, int kind = Kind.MMX, int bit = 64)
	{
		super(idx, kind, bit);
	}
}


class EvexModifierRounding {
	enum {
		T_RN_SAE = 1,
		T_RD_SAE = 2,
		T_RU_SAE = 3,
		T_RZ_SAE = 4,
		T_SAE = 5
	}
	
	this(int r)
	{
		rounding = r;
	}
	
	int rounding;
	
	T opBinaryRight(string op:"|", T)(T x)
	{		
		T r = new T();
		r.setRounding(this.rounding);
		return r;
	}
	
}

class EvexModifierZero
{

	T opBinaryRight(string op:"|", T)(T x)
	{
		T r = new T();
		r.setZero();
		return r;
	}
}


public class Xmm : Mmx {
public:
	this(int idx, int kind = Kind.XMM, int bit = 128)
	{
		super(idx, kind, bit);
	}
	
	RegExp opBinary(string op:"+") (Reg32e b)
	{
		return new RegExp(this) + new RegExp(b);
	}

	RegExp opBinaryRight(string op:"+") (Reg32e a)
	{
		return new RegExp(a) + new RegExp(this);
	}

	RegExp opBinary(string op:"*") (int scale)
	{
		return new RegExp(this, scale);
	}

	RegExp opBinary(string op:"+") (int disp)
	{
		return new RegExp(this) + disp;
	}
	
	
	Xmm opBinary(string op:"|") (EvexModifierRounding emr)
	{
		Xmm r = this;
		r.setRounding(emr.rounding);
		return r;
	}
	
	Xmm copyAndSetIdx(int idx)
	{
		Xmm ret = this;
		ret.setIdx(idx);
		return ret;
	}
	
	Xmm copyAndSetKind(int kind)
	{
		Xmm ret = this;
		ret.setKind(kind);
		return ret;
	}
}


public class Ymm : Xmm {
public:
	this(int idx = 0)
	{
		super(idx, Kind.YMM, 256);
	}
	
	Ymm opBinary(string op:"|")(EvexModifierRounding emr)
	{
		Ymm r = this;
		r.setRounding(emr.rounding);
		return r;
	}
	
	
	RegExp opBinary(string op:"+") (Reg32e b)
	{
		return new RegExp(this) + new RegExp(b);
	}

	RegExp opBinaryRight(string op:"+") (Reg32e a)
	{
		return new RegExp(a) + new RegExp(this);
	}

	RegExp opBinary(string op:"*") (int scale)
	{
		return new RegExp(this, scale);
	}

	RegExp opBinary(string op:"+") (int disp)
	{
		return new RegExp(this) + disp;
	}
}

public class Zmm : Xmm {
public:
	this(int idx = 0)
	{
		super(idx, Kind.ZMM, 512);
	}
	
	Zmm opBinary(string op:"|")(EvexModifierRounding emr)
	{
		Zmm r = this;
		r.setRounding(emr.rounding);
		return r;
	}
	
}

class Opmask : Reg {
	this(int idx = 0)
	{
		super(idx, Kind.OPMASK, 64);
	}
	
	T opBinaryRight(string op:"|", T)(T x)
	{
		T r = new T();
		r.setOpmaskIdx(k.getIdx());
		return r;
	}
}

class BoundsReg : Reg {
	this(int idx = 0)
	{
		super(idx, Kind.BNDREG, 128);
	}
}


public class Fpu : Reg {
public:
	this(int idx)
	{
		super(idx, Kind.FPU, 32);
	}
}


public class Reg32e : Reg {
	this(int idx, int bit)
	{
		super(idx, Kind.REG, bit);
	}
	
	RegExp opBinary(string op:"+") (Reg32e b)
	{
		return new RegExp(this) + new RegExp(b);
	}

	RegExp opBinary(string op:"*") (int scale)
	{
		return new RegExp(this, scale);
	}

	RegExp opBinary(string op:"+") (int disp)
	{
		return new RegExp(this) + disp;
	}

 	RegExp opBinaryRight(string op:"+") (int disp)
	{
		return new RegExp(this) + disp;
	}
}


public class Reg32 : Reg32e {
	this(int idx)
	{
		super(idx, 32);
	}
}

version (XBYAK64)
{
	public class Reg64 : Reg32e {
		this(int idx = 0)
		{
			super(idx, 64);
		}
	}

	struct RegRip
	{
		sint64 disp_ = 0;
		Label label_;
        bool isAddr_;
		
		this(sint64 disp, Label label = cast(Label)null, bool isAddr = false)
		{
			disp_  = disp;
			label_ = label;
			isAddr_ = isAddr;
		}
        
		RegRip opBinary(string op:"+") (int disp)
		{
			return RegRip(disp_ + disp, label_, r.isAddr_);
		}
		RegRip opBinary(string op:"-") (int disp)
		{
			return RegRip(disp_ - disp, label_, r.isAddr_);
		}
		
		RegRip opBinary(string op:"+") (sint64 disp)
		{
			return RegRip(disp_ + disp, label_, r.isAddr_);
		}
		RegRip opBinary(string op:"-") (sint64 disp)
		{
			return RegRip(disp_ - disp, label_, r.isAddr_);
		}
		RegRip opBinary(string op:"+") (Label label)
		{
			if (label_) throw new XError(ERR.BAD_ADDRESSING);
			return RegRip(disp_ + disp, label);
		}
		RegRip opBinary(string op:"+")(void* addr)
		{
			if (r.label_ || r.isAddr_) throw new XError(ERR.BAD_ADDRESSING);
			return RegRip(r.disp_ + cast(sint64)addr, 0, true);
		}	
		
		
	}
}

version (XBYAK_DISABLE_SEGMENT) {}
else{
// not derived from Reg
    class Segment {
    int idx_;
public:
    enum
    {
        es, cs, ss, ds, fs, gs
    }
    this(int idx){ assert(0 <= idx_ && idx_ < 6); idx_ = idx; }
    int getIdx() const
    {
        return idx_;
    }
    override string toString()
    {
        string[] tbl = [
            "es", "cs", "ss", "ds", "fs", "gs"
        ];
        return tbl[idx_];
    }
    }
}

class RegExp {

public:
version ( XBYAK64)
{
	enum { i32e = 32 | 64 };
}
else
{
	enum { i32e = 32 };
}	
	
	this(size_t disp = 0)
	{
		scale_ = 0;
		disp_ = disp;
	}
	

	this(Reg r, int scale = 1)
	{
		scale_ = scale;
		disp_ = 0;
		if (!r.isREG(i32e) && !r.isKind(Kind.XMM | Kind.YMM | Kind.ZMM)) throw new XError(ERR.BAD_SIZE_OF_REGISTER);
		if (scale == 0) return;
		if (scale != 1 && scale != 2 && scale != 4 && scale != 8) throw new XError(ERR.BAD_SCALE);
		if (r.getBit() >= 128 || scale != 1) { // xmm/ymm is always index
			index_ = r;
		} else {
			base_ = r;
		}
	}	
	
	bool isVsib(int bit = 128 | 256 | 512) const
	{
		return index_.isBit(bit);
	}
	
	
	RegExp optimize()
	{
		RegExp exp = this;
		// [reg * 2] => [reg + reg]
		if (index_.isBit(i32e) && !base_.getBit() && scale_ == 2) {
			exp.base_ = index_;
			exp.scale_ = 1;
		}
		return exp;
	}
	
	bool opEquals(RegExp rhs) const
	{
		return base_ == rhs.base_ && index_ == rhs.index_ && disp_ == rhs.disp_ && scale_ == rhs.scale_;
	}
	
	Reg getBase()	{	return base_; }
	Reg getIndex() 	{	return index_;	}
	int getScale() 	{	return scale_;	}
	size_t getDisp()	{	return cast(size_t)disp_; }
	
	void verify() const
	{
		if (base_.getBit() >= 128)	throw new XError(ERR.BAD_SIZE_OF_REGISTER);
		if (index_.getBit() && index_.getBit() <= 64)
		{
			if (index_.getIdx()== Operand.ESP) throw new XError(ERR.ESP_CANT_BE_INDEX);
			if (base_.getBit() && base_.getBit() != index_.getBit())	throw new XError(ERR.BAD_SIZE_OF_REGISTER);
		}
	}

	uint8 getRex() const
	{
		uint8 rex = index_.getRexX() | base_.getRexB();
		return rex ? uint8(rex | 0x40) : 0;
	}

	RegExp opBinary(string op:"+") (RegExp b)
	{
		if (this.index_.getBit() && b.index_.getBit()) throw new XError(ERR.BAD_ADDRESSING);
		RegExp ret = this;
		if (!ret.index_.getBit()) { ret.index_ = b.index_; ret.scale_ = b.scale_; }
		
		
		if (b.base_.getBit()) {
			if (ret.base_.getBit()) {
				if (ret.index_.getBit()) throw new XError(ERR.BAD_ADDRESSING);
				
				// base + base => base + index * 1
				ret.index_ = b.base_;
				
				// [reg + esp] => [esp + reg]
				if (ret.index_.getIdx() == Operand.ESP) swap(ret.base_, ret.index_);
				ret.scale_ = 1;

			} else { 
				ret.base_ = b.base_;
			}
		}
		ret.disp_ += b.disp_;
		return ret;
	}
	
 	RegExp opBinary(string op:"+") (Reg32e b)
	{
		return this + new RegExp(b);
	}
	
	RegExp opBinaryRight(string op:"+") (Reg32e a)
	{
		return new RegExp(a) + this;
	}
	
	RegExp opBinary(string op:"+") (int disp)
	{
		RegExp ret = this;
		ret.disp_ += disp;
		return ret;
	}
	
	RegExp opBinary(string op:"-") (int disp)
	{
		RegExp ret = this;
		ret.disp_ -= disp;
		return ret;
	}

private:
	/*
		[base_ + index_ * scale_ + disp_]
		base : Reg32e, index : Reg32e(w/o esp), Xmm, Ymm
	*/
	Reg base_ = new Reg();
	Reg index_ = new Reg();
	int scale_;
	size_t disp_;
}

// 2nd parameter for constructor of CodeArray(maxSize, userPtr, alloc)
enum AutoGrow = cast(void*)1; 
enum DontSetProtectRWE = cast(void*)2;

class CodeArray
{
	enum Type
	{
		USER_BUF = 1,	// use userPtr(non alignment, non protect)
		ALLOC_BUF,		// use new(alignment, protect)
		AUTO_GROW		// automatically move and grow memory if necessary
	}
	
	bool isAllocType() const
	{
		return type_ == Type.ALLOC_BUF || type_ == Type.AUTO_GROW;
	}

	struct AddrInfo
	{
		size_t codeOffset;  // position to write
		size_t jmpAddr;     // value to write
		int jmpSize;        // size of jmpAddr
		inner.LabelMode mode;
		this(size_t _codeOffset, size_t _jmpAddr, int _jmpSize, inner.LabelMode _mode)
		{
			codeOffset = _codeOffset;
			jmpAddr    = _jmpAddr;
			jmpSize    = _jmpSize;
			mode       = _mode;
		}

		uint64 getVal(uint8* top) const
		{
			uint64 disp = (mode == inner.LabelMode.LaddTop) ? jmpAddr + cast(size_t) top : (mode == inner.LabelMode.LasIs) ? jmpAddr : jmpAddr - cast(size_t) top;
			if (jmpSize == 4)
			{
				disp = inner.VerifyInInt32(disp);
			}
			return disp;
		}
	}

	alias AddrInfoList = AddrInfo[] ;
	AddrInfoList addrInfoList_;
	Type type_;
	Allocator defaultAllocator_;
	Allocator alloc_;

protected:
	size_t maxSize_;
	uint8* top_;
	size_t size_;
	bool isCalledCalcJmpAddress_;

	bool useProtect() { return alloc_.useProtect(); }

	/*
		allocate new memory and copy old data to the new area
	*/
	void growMemory()
	{
		size_t newSize  = max(DEFAULT_MAX_CODE_SIZE, maxSize_ * 2);
		uint8  * newTop = alloc_.alloc(newSize);
		if (null == newTop)
		{
			throw new XError(ERR.CANT_ALLOC);
		}

		newTop[0..size_] = top_[0..size_];

		alloc_.free(top_);
		top_     = newTop;
		maxSize_ = newSize;
	}

//	calc jmp address for AutoGrow mode
	void calcJmpAddress()
	{
		if (isCalledCalcJmpAddress_) return;
		foreach (i; addrInfoList_)
		{
			rewrite(i.codeOffset, i.getVal(top_), i.jmpSize);
		}
		isCalledCalcJmpAddress_ = true;
	}

public:
	enum ProtectMode
	{
		PROTECT_RW = 0, // read/write
		PROTECT_RWE = 1, // read/write/exec
		PROTECT_RE = 2 // read/exec
	}
	
	this(size_t maxSize, void* userPtr = null, Allocator allocator = new Allocator())
	{
		type_ = (userPtr == AutoGrow ? Type.AUTO_GROW : (userPtr == null || userPtr == DontSetProtectRWE) ? Type.ALLOC_BUF : Type.USER_BUF);
		alloc_   = allocator;
		maxSize_ = maxSize;
		top_     = type_ == Type.USER_BUF ? cast(uint8*)userPtr: alloc_.alloc(max(maxSize, 1));
		size_    = 0;
		isCalledCalcJmpAddress_ = false;

		if (maxSize_ > 0 && null == top_)	throw new XError(ERR.CANT_ALLOC);
		if ((type_ == Type.ALLOC_BUF && userPtr != DontSetProtectRWE && alloc_.useProtect()) && !setProtectMode(ProtectMode.PROTECT_RWE, false))
		{
			alloc_.free(top_);
			throw new XError(ERR.CANT_PROTECT);
		}
	}

	~this()
	{
		if (isAllocType)
		{
			if (alloc_.useProtect()) setProtectModeRW(false);
			alloc_.free(top_);
		}
	}

	bool setProtectMode(ProtectMode mode, bool throwException = true)
	{
		bool isOK = protect(top_, maxSize_, mode);
		if (isOK) return true;
		if (throwException) throw new XError(ERR.CANT_PROTECT);
		return false;
	}
	bool setProtectModeRE(bool throwException = true) { return setProtectMode(ProtectMode.PROTECT_RE, throwException); }
	bool setProtectModeRW(bool throwException = true) { return setProtectMode(ProtectMode.PROTECT_RW, throwException); }


	void resetSize()
	{
		size_ = 0;
		addrInfoList_.destroy;
	}

	void db(int code)
	{
		
		if (size_ >= maxSize_)
		{
			if (type_ == Type.AUTO_GROW)
			{
				growMemory;
			}
			else
			{
				throw new XError(ERR.CODE_IS_TOO_BIG);
			}
		}
		top_[size_++] = cast(uint8) code;
	}

	void db(uint8* code, size_t codeSize)
	{
		foreach (i; 0..codeSize)
		{
			db(code[i]);
		}
	}

	void db(uint64 code, size_t codeSize)
	{
		if (codeSize > 8) throw new XError(ERR.BAD_PARAMETER);
		foreach (i; 0..codeSize)
		{
			db(cast(uint8) (code >> (i * 8)));
		}
	}

	void dw(uint32 code) {	db(code, 2); }
	void dd(uint32 code) {	db(code, 4); }
	void dq(uint64 code) {	db(code, 8); }
	uint8* getCode() { return top_; }
	F getCode(F)() { return CastTo !(F)(top_); }
	uint8* getCurr() {	return &top_[size_];}
	F getCurr(F)() const {	return CastTo !(F)(&top_[size_]);	}
	size_t getSize() const { return size_; }
	void setSize(size_t size)
	{
		if (size > maxSize_) throw new XError(ERR.OFFSET_IS_TOO_BIG);
		size_ = size;
	}

	void dump() 
	{
		uint8  * p     = CodeArray.getCode();
		size_t bufSize = getSize();
		size_t remain  = bufSize;
		for (int i = 0; i < 4; i++)
		{
			size_t disp = 16;
			if (remain < 16)
			{
				disp = remain;
			}
			for (size_t j = 0; j < 16; j++)
			{
				if (j < disp)
				{
					write(format("%02X", p[i * 16 + j]));
				}
			}
			writeln();
			remain -= disp;
			if (remain <= 0)
			{
				break;
			}
		}
		
		size_ = 0; ////TEST
	}

//	@param data [in] address of jmp data
//	@param disp [in] offset from the next of jmp
//	@param size [in] write size(1, 2, 4, 8)
	void rewrite(size_t offset, uint64 disp, size_t size)
	{
		assert(offset < maxSize_);

		if (size != 1 && size != 2 && size != 4 && size != 8)
		{
			throw new XError(ERR.BAD_PARAMETER);
		}

		uint8* data = top_ + offset;
		foreach (i; 0..size)
		{
			data[i] = cast(uint8) (disp >> (i * 8));
		}
	}
	void save(size_t offset, size_t val, int size, inner.LabelMode mode)
	{
		addrInfoList_ ~= AddrInfo(offset, val, size, mode);
	}
	bool isAutoGrow() const
	{
		return type_ == Type.AUTO_GROW;
	}
	
	bool isCalledCalcJmpAddress() const { return isCalledCalcJmpAddress_; }
	/**
		change exec permission of memory
		@param addr [in] buffer address
		@param size [in] buffer size
		@param protectMode [in] mode(RW/RWE/RE)
		@return true(success), false(failure)
	*/
	
	static bool protect(void* addr, size_t size, ProtectMode protectMode_)
	{
version (Windows)
{
		const DWORD c_rw = PAGE_READWRITE;
		const DWORD c_rwe = PAGE_EXECUTE_READWRITE;
		const DWORD c_re = PAGE_EXECUTE_READ;
		DWORD mode;
}
else
{
		const int c_rw = PROT_READ | PROT_WRITE;
		const int c_rwe = PROT_READ | PROT_WRITE | PROT_EXEC;
		const int c_re = PROT_READ | PROT_EXEC;
		int mode;
}
		
		switch (protectMode_)
		{
			case ProtectMode.PROTECT_RW: mode = c_rw; break;
			case ProtectMode.PROTECT_RWE: mode = c_rwe; break;
			case ProtectMode.PROTECT_RE: mode = c_re; break;
			default:
				return false;
		}
		
		version (Windows)
		{
			DWORD oldProtect;
			return VirtualProtect(addr, size, mode, &oldProtect) != 0;
		}
        
		version (linux)
		{

// size_t pageSize = sysconf(_SC_PAGESIZE);
// size_t iaddr = reinterpret_cast<size_t>(addr);
// size_t roundAddr = iaddr & ~(pageSize - static_cast<size_t>(1));

// #ifndef NDEBUG
		// if (pageSize != 4096) fprintf(stderr, "large page(%zd) is used. not tested enough.\n", pageSize);
// #endif
		// return mprotect(reinterpret_cast<void*>(roundAddr), size + (iaddr - roundAddr), mode) == 0;
// #else
		    return true;
        }
	}

//	get aligned memory pointer
//	@param addr [in] address
//	@param alingedSize [in] power of two
//	@return aligned addr by alingedSize
	uint8* getAlignedAddress(uint8* addr, size_t alignedSize = 16)
	{
		size_t mask = alignedSize - 1;
		return cast(uint8*) ((cast(size_t) addr + mask) & ~mask);
	}
}

public class Address : Operand {
public:
	enum Mode
	{
		M_ModRM,
		M_64bitDisp,
		M_rip,
		M_ripAddr
	}
	
   	this(uint32 sizeBit, bool broadcast, RegExp e)
	{
		super(0, Kind.MEM, sizeBit);
		e_ = e;
		label_ = new Label();
		mode_ = Mode.M_ModRM;
		broadcast_ = broadcast;
		e_.verify();
	}

version(XBYAK64)
{
	this(sint64 disp)
	{
		super(0, Kind.MEM, 64);
		e_ = new RegExp(disp);
		label_ = new Label();
		mode_ = Mode.M_64bitDisp;
		broadcast_ = false;
	}
	
	this(uint32 sizeBit, bool broadcast, RegRip addr)
	{
		super(0, Kind.MEM, sizeBit);
		e_ = new RegExp(addr.disp_);
		label_ = addr.label_;
		mode_ = addr.isAddr_ ? Mode.M_ripAddr : Mode.M_rip;
		broadcast_ = broadcast;
	}
}

	RegExp getRegExp(bool optimize = true)
	{
		return optimize ? e_.optimize() : e_;
	}
	Mode getMode() const { return mode_; }

	bool is32bit() { return e_.getBase().getBit() == 32 || e_.getIndex().getBit() == 32; }
	bool isOnlyDisp() { return !e_.getBase().getBit() && !e_.getIndex().getBit(); } // for mov eax
	size_t getDisp() { return e_.getDisp(); }
	uint8 getRex() 
	{
		if (mode_ != Mode.M_ModRM) return 0;
		return getRegExp().getRex();
	}
	bool is64bitDisp() const { return mode_ == Mode.M_64bitDisp; } // for moffset
	bool isBroadcast() const { return broadcast_; }
	Label getLabel() { return label_; }

	override bool opEquals(Object o) const
	{
		Address rhs = cast(Address)o;
		if(!rhs) return false;
		return this.getBit() == rhs.getBit() && this.e_ == rhs.e_ && this.label_ == rhs.label_ && this.mode_ == rhs.mode_ && this.broadcast_ == rhs.broadcast_;
	}

	bool isVsib() const { return e_.isVsib(); }

private:
	RegExp e_;
	Label label_;
	Mode mode_;
	bool broadcast_;
}


class AddressFrame {
public:
	uint32 bit_;
	bool broadcast_;
	
	this(uint32 bit, bool broadcast = false)
	{
		bit_ = bit;
		broadcast_ = broadcast;
	}
	
	Address opIndex(RegExp e)
	{
		return new Address(bit_, broadcast_, e);
	}
	
	Address opIndex(void* disp)
	{
		return new Address(bit_, broadcast_, new RegExp(cast(size_t)disp));
	}


	version (XBYAK64)
	{
		Address opIndex(uint64 disp)
		{
			return new Address(disp);
		}
		
		Address opIndex(RegRip addr)
		{
			return new Address(bit_, broadcast_, addr);
		}
	}

	Address opIndex(Reg32e reg)
	{
		RegExp ret = new RegExp(reg);
		return opIndex(ret);
	}

	Address opIndex(Mmx mmx)
	{
		RegExp ret = new RegExp(mmx);
		return opIndex(ret);
	}
}

struct JmpLabel
{
	size_t endOfJmp;        // offset from top to the end address of jmp
	int jmpSize;
	inner.LabelMode mode;
	size_t disp;                            // disp for [rip + disp]
   
	this(size_t endOfJmp, int jmpSize, inner.LabelMode mode = inner.LabelMode.LasIs, size_t disp = 0)
	{
		this.endOfJmp = endOfJmp;
		this.jmpSize  = jmpSize;
		this.mode     = mode;
		this.disp     = disp;
	}
}

class Label
{
	LabelManager mgr;
	int id;
public:
	this()
	{
		mgr = new LabelManager();
		id  = 0;
	}

	this(Label rhs)
	{
		id  = rhs.id;
		mgr = rhs.mgr;
		if (mgr is null) {
			mgr.incRefCount(id, this);
		}
	}

	override bool opEquals(Object o)
	{
		if (id) throw new XError(ERR.LABEL_IS_ALREADY_SET_BY_L);

		Label rhs = cast(Label) o;
		id  = rhs.id;
		mgr = rhs.mgr;
		if (mgr is null) {
			mgr.incRefCount(id, this);
		}
		return this.id == rhs.id;
	}

	~this()
	{
		if (id && mgr) {
			mgr.decRefCount(id, this);
		}
	}
	void clear() {
		mgr = new LabelManager();
		id = 0;
	}
	
	int getId() const { return id; }

	string toStr(int num) const
	{
		return format(".%08x", num);
	}
}


class LabelManager
{
// for string label
	struct SlabelVal
	{
		size_t offset = 0;
        this(size_t offset)
		{
			this.offset = offset;
		}
	}

	alias SlabelDefList = SlabelVal[string] ;
	alias SlabelUndefList = JmpLabel[][string] ;

	struct SlabelState
	{
		SlabelDefList defList;
		SlabelUndefList undefList;
	}

	alias StateList = SlabelState[] ;

// for Label class
	struct ClabelVal
	{
		size_t offset;
		int refCount;
		this(size_t offset)
		{
			this.offset   = offset;
			this.refCount = 1;
		}
	}

	alias ClabelDefList = ClabelVal[int] ;
	alias ClabelUndefList = JmpLabel[][int] ;
	alias LabelPtrList = Label[] ;

	CodeArray base_;

// global : stateList_[0], local : stateList_{$-1]
	StateList stateList_;
	int labelId_;
	ClabelDefList clabelDefList_;
	ClabelUndefList clabelUndefList_;
	LabelPtrList labelPtrList_;
	
	int getId(Label label)
	{
		if (label.id == 0)
		{
			label.id = labelId_++;
		}

		return label.id;
	}

	void define_inner(DefList, UndefList, T)(ref DefList deflist, ref UndefList undeflist, T labelId, size_t addrOffset)
	{
		
		// add label
//		if (labelId in deflist)	throw new XError(ERR.LABEL_IS_REDEFINED);
//		deflist[labelId] = typeof(deflist[labelId])(addrOffset);


		// search undefined label
		if (null == (labelId in undeflist)) return;
		foreach (JmpLabel jmp; undeflist[labelId]) 
		{
			size_t offset = jmp.endOfJmp - jmp.jmpSize;
			size_t disp;
			if (jmp.mode == inner.LabelMode.LaddTop)
			{
				disp = addrOffset;
			}
			else if (jmp.mode == inner.LabelMode.Labs)
			{
				disp = cast(size_t) base_.getCurr;
			}
			else
			{
				disp = addrOffset - jmp.endOfJmp + to!size_t(jmp.disp);
version (XBYAK64)
{
				if (jmp.jmpSize <= 4 && !inner.IsInInt32(disp))
					throw new XError(ERR.OFFSET_IS_TOO_BIG);
}
				if (jmp.jmpSize == 1 && !inner.IsInDisp8(cast(uint32) disp))
					throw new XError(ERR.LABEL_IS_TOO_FAR);
			}

			if (base_.isAutoGrow)
				base_.save(offset, disp, jmp.jmpSize, jmp.mode);
			else
				base_.rewrite(offset, disp, jmp.jmpSize);

			undeflist.remove(labelId);

		}
	}

	bool getOffset_inner(DefList, T)(DefList defList, size_t* offset, T label)
	{
		if (null == (label in defList))
		{
			return false;
		}

		*offset = defList[label].offset;
		return true;
	}

	void incRefCount(int id, Label label)
	{
		clabelDefList_[id].refCount++;
		labelPtrList_ ~= label;
	}

	void decRefCount(int id, Label label)
	{
		for(int i; i<labelPtrList_.length ; i++)
		{
			if(labelPtrList_[i] != label)
				labelPtrList_.remove(i);
		}
		
		if (null == (id in clabelDefList_)) {
			return;
		}

		if (clabelDefList_[id].refCount == 1)
		{
			clabelDefList_.remove(id);
		}
		else
		{
			clabelDefList_[id].refCount -= 1;
		}
	}

	bool hasUndefinedLabel_inner(T)(T list) const
	{
		return !list.empty();
	}
	
	// detach all labels linked to LabelManager
	void resetLabelPtrList()
	{
		foreach (i; labelPtrList_) {
			i.clear();
		}
		labelPtrList_.destroy();
	}
	
public:
	this()
	{
		reset();

	}
	~this()
	{
		resetLabelPtrList();
	}
	
	void reset()
	{
		base_    = null;
		labelId_ = 1;
		stateList_.destroy;
		stateList_ = [SlabelState(), SlabelState()];

		clabelDefList_.destroy;
		clabelUndefList_.destroy;
		resetLabelPtrList();
	}
	void enterLocal()
	{
		stateList_ ~= SlabelState();
	}
	void leaveLocal()
	{
		if (stateList_.length <= 2)
		{
			throw new XError(ERR.UNDER_LOCAL_LABEL);
		}

		if (hasUndefinedLabel_inner(stateList_[$-1].undefList))
		{
				throw new XError(ERR.LABEL_IS_NOT_FOUND);
		}
		stateList_.popBack();
	}

	void set(CodeArray base)
	{
		base_ = base;
	}

	void defineSlabel(string label)
	{
		if ("@b" == label || "@f" == label) throw new XError(ERR.BAD_LABEL_STR);
		if ("@@" == label)
		{
			if ("@f" in stateList_[0].defList)
			{				
				stateList_[0].defList.remove("@f");
				label = "@b";
			}
			else
			{
				if ("@b" in stateList_[0].defList)
				{
					stateList_[0].defList.remove("@b");
				}
				label = "@f";
			}
		}
		
		auto st = label[0] == '.' ? &stateList_[$-1] : &stateList_[0];

		if (label in st.defList) throw new XError(ERR.LABEL_IS_REDEFINED);
		st.defList[label] = SlabelVal(base_.getSize());

		define_inner(stateList_[0].defList, st.undefList, label, base_.getSize());
	}


	void defineClabel(Label label)
	{
		
		if (getId(label) in clabelDefList_)	throw new XError(ERR.LABEL_IS_REDEFINED);

		clabelDefList_[getId(label)] = ClabelVal(base_.getSize());

		
		define_inner(clabelDefList_, clabelUndefList_, getId(label), base_.getSize);
		label.mgr = this;
		labelPtrList_ ~= label;
	}

	void assign(Label dst, Label src)
	{
		if (null == (src.id in clabelDefList_)) {
			throw new XError(ERR.LABEL_ISNOT_SET_BY_L);
		}

		define_inner(clabelDefList_, clabelUndefList_, dst.id, clabelDefList_[src.id].offset);
		dst.mgr = this;
		labelPtrList_ ~= dst;
	}

	bool getOffset(size_t* offset, ref string label)  ////fix :( Add ref )
	{
		SlabelDefList df = stateList_[0].defList;
		if (label == "@b")
		{
			if ("@f" in df)
			{
				label = "@f";
			}
			else if (!("@b" in df))
			{
				throw new XError(ERR.LABEL_IS_NOT_FOUND);
			}
		}
		else if ("@f" == label)
		{
			if ("@f" in df)
				label = "@b";
		}

		SlabelState* st = label[0] == '.' ? &stateList_[$-1] : &stateList_[0];
		return getOffset_inner(st.defList, offset, label);
	}

	bool getOffset(size_t* offset, Label label)
	{
		return getOffset_inner(clabelDefList_, offset, getId(label));
	}

	void addUndefinedLabel(string label, JmpLabel jmp)
	{
		SlabelState* st = label[0] == '.' ? &stateList_[$-1] : &stateList_[0];
		st.undefList[label] ~= jmp;
	}

	void addUndefinedLabel(Label label, JmpLabel jmp)
	{
		clabelUndefList_[label.id] ~= jmp;
	}

	bool hasUndefSlabel() const
	{
		foreach (st; stateList_)
		{
			if (hasUndefinedLabel_inner(st.undefList)) {
				return true;
			}
		}
		return false;
	}

	bool hasUndefClabel() const
	{
		return hasUndefinedLabel_inner(clabelUndefList_);
	}
	uint8* getCode() { return base_.getCode(); }
	bool isReady() const { return !base_.isAutoGrow() || base_.isCalledCalcJmpAddress(); }

/+
inline Label::Label(const Label& rhs)
{
	id = rhs.id;
	mgr = rhs.mgr;
	if (mgr) mgr->incRefCount(id, this);
}
inline Label& Label::operator=(const Label& rhs)
{
	if (id) throw Error(ERR_LABEL_IS_ALREADY_SET_BY_L);
	id = rhs.id;
	mgr = rhs.mgr;
	if (mgr) mgr->incRefCount(id, this);
	return *this;
}
inline Label::~Label()
{
	if (id && mgr) mgr->decRefCount(id, this);
}
inline const uint8* Label::getAddress() const
{
	if (mgr == 0 || !mgr->isReady()) return 0;
	size_t offset;
	if (!mgr->getOffset(&offset, *this)) return 0;
	return mgr->getCode() + offset;
}
+/
	
}	
	

enum LabelType
{
	T_SHORT,
	T_NEAR,
	T_AUTO // T_SHORT if possible
}

public class CodeGenerator : CodeArray
{
	version (XBYAK64)
	{
		enum { i32e = 64 | 32, BIT = 64 }
		size_t dummyAddr = cast(size_t) (0x11223344UL << 32) | 55667788;
		alias NativeReg = Reg64;
	}
	else
	{
		enum { i32e = 32, BIT = 32 }
		size_t dummyAddr = 0x12345678;
		alias NativeReg = Reg32;
	}
	// (XMM, XMM|MEM)
	bool isXMM_XMMorMEM  (Operand op1, Operand op2)
	{
		return op1.isXMM && (op2.isXMM || op2.isMEM);
	}
	// (MMX, MMX|MEM) or (XMM, XMM|MEM)
	bool isXMMorMMX_MEM  (Operand op1, Operand op2)
	{
		return (op1.isMMX && (op2.isMMX || op2.isMEM)) || isXMM_XMMorMEM(op1, op2);
	} 
	// (XMM, MMX|MEM)
	bool isXMM_MMXorMEM  (Operand op1, Operand op2)
	{
		return op1.isXMM && (op2.isMMX || op2.isMEM);
	}
	// (MMX, XMM|MEM)
	bool isMMX_XMMorMEM  (Operand op1, Operand op2)
	{
		return op1.isMMX && (op2.isXMM || op2.isMEM);
	}
	// (XMM, REG32|MEM)
	bool isXMM_REG32orMEM(Operand op1, Operand op2)
	{
		return op1.isXMM && (op2.isREG(i32e) || op2.isMEM);
	}
	// (REG32, XMM|MEM)
	bool isREG32_XMMorMEM(Operand op1, Operand op2)
	{
		return op1.isREG(i32e) && (op2.isXMM || op2.isMEM);
	}
	// (REG32, REG32|MEM)
	bool isREG32_REG32orMEM(Operand op1 = new Operand(), Operand op2 = new Operand())
	{
		return op1.isREG(i32e) && ((op2.isREG(i32e) && op1.getBit == op2.getBit) || op2.isMEM);
	}

	void rex(Operand op1, Operand op2 = new Reg())
	{
		uint8 rex = 0;
		Operand p1  = op1;
		Operand p2  = op2;
		if (p1.isMEM)	swap(p1, p2);
		if (p1.isMEM)	throw new XError(ERR.BAD_COMBINATION);
		if (p2.isMEM)
		{
			Address addr = p2.getAddress();
			if (BIT == 64 && addr.is32bit() )	db(0x67);
			Reg r1 = p1.getReg();
			rex = addr.getRex() | r1.getRex();
		}
		else
		{
			// ModRM(reg, base);
			Reg r1 = op1.getReg();
			Reg r2 = op2.getReg();
			rex = r2.getRex(r1);
		}
		// except movsx(16bit, 32/64bit)
		if ((op1.isBit(16) && !op2.isBit(i32e)) || (op2.isBit(16) && !op1.isBit(i32e)))	db(0x66);
		if (rex) db(rex);
	}

	enum // AVXtype  
	{
		// low 3 bit
		T_N1 = 1,
		T_N2 = 2,
		T_N4 = 3,
		T_N8 = 4,
		T_N16 = 5,
		T_N32 = 6,
		T_NX_MASK = 7,
		//
		T_N_VL = 1 << 3, // N * (1, 2, 4) for VL
		T_DUP = 1 << 4, // N = (8, 32, 64)
		T_66 = 1 << 5,
		T_F3 = 1 << 6,
		T_F2 = 1 << 7,
		T_0F = 1 << 8,
		T_0F38 = 1 << 9,
		T_0F3A = 1 << 10,
		T_L0 = 1 << 11,
		T_L1 = 1 << 12,
		T_W0 = 1 << 13,
		T_W1 = 1 << 14,
		T_EW0 = 1 << 15,
		T_EW1 = 1 << 16,
		T_YMM = 1 << 17, // support YMM, ZMM
		T_EVEX = 1 << 18,
		T_ER_X = 1 << 19, // xmm{er}
		T_ER_Y = 1 << 20, // ymm{er}
		T_ER_Z = 1 << 21, // zmm{er}
		T_SAE_X = 1 << 22, // xmm{sae}
		T_SAE_Y = 1 << 23, // ymm{sae}
		T_SAE_Z = 1 << 24, // zmm{sae}
		T_MUST_EVEX = 1 << 25, // contains T_EVEX
		T_B32 = 1 << 26, // m32bcst
		T_B64 = 1 << 27, // m64bcst
		T_M_K = 1 << 28, // mem{k}
		T_VSIB = 1 << 29,
		T_MEM_EVEX = 1 << 30, // use evex if mem
		T_XXX
	}

	void vex(Reg reg, Reg base, Operand v, int type, int code, bool x = false)
	{
		int w = (type & T_W1) ? 1 : 0;
		bool is256 = (type & T_L1) ? true : (type & T_L0) ? false : reg.isYMM();
		bool r = reg.isExtIdx();
		bool b = base.isExtIdx();
		int idx = v ? v.getIdx() : 0;
		if ((idx | reg.getIdx() | base.getIdx()) >= 16) throw new XError(ERR.BAD_COMBINATION);
		uint32 pp = (type & T_66) ? 1 : (type & T_F3) ? 2 : (type & T_F2) ? 3 : 0;
		uint32 vvvv = (((~idx) & 15) << 3) | (is256 ? 4 : 0) | pp;
		if (!b && !x && !w && (type & T_0F)) {
			db(0xC5); db((r ? 0 : 0x80) | vvvv);
		} else {
			uint32 mmmm = (type & T_0F) ? 1 : (type & T_0F38) ? 2 : (type & T_0F3A) ? 3 : 0;
			db(0xC4); db((r ? 0 : 0x80) | (x ? 0 : 0x40) | (b ? 0 : 0x20) | mmmm); db((w << 7) | vvvv);
		}
		db(code);
	}



	void verifySAE(Reg r, int type)
	{
		if (
			((type & T_SAE_X) && r.isXMM()) ||
			((type & T_SAE_Y) && r.isYMM()) || 
			((type & T_SAE_Z) && r.isZMM())
		) return;
		throw new XError(ERR.SAE_IS_INVALID);
	}
	void verifyER(Reg r, int type)
	{
		if (
			((type & T_ER_X) && r.isXMM()) ||
			((type & T_ER_Y) && r.isYMM()) ||
			((type & T_ER_Z) && r.isZMM())
		) return;
		throw new XError(ERR.ER_IS_INVALID);
	}
	// (a, b, c) contains non zero two or three values then err
	int verifyDuplicate(int a, int b, int c, ERR err)
	{
		int v = a | b | c;
		if ((a > 0 && a != v) + (b > 0 && b != v) + (c > 0 && c != v) > 0) return cast(int)(new XError(err));
		return v;
	}
	int evex(Reg reg, Reg base, Operand v, int type, int code, bool x = false, bool b = false, int aaa = 0, uint32 VL = 0, bool Hi16Vidx = false)
	{
		if (!(type & (T_EVEX | T_MUST_EVEX))) throw new XError(ERR.EVEX_IS_INVALID);
		int w = (type & T_EW1) ? 1 : 0;
		uint32 mm = (type & T_0F) ? 1 : (type & T_0F38) ? 2 : (type & T_0F3A) ? 3 : 0;
		uint32 pp = (type & T_66) ? 1 : (type & T_F3) ? 2 : (type & T_F2) ? 3 : 0;

		int idx = v ? v.getIdx() : 0;
		uint32 vvvv = ~idx;

		bool R = !reg.isExtIdx();
		bool X = x ? false : !base.isExtIdx2();
		bool B = !base.isExtIdx();
		bool Rp = !reg.isExtIdx2();
		int LL;
		int rounding = verifyDuplicate(reg.getRounding(), base.getRounding(), v ? v.getRounding() : 0, ERR.ROUNDING_IS_ALREADY_SET);
		int disp8N = 1;
		if (rounding) {
			if (rounding == EvexModifierRounding.T_SAE) {
				verifySAE(base, type); LL = 0;
			} else {
				verifyER(base, type); LL = rounding - 1;
			}
			b = true;
		} else {
			if (v) VL = max(VL, v.getBit());
			VL = max(max(reg.getBit(), base.getBit()), VL);
			LL = (VL == 512) ? 2 : (VL == 256) ? 1 : 0;
			if (b) {
				disp8N = (type & T_B32) ? 4 : 8;
			} else if (type & T_DUP) {
				disp8N = VL == 128 ? 8 : VL == 256 ? 32 : 64;
			} else {
				if ((type & (T_NX_MASK | T_N_VL)) == 0) {
					type |= T_N16 | T_N_VL; // default
				}
				int low = type & T_NX_MASK;
				if (low > 0) {
					disp8N = 1 << (low - 1);
					if (type & T_N_VL) disp8N *= (VL == 512 ? 4 : VL == 256 ? 2 : 1);
				}
			}
		}
		bool Vp = !((v ? v.isExtIdx2() : 0) | Hi16Vidx);
		bool z = reg.hasZero() || base.hasZero() || (v ? v.hasZero() : false);
		if (aaa == 0) aaa = verifyDuplicate(base.getOpmaskIdx(), reg.getOpmaskIdx(), (v ? v.getOpmaskIdx() : 0), ERR.OPMASK_IS_ALREADY_SET);
		db(0x62);
		db((R ? 0x80 : 0) | (X ? 0x40 : 0) | (B ? 0x20 : 0) | (Rp ? 0x10 : 0) | (mm & 3));
		db((w == 1 ? 0x80 : 0) | ((vvvv & 15) << 3) | 4 | (pp & 3));
		db((z ? 0x80 : 0) | ((LL & 3) << 5) | (b ? 0x10 : 0) | (Vp ? 8 : 0) | (aaa & 7));
		db(code);
		return disp8N;
	}
	void setModRM(int mod, int r1, int r2)
	{
		db( cast(uint8)((mod << 6) | ((r1 & 7) << 3) | (r2 & 7)) );
	}
	void setSIB(RegExp e, int reg, int disp8N = 0)
	{
		size_t disp64 = e.getDisp();
version (XBYAK64)
{
		size_t high = disp64 >> 32;
		if (high != 0 && high != 0xFFFFFFFF) throw new XError(ERR.OFFSET_IS_TOO_BIG);
}
		uint32 disp = cast(uint32)(disp64);
		Reg base = e.getBase();
		Reg index = e.getIndex();
		int baseIdx = base.getIdx();
		int baseBit = base.getBit();
		int indexBit = index.getBit();
		enum {
			mod00 = 0, mod01 = 1, mod10 = 2
		}
		int mod = mod10; // disp32
		if (!baseBit || ((baseIdx & 7) != Operand.EBP && disp == 0)) {
			mod = mod00;
		} else {
			if (disp8N == 0) {
				if (inner.IsInDisp8(disp)) {
					mod = mod01;
				}
			} else {
				// disp must be casted to signed
				uint32 t = cast(uint32)(cast(int)disp / disp8N);
				if ((disp % disp8N) == 0 && inner.IsInDisp8(t)) {
					disp = t;
					mod = mod01;
				}
			}
		}
		const int newBaseIdx = baseBit ? (baseIdx & 7) : Operand.EBP;
		/* ModR/M = [2:3:3] = [Mod:reg/code:R/M] */
		bool hasSIB = indexBit || (baseIdx & 7) == Operand.ESP;
version (XBYAK64)
{
		if (!baseBit && !indexBit) hasSIB = true;
}
		if (hasSIB) {
			setModRM(mod, reg, Operand.ESP);
			/* SIB = [2:3:3] = [SS:index:base(=rm)] */
			int idx = indexBit ? (index.getIdx() & 7) : Operand.ESP;
			int scale = e.getScale();
			int SS = (scale == 8) ? 3 : (scale == 4) ? 2 : (scale == 2) ? 1 : 0;
			setModRM(SS, idx, newBaseIdx);
		} else {
			setModRM(mod, reg, newBaseIdx);
		}
		if (mod == mod01) {
			db(disp);
		} else if (mod == mod10 || (mod == mod00 && !baseBit)) {
			dd(disp);
		}
	}


	LabelManager labelMgr_ = new LabelManager();

	uint8 getModRM(int mod, int r1, int r2) const
	{
		return cast(uint8) ((mod << 6) | ((r1 & 7) << 3) | (r2 & 7));
	}

	void opModR(Reg reg1, Reg reg2, int code0, int code1 = NONE, int code2 = NONE)
	{
		rex(reg2, reg1);
		db(code0 | (reg1.isBit(8) ? 0 : 1));
		if (code1 != NONE) db(code1);
		if (code2 != NONE) db(code2);
		setModRM(3, reg1.getIdx(), reg2.getIdx());
	}

	void opModM(Address addr, Reg reg, int code0, int code1 = NONE, int code2 = NONE, int immSize = 0)
	{
		if (addr.is64bitDisp)	throw new XError(ERR.CANT_USE_64BIT_DISP);
		rex(addr, reg);
		db(code0 | (reg.isBit(8) ? 0 : 1));
		if (code1 != NONE) db(code1);
		if (code2 != NONE) db(code2);
		opAddr(addr, reg.getIdx(), immSize);
	}
	
	void opLoadSeg(Address addr, Reg reg, int code0, int code1 = NONE)
	{
		if (addr.is64bitDisp()) throw new XError(ERR.CANT_USE_64BIT_DISP);
		if (reg.isBit(8)) throw new XError(ERR.BAD_SIZE_OF_REGISTER);
		rex(addr, reg);
		db(code0); if (code1 != NONE) db(code1);
		opAddr(addr, reg.getIdx());
	}

	void opMIB(Address addr, Reg reg, int code0, int code1)
	{
		if (addr.is64bitDisp()) throw new XError(ERR.CANT_USE_64BIT_DISP);
		if (addr.getMode() != Address.Mode.M_ModRM) throw new XError(ERR.INVALID_MIB_ADDRESS);
		if (BIT == 64 && addr.is32bit()) db(0x67);
		RegExp regExp = addr.getRegExp(false);
		uint8 rex = regExp.getRex();
		if (rex) db(rex);
		db(code0); db(code1);
		setSIB(regExp, reg.getIdx());
	}
	
	void makeJmp(uint32 disp, LabelType type, uint8 shortCode, uint8 longCode, uint8 longPref)
	{
		int shortJmpSize   = 2;
		int longHeaderSize = longPref ? 2 : 1;
		int longJmpSize    = longHeaderSize + 4;
		if (type != T_NEAR && inner.IsInDisp8(disp - shortJmpSize))
		{
			db(shortCode);
			db(disp - shortJmpSize);
		}
		else
		{
			if (type == T_SHORT) throw new XError(ERR.LABEL_IS_TOO_FAR);
			if (longPref) db(longPref);

			db(longCode);
			dd(disp - longJmpSize);
		}
	}

	void opJmp(T)(T label, LabelType type, uint8 shortCode, uint8 longCode, uint8 longPref)
	if( is(T == string) || is(T == Label) )
	{
		if (isAutoGrow && size_ + 16 >= maxSize_)	growMemory(); // avoid splitting code of jmp
		size_t offset = 0;                      
		if (labelMgr_.getOffset(&offset, label))	// label exists
		{
			makeJmp(inner.VerifyInInt32(offset - size_), type, shortCode, longCode, longPref);
		}
		else
		{
			int jmpSize = 0;
			if (type == T_NEAR)
			{
				jmpSize = 4;
				if (longPref) db(longPref);
				db(longCode); dd(0);
			}
			else
			{
				jmpSize = 1;
				db(shortCode); db(0);
			}
			JmpLabel jmp = JmpLabel(size_, jmpSize, inner.LabelMode.LasIs);
			labelMgr_.addUndefinedLabel(label, jmp);
		}
	}

	void opJmpAbs(const void* addr, LabelType type, uint8 shortCode, uint8 longCode, uint8 longPref = 0)
	{
		if (isAutoGrow)
		{
			if (type != T_NEAR)	throw new XError(ERR.ONLY_T_NEAR_IS_SUPPORTED_IN_AUTO_GROW);
			if (size_ + 16 >= maxSize_)	growMemory;
			if (longPref) db(longPref);  //// fix
			db(longCode);
			dd(0);
			save(size_ - 4, cast(size_t) addr - size_, 4, inner.LabelMode.Labs);
		}
		else
		{
			makeJmp(inner.VerifyInInt32(cast(uint8*) addr - getCurr), type, shortCode, longCode, longPref);
		}
	}
	
	// reg is reg field of ModRM
	// immSize is the size for immediate value
	// disp8N = 0(normal), disp8N = 1(force disp32), disp8N = {2, 4, 8} ; compressed displacement
	void opAddr(Address addr, int reg, int immSize = 0, int disp8N = 0, bool permitVisb = false)
	{
		if (!permitVisb && addr.isVsib()) throw new XError(ERR.BAD_VSIB_ADDRESSING);
		if (addr.getMode() == Address.Mode.M_ModRM) {
			setSIB(addr.getRegExp(), reg, disp8N);
		} else if (addr.getMode() == Address.Mode.M_rip || addr.getMode() == Address.Mode.M_ripAddr) {
			setModRM(0, reg, 5);
			if (addr.getLabel()) { // [rip + Label]
				putL_inner(addr.getLabel(), true, addr.getDisp() - immSize);
			} else {
				size_t disp = addr.getDisp();
				if (addr.getMode() == Address.Mode.M_ripAddr) {
					if (isAutoGrow()) throw new XError(ERR.INVALID_RIP_IN_AUTO_GROW);
					disp -= cast(size_t)getCurr() + 4 + immSize;
				}
				dd(inner.VerifyInInt32(disp));
			}
		}
	}
	
	
//	preCode is for SSSE3/SSE4
	void opGen(Operand reg, Operand op, int code, int pref, bool delegate(Operand, Operand)isValid, int imm8 = NONE, int preCode = NONE)
	{
		if (isValid && !isValid(reg, op)) throw new XError(ERR.BAD_COMBINATION);
		if (pref != NONE) db(pref);
		if (op.isMEM)
		{
			opModM(op.getAddress(), reg.getReg(), 0x0F, preCode, code, (imm8 != NONE) ? 1 : 0);
		}
		else
		{
			opModR(reg.getReg(), op.getReg(), 0x0F, preCode, code);
		}

		if (imm8 != NONE) db(imm8);
	}

	void opMMX_IMM(Mmx mmx, int imm8, int code, int ext)
	{
		if (mmx.isXMM) { db(0x66); }
		opModR(new Reg32(ext), mmx, 0x0F, code);
		db(imm8);
	}

	void opMMX(Mmx mmx, Operand op, int code, int pref = 0x66, int imm8 = NONE, int preCode = NONE)
	{
		opGen(mmx, op, code, (mmx.isXMM ? pref : NONE), &isXMMorMMX_MEM, imm8, preCode);
	}

	void opMovXMM(Operand op1, Operand op2, int code, int pref)
	{
		if (pref != NONE) db(pref);
		if (op1.isXMM && op2.isMEM)
		{
			opModM(op2.getAddress(), op1.getReg(), 0x0F, code);
		}
		else if (op1.isMEM && op2.isXMM)
		{
			opModM(op1.getAddress(), op2.getReg(), 0x0F, code | 1);
		}
		else
		{
			throw new XError(ERR.BAD_COMBINATION);
		}
	}

	void opExt(Operand op, Mmx mmx, int code, int imm, bool hasMMX2 = false)
	{
		// pextrw is special
		if (hasMMX2 && op.isREG(i32e))
		{
			if (mmx.isXMM) db(0x66);
			opModR(op.getReg(), mmx, 0x0F, 0xC5);
			db(imm);
		}
		else
		{
			opGen(mmx, op, code, 0x66, &isXMM_REG32orMEM, imm, 0x3A);
		}
	}

	void opR_ModM(Operand op, int bit, int ext, int code0, int code1 = NONE, int code2 = NONE, bool disableRex = false, int immSize = 0)
	{
		int opBit = op.getBit;
		if (disableRex && opBit == 64) opBit = 32;
		if (op.isREG(bit))
		{
			opModR(new Reg(ext, Kind.REG, opBit), op.getReg().changeBit(opBit), code0, code1, code2);
		}
		else if (op.isMEM)
		{
			opModM(op.getAddress(), new Reg(ext, Kind.REG, opBit), code0, code1, code2, immSize);
		}
		else
		{
			throw new XError(ERR.BAD_COMBINATION);
		}
	}

	void opShift(Operand op, int imm, int ext)
	{
		verifyMemHasSize(op);
		opR_ModM(op, 0, ext, (0xC0 | ((imm == 1 ? 1 : 0) << 4)), NONE, NONE, false, (imm != 1) ? 1 : 0);
		if (imm != 1) db(imm);
	}

	void opShift(Operand op, Reg8 cl, int ext)
	{
		if (cl.getIdx != Operand.CL) throw new XError(ERR.BAD_COMBINATION);
		opR_ModM(op, 0, ext, 0xD2);
	}

	void opModRM(Operand op1, Operand op2, bool condR, bool condM, int code0, int code1 = NONE, int code2 = NONE, int immSize = 0)
	{
		if (condR)
		{
			opModR(op1.getReg(), op2.getReg(), code0, code1, code2);
		}
		else if (condM)
		{
			opModM(op2.getAddress(), op1.getReg(), code0, code1, code2, immSize);
		}
		else
		{
			throw new XError(ERR.BAD_COMBINATION);
		}
	}

	void opShxd(Operand op, Reg reg, uint8 imm, int code, Reg8 _cl = new Reg8)
	{
		if (_cl && _cl.getIdx != Operand.CL) throw new XError(ERR.BAD_COMBINATION);
		opModRM(reg, op, (op.isREG(16 | i32e) && op.getBit == reg.getBit), op.isMEM && (reg.isREG(16 | i32e)), 0x0F, code | (_cl ? 1 : 0), NONE, _cl ? 0 : 1);
		if (!cl) db(imm);
	}

// (REG, REG|MEM), (MEM, REG)
	void opRM_RM(Operand op1, Operand op2, int code)
	{
		if (op1.isREG() && op2.isMEM())
		{
			opModM(op2.getAddress(), op1.getReg(), code | 2);
		}
		else
		{
			opModRM(op2, op1, op1.isREG() && op1.getKind() == op2.getKind(), op1.isMEM() && op2.isREG(), code);
		}
	}

// (REG|MEM, IMM)
	void opRM_I(Operand op, uint32 imm, int code, int ext)
	{
		verifyMemHasSize(op);
		uint32 immBit = inner.IsInDisp8(imm) ? 8 : inner.IsInDisp16(imm) ? 16 : 32;
		if (op.getBit < immBit) throw new XError(ERR.IMM_IS_TOO_BIG);

		// don't use MEM16 if 32/64bit mode
		if (op.isREG(32 | 64) && immBit == 16) immBit = 32;

		// rax, eax, ax, al
		if (op.isREG && op.getIdx == 0 && (op.getBit == immBit || (op.isBit(64) && immBit == 32)))
		{
			rex(op);
			db(code | 4 | (immBit == 8 ? 0 : 1));
		}
		else
		{
			int tmp = immBit < min(op.getBit, 32U) ? 2 : 0;
			opR_ModM(op, 0, ext, 0x80 | tmp, NONE, NONE, false, immBit / 8);
		}
		db(imm, immBit / 8);
	}

	void opIncDec(Operand op, int code, int ext)
	{
		verifyMemHasSize(op);
		version (XBYAK64)
        {
            code = 0xFE;
		    if (op.isREG)
		    {
			    opModR(new Reg(ext, Kind.REG, op.getBit()), op.getReg(), code);
		    }
		    else
		    {
			    opModM(op.getAddress(), new Reg(ext, Kind.REG, op.getBit()), code);
		    }
        }
        else
        {
			if (op.isREG && !op.isBit(8))
			{
				rex(op);
				db(code | op.getIdx);
			}
		}
	}

	void opPushPop(Operand op, int code, int ext, int alt)
	{
		if (op.isREG)
		{
			if (op.isBit(16))
				db(0x66);
			if (op.getReg().getIdx >= 8)
				db(0x41);
			db(alt | (op.getIdx & 7));
		}
		else if (op.isMEM)
		{
			opModM(op.getAddress(), new Reg(ext, Kind.REG, op.getBit), code);
		}
		else
		{
			throw new XError(ERR.BAD_COMBINATION);
		}
	}

	void verifyMemHasSize(Operand op) const
	{
		if (op.isMEM && op.getBit == 0)
			throw new XError(ERR.MEM_SIZE_IS_NOT_SPECIFIED);
	}
	
	//	mov(r, imm) = db(imm, mov_imm(r, imm))
	int mov_imm(Reg reg, size_t imm)
	{
		int bit = reg.getBit();
		const int idx  = reg.getIdx();
		int code = 0xB0 | ((bit == 8 ? 0 : 1) << 3);
		if (bit == 64 && (imm & ~cast(size_t) (0xffffffffu)) == 0)
		{
			rex(new Reg32(idx));
			bit = 32;
		}
		else
		{
			rex(reg);
			if (bit == 64 && inner.IsInInt32(imm))
			{
				db(0xC7);
				code = 0xC0;
				bit  = 32;
			}
		}
		db(code | (idx & 7));
		return bit / 8;
	}


	void putL_inner(T)(T label, bool relative = false, size_t disp = 0)
	if(is(T == string) || is(T == Label) )
	{
		const int jmpSize = relative ? 4 : cast(int) size_t.sizeof;
		if (isAutoGrow() && size_ + 16 >= maxSize_)
			growMemory();
		size_t offset = 0;
		if (labelMgr_.getOffset(&offset, label))
		{
			if (relative)
			{
				db(inner.VerifyInInt32(offset + disp - size_ - jmpSize), jmpSize);
			}
			else if (isAutoGrow())
			{
				db(uint64(0), jmpSize);
				save(size_ - jmpSize, offset, jmpSize, inner.LabelMode.LaddTop);
			}
			else
			{
				db(cast(size_t) top_ + offset, jmpSize);
			}
			return;
		}
		db(uint64(0), jmpSize);
		JmpLabel jmp = JmpLabel(size_, jmpSize, (relative ? inner.LabelMode.LasIs : isAutoGrow() ? inner.LabelMode.LaddTop : inner.LabelMode.Labs), disp);
		labelMgr_.addUndefinedLabel(label, jmp);
	}


	void opMovxx(Reg reg, Operand op, uint8 code)
	{
		if (op.isBit(32))
			throw new XError(ERR.BAD_COMBINATION);

		int w = op.isBit(16);

		version (XBYAK64)
		{
			if (op.isHigh8bit())
				throw new XError(ERR.BAD_COMBINATION);
		}

		bool cond = reg.isREG && (reg.getBit > op.getBit);
		opModRM(reg, op, cond && op.isREG, cond && op.isMEM, 0x0F, code | w);
	}

	void opFpuMem(Address addr, uint8 m16, uint8 m32, uint8 m64, uint8 ext, uint8 m64ext)
	{
		if (addr.is64bitDisp)	throw new XError(ERR.CANT_USE_64BIT_DISP);
		uint8 code = addr.isBit(16) ? m16 : addr.isBit(32) ? m32 : addr.isBit(64) ? m64 : 0;
		if (!code)	throw new XError(ERR.BAD_MEM_SIZE);
		if (m64ext && addr.isBit(64))	ext = m64ext;
		
		rex(addr, st0);
		db(code);
		opAddr(addr, ext);
	}

// use code1 if reg1 == st0
// use code2 if reg1 != st0 && reg2 == st0
	void opFpuFpu(Fpu reg1, Fpu reg2, uint32 code1, uint32 code2)
	{
		uint32 code = reg1.getIdx == 0 ? code1 : reg2.getIdx == 0 ? code2 : 0;
		if (!code)
			throw new XError(ERR.BAD_ST_COMBINATION);

		db(cast(uint8) (code >> 8));
		db(cast(uint8) (code | (reg1.getIdx | reg2.getIdx)));
	}

	void opFpu(Fpu reg, uint8 code1, uint8 code2)
	{
		db(code1);
		db(code2 | reg.getIdx);
	}

	void opVex(Reg r, Operand op1, Operand op2, int type, int code, int imm8 = NONE)
	{
		if (op2.isMEM()) {
			Address addr = op2.getAddress();
			RegExp regExp = addr.getRegExp();
			Reg base = regExp.getBase();
			Reg index = regExp.getIndex();
			if (BIT == 64 && addr.is32bit()) db(0x67);
			int disp8N = 0;
			bool x = index.isExtIdx();
			
			if ((type & (T_MUST_EVEX | T_MEM_EVEX)) || r.hasEvex() || (op1 && op1.hasEvex()) || addr.isBroadcast() || addr.getOpmaskIdx()) {
				int aaa = addr.getOpmaskIdx();
				if (aaa && !(type & T_M_K)) throw new XError(ERR.INVALID_OPMASK_WITH_MEMORY);
				bool b = false;
				if (addr.isBroadcast()) {
					if (!(type & (T_B32 | T_B64))) throw new XError(ERR.INVALID_BROADCAST);
					b = true;
				}
				int VL = regExp.isVsib() ? index.getBit() : 0;
				disp8N = evex(r, base, op1, type, code, x, b, aaa, VL, index.isExtIdx2());
			} else {
				vex(r, base, op1, type, code, x);
			}
			opAddr(addr, r.getIdx(), (imm8 != NONE) ? 1 : 0, disp8N, (type & T_VSIB) != 0);
		} else {		
			Reg base = op2.getReg();
			if ((type & T_MUST_EVEX) || r.hasEvex() || (op1 && op1.hasEvex()) || base.hasEvex()) {
				evex(r, base, op1, type, code);
			} else {
				vex(r, base, op1, type, code);
			}
			setModRM(3, r.getIdx(), base.getIdx());
		}
		if (imm8 != NONE) db(imm8);
	}		

// (r, r, r/m) if isR_R_RM
// (r, r/m, r)
	void opGpr(Reg32e r, Operand op1, Operand op2, int type, uint8 code, bool isR_R_RM, int imm8 = NONE)
	{
		Operand p1 = op1;
		Operand p2 = op2;
		if (!isR_R_RM)	swap(p1, p2);
		uint bit = r.getBit;
		if (p1.getBit != bit || (p2.isREG && p2.getBit != bit))	throw new XError(ERR.BAD_COMBINATION);
		type |= (bit == 64) ? T_W1 : T_W0;
		opVex(r, p1, p2, type, code, imm8);
	}
	void opAVX_X_X_XM(Xmm x1, Operand op1, Operand op2, int type, int code0, int imm8 = NONE)
	{
		Xmm x2 = cast(Xmm)op1;
		Operand op = op2;
		if (op2.isNone) { // (x1, op1) -> (x1, x1, op1)
			x2 = x1;
			op = op1;
		}
		// (x1, x2, op)
		if (!((x1.isXMM && x2.isXMM) || ((type & T_YMM) && ((x1.isYMM && x2.isYMM) || (x1.isZMM && x2.isZMM))))) throw new XError(ERR.BAD_COMBINATION);
		opVex(x1, x2, op, type, code0, imm8);
	}

	void opAVX_K_X_XM(Opmask k, Xmm x2, Operand op3, int type, int code0, int imm8 = NONE)
	{
		if (!op3.isMEM() && (x2.getKind() != op3.getKind())) throw new XError(ERR.BAD_COMBINATION);
		opVex(k, x2, op3, type, code0, imm8);
	}

	// (x, x/m), (y, x/m256), (z, y/m)
	void checkCvt1(Operand x, Operand op)
	{
		if (!op.isMEM() && !(x.isKind(Kind.XMM | Kind.YMM) && op.isXMM()) && !(x.isZMM() && op.isYMM())) throw new XError(ERR.BAD_COMBINATION);
	}
	// (x, x/m), (x, y/m256), (y, z/m)
	void checkCvt2(Xmm x, Operand op)
	{
		if (!(x.isXMM() && op.isKind(Kind.XMM | Kind.YMM | Kind.MEM)) && !(x.isYMM() && op.isKind(Kind.ZMM | Kind.MEM))) throw new XError(ERR.BAD_COMBINATION);
	}
	void opCvt2(Xmm x, Operand op, int type, int code)
	{
		checkCvt2(x, op);
		int kind = x.isXMM() ? (op.isBit(256) ? Kind.YMM : Kind.XMM) : Kind.ZMM;
		opVex(x.copyAndSetKind(kind), xm0, op, type, code);
	}
	void opCvt3(Xmm x1, Xmm x2, Operand op, int type, int type64, int type32, uint8 code)
	{
		if (!(x1.isXMM() && x2.isXMM() && (op.isREG(i32e) || op.isMEM()))) throw new XError(ERR.BAD_SIZE_OF_REGISTER);
		Xmm x = new Xmm(op.getIdx());
		Operand p = op.isREG() ? x : op;
		opVex(x1, x2, p, (type | (op.isBit(64) ? type64 : type32)), code);
	}
	const Xmm cvtIdx0(Operand x)
	{
		return x.isZMM() ? zm0 : x.isYMM() ? ym0 : xm0;
	}

// support (x, x/m, imm), (y, y/m, imm)
	void opAVX_X_XM_IMM(Xmm x, Operand op, int type, int code, int imm8 = NONE)
	{
		opAVX_X_X_XM(x, cvtIdx0(x), op, type, code, imm8);
	}
// QQQ:need to refactor
	void opSp1(Reg reg, Operand op, uint8 pref, uint8 code0, uint8 code1)
	{
		if (reg.isBit(8))
			throw new XError(ERR.BAD_SIZE_OF_REGISTER);
		bool is16bit = reg.isREG(16) && (op.isREG(16) || op.isMEM);
		if (!is16bit && !(reg.isREG(i32e) && (op.isREG(reg.getBit) || op.isMEM)))
			throw new XError(ERR.BAD_COMBINATION);
		if (is16bit)
			db(0x66);
		db(pref); opModRM(reg.changeBit(i32e == 32 ? 32 : reg.getBit), op, op.isREG, true, code0, code1);
	}

	void opGather(Xmm x1, Address addr, Xmm x2, int type, uint8 code, int mode)
	{
		RegExp regExp = addr.getRegExp();
		if (!regExp.isVsib(128 | 256)) throw new XError(ERR.BAD_VSIB_ADDRESSING);
		int y_vx_y = 0;
		int y_vy_y = 1;
//		int x_vy_x = 2;
		bool isAddrYMM = regExp.getIndex().getBit() == 256;

		if (!x1.isXMM || isAddrYMM || !x2.isXMM)
		{
			bool isOK = false;
			if (mode == y_vx_y)
			{
				isOK = x1.isYMM && !isAddrYMM && x2.isYMM;
			}
			else if (mode == y_vy_y)
			{
				isOK = x1.isYMM && isAddrYMM && x2.isYMM;
			}
			else     // x_vy_x
			{
				isOK = !x1.isYMM && isAddrYMM && !x2.isYMM;
			}
			if (!isOK)
				throw new XError(ERR.BAD_VSIB_ADDRESSING);
		}
		opAVX_X_X_XM(isAddrYMM ? new Ymm(x1.getIdx()) : x1, isAddrYMM ? new Ymm(x2.getIdx()) : x2, addr, type, code);
	}
	
	enum {
		xx_yy_zz = 0,
		xx_yx_zy = 1,
		xx_xy_yz = 2
	}
	
	void checkGather2(Xmm x1, Reg x2, int mode) const
	{
		if (x1.isXMM() && x2.isXMM()) return;
		switch (mode) {
		case xx_yy_zz: if ((x1.isYMM() && x2.isYMM()) || (x1.isZMM() && x2.isZMM())) return;
			break;
		case xx_yx_zy: if ((x1.isYMM() && x2.isXMM()) || (x1.isZMM() && x2.isYMM())) return;
			break;
		case xx_xy_yz: if ((x1.isXMM() && x2.isYMM()) || (x1.isYMM() && x2.isZMM())) return;
			break;
		default:
			break;
		}
		throw new XError(ERR.BAD_VSIB_ADDRESSING);
	}
	
	void opGather2(Xmm x, Address addr, int type, uint8 code, int mode)
	{
		if (x.hasZero()) throw new XError(ERR.INVALID_ZERO);
		checkGather2(x, addr.getRegExp().getIndex(), mode);
		opVex(x, null, addr, type, code);
	}
	/*
		xx_xy_yz ; mode = true
		xx_xy_xz ; mode = false
	*/
	void opVmov(Operand op, Xmm x, int type, uint8 code, bool mode)
	{
		if (mode) {
			if (!op.isMEM() && !((op.isXMM() && x.isXMM()) || (op.isXMM() && x.isYMM()) || (op.isYMM() && x.isZMM())))  throw new XError(ERR.BAD_COMBINATION);
		} else {
			if (!op.isMEM() && !op.isXMM()) throw new XError(ERR.BAD_COMBINATION);
		}
		opVex(x, cast(Operand)null, op, type, code);
	}
	void opGatherFetch(Address addr, Xmm x, int type, uint8 code, int kind)
	{
		if (addr.hasZero()) throw new XError(ERR.INVALID_ZERO);
		if (addr.getRegExp().getIndex().getKind() != kind) throw new XError(ERR.BAD_VSIB_ADDRESSING);
		opVex(x, cast(Operand)null, addr, type, code);
	}
	
	void opInOut(Reg a, Reg d, uint8 code)
	{
		if (a.getIdx() == Operand.AL && d.getIdx() == Operand.DX && d.getBit() == 16) {
			switch (a.getBit())
			{
				case 8: db(code); return;
				case 16: db(0x66); db(code + 1); return;
				case 32: db(code + 1); return;
				default: break;
			}
		}
		throw new XError(ERR.BAD_COMBINATION);
	}
	void opInOut(Reg a, uint8 code, uint8 v)
	{
		if (a.getIdx() == Operand.AL) {
			switch (a.getBit())
			{
				case 8: db(code); db(v); return;
				case 16: db(0x66); db(code + 1); db(v); return;
				case 32: db(code + 1); db(v); return;
				default: break;
			}
		}
		throw new XError(ERR.BAD_COMBINATION);
	}
	
public:
	size_t getVersion() const
	{
		return xbyak.VERSION;
	}
	enum
	{
		mm0   = new Mmx(0), mm1 = new Mmx(1), mm2 = new Mmx(2), mm3 = new Mmx(3),
		mm4   = new Mmx(4), mm5 = new Mmx(5), mm6 = new Mmx(6), mm7 = new Mmx(7),
		xmm0  = new Xmm(0), xmm1 = new Xmm(1), xmm2 = new Xmm(2), xmm3 = new Xmm(3),
		xmm4  = new Xmm(4), xmm5 = new Xmm(5), xmm6 = new Xmm(6), xmm7 = new Xmm(7),
		ymm0  = new Ymm(0), ymm1 = new Ymm(1), ymm2 = new Ymm(2), ymm3 = new Ymm(3),
		ymm4  = new Ymm(4), ymm5 = new Ymm(5), ymm6 = new Ymm(6), ymm7 = new Ymm(7),
		zmm0  = new Zmm(0), zmm1 = new Zmm(1), zmm2 = new Zmm(2), zmm3 = new Zmm(3),
		zmm4  = new Zmm(4), zmm5 = new Zmm(5), zmm6 = new Zmm(6), zmm7 = new Zmm(7),
		// for my convenience		
		xm0   = xmm0, xm1 = xmm1, xm2 = xmm2, xm3 = xmm3,
		xm4   = xmm4, xm5 = xmm5, xm6 = xmm6, xm7 = xmm7,
		ym0   = ymm0, ym1 = ymm1, ym2 = ymm2, ym3 = ymm3,
		ym4   = ymm4, ym5 = ymm5, ym6 = ymm6, ym7 = ymm7,
		zm0   = zmm0, zm1 = zmm1, zm2 = zmm2, zm3 = zmm3,
		zm4   = zmm4, zm5 = zmm5, zm6 = zmm6, zm7 = zmm7,		
			
		eax = new Reg32(Operand.EAX),
		ecx = new Reg32(Operand.ECX),
		edx = new Reg32(Operand.EDX),
		ebx = new Reg32(Operand.EBX),
		esp = new Reg32(Operand.ESP),
		ebp = new Reg32(Operand.EBP),
		esi = new Reg32(Operand.ESI),
		edi = new Reg32(Operand.EDI),
		ax    = new Reg16(Operand.EAX), cx = new Reg16(Operand.ECX), dx = new Reg16(Operand.EDX), bx = new Reg16(Operand.EBX),
		sp    = new Reg16(Operand.ESP), bp = new Reg16(Operand.EBP), si = new Reg16(Operand.ESI), di = new Reg16(Operand.EDI),
		al    = new Reg8(Operand.AL), cl = new Reg8(Operand.CL), dl = new Reg8(Operand.DL), bl = new Reg8(Operand.BL),
		ah    = new Reg8(Operand.AH), ch = new Reg8(Operand.CH), dh = new Reg8(Operand.DH), bh = new Reg8(Operand.BH),
		ptr   = new AddressFrame(0),
		byte_ = new AddressFrame(8),
		word  = new AddressFrame(16),
		dword = new AddressFrame(32),
		qword = new AddressFrame(64),
		xword = new AddressFrame(128), 
		yword = new AddressFrame(256), 
		zword = new AddressFrame(512),
		ptr_b = new AddressFrame(0, true),
		xword_b = new AddressFrame(128, true), 
		yword_b = new AddressFrame(256, true),
		zword_b = new AddressFrame(512, true),
		st0   = new Fpu(0), st1 = new Fpu(1), st2 = new Fpu(2), st3 = new Fpu(3),
		st4   = new Fpu(4), st5 = new Fpu(5), st6 = new Fpu(6), st7 = new Fpu(7),
		k0 = new Opmask(0), k1 = new Opmask(1), k2 = new Opmask(2), k3 = new Opmask(3), 
		k4 = new Opmask(4), k5 = new Opmask(5), k6 = new Opmask(6), k7 = new Opmask(7),
		bnd0 = new BoundsReg(0),
		bnd1 = new BoundsReg(1),
		bnd2 = new BoundsReg(2),
		bnd3 = new BoundsReg(3),
		T_sae = new EvexModifierRounding(EvexModifierRounding.T_SAE),
		T_rn_sae = new EvexModifierRounding(EvexModifierRounding.T_RN_SAE),
		T_rd_sae = new EvexModifierRounding(EvexModifierRounding.T_RD_SAE),
		T_ru_sae = new EvexModifierRounding(EvexModifierRounding.T_RU_SAE),
		T_rz_sae = new EvexModifierRounding(EvexModifierRounding.T_RZ_SAE),
		T_z = new EvexModifierZero()
	}
	version (XBYAK64)
	{
		enum
		{
			rax = new Reg64(Operand.RAX),
			rcx = new Reg64(Operand.RCX),
			rdx = new Reg64(Operand.RDX),
			rbx = new Reg64(Operand.RBX),
			rsp = new Reg64(Operand.RSP),
			rbp = new Reg64(Operand.RBP),
			rsi = new Reg64(Operand.RSI),
			rdi = new Reg64(Operand.RDI),
			r8 = new Reg64(Operand.R8),
			r9 = new Reg64(Operand.R9),
			r10 = new Reg64(Operand.R10),
			r11 = new Reg64(Operand.R11),
			r12 = new Reg64(Operand.R12),
			r13 = new Reg64(Operand.R13),
			r14 = new Reg64(Operand.R14),
			r15 = new Reg64(Operand.R15),

			r8d = new Reg32(Operand.R8D),
			r9d = new Reg32(Operand.R9D),
			r10d = new Reg32(Operand.R10D),
			r11d = new Reg32(Operand.R11D),
			r12d = new Reg32(Operand.R12D),
			r13d = new Reg32(Operand.R13D),
			r14d = new Reg32(Operand.R14D),
			r15d = new Reg32(Operand.R15D),

			r8w = new Reg16(Operand.R8W),
			r9w = new Reg16(Operand.R9W),
			r10w = new Reg16(Operand.R10W),
			r11w = new Reg16(Operand.R11W),
			r12w = new Reg16(Operand.R12W),
			r13w = new Reg16(Operand.R13W),
			r14w = new Reg16(Operand.R14W),
			r15w = new Reg16(Operand.R15W),

			r8b = new Reg8(Operand.R8B),
			r9b = new Reg8(Operand.R9B),
			r10b = new Reg8(Operand.R10B),
			r11b = new Reg8(Operand.R11B),
			r12b = new Reg8(Operand.R12B),
			r13b = new Reg8(Operand.R13B),
			r14b = new Reg8(Operand.R14B),
			r15b = new Reg8(Operand.R15B),

			spl = new Reg8(Operand.SPL, true),
			bpl = new Reg8(Operand.BPL, true),
			sil = new Reg8(Operand.SIL, true),
			dil = new Reg8(Operand.DIL, true),

			xmm8 = new Xmm(8),
			xmm9 = new Xmm(9),
			xmm10 = new Xmm(10),
			xmm11 = new Xmm(11),
			xmm12 = new Xmm(12),
			xmm13 = new Xmm(13),
			xmm14 = new Xmm(14),
			xmm15 = new Xmm(15),
			xmm16 = new Xmm(16),
			xmm17 = new Xmm(17),
			xmm18 = new Xmm(18),
			xmm19 = new Xmm(19),
			xmm20 = new Xmm(20),
			xmm21 = new Xmm(21),
			xmm22 = new Xmm(22),
			xmm23 = new Xmm(23),
			xmm24 = new Xmm(24),
			xmm25 = new Xmm(25),
			xmm26 = new Xmm(26),
			xmm27 = new Xmm(27),
			xmm28 = new Xmm(28),
			xmm29 = new Xmm(29),
			xmm30 = new Xmm(30),
			xmm31 = new Xmm(31),
		
			ymm8 = new Ymm(8),
			ymm9 = new Ymm(9),
			ymm10 = new Ymm(10),
			ymm11 = new Ymm(11),
			ymm12 = new Ymm(12),
			ymm13 = new Ymm(13),
			ymm14 = new Ymm(14),
			ymm15 = new Ymm(15),
			ymm16 = new Ymm(16),
			ymm17 = new Ymm(17),
			ymm18 = new Ymm(18),
			ymm19 = new Ymm(19),
			ymm20 = new Ymm(20),
			ymm21 = new Ymm(21),
			ymm22 = new Ymm(22),
			ymm23 = new Ymm(23),
			ymm24 = new Ymm(24),
			ymm25 = new Ymm(25),
			ymm26 = new Ymm(26),
			ymm27 = new Ymm(27),
			ymm28 = new Ymm(28),
			ymm29 = new Ymm(29),
			ymm30 = new Ymm(30),
			ymm31 = new Ymm(31),

			zmm8 = new Zmm(8),
			zmm9 = new Zmm(9),
			zmm10 = new Zmm(10),
			zmm11 = new Zmm(11),
			zmm12 = new Zmm(12),
			zmm13 = new Zmm(13),
			zmm14 = new Zmm(14),
			zmm15 = new Zmm(15),
			zmm16 = new Zmm(16),
			zmm17 = new Zmm(17),
			zmm18 = new Zmm(18),
			zmm19 = new Zmm(19),
			zmm20 = new Zmm(20),
			zmm21 = new Zmm(21),
			zmm22 = new Zmm(22),
			zmm23 = new Zmm(23),
			zmm24 = new Zmm(24),
			zmm25 = new Zmm(25),
			zmm26 = new Zmm(26),
			zmm27 = new Zmm(27),
			zmm28 = new Zmm(28),
			zmm29 = new Zmm(29),
			zmm30 = new Zmm(30),
			zmm31 = new Zmm(31),

			// for my convenience
			xm8 = xmm8, xm9 = xmm9, xm10 = xmm10, xm11 = xmm11, xm12 = xmm12, xm13 = xmm13, xm14 = xmm14, xm15 = xmm15, 
			xm16 = xmm16, xm17 = xmm17, xm18 = xmm18, xm19 = xmm19, xm20 = xmm20, xm21 = xmm21, xm22 = xmm22, xm23 = xmm23, 
			xm24 = xmm24, xm25 = xmm25, xm26 = xmm26, xm27 = xmm28, xm29 = xmm29, xm30 = xmm30, xm31 = xmm31,
			
			ym8 = ymm8, ym9 = ymm9, ym10 = ymm10, ym11 = ymm11, ym12 = ymm12, ym13 = ymm13, ym14 = ymm14, ym15 = ymm15, 
			ym16 = ymm16, ym17 = ymm17, ym18 = ymm18, ym19 = ymm19, ym20 = ymm20, ym21 = ymm21, ym22 = ymm22, ym23 = ymm23, 
			ym24 = ymm24, ym25 = ymm25, ym26 = ymm26, ym27 = ymm28, ym29 = ymm29, ym30 = ymm30, ym31 = ymm31,
			
			zm8 = zmm8, zm9 = zmm9, zm10 = zmm10, zm11 = zmm11, zm12 = zmm12, zm13 = zmm13, zm14 = zmm14, zm15 = zmm15, 
			zm16 = zmm16, zm17 = zmm17, zm18 = zmm18, zm19 = zmm19, zm20 = zmm20, zm21 = zmm21, zm22 = zmm22, zm23 = zmm23, 
			zm24 = zmm24, zm25 = zmm25, zm26 = zmm26, zm27 = zmm28, zm29 = zmm29, zm30 = zmm30, zm31 = zmm31,

			rip = RegRip()
		}
		version (XBYAK_DISABLE_SEGMENT) {}
		else{
		    enum{
			    es = new Segment(Segment.es),
			    cs = new Segment(Segment.cs),
			    ss = new Segment(Segment.ss),
			    ds = new Segment(Segment.ds),
			    fs = new Segment(Segment.fs),
			    gs = new Segment(Segment.gs)
		    }
        }
	}
	
	Label L()
	{
		return new Label();
	}
	void L(string label)
	{
		labelMgr_.defineSlabel(label);
	}
	void L(Label label)
	{
		labelMgr_.defineClabel(label);
	}
	void inLocalLabel()
	{
		labelMgr_.enterLocal;
	}
	void outLocalLabel()
	{
		labelMgr_.leaveLocal;
	}

//		assign src to dst
//		require
//		dst : does not used by L()
//		src : used by L()
	void assignL(Label dst, Label src)
	{
		labelMgr_.assign(dst, src);
	}

	/*
		put address of label to buffer
		@note the put size is 4(32-bit), 8(64-bit)
	*/
	void putL(string label) { putL_inner(label); }
	void putL(Label label) { putL_inner(label); }

	void jmp(Operand op) { opR_ModM(op, BIT, 4, 0xFF, NONE, NONE, true); }
	void jmp(string label, LabelType type = T_AUTO) { opJmp(label, type, 0xEB, 0xE9, 0); }
	void jmp(const char* label, LabelType type = T_AUTO) { jmp(to!string(label), type); }
	void jmp(Label label, LabelType type = T_AUTO) { opJmp(label, type, 0xEB, 0xE9, 0); }
	void jmp(const void* addr, LabelType type = T_AUTO) { opJmpAbs(addr, type, 0xEB, 0xE9); }
	
	void call(Operand op) { opR_ModM(op, 16 | i32e, 2, 0xFF, NONE, NONE, true); }
	// call(string label), not string
	void call(string label) { opJmp(label, T_NEAR, 0, 0xE8, 0); }
	void call(const char* label) { call(to!string(label)); }
	void call(Label label) { opJmp(label, T_NEAR, 0, 0xE8, 0); }

	// call(function pointer)
version(XBYAK_VARIADIC_TEMPLATE)
{	
    void call(Ret, Params)(Ret function(Params...) func)
    {
        call(CastTo(opJmpAbs(&func)));
    }
}   
	
	void call(void* addr) { opJmpAbs(addr, T_NEAR, 0, 0xE8); }

	void test(Operand op, Reg reg)
	{
		opModRM(reg, op, op.isREG && (op.getKind == reg.getKind), op.isMEM, 0x84);
	}

	void test(Operand op, uint32 imm)
	{
		verifyMemHasSize(op);
		int immSize = min(op.getBit / 8, 4U);
		if (op.isREG && op.getIdx == 0)   // al, ax, eax
		{
			rex(op);
			db(0xA8 | (op.isBit(8) ? 0 : 1));
		}
		else
		{
			opR_ModM(op, 0, 0, 0xF6, NONE, NONE, false, immSize);
		}
		db(imm, immSize);
	}

	void imul(Reg reg, Operand op)
	{
		opModRM(reg, op, op.isREG && (reg.getKind == op.getKind), op.isMEM, 0x0F, 0xAF);
	}

	void imul(Reg reg, Operand op, int imm)
	{
		int s = inner.IsInDisp8(imm) ? 1 : 0;
		int immSize = s ? 1 : reg.isREG(16) ? 2 : 4;
		opModRM(reg, op, op.isREG && (reg.getKind == op.getKind), op.isMEM, 0x69 | (s << 1), NONE, NONE, immSize);
		db(imm, immSize);
	}

	void pop(Operand op) { opPushPop(op, 0x8F, 0, 0x58); }
	void push(Operand op) { opPushPop(op, 0xFF, 6, 0x50); }
	void push(AddressFrame af, uint32 imm)
	{
		if (af.bit_ == 8 && inner.IsInDisp8(imm))
		{
			db(0x6A); db(imm);
		}
		else if (af.bit_ == 16 && inner.IsInDisp16(imm))
		{
			db(0x66); db(0x68); dw(imm);
		}
		else
		{
			db(0x68); dd(imm);
		}
	}

	// use "push(word, 4)" if you want "push word 4"
	void push(uint32 imm)
	{
		if (inner.IsInDisp8(imm))
		{
			push(byte_, imm);
		}
		else
		{
			push(dword, imm);
		}
	}


	void mov(Operand reg1, Operand reg2)
	{
		Reg reg;
		Address addr;
		uint8 code;
		if (reg1.isREG() && reg1.getIdx() == 0 && reg2.isMEM())   // mov eax|ax|al, [disp]
		{
			reg  = reg1.getReg();
			addr = reg2.getAddress();
			code = 0xA0;
		}
		else if (reg1.isMEM() && reg2.isREG() && reg2.getIdx() == 0)     // mov [disp], eax|ax|al
		{
			reg  = reg2.getReg();
			addr = reg1.getAddress();
			code = 0xA2;
		}

version (XBYAK64)
{
			if (addr && addr.is64bitDisp)
			{
				if (code)
				{
					rex(reg);
					db(reg1.isREG(8) ? 0xA0 : reg1.isREG() ? 0xA1 : reg2.isREG(8) ? 0xA2 : 0xA3);
					db(addr.getDisp(), 8);
				}
				else
					throw new XError(ERR.BAD_COMBINATION);
			}
			else
				opRM_RM(reg1, reg2, 0x88);
}
else
{
			if (code && addr.isOnlyDisp())
			{
				rex(reg, addr);
				db(code | (reg.isBit(8) ? 0 : 1));
				dd(cast(uint32) (addr.getDisp()));
			}
			else
				opRM_RM(reg1, reg2, 0x88);
}
	}

	void mov(Operand op, size_t imm)
	{
		if (op.isREG()) {
			const int size = mov_imm(op.getReg(), imm);
			db(imm, size);
		} else if (op.isMEM()) {
			verifyMemHasSize(op);
			int immSize = op.getBit() / 8;
			if (immSize <= 4) {
				sint64 s = sint64(imm) >> (immSize * 8);
				if (s != 0 && s != -1) throw new XError(ERR.IMM_IS_TOO_BIG);
			} else {
				if (!inner.IsInInt32(imm)) throw new XError(ERR.IMM_IS_TOO_BIG);
				immSize = 4;
			}
			opModM(op.getAddress(), new Reg(0, Kind.REG, op.getBit()), 0xC6, NONE, NONE, immSize);
			db(cast(uint32)(imm), immSize);
		} else {
			throw new XError(ERR.BAD_COMBINATION);
		}
	}
	
	void mov(NativeReg reg, const char* label) // can't use string
	{
		if (label == null) {
			mov(cast(Operand)(reg), 0); // call imm
			return;
		}
		mov_imm(reg, dummyAddr);
		putL(to!string(label));
	}

	void mov(NativeReg reg, Label label)
	{
		mov_imm(reg, dummyAddr);
		putL(label);
	}

	void xchg(Operand op1, Operand op2)
	{
		Operand p1 = op1;
		Operand p2 = op2;
		if (p1.isMEM || (p2.isREG(16 | i32e) && p2.getIdx == 0))
		{
			p1 = op2; p2 = op1;
		}
		if (p1.isMEM)
			throw new XError(ERR.BAD_COMBINATION);

		bool BL = true;
		version (XBYAK64)
		{
			BL = (p2.getIdx != 0 || !p1.isREG(32));
		}
		if (p2.isREG && (p1.isREG(16 | i32e) && p1.getIdx == 0) && BL)
		{
			rex(p2, p1);
			db(0x90 | (p2.getIdx & 7));
			return;
		}
		opModRM(p1, p2, (p1.isREG && p2.isREG && (p1.getBit == p2.getBit)), p2.isMEM, 0x86 | (p1.isBit(8) ? 40 : 1));
	}

version(XBYAK_DISABLE_SEGMENT){}
else
{
	void push(Segment seg)
	{
		switch (seg.getIdx()) {
		case Segment.es: db(0x06); break;
		case Segment.cs: db(0x0E); break;
		case Segment.ss: db(0x16); break;
		case Segment.ds: db(0x1E); break;
		case Segment.fs: db(0x0F); db(0xA0); break;
		case Segment.gs: db(0x0F); db(0xA8); break;
		default:
			assert(0);
		}
	}
	void pop(Segment seg)
	{
		switch (seg.getIdx()) {
		case Segment.es: db(0x07); break;
		case Segment.cs: throw new XError(ERR.BAD_COMBINATION);
		case Segment.ss: db(0x17); break;
		case Segment.ds: db(0x1F); break;
		case Segment.fs: db(0x0F); db(0xA1); break;
		case Segment.gs: db(0x0F); db(0xA9); break;
		default:
			assert(0);
		}
	}
	void putSeg(Segment seg)
	{
		switch (seg.getIdx()) {
		case Segment.es: db(0x2E); break;
		case Segment.cs: db(0x36); break;
		case Segment.ss: db(0x3E); break;
		case Segment.ds: db(0x26); break;
		case Segment.fs: db(0x64); break;
		case Segment.gs: db(0x65); break;
		default:
			assert(0);
		}
	}
	void mov(Operand op, Segment seg)
	{
		opModRM(new Reg8(seg.getIdx()), op, op.isREG(16|i32e), op.isMEM(), 0x8C);
	}
	void mov(Segment seg, Operand op)
	{
		Reg r1 = op.getReg().cvt32();
		Operand op_r1 = cast(Operand)r1;
		opModRM(new Reg8(seg.getIdx()), op.isREG(16|i32e) ? op_r1 : op, op.isREG(16|i32e), op.isMEM(), 0x8E);
	}
}		
		
	enum { NONE = 256 }
public:
    this(size_t maxSize = DEFAULT_MAX_CODE_SIZE, void* userPtr = null, Allocator allocator = new Allocator())
	{
		super(maxSize, userPtr, allocator);
		this.reset();	////fix
		
		labelMgr_.set(this);
	}

	void reset()
	{
		resetSize;
		labelMgr_.reset;
		labelMgr_.set(this);
	}

	bool hasUndefinedLabel() const
	{
		return labelMgr_.hasUndefSlabel() || labelMgr_.hasUndefClabel();
	}


	/*
		MUST call ready() to complete generating code if you use AutoGrow mode.
		It is not necessary for the other mode if hasUndefinedLabel() is true.
	*/
	void ready(ProtectMode mode = ProtectMode.PROTECT_RWE)
	{
//		if (hasUndefinedLabel()) throw new XError(ERR.LABEL_IS_NOT_FOUND);
		if (isAutoGrow()) {
			calcJmpAddress();
			if (useProtect()) setProtectMode(mode);
		}
	}
	
	// set read/exec
	void readyRE() { return ready(ProtectMode.PROTECT_RE); }

	/*
		use single byte nop if useMultiByteNop = false
	*/
	void nop(size_t size = 1, bool useMultiByteNop = true)
	{
		if (!useMultiByteNop) {
			for (size_t i = 0; i < size; i++) {
				db(0x90);
			}
			return;
		}
		/*
			Intel Architectures Software Developer's Manual Volume 2
			recommended multi-byte sequence of NOP instruction
			AMD and Intel seem to agree on the same sequences for up to 9 bytes:
			https://support.amd.com/TechDocs/55723_SOG_Fam_17h_Processors_3.00.pdf
		*/
		uint8[][] nopTbl = [
			[0x90],
			[0x66, 0x90],
			[0x0F, 0x1F, 0x00],
			[0x0F, 0x1F, 0x40, 0x00],
			[0x0F, 0x1F, 0x44, 0x00, 0x00],
			[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],
			[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],
			[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
			[0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
		];
		size_t n = nopTbl.sizeof / nopTbl[0].sizeof;
		while (size > 0) {
			size_t len = min(n, size);
			uint8* seq = nopTbl[len - 1].ptr;
			db(seq, len);
			size -= len;
		}
	}

	void Align(int x = 16)
	{
		if (x == 1)
			return;
		if (x < 1 || (x & (x - 1)))
			throw new XError(ERR.BAD_ALIGN);
		if (isAutoGrow() && x > cast(int) inner.ALIGN_PAGE_SIZE)
		{
			throw new Exception(format("warning:autoGrow mode does not support %d align", x));
		}
		while (cast(size_t) getCurr % x)
		{
			nop();
		}
	}


string getVersionString() const { return "0.099"; }
void adc(Operand op, uint32 imm) { opRM_I(op, imm, 0x10, 2); }
void adc(Operand op1, Operand op2) { opRM_RM(op1, op2, 0x10); }
void adcx(Reg32e reg, Operand op) { opGen(reg, op, 0xF6, 0x66, &isREG32_REG32orMEM, NONE, 0x38); }
void add(Operand op, uint32 imm) { opRM_I(op, imm, 0x00, 0); }
void add(Operand op1, Operand op2) { opRM_RM(op1, op2, 0x00); }
void addpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x58, 0x66, &isXMM_XMMorMEM); }
void addps(Xmm xmm, Operand op) { opGen(xmm, op, 0x58, 0x100, &isXMM_XMMorMEM); }
void addsd(Xmm xmm, Operand op) { opGen(xmm, op, 0x58, 0xF2, &isXMM_XMMorMEM); }
void addss(Xmm xmm, Operand op) { opGen(xmm, op, 0x58, 0xF3, &isXMM_XMMorMEM); }
void addsubpd(Xmm xmm, Operand op) { opGen(xmm, op, 0xD0, 0x66, &isXMM_XMMorMEM); }
void addsubps(Xmm xmm, Operand op) { opGen(xmm, op, 0xD0, 0xF2, &isXMM_XMMorMEM); }
void adox(Reg32e reg, Operand op) { opGen(reg, op, 0xF6, 0xF3, &isREG32_REG32orMEM, NONE, 0x38); }
void aesdec(Xmm xmm, Operand op) { opGen(xmm, op, 0xDE, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void aesdeclast(Xmm xmm, Operand op) { opGen(xmm, op, 0xDF, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void aesenc(Xmm xmm, Operand op) { opGen(xmm, op, 0xDC, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void aesenclast(Xmm xmm, Operand op) { opGen(xmm, op, 0xDD, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void aesimc(Xmm xmm, Operand op) { opGen(xmm, op, 0xDB, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void aeskeygenassist(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0xDF, 0x66, &isXMM_XMMorMEM, imm, 0x3A); }
void and(Operand op, uint32 imm) { opRM_I(op, imm, 0x20, 4); }
void and(Operand op1, Operand op2) { opRM_RM(op1, op2, 0x20); }
void andn(Reg32e r1, Reg32e r2, Operand op) { opGpr(r1, r2, op, T_0F38, 0xf2, true); }
void andnpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x55, 0x66, &isXMM_XMMorMEM); }
void andnps(Xmm xmm, Operand op) { opGen(xmm, op, 0x55, 0x100, &isXMM_XMMorMEM); }
void andpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x54, 0x66, &isXMM_XMMorMEM); }
void andps(Xmm xmm, Operand op) { opGen(xmm, op, 0x54, 0x100, &isXMM_XMMorMEM); }


void bextr(Reg32e r1, Operand op, Reg32e r2) { opGpr(r1, op, r2, T_0F38, 0xf7, false); }
void blendpd(Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0x0D, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }
void blendps(Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0x0C, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }
void blendvpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x15, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void blendvps(Xmm xmm, Operand op) { opGen(xmm, op, 0x14, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void blsi(Reg32e r, Operand op) { opGpr(new Reg32e(3, r.getBit()), op, r, T_0F38, 0xf3, false); }
void blsmsk(Reg32e r, Operand op) { opGpr(new Reg32e(2, r.getBit()), op, r, T_0F38, 0xf3, false); }
void blsr(Reg32e r, Operand op) { opGpr(new Reg32e(1, r.getBit()), op, r, T_0F38, 0xf3, false); }
void bnd() { db(0xF2); }
void bndcl(BoundsReg bnd, Operand op) { db(0xF3); opR_ModM(op, i32e, bnd.getIdx(), 0x0F, 0x1A, NONE, !op.isMEM()); }
void bndcn(BoundsReg bnd, Operand op) { db(0xF2); opR_ModM(op, i32e, bnd.getIdx(), 0x0F, 0x1B, NONE, !op.isMEM()); }
void bndcu(BoundsReg bnd, Operand op) { db(0xF2); opR_ModM(op, i32e, bnd.getIdx(), 0x0F, 0x1A, NONE, !op.isMEM()); }
void bndldx(BoundsReg bnd, Address addr) { opMIB(addr, bnd, 0x0F, 0x1A); }
void bndmk(BoundsReg bnd, Address addr) { db(0xF3); opModM(addr, bnd, 0x0F, 0x1B); }
void bndmov(Address addr, BoundsReg bnd) { db(0x66); opModM(addr, bnd, 0x0F, 0x1B); }
void bndmov(BoundsReg bnd, Operand op) { db(0x66); opModRM(bnd, op, op.isBNDREG(), op.isMEM(), 0x0F, 0x1A); }
void bndstx(Address addr, BoundsReg bnd) { opMIB(addr, bnd, 0x0F, 0x1B); }
void bsf(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0xBC); }
void bsr(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0xBD); }
void bswap(Reg32e reg) { opModR(new Reg32(1), reg, 0x0F); }
void bt(Operand op, Reg reg) { opModRM(reg, op, op.isREG(16|32|64) && op.getBit() == reg.getBit(), op.isMEM(), 0x0f, 0xA3); }
void bt(Operand op, uint8 imm) { opR_ModM(op, 16|32|64, 4, 0x0f, 0xba, NONE, false, 1); db(imm); }
void btc(Operand op, Reg reg) { opModRM(reg, op, op.isREG(16|32|64) && op.getBit() == reg.getBit(), op.isMEM(), 0x0f, 0xBB); }
void btc(Operand op, uint8 imm) { opR_ModM(op, 16|32|64, 7, 0x0f, 0xba, NONE, false, 1); db(imm); }
void btr(Operand op, Reg reg) { opModRM(reg, op, op.isREG(16|32|64) && op.getBit() == reg.getBit(), op.isMEM(), 0x0f, 0xB3); }
void btr(Operand op, uint8 imm) { opR_ModM(op, 16|32|64, 6, 0x0f, 0xba, NONE, false, 1); db(imm); }
void bts(Operand op, Reg reg) { opModRM(reg, op, op.isREG(16|32|64) && op.getBit() == reg.getBit(), op.isMEM(), 0x0f, 0xAB); }
void bts(Operand op, uint8 imm) { opR_ModM(op, 16|32|64, 5, 0x0f, 0xba, NONE, false, 1); db(imm); }
void bzhi(Reg32e r1, Operand op, Reg32e r2) { opGpr(r1, op, r2, T_0F38, 0xf5, false); }

void cbw() { db(0x66); db(0x98); }
void cdq() { db(0x99); }
void clc() { db(0xF8); }
void cld() { db(0xFC); }
void clflush(Address addr) { opModM(addr, new Reg32(7), 0x0F, 0xAE); }
void clflushopt(Address addr) { db(0x66); opModM(addr, new Reg32(7), 0x0F, 0xAE); }
void cli() { db(0xFA); }
void clzero() { db(0x0F); db(0x01); db(0xFC); }
void cmc() { db(0xF5); }
void cmova(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 7); }
void cmovae(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 3); }
void cmovb(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 2); }
void cmovbe(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 6); }
void cmovc(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 2); }
void cmove(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 4); }
void cmovg(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 15); }
void cmovge(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 13); }
void cmovl(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 12); }
void cmovle(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 14); }
void cmovna(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 6); }
void cmovnae(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 2); }
void cmovnb(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 3); }
void cmovnbe(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 7); }
void cmovnc(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 3); }
void cmovne(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 5); }
void cmovng(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 14); }
void cmovnge(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 12); }
void cmovnl(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 13); }
void cmovnle(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 15); }
void cmovno(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 1); }
void cmovnp(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 11); }
void cmovns(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 9); }
void cmovnz(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 5); }
void cmovo(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 0); }
void cmovp(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 10); }
void cmovpe(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 10); }
void cmovpo(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 11); }
void cmovs(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 8); }
void cmovz(Reg reg, Operand op) { opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0x40 | 4); }
void cmp(Operand op, uint32 imm) { opRM_I(op, imm, 0x38, 7); }
void cmp(Operand op1, Operand op2) { opRM_RM(op1, op2, 0x38); }
void cmpeqpd(Xmm x, Operand op) { cmppd(x, op, 0); }
void cmpeqps(Xmm x, Operand op) { cmpps(x, op, 0); }
void cmpeqsd(Xmm x, Operand op) { cmpsd(x, op, 0); }
void cmpeqss(Xmm x, Operand op) { cmpss(x, op, 0); }
void cmplepd(Xmm x, Operand op) { cmppd(x, op, 2); }
void cmpleps(Xmm x, Operand op) { cmpps(x, op, 2); }
void cmplesd(Xmm x, Operand op) { cmpsd(x, op, 2); }
void cmpless(Xmm x, Operand op) { cmpss(x, op, 2); }
void cmpltpd(Xmm x, Operand op) { cmppd(x, op, 1); }
void cmpltps(Xmm x, Operand op) { cmpps(x, op, 1); }
void cmpltsd(Xmm x, Operand op) { cmpsd(x, op, 1); }
void cmpltss(Xmm x, Operand op) { cmpss(x, op, 1); }
void cmpneqpd(Xmm x, Operand op) { cmppd(x, op, 4); }
void cmpneqps(Xmm x, Operand op) { cmpps(x, op, 4); }
void cmpneqsd(Xmm x, Operand op) { cmpsd(x, op, 4); }
void cmpneqss(Xmm x, Operand op) { cmpss(x, op, 4); }
void cmpnlepd(Xmm x, Operand op) { cmppd(x, op, 6); }
void cmpnleps(Xmm x, Operand op) { cmpps(x, op, 6); }
void cmpnlesd(Xmm x, Operand op) { cmpsd(x, op, 6); }
void cmpnless(Xmm x, Operand op) { cmpss(x, op, 6); }
void cmpnltpd(Xmm x, Operand op) { cmppd(x, op, 5); }
void cmpnltps(Xmm x, Operand op) { cmpps(x, op, 5); }
void cmpnltsd(Xmm x, Operand op) { cmpsd(x, op, 5); }
void cmpnltss(Xmm x, Operand op) { cmpss(x, op, 5); }
void cmpordpd(Xmm x, Operand op) { cmppd(x, op, 7); }
void cmpordps(Xmm x, Operand op) { cmpps(x, op, 7); }
void cmpordsd(Xmm x, Operand op) { cmpsd(x, op, 7); }
void cmpordss(Xmm x, Operand op) { cmpss(x, op, 7); }
void cmppd(Xmm xmm, Operand op, uint8 imm8) { opGen(xmm, op, 0xC2, 0x66, &isXMM_XMMorMEM, imm8); }
void cmpps(Xmm xmm, Operand op, uint8 imm8) { opGen(xmm, op, 0xC2, 0x100, &isXMM_XMMorMEM, imm8); }
void cmpsb() { db(0xA6); }
void cmpsd() { db(0xA7); }
void cmpsd(Xmm xmm, Operand op, uint8 imm8) { opGen(xmm, op, 0xC2, 0xF2, &isXMM_XMMorMEM, imm8); }
void cmpss(Xmm xmm, Operand op, uint8 imm8) { opGen(xmm, op, 0xC2, 0xF3, &isXMM_XMMorMEM, imm8); }
void cmpsw() { db(0x66); db(0xA7); }
void cmpunordpd(Xmm x, Operand op) { cmppd(x, op, 3); }
void cmpunordps(Xmm x, Operand op) { cmpps(x, op, 3); }
void cmpunordsd(Xmm x, Operand op) { cmpsd(x, op, 3); }
void cmpunordss(Xmm x, Operand op) { cmpss(x, op, 3); }
void cmpxchg(Operand op, Reg reg) { opModRM(reg, op, (op.isREG() && reg.isREG() && op.getBit() == reg.getBit()), op.isMEM(), 0x0F, 0xB0 | (reg.isBit(8) ? 0 : 1)); }
void cmpxchg8b(Address addr) { opModM(addr, new Reg32(1), 0x0F, 0xC7); }
void comisd(Xmm xmm, Operand op) { opGen(xmm, op, 0x2F, 0x66, &isXMM_XMMorMEM); }
void comiss(Xmm xmm, Operand op) { opGen(xmm, op, 0x2F, 0x100, &isXMM_XMMorMEM); }
void cpuid() { db(0x0F); db(0xA2); }
void crc32(Reg32e reg, Operand op) { if (reg.isBit(32) && op.isBit(16)) db(0x66); db(0xF2); opModRM(reg, op, op.isREG(), op.isMEM(), 0x0F, 0x38, 0xF0 | (op.isBit(8) ? 0 : 1)); }
void cvtdq2pd(Xmm xmm, Operand op) { opGen(xmm, op, 0xE6, 0xF3, &isXMM_XMMorMEM); }
void cvtdq2ps(Xmm xmm, Operand op) { opGen(xmm, op, 0x5B, 0x100, &isXMM_XMMorMEM); }
void cvtpd2dq(Xmm xmm, Operand op) { opGen(xmm, op, 0xE6, 0xF2, &isXMM_XMMorMEM); }
void cvtpd2pi(Operand reg, Operand op) { opGen(reg, op, 0x2D, 0x66, &isMMX_XMMorMEM); }
void cvtpd2ps(Xmm xmm, Operand op) { opGen(xmm, op, 0x5A, 0x66, &isXMM_XMMorMEM); }
void cvtpi2pd(Operand reg, Operand op) { opGen(reg, op, 0x2A, 0x66, &isXMM_MMXorMEM); }
void cvtpi2ps(Operand reg, Operand op) { opGen(reg, op, 0x2A, 0x100, &isXMM_MMXorMEM); }
void cvtps2dq(Xmm xmm, Operand op) { opGen(xmm, op, 0x5B, 0x66, &isXMM_XMMorMEM); }
void cvtps2pd(Xmm xmm, Operand op) { opGen(xmm, op, 0x5A, 0x100, &isXMM_XMMorMEM); }
void cvtps2pi(Operand reg, Operand op) { opGen(reg, op, 0x2D, 0x100, &isMMX_XMMorMEM); }
void cvtsd2si(Operand reg, Operand op) { opGen(reg, op, 0x2D, 0xF2, &isREG32_XMMorMEM); }
void cvtsd2ss(Xmm xmm, Operand op) { opGen(xmm, op, 0x5A, 0xF2, &isXMM_XMMorMEM); }
void cvtsi2sd(Operand reg, Operand op) { opGen(reg, op, 0x2A, 0xF2, &isXMM_REG32orMEM); }
void cvtsi2ss(Operand reg, Operand op) { opGen(reg, op, 0x2A, 0xF3, &isXMM_REG32orMEM); }
void cvtss2sd(Xmm xmm, Operand op) { opGen(xmm, op, 0x5A, 0xF3, &isXMM_XMMorMEM); }
void cvtss2si(Operand reg, Operand op) { opGen(reg, op, 0x2D, 0xF3, &isREG32_XMMorMEM); }
void cvttpd2dq(Xmm xmm, Operand op) { opGen(xmm, op, 0xE6, 0x66, &isXMM_XMMorMEM); }
void cvttpd2pi(Operand reg, Operand op) { opGen(reg, op, 0x2C, 0x66, &isMMX_XMMorMEM); }
void cvttps2dq(Xmm xmm, Operand op) { opGen(xmm, op, 0x5B, 0xF3, &isXMM_XMMorMEM); }
void cvttps2pi(Operand reg, Operand op) { opGen(reg, op, 0x2C, 0x100, &isMMX_XMMorMEM); }
void cvttsd2si(Operand reg, Operand op) { opGen(reg, op, 0x2C, 0xF2, &isREG32_XMMorMEM); }
void cvttss2si(Operand reg, Operand op) { opGen(reg, op, 0x2C, 0xF3, &isREG32_XMMorMEM); }
void cwd() { db(0x66); db(0x99); }
void cwde() { db(0x98); }

void dec(Operand op) { opIncDec(op, 0x48, 1); }
void div(Operand op) { opR_ModM(op, 0, 6, 0xF6); }
void divpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x5E, 0x66, &isXMM_XMMorMEM); }
void divps(Xmm xmm, Operand op) { opGen(xmm, op, 0x5E, 0x100, &isXMM_XMMorMEM); }
void divsd(Xmm xmm, Operand op) { opGen(xmm, op, 0x5E, 0xF2, &isXMM_XMMorMEM); }
void divss(Xmm xmm, Operand op) { opGen(xmm, op, 0x5E, 0xF3, &isXMM_XMMorMEM); }
void dppd(Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0x41, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }
void dpps(Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0x40, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }

void emms() { db(0x0F); db(0x77); }
void enter(uint16 x, uint8 y) { db(0xC8); dw(x); db(y); }
void extractps(Operand op, Xmm xmm, uint8 imm) { opExt(op, xmm, 0x17, imm); }

void f2xm1() { db(0xD9); db(0xF0); }
void fabs() { db(0xD9); db(0xE1); }
void fadd(Address addr) { opFpuMem(addr, 0x00, 0xD8, 0xDC, 0, 0); }
void fadd(Fpu reg1) { opFpuFpu(st0, reg1, 0xD8C0, 0xDCC0); }
void fadd(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xD8C0, 0xDCC0); }
void faddp() { db(0xDE); db(0xC1); }
void faddp(Fpu reg1) { opFpuFpu(reg1, st0, 0x0000, 0xDEC0); }
void faddp(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0x0000, 0xDEC0); }
void fbld(Address addr) { opModM(addr, new Reg32(4), 0xDF, 0x100); }
void fbstp(Address addr) { opModM(addr, new Reg32(6), 0xDF, 0x100); }
void fchs() { db(0xD9); db(0xE0); }
void fclex() { db(0x9B); db(0xDB); db(0xE2); }
void fcmovb(Fpu reg1) { opFpuFpu(st0, reg1, 0xDAC0, 0x00C0); }
void fcmovb(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDAC0, 0x00C0); }
void fcmovbe(Fpu reg1) { opFpuFpu(st0, reg1, 0xDAD0, 0x00D0); }
void fcmovbe(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDAD0, 0x00D0); }
void fcmove(Fpu reg1) { opFpuFpu(st0, reg1, 0xDAC8, 0x00C8); }
void fcmove(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDAC8, 0x00C8); }
void fcmovnb(Fpu reg1) { opFpuFpu(st0, reg1, 0xDBC0, 0x00C0); }
void fcmovnb(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDBC0, 0x00C0); }
void fcmovnbe(Fpu reg1) { opFpuFpu(st0, reg1, 0xDBD0, 0x00D0); }
void fcmovnbe(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDBD0, 0x00D0); }
void fcmovne(Fpu reg1) { opFpuFpu(st0, reg1, 0xDBC8, 0x00C8); }
void fcmovne(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDBC8, 0x00C8); }
void fcmovnu(Fpu reg1) { opFpuFpu(st0, reg1, 0xDBD8, 0x00D8); }
void fcmovnu(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDBD8, 0x00D8); }
void fcmovu(Fpu reg1) { opFpuFpu(st0, reg1, 0xDAD8, 0x00D8); }
void fcmovu(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDAD8, 0x00D8); }
void fcom() { db(0xD8); db(0xD1); }
void fcom(Address addr) { opFpuMem(addr, 0x00, 0xD8, 0xDC, 2, 0); }
void fcom(Fpu reg) { opFpu(reg, 0xD8, 0xD0); }
void fcomi(Fpu reg1) { opFpuFpu(st0, reg1, 0xDBF0, 0x00F0); }
void fcomi(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDBF0, 0x00F0); }
void fcomip(Fpu reg1) { opFpuFpu(st0, reg1, 0xDFF0, 0x00F0); }
void fcomip(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDFF0, 0x00F0); }
void fcomp() { db(0xD8); db(0xD9); }
void fcomp(Address addr) { opFpuMem(addr, 0x00, 0xD8, 0xDC, 3, 0); }
void fcomp(Fpu reg) { opFpu(reg, 0xD8, 0xD8); }
void fcompp() { db(0xDE); db(0xD9); }
void fcos() { db(0xD9); db(0xFF); }
void fdecstp() { db(0xD9); db(0xF6); }
void fdiv(Address addr) { opFpuMem(addr, 0x00, 0xD8, 0xDC, 6, 0); }
void fdiv(Fpu reg1) { opFpuFpu(st0, reg1, 0xD8F0, 0xDCF8); }
void fdiv(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xD8F0, 0xDCF8); }
void fdivp() { db(0xDE); db(0xF9); }
void fdivp(Fpu reg1) { opFpuFpu(reg1, st0, 0x0000, 0xDEF8); }
void fdivp(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0x0000, 0xDEF8); }
void fdivr(Address addr) { opFpuMem(addr, 0x00, 0xD8, 0xDC, 7, 0); }
void fdivr(Fpu reg1) { opFpuFpu(st0, reg1, 0xD8F8, 0xDCF0); }
void fdivr(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xD8F8, 0xDCF0); }
void fdivrp() { db(0xDE); db(0xF1); }
void fdivrp(Fpu reg1) { opFpuFpu(reg1, st0, 0x0000, 0xDEF0); }
void fdivrp(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0x0000, 0xDEF0); }
void ffree(Fpu reg) { opFpu(reg, 0xDD, 0xC0); }
void fiadd(Address addr) { opFpuMem(addr, 0xDE, 0xDA, 0x00, 0, 0); }
void ficom(Address addr) { opFpuMem(addr, 0xDE, 0xDA, 0x00, 2, 0); }
void ficomp(Address addr) { opFpuMem(addr, 0xDE, 0xDA, 0x00, 3, 0); }
void fidiv(Address addr) { opFpuMem(addr, 0xDE, 0xDA, 0x00, 6, 0); }
void fidivr(Address addr) { opFpuMem(addr, 0xDE, 0xDA, 0x00, 7, 0); }
void fild(Address addr) { opFpuMem(addr, 0xDF, 0xDB, 0xDF, 0, 5); }
void fimul(Address addr) { opFpuMem(addr, 0xDE, 0xDA, 0x00, 1, 0); }
void fincstp() { db(0xD9); db(0xF7); }
void finit() { db(0x9B); db(0xDB); db(0xE3); }
void fist(Address addr) { opFpuMem(addr, 0xDF, 0xDB, 0x00, 2, 0); }
void fistp(Address addr) { opFpuMem(addr, 0xDF, 0xDB, 0xDF, 3, 7); }
void fisttp(Address addr) { opFpuMem(addr, 0xDF, 0xDB, 0xDD, 1, 0); }
void fisub(Address addr) { opFpuMem(addr, 0xDE, 0xDA, 0x00, 4, 0); }
void fisubr(Address addr) { opFpuMem(addr, 0xDE, 0xDA, 0x00, 5, 0); }
void fld(Address addr) { opFpuMem(addr, 0x00, 0xD9, 0xDD, 0, 0); }
void fld(Fpu reg) { opFpu(reg, 0xD9, 0xC0); }
void fld1() { db(0xD9); db(0xE8); }
void fldcw(Address addr) { opModM(addr, new Reg32(5), 0xD9, 0x100); }
void fldenv(Address addr) { opModM(addr, new Reg32(4), 0xD9, 0x100); }
void fldl2e() { db(0xD9); db(0xEA); }
void fldl2t() { db(0xD9); db(0xE9); }
void fldlg2() { db(0xD9); db(0xEC); }
void fldln2() { db(0xD9); db(0xED); }
void fldpi() { db(0xD9); db(0xEB); }
void fldz() { db(0xD9); db(0xEE); }
void fmul(Address addr) { opFpuMem(addr, 0x00, 0xD8, 0xDC, 1, 0); }
void fmul(Fpu reg1) { opFpuFpu(st0, reg1, 0xD8C8, 0xDCC8); }
void fmul(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xD8C8, 0xDCC8); }
void fmulp() { db(0xDE); db(0xC9); }
void fmulp(Fpu reg1) { opFpuFpu(reg1, st0, 0x0000, 0xDEC8); }
void fmulp(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0x0000, 0xDEC8); }
void fnclex() { db(0xDB); db(0xE2); }
void fninit() { db(0xDB); db(0xE3); }
void fnop() { db(0xD9); db(0xD0); }
void fnsave(Address addr) { opModM(addr, new Reg32(6), 0xDD, 0x100); }
void fnstcw(Address addr) { opModM(addr, new Reg32(7), 0xD9, 0x100); }
void fnstenv(Address addr) { opModM(addr, new Reg32(6), 0xD9, 0x100); }
void fnstsw(Address addr) { opModM(addr, new Reg32(7), 0xDD, 0x100); }
void fnstsw(Reg16 r) { if (r.getIdx() != Operand.AX) throw new XError(ERR.BAD_PARAMETER); db(0xDF); db(0xE0); }
void fpatan() { db(0xD9); db(0xF3); }
void fprem() { db(0xD9); db(0xF8); }
void fprem1() { db(0xD9); db(0xF5); }
void fptan() { db(0xD9); db(0xF2); }
void frndint() { db(0xD9); db(0xFC); }
void frstor(Address addr) { opModM(addr, new Reg32(4), 0xDD, 0x100); }
void fsave(Address addr) { db(0x9B); opModM(addr, new Reg32(6), 0xDD, 0x100); }
void fscale() { db(0xD9); db(0xFD); }
void fsin() { db(0xD9); db(0xFE); }
void fsincos() { db(0xD9); db(0xFB); }
void fsqrt() { db(0xD9); db(0xFA); }
void fst(Address addr) { opFpuMem(addr, 0x00, 0xD9, 0xDD, 2, 0); }
void fst(Fpu reg) { opFpu(reg, 0xDD, 0xD0); }
void fstcw(Address addr) { db(0x9B); opModM(addr, new Reg32(7), 0xD9, 0x100); }
void fstenv(Address addr) { db(0x9B); opModM(addr, new Reg32(6), 0xD9, 0x100); }
void fstp(Address addr) { opFpuMem(addr, 0x00, 0xD9, 0xDD, 3, 0); }
void fstp(Fpu reg) { opFpu(reg, 0xDD, 0xD8); }
void fstsw(Address addr) { db(0x9B); opModM(addr, new Reg32(7), 0xDD, 0x100); }
void fstsw(Reg16 r) { if (r.getIdx() != Operand.AX) throw new XError(ERR.BAD_PARAMETER); db(0x9B); db(0xDF); db(0xE0); }
void fsub(Address addr) { opFpuMem(addr, 0x00, 0xD8, 0xDC, 4, 0); }
void fsub(Fpu reg1) { opFpuFpu(st0, reg1, 0xD8E0, 0xDCE8); }
void fsub(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xD8E0, 0xDCE8); }
void fsubp() { db(0xDE); db(0xE9); }
void fsubp(Fpu reg1) { opFpuFpu(reg1, st0, 0x0000, 0xDEE8); }
void fsubp(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0x0000, 0xDEE8); }
void fsubr(Address addr) { opFpuMem(addr, 0x00, 0xD8, 0xDC, 5, 0); }
void fsubr(Fpu reg1) { opFpuFpu(st0, reg1, 0xD8E8, 0xDCE0); }
void fsubr(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xD8E8, 0xDCE0); }
void fsubrp() { db(0xDE); db(0xE1); }
void fsubrp(Fpu reg1) { opFpuFpu(reg1, st0, 0x0000, 0xDEE0); }
void fsubrp(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0x0000, 0xDEE0); }
void ftst() { db(0xD9); db(0xE4); }
void fucom() { db(0xDD); db(0xE1); }
void fucom(Fpu reg) { opFpu(reg, 0xDD, 0xE0); }
void fucomi(Fpu reg1) { opFpuFpu(st0, reg1, 0xDBE8, 0x00E8); }
void fucomi(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDBE8, 0x00E8); }
void fucomip(Fpu reg1) { opFpuFpu(st0, reg1, 0xDFE8, 0x00E8); }
void fucomip(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xDFE8, 0x00E8); }
void fucomp() { db(0xDD); db(0xE9); }
void fucomp(Fpu reg) { opFpu(reg, 0xDD, 0xE8); }
void fucompp() { db(0xDA); db(0xE9); }
void fwait() { db(0x9B); }
void fxam() { db(0xD9); db(0xE5); }
void fxch() { db(0xD9); db(0xC9); }
void fxch(Fpu reg) { opFpu(reg, 0xD9, 0xC8); }
void fxrstor(Address addr) { opModM(addr, new Reg32(1), 0x0F, 0xAE); }
void fxtract() { db(0xD9); db(0xF4); }
void fyl2x() { db(0xD9); db(0xF1); }
void fyl2xp1() { db(0xD9); db(0xF9); }

void gf2p8affineinvqb(Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0xCF, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }
void gf2p8affineqb( Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0xCE, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }
void gf2p8mulb(Xmm xmm, Operand op) { opGen(xmm, op, 0xCF, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }

void haddpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x7C, 0x66, &isXMM_XMMorMEM); }
void haddps(Xmm xmm, Operand op) { opGen(xmm, op, 0x7C, 0xF2, &isXMM_XMMorMEM); }
void hsubpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x7D, 0x66, &isXMM_XMMorMEM); }
void hsubps(Xmm xmm, Operand op) { opGen(xmm, op, 0x7D, 0xF2, &isXMM_XMMorMEM); }

void idiv(Operand op) { opR_ModM(op, 0, 7, 0xF6); }
void imul(Operand op) { opR_ModM(op, 0, 5, 0xF6); }
void in_(Reg a, Reg d) { opInOut(a, d, 0xEC); }
void in_(Reg a, uint8 v) { opInOut(a, 0xE4, v); }
void inc(Operand op) { opIncDec(op, 0x40, 0); }
void insertps(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0x21, 0x66, &isXMM_XMMorMEM, imm, 0x3A); }
void int3() { db(0xCC); }
void int_(uint8 x) { db(0xCD); db(x); }

void ja(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x77, 0x87, 0x0F); }
void ja(const char* label, LabelType type = T_AUTO) { ja(to!string(label), type); }
void ja(const void* addr) { opJmpAbs(addr, T_NEAR, 0x77, 0x87, 0x0F); }

void jae(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x73, 0x83, 0x0F); }
void jae(const char* label, LabelType type = T_AUTO) { jae(to!string(label), type); }
void jae(const void* addr) { opJmpAbs(addr, T_NEAR, 0x73, 0x83, 0x0F); }

void jb(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x72, 0x82, 0x0F); }
void jb(const char* label, LabelType type = T_AUTO) { jb(to!string(label), type); }
void jb(const void* addr) { opJmpAbs(addr, T_NEAR, 0x72, 0x82, 0x0F); }

void jbe(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x76, 0x86, 0x0F); }
void jbe(const char* label, LabelType type = T_AUTO) { jbe(to!string(label), type); }
void jbe(const void* addr) { opJmpAbs(addr, T_NEAR, 0x76, 0x86, 0x0F); }

void jc(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x72, 0x82, 0x0F); }
void jc(const char* label, LabelType type = T_AUTO) { jc(to!string(label), type); }
void jc(const void* addr) { opJmpAbs(addr, T_NEAR, 0x72, 0x82, 0x0F); }

void je(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x74, 0x84, 0x0F); }
void je(const char* label, LabelType type = T_AUTO) { je(to!string(label), type); }
void je(const void* addr) { opJmpAbs(addr, T_NEAR, 0x74, 0x84, 0x0F); }

void jg(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7F, 0x8F, 0x0F); }
void jg(const char* label, LabelType type = T_AUTO) { jg(to!string(label), type); }
void jg(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7F, 0x8F, 0x0F); }

void jge(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7D, 0x8D, 0x0F); }
void jge(const char* label, LabelType type = T_AUTO) { jge(to!string(label), type); }
void jge(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7D, 0x8D, 0x0F); }

void jl(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7C, 0x8C, 0x0F); }
void jl(const char* label, LabelType type = T_AUTO) { jl(to!string(label), type); }
void jl(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7C, 0x8C, 0x0F); }

void jle(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7E, 0x8E, 0x0F); }
void jle(const char* label, LabelType type = T_AUTO) { jle(to!string(label), type); }
void jle(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7E, 0x8E, 0x0F); }

void jna(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x76, 0x86, 0x0F); }
void jna(const char* label, LabelType type = T_AUTO) { jna(to!string(label), type); }
void jna(const void* addr) { opJmpAbs(addr, T_NEAR, 0x76, 0x86, 0x0F); }

void jnae(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x72, 0x82, 0x0F); }
void jnae(const char* label, LabelType type = T_AUTO) { jnae(to!string(label), type); }
void jnae(const void* addr) { opJmpAbs(addr, T_NEAR, 0x72, 0x82, 0x0F); }

void jnb(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x73, 0x83, 0x0F); }
void jnb(const char* label, LabelType type = T_AUTO) { jnb(to!string(label), type); }
void jnb(const void* addr) { opJmpAbs(addr, T_NEAR, 0x73, 0x83, 0x0F); }

void jnbe(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x77, 0x87, 0x0F); }
void jnbe(const char* label, LabelType type = T_AUTO) { jnbe(to!string(label), type); }
void jnbe(const void* addr) { opJmpAbs(addr, T_NEAR, 0x77, 0x87, 0x0F); }

void jnc(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x73, 0x83, 0x0F); }
void jnc(const char* label, LabelType type = T_AUTO) { jnc(to!string(label), type); }
void jnc(const void* addr) { opJmpAbs(addr, T_NEAR, 0x73, 0x83, 0x0F); }

void jne(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x75, 0x85, 0x0F); }
void jne(const char* label, LabelType type = T_AUTO) { jne(to!string(label), type); }
void jne(const void* addr) { opJmpAbs(addr, T_NEAR, 0x75, 0x85, 0x0F); }

void jng(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7E, 0x8E, 0x0F); }
void jng(const char* label, LabelType type = T_AUTO) { jng(to!string(label), type); }
void jng(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7E, 0x8E, 0x0F); }

void jnge(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7C, 0x8C, 0x0F); }
void jnge(const char* label, LabelType type = T_AUTO) { jnge(to!string(label), type); }
void jnge(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7C, 0x8C, 0x0F); }

void jnl(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7D, 0x8D, 0x0F); }
void jnl(const char* label, LabelType type = T_AUTO) { jnl(to!string(label), type); }
void jnl(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7D, 0x8D, 0x0F); }

void jnle(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7F, 0x8F, 0x0F); }
void jnle(const char* label, LabelType type = T_AUTO) { jnle(to!string(label), type); }
void jnle(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7F, 0x8F, 0x0F); }

void jno(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x71, 0x81, 0x0F); }
void jno(const char* label, LabelType type = T_AUTO) { jno(to!string(label), type); }
void jno(const void* addr) { opJmpAbs(addr, T_NEAR, 0x71, 0x81, 0x0F); }

void jnp(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7B, 0x8B, 0x0F); }
void jnp(const char* label, LabelType type = T_AUTO) { jnp(to!string(label), type); }
void jnp(void* addr) { opJmpAbs(addr, T_NEAR, 0x7B, 0x8B, 0x0F); }

void jns(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x79, 0x89, 0x0F); }
void jns(const char* label, LabelType type = T_AUTO) { jns(to!string(label), type); }
void jns(const void* addr) { opJmpAbs(addr, T_NEAR, 0x79, 0x89, 0x0F); }

void jnz(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x75, 0x85, 0x0F); }
void jnz(const char* label, LabelType type = T_AUTO) { jnz(to!string(label), type); }
void jnz(const void* addr) { opJmpAbs(addr, T_NEAR, 0x75, 0x85, 0x0F); }

void jo(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x70, 0x80, 0x0F); }
void jo(const char* label, LabelType type = T_AUTO) { jo(to!string(label), type); }
void jo(const void* addr) { opJmpAbs(addr, T_NEAR, 0x70, 0x80, 0x0F); }

void jp(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7A, 0x8A, 0x0F); }
void jp(const char* label, LabelType type = T_AUTO) { jp(to!string(label), type); }
void jp(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7A, 0x8A, 0x0F); }

void jpe(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7A, 0x8A, 0x0F); }
void jpe(const char* label, LabelType type = T_AUTO) { jpe(to!string(label), type); }
void jpe(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7A, 0x8A, 0x0F); }

void jpo(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x7B, 0x8B, 0x0F); }
void jpo(const char* label, LabelType type = T_AUTO) { jpo(to!string(label), type); }
void jpo(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7B, 0x8B, 0x0F); }

void js(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x78, 0x88, 0x0F); }
void js(const char* label, LabelType type = T_AUTO) { js(to!string(label), type); }
void js(const void* addr) { opJmpAbs(addr, T_NEAR, 0x78, 0x88, 0x0F); }

void jz(T)(T label, LabelType type = T_AUTO) { opJmp(label, type, 0x74, 0x84, 0x0F); }
void jz(const char* label, LabelType type = T_AUTO) { jz(to!string(label), type); }
void jz(const void* addr) { opJmpAbs(addr, T_NEAR, 0x74, 0x84, 0x0F); }

void lahf() { db(0x9F); }
void lddqu(Xmm xmm, Address addr) { db(0xF2); opModM(addr, xmm, 0x0F, 0xF0); }
void ldmxcsr(Address addr) { opModM(addr, new Reg32(2), 0x0F, 0xAE); }
void lea(Reg reg, Address addr) { if (!reg.isBit(16 | i32e)) throw new XError(ERR.BAD_SIZE_OF_REGISTER); opModM(addr, reg, 0x8D); }
void leave() { db(0xC9); }
void lfence() { db(0x0F); db(0xAE); db(0xE8); }
void lfs(Reg reg, Address addr) { opLoadSeg(addr, reg, 0x0F, 0xB4); }
void lgs(Reg reg, Address addr) { opLoadSeg(addr, reg, 0x0F, 0xB5); }
void lock() { db(0xF0); }
void lodsb() { db(0xAC); }
void lodsd() { db(0xAD); }
void lodsw() { db(0x66); db(0xAD); }
void lss(Reg reg, Address addr) { opLoadSeg(addr, reg, 0x0F, 0xB2); }
void loop(Label label) { opJmp(label, T_SHORT, 0xE2, 0, 0); }
void loop(const char* label) { loop(to!string(label)); }
void loop(string label) { opJmp(label, T_SHORT, 0xE2, 0, 0); }
void loope(Label label) { opJmp(label, T_SHORT, 0xE1, 0, 0); }
void loope(const char* label) { loope(to!string(label)); }
void loope(string label) { opJmp(label, T_SHORT, 0xE1, 0, 0); }
void loopne(Label label) { opJmp(label, T_SHORT, 0xE0, 0, 0); }
void loopne(const char* label) { loopne(to!string(label)); }
void loopne(string label) { opJmp(label, T_SHORT, 0xE0, 0, 0); }
void lzcnt(Reg reg, Operand op) { opSp1(reg, op, 0xF3, 0x0F, 0xBD); }

void maskmovdqu(Xmm reg1, Xmm reg2) { db(0x66);  opModR(reg1, reg2, 0x0F, 0xF7); }
void maskmovq(Mmx reg1, Mmx reg2) { if (!reg1.isMMX() || !reg2.isMMX()) throw new XError(ERR.BAD_COMBINATION); opModR(reg1, reg2, 0x0F, 0xF7); }
void maxpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x5F, 0x66, &isXMM_XMMorMEM); }
void maxps(Xmm xmm, Operand op) { opGen(xmm, op, 0x5F, 0x100, &isXMM_XMMorMEM); }
void maxsd(Xmm xmm, Operand op) { opGen(xmm, op, 0x5F, 0xF2, &isXMM_XMMorMEM); }
void maxss(Xmm xmm, Operand op) { opGen(xmm, op, 0x5F, 0xF3, &isXMM_XMMorMEM); }
void mfence() { db(0x0F); db(0xAE); db(0xF0); }
void minpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x5D, 0x66, &isXMM_XMMorMEM); }
void minps(Xmm xmm, Operand op) { opGen(xmm, op, 0x5D, 0x100, &isXMM_XMMorMEM); }
void minsd(Xmm xmm, Operand op) { opGen(xmm, op, 0x5D, 0xF2, &isXMM_XMMorMEM); }
void minss(Xmm xmm, Operand op) { opGen(xmm, op, 0x5D, 0xF3, &isXMM_XMMorMEM); }
void monitor() { db(0x0F); db(0x01); db(0xC8); }
void monitorx() { db(0x0F); db(0x01); db(0xFA); }
void movapd(Address addr, Xmm xmm) { db(0x66); opModM(addr, xmm, 0x0F, 0x29); }
void movapd(Xmm xmm, Operand op) { opMMX(xmm, op, 0x28, 0x66); }
void movaps(Address addr, Xmm xmm) { opModM(addr, xmm, 0x0F, 0x29); }
void movaps(Xmm xmm, Operand op) { opMMX(xmm, op, 0x28, 0x100); }
void movbe(Address addr, Reg reg) { opModM(addr, reg, 0x0F, 0x38, 0xF1); }
void movbe(Reg reg, Address addr) { opModM(addr, reg, 0x0F, 0x38, 0xF0); }
void movd(Address addr, Mmx mmx) { if (mmx.isXMM()) db(0x66); opModM(addr, mmx, 0x0F, 0x7E); }
void movd(Mmx mmx, Address addr) { if (mmx.isXMM()) db(0x66); opModM(addr, mmx, 0x0F, 0x6E); }
void movd(Mmx mmx, Reg32 reg) { if (mmx.isXMM()) db(0x66); opModR(mmx, reg, 0x0F, 0x6E); }
void movd(Reg32 reg, Mmx mmx) { if (mmx.isXMM()) db(0x66); opModR(mmx, reg, 0x0F, 0x7E); }
void movddup(Xmm xmm, Operand op) { opGen(xmm, op, 0x12, 0xF2, &isXMM_XMMorMEM, NONE, NONE); }
void movdq2q(Mmx mmx, Xmm xmm) { db(0xF2); opModR(mmx, xmm, 0x0F, 0xD6); }
void movdqa(Address addr, Xmm xmm) { db(0x66); opModM(addr, xmm, 0x0F, 0x7F); }
void movdqa(Xmm xmm, Operand op) { opMMX(xmm, op, 0x6F, 0x66); }
void movdqu(Address addr, Xmm xmm) { db(0xF3); opModM(addr, xmm, 0x0F, 0x7F); }
void movdqu(Xmm xmm, Operand op) { opMMX(xmm, op, 0x6F, 0xF3); }
void movhlps(Xmm reg1, Xmm reg2) {  opModR(reg1, reg2, 0x0F, 0x12); }
void movhpd(Operand op1, Operand op2) { opMovXMM(op1, op2, 0x16, 0x66); }
void movhps(Operand op1, Operand op2) { opMovXMM(op1, op2, 0x16, 0x100); }
void movlhps(Xmm reg1, Xmm reg2) {  opModR(reg1, reg2, 0x0F, 0x16); }
void movlpd(Operand op1, Operand op2) { opMovXMM(op1, op2, 0x12, 0x66); }
void movlps(Operand op1, Operand op2) { opMovXMM(op1, op2, 0x12, 0x100); }
void movmskpd(Reg32e reg, Xmm xmm) { db(0x66); movmskps(reg, xmm); }
void movmskps(Reg32e reg, Xmm xmm) { opModR(reg, xmm, 0x0F, 0x50); }
void movntdq(Address addr, Xmm reg) { opModM(addr, new Reg16(reg.getIdx()), 0x0F, 0xE7); }
void movntdqa(Xmm xmm, Address addr) { db(0x66); opModM(addr, xmm, 0x0F, 0x38, 0x2A); }
void movnti(Address addr, Reg32e reg) { opModM(addr, reg, 0x0F, 0xC3); }
void movntpd(Address addr, Xmm reg) { opModM(addr, new Reg16(reg.getIdx()), 0x0F, 0x2B); }
void movntps(Address addr, Xmm xmm) { opModM(addr, new Mmx(xmm.getIdx()), 0x0F, 0x2B); }
void movntq(Address addr, Mmx mmx) { if (!mmx.isMMX()) throw new XError(ERR.BAD_COMBINATION); opModM(addr, mmx, 0x0F, 0xE7); }
void movq(Address addr, Mmx mmx) { if (mmx.isXMM()) db(0x66); opModM(addr, mmx, 0x0F, mmx.isXMM() ? 0xD6 : 0x7F); }
void movq(Mmx mmx, Operand op) { if (mmx.isXMM()) db(0xF3); opModRM(mmx, op, (mmx.getKind() == op.getKind()), op.isMEM(), 0x0F, mmx.isXMM() ? 0x7E : 0x6F); }
void movq2dq(Xmm xmm, Mmx mmx) { db(0xF3); opModR(xmm, mmx, 0x0F, 0xD6); }
void movsb() { db(0xA4); }
void movsd() { db(0xA5); }
void movsd(Address addr, Xmm xmm) { db(0xF2); opModM(addr, xmm, 0x0F, 0x11); }
void movsd(Xmm xmm, Operand op) { opMMX(xmm, op, 0x10, 0xF2); }
void movshdup(Xmm xmm, Operand op) { opGen(xmm, op, 0x16, 0xF3, &isXMM_XMMorMEM, NONE, NONE); }
void movsldup(Xmm xmm, Operand op) { opGen(xmm, op, 0x12, 0xF3, &isXMM_XMMorMEM, NONE, NONE); }
void movss(Address addr, Xmm xmm) { db(0xF3); opModM(addr, xmm, 0x0F, 0x11); }
void movss(Xmm xmm, Operand op) { opMMX(xmm, op, 0x10, 0xF3); }
void movsw() { db(0x66); db(0xA5); }
void movsx(Reg reg, Operand op) { opMovxx(reg, op, 0xBE); }
void movupd(Address addr, Xmm xmm) { db(0x66); opModM(addr, xmm, 0x0F, 0x11); }
void movupd(Xmm xmm, Operand op) { opMMX(xmm, op, 0x10, 0x66); }
void movups(Address addr, Xmm xmm) { opModM(addr, xmm, 0x0F, 0x11); }
void movups(Xmm xmm, Operand op) { opMMX(xmm, op, 0x10, 0x100); }
void movzx(Reg reg, Operand op) { opMovxx(reg, op, 0xB6); }
void mpsadbw(Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0x42, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }
void mul(Operand op) { opR_ModM(op, 0, 4, 0xF6); }
void mulpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x59, 0x66, &isXMM_XMMorMEM); }
void mulps(Xmm xmm, Operand op) { opGen(xmm, op, 0x59, 0x100, &isXMM_XMMorMEM); }
void mulsd(Xmm xmm, Operand op) { opGen(xmm, op, 0x59, 0xF2, &isXMM_XMMorMEM); }
void mulss(Xmm xmm, Operand op) { opGen(xmm, op, 0x59, 0xF3, &isXMM_XMMorMEM); }
void mulx(Reg32e r1, Reg32e r2, Operand op) { opGpr(r1, r2, op, T_F2 | T_0F38, 0xf6, true); }
void mwait() { db(0x0F); db(0x01); db(0xC9); }
void mwaitx() { db(0x0F); db(0x01); db(0xFB); }

void neg(Operand op) { opR_ModM(op, 0, 3, 0xF6); }
void not(Operand op) { opR_ModM(op, 0, 2, 0xF6); }

void or(Operand op, uint32 imm) { opRM_I(op, imm, 0x08, 1); }
void or(Operand op1, Operand op2) { opRM_RM(op1, op2, 0x08); }
void orpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x56, 0x66, &isXMM_XMMorMEM); }
void orps(Xmm xmm, Operand op) { opGen(xmm, op, 0x56, 0x100, &isXMM_XMMorMEM); }
void out_(Reg d, Reg a) { opInOut(a, d, 0xEE); }
void out_(uint8 v, Reg a) { opInOut(a, 0xE6, v); }
void outsb() { db(0x6E); }
void outsd() { db(0x6F); }
void outsw() { db(0x66); db(0x6F); }

void pabsb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x1C, 0x66, NONE, 0x38); }
void pabsd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x1E, 0x66, NONE, 0x38); }
void pabsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x1D, 0x66, NONE, 0x38); }
void packssdw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x6B); }
void packsswb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x63); }
void packusdw(Xmm xmm, Operand op) { opGen(xmm, op, 0x2B, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void packuswb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x67); }
void paddb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xFC); }
void paddd(Mmx mmx, Operand op) { opMMX(mmx, op, 0xFE); }
void paddq(Mmx mmx, Operand op) { opMMX(mmx, op, 0xD4); }
void paddsb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xEC); }
void paddsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xED); }
void paddusb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDC); }
void paddusw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDD); }
void paddw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xFD); }
void palignr(Mmx mmx, Operand op, int imm) { opMMX(mmx, op, 0x0f, 0x66, cast(uint8)(imm), 0x3a); }
void pand(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDB); }
void pandn(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDF); }
void pause() { db(0xF3); db(0x90); }
void pavgb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE0); }
void pavgw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE3); }
void pblendvb(Xmm xmm, Operand op) { opGen(xmm, op, 0x10, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pblendw(Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0x0E, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }
void pclmulhqhdq(Xmm xmm, Operand op) { pclmulqdq(xmm, op, 0x11); }
void pclmulhqlqdq(Xmm xmm, Operand op) { pclmulqdq(xmm, op, 0x01); }
void pclmullqhdq(Xmm xmm, Operand op) { pclmulqdq(xmm, op, 0x10); }
void pclmullqlqdq(Xmm xmm, Operand op) { pclmulqdq(xmm, op, 0x00); }
void pclmulqdq(Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0x44, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }
void pcmpeqb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x74); }
void pcmpeqd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x76); }
void pcmpeqq(Xmm xmm, Operand op) { opGen(xmm, op, 0x29, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pcmpeqw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x75); }
void pcmpestri(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0x61, 0x66, &isXMM_XMMorMEM, imm, 0x3A); }
void pcmpestrm(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0x60, 0x66, &isXMM_XMMorMEM, imm, 0x3A); }
void pcmpgtb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x64); }
void pcmpgtd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x66); }
void pcmpgtq(Xmm xmm, Operand op) { opGen(xmm, op, 0x37, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pcmpgtw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x65); }
void pcmpistri(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0x63, 0x66, &isXMM_XMMorMEM, imm, 0x3A); }
void pcmpistrm(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0x62, 0x66, &isXMM_XMMorMEM, imm, 0x3A); }
void pdep(Reg32e r1, Reg32e r2, Operand op) { opGpr(r1, r2, op, T_F2 | T_0F38, 0xf5, true); }
void pext(Reg32e r1, Reg32e r2, Operand op) { opGpr(r1, r2, op, T_F3 | T_0F38, 0xf5, true); }
void pextrb(Operand op, Xmm xmm, uint8 imm) { opExt(op, xmm, 0x14, imm); }
void pextrd(Operand op, Xmm xmm, uint8 imm) { opExt(op, xmm, 0x16, imm); }
void pextrw(Operand op, Mmx xmm, uint8 imm) { opExt(op, xmm, 0x15, imm, true); }
void phaddd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x02, 0x66, NONE, 0x38); }
void phaddsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x03, 0x66, NONE, 0x38); }
void phaddw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x01, 0x66, NONE, 0x38); }
void phminposuw(Xmm xmm, Operand op) { opGen(xmm, op, 0x41, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void phsubd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x06, 0x66, NONE, 0x38); }
void phsubsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x07, 0x66, NONE, 0x38); }
void phsubw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x05, 0x66, NONE, 0x38); }
void pinsrb(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0x20, 0x66, &isXMM_REG32orMEM, imm, 0x3A); }
void pinsrd(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0x22, 0x66, &isXMM_REG32orMEM, imm, 0x3A); }
void pinsrw(Mmx mmx, Operand op, int imm) { if (!op.isREG(32) && !op.isMEM()) throw new XError(ERR.BAD_COMBINATION); opGen(mmx, op, 0xC4, mmx.isXMM() ? 0x66 : NONE, null, imm); }
void pmaddubsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x04, 0x66, NONE, 0x38); }
void pmaddwd(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF5); }
void pmaxsb(Xmm xmm, Operand op) { opGen(xmm, op, 0x3C, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmaxsd(Xmm xmm, Operand op) { opGen(xmm, op, 0x3D, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmaxsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xEE); }
void pmaxub(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDE); }
void pmaxud(Xmm xmm, Operand op) { opGen(xmm, op, 0x3F, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmaxuw(Xmm xmm, Operand op) { opGen(xmm, op, 0x3E, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pminsb(Xmm xmm, Operand op) { opGen(xmm, op, 0x38, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pminsd(Xmm xmm, Operand op) { opGen(xmm, op, 0x39, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pminsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xEA); }
void pminub(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDA); }
void pminud(Xmm xmm, Operand op) { opGen(xmm, op, 0x3B, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pminuw(Xmm xmm, Operand op) { opGen(xmm, op, 0x3A, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovmskb(Reg32e reg, Mmx mmx) { if (mmx.isXMM()) db(0x66); opModR(reg, mmx, 0x0F, 0xD7); }
void pmovsxbd(Xmm xmm, Operand op) { opGen(xmm, op, 0x21, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovsxbq(Xmm xmm, Operand op) { opGen(xmm, op, 0x22, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovsxbw(Xmm xmm, Operand op) { opGen(xmm, op, 0x20, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovsxdq(Xmm xmm, Operand op) { opGen(xmm, op, 0x25, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovsxwd(Xmm xmm, Operand op) { opGen(xmm, op, 0x23, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovsxwq(Xmm xmm, Operand op) { opGen(xmm, op, 0x24, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovzxbd(Xmm xmm, Operand op) { opGen(xmm, op, 0x31, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovzxbq(Xmm xmm, Operand op) { opGen(xmm, op, 0x32, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovzxbw(Xmm xmm, Operand op) { opGen(xmm, op, 0x30, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovzxdq(Xmm xmm, Operand op) { opGen(xmm, op, 0x35, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovzxwd(Xmm xmm, Operand op) { opGen(xmm, op, 0x33, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmovzxwq(Xmm xmm, Operand op) { opGen(xmm, op, 0x34, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmuldq(Xmm xmm, Operand op) { opGen(xmm, op, 0x28, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmulhrsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x0B, 0x66, NONE, 0x38); }
void pmulhuw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE4); }
void pmulhw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE5); }
void pmulld(Xmm xmm, Operand op) { opGen(xmm, op, 0x40, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void pmullw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xD5); }
void pmuludq(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF4); }
void popcnt(Reg reg, Operand op) { opSp1(reg, op, 0xF3, 0x0F, 0xB8); }
void popf() { db(0x9D); }
void por(Mmx mmx, Operand op) { opMMX(mmx, op, 0xEB); }
void prefetchnta(Address addr) { opModM(addr, new Reg32(0), 0x0F, 0x18); }
void prefetcht0(Address addr) { opModM(addr, new Reg32(1), 0x0F, 0x18); }
void prefetcht1(Address addr) { opModM(addr, new Reg32(2), 0x0F, 0x18); }
void prefetcht2(Address addr) { opModM(addr, new Reg32(3), 0x0F, 0x18); }
void prefetchw(Address addr) { opModM(addr, new Reg32(1), 0x0F, 0x0D); }
void prefetchwt1(Address addr) { opModM(addr, new Reg32(2), 0x0F, 0x0D); }
void psadbw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF6); }
void pshufb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x00, 0x66, NONE, 0x38); }
void pshufd(Mmx mmx, Operand op, uint8 imm8) { opMMX(mmx, op, 0x70, 0x66, imm8); }
void pshufhw(Mmx mmx, Operand op, uint8 imm8) { opMMX(mmx, op, 0x70, 0xF3, imm8); }
void pshuflw(Mmx mmx, Operand op, uint8 imm8) { opMMX(mmx, op, 0x70, 0xF2, imm8); }
void pshufw(Mmx mmx, Operand op, uint8 imm8) { opMMX(mmx, op, 0x70, 0x00, imm8); }
void psignb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x08, 0x66, NONE, 0x38); }
void psignd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x0A, 0x66, NONE, 0x38); }
void psignw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x09, 0x66, NONE, 0x38); }
void pslld(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF2); }
void pslld(Mmx mmx, int imm8) { opMMX_IMM(mmx, imm8, 0x72, 6); }
void pslldq(Xmm xmm, int imm8) { opMMX_IMM(xmm, imm8, 0x73, 7); }
void psllq(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF3); }
void psllq(Mmx mmx, int imm8) { opMMX_IMM(mmx, imm8, 0x73, 6); }
void psllw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF1); }
void psllw(Mmx mmx, int imm8) { opMMX_IMM(mmx, imm8, 0x71, 6); }
void psrad(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE2); }
void psrad(Mmx mmx, int imm8) { opMMX_IMM(mmx, imm8, 0x72, 4); }
void psraw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE1); }
void psraw(Mmx mmx, int imm8) { opMMX_IMM(mmx, imm8, 0x71, 4); }
void psrld(Mmx mmx, Operand op) { opMMX(mmx, op, 0xD2); }
void psrld(Mmx mmx, int imm8) { opMMX_IMM(mmx, imm8, 0x72, 2); }
void psrldq(Xmm xmm, int imm8) { opMMX_IMM(xmm, imm8, 0x73, 3); }
void psrlq(Mmx mmx, Operand op) { opMMX(mmx, op, 0xD3); }
void psrlq(Mmx mmx, int imm8) { opMMX_IMM(mmx, imm8, 0x73, 2); }
void psrlw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xD1); }
void psrlw(Mmx mmx, int imm8) { opMMX_IMM(mmx, imm8, 0x71, 2); }
void psubb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF8); }
void psubd(Mmx mmx, Operand op) { opMMX(mmx, op, 0xFA); }
void psubq(Mmx mmx, Operand op) { opMMX(mmx, op, 0xFB); }
void psubsb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE8); }
void psubsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE9); }
void psubusb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xD8); }
void psubusw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xD9); }
void psubw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF9); }
void ptest(Xmm xmm, Operand op) { opGen(xmm, op, 0x17, 0x66, &isXMM_XMMorMEM, NONE, 0x38); }
void punpckhbw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x68); }
void punpckhdq(Mmx mmx, Operand op) { opMMX(mmx, op, 0x6A); }
void punpckhqdq(Xmm xmm, Operand op) { opGen(xmm, op, 0x6D, 0x66, &isXMM_XMMorMEM); }
void punpckhwd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x69); }
void punpcklbw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x60); }
void punpckldq(Mmx mmx, Operand op) { opMMX(mmx, op, 0x62); }
void punpcklqdq(Xmm xmm, Operand op) { opGen(xmm, op, 0x6C, 0x66, &isXMM_XMMorMEM); }
void punpcklwd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x61); }
void pushf() { db(0x9C); }
void pxor(Mmx mmx, Operand op) { opMMX(mmx, op, 0xEF); }

void rcl(Operand op, Reg8 _cl) { opShift(op, _cl, 2); }
void rcl(Operand op, int imm) { opShift(op, imm, 2); }
void rcpps(Xmm xmm, Operand op) { opGen(xmm, op, 0x53, 0x100, &isXMM_XMMorMEM); }
void rcpss(Xmm xmm, Operand op) { opGen(xmm, op, 0x53, 0xF3, &isXMM_XMMorMEM); }
void rcr(Operand op, Reg8 _cl) { opShift(op, _cl, 3); }
void rcr(Operand op, int imm) { opShift(op, imm, 3); }
void rdmsr() { db(0x0F); db(0x32); }
void rdpmc() { db(0x0F); db(0x33); }
void rdrand(Reg r) { if (r.isBit(8)) throw new XError(ERR.BAD_SIZE_OF_REGISTER); opModR(new Reg(6, Kind.REG, r.getBit()), r, 0x0F, 0xC7); }
void rdseed(Reg r) { if (r.isBit(8)) throw new XError(ERR.BAD_SIZE_OF_REGISTER); opModR(new Reg(7, Kind.REG, r.getBit()), r, 0x0F, 0xC7); }
void rdtsc() { db(0x0F); db(0x31); }
void rdtscp() { db(0x0F); db(0x01); db(0xF9); }
void rep() { db(0xF3); }
void repe() { db(0xF3); }
void repne() { db(0xF2); }
void repnz() { db(0xF2); }
void repz() { db(0xF3); }
void ret(int imm = 0) { if (imm) { db(0xC2); dw(imm); } else { db(0xC3); } }
void rol(Operand op, Reg8 _cl) { opShift(op, _cl, 0); }
void rol(Operand op, int imm) { opShift(op, imm, 0); }
void ror(Operand op, Reg8 _cl) { opShift(op, _cl, 1); }
void ror(Operand op, int imm) { opShift(op, imm, 1); }
void rorx(Reg32e r, Operand op, uint8 imm) { opGpr(r, op, new Reg32e(0, r.getBit()), T_0F3A | T_F2, 0xF0, false, imm); }
void roundpd(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0x09, 0x66, &isXMM_XMMorMEM, imm, 0x3A); }
void roundps(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0x08, 0x66, &isXMM_XMMorMEM, imm, 0x3A); }
void roundsd(Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0x0B, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }
void roundss(Xmm xmm, Operand op, int imm) { opGen(xmm, op, 0x0A, 0x66, &isXMM_XMMorMEM, cast(uint8)(imm), 0x3A); }
void rsqrtps(Xmm xmm, Operand op) { opGen(xmm, op, 0x52, 0x100, &isXMM_XMMorMEM); }
void rsqrtss(Xmm xmm, Operand op) { opGen(xmm, op, 0x52, 0xF3, &isXMM_XMMorMEM); }

void sahf() { db(0x9E); }
void sal(Operand op, Reg8 _cl) { opShift(op, _cl, 4); }
void sal(Operand op, int imm) { opShift(op, imm, 4); }
void sar(Operand op, Reg8 _cl) { opShift(op, _cl, 7); }
void sar(Operand op, int imm) { opShift(op, imm, 7); }
void sarx(Reg32e r1, Operand op, Reg32e r2) { opGpr(r1, op, r2, T_F3 | T_0F38, 0xf7, false); }
void sbb(Operand op, uint32 imm) { opRM_I(op, imm, 0x18, 3); }
void sbb(Operand op1, Operand op2) { opRM_RM(op1, op2, 0x18); }
void scasb() { db(0xAE); }
void scasd() { db(0xAF); }
void scasw() { db(0x66); db(0xAF); }
void seta(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 7); }
void setae(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 3); }
void setb(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 2); }
void setbe(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 6); }
void setc(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 2); }
void sete(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 4); }
void setg(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 15); }
void setge(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 13); }
void setl(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 12); }
void setle(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 14); }
void setna(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 6); }
void setnae(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 2); }
void setnb(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 3); }
void setnbe(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 7); }
void setnc(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 3); }
void setne(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 5); }
void setng(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 14); }
void setnge(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 12); }
void setnl(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 13); }
void setnle(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 15); }
void setno(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 1); }
void setnp(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 11); }
void setns(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 9); }
void setnz(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 5); }
void seto(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 0); }
void setp(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 10); }
void setpe(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 10); }
void setpo(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 11); }
void sets(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 8); }
void setz(Operand op) { opR_ModM(op, 8, 0, 0x0F, 0x90 | 4); }
void sfence() { db(0x0F); db(0xAE); db(0xF8); }
void sha1msg1(Xmm xmm, Operand op) { opGen(xmm, op, 0xC9, NONE, &isXMM_XMMorMEM, NONE, 0x38); }
void sha1msg2(Xmm xmm, Operand op) { opGen(xmm, op, 0xCA, NONE, &isXMM_XMMorMEM, NONE, 0x38); }
void sha1nexte(Xmm xmm, Operand op) { opGen(xmm, op, 0xC8, NONE, &isXMM_XMMorMEM, NONE, 0x38); }
void sha1rnds4(Xmm xmm, Operand op, uint8 imm) { opGen(xmm, op, 0xCC, NONE, &isXMM_XMMorMEM, imm, 0x3A); }
void sha256msg1(Xmm xmm, Operand op) { opGen(xmm, op, 0xCC, NONE, &isXMM_XMMorMEM, NONE, 0x38); }
void sha256msg2(Xmm xmm, Operand op) { opGen(xmm, op, 0xCD, NONE, &isXMM_XMMorMEM, NONE, 0x38); }
void sha256rnds2(Xmm xmm, Operand op) { opGen(xmm, op, 0xCB, NONE, &isXMM_XMMorMEM, NONE, 0x38); }
void shl(Operand op, Reg8 _cl) { opShift(op, _cl, 4); }
void shl(Operand op, int imm) { opShift(op, imm, 4); }
void shld(Operand op, Reg reg, Reg8 _cl) { opShxd(op, reg, 0, 0xA4, _cl); }
void shld(Operand op, Reg reg, uint8 imm) { opShxd(op, reg, imm, 0xA4); }
void shlx(Reg32e r1, Operand op, Reg32e r2) { opGpr(r1, op, r2, T_66 | T_0F38, 0xf7, false); }
void shr(Operand op, Reg8 _cl) { opShift(op, _cl, 5); }
void shr(Operand op, int imm) { opShift(op, imm, 5); }
void shrd(Operand op, Reg reg, Reg8 _cl) { opShxd(op, reg, 0, 0xAC, _cl); }
void shrd(Operand op, Reg reg, uint8 imm) { opShxd(op, reg, imm, 0xAC); }
void shrx(Reg32e r1, Operand op, Reg32e r2) { opGpr(r1, op, r2, T_F2 | T_0F38, 0xf7, false); }
void shufpd(Xmm xmm, Operand op, uint8 imm8) { opGen(xmm, op, 0xC6, 0x66, &isXMM_XMMorMEM, imm8); }
void shufps(Xmm xmm, Operand op, uint8 imm8) { opGen(xmm, op, 0xC6, 0x100, &isXMM_XMMorMEM, imm8); }
void sqrtpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x51, 0x66, &isXMM_XMMorMEM); }
void sqrtps(Xmm xmm, Operand op) { opGen(xmm, op, 0x51, 0x100, &isXMM_XMMorMEM); }
void sqrtsd(Xmm xmm, Operand op) { opGen(xmm, op, 0x51, 0xF2, &isXMM_XMMorMEM); }
void sqrtss(Xmm xmm, Operand op) { opGen(xmm, op, 0x51, 0xF3, &isXMM_XMMorMEM); }
void stac() { db(0x0F); db(0x01); db(0xCB); }
void stc() { db(0xF9); }
void std() { db(0xFD); }
void sti() { db(0xFB); }
void stmxcsr(Address addr) { opModM(addr, new Reg32(3), 0x0F, 0xAE); }
void stosb() { db(0xAA); }
void stosd() { db(0xAB); }
void stosw() { db(0x66); db(0xAB); }
void sub(Operand op, uint32 imm) { opRM_I(op, imm, 0x28, 5); }
void sub(Operand op1, Operand op2) { opRM_RM(op1, op2, 0x28); }
void subpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x5C, 0x66, &isXMM_XMMorMEM); }
void subps(Xmm xmm, Operand op) { opGen(xmm, op, 0x5C, 0x100, &isXMM_XMMorMEM); }
void subsd(Xmm xmm, Operand op) { opGen(xmm, op, 0x5C, 0xF2, &isXMM_XMMorMEM); }
void subss(Xmm xmm, Operand op) { opGen(xmm, op, 0x5C, 0xF3, &isXMM_XMMorMEM); }
void sysenter() { db(0x0F); db(0x34); }
void sysexit() { db(0x0F); db(0x35); }

void tzcnt(Reg reg, Operand op) { opSp1(reg, op, 0xF3, 0x0F, 0xBC); }

void ucomisd(Xmm xmm, Operand op) { opGen(xmm, op, 0x2E, 0x66, &isXMM_XMMorMEM); }
void ucomiss(Xmm xmm, Operand op) { opGen(xmm, op, 0x2E, 0x100, &isXMM_XMMorMEM); }
void ud2() { db(0x0F); db(0x0B); }
void unpckhpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x15, 0x66, &isXMM_XMMorMEM); }
void unpckhps(Xmm xmm, Operand op) { opGen(xmm, op, 0x15, 0x100, &isXMM_XMMorMEM); }
void unpcklpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x14, 0x66, &isXMM_XMMorMEM); }
void unpcklps(Xmm xmm, Operand op) { opGen(xmm, op, 0x14, 0x100, &isXMM_XMMorMEM); }

void vaddpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x58); }
void vaddps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x58); }
void vaddsd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_ER_Z | T_N8, 0x58); }
void vaddss(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_ER_Z | T_N4, 0x58); }
void vaddsubpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66 | T_0F | T_YMM, 0xD0); }
void vaddsubps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_F2 | T_0F | T_YMM, 0xD0); }
void vaesdec(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66 | T_0F38 | T_YMM | T_EVEX, 0xDE); }
void vaesdeclast(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66 | T_0F38 | T_YMM | T_EVEX, 0xDF); }
void vaesenc(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66 | T_0F38 | T_YMM | T_EVEX, 0xDC); }
void vaesenclast(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66 | T_0F38 | T_YMM | T_EVEX, 0xDD); }
void vaesimc(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F38 | T_W0, 0xDB); }
void vaeskeygenassist(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F3A, 0xDF, imm); }
void vandnpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x55); }
void vandnps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x55); }
void vandpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x54); }
void vandps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x54); }
void vblendpd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W0 | T_YMM, 0x0D, imm); }
void vblendps(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W0 | T_YMM, 0x0C, imm); }
void vblendvpd(Xmm x1, Xmm x2, Operand op, Xmm x4) { opAVX_X_X_XM(x1, x2, op, T_0F3A | T_66 | T_YMM, 0x4B, x4.getIdx() << 4); }
void vblendvps(Xmm x1, Xmm x2, Operand op, Xmm x4) { opAVX_X_X_XM(x1, x2, op, T_0F3A | T_66 | T_YMM, 0x4A, x4.getIdx() << 4); }
void vbroadcastf128(Ymm y, Address addr) { opAVX_X_XM_IMM(y, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x1A); }
void vbroadcasti128(Ymm y, Address addr) { opAVX_X_XM_IMM(y, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x5A); }
void vbroadcastsd(Ymm y, Operand op) { if (!op.isMEM() && !(y.isYMM() && op.isXMM()) && !(y.isZMM() && op.isXMM())) throw new XError(ERR.BAD_COMBINATION); opAVX_X_XM_IMM(y, op, T_0F38 | T_66 | T_W0 | T_YMM | T_EVEX | T_EW1 | T_N8, 0x19); }
void vbroadcastss(Xmm x, Operand op) { if (!(op.isXMM() || op.isMEM())) throw new XError(ERR.BAD_COMBINATION); opAVX_X_XM_IMM(x, op, T_N4 | T_66 | T_0F38 | T_W0 | T_YMM | T_EVEX, 0x18); }
void vcmpeq_ospd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 16); }
void vcmpeq_osps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 16); }
void vcmpeq_ossd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 16); }
void vcmpeq_osss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 16); }
void vcmpeq_uqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 8); }
void vcmpeq_uqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 8); }
void vcmpeq_uqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 8); }
void vcmpeq_uqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 8); }
void vcmpeq_uspd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 24); }
void vcmpeq_usps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 24); }
void vcmpeq_ussd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 24); }
void vcmpeq_usss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 24); }
void vcmpeqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 0); }
void vcmpeqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 0); }
void vcmpeqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 0); }
void vcmpeqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 0); }
void vcmpfalse_ospd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 27); }
void vcmpfalse_osps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 27); }
void vcmpfalse_ossd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 27); }
void vcmpfalse_osss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 27); }
void vcmpfalsepd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 11); }
void vcmpfalseps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 11); }
void vcmpfalsesd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 11); }
void vcmpfalsess(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 11); }
void vcmpge_oqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 29); }
void vcmpge_oqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 29); }
void vcmpge_oqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 29); }
void vcmpge_oqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 29); }
void vcmpgepd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 13); }
void vcmpgeps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 13); }
void vcmpgesd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 13); }
void vcmpgess(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 13); }
void vcmpgt_oqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 30); }
void vcmpgt_oqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 30); }
void vcmpgt_oqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 30); }
void vcmpgt_oqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 30); }
void vcmpgtpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 14); }
void vcmpgtps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 14); }
void vcmpgtsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 14); }
void vcmpgtss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 14); }
void vcmple_oqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 18); }
void vcmple_oqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 18); }
void vcmple_oqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 18); }
void vcmple_oqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 18); }
void vcmplepd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 2); }
void vcmpleps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 2); }
void vcmplesd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 2); }
void vcmpless(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 2); }
void vcmplt_oqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 17); }
void vcmplt_oqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 17); }
void vcmplt_oqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 17); }
void vcmplt_oqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 17); }
void vcmpltpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 1); }
void vcmpltps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 1); }
void vcmpltsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 1); }
void vcmpltss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 1); }
void vcmpneq_oqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 12); }
void vcmpneq_oqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 12); }
void vcmpneq_oqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 12); }
void vcmpneq_oqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 12); }
void vcmpneq_ospd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 28); }
void vcmpneq_osps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 28); }
void vcmpneq_ossd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 28); }
void vcmpneq_osss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 28); }
void vcmpneq_uspd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 20); }
void vcmpneq_usps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 20); }
void vcmpneq_ussd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 20); }
void vcmpneq_usss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 20); }
void vcmpneqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 4); }
void vcmpneqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 4); }
void vcmpneqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 4); }
void vcmpneqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 4); }
void vcmpnge_uqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 25); }
void vcmpnge_uqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 25); }
void vcmpnge_uqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 25); }
void vcmpnge_uqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 25); }
void vcmpngepd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 9); }
void vcmpngeps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 9); }
void vcmpngesd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 9); }
void vcmpngess(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 9); }
void vcmpngt_uqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 26); }
void vcmpngt_uqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 26); }
void vcmpngt_uqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 26); }
void vcmpngt_uqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 26); }
void vcmpngtpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 10); }
void vcmpngtps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 10); }
void vcmpngtsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 10); }
void vcmpngtss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 10); }
void vcmpnle_uqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 22); }
void vcmpnle_uqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 22); }
void vcmpnle_uqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 22); }
void vcmpnle_uqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 22); }
void vcmpnlepd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 6); }
void vcmpnleps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 6); }
void vcmpnlesd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 6); }
void vcmpnless(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 6); }
void vcmpnlt_uqpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 21); }
void vcmpnlt_uqps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 21); }
void vcmpnlt_uqsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 21); }
void vcmpnlt_uqss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 21); }
void vcmpnltpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 5); }
void vcmpnltps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 5); }
void vcmpnltsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 5); }
void vcmpnltss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 5); }
void vcmpord_spd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 23); }
void vcmpord_sps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 23); }
void vcmpord_ssd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 23); }
void vcmpord_sss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 23); }
void vcmpordpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 7); }
void vcmpordps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 7); }
void vcmpordsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 7); }
void vcmpordss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 7); }
void vcmppd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0xC2, imm); }
void vcmpps(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_0F | T_YMM, 0xC2, imm); }
void vcmpsd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_F2 | T_0F, 0xC2, imm); }
void vcmpss(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_F3 | T_0F, 0xC2, imm); }
void vcmptrue_uspd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 31); }
void vcmptrue_usps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 31); }
void vcmptrue_ussd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 31); }
void vcmptrue_usss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 31); }
void vcmptruepd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 15); }
void vcmptrueps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 15); }
void vcmptruesd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 15); }
void vcmptruess(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 15); }
void vcmpunord_spd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 19); }
void vcmpunord_sps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 19); }
void vcmpunord_ssd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 19); }
void vcmpunord_sss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 19); }
void vcmpunordpd(Xmm x1, Xmm x2, Operand op) { vcmppd(x1, x2, op, 3); }
void vcmpunordps(Xmm x1, Xmm x2, Operand op) { vcmpps(x1, x2, op, 3); }
void vcmpunordsd(Xmm x1, Xmm x2, Operand op) { vcmpsd(x1, x2, op, 3); }
void vcmpunordss(Xmm x1, Xmm x2, Operand op) { vcmpss(x1, x2, op, 3); }
void vcomisd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8 | T_66 | T_0F | T_EW1 | T_EVEX | T_SAE_X, 0x2F); }
void vcomiss(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4 | T_0F | T_EW0 | T_EVEX | T_SAE_X, 0x2F); }
void vcvtdq2pd(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_0F | T_F3 | T_YMM | T_EVEX | T_EW0 | T_B32 | T_N8 | T_N_VL, 0xE6); }
void vcvtdq2ps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x5B); }
void vcvtpd2dq(Xmm x, Operand op) { opCvt2(x, op, T_0F | T_F2 | T_YMM | T_EVEX | T_EW1 | T_B64 | T_ER_Z, 0xE6); }
void vcvtpd2ps(Xmm x, Operand op) { opCvt2(x, op, T_0F | T_66 | T_YMM | T_EVEX | T_EW1 | T_B64 | T_ER_Z, 0x5A); }
void vcvtph2ps(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_0F38 | T_66 | T_W0 | T_EVEX | T_EW0 | T_N8 | T_N_VL | T_SAE_Y, 0x13); }
void vcvtps2dq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x5B); }
void vcvtps2pd(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_0F | T_YMM | T_EVEX | T_EW0 | T_B32 | T_N8 | T_N_VL | T_SAE_Y, 0x5A); }
void vcvtps2ph(Operand op, Xmm x, uint8 imm) { checkCvt1(x, op); opVex(x, null, op, T_0F3A | T_66 | T_W0 | T_EVEX | T_EW0 | T_N8 | T_N_VL | T_SAE_Y, 0x1D, imm); }
void vcvtsd2si(Reg32 r, Operand op) { opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, T_0F | T_F2 | T_W0 | T_EVEX | T_EW0 | T_N4 | T_ER_X, 0x2D); }
void vcvtsd2ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_F2 | T_0F | T_EW1 | T_EVEX | T_ER_X, 0x5A); }
void vcvtsi2sd(Xmm x1, Xmm x2, Operand op) { opCvt3(x1, x2, op, T_0F | T_F2 | T_EVEX, T_W1 | T_EW1 | T_ER_X | T_N8, T_W0 | T_EW0 | T_N4, 0x2A); }
void vcvtsi2ss(Xmm x1, Xmm x2, Operand op) { opCvt3(x1, x2, op, T_0F | T_F3 | T_EVEX | T_ER_X, T_W1 | T_EW1 | T_N8, T_W0 | T_EW0 | T_N4, 0x2A); }
void vcvtss2sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_F3 | T_0F | T_EW0 | T_EVEX | T_SAE_X, 0x5A); }
void vcvtss2si(Reg32 r, Operand op) { opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, T_0F | T_F3 | T_W0 | T_EVEX | T_EW0 | T_ER_X | T_N8, 0x2D); }
void vcvttpd2dq(Xmm x, Operand op) { opCvt2(x, op, T_66 | T_0F | T_YMM | T_EVEX |T_EW1 | T_B64 | T_ER_Z, 0xE6); }
void vcvttps2dq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_F3 | T_0F | T_EW0 | T_YMM | T_EVEX | T_SAE_Z | T_B32, 0x5B); }
void vcvttsd2si(Reg32 r, Operand op) { opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, T_0F | T_F2 | T_W0 | T_EVEX | T_EW0 | T_N4 | T_SAE_X, 0x2C); }
void vcvttss2si(Reg32 r, Operand op) { opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, T_0F | T_F3 | T_W0 | T_EVEX | T_EW0 | T_SAE_X | T_N8, 0x2C); }
void vdivpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x5E); }
void vdivps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x5E); }
void vdivsd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_ER_Z | T_N8, 0x5E); }
void vdivss(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_ER_Z | T_N4, 0x5E); }
void vdppd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W0, 0x41, imm); }
void vdpps(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W0 | T_YMM, 0x40, imm); }
void vextractf128(Operand op, Ymm y, uint8 imm) { if (!(op.isXMEM() & y.isYMM())) throw new XError(ERR.BAD_COMBINATION); opVex(y, null, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x19, imm); }
void vextracti128(Operand op, Ymm y, uint8 imm) { if (!(op.isXMEM() & y.isYMM())) throw new XError(ERR.BAD_COMBINATION); opVex(y, null, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x39, imm); }
void vextractps(Operand op, Xmm x, uint8 imm) { if (!((op.isREG(32) || op.isMEM()) && x.isXMM())) throw new XError(ERR.BAD_COMBINATION); opVex(x, null, op, T_0F3A | T_66 | T_W0 | T_EVEX | T_N4, 0x17, imm); }
void vfmadd132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x98); }
void vfmadd132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x98); }
void vfmadd132sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0x99); }
void vfmadd132ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0x99); }
void vfmadd213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xA8); }
void vfmadd213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xA8); }
void vfmadd213sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0xA9); }
void vfmadd213ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0xA9); }
void vfmadd231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xB8); }
void vfmadd231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xB8); }
void vfmadd231sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0xB9); }
void vfmadd231ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0xB9); }
void vfmaddsub132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x96); }
void vfmaddsub132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x96); }
void vfmaddsub213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xA6); }
void vfmaddsub213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xA6); }
void vfmaddsub231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xB6); }
void vfmaddsub231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xB6); }
void vfmsub132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x9A); }
void vfmsub132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x9A); }
void vfmsub132sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0x9B); }
void vfmsub132ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0x9B); }
void vfmsub213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xAA); }
void vfmsub213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xAA); }
void vfmsub213sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0xAB); }
void vfmsub213ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0xAB); }
void vfmsub231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xBA); }
void vfmsub231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xBA); }
void vfmsub231sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0xBB); }
void vfmsub231ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0xBB); }
void vfmsubadd132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x97); }
void vfmsubadd132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x97); }
void vfmsubadd213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xA7); }
void vfmsubadd213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xA7); }
void vfmsubadd231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xB7); }
void vfmsubadd231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xB7); }
void vfnmadd132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x9C); }
void vfnmadd132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x9C); }
void vfnmadd132sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0x9D); }
void vfnmadd132ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0x9D); }
void vfnmadd213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xAC); }
void vfnmadd213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xAC); }
void vfnmadd213sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0xAD); }
void vfnmadd213ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0xAD); }
void vfnmadd231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xBC); }
void vfnmadd231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xBC); }
void vfnmadd231sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0xBD); }
void vfnmadd231ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0xBD); }
void vfnmsub132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x9E); }
void vfnmsub132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x9E); }
void vfnmsub132sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0x9F); }
void vfnmsub132ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0x9F); }
void vfnmsub213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xAE); }
void vfnmsub213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xAE); }
void vfnmsub213sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0xAF); }
void vfnmsub213ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0xAF); }
void vfnmsub231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0xBE); }
void vfnmsub231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0xBE); }
void vfnmsub231sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_W1 | T_EW1 | T_EVEX | T_ER_X, 0xBF); }
void vfnmsub231ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_W0 | T_EW0 | T_EVEX | T_ER_X, 0xBF); }
void vgatherdpd(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W1, 0x92, 0); }
void vgatherdps(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W0, 0x92, 1); }
void vgatherqpd(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W1, 0x93, 1); }
void vgatherqps(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W0, 0x93, 2); }
void vgf2p8affineinvqb(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W1 | T_EW1 | T_YMM | T_EVEX | T_SAE_Z | T_B64, 0xCF, imm); }
void vgf2p8affineqb(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W1 | T_EW1 | T_YMM | T_EVEX | T_SAE_Z | T_B64, 0xCE, imm); }
void vgf2p8mulb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_SAE_Z, 0xCF); }
void vhaddpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66 | T_0F | T_YMM, 0x7C); }
void vhaddps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_F2 | T_0F | T_YMM, 0x7C); }
void vhsubpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66 | T_0F | T_YMM, 0x7D); }
void vhsubps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_F2 | T_0F | T_YMM, 0x7D); }
void vinsertf128(Ymm y1, Ymm y2, Operand op, uint8 imm) { if (!(y1.isYMM() && y2.isYMM() && op.isXMEM())) throw new XError(ERR.BAD_COMBINATION); opVex(y1, y2, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x18, imm); }
void vinserti128(Ymm y1, Ymm y2, Operand op, uint8 imm) { if (!(y1.isYMM() && y2.isYMM() && op.isXMEM())) throw new XError(ERR.BAD_COMBINATION); opVex(y1, y2, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x38, imm); }
void vinsertps(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F3A | T_W0 | T_EW0 | T_EVEX, 0x21, imm); }
void vlddqu(Xmm x, Address addr) { opAVX_X_X_XM(x, cvtIdx0(x), addr, T_0F | T_F2 | T_W0 | T_YMM, 0xF0); }
void vldmxcsr(Address addr) { opAVX_X_X_XM(xm2, xm0, addr, T_0F, 0xAE); }
void vmaskmovdqu(Xmm x1, Xmm x2) { opAVX_X_X_XM(x1, xm0, x2, T_0F | T_66, 0xF7); }
void vmaskmovpd(Address addr, Xmm x1, Xmm x2) { opAVX_X_X_XM(x2, x1, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x2F); }
void vmaskmovpd(Xmm x1, Xmm x2, Address addr) { opAVX_X_X_XM(x1, x2, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x2D); }
void vmaskmovps(Address addr, Xmm x1, Xmm x2) { opAVX_X_X_XM(x2, x1, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x2E); }
void vmaskmovps(Xmm x1, Xmm x2, Address addr) { opAVX_X_X_XM(x1, x2, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x2C); }
void vmaxpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x5F); }
void vmaxps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x5F); }
void vmaxsd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_ER_Z | T_N8, 0x5F); }
void vmaxss(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_ER_Z | T_N4, 0x5F); }
void vminpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x5D); }
void vminps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x5D); }
void vminsd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_ER_Z | T_N8, 0x5D); }
void vminss(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_ER_Z | T_N4, 0x5D); }
void vmovapd(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_M_K, 0x29); }
void vmovapd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX, 0x28); }
void vmovaps(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_0F | T_EW0 | T_YMM | T_EVEX | T_M_K, 0x29); }
void vmovaps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F | T_EW0 | T_YMM | T_EVEX, 0x28); }
void vmovd(Operand op, Xmm x) { if (!op.isREG(32) && !op.isMEM()) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x, xm0, op, T_0F | T_66 | T_W0 | T_EVEX | T_N4, 0x7E); }
void vmovd(Xmm x, Operand op) { if (!op.isREG(32) && !op.isMEM()) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x, xm0, op, T_0F | T_66 | T_W0 | T_EVEX | T_N4, 0x6E); }
void vmovddup(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_DUP | T_F2 | T_0F | T_EW1 | T_YMM | T_EVEX | T_ER_X | T_ER_Y | T_ER_Z, 0x12); }
void vmovdqa(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_66 | T_0F | T_YMM, 0x7F); }
void vmovdqa(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F | T_YMM, 0x6F); }
void vmovdqu(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_F3 | T_0F | T_YMM, 0x7F); }
void vmovdqu(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_F3 | T_0F | T_YMM, 0x6F); }
void vmovhlps(Xmm x1, Xmm x2, Operand op = new Operand()) { if (!op.isNone() && !op.isXMM()) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x1, x2, op, T_0F | T_EVEX | T_EW0, 0x12); }
void vmovhpd(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_0F | T_66 | T_EVEX | T_EW1 | T_N8, 0x17); }
void vmovhpd(Xmm x, Operand op1, Operand op2 = new Operand()) { if (!op2.isNone() && !op2.isMEM()) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x, op1, op2, T_0F | T_66 | T_EVEX | T_EW1 | T_N8, 0x16); }
void vmovhps(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_0F | T_EVEX | T_EW0 | T_N8, 0x17); }
void vmovhps(Xmm x, Operand op1, Operand op2 = new Operand()) { if (!op2.isNone() && !op2.isMEM()) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x, op1, op2, T_0F | T_EVEX | T_EW0 | T_N8, 0x16); }
void vmovlhps(Xmm x1, Xmm x2, Operand op = new Operand()) { if (!op.isNone() && !op.isXMM()) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x1, x2, op, T_0F | T_EVEX | T_EW0, 0x16); }
void vmovlpd(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_0F | T_66 | T_EVEX | T_EW1 | T_N8, 0x13); }
void vmovlpd(Xmm x, Operand op1, Operand op2 = new Operand()) { if (!op2.isNone() && !op2.isMEM()) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x, op1, op2, T_0F | T_66 | T_EVEX | T_EW1 | T_N8, 0x12); }
void vmovlps(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_0F | T_EVEX | T_EW0 | T_N8, 0x13); }
void vmovlps(Xmm x, Operand op1, Operand op2 = new Operand()) { if (!op2.isNone() && !op2.isMEM()) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x, op1, op2, T_0F | T_EVEX | T_EW0 | T_N8, 0x12); }
void vmovmskpd(Reg r, Xmm x) { if (!r.isBit(i32e)) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x.isXMM() ? new Xmm(r.getIdx()) : new Ymm(r.getIdx()), cvtIdx0(x), x, T_0F | T_66 | T_W0 | T_YMM, 0x50); }
void vmovmskps(Reg r, Xmm x) { if (!r.isBit(i32e)) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x.isXMM() ? new Xmm(r.getIdx()) : new Ymm(r.getIdx()), cvtIdx0(x), x, T_0F | T_W0 | T_YMM, 0x50); }
void vmovntdq(Address addr, Xmm x) { opVex(x, null, addr, T_0F | T_66 | T_YMM | T_EVEX | T_EW0, 0xE7); }
void vmovntdqa(Xmm x, Address addr) { opVex(x, null, addr, T_0F38 | T_66 | T_YMM | T_EVEX | T_EW0, 0x2A); }
void vmovntpd(Address addr, Xmm x) { opVex(x, null, addr, T_0F | T_66 | T_YMM | T_EVEX | T_EW1, 0x2B); }
void vmovntps(Address addr, Xmm x) { opVex(x, null, addr, T_0F | T_YMM | T_EVEX | T_EW0, 0x2B); }
void vmovq(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_0F | T_66 | T_EVEX | T_EW1 | T_N8, x.getIdx() < 16 ? 0xD6 : 0x7E); }
void vmovq(Xmm x, Address addr) { int type, code; if (x.getIdx() < 16) { type = T_0F | T_F3; code = 0x7E; } else { type = T_0F | T_66 | T_EVEX | T_EW1 | T_N8; code = 0x6E; } opAVX_X_X_XM(x, xm0, addr, type, code); }
void vmovq(Xmm x1, Xmm x2) { opAVX_X_X_XM(x1, xm0, x2, T_0F | T_F3 | T_EVEX | T_EW1 | T_N8, 0x7E); }
void vmovsd(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_N8 | T_F2 | T_0F | T_EW1 | T_EVEX | T_M_K, 0x11); }
void vmovsd(Xmm x, Address addr) { opAVX_X_X_XM(x, xm0, addr, T_N8 | T_F2 | T_0F | T_EW1 | T_EVEX, 0x10); }
void vmovsd(Xmm x1, Xmm x2, Operand op = new Operand()) { if (!op.isNone() && !op.isXMM()) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x1, x2, op, T_N8 | T_F2 | T_0F | T_EW1 | T_EVEX, 0x10); }
void vmovshdup(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_F3 | T_0F | T_EW0 | T_YMM | T_EVEX, 0x16); }
void vmovsldup(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_F3 | T_0F | T_EW0 | T_YMM | T_EVEX, 0x12); }
void vmovss(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_N4 | T_F3 | T_0F | T_EW0 | T_EVEX | T_M_K, 0x11); }
void vmovss(Xmm x, Address addr) { opAVX_X_X_XM(x, xm0, addr, T_N4 | T_F3 | T_0F | T_EW0 | T_EVEX, 0x10); }
void vmovss(Xmm x1, Xmm x2, Operand op = new Operand()) { if (!op.isNone() && !op.isXMM()) throw new XError(ERR.BAD_COMBINATION); opAVX_X_X_XM(x1, x2, op, T_N4 | T_F3 | T_0F | T_EW0 | T_EVEX, 0x10); }
void vmovupd(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_M_K, 0x11); }
void vmovupd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX, 0x10); }
void vmovups(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_0F | T_EW0 | T_YMM | T_EVEX | T_M_K, 0x11); }
void vmovups(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F | T_EW0 | T_YMM | T_EVEX, 0x10); }
void vmpsadbw(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W0 | T_YMM, 0x42, imm); }
void vmulpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x59); }
void vmulps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x59); }
void vmulsd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_ER_Z | T_N8, 0x59); }
void vmulss(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_ER_Z | T_N4, 0x59); }
void vorpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x56); }
void vorps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x56); }
void vpabsb(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F38 | T_YMM | T_EVEX, 0x1C); }
void vpabsd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x1E); }
void vpabsw(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F38 | T_YMM | T_EVEX, 0x1D); }
void vpackssdw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW0 | T_YMM | T_EVEX | T_B32, 0x6B); }
void vpacksswb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0x63); }
void vpackusdw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x2B); }
void vpackuswb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0x67); }
void vpaddb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xFC); }
void vpaddd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW0 | T_YMM | T_EVEX | T_B32, 0xFE); }
void vpaddq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_B64, 0xD4); }
void vpaddsb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xEC); }
void vpaddsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xED); }
void vpaddusb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xDC); }
void vpaddusw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xDD); }
void vpaddw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xFD); }
void vpalignr(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_YMM | T_EVEX, 0x0F, imm); }
void vpand(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0xDB); }
void vpandn(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0xDF); }
void vpavgb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xE0); }
void vpavgw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xE3); }
void vpblendd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W0 | T_YMM, 0x02, imm); }
void vpblendvb(Xmm x1, Xmm x2, Operand op, Xmm x4) { opAVX_X_X_XM(x1, x2, op, T_0F3A | T_66 | T_YMM, 0x4C, x4.getIdx() << 4); }
void vpblendw(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W0 | T_YMM, 0x0E, imm); }
void vpbroadcastb(Xmm x, Operand op) { if (!(op.isXMM() || op.isMEM())) throw new XError(ERR.BAD_COMBINATION); opAVX_X_XM_IMM(x, op, T_N1 | T_66 | T_0F38 | T_W0 | T_YMM | T_EVEX, 0x78); }
void vpbroadcastd(Xmm x, Operand op) { if (!(op.isXMM() || op.isMEM())) throw new XError(ERR.BAD_COMBINATION); opAVX_X_XM_IMM(x, op, T_N4 | T_66 | T_0F38 | T_W0 | T_YMM | T_EVEX, 0x58); }
void vpbroadcastq(Xmm x, Operand op) { if (!(op.isXMM() || op.isMEM())) throw new XError(ERR.BAD_COMBINATION); opAVX_X_XM_IMM(x, op, T_N8 | T_66 | T_0F38 | T_W0 | T_EW1 | T_YMM | T_EVEX, 0x59); }
void vpbroadcastw(Xmm x, Operand op) { if (!(op.isXMM() || op.isMEM())) throw new XError(ERR.BAD_COMBINATION); opAVX_X_XM_IMM(x, op, T_N2 | T_66 | T_0F38 | T_W0 | T_YMM | T_EVEX, 0x79); }
void vpclmulqdq(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W0 | T_YMM | T_EVEX, 0x44, imm); }
void vpcmpeqb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0x74); }
void vpcmpeqd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0x76); }
void vpcmpeqq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x29); }
void vpcmpeqw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0x75); }
void vpcmpestri(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F3A, 0x61, imm); }
void vpcmpestrm(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F3A, 0x60, imm); }
void vpcmpgtb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0x64); }
void vpcmpgtd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0x66); }
void vpcmpgtq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x37); }
void vpcmpgtw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0x65); }
void vpcmpistri(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F3A, 0x63, imm); }
void vpcmpistrm(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F3A, 0x62, imm); }
void vperm2f128(Ymm y1, Ymm y2, Operand op, uint8 imm) { if (!(y1.isYMM() && y2.isYMM() && op.isYMEM())) throw new XError(ERR.BAD_COMBINATION); opVex(y1, y2, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x06, imm); }
void vperm2i128(Ymm y1, Ymm y2, Operand op, uint8 imm) { if (!(y1.isYMM() && y2.isYMM() && op.isYMEM())) throw new XError(ERR.BAD_COMBINATION); opVex(y1, y2, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x46, imm); }
void vpermd(Ymm y1, Ymm y2, Operand op) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x36); }
void vpermilpd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x0D); }
void vpermilpd(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_EVEX | T_B64, 0x05, imm); }
void vpermilps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x0C); }
void vpermilps(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_EVEX | T_B32, 0x04, imm); }
void vpermpd(Ymm y, Operand op, uint8 imm) { opAVX_X_XM_IMM(y, op, T_66 | T_0F3A | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x01, imm); }
void vpermpd(Ymm y1, Ymm y2, Operand op) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x16); }
void vpermps(Ymm y1, Ymm y2, Operand op) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x16); }
void vpermq(Ymm y, Operand op, uint8 imm) { opAVX_X_XM_IMM(y, op, T_66 | T_0F3A | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x00, imm); }
void vpermq(Ymm y1, Ymm y2, Operand op) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F38 | T_W0 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x36); }
void vpextrb(Operand op, Xmm x, uint8 imm) { if (!((op.isREG(8|16|i32e) || op.isMEM()) && x.isXMM())) throw new XError(ERR.BAD_COMBINATION); opVex(x, null, op, T_0F3A | T_66 | T_EVEX | T_N1, 0x14, imm); }
void vpextrd(Operand op, Xmm x, uint8 imm) { if (!((op.isREG(32) || op.isMEM()) && x.isXMM())) throw new XError(ERR.BAD_COMBINATION); opVex(x, null, op, T_0F3A | T_66 | T_W0 | T_EVEX | T_EW0 | T_N4, 0x16, imm); }
void vpextrq(Operand op, Xmm x, uint8 imm) { if (!((op.isREG(64) || op.isMEM()) && x.isXMM())) throw new XError(ERR.BAD_COMBINATION); opVex(x, null, op, T_0F3A | T_66 | T_W1 | T_EVEX | T_EW1 | T_N8, 0x16, imm); }
void vpextrw(Operand op, Xmm x, uint8 imm) { if (!((op.isREG(16|i32e) || op.isMEM()) && x.isXMM())) throw new XError(ERR.BAD_COMBINATION); if (op.isREG() && x.getIdx() < 16) { opAVX_X_X_XM(new Xmm(op.getIdx()), xm0, x, T_0F | T_66, 0xC5, imm); } else { opVex(x, null, op, T_0F3A | T_66 | T_EVEX | T_N2, 0x15, imm); } }
void vpgatherdd(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W0, 0x90, 1); }
void vpgatherdq(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W1, 0x90, 0); }
void vpgatherqd(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W0, 0x91, 2); }
void vpgatherqq(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W1, 0x91, 1); }
void vphaddd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x02); }
void vphaddsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x03); }
void vphaddw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x01); }
void vphminposuw(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F38, 0x41); }
void vphsubd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x06); }
void vphsubsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x07); }
void vphsubw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x05); }
void vpinsrb(Xmm x1, Xmm x2, Operand op, uint8 imm) { if (!(x1.isXMM() && x2.isXMM() && (op.isREG(32) || op.isMEM()))) throw new XError(ERR.BAD_COMBINATION); opVex(x1, x2, op, T_0F3A | T_66 | T_EVEX | T_N1, 0x20, imm); }
void vpinsrd(Xmm x1, Xmm x2, Operand op, uint8 imm) { if (!(x1.isXMM() && x2.isXMM() && (op.isREG(32) || op.isMEM()))) throw new XError(ERR.BAD_COMBINATION); opVex(x1, x2, op, T_0F3A | T_66 | T_W0 | T_EVEX | T_EW0 | T_N4, 0x22, imm); }
void vpinsrq(Xmm x1, Xmm x2, Operand op, uint8 imm) { if (!(x1.isXMM() && x2.isXMM() && (op.isREG(64) || op.isMEM()))) throw new XError(ERR.BAD_COMBINATION); opVex(x1, x2, op, T_0F3A | T_66 | T_W1 | T_EVEX | T_EW1 | T_N8, 0x22, imm); }
void vpinsrw(Xmm x1, Xmm x2, Operand op, uint8 imm) { if (!(x1.isXMM() && x2.isXMM() && (op.isREG(32) || op.isMEM()))) throw new XError(ERR.BAD_COMBINATION); opVex(x1, x2, op, T_0F | T_66 | T_EVEX | T_N2, 0xC4, imm); }
void vpmaddubsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM | T_EVEX, 0x04); }
void vpmaddwd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xF5); }
void vpmaskmovd(Address addr, Xmm x1, Xmm x2) { opAVX_X_X_XM(x2, x1, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x8E); }
void vpmaskmovd(Xmm x1, Xmm x2, Address addr) { opAVX_X_X_XM(x1, x2, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x8C); }
void vpmaskmovq(Address addr, Xmm x1, Xmm x2) { opAVX_X_X_XM(x2, x1, addr, T_0F38 | T_66 | T_W1 | T_YMM, 0x8E); }
void vpmaskmovq(Xmm x1, Xmm x2, Address addr) { opAVX_X_X_XM(x1, x2, addr, T_0F38 | T_66 | T_W1 | T_YMM, 0x8C); }
void vpmaxsb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM | T_EVEX, 0x3C); }
void vpmaxsd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x3D); }
void vpmaxsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xEE); }
void vpmaxub(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xDE); }
void vpmaxud(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x3F); }
void vpmaxuw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM | T_EVEX, 0x3E); }
void vpminsb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM | T_EVEX, 0x38); }
void vpminsd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x39); }
void vpminsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xEA); }
void vpminub(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xDA); }
void vpminud(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x3B); }
void vpminuw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM | T_EVEX, 0x3A); }
void vpmovmskb(Reg32e r, Xmm x) { if (!x.isKind(Kind.XMM | Kind.YMM)) throw new XError(ERR.BAD_COMBINATION); opVex(x.isYMM() ? new Ymm(r.getIdx()) : new Xmm(r.getIdx()), null, x, T_0F | T_66 | T_YMM, 0xD7); }
void vpmovsxbd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4 | T_N_VL | T_66 | T_0F38 | T_YMM | T_EVEX, 0x21); }
void vpmovsxbq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N2 | T_N_VL | T_66 | T_0F38 | T_YMM | T_EVEX, 0x22); }
void vpmovsxbw(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8 | T_N_VL | T_66 | T_0F38 | T_YMM | T_EVEX, 0x20); }
void vpmovsxdq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8 | T_N_VL | T_66 | T_0F38 | T_EW0 | T_YMM | T_EVEX, 0x25); }
void vpmovsxwd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8 | T_N_VL | T_66 | T_0F38 | T_YMM | T_EVEX, 0x23); }
void vpmovsxwq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4 | T_N_VL | T_66 | T_0F38 | T_YMM | T_EVEX, 0x24); }
void vpmovzxbd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4 | T_N_VL | T_66 | T_0F38 | T_YMM | T_EVEX, 0x31); }
void vpmovzxbq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N2 | T_N_VL | T_66 | T_0F38 | T_YMM | T_EVEX, 0x32); }
void vpmovzxbw(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8 | T_N_VL | T_66 | T_0F38 | T_YMM | T_EVEX, 0x30); }
void vpmovzxdq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8 | T_N_VL | T_66 | T_0F38 | T_EW0 | T_YMM | T_EVEX, 0x35); }
void vpmovzxwd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8 | T_N_VL | T_66 | T_0F38 | T_YMM | T_EVEX, 0x33); }
void vpmovzxwq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4 | T_N_VL | T_66 | T_0F38 | T_YMM | T_EVEX, 0x34); }
void vpmuldq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x28); }
void vpmulhrsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM | T_EVEX, 0x0B); }
void vpmulhuw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xE4); }
void vpmulhw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xE5); }
void vpmulld(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x40); }
void vpmullw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xD5); }
void vpmuludq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_B64, 0xF4); }
void vpor(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0xEB); }
void vpsadbw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xF6); }
void vpshufb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM | T_EVEX, 0x00); }
void vpshufd(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F | T_EW0 | T_YMM | T_EVEX | T_B32, 0x70, imm); }
void vpshufhw(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_F3 | T_0F | T_YMM | T_EVEX, 0x70, imm); }
void vpshuflw(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_F2 | T_0F | T_YMM | T_EVEX, 0x70, imm); }
void vpsignb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x08); }
void vpsignd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x0A); }
void vpsignw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_YMM, 0x09); }
void vpslld(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 6), x, op, T_66 | T_0F | T_EW0 | T_YMM | T_EVEX | T_B32 | T_MEM_EVEX, 0x72, imm); }
void vpslld(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16 | T_66 | T_0F | T_EW0 | T_YMM | T_EVEX, 0xF2); }
void vpslldq(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 7), x, op, T_66 | T_0F | T_YMM | T_EVEX | T_MEM_EVEX, 0x73, imm); }
void vpsllq(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 6), x, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_B64 | T_MEM_EVEX, 0x73, imm); }
void vpsllq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16 | T_66 | T_0F | T_EW1 | T_YMM | T_EVEX, 0xF3); }
void vpsllvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x47); }
void vpsllvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x47); }
void vpsllw(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 6), x, op, T_66 | T_0F | T_YMM | T_EVEX | T_MEM_EVEX, 0x71, imm); }
void vpsllw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16 | T_66 | T_0F | T_YMM | T_EVEX, 0xF1); }
void vpsrad(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 4), x, op, T_66 | T_0F | T_EW0 | T_YMM | T_EVEX | T_B32 | T_MEM_EVEX, 0x72, imm); }
void vpsrad(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16 | T_66 | T_0F | T_EW0 | T_YMM | T_EVEX, 0xE2); }
void vpsravd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x46); }
void vpsraw(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 4), x, op, T_66 | T_0F | T_YMM | T_EVEX | T_MEM_EVEX, 0x71, imm); }
void vpsraw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16 | T_66 | T_0F | T_YMM | T_EVEX, 0xE1); }
void vpsrld(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 2), x, op, T_66 | T_0F | T_EW0 | T_YMM | T_EVEX | T_B32 | T_MEM_EVEX, 0x72, imm); }
void vpsrld(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16 | T_66 | T_0F | T_EW0 | T_YMM | T_EVEX, 0xD2); }
void vpsrldq(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 3), x, op, T_66 | T_0F | T_YMM | T_EVEX | T_MEM_EVEX, 0x73, imm); }
void vpsrlq(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 2), x, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_B64 | T_MEM_EVEX, 0x73, imm); }
void vpsrlq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16 | T_66 | T_0F | T_EW1 | T_YMM | T_EVEX, 0xD3); }
void vpsrlvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W0 | T_EW0 | T_YMM | T_EVEX | T_B32, 0x45); }
void vpsrlvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_W1 | T_EW1 | T_YMM | T_EVEX | T_B64, 0x45); }
void vpsrlw(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 2), x, op, T_66 | T_0F | T_YMM | T_EVEX | T_MEM_EVEX, 0x71, imm); }
void vpsrlw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16 | T_66 | T_0F | T_YMM | T_EVEX, 0xD1); }
void vpsubb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xF8); }
void vpsubd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW0 | T_YMM | T_EVEX | T_B32, 0xFA); }
void vpsubq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_B64, 0xFB); }
void vpsubsb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xE8); }
void vpsubsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xE9); }
void vpsubusb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xD8); }
void vpsubusw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xD9); }
void vpsubw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0xF9); }
void vptest(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F38 | T_YMM, 0x17); }
void vpunpckhbw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0x68); }
void vpunpckhdq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW0 | T_YMM | T_EVEX | T_B32, 0x6A); }
void vpunpckhqdq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_B64, 0x6D); }
void vpunpckhwd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0x69); }
void vpunpcklbw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0x60); }
void vpunpckldq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW0 | T_YMM | T_EVEX | T_B32, 0x62); }
void vpunpcklqdq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_B64, 0x6C); }
void vpunpcklwd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM | T_EVEX, 0x61); }
void vpxor(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_YMM, 0xEF); }
void vrcpps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F | T_YMM, 0x53); }
void vrcpss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F3 | T_0F, 0x53); }
void vroundpd(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F3A | T_YMM, 0x09, imm); }
void vroundps(Xmm xm, Operand op, uint8 imm) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F3A | T_YMM, 0x08, imm); }
void vroundsd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W0, 0x0B, imm); }
void vroundss(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_W0, 0x0A, imm); }
void vrsqrtps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F | T_YMM, 0x52); }
void vrsqrtss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F3 | T_0F, 0x52); }
void vshufpd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_B64, 0xC6, imm); }
void vshufps(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_0F | T_EW0 | T_YMM | T_EVEX | T_B32, 0xC6, imm); }
void vsqrtpd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x51); }
void vsqrtps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x51); }
void vsqrtsd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_F2 | T_0F | T_EW1 | T_EVEX | T_ER_X, 0x51); }
void vsqrtss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_F3 | T_0F | T_EW0 | T_EVEX | T_ER_X, 0x51); }
void vstmxcsr(Address addr) { opAVX_X_X_XM(xm3, xm0, addr, T_0F, 0xAE); }
void vsubpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x5C); }
void vsubps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x5C); }
void vsubsd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_ER_Z | T_N8, 0x5C); }
void vsubss(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_ER_Z | T_N4, 0x5C); }
void vtestpd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F38 | T_YMM, 0x0F); }
void vtestps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66 | T_0F38 | T_YMM, 0x0E); }
void vucomisd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8 | T_66 | T_0F | T_EW1 | T_EVEX | T_SAE_X, 0x2E); }
void vucomiss(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4 | T_0F | T_EW0 | T_EVEX | T_SAE_X, 0x2E); }
void vunpckhpd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_B64, 0x15); }
void vunpckhps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_0F | T_EW0 | T_YMM | T_EVEX | T_B32, 0x15); }
void vunpcklpd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_EVEX | T_B64, 0x14); }
void vunpcklps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_0F | T_EW0 | T_YMM | T_EVEX | T_B32, 0x14); }
void vxorpd(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x57); }
void vxorps(Xmm xmm, Operand op1, Operand op2 = new Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x57); }
void vzeroall() { db(0xC5); db(0xFC); db(0x77); }
void vzeroupper() { db(0xC5); db(0xF8); db(0x77); }

void wait() { db(0x9B); }
void wbinvd() { db(0x0F); db(0x09); }
void wrmsr() { db(0x0F); db(0x30); }

void xadd(Operand op, Reg reg) { opModRM(reg, op, (op.isREG() && reg.isREG() && op.getBit() == reg.getBit()), op.isMEM(), 0x0F, 0xC0 | (reg.isBit(8) ? 0 : 1)); }
void xgetbv() { db(0x0F); db(0x01); db(0xD0); }
void xlatb() { db(0xD7); }
void xor(Operand op, uint32 imm) { opRM_I(op, imm, 0x30, 6); }
void xor(Operand op1, Operand op2) { opRM_RM(op1, op2, 0x30); }
void xorpd(Xmm xmm, Operand op) { opGen(xmm, op, 0x57, 0x66, &isXMM_XMMorMEM); }
void xorps(Xmm xmm, Operand op) { opGen(xmm, op, 0x57, 0x100, &isXMM_XMMorMEM); }

version(XBYAK_ENABLE_OMITTED_OPERAND)
{
void vblendpd(Xmm x, Operand op, uint8 imm) { vblendpd(x, x, op, imm); }
void vblendps(Xmm x, Operand op, uint8 imm) { vblendps(x, x, op, imm); }
void vblendvpd(Xmm x1, Operand op, Xmm x4) { vblendvpd(x1, x1, op, x4); }
void vblendvps(Xmm x1, Operand op, Xmm x4) { vblendvps(x1, x1, op, x4); }
void vcmpeq_ospd(Xmm x, Operand op) { vcmpeq_ospd(x, x, op); }
void vcmpeq_osps(Xmm x, Operand op) { vcmpeq_osps(x, x, op); }
void vcmpeq_ossd(Xmm x, Operand op) { vcmpeq_ossd(x, x, op); }
void vcmpeq_osss(Xmm x, Operand op) { vcmpeq_osss(x, x, op); }
void vcmpeq_uqpd(Xmm x, Operand op) { vcmpeq_uqpd(x, x, op); }
void vcmpeq_uqps(Xmm x, Operand op) { vcmpeq_uqps(x, x, op); }
void vcmpeq_uqsd(Xmm x, Operand op) { vcmpeq_uqsd(x, x, op); }
void vcmpeq_uqss(Xmm x, Operand op) { vcmpeq_uqss(x, x, op); }
void vcmpeq_uspd(Xmm x, Operand op) { vcmpeq_uspd(x, x, op); }
void vcmpeq_usps(Xmm x, Operand op) { vcmpeq_usps(x, x, op); }
void vcmpeq_ussd(Xmm x, Operand op) { vcmpeq_ussd(x, x, op); }
void vcmpeq_usss(Xmm x, Operand op) { vcmpeq_usss(x, x, op); }
void vcmpeqpd(Xmm x, Operand op) { vcmpeqpd(x, x, op); }
void vcmpeqps(Xmm x, Operand op) { vcmpeqps(x, x, op); }
void vcmpeqsd(Xmm x, Operand op) { vcmpeqsd(x, x, op); }
void vcmpeqss(Xmm x, Operand op) { vcmpeqss(x, x, op); }
void vcmpfalse_ospd(Xmm x, Operand op) { vcmpfalse_ospd(x, x, op); }
void vcmpfalse_osps(Xmm x, Operand op) { vcmpfalse_osps(x, x, op); }
void vcmpfalse_ossd(Xmm x, Operand op) { vcmpfalse_ossd(x, x, op); }
void vcmpfalse_osss(Xmm x, Operand op) { vcmpfalse_osss(x, x, op); }
void vcmpfalsepd(Xmm x, Operand op) { vcmpfalsepd(x, x, op); }
void vcmpfalseps(Xmm x, Operand op) { vcmpfalseps(x, x, op); }
void vcmpfalsesd(Xmm x, Operand op) { vcmpfalsesd(x, x, op); }
void vcmpfalsess(Xmm x, Operand op) { vcmpfalsess(x, x, op); }
void vcmpge_oqpd(Xmm x, Operand op) { vcmpge_oqpd(x, x, op); }
void vcmpge_oqps(Xmm x, Operand op) { vcmpge_oqps(x, x, op); }
void vcmpge_oqsd(Xmm x, Operand op) { vcmpge_oqsd(x, x, op); }
void vcmpge_oqss(Xmm x, Operand op) { vcmpge_oqss(x, x, op); }
void vcmpgepd(Xmm x, Operand op) { vcmpgepd(x, x, op); }
void vcmpgeps(Xmm x, Operand op) { vcmpgeps(x, x, op); }
void vcmpgesd(Xmm x, Operand op) { vcmpgesd(x, x, op); }
void vcmpgess(Xmm x, Operand op) { vcmpgess(x, x, op); }
void vcmpgt_oqpd(Xmm x, Operand op) { vcmpgt_oqpd(x, x, op); }
void vcmpgt_oqps(Xmm x, Operand op) { vcmpgt_oqps(x, x, op); }
void vcmpgt_oqsd(Xmm x, Operand op) { vcmpgt_oqsd(x, x, op); }
void vcmpgt_oqss(Xmm x, Operand op) { vcmpgt_oqss(x, x, op); }
void vcmpgtpd(Xmm x, Operand op) { vcmpgtpd(x, x, op); }
void vcmpgtps(Xmm x, Operand op) { vcmpgtps(x, x, op); }
void vcmpgtsd(Xmm x, Operand op) { vcmpgtsd(x, x, op); }
void vcmpgtss(Xmm x, Operand op) { vcmpgtss(x, x, op); }
void vcmple_oqpd(Xmm x, Operand op) { vcmple_oqpd(x, x, op); }
void vcmple_oqps(Xmm x, Operand op) { vcmple_oqps(x, x, op); }
void vcmple_oqsd(Xmm x, Operand op) { vcmple_oqsd(x, x, op); }
void vcmple_oqss(Xmm x, Operand op) { vcmple_oqss(x, x, op); }
void vcmplepd(Xmm x, Operand op) { vcmplepd(x, x, op); }
void vcmpleps(Xmm x, Operand op) { vcmpleps(x, x, op); }
void vcmplesd(Xmm x, Operand op) { vcmplesd(x, x, op); }
void vcmpless(Xmm x, Operand op) { vcmpless(x, x, op); }
void vcmplt_oqpd(Xmm x, Operand op) { vcmplt_oqpd(x, x, op); }
void vcmplt_oqps(Xmm x, Operand op) { vcmplt_oqps(x, x, op); }
void vcmplt_oqsd(Xmm x, Operand op) { vcmplt_oqsd(x, x, op); }
void vcmplt_oqss(Xmm x, Operand op) { vcmplt_oqss(x, x, op); }
void vcmpltpd(Xmm x, Operand op) { vcmpltpd(x, x, op); }
void vcmpltps(Xmm x, Operand op) { vcmpltps(x, x, op); }
void vcmpltsd(Xmm x, Operand op) { vcmpltsd(x, x, op); }
void vcmpltss(Xmm x, Operand op) { vcmpltss(x, x, op); }
void vcmpneq_oqpd(Xmm x, Operand op) { vcmpneq_oqpd(x, x, op); }
void vcmpneq_oqps(Xmm x, Operand op) { vcmpneq_oqps(x, x, op); }
void vcmpneq_oqsd(Xmm x, Operand op) { vcmpneq_oqsd(x, x, op); }
void vcmpneq_oqss(Xmm x, Operand op) { vcmpneq_oqss(x, x, op); }
void vcmpneq_ospd(Xmm x, Operand op) { vcmpneq_ospd(x, x, op); }
void vcmpneq_osps(Xmm x, Operand op) { vcmpneq_osps(x, x, op); }
void vcmpneq_ossd(Xmm x, Operand op) { vcmpneq_ossd(x, x, op); }
void vcmpneq_osss(Xmm x, Operand op) { vcmpneq_osss(x, x, op); }
void vcmpneq_uspd(Xmm x, Operand op) { vcmpneq_uspd(x, x, op); }
void vcmpneq_usps(Xmm x, Operand op) { vcmpneq_usps(x, x, op); }
void vcmpneq_ussd(Xmm x, Operand op) { vcmpneq_ussd(x, x, op); }
void vcmpneq_usss(Xmm x, Operand op) { vcmpneq_usss(x, x, op); }
void vcmpneqpd(Xmm x, Operand op) { vcmpneqpd(x, x, op); }
void vcmpneqps(Xmm x, Operand op) { vcmpneqps(x, x, op); }
void vcmpneqsd(Xmm x, Operand op) { vcmpneqsd(x, x, op); }
void vcmpneqss(Xmm x, Operand op) { vcmpneqss(x, x, op); }
void vcmpnge_uqpd(Xmm x, Operand op) { vcmpnge_uqpd(x, x, op); }
void vcmpnge_uqps(Xmm x, Operand op) { vcmpnge_uqps(x, x, op); }
void vcmpnge_uqsd(Xmm x, Operand op) { vcmpnge_uqsd(x, x, op); }
void vcmpnge_uqss(Xmm x, Operand op) { vcmpnge_uqss(x, x, op); }
void vcmpngepd(Xmm x, Operand op) { vcmpngepd(x, x, op); }
void vcmpngeps(Xmm x, Operand op) { vcmpngeps(x, x, op); }
void vcmpngesd(Xmm x, Operand op) { vcmpngesd(x, x, op); }
void vcmpngess(Xmm x, Operand op) { vcmpngess(x, x, op); }
void vcmpngt_uqpd(Xmm x, Operand op) { vcmpngt_uqpd(x, x, op); }
void vcmpngt_uqps(Xmm x, Operand op) { vcmpngt_uqps(x, x, op); }
void vcmpngt_uqsd(Xmm x, Operand op) { vcmpngt_uqsd(x, x, op); }
void vcmpngt_uqss(Xmm x, Operand op) { vcmpngt_uqss(x, x, op); }
void vcmpngtpd(Xmm x, Operand op) { vcmpngtpd(x, x, op); }
void vcmpngtps(Xmm x, Operand op) { vcmpngtps(x, x, op); }
void vcmpngtsd(Xmm x, Operand op) { vcmpngtsd(x, x, op); }
void vcmpngtss(Xmm x, Operand op) { vcmpngtss(x, x, op); }
void vcmpnle_uqpd(Xmm x, Operand op) { vcmpnle_uqpd(x, x, op); }
void vcmpnle_uqps(Xmm x, Operand op) { vcmpnle_uqps(x, x, op); }
void vcmpnle_uqsd(Xmm x, Operand op) { vcmpnle_uqsd(x, x, op); }
void vcmpnle_uqss(Xmm x, Operand op) { vcmpnle_uqss(x, x, op); }
void vcmpnlepd(Xmm x, Operand op) { vcmpnlepd(x, x, op); }
void vcmpnleps(Xmm x, Operand op) { vcmpnleps(x, x, op); }
void vcmpnlesd(Xmm x, Operand op) { vcmpnlesd(x, x, op); }
void vcmpnless(Xmm x, Operand op) { vcmpnless(x, x, op); }
void vcmpnlt_uqpd(Xmm x, Operand op) { vcmpnlt_uqpd(x, x, op); }
void vcmpnlt_uqps(Xmm x, Operand op) { vcmpnlt_uqps(x, x, op); }
void vcmpnlt_uqsd(Xmm x, Operand op) { vcmpnlt_uqsd(x, x, op); }
void vcmpnlt_uqss(Xmm x, Operand op) { vcmpnlt_uqss(x, x, op); }
void vcmpnltpd(Xmm x, Operand op) { vcmpnltpd(x, x, op); }
void vcmpnltps(Xmm x, Operand op) { vcmpnltps(x, x, op); }
void vcmpnltsd(Xmm x, Operand op) { vcmpnltsd(x, x, op); }
void vcmpnltss(Xmm x, Operand op) { vcmpnltss(x, x, op); }
void vcmpord_spd(Xmm x, Operand op) { vcmpord_spd(x, x, op); }
void vcmpord_sps(Xmm x, Operand op) { vcmpord_sps(x, x, op); }
void vcmpord_ssd(Xmm x, Operand op) { vcmpord_ssd(x, x, op); }
void vcmpord_sss(Xmm x, Operand op) { vcmpord_sss(x, x, op); }
void vcmpordpd(Xmm x, Operand op) { vcmpordpd(x, x, op); }
void vcmpordps(Xmm x, Operand op) { vcmpordps(x, x, op); }
void vcmpordsd(Xmm x, Operand op) { vcmpordsd(x, x, op); }
void vcmpordss(Xmm x, Operand op) { vcmpordss(x, x, op); }
void vcmppd(Xmm x, Operand op, uint8 imm) { vcmppd(x, x, op, imm); }
void vcmpps(Xmm x, Operand op, uint8 imm) { vcmpps(x, x, op, imm); }
void vcmpsd(Xmm x, Operand op, uint8 imm) { vcmpsd(x, x, op, imm); }
void vcmpss(Xmm x, Operand op, uint8 imm) { vcmpss(x, x, op, imm); }
void vcmptrue_uspd(Xmm x, Operand op) { vcmptrue_uspd(x, x, op); }
void vcmptrue_usps(Xmm x, Operand op) { vcmptrue_usps(x, x, op); }
void vcmptrue_ussd(Xmm x, Operand op) { vcmptrue_ussd(x, x, op); }
void vcmptrue_usss(Xmm x, Operand op) { vcmptrue_usss(x, x, op); }
void vcmptruepd(Xmm x, Operand op) { vcmptruepd(x, x, op); }
void vcmptrueps(Xmm x, Operand op) { vcmptrueps(x, x, op); }
void vcmptruesd(Xmm x, Operand op) { vcmptruesd(x, x, op); }
void vcmptruess(Xmm x, Operand op) { vcmptruess(x, x, op); }
void vcmpunord_spd(Xmm x, Operand op) { vcmpunord_spd(x, x, op); }
void vcmpunord_sps(Xmm x, Operand op) { vcmpunord_sps(x, x, op); }
void vcmpunord_ssd(Xmm x, Operand op) { vcmpunord_ssd(x, x, op); }
void vcmpunord_sss(Xmm x, Operand op) { vcmpunord_sss(x, x, op); }
void vcmpunordpd(Xmm x, Operand op) { vcmpunordpd(x, x, op); }
void vcmpunordps(Xmm x, Operand op) { vcmpunordps(x, x, op); }
void vcmpunordsd(Xmm x, Operand op) { vcmpunordsd(x, x, op); }
void vcmpunordss(Xmm x, Operand op) { vcmpunordss(x, x, op); }
void vcvtsd2ss(Xmm x, Operand op) { vcvtsd2ss(x, x, op); }
void vcvtsi2sd(Xmm x, Operand op) { vcvtsi2sd(x, x, op); }
void vcvtsi2ss(Xmm x, Operand op) { vcvtsi2ss(x, x, op); }
void vcvtss2sd(Xmm x, Operand op) { vcvtss2sd(x, x, op); }
void vdppd(Xmm x, Operand op, uint8 imm) { vdppd(x, x, op, imm); }
void vdpps(Xmm x, Operand op, uint8 imm) { vdpps(x, x, op, imm); }
void vinsertps(Xmm x, Operand op, uint8 imm) { vinsertps(x, x, op, imm); }
void vmpsadbw(Xmm x, Operand op, uint8 imm) { vmpsadbw(x, x, op, imm); }
void vpackssdw(Xmm x, Operand op) { vpackssdw(x, x, op); }
void vpacksswb(Xmm x, Operand op) { vpacksswb(x, x, op); }
void vpackusdw(Xmm x, Operand op) { vpackusdw(x, x, op); }
void vpackuswb(Xmm x, Operand op) { vpackuswb(x, x, op); }
void vpaddb(Xmm x, Operand op) { vpaddb(x, x, op); }
void vpaddd(Xmm x, Operand op) { vpaddd(x, x, op); }
void vpaddq(Xmm x, Operand op) { vpaddq(x, x, op); }
void vpaddsb(Xmm x, Operand op) { vpaddsb(x, x, op); }
void vpaddsw(Xmm x, Operand op) { vpaddsw(x, x, op); }
void vpaddusb(Xmm x, Operand op) { vpaddusb(x, x, op); }
void vpaddusw(Xmm x, Operand op) { vpaddusw(x, x, op); }
void vpaddw(Xmm x, Operand op) { vpaddw(x, x, op); }
void vpalignr(Xmm x, Operand op, uint8 imm) { vpalignr(x, x, op, imm); }
void vpand(Xmm x, Operand op) { vpand(x, x, op); }
void vpandn(Xmm x, Operand op) { vpandn(x, x, op); }
void vpavgb(Xmm x, Operand op) { vpavgb(x, x, op); }
void vpavgw(Xmm x, Operand op) { vpavgw(x, x, op); }
void vpblendd(Xmm x, Operand op, uint8 imm) { vpblendd(x, x, op, imm); }
void vpblendvb(Xmm x1, Operand op, Xmm x4) { vpblendvb(x1, x1, op, x4); }
void vpblendw(Xmm x, Operand op, uint8 imm) { vpblendw(x, x, op, imm); }
void vpclmulqdq(Xmm x, Operand op, uint8 imm) { vpclmulqdq(x, x, op, imm); }
void vpcmpeqb(Xmm x, Operand op) { vpcmpeqb(x, x, op); }
void vpcmpeqd(Xmm x, Operand op) { vpcmpeqd(x, x, op); }
void vpcmpeqq(Xmm x, Operand op) { vpcmpeqq(x, x, op); }
void vpcmpeqw(Xmm x, Operand op) { vpcmpeqw(x, x, op); }
void vpcmpgtb(Xmm x, Operand op) { vpcmpgtb(x, x, op); }
void vpcmpgtd(Xmm x, Operand op) { vpcmpgtd(x, x, op); }
void vpcmpgtq(Xmm x, Operand op) { vpcmpgtq(x, x, op); }
void vpcmpgtw(Xmm x, Operand op) { vpcmpgtw(x, x, op); }
void vphaddd(Xmm x, Operand op) { vphaddd(x, x, op); }
void vphaddsw(Xmm x, Operand op) { vphaddsw(x, x, op); }
void vphaddw(Xmm x, Operand op) { vphaddw(x, x, op); }
void vphsubd(Xmm x, Operand op) { vphsubd(x, x, op); }
void vphsubsw(Xmm x, Operand op) { vphsubsw(x, x, op); }
void vphsubw(Xmm x, Operand op) { vphsubw(x, x, op); }
void vpinsrb(Xmm x, Operand op, uint8 imm) { vpinsrb(x, x, op, imm); }
void vpinsrd(Xmm x, Operand op, uint8 imm) { vpinsrd(x, x, op, imm); }
void vpinsrq(Xmm x, Operand op, uint8 imm) { vpinsrq(x, x, op, imm); }
void vpinsrw(Xmm x, Operand op, uint8 imm) { vpinsrw(x, x, op, imm); }
void vpmaddubsw(Xmm x, Operand op) { vpmaddubsw(x, x, op); }
void vpmaddwd(Xmm x, Operand op) { vpmaddwd(x, x, op); }
void vpmaxsb(Xmm x, Operand op) { vpmaxsb(x, x, op); }
void vpmaxsd(Xmm x, Operand op) { vpmaxsd(x, x, op); }
void vpmaxsw(Xmm x, Operand op) { vpmaxsw(x, x, op); }
void vpmaxub(Xmm x, Operand op) { vpmaxub(x, x, op); }
void vpmaxud(Xmm x, Operand op) { vpmaxud(x, x, op); }
void vpmaxuw(Xmm x, Operand op) { vpmaxuw(x, x, op); }
void vpminsb(Xmm x, Operand op) { vpminsb(x, x, op); }
void vpminsd(Xmm x, Operand op) { vpminsd(x, x, op); }
void vpminsw(Xmm x, Operand op) { vpminsw(x, x, op); }
void vpminub(Xmm x, Operand op) { vpminub(x, x, op); }
void vpminud(Xmm x, Operand op) { vpminud(x, x, op); }
void vpminuw(Xmm x, Operand op) { vpminuw(x, x, op); }
void vpmuldq(Xmm x, Operand op) { vpmuldq(x, x, op); }
void vpmulhrsw(Xmm x, Operand op) { vpmulhrsw(x, x, op); }
void vpmulhuw(Xmm x, Operand op) { vpmulhuw(x, x, op); }
void vpmulhw(Xmm x, Operand op) { vpmulhw(x, x, op); }
void vpmulld(Xmm x, Operand op) { vpmulld(x, x, op); }
void vpmullw(Xmm x, Operand op) { vpmullw(x, x, op); }
void vpmuludq(Xmm x, Operand op) { vpmuludq(x, x, op); }
void vpor(Xmm x, Operand op) { vpor(x, x, op); }
void vpsadbw(Xmm x, Operand op) { vpsadbw(x, x, op); }
void vpsignb(Xmm x, Operand op) { vpsignb(x, x, op); }
void vpsignd(Xmm x, Operand op) { vpsignd(x, x, op); }
void vpsignw(Xmm x, Operand op) { vpsignw(x, x, op); }
void vpslld(Xmm x, Operand op) { vpslld(x, x, op); }
void vpslld(Xmm x, uint8 imm) { vpslld(x, x, imm); }
void vpslldq(Xmm x, uint8 imm) { vpslldq(x, x, imm); }
void vpsllq(Xmm x, Operand op) { vpsllq(x, x, op); }
void vpsllq(Xmm x, uint8 imm) { vpsllq(x, x, imm); }
void vpsllw(Xmm x, Operand op) { vpsllw(x, x, op); }
void vpsllw(Xmm x, uint8 imm) { vpsllw(x, x, imm); }
void vpsrad(Xmm x, Operand op) { vpsrad(x, x, op); }
void vpsrad(Xmm x, uint8 imm) { vpsrad(x, x, imm); }
void vpsraw(Xmm x, Operand op) { vpsraw(x, x, op); }
void vpsraw(Xmm x, uint8 imm) { vpsraw(x, x, imm); }
void vpsrld(Xmm x, Operand op) { vpsrld(x, x, op); }
void vpsrld(Xmm x, uint8 imm) { vpsrld(x, x, imm); }
void vpsrldq(Xmm x, uint8 imm) { vpsrldq(x, x, imm); }
void vpsrlq(Xmm x, Operand op) { vpsrlq(x, x, op); }
void vpsrlq(Xmm x, uint8 imm) { vpsrlq(x, x, imm); }
void vpsrlw(Xmm x, Operand op) { vpsrlw(x, x, op); }
void vpsrlw(Xmm x, uint8 imm) { vpsrlw(x, x, imm); }
void vpsubb(Xmm x, Operand op) { vpsubb(x, x, op); }
void vpsubd(Xmm x, Operand op) { vpsubd(x, x, op); }
void vpsubq(Xmm x, Operand op) { vpsubq(x, x, op); }
void vpsubsb(Xmm x, Operand op) { vpsubsb(x, x, op); }
void vpsubsw(Xmm x, Operand op) { vpsubsw(x, x, op); }
void vpsubusb(Xmm x, Operand op) { vpsubusb(x, x, op); }
void vpsubusw(Xmm x, Operand op) { vpsubusw(x, x, op); }
void vpsubw(Xmm x, Operand op) { vpsubw(x, x, op); }
void vpunpckhbw(Xmm x, Operand op) { vpunpckhbw(x, x, op); }
void vpunpckhdq(Xmm x, Operand op) { vpunpckhdq(x, x, op); }
void vpunpckhqdq(Xmm x, Operand op) { vpunpckhqdq(x, x, op); }
void vpunpckhwd(Xmm x, Operand op) { vpunpckhwd(x, x, op); }
void vpunpcklbw(Xmm x, Operand op) { vpunpcklbw(x, x, op); }
void vpunpckldq(Xmm x, Operand op) { vpunpckldq(x, x, op); }
void vpunpcklqdq(Xmm x, Operand op) { vpunpcklqdq(x, x, op); }
void vpunpcklwd(Xmm x, Operand op) { vpunpcklwd(x, x, op); }
void vpxor(Xmm x, Operand op) { vpxor(x, x, op); }
void vrcpss(Xmm x, Operand op) { vrcpss(x, x, op); }
void vroundsd(Xmm x, Operand op, uint8 imm) { vroundsd(x, x, op, imm); }
void vroundss(Xmm x, Operand op, uint8 imm) { vroundss(x, x, op, imm); }
void vrsqrtss(Xmm x, Operand op) { vrsqrtss(x, x, op); }
void vshufpd(Xmm x, Operand op, uint8 imm) { vshufpd(x, x, op, imm); }
void vshufps(Xmm x, Operand op, uint8 imm) { vshufps(x, x, op, imm); }
void vsqrtsd(Xmm x, Operand op) { vsqrtsd(x, x, op); }
void vsqrtss(Xmm x, Operand op) { vsqrtss(x, x, op); }
void vunpckhpd(Xmm x, Operand op) { vunpckhpd(x, x, op); }
void vunpckhps(Xmm x, Operand op) { vunpckhps(x, x, op); }
void vunpcklpd(Xmm x, Operand op) { vunpcklpd(x, x, op); }
void vunpcklps(Xmm x, Operand op) { vunpcklps(x, x, op); }
}

version(XBYAK64)
{
void jecxz(string label) { db(0x67); opJmp(label, T_SHORT, 0xe3, 0, 0); }
void jecxz(Label label) { db(0x67); opJmp(label, T_SHORT, 0xe3, 0, 0); }
void jrcxz(string label) { opJmp(label, T_SHORT, 0xe3, 0, 0); }
void jrcxz(Label label) { opJmp(label, T_SHORT, 0xe3, 0, 0); }
void cdqe() { db(0x48); db(0x98); }
void cqo() { db(0x48); db(0x99); }
void cmpsq() { db(0x48); db(0xA7); }
void popfq() { db(0x9D); }
void pushfq() { db(0x9C); }
void lodsq() { db(0x48); db(0xAD); }
void movsq() { db(0x48); db(0xA5); }
void scasq() { db(0x48); db(0xAF); }
void stosq() { db(0x48); db(0xAB); }
void syscall() { db(0x0F); db(0x05); }
void sysret() { db(0x0F); db(0x07); }
void cmpxchg16b(Address addr) { opModM(addr, new Reg64(1), 0x0F, 0xC7); }
void fxrstor64(Address addr) { opModM(addr, new Reg64(1), 0x0F, 0xAE); }
void movq(Reg64 reg, Mmx mmx) { if (mmx.isXMM()) db(0x66); opModR(mmx, reg, 0x0F, 0x7E); }
void movq(Mmx mmx, Reg64 reg) { if (mmx.isXMM()) db(0x66); opModR(mmx, reg, 0x0F, 0x6E); }
void movsxd(Reg64 reg, Operand op) { if (!op.isBit(32)) throw new XError(ERR.BAD_COMBINATION); opModRM(reg, op, op.isREG(), op.isMEM(), 0x63); }
void pextrq(Operand op, Xmm xmm, uint8 imm) { if (!op.isREG(64) && !op.isMEM()) throw new XError(ERR.BAD_COMBINATION); opGen(new Reg64(xmm.getIdx()), op, 0x16, 0x66, null, imm, 0x3A); }
void pinsrq(Xmm xmm, Operand op, uint8 imm) { if (!op.isREG(64) && !op.isMEM()) throw new XError(ERR.BAD_COMBINATION); opGen(new Reg64(xmm.getIdx()), op, 0x22, 0x66, null, imm, 0x3A); }
void vcvtss2si(Reg64 r, Operand op) { opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, T_0F | T_F3 | T_W1 | T_EVEX | T_EW1 | T_ER_X | T_N8, 0x2D); }
void vcvttss2si(Reg64 r, Operand op) { opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, T_0F | T_F3 | T_W1 | T_EVEX | T_EW1 | T_SAE_X | T_N8, 0x2C); }
void vcvtsd2si(Reg64 r, Operand op) { opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, T_0F | T_F2 | T_W1 | T_EVEX | T_EW1 | T_N4 | T_ER_X, 0x2D); }
void vcvttsd2si(Reg64 r, Operand op) { opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, T_0F | T_F2 | T_W1 | T_EVEX | T_EW1 | T_N4 | T_SAE_X, 0x2C); }
void vmovq(Xmm x, Reg64 r) { opAVX_X_X_XM(x, xm0, new Xmm(r.getIdx()), T_66 | T_0F | T_W1 | T_EVEX | T_EW1, 0x6E); }
void vmovq(Reg64 r, Xmm x) { opAVX_X_X_XM(x, xm0, new Xmm(r.getIdx()), T_66 | T_0F | T_W1 | T_EVEX | T_EW1, 0x7E); }
}
else
{
void jcxz(string label) { db(0x67); opJmp(label, T_SHORT, 0xe3, 0, 0); }
void jcxz(Label label) { db(0x67); opJmp(label, T_SHORT, 0xe3, 0, 0); }
void jecxz(string label) { opJmp(label, T_SHORT, 0xe3, 0, 0); }
void jecxz(Label label) { opJmp(label, T_SHORT, 0xe3, 0, 0); }
void aaa() { db(0x37); }
void aad() { db(0xD5); db(0x0A); }
void aam() { db(0xD4); db(0x0A); }
void aas() { db(0x3F); }
void daa() { db(0x27); }
void das() { db(0x2F); }
void into() { db(0xCE); }
void popad() { db(0x61); }
void popfd() { db(0x9D); }
void pusha() { db(0x60); }
void pushad() { db(0x60); }
void pushfd() { db(0x9C); }
void popa() { db(0x61); }
void lds(Reg reg, Address addr) { opLoadSeg(addr, reg, 0xC5, 0x100); }
void les(Reg reg, Address addr) { opLoadSeg(addr, reg, 0xC4, 0x100); }
}


version(XBYAK_DISABLE_AVX512)
{
void kaddb(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W0, 0x4A); }
void kaddd(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W1, 0x4A); }
void kaddq(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W1, 0x4A); }
void kaddw(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W0, 0x4A); }
void kandb(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W0, 0x41); }
void kandd(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W1, 0x41); }
void kandnb(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W0, 0x42); }
void kandnd(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W1, 0x42); }
void kandnq(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W1, 0x42); }
void kandnw(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W0, 0x42); }
void kandq(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W1, 0x41); }
void kandw(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W0, 0x41); }
void kmovb(Address addr, Opmask k) { opVex(k, null, addr, T_L0 | T_0F | T_66 | T_W0, 0x91); }
void kmovb(Opmask k, Operand op) { if (!op.isMEM() && !op.isOPMASK()) throw XError(ERR.BAD_COMBINATION); opVex(k, null, op, T_L0 | T_0F | T_66 | T_W0, 0x90); }
void kmovb(Opmask k, Reg32 r) { opVex(k, null, r, T_L0 | T_0F | T_66 | T_W0, 0x92); }
void kmovb(Reg32 r, Opmask k) { opVex(r, null, k, T_L0 | T_0F | T_66 | T_W0, 0x93); }
void kmovd(Address addr, Opmask k) { opVex(k, null, addr, T_L0 | T_0F | T_66 | T_W1, 0x91); }
void kmovd(Opmask k, Operand op) { if (!op.isMEM() && !op.isOPMASK()) throw XError(ERR.BAD_COMBINATION); opVex(k, null, op, T_L0 | T_0F | T_66 | T_W1, 0x90); }
void kmovd(Opmask k, Reg32 r) { opVex(k, null, r, T_L0 | T_0F | T_F2 | T_W0, 0x92); }
void kmovd(Reg32 r, Opmask k) { opVex(r, null, k, T_L0 | T_0F | T_F2 | T_W0, 0x93); }
void kmovq(Address addr, Opmask k) { opVex(k, null, addr, T_L0 | T_0F | T_W1, 0x91); }
void kmovq(Opmask k, Operand op) { if (!op.isMEM() && !op.isOPMASK()) throw XError(ERR.BAD_COMBINATION); opVex(k, null, op, T_L0 | T_0F | T_W1, 0x90); }
void kmovw(Address addr, Opmask k) { opVex(k, null, addr, T_L0 | T_0F | T_W0, 0x91); }
void kmovw(Opmask k, Operand op) { if (!op.isMEM() && !op.isOPMASK()) throw XError(ERR.BAD_COMBINATION); opVex(k, null, op, T_L0 | T_0F | T_W0, 0x90); }
void kmovw(Opmask k, Reg32 r) { opVex(k, null, r, T_L0 | T_0F | T_W0, 0x92); }
void kmovw(Reg32 r, Opmask k) { opVex(r, null, k, T_L0 | T_0F | T_W0, 0x93); }
void knotb(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_66 | T_W0, 0x44); }
void knotd(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_66 | T_W1, 0x44); }
void knotq(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_W1, 0x44); }
void knotw(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_W0, 0x44); }
void korb(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W0, 0x45); }
void kord(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W1, 0x45); }
void korq(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W1, 0x45); }
void kortestb(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_66 | T_W0, 0x98); }
void kortestd(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_66 | T_W1, 0x98); }
void kortestq(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_W1, 0x98); }
void kortestw(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_W0, 0x98); }
void korw(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W0, 0x45); }
void kshiftlb(Opmask r1, Opmask r2, uint8 imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W0, 0x32, imm); }
void kshiftld(Opmask r1, Opmask r2, uint8 imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W0, 0x33, imm); }
void kshiftlq(Opmask r1, Opmask r2, uint8 imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W1, 0x33, imm); }
void kshiftlw(Opmask r1, Opmask r2, uint8 imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W1, 0x32, imm); }
void kshiftrb(Opmask r1, Opmask r2, uint8 imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W0, 0x30, imm); }
void kshiftrd(Opmask r1, Opmask r2, uint8 imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W0, 0x31, imm); }
void kshiftrq(Opmask r1, Opmask r2, uint8 imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W1, 0x31, imm); }
void kshiftrw(Opmask r1, Opmask r2, uint8 imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W1, 0x30, imm); }
void ktestb(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_66 | T_W0, 0x99); }
void ktestd(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_66 | T_W1, 0x99); }
void ktestq(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_W1, 0x99); }
void ktestw(Opmask r1, Opmask r2) { opVex(r1, null, r2, T_0F | T_W0, 0x99); }
void kunpckbw(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W0, 0x4B); }
void kunpckdq(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W1, 0x4B); }
void kunpckwd(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W0, 0x4B); }
void kxnorb(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W0, 0x46); }
void kxnord(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W1, 0x46); }
void kxnorq(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W1, 0x46); }
void kxnorw(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W0, 0x46); }
void kxorb(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W0, 0x47); }
void kxord(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_66 | T_W1, 0x47); }
void kxorq(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W1, 0x47); }
void kxorw(Opmask r1, Opmask r2, Opmask r3) { opVex(r1, r2, r3, T_L1 | T_0F | T_W0, 0x47); }
void v4fmaddps(Zmm z1, Zmm z2, Address addr) { opAVX_X_X_XM(z1, z2, addr, T_0F38 | T_F2 | T_EW0 | T_YMM | T_MUST_EVEX | T_N16, 0x9A); }
void v4fmaddss(Xmm x1, Xmm x2, Address addr) { opAVX_X_X_XM(x1, x2, addr, T_0F38 | T_F2 | T_EW0 | T_MUST_EVEX | T_N16, 0x9B); }
void v4fnmaddps(Zmm z1, Zmm z2, Address addr) { opAVX_X_X_XM(z1, z2, addr, T_0F38 | T_F2 | T_EW0 | T_YMM | T_MUST_EVEX | T_N16, 0xAA); }
void v4fnmaddss(Xmm x1, Xmm x2, Address addr) { opAVX_X_X_XM(x1, x2, addr, T_0F38 | T_F2 | T_EW0 | T_MUST_EVEX | T_N16, 0xAB); }
void valignd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x03, imm); }
void valignq(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x03, imm); }
void vblendmpd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x65); }
void vblendmps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x65); }
void vbroadcastf32x2(Ymm y, Operand op) { opAVX_X_XM_IMM(y, op, T_66 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW0 | T_N8, 0x19); }
void vbroadcastf32x4(Ymm y, Address addr) { opAVX_X_XM_IMM(y, addr, T_66 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW0 | T_N16, 0x1A); }
void vbroadcastf32x8(Zmm y, Address addr) { opAVX_X_XM_IMM(y, addr, T_66 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW0 | T_N32, 0x1B); }
void vbroadcastf64x2(Ymm y, Address addr) { opAVX_X_XM_IMM(y, addr, T_66 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW1 | T_N16, 0x1A); }
void vbroadcastf64x4(Zmm y, Address addr) { opAVX_X_XM_IMM(y, addr, T_66 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW1 | T_N32, 0x1B); }
void vbroadcasti32x2(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW0 | T_N8, 0x59); }
void vbroadcasti32x4(Ymm y, Operand op) { opAVX_X_XM_IMM(y, op, T_66 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW0 | T_N16, 0x5A); }
void vbroadcasti32x8(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW0 | T_N32, 0x5B); }
void vbroadcasti64x2(Ymm y, Operand op) { opAVX_X_XM_IMM(y, op, T_66 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW1 | T_N16, 0x5A); }
void vbroadcasti64x4(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW1 | T_N32, 0x5B); }
void vcmppd(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_66 | T_0F | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0xC2, imm); }
void vcmpps(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_0F | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0xC2, imm); }
void vcmpsd(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_N8 | T_F2 | T_0F | T_EW1 | T_SAE_Z | T_MUST_EVEX, 0xC2, imm); }
void vcmpss(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_N4 | T_F3 | T_0F | T_EW0 | T_SAE_Z | T_MUST_EVEX, 0xC2, imm); }
void vcompressb(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N1 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x63); }
void vcompresspd(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x8A); }
void vcompressps(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x8A); }
void vcompressw(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N2 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x63); }
void vcvtne2ps2bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F2 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x72); }
void vcvtneps2bf16(Xmm x, Operand op) { opCvt2(x, op, T_F3 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x72); }
void vcvtpd2qq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F | T_EW1 | T_YMM | T_ER_Z | T_MUST_EVEX | T_B64, 0x7B); }
void vcvtpd2udq(Xmm x, Operand op) { opCvt2(x, op, T_0F | T_YMM | T_MUST_EVEX | T_EW1 | T_B64 | T_ER_Z, 0x79); }
void vcvtpd2uqq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F | T_EW1 | T_YMM | T_ER_Z | T_MUST_EVEX | T_B64, 0x79); }
void vcvtps2qq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_66 | T_0F | T_YMM | T_MUST_EVEX | T_EW0 | T_B32 | T_N8 | T_N_VL | T_ER_Y, 0x7B); }
void vcvtps2udq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_0F | T_EW0 | T_YMM | T_ER_Z | T_MUST_EVEX | T_B32, 0x79); }
void vcvtps2uqq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_66 | T_0F | T_YMM | T_MUST_EVEX | T_EW0 | T_B32 | T_N8 | T_N_VL | T_ER_Y, 0x79); }
void vcvtqq2pd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F3 | T_0F | T_EW1 | T_YMM | T_ER_Z | T_MUST_EVEX | T_B64, 0xE6); }
void vcvtqq2ps(Xmm x, Operand op) { opCvt2(x, op, T_0F | T_YMM | T_MUST_EVEX | T_EW1 | T_B64 | T_ER_Z, 0x5B); }
void vcvtsd2usi(Reg32e r, Operand op) { int type = (T_F2 | T_0F | T_MUST_EVEX | T_N8 | T_ER_X) | (r.isREG(64) ? T_EW1 : T_EW0); opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, type, 0x79); }
void vcvtss2usi(Reg32e r, Operand op) { int type = (T_F3 | T_0F | T_MUST_EVEX | T_N4 | T_ER_X) | (r.isREG(64) ? T_EW1 : T_EW0); opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, type, 0x79); }
void vcvttpd2qq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x7A); }
void vcvttpd2udq(Xmm x, Operand op) { opCvt2(x, op, T_0F | T_YMM | T_MUST_EVEX | T_EW1 | T_B64 | T_SAE_Z, 0x78); }
void vcvttpd2uqq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x78); }
void vcvttps2qq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_66 | T_0F | T_YMM | T_MUST_EVEX | T_EW0 | T_B32 | T_N8 | T_N_VL | T_SAE_Y, 0x7A); }
void vcvttps2udq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_0F | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x78); }
void vcvttps2uqq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_66 | T_0F | T_YMM | T_MUST_EVEX | T_EW0 | T_B32 | T_N8 | T_N_VL | T_SAE_Y, 0x78); }
void vcvttsd2usi(Reg32e r, Operand op) { int type = (T_F2 | T_0F | T_MUST_EVEX | T_N8 | T_SAE_X) | (r.isREG(64) ? T_EW1 : T_EW0); opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, type, 0x78); }
void vcvttss2usi(Reg32e r, Operand op) { int type = (T_F3 | T_0F | T_MUST_EVEX | T_N4 | T_SAE_X) | (r.isREG(64) ? T_EW1 : T_EW0); opAVX_X_X_XM(new Xmm(r.getIdx()), xm0, op, type, 0x78); }
void vcvtudq2pd(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_F3 | T_0F | T_YMM | T_MUST_EVEX | T_EW0 | T_B32 | T_N8 | T_N_VL, 0x7A); }
void vcvtudq2ps(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2 | T_0F | T_EW0 | T_YMM | T_ER_Z | T_MUST_EVEX | T_B32, 0x7A); }
void vcvtuqq2pd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F3 | T_0F | T_EW1 | T_YMM | T_ER_Z | T_MUST_EVEX | T_B64, 0x7A); }
void vcvtuqq2ps(Xmm x, Operand op) { opCvt2(x, op, T_F2 | T_0F | T_YMM | T_MUST_EVEX | T_EW1 | T_B64 | T_ER_Z, 0x7A); }
void vcvtusi2sd(Xmm x1, Xmm x2, Operand op) { opCvt3(x1, x2, op, T_F2 | T_0F | T_MUST_EVEX, T_W1 | T_EW1 | T_ER_X | T_N8, T_W0 | T_EW0 | T_N4, 0x7B); }
void vcvtusi2ss(Xmm x1, Xmm x2, Operand op) { opCvt3(x1, x2, op, T_F3 | T_0F | T_MUST_EVEX | T_ER_X, T_W1 | T_EW1 | T_N8, T_W0 | T_EW0 | T_N4, 0x7B); }
void vdbpsadbw(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x42, imm); }
void vdpbf16ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F3 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x52); }
void vexp2pd(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1 | T_B64 | T_SAE_Z, 0xC8); }
void vexp2ps(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0 | T_B32 | T_SAE_Z, 0xC8); }
void vexpandpd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x88); }
void vexpandps(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x88); }
void vextractf32x4(Operand op, Ymm r, uint8 imm) { if (!op.isKind(Operand.Kind.MEM | Operand.Kind.XMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r, null, op, T_N16 | T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x19, imm); }
void vextractf32x8(Operand op, Zmm r, uint8 imm) { if (!op.isKind(Operand.Kind.MEM | Operand.Kind.YMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r, null, op, T_N32 | T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x1B, imm); }
void vextractf64x2(Operand op, Ymm r, uint8 imm) { if (!op.isKind(Operand.Kind.MEM | Operand.Kind.XMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r, null, op, T_N16 | T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x19, imm); }
void vextractf64x4(Operand op, Zmm r, uint8 imm) { if (!op.isKind(Operand.Kind.MEM | Operand.Kind.YMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r, null, op, T_N32 | T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x1B, imm); }
void vextracti32x4(Operand op, Ymm r, uint8 imm) { if (!op.isKind(Operand.Kind.MEM | Operand.Kind.XMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r, null, op, T_N16 | T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x39, imm); }
void vextracti32x8(Operand op, Zmm r, uint8 imm) { if (!op.isKind(Operand.Kind.MEM | Operand.Kind.YMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r, null, op, T_N32 | T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x3B, imm); }
void vextracti64x2(Operand op, Ymm r, uint8 imm) { if (!op.isKind(Operand.Kind.MEM | Operand.Kind.XMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r, null, op, T_N16 | T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x39, imm); }
void vextracti64x4(Operand op, Zmm r, uint8 imm) { if (!op.isKind(Operand.Kind.MEM | Operand.Kind.YMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r, null, op, T_N32 | T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x3B, imm); }
void vfixupimmpd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x54, imm); }
void vfixupimmps(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x54, imm); }
void vfixupimmsd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F3A | T_EW1 | T_SAE_Z | T_MUST_EVEX, 0x55, imm); }
void vfixupimmss(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F3A | T_EW0 | T_SAE_Z | T_MUST_EVEX, 0x55, imm); }
void vfpclasspd(Opmask k, Operand op, uint8 imm) { if (!op.isBit(128|256|512)) throw new XError(ERR.BAD_MEM_SIZE); opVex(k.changeBit(op.getBit()), null, op, T_66 | T_0F3A | T_MUST_EVEX | T_YMM | T_EW1 | T_B64, 0x66, imm); }
void vfpclassps(Opmask k, Operand op, uint8 imm) { if (!op.isBit(128|256|512)) throw new XError(ERR.BAD_MEM_SIZE); opVex(k.changeBit(op.getBit()), null, op, T_66 | T_0F3A | T_MUST_EVEX | T_YMM | T_EW0 | T_B32, 0x66, imm); }
void vfpclasssd(Opmask k, Operand op, uint8 imm) { if (!op.isXMEM()) throw new XError(ERR.BAD_MEM_SIZE); opVex(k, null, op, T_66 | T_0F3A | T_MUST_EVEX | T_EW1 | T_N8, 0x67, imm); }
void vfpclassss(Opmask k, Operand op, uint8 imm) { if (!op.isXMEM()) throw new XError(ERR.BAD_MEM_SIZE); opVex(k, null, op, T_66 | T_0F3A | T_MUST_EVEX | T_EW0 | T_N4, 0x67, imm); }
void vgatherdpd(Xmm x, Address addr) { opGather2(x, addr, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_VSIB, 0x92, 1); }
void vgatherdps(Xmm x, Address addr) { opGather2(x, addr, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_VSIB, 0x92, 0); }
void vgatherpf0dpd(Address addr) { opGatherFetch(addr, zm1, T_N8 | T_66 | T_0F38 | T_EW1 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC6, Operand.Kind.YMM); }
void vgatherpf0dps(Address addr) { opGatherFetch(addr, zm1, T_N4 | T_66 | T_0F38 | T_EW0 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC6, Operand.Kind.ZMM); }
void vgatherpf0qpd(Address addr) { opGatherFetch(addr, zm1, T_N8 | T_66 | T_0F38 | T_EW1 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC7, Operand.Kind.ZMM); }
void vgatherpf0qps(Address addr) { opGatherFetch(addr, zm1, T_N4 | T_66 | T_0F38 | T_EW0 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC7, Operand.Kind.ZMM); }
void vgatherpf1dpd(Address addr) { opGatherFetch(addr, zm2, T_N8 | T_66 | T_0F38 | T_EW1 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC6, Operand.Kind.YMM); }
void vgatherpf1dps(Address addr) { opGatherFetch(addr, zm2, T_N4 | T_66 | T_0F38 | T_EW0 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC6, Operand.Kind.ZMM); }
void vgatherpf1qpd(Address addr) { opGatherFetch(addr, zm2, T_N8 | T_66 | T_0F38 | T_EW1 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC7, Operand.Kind.ZMM); }
void vgatherpf1qps(Address addr) { opGatherFetch(addr, zm2, T_N4 | T_66 | T_0F38 | T_EW0 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC7, Operand.Kind.ZMM); }
void vgatherqpd(Xmm x, Address addr) { opGather2(x, addr, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_VSIB, 0x93, 0); }
void vgatherqps(Xmm x, Address addr) { opGather2(x, addr, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_VSIB, 0x93, 2); }
void vgetexppd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x42); }
void vgetexpps(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x42); }
void vgetexpsd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_EW1 | T_SAE_X | T_MUST_EVEX, 0x43); }
void vgetexpss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_EW0 | T_SAE_X | T_MUST_EVEX, 0x43); }
void vgetmantpd(Xmm x, Operand op, uint8 imm) { opAVX_X_XM_IMM(x, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x26, imm); }
void vgetmantps(Xmm x, Operand op, uint8 imm) { opAVX_X_XM_IMM(x, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x26, imm); }
void vgetmantsd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F3A | T_EW1 | T_SAE_X | T_MUST_EVEX, 0x27, imm); }
void vgetmantss(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F3A | T_EW0 | T_SAE_X | T_MUST_EVEX, 0x27, imm); }
void vinsertf32x4(Ymm r1, Ymm r2, Operand op, uint8 imm) {if (!(r1.getKind() == r2.getKind() && op.isKind(Operand.Kind.MEM | Operand.Kind.XMM))) throw new XError(ERR.BAD_COMBINATION); opVex(r1, r2, op, T_N16 | T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x18, imm); }
void vinsertf32x8(Zmm r1, Zmm r2, Operand op, uint8 imm) {if (!op.isKind(Operand.Kind.MEM | Operand.Kind.YMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r1, r2, op, T_N32 | T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x1A, imm); }
void vinsertf64x2(Ymm r1, Ymm r2, Operand op, uint8 imm) {if (!(r1.getKind() == r2.getKind() && op.isKind(Operand.Kind.MEM | Operand.Kind.XMM))) throw new XError(ERR.BAD_COMBINATION); opVex(r1, r2, op, T_N16 | T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x18, imm); }
void vinsertf64x4(Zmm r1, Zmm r2, Operand op, uint8 imm) {if (!op.isKind(Operand.Kind.MEM | Operand.Kind.YMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r1, r2, op, T_N32 | T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x1A, imm); }
void vinserti32x4(Ymm r1, Ymm r2, Operand op, uint8 imm) {if (!(r1.getKind() == r2.getKind() && op.isKind(Operand.Kind.MEM | Operand.Kind.XMM))) throw new XError(ERR.BAD_COMBINATION); opVex(r1, r2, op, T_N16 | T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x38, imm); }
void vinserti32x8(Zmm r1, Zmm r2, Operand op, uint8 imm) {if (!op.isKind(Operand.Kind.MEM | Operand.Kind.YMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r1, r2, op, T_N32 | T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x3A, imm); }
void vinserti64x2(Ymm r1, Ymm r2, Operand op, uint8 imm) {if (!(r1.getKind() == r2.getKind() && op.isKind(Operand.Kind.MEM | Operand.Kind.XMM))) throw new XError(ERR.BAD_COMBINATION); opVex(r1, r2, op, T_N16 | T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x38, imm); }
void vinserti64x4(Zmm r1, Zmm r2, Operand op, uint8 imm) {if (!op.isKind(Operand.Kind.MEM | Operand.Kind.YMM)) throw new XError(ERR.BAD_COMBINATION); opVex(r1, r2, op, T_N32 | T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x3A, imm); }
void vmovdqa32(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_66 | T_0F | T_EW0 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX | T_M_K, 0x7F); }
void vmovdqa32(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F | T_EW0 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX, 0x6F); }
void vmovdqa64(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_66 | T_0F | T_EW1 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX | T_M_K, 0x7F); }
void vmovdqa64(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F | T_EW1 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX, 0x6F); }
void vmovdqu16(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_F2 | T_0F | T_EW1 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX | T_M_K, 0x7F); }
void vmovdqu16(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2 | T_0F | T_EW1 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX, 0x6F); }
void vmovdqu32(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_F3 | T_0F | T_EW0 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX | T_M_K, 0x7F); }
void vmovdqu32(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F3 | T_0F | T_EW0 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX, 0x6F); }
void vmovdqu64(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_F3 | T_0F | T_EW1 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX | T_M_K, 0x7F); }
void vmovdqu64(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F3 | T_0F | T_EW1 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX, 0x6F); }
void vmovdqu8(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_F2 | T_0F | T_EW0 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX | T_M_K, 0x7F); }
void vmovdqu8(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2 | T_0F | T_EW0 | T_YMM | T_ER_X | T_ER_Y | T_ER_Z | T_MUST_EVEX, 0x6F); }
void vp2intersectd(Opmask k, Xmm x, Operand op) { if (k.getOpmaskIdx() != 0) throw new XError(ERR.OPMASK_IS_ALREADY_SET); opAVX_K_X_XM(k, x, op, T_F2 | T_0F38 | T_YMM | T_EVEX | T_EW0 | T_B32, 0x68); }
void vp2intersectq(Opmask k, Xmm x, Operand op) { if (k.getOpmaskIdx() != 0) throw new XError(ERR.OPMASK_IS_ALREADY_SET); opAVX_K_X_XM(k, x, op, T_F2 | T_0F38 | T_YMM | T_EVEX | T_EW1 | T_B64, 0x68); }
void vp4dpwssd(Zmm z1, Zmm z2, Address addr) { opAVX_X_X_XM(z1, z2, addr, T_0F38 | T_F2 | T_EW0 | T_YMM | T_MUST_EVEX | T_N16, 0x52); }
void vp4dpwssds(Zmm z1, Zmm z2, Address addr) { opAVX_X_X_XM(z1, z2, addr, T_0F38 | T_F2 | T_EW0 | T_YMM | T_MUST_EVEX | T_N16, 0x53); }
void vpabsq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_MUST_EVEX | T_EW1 | T_B64 | T_YMM, 0x1F); }
void vpandd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0xDB); }
void vpandnd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0xDF); }
void vpandnq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0xDF); }
void vpandq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0xDB); }
void vpblendmb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x66); }
void vpblendmd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x64); }
void vpblendmq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x64); }
void vpblendmw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x66); }
void vpbroadcastb(Xmm x, Reg8 r) { opVex(x, null, r, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x7A); }
void vpbroadcastd(Xmm x, Reg32 r) { opVex(x, null, r, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x7C); }
void vpbroadcastmb2q(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW1, 0x2A); }
void vpbroadcastmw2d(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW0, 0x3A); }
void vpbroadcastw(Xmm x, Reg16 r) { opVex(x, null, r, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x7B); }
void vpcmpb(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x3F, imm); }
void vpcmpd(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x1F, imm); }
void vpcmpeqb(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F | T_YMM | T_MUST_EVEX, 0x74); }
void vpcmpeqd(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F | T_YMM | T_MUST_EVEX | T_B32, 0x76); }
void vpcmpeqq(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x29); }
void vpcmpeqw(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F | T_YMM | T_MUST_EVEX, 0x75); }
void vpcmpgtb(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F | T_YMM | T_MUST_EVEX, 0x64); }
void vpcmpgtd(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x66); }
void vpcmpgtq(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x37); }
void vpcmpgtw(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F | T_YMM | T_MUST_EVEX, 0x65); }
void vpcmpq(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x1F, imm); }
void vpcmpub(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX, 0x3E, imm); }
void vpcmpud(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x1E, imm); }
void vpcmpuq(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x1E, imm); }
void vpcmpuw(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x3E, imm); }
void vpcmpw(Opmask k, Xmm x, Operand op, uint8 imm) { opAVX_K_X_XM(k, x, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX, 0x3F, imm); }
void vpcompressd(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x8B); }
void vpcompressq(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x8B); }
void vpconflictd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0xC4); }
void vpconflictq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0xC4); }
void vpdpbusd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x50); }
void vpdpbusds(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x51); }
void vpdpwssd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x52); }
void vpdpwssds(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x53); }
void vpermb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x8D); }
void vpermi2b(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x75); }
void vpermi2d(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x76); }
void vpermi2pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x77); }
void vpermi2ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x77); }
void vpermi2q(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x76); }
void vpermi2w(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x75); }
void vpermt2b(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x7D); }
void vpermt2d(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x7E); }
void vpermt2pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x7F); }
void vpermt2ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x7F); }
void vpermt2q(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x7E); }
void vpermt2w(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x7D); }
void vpermw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x8D); }
void vpexpandb(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N1 | T_66 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX, 0x62); }
void vpexpandd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x89); }
void vpexpandq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x89); }
void vpexpandw(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N2 | T_66 | T_0F38 | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX, 0x62); }
void vpgatherdd(Xmm x, Address addr) { opGather2(x, addr, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_VSIB, 0x90, 0); }
void vpgatherdq(Xmm x, Address addr) { opGather2(x, addr, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_VSIB, 0x90, 1); }
void vpgatherqd(Xmm x, Address addr) { opGather2(x, addr, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_VSIB, 0x91, 2); }
void vpgatherqq(Xmm x, Address addr) { opGather2(x, addr, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_VSIB, 0x91, 0); }
void vplzcntd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x44); }
void vplzcntq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x44); }
void vpmadd52huq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0xB5); }
void vpmadd52luq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0xB4); }
void vpmaxsq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x3D); }
void vpmaxuq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x3F); }
void vpminsq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x39); }
void vpminuq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x3B); }
void vpmovb2m(Opmask k, Xmm x) { opVex(k, null, x, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0, 0x29); }
void vpmovd2m(Opmask k, Xmm x) { opVex(k, null, x, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0, 0x39); }
void vpmovdb(Operand op, Xmm x) { opVmov(op, x, T_N4 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x31, false); }
void vpmovdw(Operand op, Xmm x) { opVmov(op, x, T_N8 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x33, true); }
void vpmovm2b(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0, 0x28); }
void vpmovm2d(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0, 0x38); }
void vpmovm2q(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1, 0x38); }
void vpmovm2w(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1, 0x28); }
void vpmovq2m(Opmask k, Xmm x) { opVex(k, null, x, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1, 0x39); }
void vpmovqb(Operand op, Xmm x) { opVmov(op, x, T_N2 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x32, false); }
void vpmovqd(Operand op, Xmm x) { opVmov(op, x, T_N8 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x35, true); }
void vpmovqw(Operand op, Xmm x) { opVmov(op, x, T_N4 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x34, false); }
void vpmovsdb(Operand op, Xmm x) { opVmov(op, x, T_N4 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x21, false); }
void vpmovsdw(Operand op, Xmm x) { opVmov(op, x, T_N8 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x23, true); }
void vpmovsqb(Operand op, Xmm x) { opVmov(op, x, T_N2 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x22, false); }
void vpmovsqd(Operand op, Xmm x) { opVmov(op, x, T_N8 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x25, true); }
void vpmovsqw(Operand op, Xmm x) { opVmov(op, x, T_N4 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x24, false); }
void vpmovswb(Operand op, Xmm x) { opVmov(op, x, T_N8 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x20, true); }
void vpmovusdb(Operand op, Xmm x) { opVmov(op, x, T_N4 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x11, false); }
void vpmovusdw(Operand op, Xmm x) { opVmov(op, x, T_N8 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x13, true); }
void vpmovusqb(Operand op, Xmm x) { opVmov(op, x, T_N2 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x12, false); }
void vpmovusqd(Operand op, Xmm x) { opVmov(op, x, T_N8 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x15, true); }
void vpmovusqw(Operand op, Xmm x) { opVmov(op, x, T_N4 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x14, false); }
void vpmovuswb(Operand op, Xmm x) { opVmov(op, x, T_N8 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x10, true); }
void vpmovw2m(Opmask k, Xmm x) { opVex(k, null, x, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1, 0x29); }
void vpmovwb(Operand op, Xmm x) { opVmov(op, x, T_N8 | T_N_VL | T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x30, true); }
void vpmullq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x40); }
void vpmultishiftqb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x83); }
void vpopcntb(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX, 0x54); }
void vpopcntd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x55); }
void vpopcntq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x55); }
void vpopcntw(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX, 0x54); }
void vpord(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0xEB); }
void vporq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0xEB); }
void vprold(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 1), x, op, T_66 | T_0F | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x72, imm); }
void vprolq(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 1), x, op, T_66 | T_0F | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x72, imm); }
void vprolvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x15); }
void vprolvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x15); }
void vprord(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 0), x, op, T_66 | T_0F | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x72, imm); }
void vprorq(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 0), x, op, T_66 | T_0F | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x72, imm); }
void vprorvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x14); }
void vprorvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x14); }
void vpscatterdd(Address addr, Xmm x) { opGather2(x, addr, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_M_K | T_VSIB, 0xA0, 0); }
void vpscatterdq(Address addr, Xmm x) { opGather2(x, addr, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_M_K | T_VSIB, 0xA0, 1); }
void vpscatterqd(Address addr, Xmm x) { opGather2(x, addr, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_M_K | T_VSIB, 0xA1, 2); }
void vpscatterqq(Address addr, Xmm x) { opGather2(x, addr, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_M_K | T_VSIB, 0xA1, 0); }
void vpshldd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x71, imm); }
void vpshldq(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x71, imm); }
void vpshldvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x71); }
void vpshldvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x71); }
void vpshldvw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX, 0x70); }
void vpshldw(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX, 0x70, imm); }
void vpshrdd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x73, imm); }
void vpshrdq(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x73, imm); }
void vpshrdvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x73); }
void vpshrdvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x73); }
void vpshrdvw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX, 0x72); }
void vpshrdw(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX, 0x72, imm); }
void vpshufbitqmb(Opmask k, Xmm x, Operand op) { opVex(k, x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x8F); }
void vpsllvw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x12); }
void vpsraq(Xmm x, Operand op, uint8 imm) { opAVX_X_X_XM(new Xmm(x.getKind(), 4), x, op, T_66 | T_0F | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x72, imm); }
void vpsraq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16 | T_66 | T_0F | T_EW1 | T_YMM | T_MUST_EVEX, 0xE2); }
void vpsravq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x46); }
void vpsravw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x11); }
void vpsrlvw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x10); }
void vpternlogd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x25, imm); }
void vpternlogq(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x25, imm); }
void vptestmb(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x26); }
void vptestmd(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x27); }
void vptestmq(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x27); }
void vptestmw(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x26); }
void vptestnmb(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x26); }
void vptestnmd(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_F3 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x27); }
void vptestnmq(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_F3 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x27); }
void vptestnmw(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_F3 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x26); }
void vpxord(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0xEF); }
void vpxorq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0xEF); }
void vrangepd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x50, imm); }
void vrangeps(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x50, imm); }
void vrangesd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F3A | T_EW1 | T_SAE_X | T_MUST_EVEX, 0x51, imm); }
void vrangess(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F3A | T_EW0 | T_SAE_X | T_MUST_EVEX, 0x51, imm); }
void vrcp14pd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x4C); }
void vrcp14ps(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x4C); }
void vrcp14sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_EW1 | T_MUST_EVEX, 0x4D); }
void vrcp14ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_EW0 | T_MUST_EVEX, 0x4D); }
void vrcp28pd(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1 | T_B64 | T_SAE_Z, 0xCA); }
void vrcp28ps(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0 | T_B32 | T_SAE_Z, 0xCA); }
void vrcp28sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_EW1 | T_SAE_X | T_MUST_EVEX, 0xCB); }
void vrcp28ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_EW0 | T_SAE_X | T_MUST_EVEX, 0xCB); }
void vreducepd(Xmm x, Operand op, uint8 imm) { opAVX_X_XM_IMM(x, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B64, 0x56, imm); }
void vreduceps(Xmm x, Operand op, uint8 imm) { opAVX_X_XM_IMM(x, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_SAE_Z | T_MUST_EVEX | T_B32, 0x56, imm); }
void vreducesd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F3A | T_EW1 | T_SAE_X | T_MUST_EVEX, 0x57, imm); }
void vreducess(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F3A | T_EW0 | T_SAE_X | T_MUST_EVEX, 0x57, imm); }
void vrndscalepd(Xmm x, Operand op, uint8 imm) { opAVX_X_XM_IMM(x, op, T_66 | T_0F3A | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x09, imm); }
void vrndscaleps(Xmm x, Operand op, uint8 imm) { opAVX_X_XM_IMM(x, op, T_66 | T_0F3A | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x08, imm); }
void vrndscalesd(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F3A | T_EW1 | T_MUST_EVEX, 0x0B, imm); }
void vrndscaless(Xmm x1, Xmm x2, Operand op, uint8 imm) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F3A | T_EW0 | T_MUST_EVEX, 0x0A, imm); }
void vrsqrt14pd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_B64, 0x4E); }
void vrsqrt14ps(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_B32, 0x4E); }
void vrsqrt14sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x4F); }
void vrsqrt14ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x4F); }
void vrsqrt28pd(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1 | T_B64 | T_SAE_Z, 0xCC); }
void vrsqrt28ps(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0 | T_B32 | T_SAE_Z, 0xCC); }
void vrsqrt28sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_EW1 | T_SAE_X | T_MUST_EVEX, 0xCD); }
void vrsqrt28ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_EW0 | T_SAE_X | T_MUST_EVEX, 0xCD); }
void vscalefpd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW1 | T_YMM | T_ER_Z | T_MUST_EVEX | T_B64, 0x2C); }
void vscalefps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_ER_Z | T_MUST_EVEX | T_B32, 0x2C); }
void vscalefsd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8 | T_66 | T_0F38 | T_EW1 | T_ER_X | T_MUST_EVEX, 0x2D); }
void vscalefss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4 | T_66 | T_0F38 | T_EW0 | T_ER_X | T_MUST_EVEX, 0x2D); }
void vscatterdpd(Address addr, Xmm x) { opGather2(x, addr, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_M_K | T_VSIB, 0xA2, 1); }
void vscatterdps(Address addr, Xmm x) { opGather2(x, addr, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_M_K | T_VSIB, 0xA2, 0); }
void vscatterpf0dpd(Address addr) { opGatherFetch(addr, zm5, T_N8 | T_66 | T_0F38 | T_EW1 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC6, Operand.Kind.YMM); }
void vscatterpf0dps(Address addr) { opGatherFetch(addr, zm5, T_N4 | T_66 | T_0F38 | T_EW0 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC6, Operand.Kind.ZMM); }
void vscatterpf0qpd(Address addr) { opGatherFetch(addr, zm5, T_N8 | T_66 | T_0F38 | T_EW1 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC7, Operand.Kind.ZMM); }
void vscatterpf0qps(Address addr) { opGatherFetch(addr, zm5, T_N4 | T_66 | T_0F38 | T_EW0 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC7, Operand.Kind.ZMM); }
void vscatterpf1dpd(Address addr) { opGatherFetch(addr, zm6, T_N8 | T_66 | T_0F38 | T_EW1 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC6, Operand.Kind.YMM); }
void vscatterpf1dps(Address addr) { opGatherFetch(addr, zm6, T_N4 | T_66 | T_0F38 | T_EW0 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC6, Operand.Kind.ZMM); }
void vscatterpf1qpd(Address addr) { opGatherFetch(addr, zm6, T_N8 | T_66 | T_0F38 | T_EW1 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC7, Operand.Kind.ZMM); }
void vscatterpf1qps(Address addr) { opGatherFetch(addr, zm6, T_N4 | T_66 | T_0F38 | T_EW0 | T_MUST_EVEX | T_M_K | T_VSIB, 0xC7, Operand.Kind.ZMM); }
void vscatterqpd(Address addr, Xmm x) { opGather2(x, addr, T_N8 | T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX | T_M_K | T_VSIB, 0xA3, 0); }
void vscatterqps(Address addr, Xmm x) { opGather2(x, addr, T_N4 | T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX | T_M_K | T_VSIB, 0xA3, 2); }
void vshuff32x4(Ymm y1, Ymm y2, Operand op, uint8 imm) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F3A | T_YMM | T_MUST_EVEX | T_EW0 | T_B32, 0x23, imm); }
void vshuff64x2(Ymm y1, Ymm y2, Operand op, uint8 imm) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F3A | T_YMM | T_MUST_EVEX | T_EW1 | T_B64, 0x23, imm); }
void vshufi32x4(Ymm y1, Ymm y2, Operand op, uint8 imm) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F3A | T_YMM | T_MUST_EVEX | T_EW0 | T_B32, 0x43, imm); }
void vshufi64x2(Ymm y1, Ymm y2, Operand op, uint8 imm) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F3A | T_YMM | T_MUST_EVEX | T_EW1 | T_B64, 0x43, imm); }
version(XBYAK64)
{
void kmovq(Opmask k, Reg64 r) { opVex(k, null, r, T_L0 | T_0F | T_F2 | T_W1, 0x92); }
void kmovq(Reg64 r, Opmask k) { opVex(r, null, k, T_L0 | T_0F | T_F2 | T_W1, 0x93); }
void vpbroadcastq(Xmm x, Reg64 r) { opVex(x, null, r, T_66 | T_0F38 | T_EW1 | T_YMM | T_MUST_EVEX, 0x7C); }
}
}



}

// CodeGenerator
alias T_SHORT = LabelType.T_SHORT;
alias T_NEAR  = LabelType.T_NEAR;
alias T_AUTO  = LabelType.T_AUTO;

string def_alias(string[] names)
{
 string result;
  foreach(name; names){
	  result ~="alias "~name~" = CodeGenerator."~name~";\n"; 
	}
 return result;
}

mixin(["mm0","mm1","mm2","mm3","mm4","mm5","mm6","mm7"].def_alias);
mixin(["xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7"].def_alias);
mixin(["ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7"].def_alias);

mixin(["eax","ecx","edx","ebx","esp","ebp","esi","edi"].def_alias);
mixin(["ax","cx","dx","bx","sp","bp","si","di"].def_alias);
mixin(["al","cl","dl","bl","ah","ch","dh","bh"].def_alias);
mixin(["ptr","byte_","word","dword","qword"].def_alias);

mixin(["st0","st1","st2","st3","st4","st5","st6","st7"].def_alias);

version (XBYAK64)
{
    mixin(["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"].def_alias);
    mixin(["r8","r9","r10","r11","r12","r13","r14","r15"].def_alias);
    mixin(["r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"].def_alias);
    mixin(["r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"].def_alias);
    mixin(["r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"].def_alias);
    
    mixin(["spl","bpl","sil","dil"].def_alias);
    mixin(["xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"].def_alias);
    mixin(["ymm8","ymm9","ymm10","ymm11","ymm12","ymm13","ymm14","ymm15"].def_alias);
    mixin(["rip"].def_alias);
}

version(XBYAK_DISABLE_SEGMENT){}
else
{
	alias es = Segment.es;
    alias cs = Segment.cs;
    alias ss = Segment.ss;
    alias ds = Segment.ds;
    alias fs = Segment.fs;
    alias gs = Segment.gs;
}

