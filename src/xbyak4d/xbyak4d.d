/**
 * xbyak for the D programming language
 * Version: 0.051
 * Date: 2015/05/05
 * See_Also:
 * URL: <a href="http://code.google.com/p/xbyak4d/index.html">xbyak4d</a>.
 * Copyright: Copyright deepprog 2012-.
 * License: <http://opensource.org/licenses/BSD-3-Clause>BSD-3-Clause</a>.
 * Authors: deepprog
 */

module xbyak4d;
/*
   version = XBYAK64;
   /*/
version = XBYAK32;
//*/
import std.stdio;
import std.array;
import std.string    : format;
import std.algorithm : swap, max, min;
import std.conv;

version(Windows)
{
    import core.sys.windows.windows;      // VirtualProtect
}

version(linux)
{
    import core.sys.posix.sys.mman;
    import std.c.linux.linux;
}

enum : uint
{
    DEFAULT_MAX_CODE_SIZE = 4096,
    VERSION               = 0x0051, // 0xABCD = A.BC(D)
}

alias ulong  uint64;
alias long   int64;
alias uint   uint32;
alias ushort uint16;
alias ubyte  uint8;
alias int    size_t;

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
    OVER_LOCAL_LABEL,
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
    INTERNAL
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
            stderr.writefln("bad err=%d in Xbyak::Error", err_);
            import core.stdc.stdlib;
            _Exit(1);
        }
        super(this.what(), file, line, next);
    }
    int opCast(int)
    {
        return err_;
    }

    string what()
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
            "internal error"
        ];

        return errTbl[err_];
    }
};

string ConvertErrorToString(XError err)
{
    return err.what();
}


struct Aligned
{
    static :
private:
    void*[void*] MemTbl;
    size_t[void*] SizeTbl;

public:
    void* getAlignedAddress(void* addr, size_t alignedSize = 16)
    {
        size_t mask = alignedSize - 1;
        return cast(void*) ((cast(size_t) addr + mask) & ~mask);
    }

    void* Malloc(size_t size, size_t alignment = inner.ALIGN_PAGE_SIZE)
    {
        void* p;
        version(Windows)
        {
            void* mp = core.memory.GC.malloc(size + alignment);
        }
        version(linux)
        {
            const size_t alignedSizeM1 = inner.ALIGN_PAGE_SIZE - 1;

            size = (size + alignedSizeM1) & ~alignedSizeM1;
            int    prot     = PROT_EXEC | PROT_READ | PROT_WRITE;
            int    mode     = MAP_PRIVATE | MAP_ANONYMOUS;
            int    fd       = open("/dev/zero", O_RDONLY);
            size_t pageSize = sysconf(_SC_PAGESIZE);

            void   * mp = mmap(null, size, prot, mode, fd, pageSize);

            if (mp == MAP_FAILED)
            {
                throw new XError(ERR.CANT_ALLOC);
            }
        }
        assert(mp);
        SizeTbl[mp] = size + alignment;
        MemTbl[mp]  = getAlignedAddress(mp, alignment);
        return MemTbl[mp];
    }

    void Free(void* p)
    {
        version(Windows)
        {
            //core.memory.GC.free(MemTbl[p]);
            MemTbl.remove(p);
        }
        version(linux)
        {
            if (p == 0)
            {
                return;
            }

            void   * ret = MemTbl[p];
            size_t size  = SizeTbl[p];

            if (munmap(ret, size) < 0)
            {
                throw new XError(ERR.MUNMAP);
            }
            MemTbl.remove(p);
            SizeTbl.remove(p);
        }
    }
}

To CastTo(To, From)(From p)
{
    return cast(To) (p);
}

struct inner
{
    static :
    const size_t ALIGN_PAGE_SIZE = 4096;
    bool IsInDisp8(uint32 x)
    {
        return 0xFFFFFF80 <= x || x <= 0x7F;
    }
    bool IsInDisp16(uint32 x)
    {
        return 0xFFFF8000 <= x || x <= 0x7FFF;
    }
    bool IsInDisp32(uint64 x)
    {
        return 0xFFFFFFFF80000000UL <= x || x <= 0x7FFFFFFFU;
    }
    uint32 VerifyInInt32(uint64 x)
    {
        version(XBYAK64)
        {
            if (!IsInDisp32(x))
                throw new XError(ERR.OFFSET_IS_TOO_BIG);
        }
        return cast(uint32) x;
    }

    enum LabelMode
    {
        LasIs,  // as is
        Labs,   // absolute
        LaddTop // (addr + top) for mov(reg, label) with AutoGrow
    }
}
// inner

// custom allocator
struct Allocator
{
    uint8* alloc(size_t size)
    {
        return cast(uint8*) (Aligned.Malloc(size, inner.ALIGN_PAGE_SIZE));
    }
    void free(uint8* p)
    {
        Aligned.Free(p);
    }

    // override to return false if you call protect() manually
    bool useProtect()
    {
        return true;
    }
};

// Operand
enum Kind
{
    NONE = 0,
    MEM  = 1 << 1,
    IMM  = 1 << 2,
    REG  = 1 << 3,
    MMX  = 1 << 4,
    XMM  = 1 << 5,
    FPU  = 1 << 6,
    YMM  = 1 << 7
}

version(XBYAK64)
{
    enum Code
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

version(XBYAK32)
{
    enum Code
    {
        EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
        AX  = 0, CX, DX, BX, SP, BP, SI, DI,
        AL  = 0, CL, DL, BL, AH, CH, DH, BH
    }
}

// Operand
Operand OP(int idx = 0, Kind kind = Kind.NONE, int bit = 0, int ext8bit = 0)
{
    return new Operand(idx, kind, bit, ext8bit);
}
public class Operand {
private:
    uint8  idx_;    // 0..15, MSB = 1 if spl/bpl/sil/dil
    uint8  kind_;
    uint16 bit_;
public:
    this()
    {
        idx_ = 0; kind_ = 0; bit_ = 0;
    }
    this(int idx, Kind kind, int bit, int ext8bit = 0)
    {
        idx_  = cast(uint8) (idx | (ext8bit ? 0x80 : 0));
        kind_ = cast(uint8) kind;
        bit_  = cast(uint16) bit;
        assert((bit_ & (bit_ - 1)) == 0);         // bit must be power of two
    }
    Kind getKind()
    {
        return cast(Kind) kind_;
    }
    int getIdx()
    {
        return cast(int) idx_ & 15;
    }
    bool isNone()
    {
        return(kind_ == 0);
    }
    bool isMMX()
    {
        return isKind(Kind.MMX);
    }
    bool isXMM()
    {
        return isKind(Kind.XMM);
    }
    bool isYMM()
    {
        return isKind(Kind.YMM);
    }
    bool isREG(int bit = 0)
    {
        return isKind(Kind.REG, bit);
    }
    bool isMEM(int bit = 0)
    {
        return isKind(Kind.MEM, bit);
    }
    bool isFPU()
    {
        return isKind(Kind.FPU);
    }
    bool isExt8bit()
    {
        return (idx_ & 0x80) != 0;
    }

// ah, ch, dh, bh?
    bool isHigh8bit()
    {
        if (!isBit(8))
        {
            return false;
        }

        if (isExt8bit())
        {
            return false;
        }

        const int idx = getIdx();
        return Code.AH <= idx && idx <= Code.BH;
    }

// any bit is accetable if bit == 0
    bool isKind(int kind, uint32 bit = 0)
    {
        return (kind_ & kind) && (bit == 0 || (bit_ & bit));         // cf. you can set (8|16)
    }
    bool isBit(uint32 bit)
    {
        return (bit_ & bit) != 0;
    }
    uint32 getBit()
    {
        return bit_;
    }

    override string toString()
    {
        int idx = getIdx;
        if (kind_ == Kind.REG)
        {
            if (isExt8bit)
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
        else if (isYMM)
        {
            string[] tbl = [ "ym0", "ym1", "ym2", "ym3", "ym4", "ym5", "ym6", "ym7", "ym8", "ym9", "ym10", "ym11", "ym12", "ym13", "ym14", "ym15" ];
            return tbl[idx];
        }
        else if (isXMM)
        {
            string[] tbl = [ "xm0", "xm1", "xm2", "xm3", "xm4", "xm5", "xm6", "xm7", "xm8", "xm9", "xm10", "xm11", "xm12", "xm13", "xm14", "xm15" ];
            return tbl[idx];
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
        throw new XError(ERR.INTERNAL);
    }
    override bool opEquals(Object o)
    {
        Operand rhs = cast(Operand) o;
        return idx_ == rhs.idx_ && kind_ == rhs.kind_ && bit_ == rhs.bit_;
    }
};

Reg REG(int idx = 0, Kind kind = Kind.NONE, int bit = 0, int ext8bit = 0)
{
    return new Reg(idx, kind, bit, ext8bit);
}
public class Reg : Operand {
private:
    bool hasRex()
    {
        return isExt8bit | isREG(64) | isExtIdx;
    }
public:
    this()
    {
    }
    this(int idx, Kind kind, int bit = 0, int ext8bit = 0)
    {
        super(idx, kind, bit, ext8bit);
    }
    Reg changeBit(int bit)
    {
        return REG(getIdx, getKind, bit, isExt8bit);
    }
    bool isExtIdx()
    {
        return getIdx > 7;
    }
    uint8 getRex(Reg base = REG)
    {
        return cast(uint8) ((hasRex || base.hasRex) ? (0x40 | ((isREG(64) | base.isREG(64)) ? 8 : 0) | (isExtIdx ? 4 : 0) | (base.isExtIdx ? 1 : 0)) : 0);
    }
    Reg8 cvt8()
    {
        int idx = getIdx;
        if (isBit(8))
            return REG8(idx, isExt8bit);
        version(XBYAK32)
        {
            if (idx >= 4)
                throw new XError(ERR.CANT_CONVERT);
        }
        return REG8(idx, 4 <= idx && idx < 8);
    }

    Reg16 cvt16()
    {
        int idx = getIdx;
        if (isBit(8) && (4 <= idx && idx < 8) && !isExt8bit)
            throw new XError(ERR.CANT_CONVERT);
        return REG16(idx);
    }

    Reg32 cvt32()
    {
        int idx = getIdx;
        if (isBit(8) && (4 <= idx && idx < 8) && !isExt8bit)
            throw new XError(ERR.CANT_CONVERT);
        return REG32(idx);
    }

    version(XBYAK64)
    {
        Reg64 cvt64()
        {
            int idx = getIdx;
            if (isBit(8) && (4 <= idx && idx < 8) && !isExt8bit)
                throw new XError(ERR.CANT_CONVERT);
            return REG64(idx);
        }
    }
};

Reg8 REG8(int idx = 0, int ext8bit = 0)
{
    return new Reg8(idx, ext8bit);
}

public class Reg8 : Reg {
public:
    this(int idx, int ext8bit)
    {
        super(idx, Kind.REG, 8, ext8bit);
    }
};

Reg16 REG16(int idx)
{
    return new Reg16(idx);
}
public class Reg16 : Reg {
public:
    this(int idx)
    {
        super(idx, Kind.REG, 16);
    }
};

Mmx MMX(int idx, Kind kind = Kind.MMX, int bit = 64)
{
    return new Mmx(idx, kind, bit);
}
public class Mmx : Reg {
public:
    this(int idx, Kind kind = Kind.MMX, int bit = 64)
    {
        super(idx, kind, bit);
    }
};

Xmm XMM(int idx, Kind kind = Kind.MMX, int bit = 128)
{
    return new Xmm(idx, kind, bit);
}
public class Xmm : Mmx {
public:
    this(int idx, Kind kind = Kind.XMM, int bit = 128)
    {
        super(idx, kind, bit);
    }
};

Ymm YMM(int idx)
{
    return new Ymm(idx);
}
public class Ymm : Xmm {
public:
    this(int idx)
    {
        super(idx, Kind.YMM, 256);
    }
};

Fpu FPU(int idx)
{
    return new Fpu(idx);
}
public class Fpu : Reg {
public:
    this(int idx)
    {
        super(idx, Kind.FPU, 32);
    }
};

Reg32e REG32E(int idx, int bit)
{
    return new Reg32e(idx, bit);
}
public class Reg32e : Reg {
    this(int idx, int bit)
    {
        super(idx, Kind.REG, bit);
    }
}

Reg32 REG32(int idx)
{
    return new Reg32(idx);
}
public class Reg32 : Reg32e {
    this(int idx)
    {
        super(idx, 32);
    }
};

version(XBYAK64)
{
    Reg64 REG64(int idx)
    {
        return new Reg64(idx);
    }
    public class Reg64 : Reg32e {
        this(int idx)
        {
            super(idx, 64);
        }
    };

    struct RegRip
    {
        uint32 disp_;
        this(uint disp = 0)
        {
            disp_ = disp;
        }
        RegRip opBinary(string op) (uint disp) if (op == "+")
        {
            return RegRip(disp_ + disp);
        }
        RegRip opBinary(string op) (uint disp) if (op == "-")
        {
            return RegRip(disp_ - disp);
        }
    };
}

class RegExp {
public:
    struct SReg
    {
        uint16 bit = 9;         // 32/64/128/256 none if 0
        uint16 idx = 7;
        void   set(Reg r)
        {
            this.bit = cast(uint16) (r.getBit);
            this.idx = cast(uint16) (r.getIdx);
        }
        int opEquals(ref const SReg rhs)
        {
            return bit == rhs.bit && idx == rhs.idx;
        }
    };
    this(size_t disp = 0)
    {
        disp_  = disp;
        scale_ = 0;
    }
    this(Reg r, int scale = 1)
    {
        disp_  = 0;
        scale_ = scale;
        if (!r.isKind(Kind.REG, 32 | 64) && !r.isKind(Kind.XMM | Kind.YMM))
        {
            throw new XError(ERR.BAD_SIZE_OF_REGISTER);
        }
        if (scale != 1 && scale != 2 && scale != 4 && scale != 8)
        {
            throw new XError(ERR.BAD_SCALE);
        }
        if (r.getBit >= 128 || scale != 1)               // xmm/ymm is always index
        {
            index_.set(r);
        }
        else
        {
            base_.set(r);
        }
    }
    bool isVsib()
    {
        return index_.bit >= 128;
    }
    bool isYMM()
    {
        return index_.bit >= 256;
    }
    RegExp optimize()     // select smaller size
    {
        // [reg * 2] => [reg + reg]
        if (!isVsib && !base_.bit && index_.bit && scale_ == 2)
        {
            RegExp ret = this;
            ret.base_  = index_;
            ret.scale_ = 1;
            return ret;
        }
        return this;
    }
    override bool opEquals(Object o)
    {
        RegExp rhs = cast(RegExp) (o);
        return base_ == rhs.base_ && index_ == rhs.index_ && disp_ == rhs.disp_;
    }
    SReg getBase()
    {
        return base_;
    }
    SReg getIndex()
    {
        return index_;
    }
    int getScale()
    {
        return scale_;
    }
    uint32 getDisp()
    {
        return cast(uint32) disp_;
    }
    void verify()
    {
        if (base_.bit >= 128)
        {
            throw new XError(ERR.BAD_SIZE_OF_REGISTER);
        }
        if (index_.bit && index_.bit <= 64)
        {
            if (index_.idx == Code.ESP)
            {
                throw new XError(ERR.ESP_CANT_BE_INDEX);
            }
            if (base_.bit && base_.bit != index_.bit)
            {
                throw new XError(ERR.BAD_SIZE_OF_REGISTER);
            }
        }
    }
private:
//	[base_ + index_ * scale_ + disp_]
//	base : Reg32e, index : Reg32e(w/o esp), Xmm, Ymm
    RegExp opBinary(string op) (RegExp b) if (op == "+")
    {
        if (index_.bit && b.index_.bit)
        {
            throw new XError(ERR.BAD_ADDRESSING);
        }
        if (!this.index_.bit)
        {
            this.index_ = b.index_; this.scale_ = b.scale_;
        }
        if (b.base_.bit)
        {
            if (this.base_.bit)
            {
                if (this.index_.bit)
                    throw new XError(ERR.BAD_ADDRESSING);
                // base + base => base + index * 1
                this.index_ = b.base_;
                // [reg + esp] => [esp + reg]
                if (this.index_.idx == Code.ESP)
                {
                    swap(this.base_, this.index_);
                }
                this.scale_ = 1;
            }
            else
            {
                this.base_ = b.base_;
            }
        }
        this.disp_ += b.disp_;
        return ret;
    }
    RegExp opBinary(string op) (int scale) if (op == "*")
    {
        return new RegExp(r, scale);
    }
    RegExp opBinary(string op) (uint disp) if (op == "-")
    {
        RegExp ret = this;
        ret.disp_ -= disp;
        return ret;
    }
    size_t disp_;
    int    scale_;
    SReg   base_;
    SReg   index_;
};

// 1nd parameter for constructor of CodeArray(userPtr, maxSize, alloc)
enum AutoGrow = cast(void*) (1);

class CodeArray {
    enum Type
    {
        USER_BUF = 1,     // use userPtr(non alignment, non protect)
        ALLOC_BUF,        // use new(alignment, protect)
        AUTO_GROW         // automatically move and grow memory if necessary
    }
    bool isAllocType()
    {
        return type_ == Type.ALLOC_BUF || type_ == Type.AUTO_GROW;
    }
    struct AddrInfo
    {
        size_t          codeOffset; // position to write
        size_t          jmpAddr;    // value to write
        int             jmpSize;    // size of jmpAddr
        inner.LabelMode mode;
        this(size_t _codeOffset, size_t _jmpAddr, int _jmpSize, inner.LabelMode _mode)
        {
            codeOffset = _codeOffset;
            jmpAddr    = _jmpAddr;
            jmpSize    = _jmpSize;
            mode       = _mode;
        }
        uint64 getVal(uint8* top)
        {
            uint64 disp = (mode == inner.LabelMode.LaddTop) ? jmpAddr + cast(size_t) top : (mode == inner.LabelMode.LasIs) ? jmpAddr : jmpAddr - cast(size_t) top;
            if (jmpSize == 4)
            {
                disp = inner.VerifyInInt32(disp);
            }
            return disp;
        }
    }

    alias        AddrInfo[] AddrInfoList;
    AddrInfoList addrInfoList_;
    Type         type_;
    Allocator    defaultAllocator_;
    Allocator    * alloc_;
protected:
    size_t       maxSize_;
    uint8        * top_;
    size_t       size_;


//	allocate new memory and copy old data to the new area
    void growMemory()
    {
        size_t newSize  = max(DEFAULT_MAX_CODE_SIZE, maxSize_ * 2);
        uint8  * newTop = alloc_.alloc(newSize);
        if (null == newTop)
        {
            throw new XError(ERR.CANT_ALLOC);
        }

        foreach(i; 0..size_)
        {
            newTop[i] = top_[i];
        }

        alloc_.free(top_);
        top_     = newTop;
        maxSize_ = newSize;
    }

//	calc jmp address for AutoGrow mode
    void calcJmpAddress()
    {
        foreach(i; addrInfoList_)
        {
            uint64 disp = i.getVal(top_);
            rewrite(i.codeOffset, disp, i.jmpSize);
        }
        if (alloc_.useProtect && !protect(top_, size_, true))
        {
            throw new XError(ERR.CANT_PROTECT);
        }
    }

public:
    this(void* userPtr = null, size_t maxSize = DEFAULT_MAX_CODE_SIZE, Allocator * allocator = null)
    {
        type_    = userPtr == AutoGrow ? Type.AUTO_GROW : userPtr ? Type.USER_BUF : Type.ALLOC_BUF;
        alloc_   = allocator ? allocator : &defaultAllocator_;
        maxSize_ = maxSize;
        top_     = type_ == Type.USER_BUF ? cast(uint8*) (userPtr) : alloc_.alloc(max(maxSize, 1));
        size_    = 0;

        if (maxSize_ > 0 && null == top_)
        {
            throw new XError(ERR.CANT_ALLOC);
        }

        if (type_ == Type.ALLOC_BUF && alloc_.useProtect && !protect(top_, maxSize, true))
        {
            alloc_.free(top_);
            throw new XError(ERR.CANT_PROTECT);
        }
    }

    ~this()
    {
        if (isAllocType)
        {
            if (alloc_.useProtect)
            {
                protect(top_, maxSize_, false);
            }

            alloc_.free(top_);
        }
    }

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

    void db(uint8* code, int codeSize)
    {
        foreach(i; 0..codeSize)
        {
            db(code[i]);
        }
    }

    void db(uint64 code, int codeSize)
    {
        if (codeSize > 8)
        {
            throw new XError(ERR.BAD_PARAMETER);
        }

        foreach(i; 0..codeSize)
        {
            db(cast(uint8) (code >> (i * 8)));
        }
    }

    void dw(uint32 code)
    {
        db(code, 2);
    }
    void dd(uint32 code)
    {
        db(code, 4);
    }
    void dq(uint64 code)
    {
        db(code, 8);
    }
    uint8* getCode()
    {
        return top_;
    }

    F getCode(F)()
    {
        return CastTo !(F) (top_);
    }

    uint8* getCurr()
    {
        return &top_[size_];
    }

    F getCurr(F)()
    {
        return CastTo !(F) (&top_[size_]);
    }

    size_t getSize()
    {
        return size_;
    }
    void setSize(size_t size)
    {
        if (size > maxSize_)
        {
            throw new XError(ERR.OFFSET_IS_TOO_BIG);
        }

        size_ = size;
    }

    void dump()
    {
        uint8  * p     = getCode;
        size_t bufSize = getSize;
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
                    format("%02X ", p[i * 16 + j]).write;
                }
            }
            writeln();
            remain -= disp;
            if (remain <= 0)
            {
                break;
            }
        }
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
        foreach(i; 0..size)
        {
            data[i] = cast(uint8) (disp >> (i * 8));
        }
    }
    void save(size_t offset, size_t val, int size, inner.LabelMode mode)
    {
        addrInfoList_ ~= AddrInfo(offset, val, size, mode);
    }
    bool isAutoGrow()
    {
        return type_ == Type.AUTO_GROW;
    }

//	change exec permission of memory
//	@param addr [in] buffer address
//	@param size [in] buffer size
//	@param canExec [in] true(enable to exec), false(disable to exec)
//	@return true(success), false(failure)
    bool protect(void* addr, size_t size, bool canExec)
    {
        version(Windows)
        {
            DWORD oldProtect;
            return VirtualProtect(cast(void*)(addr), size, canExec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &oldProtect) != 0;
        }
        version(linux)
        {
            size_t pageSize = sysconf(_SC_PAGESIZE);
            int    fd       = open("/dev/zero", O_RDONLY);
            auto   m        = cast(uint8*) mmap(addr, size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, pageSize);
            return(m == addr);
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
};

public class Address : Operand {
    uint8  top_[6];            // 6 = 1(ModRM) + 1(SIB) + 4(disp)
    uint8  size_;
    uint8  rex_;
    uint64 disp_;
    bool   isOnlyDisp_;
    bool   is64bitDisp_;
    bool   is32bit_;
    bool   isVsib_;
    bool   isYMM_;

    void verify()
    {
        if (isVsib_)
        {
            throw new XError(ERR.BAD_VSIB_ADDRESSING);
        }
    }

public:
    this(uint32 sizeBit, bool isOnlyDisp, uint64 disp, bool is32bit, bool is64bitDisp = false, bool isVsib = false, bool isYMM = false)
    {
        super(0, Kind.MEM, sizeBit);
        size_        = 0;
        rex_         = 0;
        disp_        = disp;
        isOnlyDisp_  = isOnlyDisp;
        is64bitDisp_ = is64bitDisp;
        is32bit_     = is32bit;
        isVsib_      = isVsib;
        isYMM_       = isYMM;
    }

    void db(int code)
    {
        if (size_ >= top_.sizeof )
        {
            throw new XError(ERR.CODE_IS_TOO_BIG);
        }
        top_[size_++] = cast(uint8) code;
    }
    void dd(uint32 code)
    {
        foreach(i; 0..4)
        {
            db(code >> (i * 8));
        }
    }

    uint8* getCode()
    {
        return cast(uint8*) top_;
    }
    size_t getSize()
    {
        return size_;
    }
    void updateRegField(uint8 regIdx)
    {
        *(this.top_).ptr = (*(this.top_).ptr & 0B11000111) | ((regIdx << 3) & 0B00111000);
    }
    void setVsib(bool isVsib)
    {
        isVsib_ = isVsib;
    }
    bool isVsib()
    {
        return isVsib_;
    }
    override bool isYMM()
    {
        return isYMM_;
    }
    bool is32bit()
    {
        verify();
        return is32bit_;
    }
    bool isOnlyDisp()
    {
        verify(); // for mov eax
        return isOnlyDisp_;
    }
    uint64 getDisp()
    {
        return disp_;
    }
    uint8 getRex()
    {
        verify();
        return rex_;
    }
    bool is64bitDisp()
    {
        verify(); // for moffset
        return is64bitDisp_;
    }
    void setRex(uint8 rex)
    {
        rex_ = rex;
    }
};

class AddressFrame {
private:
    Address makeAddress(RegExp e)
    {
        e.verify;
        bool        isVsib = e.isVsib;
        bool        isYMM  = e.isYMM;
        RegExp.SReg base   = e.getBase;
        RegExp.SReg index  = e.getIndex;
        uint32      disp   = e.getDisp;

        Address     frame = new Address(bit_, (!base.bit && !index.bit), disp, base.bit == 32 || index.bit == 32, false, isVsib, isYMM);
        enum
        {
            mod00 = 0, mod01 = 1, mod10 = 2
        }
        int mod;

        if (!base.bit || ((base.idx & 7) != Code.EBP && disp == 0))
        {
            mod = mod00;
        }
        else if (inner.IsInDisp8(disp))
        {
            mod = mod01;
        }
        else
        {
            mod = mod10;
        }
        int baseIdx = base.bit ? (base.idx & 7) : Code.EBP;

        // ModR/M = [2:3:3] = [Mod:reg/code:R/M]
        bool hasSIB = index.bit || (base.idx & 7) == Code.ESP;
        version(XBYAK64)
        {
            if (!base.bit && !index.bit)
            {
                hasSIB = true;
            }
        }
        if (hasSIB)
        {
            frame.db((mod << 6) | Code.ESP);

            // SIB = [2:3:3] = [SS:index:base(=rm)]
            int indexIdx = index.bit ? (index.idx & 7) : Code.ESP;
            int scale    = e.getScale;
            int ss       = (scale == 8) ? 3 : (scale == 4) ? 2 : (scale == 2) ? 1 : 0;
            frame.db((ss << 6) | (indexIdx << 3) | baseIdx);
        }
        else
        {
            frame.db((mod << 6) | baseIdx);
        }
        if (mod == mod01)
        {
            frame.db(disp);
        }
        else if (mod == mod10 || (mod == mod00 && !base.bit))
        {
            frame.dd(disp);
        }

        int rex = ((index.idx >> 3) << 1) | (base.idx >> 3);

        if (rex)
        {
            rex |= 0x40;
        }
        frame.setRex(cast(uint8) rex);
        return frame;
    }
public:
    uint32 bit_;
    this(uint32 bit)
    {
        bit_ = bit;
    }
    Address opIndex(void* disp)
    {
        size_t adr = cast(size_t) disp;
        version(XBYAK64)
        {
            if (adr > 0xFFFFFFFFU)
            {
                throw new XError(ERR.OFFSET_IS_TOO_BIG);
            }
        }
        RegExp e = new RegExp(cast(uint32)adr);
        return opIndex(e);
    }
    version(XBYAK64)
    {
        Address opIndex(uint64 disp)
        {
            return new Address(64, true, disp, false, true);
        }
        Address opIndex(RegRip addr)
        {
            Address frame = new Address(bit_, true, addr.disp_, false);
            frame.db(0B00000101);
            frame.dd(addr.disp_);
            return frame;
        }
    }
    Address opIndex(RegExp e)
    {
        return makeAddress(e.optimize);
    }
};

struct JmpLabel
{
    size_t          endOfJmp;   // offset from top to the end address of jmp
    int             jmpSize;
    inner.LabelMode mode;
    uint64          disp;                       // dsip for [rip + disp]
    this(size_t endOfJmp = 0, int jmpSize = 0, inner.LabelMode mode = inner.LabelMode.LasIs, uint64 disp = 0)
    {
        this.endOfJmp = endOfJmp;
        this.jmpSize  = jmpSize;
        this.mode     = mode;
        this.disp     = disp;
    }
};

class Label
{
    LabelManager mgr;
    int          id;
public:
    this()
    {
        mgr = new LabelManager();
        id  = 0;
    }

    int getId()
    {
        return id;
    }

    string toStr(int num)
    {
        return format(".%08x", num);
    }
};


class LabelManager
{
    // for string label
    struct SlabelVal
    {
        size_t offset;
        this(size_t offset = 0)
        {
            this.offset = offset;
        }
    }

    alias SlabelVal[string] SlabelDefList;
    alias JmpLabel[][string] SlabelUndefList;

    struct SlabelState
    {
        SlabelDefList   defList;
        SlabelUndefList undefList;
    }

    alias SlabelState[] StateList;

// for Label class
    struct ClabelVal
    {
        size_t offset;
        int    refCount = 1;

        this(size_t offset = 0)
        {
            this.offset   = offset;
            this.refCount = 1;
        }
    }

    alias           ClabelVal[int] ClabelDefList;
    alias           JmpLabel[][int] ClabelUndefList;

    CodeArray       base_;
// global : stateList_.front(), local : stateList_.back()
    StateList       stateList_;
    int             labelId_;
    ClabelDefList   clabelDefList_;
    ClabelUndefList clabelUndefList_;

    int getId(Label label)
    {
        if (label.id == 0)
        {
            label.id = labelId_++;
        }
        return label.id;
    }

    SlabelVal setVal(string id, int val)
    {
        return SlabelVal(val);
    }

    ClabelVal setVal(int id, int val)
    {
        return ClabelVal(val);
    }

    void define_inner(DefList, UndefList, T)(ref DefList deflist, ref UndefList undeflist, T labelId, size_t addrOffset)
    {
        // add label
        if (null != (labelId in deflist))
        {
            throw new XError(ERR.LABEL_IS_REDEFINED);
        }

        deflist[labelId] = setVal(labelId, addrOffset);

        // search undefined label
        if (null == (labelId in undeflist))
        {
            return;
        }

        foreach(JmpLabel jmp; undeflist[labelId])
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
                disp = addrOffset - jmp.endOfJmp;
                version(XBYAK64)
                {
                    if (jmp.jmpSize <= 4 && !inner.IsInInt32(disp))
                    {
                        throw new XError(ERR.OFFSET_IS_TOO_BIG);
                    }
                }
                if (jmp.jmpSize == 1 && !inner.IsInDisp8(cast(uint32) disp))
                {
                    throw new XError(ERR.LABEL_IS_TOO_FAR);
                }
            }
            if (base_.isAutoGrow)
            {
                base_.save(offset, disp, jmp.jmpSize, jmp.mode);
            }
            else
            {
                base_.rewrite(offset, disp, jmp.jmpSize);
            }
            undeflist.remove(labelId);
        }
    }

    void incRefCount(int id)
    {
        clabelDefList_[id].refCount++;
    }

    void decRefCount(int id)
    {
        if (null == (id in clabelDefList_))
            return;

        auto i = clabelDefList_[id];
        if (i.refCount == 1)
        {
            clabelDefList_.remove(id);
        }
        else
        {
            i.refCount -= 1;
        }
    }

    bool hasUndefinedLabel_inner(T)(T list)
    {
        version(NDEBUG)
        {
            foreach(i; list)
            {
                stderr.writefln("undefined label:%s", i[0]);
            }
        }

        return list.length == 0;
    }

public:
    this()
    {
        reset();
    }
    void reset()
    {
        base_    = null;
        labelId_ = 1;
        stateList_.destroy;
        stateList_ ~= SlabelState();
        stateList_ ~= SlabelState();
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
        if (stateList_[$ - 1].undefList.length == 0)
        {
            throw new XError(ERR.LABEL_IS_NOT_FOUND);
        }
        stateList_.length -= 1;
    }

    void set(CodeArray base)
    {
        base_ = base;
    }

    void defineSlabel(string label)
    {
        if (label == "@b" || label == "@f")
        {
            throw new XError(ERR.BAD_LABEL_STR);
        }

        if (label == "@@")
        {
            if (("@f" in stateList_[0].defList) != null)
            {
                stateList_[0].defList.remove("@f");
                label = "@b";
            }
            else
            {
                if (("@b" in stateList_[0].defList) != null)
                {
                    stateList_[0].defList.remove("@b");
                }
                label = "@f";
            }
        }
        int p = 0;
        if (label[0] == '.')
        {
            p = stateList_.length - 1;
        }
        define_inner(stateList_[p].defList, stateList_[p].undefList, label, base_.getSize);
    }

    void defineClabel(Label label)
    {
        define_inner(clabelDefList_, clabelUndefList_, getId(label), base_.getSize);
        label.mgr = this;
    }

    void assign(Label dst, Label src)
    {
        if (null == (src.id in clabelDefList_))
            throw new XError(ERR.LABEL_ISNOT_SET_BY_L);
        define_inner(clabelDefList_, clabelUndefList_, dst.id, clabelDefList_[src.id].offset);
        dst.mgr = this;
    }

    bool getOffset(size_t* offset, string label)
    {
        if (label == "@b")
        {
            if (null != ("@f" in stateList_[0].defList))
            {
                label = "@f";
            }
            else if (null == ("@b" in stateList_[0].defList))
            {
                throw new XError(ERR.LABEL_IS_NOT_FOUND);
            }
        }
        else if (label == "@f")
        {
            if (null != ("@f" in stateList_[0].defList))
            {
                label = "@b";
            }
        }

        int p = 0;
        if (label[0] == '.')
        {
            p = stateList_.length - 1;
        }

        if (null == (label in stateList_[p].defList))
        {
            return false;
        }

        *offset = stateList_[p].defList[label].offset;
        return true;
    }

    bool getOffset(size_t* offset, Label label)
    {
        auto i = (*offset in clabelDefList_);
        if (i != null)
        {
            return false;
        }

        *offset = clabelDefList_[label.getId].offset;
        return true;
    }

    void addUndefinedLabel(string label, JmpLabel jmp)
    {
        int p = 0;
        if (label[0] == '.')
        {
            p = stateList_.length - 1;
        }
        stateList_[p].undefList[label] ~= jmp;
    }

    void addUndefinedLabel(Label label, JmpLabel jmp)
    {
        clabelUndefList_[label.id] ~= jmp;
    }

    bool hasUndefSlabel()
    {
        foreach(i; stateList_)
        {
            auto ikey = i.undefList.keys;
            if (ikey.length != 0)
                return true;
        }
        return false;
    }

    bool hasUndefClabel()
    {
        return(clabelUndefList_.length != 0);
    }
};


enum LabelType
{
    T_SHORT,
    T_NEAR,
    T_AUTO     // T_SHORT if possible
}


public class CodeGenerator : CodeArray {
    version(XBYAK64)
    {
        enum { i32e = 64 | 32, BIT = 64 }
    }
    else
    {
        enum { i32e = 32, BIT = 32 }
    }
// (XMM, XMM|MEM)
    bool isXMM_XMMorMEM(Operand op1, Operand op2)
    {
        return op1.isXMM && (op2.isXMM || op2.isMEM);
    }
// (MMX, MMX|MEM) or (XMM, XMM|MEM)
    bool isXMMorMMX_MEM(Operand op1, Operand op2)
    {
        return (op1.isMMX && (op2.isMMX || op2.isMEM)) || isXMM_XMMorMEM(op1, op2);
    }
// (XMM, MMX|MEM)
    bool isXMM_MMXorMEM(Operand op1, Operand op2)
    {
        return op1.isXMM && (op2.isMMX || op2.isMEM);
    }
// (MMX, XMM|MEM)
    bool isMMX_XMMorMEM(Operand op1, Operand op2)
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
    bool isREG32_REG32orMEM(Operand op1 = OP(), Operand op2 = OP())
    {
        return op1.isREG(i32e) && ((op2.isREG(i32e) && op1.getBit() == op2.getBit()) || op2.isMEM());
    }


    void rex(Operand op1, Operand op2 = REG)
    {
        uint8   rex = 0;
        Operand p1  = op1;
        Operand p2  = op2;
        if (p1.isMEM)
            swap(p1, p2);
        if (p1.isMEM)
            throw new XError(ERR.BAD_COMBINATION);
        if (p2.isMEM)
        {
            Address addr = cast(Address) p2;
            if (BIT == 64 && addr.is32bit_)
                db(0x67);
            rex = addr.getRex | (cast(Reg) p1).getRex;
        }
        else
        {
            // ModRM(reg, base);
            rex = (cast(Reg) op2).getRex((cast(Reg) op1));
        }
        // except movsx(16bit, 32/64bit)
        if ((op1.isBit(16) && !op2.isBit(i32e)) || (op2.isBit(16) && !op1.isBit(i32e)))
            db(0x66);
        if (rex)
            db(rex);
    }

    enum     //AVXtype
    {
        PP_NONE     = 1 << 0,
        PP_66       = 1 << 1,
        PP_F3       = 1 << 2,
        PP_F2       = 1 << 3,
        MM_RESERVED = 1 << 4,
        MM_0F       = 1 << 5,
        MM_0F38     = 1 << 6,
        MM_0F3A     = 1 << 7
    }

    void vex(bool r, int idx, bool is256, int type, bool x = false, bool b = false, int w = 1)
    {
        uint32 pp   = (type & PP_66) ? 1 : (type & PP_F3) ? 2 : (type & PP_F2) ? 3 : 0;
        uint32 vvvv = (((~idx) & 15) << 3) | (is256 ? 4 : 0) | pp;
        if (!b && !x && !w && (type & MM_0F))
        {
            db(0xC5); db((r ? 0 : 0x80) | vvvv);
        }
        else
        {
            uint32 mmmm = (type & MM_0F) ? 1 : (type & MM_0F38) ? 2 : (type & MM_0F3A) ? 3 : 0;
            db(0xC4); db((r ? 0 : 0x80) | (x ? 0 : 0x40) | (b ? 0 : 0x20) | mmmm); db((w << 7) | vvvv);
        }
    }

    LabelManager labelMgr_ = new LabelManager();

    uint8 getModRM(int mod, int r1, int r2)
    {
        return cast(uint8) ((mod << 6) | ((r1 & 7) << 3) | (r2 & 7));
    }

    void opModR(Reg reg1, Reg reg2, int code0, int code1 = Kind.NONE, int code2 = Kind.NONE)
    {
        rex(reg2, reg1);
        db(code0 | (reg1.isBit(8) ? 0 : 1));
        if (code1 != Kind.NONE)
            db(code1);
        if (code2 != Kind.NONE)
            db(code2);
        db(getModRM(3, reg1.getIdx, reg2.getIdx));
    }

    void opModM(Address addr, Reg reg, int code0, int code1 = Kind.NONE, int code2 = Kind.NONE)
    {
        if (addr.is64bitDisp)
            new XError(ERR.CANT_USE_64BIT_DISP);
        rex(addr, reg);
        db(code0 | (reg.isBit(8) ? 0 : 1));
        if (code1 != Kind.NONE)
            db(code1);
        if (code2 != Kind.NONE)
            db(code2);
        addr.updateRegField(cast(uint8) reg.getIdx);
        db(addr.getCode, cast(int) addr.getSize);
    }

    void makeJmp(uint32 disp, LabelType type, uint8 shortCode, uint8 longCode, uint8 longPref)
    {
        int shortJmpSize   = 2;
        int longHeaderSize = longPref ? 2 : 1;
        int longJmpSize    = longHeaderSize + 4;
        if (type != LabelType.T_NEAR && inner.IsInDisp8(disp - shortJmpSize))
        {
            db(shortCode);
            db(disp - shortJmpSize);
        }
        else
        {
            if (type == LabelType.T_SHORT)
                throw new XError(ERR.LABEL_IS_TOO_FAR);
            if (longPref)
                db(longPref);
            db(longCode); dd(disp - longJmpSize);
        }
    }

    void opJmp(T)(T label, LabelType type, uint8 shortCode, uint8 longCode, uint8 longPref)
    {
        if (isAutoGrow && size_ + 16 >= maxSize_)
        {
            // avoid splitting code of jmp
            growMemory;
        }

        size_t offset = 0;

        // label exists
        if (labelMgr_.getOffset(&offset, label))
        {
            makeJmp(inner.VerifyInInt32(offset - getSize), type, shortCode, longCode, longPref);
        }
        else
        {
            int jmpSize = 0;
            if (type == LabelType.T_NEAR)
            {
                jmpSize = 4;
                if (longPref)
                    db(longPref);
                db(longCode);
                dd(0);
            }
            else
            {
                jmpSize = 1;
                db(shortCode);
                db(0);
            }
            JmpLabel jmp = JmpLabel(size_, jmpSize, inner.LabelMode.LasIs);
            labelMgr_.addUndefinedLabel(label, jmp);
        }
    }

    void opJmpAbs(void* addr, LabelType type, uint8 shortCode, uint8 longCode)
    {
        if (isAutoGrow)
        {
            if (type != LabelType.T_NEAR)
                throw new XError(ERR.ONLY_T_NEAR_IS_SUPPORTED_IN_AUTO_GROW);
            if (size_ + 16 >= maxSize_)
                growMemory;
            db(longCode);
            dd(0);
            save(size_ - 4, cast(size_t) addr - size_, 4, inner.LabelMode.Labs);
        }
        else
        {
            makeJmp(inner.VerifyInInt32(cast(uint8*) addr - getCurr), type, shortCode, longCode, 0);
        }
    }

//	preCode is for SSSE3/SSE4
    void opGen(Operand reg, Operand op, int code, int pref, bool isValid, int imm8 = Kind.NONE, int preCode = Kind.NONE)
    {
        if (isValid)
            throw new XError(ERR.BAD_COMBINATION);
        if (pref != Kind.NONE)
            db(pref);
        if (op.isMEM)
        {
            opModM(cast(Address) op, cast(Reg) reg, 0x0F, preCode, code);
        }
        else
        {
            opModR(cast(Reg) reg, cast(Reg) op, 0x0F, preCode, code);
        }
        if (imm8 != Kind.NONE)
            db(imm8);
    }

    void opMMX_IMM(Mmx mmx, int imm8, int code, int ext)
    {
        if (mmx.isXMM)
        {
            db(0x66);
        }
        opModR(REG32(ext), mmx, 0x0F, code);
        db(imm8);
    }

    void opMMX(Mmx mmx, Operand op, int code, int pref = 0x66, int imm8 = Kind.NONE, int preCode = Kind.NONE)
    {
        bool bl = isXMMorMMX_MEM(mmx, op);
        opGen(mmx, op, code, (mmx.isXMM ? pref : Kind.NONE), bl, imm8, preCode);
    }

    void opMovXMM(Operand op1, Operand op2, int code, int pref)
    {
        if (pref != Kind.NONE)
            db(pref);
        if (op1.isXMM && op2.isMEM)
        {
            opModM(cast(Address) op2, cast(Reg) op1, 0x0F, code);
        }
        else if (op1.isMEM && op2.isXMM)
        {
            opModM(cast(Address) (op1), cast(Reg) (op2), 0x0F, code | 1);
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
            if (mmx.isXMM)
                db(0x66);
            opModR(cast(Reg) op, mmx, 0x0F, 0B11000101); db(imm);
        }
        else
        {
            bool bl = isXMM_REG32orMEM(mmx, op);
            opGen(mmx, op, code, 0x66, bl, imm, 0B00111010);
        }
    }

    void opR_ModM(Operand op, int bit, int ext, int code0, int code1 = Kind.NONE, int code2 = Kind.NONE, bool disableRex = false)
    {
        int opBit = op.getBit;
        if (disableRex && opBit == 64)
            opBit = 32;
        if (op.isREG(bit))
        {
            opModR(REG(ext, Kind.REG, opBit), (cast(Reg) op).changeBit(opBit), code0, code1, code2);
        }
        else if (op.isMEM)
        {
            opModM(cast(Address) op, REG(ext, Kind.REG, opBit), code0, code1, code2);
        }
        else
        {
            throw new XError(ERR.BAD_COMBINATION);
        }
    }

    void opShift(Operand op, int imm, int ext)
    {
        verifyMemHasSize(op);
        opR_ModM(op, 0, ext, (0B11000000 | ((imm == 1 ? 1 : 0) << 4)));
        if (imm != 1)
            db(imm);
    }

    void opShift(Operand op, Reg8 cl, int ext)
    {
        if (cl.getIdx != Code.CL)
            throw new XError(ERR.BAD_COMBINATION);
        opR_ModM(op, 0, ext, 0B11010010);
    }

    void opModRM(Operand op1, Operand op2, bool condR, bool condM, int code0, int code1 = Kind.NONE, int code2 = Kind.NONE)
    {
        if (condR)
        {
            opModR(cast(Reg) op1, cast(Reg) op2, code0, code1, code2);
        }
        else if (condM)
        {
            opModM(cast(Address) op2, cast(Reg) op1, code0, code1, code2);
        }
        else
        {
            throw new XError(ERR.BAD_COMBINATION);
        }
    }

    void opShxd(Operand op, Reg reg, uint8 imm, int code, Reg8 cl = REG8())
    {
        if (cl && cl.getIdx != Code.CL)
            throw new XError(ERR.BAD_COMBINATION);
        opModRM(reg, op, (op.isREG(16 | i32e) && op.getBit == reg.getBit), op.isMEM && (reg.isREG(16 | i32e)), 0x0F, code | (cl ? 1 : 0));
        if (!cl)
            db(imm);
    }

// (REG, REG|MEM), (MEM, REG)
    void opRM_RM(Operand op1, Operand op2, int code)
    {
        if (op1.isREG && op2.isMEM)
        {
            opModM(cast(Address) op2, cast(Reg) op1, code | 2);
        }
        else
        {
            opModRM(op2, op1, op1.isREG && op1.getKind == op2.getKind, op1.isMEM && op2.isREG, code);
        }
    }

// (REG|MEM, IMM)
    void opRM_I(Operand op, uint32 imm, int code, int ext)
    {
        verifyMemHasSize(op);
        uint32 immBit = inner.IsInDisp8(imm) ? 8 : inner.IsInDisp16(imm) ? 16 : 32;
        if (op.getBit < immBit)
            throw new XError(ERR.IMM_IS_TOO_BIG);

        // don't use MEM16 if 32/64bit mode
        if (op.isREG(32 | 64) && immBit == 16)
            immBit = 32;

        if (op.isREG && op.getIdx == 0 && (op.getBit == immBit || (op.isBit(64) && immBit == 32)))         // rax, eax, ax, al
        {
            rex(op);
            db(code | 4 | (immBit == 8 ? 0 : 1));
        }
        else
        {
            int tmp = immBit < min(op.getBit, 32U) ? 2 : 0;
            opR_ModM(op, 0, ext, 0B10000000 | tmp);
        }
        db(imm, immBit / 8);
    }

    void opIncDec(Operand op, int code, int ext)
    {
        verifyMemHasSize(op);
        version(XBYAK64)
        {
            if (op.isREG && !op.isBit(8))
            {
                rex(op);
                db(code | op.getIdx);
                return;
            }
        }
        code = 0B11111110;
        if (op.isREG)
        {
            opModR(REG(ext, Kind.REG, op.getBit), cast(Reg) op, code);
        }
        else
        {
            opModM(cast(Address) op, REG(ext, Kind.REG, op.getBit), code);
        }
    }

    void opPushPop(Operand op, int code, int ext, int alt)
    {
        if (op.isREG)
        {
            if (op.isBit(16))
                db(0x66);
            if ((cast(Reg) op).getIdx >= 8)
                db(0x41);
            db(alt | (op.getIdx & 7));
        }
        else if (op.isMEM)
        {
            opModM(cast(Address) op, REG(ext, Kind.REG, op.getBit), code);
        }
        else
        {
            throw new XError(ERR.BAD_COMBINATION);
        }
    }

    void verifyMemHasSize(Operand op)
    {
        if (op.isMEM && op.getBit == 0)
            throw new XError(ERR.MEM_SIZE_IS_NOT_SPECIFIED);
    }

    void opMovxx(Reg reg, Operand op, uint8 code)
    {
        if (op.isBit(32))
            throw new XError(ERR.BAD_COMBINATION);

        int  w    = op.isBit(16);
        bool cond = reg.isREG && (reg.getBit > op.getBit);
        opModRM(reg, op, cond && op.isREG, cond && op.isMEM, 0x0F, code | w);
    }

    void opFpuMem(Address addr, uint8 m16, uint8 m32, uint8 m64, uint8 ext, uint8 m64ext)
    {
        if (addr.is64bitDisp)
            throw new XError(ERR.CANT_USE_64BIT_DISP);

        uint8 code = addr.isBit(16) ? m16 : addr.isBit(32) ? m32 : addr.isBit(64) ? m64 : 0;
        if (!code)
            throw new XError(ERR.BAD_MEM_SIZE);

        if (m64ext && addr.isBit(64))
            ext = m64ext;

        rex(addr, st0);
        db(code);
        addr.updateRegField(ext);
        db(addr.getCode, cast(int) addr.getSize);
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

    void opVex(Reg r, Operand p1, Operand p2, int type, int code, int w)
    {
        bool x, b;
        if (p2.isMEM)
        {
            Address addr = cast(Address) p2;
            uint8   rex  = addr.getRex;
            x = (rex & 2) != 0;
            b = (rex & 1) != 0;
            if (BIT == 64 && addr.is32bit)
                db(0x67);

            if (BIT == 64 && w == -1)
                w = (rex & 4) ? 1 : 0;
        }
        else
        {
            x = false;
            b = (cast(Reg) (p2)).isExtIdx;
        }
        if (w == -1)
            w = 0;

        vex(r.isExtIdx, p1.getIdx, r.isYMM, type, x, b, w);
        db(code);
        if (p2.isMEM)
        {
            Address addr = cast(Address) p2;
            addr.updateRegField(cast(uint8) (r.getIdx));
            db(addr.getCode, cast(int) (addr.getSize));
        }
        else
        {
            db(getModRM(3, r.getIdx, p2.getIdx));
        }
    }
// (r, r, r/m) if isR_R_RM
// (r, r/m, r)
    void opGpr(Reg32e r, Operand op1, Operand op2, int type, uint8 code, bool isR_R_RM)
    {
        Operand p1 = op1;
        Operand p2 = op2;
        if (!isR_R_RM)
        {
            swap(p1, p2);
        }
        uint bit = r.getBit;
        if (p1.getBit != bit || (p2.isREG && p2.getBit != bit))
            throw new XError(ERR.BAD_COMBINATION);
        int w = bit == 64;
        opVex(r, p1, p2, type, code, w);
    }
// support (x, x, x/m), (y, y, y/m)
    void opAVX_X_X_XM(Xmm x1, Operand op1, Operand op2, int type, int code0, bool supportYMM, int w = -1)
    {
        Xmm     x2;
        Operand op;
        if (op2.isNone)
        {
            x2 = x1;
            op = op1;
        }
        else
        {
            if (!(op1.isXMM || (supportYMM && op1.isYMM)))
                throw new XError(ERR.BAD_COMBINATION);
            x2 = cast(Xmm) op1;
            op = op2;
        }
        // (x1, x2, op)
        if (!((x1.isXMM && x2.isXMM) || (supportYMM && x1.isYMM && x2.isYMM)))
            throw new XError(ERR.BAD_COMBINATION);
        opVex(x1, x2, op, type, code0, w);
    }
// if cvt then return pointer to Xmm(idx) (or Ymm(idx)), otherwise return op
    void opAVX_X_X_XMcvt(Xmm x1, Operand op1, Operand op2, bool cvt, Kind kind, int type, int code0, bool supportYMM, int w = -1)
    {
        opAVX_X_X_XM(x1, op1, cvt ? kind == Kind.XMM ? cast(Operand) (XMM(op2.getIdx)) : cast(Operand) (YMM(op2.getIdx)) : op2, type, code0, supportYMM, w);
    }

// support (x, x/m, imm), (y, y/m, imm)
    void opAVX_X_XM_IMM(Xmm x, Operand op, int type, int code, bool supportYMM, int w = -1, int imm = Kind.NONE)
    {
        opAVX_X_X_XM(x, (x.isXMM ? xm0 : ym0), op, type, code, supportYMM, w);
        if (imm != Kind.NONE)
            db(cast(uint8) imm);
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

    void opGather(Xmm x1, Address addr, Xmm x2, int type, uint8 code, int w, int mode)
    {
        if (!addr.isVsib)
            throw new XError(ERR.BAD_VSIB_ADDRESSING);
        int  y_vx_y = 0;
        int  y_vy_y = 1;
//		int x_vy_x = 2;
        bool isAddrYMM = addr.isYMM;
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
            else                 // x_vy_x
            {
                isOK = !x1.isYMM && isAddrYMM && !x2.isYMM;
            }
            if (!isOK)
                throw new XError(ERR.BAD_VSIB_ADDRESSING);
        }
        addr.setVsib(false);
        opAVX_X_X_XM(isAddrYMM ? YMM(x1.getIdx) : x1, isAddrYMM ? YMM(x2.getIdx) : x2, addr, type, code, true, w);
        addr.setVsib(true);
    }
public:
    uint getVersion()
    {
        return xbyak4d.VERSION;
    }
    enum
    {
        mm0   = MMX(0), mm1 = MMX(1), mm2 = MMX(2), mm3 = MMX(3),
        mm4   = MMX(4), mm5 = MMX(5), mm6 = MMX(6), mm7 = MMX(7),
        xmm0  = XMM(0), xmm1 = XMM(1), xmm2 = XMM(2), xmm3 = XMM(3),
        xmm4  = XMM(4), xmm5 = XMM(5), xmm6 = XMM(6), xmm7 = XMM(7),
        ymm0  = YMM(0), ymm1 = YMM(1), ymm2 = YMM(2), ymm3 = YMM(3),
        ymm4  = YMM(4), ymm5 = YMM(5), ymm6 = YMM(6), ymm7 = YMM(7),
        xm0   = xmm0, xm1 = xmm1, xm2 = xmm2, xm3 = xmm3,
        xm4   = xmm4, xm5 = xmm5, xm6 = xmm6, xm7 = xmm7,               // for my convenience
        ym0   = ymm0, ym1 = ymm1, ym2 = ymm2, ym3 = ymm3,
        ym4   = ymm4, ym5 = ymm5, ym6 = ymm6, ym7 = ymm7,               // for my convenience
        eax   = REG32(Code.EAX), ecx = REG32(Code.ECX), edx = REG32(Code.EDX), ebx = REG32(Code.EBX),
        esp   = REG32(Code.ESP), ebp = REG32(Code.EBP), esi = REG32(Code.ESI), edi = REG32(Code.EDI),
        ax    = REG16(Code.EAX), cx = REG16(Code.ECX), dx = REG16(Code.EDX), bx = REG16(Code.EBX),
        sp    = REG16(Code.ESP), bp = REG16(Code.EBP), si = REG16(Code.ESI), di = REG16(Code.EDI),
        al    = REG8(Code.AL), cl = REG8(Code.CL), dl = REG8(Code.DL), bl = REG8(Code.BL),
        ah    = REG8(Code.AH), ch = REG8(Code.CH), dh = REG8(Code.DH), bh = REG8(Code.BH),
        ptr   = new AddressFrame(0),
        byte_ = new AddressFrame(8),
        word  = new AddressFrame(16),
        dword = new AddressFrame(32),
        qword = new AddressFrame(64),
        st0   = FPU(0), st1 = FPU(1), st2 = FPU(2), st3 = FPU(3),
        st4   = FPU(4), st5 = FPU(5), st6 = FPU(6), st7 = FPU(7)
    }
    version(XBYAK64)
    {
        enum
        {
            rax  = REG64(Code.RAX), rcx = REG64(Code.RCX), rdx = REG64(Code.RDX), rbx = REG64(Code.RBX),
            rsp  = REG64(Code.RSP), rbp = REG64(Code.RBP), rsi = REG64(Code.RSI), rdi = REG64(Code.RDI),
            r8   = REG64(Code.R8), r9 = REG64(Code.R9), r10 = REG64(Code.R10), r11 = REG64(Code.R11), r12 = REG64(Code.R12), r13 = REG64(Code.R13), r14 = REG64(Code.R14), r15 = REG64(Code.R15),
            r8d  = REG32(Code.R8D), r9d = REG32(Code.R9D), r10d = REG32(Code.R10D), r11d = REG32(Code.R11D), r12d = REG32(Code.R12D), r13d = REG32(Code.R13D), r14d = REG32(Code.R14D), r15d = REG32(Code.R15D),
            r8w  = REG16(Code.R8W), r9w = REG16(Code.R9W), r10w = REG16(Code.R10W), r11w = REG16(Code.R11W), r12w = REG16(Code.R12W), r13w = REG16(Code.R13W), r14w = REG16(Code.R14W), r15w = REG16(Code.R15W),
            r8b  = REG8(Code.R8B), r9b = REG8(Code.R9B), r10b = REG8(Code.R10B), r11b = REG8(Code.R11B), r12b = REG8(Code.R12B), r13b = REG8(Code.R13B), r14b = REG8(Code.R14B), r15b = REG8(Code.R15B),
            spl  = REG8(Code.SPL, 1), bpl = REG8(Code.BPL, 1), sil = REG8(Code.SIL, 1), dil = REG8(Code.DIL, 1),
            xmm8 = XMM(8), xmm9 = XMM(9), xmm10 = XMM(10), xmm11 = XMM(11), xmm12 = XMM(12), xmm13 = XMM(13), xmm14 = XMM(14), xmm15 = XMM(15),
            ymm8 = YMM(8), ymm9 = YMM(9), ymm10 = YMM(10), ymm11 = YMM(11), ymm12 = YMM(12), ymm13 = YMM(13), ymm14 = YMM(14), ymm15 = YMM(15),
            xm8  = xmm8, xm9 = xmm9, xm10 = xmm10, xm11 = xmm11, xm12 = xmm12, xm13 = xmm13, xm14 = xmm14, xm15 = xmm15,            // for my convenience
            ym8  = ymm8, ym9 = ymm9, ym10 = ymm10, ym11 = ymm11, ym12 = ymm12, ym13 = ymm13, ym14 = ymm14, ym15 = ymm15,            // for my convenience
            rip  = RegRip()
        }
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
    void jmp(string label, LabelType type = LabelType.T_AUTO)
    {
        opJmp(label, type, 0B11101011, 0B11101001, 0);
    }
    void jmp(Label label, LabelType type = LabelType.T_AUTO)
    {
        opJmp(label, type, 0B11101011, 0B11101001, 0);
    }
    void jmp(void* addr, LabelType type = LabelType.T_AUTO)
    {
        opJmpAbs(addr, type, 0B11101011, 0B11101001);
    }

    void jmp(Operand op)
    {
        opR_ModM(op, BIT, 4, 0xFF, NONE, NONE, true);
    }

    void call(Operand op)
    {
        opR_ModM(op, 16 | i32e, 2, 0xFF, NONE, NONE, true);
    }

// (REG|MEM, REG)
    void test(Operand op, Reg reg)
    {
        opModRM(reg, op, op.isREG && (op.getKind == reg.getKind), op.isMEM, 0B10000100);
    }

// (REG|MEM, IMM)
    void test(Operand op, uint32 imm)
    {
        verifyMemHasSize(op);
        if (op.isREG && op.getIdx == 0)           // al, ax, eax
        {
            rex(op);
            db(0B10101000 | (op.isBit(8) ? 0 : 1));
        }
        else
        {
            opR_ModM(op, 0, 0, 0B11110110);
        }
        db(imm, (min(op.getBit / 8, 4U)));
    }

    void ret(int imm = 0)
    {
        if (imm)
        {
            db(0B11000010); dw(imm);
        }
        else
        {
            db(0B11000011);
        }
    }

// (REG16|REG32, REG16|REG32|MEM)
    void imul(Reg reg, Operand op)
    {
        opModRM(reg, op, op.isREG && (reg.getKind == op.getKind), op.isMEM, 0x0F, 0B10101111);
    }

    void imul(Reg reg, Operand op, int imm)
    {
        int s = inner.IsInDisp8(imm) ? 1 : 0;
        opModRM(reg, op, op.isREG && (reg.getKind == op.getKind), op.isMEM, 0B01101001 | (s << 1));
        int size = s ? 1 : reg.isREG(16) ? 2 : 4;
        db(imm, size);
    }

    void pop(Operand op)
    {
        opPushPop(op, 0B10001111, 0, 0B01011000);
    }
    void push(Operand op)
    {
        opPushPop(op, 0B11111111, 6, 0B01010000);
    }
    void push(AddressFrame af, uint32 imm)
    {
        if (af.bit_ == 8 && inner.IsInDisp8(imm))
        {
            db(0B01101010); db(imm);
        }
        else if (af.bit_ == 16 && inner.IsInDisp16(imm))
        {
            db(0x66); db(0B01101000); dw(imm);
        }
        else
        {
            db(0B01101000); dd(imm);
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

    void bswap(Reg32e reg)
    {
        opModR(REG32(1), reg, 0x0F);
    }
    void mov(Operand reg1, Operand reg2)
    {
        Reg     reg;
        Address addr;
        uint8   code;
        if (reg1.isREG && reg1.getIdx == 0 && reg2.isMEM)           // mov eax|ax|al, [disp]
        {
            reg  = cast(Reg) reg1;
            addr = cast(Address) reg2;
            code = 0B10100000;
        }
        else if (reg1.isMEM && reg2.isREG && reg2.getIdx == 0)             // mov [disp], eax|ax|al
        {
            reg  = cast(Reg) reg2;
            addr = cast(Address) reg1;
            code = 0B10100010;
        }
        version(XBYAK64)
        {
            if (addr && addr.is64bitDisp)
            {
                if (code)
                {
                    rex(reg);
                    db(reg1.isREG(8) ? 0xA0 : reg1.isREG ? 0xA1 : reg2.isREG(8) ? 0xA2 : 0xA3);
                    db(addr.getDisp, 8);
                }
                else
                    throw new XError(ERR.BAD_COMBINATION);
            }
            else
                opRM_RM(reg1, reg2, 0B10001000);
        }
        version(XBYAK32)
        {
            if (code && addr.isOnlyDisp)
            {
                rex(reg, addr);
                db(code | (reg.isBit(8) ? 0 : 1));
                dd(cast(uint32) (addr.getDisp));
            }
            else
                opRM_RM(reg1, reg2, 0B10001000);
        }
    }

    version(XBYAK64)
    {
        void mov(Operand op, uint64 imm, bool opti = true)
        {
            mov_uint32or64 !(uint64) (op, imm, opti);
        }
    }
    version(XBYAK32)
    {
        void mov(Operand op, uint32 imm, bool opti = true)
        {
            mov_uint32or64 !(uint32) (op, imm, opti);
        }
    }

    void mov_uint32or64(T) (Operand op, T imm, bool opti = true) if (is(T == uint32) || is(T == uint64))
    {
        verifyMemHasSize(op);
        if (op.isREG)
        {
            int bit  = op.getBit;
            int idx  = op.getIdx;
            int code = 0B10110000 | ((bit == 8 ? 0 : 1) << 3);
            version(XBYAK64)
            {
                if (op.isBit(64) && (imm >> 32) == 0)
                {
                    rex(REG32(idx));
                    bit = 32;
                }
                else
                {
                    rex(op);
                    if (opti && bit == 64 && inner.IsInDisp32(imm))
                    {
                        db(0B11000111);
                        code = 0B11000000;
                        bit  = 32;
                    }
                }
            }
            version(XBYAK32)
            {
                rex(op);
            }
            db(code | (op.getIdx & 7));
            db(imm, bit / 8);
        }
        else if (op.isMEM)
        {
            opModM(cast(Address) op, REG(0, Kind.REG, op.getBit), 0B11000110);
            int size = op.getBit / 8; if (size > 4)
                size = 4;
            db(cast(uint32) (imm), size);
        }
        else
        {
            throw new XError(ERR.BAD_COMBINATION);
        }
    }

// QQQ : rewrite this function with putL
    version(XBYAK64)
    {
        void mov(Reg64 reg, string label)
        {
            mov_Reg32or64 !(Reg64) (reg, label);
        }
    }
    version(XBYAK32)
    {
        void mov(Reg32 reg, string label)
        {
            mov_Reg32or64 !(Reg32) (reg, label);
        }
    }

    void mov_Reg32or64(T) (T reg, string label) if (is(T == Reg32) || is(T == Reg64))
    {
        if (label.length == 0)
        {
            mov(reg, 0, true);
            return;
        }
        int jmpSize = cast(int) size_t.sizeof;
        version(XBYAK64)
        {
            auto dummyAddr = 0x1122334455667788;
        }
        version(XBYAK32)
        {
            auto dummyAddr = 0x12345678;
        }
        if (isAutoGrow && size_ + 16 >= maxSize_)
            growMemory;
        size_t offset = 0;
        if (labelMgr_.getOffset(&offset, label))
        {
            if (isAutoGrow)
            {
                mov(reg, dummyAddr);
                save(size_ - jmpSize, offset, jmpSize, inner.LabelMode.LaddTop);
            }
            else
            {
                mov(reg, cast(size_t) top_ + offset, false);                // not to optimize 32-bit imm
            }
            return;
        }
        mov(reg, dummyAddr);
        JmpLabel jmp;
        jmp.endOfJmp = size_;
        jmp.jmpSize  = jmpSize;
        jmp.mode     = isAutoGrow ? inner.LabelMode.LaddTop : inner.LabelMode.Labs;
        labelMgr_.addUndefinedLabel(label, jmp);
    }

//	put address of label to buffer
//	@note the put size is 4(32-bit), 8(64-bit)
    void putL(T)(T label) if (is(T == string) || is(T == Label))
    {
        const int jmpSize = cast(int) size_t.sizeof;
        if (isAutoGrow && size_ + 16 >= maxSize_)
            growMemory;
        size_t offset = 0;
        if (labelMgr_.getOffset(&offset, label))
        {
            if (isAutoGrow)
            {
                db(cast(uint64) 0, jmpSize);
                save(size_ - jmpSize, offset, jmpSize, inner.LabelMode.LaddTop);
            }
            else
            {
                db(cast(size_t) top_ + offset, jmpSize);
            }
            return;
        }
        db(cast(uint64) 0, jmpSize);
        JmpLabel jmp;
        jmp.endOfJmp = size_;
        jmp.jmpSize  = jmpSize;
        jmp.mode     = isAutoGrow ? inner.LabelMode.LaddTop : inner.LabelMode.Labs;
        labelMgr_.addUndefinedLabel(label, jmp);
    }

    void adcx(Reg32e reg, Operand op)
    {
        opGen(reg, op, 0xF6, 0x66, isREG32_REG32orMEM, NONE, 0x38);
    }
    void adox(Reg32e reg, Operand op)
    {
        opGen(reg, op, 0xF6, 0xF3, isREG32_REG32orMEM, NONE, 0x38);
    }


    void cmpxchg8b(Address addr)
    {
        opModM(addr, REG32(1), 0x0F, 0B11000111);
    }
    version(XBYAK64)
    {
        void cmpxchg16b(Address addr)
        {
            opModM(addr, REG64(1), 0x0F, 0B11000111);
        }
    }
    void xadd(Operand op, Reg reg)
    {
        opModRM(reg, op, (op.isREG && reg.isREG && op.getBit == reg.getBit), op.isMEM, 0x0F, 0B11000000 | (reg.isBit(8) ? 0 : 1));
    }

    void cmpxchg(Operand op, Reg reg)
    {
        opModRM(reg, op, (op.isREG() && reg.isREG() && op.getBit() == reg.getBit()), op.isMEM(), 0x0F, 0xb0 | (reg.isBit(8) ? 0 : 1));
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
        version(XBYAK64)
        {
            BL = (p2.getIdx != 0 || !p1.isREG(32));
        }
        if (p2.isREG && (p1.isREG(16 | i32e) && p1.getIdx == 0) && BL)
        {
            rex(p2, p1);
            db(0x90 | (p2.getIdx & 7));
            return;
        }
        opModRM(p1, p2, (p1.isREG && p2.isREG && (p1.getBit == p2.getBit)), p2.isMEM, 0B10000110 | (p1.isBit(8) ? 40 : 1));
    }

    void call(string label)
    {
        opJmp(label, LabelType.T_NEAR, 0, 0B11101000, 0);
    }

    void call(void* addr)
    {
        opJmpAbs(addr, LabelType.T_NEAR, 0, 0B11101000);
    }

// special case
    void movd(Address addr, Mmx mmx)
    {
        if (mmx.isXMM)
            db(0x66);
        opModM(addr, mmx, 0x0F, 0B01111110);
    }

    void movd(Reg32 reg, Mmx mmx)
    {
        if (mmx.isXMM)
            db(0x66);
        opModR(mmx, reg, 0x0F, 0B01111110);
    }

    void movd(Mmx mmx, Address addr)
    {
        if (mmx.isXMM)
            db(0x66);
        opModM(addr, mmx, 0x0F, 0B01101110);
    }

    void movd(Mmx mmx, Reg32 reg)
    {
        if (mmx.isXMM)
            db(0x66);
        opModR(mmx, reg, 0x0F, 0B01101110);
    }

    void movq2dq(Xmm xmm, Mmx mmx)
    {
        db(0xF3); opModR(xmm, mmx, 0x0F, 0B11010110);
    }

    void movdq2q(Mmx mmx, Xmm xmm)
    {
        db(0xF2); opModR(mmx, xmm, 0x0F, 0B11010110);
    }

    void movq(Mmx mmx, Operand op)
    {
        if (mmx.isXMM)
            db(0xF3);
        opModRM(mmx, op, (mmx.getKind == op.getKind), op.isMEM, 0x0F, mmx.isXMM ? 0B01111110 : 0B01101111);
    }

    void movq(Address addr, Mmx mmx)
    {
        if (mmx.isXMM)
            db(0x66);
        opModM(addr, mmx, 0x0F, mmx.isXMM ? 0B11010110 : 0B01111111);
    }

    version(XBYAK64)
    {
        void movq(Reg64 reg, Mmx mmx)
        {
            if (mmx.isXMM)
                db(0x66);
            opModR(mmx, reg, 0x0F, 0B01111110);
        }

        void movq(Mmx mmx, Reg64 reg)
        {
            if (mmx.isXMM)
                db(0x66);
            opModR(mmx, reg, 0x0F, 0B01101110);
        }

        void pextrq(Operand op, Xmm xmm, uint8 imm)
        {
            if (!op.isREG(64) && !op.isMEM)
                throw new XError(ERR.BAD_COMBINATION);
            opGen(REG64(xmm.getIdx), op, 0x16, 0x66, 0, imm, 0B00111010);     // force to 64bit
        }

        void pinsrq(Xmm xmm, Operand op, uint8 imm)
        {
            if (!op.isREG(64) && !op.isMEM)
                throw new XError(ERR.BAD_COMBINATION);
            opGen(REG64(xmm.getIdx), op, 0x22, 0x66, 0, imm, 0B00111010);     // force to 64bit
        }

        void movsxd(Reg64 reg, Operand op)
        {
            if (!op.isBit(32))
                throw new XError(ERR.BAD_COMBINATION);
            opModRM(reg, op, op.isREG, op.isMEM, 0x63);
        }
    } // version(XBYAK64)

// MMX2 : pextrw : reg, mmx/xmm, imm
// SSE4 : pextrw, pextrb, pextrd, extractps : reg/mem, mmx/xmm, imm
    void pextrw(Operand op, Mmx xmm, uint8 imm)
    {
        opExt(op, xmm, 0x15, imm, true);
    }
    void pextrb(Operand op, Xmm xmm, uint8 imm)
    {
        opExt(op, xmm, 0x14, imm);
    }
    void pextrd(Operand op, Xmm xmm, uint8 imm)
    {
        opExt(op, xmm, 0x16, imm);
    }
    void extractps(Operand op, Xmm xmm, uint8 imm)
    {
        opExt(op, xmm, 0x17, imm);
    }
    void pinsrw(Mmx mmx, Operand op, int imm)
    {
        if (!op.isREG(32) && !op.isMEM)
            throw new XError(ERR.BAD_COMBINATION);
        opGen(mmx, op, 0B11000100, mmx.isXMM ? 0x66 : NONE, 0, imm);
    }
    void insertps(Xmm xmm, Operand op, uint8 imm)
    {
        opGen(xmm, op, 0x21, 0x66, isXMM_XMMorMEM(xmm, op), imm, 0B00111010);
    }
    void pinsrb(Xmm xmm, Operand op, uint8 imm)
    {
        opGen(xmm, op, 0x20, 0x66, isXMM_REG32orMEM(xmm, op), imm, 0B00111010);
    }
    void pinsrd(Xmm xmm, Operand op, uint8 imm)
    {
        opGen(xmm, op, 0x22, 0x66, isXMM_REG32orMEM(xmm, op), imm, 0B00111010);
    }
    void pmovmskb(Reg32e reg, Mmx mmx)
    {
        if (mmx.isXMM)
            db(0x66);
        opModR(reg, mmx, 0x0F, 0B11010111);
    }
    void maskmovq(Mmx reg1, Mmx reg2)
    {
        if (!reg1.isMMX || !reg2.isMMX)
            throw new XError(ERR.BAD_COMBINATION);
        opModR(reg1, reg2, 0x0F, 0B11110111);
    }
    void lea(Reg32e reg, Address addr)
    {
        opModM(addr, reg, 0B10001101);
    }
    void movmskps(Reg32e reg, Xmm xmm)
    {
        opModR(reg, xmm, 0x0F, 0B01010000);
    }
    void movmskpd(Reg32e reg, Xmm xmm)
    {
        db(0x66); movmskps(reg, xmm);
    }
    void movntps(Address addr, Xmm xmm)
    {
        opModM(addr, MMX(xmm.getIdx), 0x0F, 0B00101011);
    }
    void movntdqa(Xmm xmm, Address addr)
    {
        db(0x66); opModM(addr, xmm, 0x0F, 0x38, 0x2A);
    }
    void lddqu(Xmm xmm, Address addr)
    {
        db(0xF2); opModM(addr, xmm, 0x0F, 0B11110000);
    }
    void movnti(Address addr, Reg32e reg)
    {
        opModM(addr, reg, 0x0F, 0B11000011);
    }
    void movntq(Address addr, Mmx mmx)
    {
        if (!mmx.isMMX)
            throw new XError(ERR.BAD_COMBINATION);
        opModM(addr, mmx, 0x0F, 0B11100111);
    }
    void crc32(Reg32e reg, Operand op)
    {
        if (reg.isBit(32) && op.isBit(16))
            db(0x66);
        db(0xF2);
        opModRM(reg, op, op.isREG, op.isMEM, 0x0F, 0x38, 0xF0 | (op.isBit(8) ? 0 : 1));
    }

    void rdrand(Reg r)
    {
        if (r.isBit(8))
            throw new XError(ERR.BAD_SIZE_OF_REGISTER);
        opModR(REG(6, Kind.REG, r.getBit), r, 0x0f, 0xc7);
    }
    void rdseed(Reg r)
    {
        if (r.isBit(8))
            throw new XError(ERR.BAD_SIZE_OF_REGISTER);
        opModR(REG(7, Kind.REG, r.getBit), r, 0x0f, 0xc7);
    }

    void rorx(Reg32e r, Operand op, uint8 imm)
    {
        opGpr(r, op, REG32E(0, r.getBit), MM_0F3A | PP_F2, 0xF0, false); db(imm);
    }
    enum { NONE = 256 };
public:
    this(void* userPtr = null, size_t maxSize = DEFAULT_MAX_CODE_SIZE, Allocator * allocator = null)
    {
        super(userPtr, maxSize, allocator);
        labelMgr_.set(this);
    }

    void reset()
    {
        resetSize;
        labelMgr_.reset;
        labelMgr_.set(this);
    }

    bool hasUndefinedLabel()
    {
        return labelMgr_.hasUndefSlabel() || labelMgr_.hasUndefClabel();
    }

    override uint8* getCode()
    {
        assert(!hasUndefinedLabel);
        if (hasUndefinedLabel)
            new XError(ERR.LABEL_IS_NOT_FOUND);
        return this.top_;
    }

    void Align(int x = 16)
    {
        if (x == 1)
            return;
        if (x < 1 || (x & (x - 1)))
            throw new XError(ERR.BAD_ALIGN);
        if (isAutoGrow() && x > cast(int) inner.ALIGN_PAGE_SIZE)
        {
            throw new Exception("warning:autoGrow mode does not support %d align".format(x));
        }
        while (cast(size_t) getCurr % x)
        {
            nop();
        }
    }


    string getVersionString()
    {
        return "0.051";
    }
    void packssdw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x6B);
    }
    void packsswb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x63);
    }
    void packuswb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x67);
    }
    void pand(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xDB);
    }
    void pandn(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xDF);
    }
    void pmaddwd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xF5);
    }
    void pmulhuw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xE4);
    }
    void pmulhw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xE5);
    }
    void pmullw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xD5);
    }
    void por(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xEB);
    }
    void punpckhbw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x68);
    }
    void punpckhwd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x69);
    }
    void punpckhdq(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x6A);
    }
    void punpcklbw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x60);
    }
    void punpcklwd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x61);
    }
    void punpckldq(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x62);
    }
    void pxor(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xEF);
    }
    void pavgb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xE0);
    }
    void pavgw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xE3);
    }
    void pmaxsw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xEE);
    }
    void pmaxub(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xDE);
    }
    void pminsw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xEA);
    }
    void pminub(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xDA);
    }
    void psadbw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xF6);
    }
    void paddq(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xD4);
    }
    void pmuludq(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xF4);
    }
    void psubq(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xFB);
    }
    void paddb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xFC);
    }
    void paddw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xFD);
    }
    void paddd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xFE);
    }
    void paddsb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xEC);
    }
    void paddsw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xED);
    }
    void paddusb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xDC);
    }
    void paddusw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xDD);
    }
    void pcmpeqb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x74);
    }
    void pcmpeqw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x75);
    }
    void pcmpeqd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x76);
    }
    void pcmpgtb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x64);
    }
    void pcmpgtw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x65);
    }
    void pcmpgtd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x66);
    }
    void psllw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xF1);
    }
    void pslld(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xF2);
    }
    void psllq(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xF3);
    }
    void psraw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xE1);
    }
    void psrad(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xE2);
    }
    void psrlw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xD1);
    }
    void psrld(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xD2);
    }
    void psrlq(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xD3);
    }
    void psubb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xF8);
    }
    void psubw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xF9);
    }
    void psubd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xFA);
    }
    void psubsb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xE8);
    }
    void psubsw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xE9);
    }
    void psubusb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xD8);
    }
    void psubusw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0xD9);
    }
    void psllw(Mmx mmx, int imm8)
    {
        opMMX_IMM(mmx, imm8, 0x71, 6);
    }
    void pslld(Mmx mmx, int imm8)
    {
        opMMX_IMM(mmx, imm8, 0x72, 6);
    }
    void psllq(Mmx mmx, int imm8)
    {
        opMMX_IMM(mmx, imm8, 0x73, 6);
    }
    void psraw(Mmx mmx, int imm8)
    {
        opMMX_IMM(mmx, imm8, 0x71, 4);
    }
    void psrad(Mmx mmx, int imm8)
    {
        opMMX_IMM(mmx, imm8, 0x72, 4);
    }
    void psrlw(Mmx mmx, int imm8)
    {
        opMMX_IMM(mmx, imm8, 0x71, 2);
    }
    void psrld(Mmx mmx, int imm8)
    {
        opMMX_IMM(mmx, imm8, 0x72, 2);
    }
    void psrlq(Mmx mmx, int imm8)
    {
        opMMX_IMM(mmx, imm8, 0x73, 2);
    }
    void pslldq(Xmm xmm, int imm8)
    {
        opMMX_IMM(xmm, imm8, 0x73, 7);
    }
    void psrldq(Xmm xmm, int imm8)
    {
        opMMX_IMM(xmm, imm8, 0x73, 3);
    }
    void pshufw(Mmx mmx, Operand op, uint8 imm8)
    {
        opMMX(mmx, op, 0x70, 0x00, imm8);
    }
    void pshuflw(Mmx mmx, Operand op, uint8 imm8)
    {
        opMMX(mmx, op, 0x70, 0xF2, imm8);
    }
    void pshufhw(Mmx mmx, Operand op, uint8 imm8)
    {
        opMMX(mmx, op, 0x70, 0xF3, imm8);
    }
    void pshufd(Mmx mmx, Operand op, uint8 imm8)
    {
        opMMX(mmx, op, 0x70, 0x66, imm8);
    }
    void movdqa(Xmm xmm, Operand op)
    {
        opMMX(xmm, op, 0x6F, 0x66);
    }
    void movdqa(Address addr, Xmm xmm)
    {
        db(0x66); opModM(addr, xmm, 0x0F, 0x7F);
    }
    void movdqu(Xmm xmm, Operand op)
    {
        opMMX(xmm, op, 0x6F, 0xF3);
    }
    void movdqu(Address addr, Xmm xmm)
    {
        db(0xF3); opModM(addr, xmm, 0x0F, 0x7F);
    }
    void movaps(Xmm xmm, Operand op)
    {
        opMMX(xmm, op, 0x28, 0x100);
    }
    void movaps(Address addr, Xmm xmm)
    {
        opModM(addr, xmm, 0x0F, 0x29);
    }
    void movss(Xmm xmm, Operand op)
    {
        opMMX(xmm, op, 0x10, 0xF3);
    }
    void movss(Address addr, Xmm xmm)
    {
        db(0xF3); opModM(addr, xmm, 0x0F, 0x11);
    }
    void movups(Xmm xmm, Operand op)
    {
        opMMX(xmm, op, 0x10, 0x100);
    }
    void movups(Address addr, Xmm xmm)
    {
        opModM(addr, xmm, 0x0F, 0x11);
    }
    void movapd(Xmm xmm, Operand op)
    {
        opMMX(xmm, op, 0x28, 0x66);
    }
    void movapd(Address addr, Xmm xmm)
    {
        db(0x66); opModM(addr, xmm, 0x0F, 0x29);
    }
    void movsd(Xmm xmm, Operand op)
    {
        opMMX(xmm, op, 0x10, 0xF2);
    }
    void movsd(Address addr, Xmm xmm)
    {
        db(0xF2); opModM(addr, xmm, 0x0F, 0x11);
    }
    void movupd(Xmm xmm, Operand op)
    {
        opMMX(xmm, op, 0x10, 0x66);
    }
    void movupd(Address addr, Xmm xmm)
    {
        db(0x66); opModM(addr, xmm, 0x0F, 0x11);
    }
    void addps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x58, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void addss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x58, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void addpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x58, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void addsd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x58, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void andnps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x55, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void andnpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x55, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void andps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x54, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void andpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x54, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void cmpps(Xmm xmm, Operand op, uint8 imm8)
    {
        opGen(xmm, op, 0xC2, 0x100, isXMM_XMMorMEM(xmm, op), imm8);
    }
    void cmpss(Xmm xmm, Operand op, uint8 imm8)
    {
        opGen(xmm, op, 0xC2, 0xF3, isXMM_XMMorMEM(xmm, op), imm8);
    }
    void cmppd(Xmm xmm, Operand op, uint8 imm8)
    {
        opGen(xmm, op, 0xC2, 0x66, isXMM_XMMorMEM(xmm, op), imm8);
    }
    void cmpsd(Xmm xmm, Operand op, uint8 imm8)
    {
        opGen(xmm, op, 0xC2, 0xF2, isXMM_XMMorMEM(xmm, op), imm8);
    }
    void divps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5E, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void divss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5E, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void divpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5E, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void divsd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5E, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void maxps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5F, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void maxss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5F, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void maxpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5F, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void maxsd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5F, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void minps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5D, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void minss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5D, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void minpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5D, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void minsd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5D, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void mulps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x59, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void mulss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x59, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void mulpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x59, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void mulsd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x59, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void orps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x56, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void orpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x56, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void rcpps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x53, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void rcpss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x53, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void rsqrtps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x52, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void rsqrtss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x52, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void shufps(Xmm xmm, Operand op, uint8 imm8)
    {
        opGen(xmm, op, 0xC6, 0x100, isXMM_XMMorMEM(xmm, op), imm8);
    }
    void shufpd(Xmm xmm, Operand op, uint8 imm8)
    {
        opGen(xmm, op, 0xC6, 0x66, isXMM_XMMorMEM(xmm, op), imm8);
    }
    void sqrtps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x51, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void sqrtss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x51, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void sqrtpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x51, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void sqrtsd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x51, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void subps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5C, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void subss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5C, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void subpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5C, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void subsd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5C, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void unpckhps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x15, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void unpckhpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x15, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void unpcklps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x14, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void unpcklpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x14, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void xorps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x57, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void xorpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x57, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void maskmovdqu(Xmm reg1, Xmm reg2)
    {
        db(0x66);  opModR(reg1, reg2, 0x0F, 0xF7);
    }
    void movhlps(Xmm reg1, Xmm reg2)
    {
        opModR(reg1, reg2, 0x0F, 0x12);
    }
    void movlhps(Xmm reg1, Xmm reg2)
    {
        opModR(reg1, reg2, 0x0F, 0x16);
    }
    void punpckhqdq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x6D, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void punpcklqdq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x6C, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void comiss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x2F, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void ucomiss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x2E, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void comisd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x2F, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void ucomisd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x2E, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void cvtpd2ps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5A, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void cvtps2pd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5A, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void cvtsd2ss(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5A, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void cvtss2sd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5A, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void cvtpd2dq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0xE6, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void cvttpd2dq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0xE6, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void cvtdq2pd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0xE6, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void cvtps2dq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5B, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void cvttps2dq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5B, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void cvtdq2ps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x5B, 0x100, isXMM_XMMorMEM(xmm, op));
    }
    void addsubpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0xD0, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void addsubps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0xD0, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void haddpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x7C, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void haddps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x7C, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void hsubpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x7D, 0x66, isXMM_XMMorMEM(xmm, op));
    }
    void hsubps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x7D, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void movddup(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x12, 0xF2, isXMM_XMMorMEM(xmm, op));
    }
    void movshdup(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x16, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void movsldup(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x12, 0xF3, isXMM_XMMorMEM(xmm, op));
    }
    void cvtpi2ps(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2A, 0x100, isXMM_XMMorMEM(reg, op));
    }
    void cvtps2pi(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2D, 0x100, isMMX_XMMorMEM(reg, op));
    }
    void cvtsi2ss(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2A, 0xF3, isXMM_REG32orMEM(reg, op));
    }
    void cvtss2si(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2D, 0xF3, isREG32_XMMorMEM(reg, op));
    }
    void cvttps2pi(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2C, 0x100, isMMX_XMMorMEM(reg, op));
    }
    void cvttss2si(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2C, 0xF3, isREG32_XMMorMEM(reg, op));
    }
    void cvtpi2pd(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2A, 0x66, isXMM_XMMorMEM(reg, op));
    }
    void cvtpd2pi(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2D, 0x66, isMMX_XMMorMEM(reg, op));
    }
    void cvtsi2sd(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2A, 0xF2, isXMM_REG32orMEM(reg, op));
    }
    void cvtsd2si(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2D, 0xF2, isREG32_XMMorMEM(reg, op));
    }
    void cvttpd2pi(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2C, 0x66, isMMX_XMMorMEM(reg, op));
    }
    void cvttsd2si(Operand reg, Operand op)
    {
        opGen(reg, op, 0x2C, 0xF2, isREG32_XMMorMEM(reg, op));
    }
    void prefetcht0(Address addr)
    {
        opModM(addr, REG32(1), 0x0F, 0B00011000);
    }
    void prefetcht1(Address addr)
    {
        opModM(addr, REG32(2), 0x0F, 0B00011000);
    }
    void prefetcht2(Address addr)
    {
        opModM(addr, REG32(3), 0x0F, 0B00011000);
    }
    void prefetchnta(Address addr)
    {
        opModM(addr, REG32(0), 0x0F, 0B00011000);
    }
    void movhps(Operand op1, Operand op2)
    {
        opMovXMM(op1, op2, 0x16, 0x100);
    }
    void movlps(Operand op1, Operand op2)
    {
        opMovXMM(op1, op2, 0x12, 0x100);
    }
    void movhpd(Operand op1, Operand op2)
    {
        opMovXMM(op1, op2, 0x16, 0x66);
    }
    void movlpd(Operand op1, Operand op2)
    {
        opMovXMM(op1, op2, 0x12, 0x66);
    }
    void cmovo(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM, 0x0F, 0B01000000 | 0);
    }
    void jo(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x70, 0x80, 0x0F);
    }
    void seto(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 0);
    }
    void cmovno(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 1);
    }
    void jno(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x71, 0x81, 0x0F);
    }
    void setno(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 1);
    }
    void cmovb(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 2);
    }
    void jb(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x72, 0x82, 0x0F);
    }
    void setb(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 2);
    }
    void cmovc(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 2);
    }
    void jc(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x72, 0x82, 0x0F);
    }
    void setc(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 2);
    }
    void cmovnae(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 2);
    }
    void jnae(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x72, 0x82, 0x0F);
    }
    void setnae(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 2);
    }
    void cmovnb(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 3);
    }
    void jnb(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x73, 0x83, 0x0F);
    }
    void setnb(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 3);
    }
    void cmovae(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 3);
    }
    void jae(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x73, 0x83, 0x0F);
    }
    void setae(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 3);
    }
    void cmovnc(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 3);
    }
    void jnc(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x73, 0x83, 0x0F);
    }
    void setnc(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 3);
    }
    void cmove(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 4);
    }
    void je(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x74, 0x84, 0x0F);
    }
    void sete(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 4);
    }
    void cmovz(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 4);
    }
    void jz(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x74, 0x84, 0x0F);
    }
    void setz(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 4);
    }
    void cmovne(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 5);
    }
    void jne(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x75, 0x85, 0x0F);
    }
    void setne(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 5);
    }
    void cmovnz(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 5);
    }
    void jnz(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x75, 0x85, 0x0F);
    }
    void setnz(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 5);
    }
    void cmovbe(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 6);
    }
    void jbe(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x76, 0x86, 0x0F);
    }
    void setbe(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 6);
    }
    void cmovna(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 6);
    }
    void jna(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x76, 0x86, 0x0F);
    }
    void setna(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 6);
    }
    void cmovnbe(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 7);
    }
    void jnbe(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x77, 0x87, 0x0F);
    }
    void setnbe(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 7);
    }
    void cmova(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 7);
    }
    void ja(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x77, 0x87, 0x0F);
    }
    void seta(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 7);
    }
    void cmovs(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 8);
    }
    void js(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x78, 0x88, 0x0F);
    }
    void sets(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 8);
    }
    void cmovns(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 9);
    }
    void jns(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x79, 0x89, 0x0F);
    }
    void setns(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 9);
    }
    void cmovp(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 10);
    }
    void jp(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7A, 0x8A, 0x0F);
    }
    void setp(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 10);
    }
    void cmovpe(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 10);
    }
    void jpe(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7A, 0x8A, 0x0F);
    }
    void setpe(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 10);
    }
    void cmovnp(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 11);
    }

    void jnp(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7B, 0x8B, 0x0F);
    }
    void setnp(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 11);
    }
    void cmovpo(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 11);
    }
    void jpo(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7B, 0x8B, 0x0F);
    }
    void setpo(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 11);
    }
    void cmovl(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 12);
    }
    void jl(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7C, 0x8C, 0x0F);
    }
    void setl(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 12);
    }
    void cmovnge(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 12);
    }
    void jnge(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7C, 0x8C, 0x0F);
    }
    void setnge(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 12);
    }
    void cmovnl(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 13);
    }
    void jnl(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7D, 0x8D, 0x0F);
    }
    void setnl(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 13);
    }
    void cmovge(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 13);
    }
    void jge(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7D, 0x8D, 0x0F);
    }
    void setge(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 13);
    }
    void cmovle(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 14);
    }
    void jle(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7E, 0x8E, 0x0F);
    }
    void setle(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 14);
    }
    void cmovng(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 14);
    }
    void jng(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7E, 0x8E, 0x0F);
    }
    void setng(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 14);
    }
    void cmovnle(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 15);
    }
    void jnle(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7F, 0x8F, 0x0F);
    }
    void setnle(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 15);
    }
    void cmovg(Reg32e reg, Operand op)
    {
        opModRM(reg, op, op.isREG(i32e), op.isMEM(), 0x0F, 0B01000000 | 15);
    }
    void jg(T)(T label, LabelType type = LabelType.T_AUTO) if (is(T == string) || is(T == Label))
    {
        opJmp(label, type, 0x7F, 0x8F, 0x0F);
    }
    void setg(Operand op)
    {
        opR_ModM(op, 8, 0, 0x0F, 0B10010000 | 15);
    }
    version(XBYAK32)
    {
        void jcxz(T)(T label) if (is(T == string) || is(T == Label))
        {
            db(0x67); opJmp(label, LabelType.T_SHORT, 0xe3, 0, 0);
        }
        void jecxz(T)(T label) if (is(T == string) || is(T == Label))
        {
            opJmp(label, LabelType.T_SHORT, 0xe3, 0, 0);
        }
    }
    else
    {
        void jecxz(T)(T label) if (is(T == string) || is(T == Label))
        {
            db(0x67); opJmp(label, LabelType.T_SHORT, 0xe3, 0, 0);
        }
        void jrcxz(T)(T label) if (is(T == string) || is(T == Label))
        {
            opJmp(label, LabelType.T_SHORT, 0xe3, 0, 0);
        }
    }
    version(XBYAK64)
    {
        void cdqe()
        {
            db(0x48); db(0x98);
        }
        void cqo()
        {
            db(0x48); db(0x99);
        }
    }
    else
    {
        void aaa()
        {
            db(0x37);
        }
        void aad()
        {
            db(0xD5); db(0x0A);
        }
        void aam()
        {
            db(0xD4); db(0x0A);
        }
        void aas()
        {
            db(0x3F);
        }
        void daa()
        {
            db(0x27);
        }
        void das()
        {
            db(0x2F);
        }
        void popad()
        {
            db(0x61);
        }
        void popfd()
        {
            db(0x9D);
        }
        void pusha()
        {
            db(0x60);
        }
        void pushad()
        {
            db(0x60);
        }
        void pushfd()
        {
            db(0x9C);
        }
        void popa()
        {
            db(0x61);
        }
    }
    void cbw()
    {
        db(0x66); db(0x98);
    }
    void cdq()
    {
        db(0x99);
    }
    void clc()
    {
        db(0xF8);
    }
    void cld()
    {
        db(0xFC);
    }
    void cli()
    {
        db(0xFA);
    }
    void cmc()
    {
        db(0xF5);
    }
    void cpuid()
    {
        db(0x0F); db(0xA2);
    }
    void cwd()
    {
        db(0x66); db(0x99);
    }
    void cwde()
    {
        db(0x98);
    }
    void lahf()
    {
        db(0x9F);
    }
    void lock()
    {
        db(0xF0);
    }
    void nop()
    {
        db(0x90);
    }
    void sahf()
    {
        db(0x9E);
    }
    void stc()
    {
        db(0xF9);
    }
    void std()
    {
        db(0xFD);
    }
    void sti()
    {
        db(0xFB);
    }
    void emms()
    {
        db(0x0F); db(0x77);
    }
    void pause()
    {
        db(0xF3); db(0x90);
    }
    void sfence()
    {
        db(0x0F); db(0xAE); db(0xF8);
    }
    void lfence()
    {
        db(0x0F); db(0xAE); db(0xE8);
    }
    void mfence()
    {
        db(0x0F); db(0xAE); db(0xF0);
    }
    void monitor()
    {
        db(0x0F); db(0x01); db(0xC8);
    }
    void mwait()
    {
        db(0x0F); db(0x01); db(0xC9);
    }
    void rdmsr()
    {
        db(0x0F); db(0x32);
    }
    void rdpmc()
    {
        db(0x0F); db(0x33);
    }
    void rdtsc()
    {
        db(0x0F); db(0x31);
    }
    void rdtscp()
    {
        db(0x0F); db(0x01); db(0xF9);
    }
    void ud2()
    {
        db(0x0F); db(0x0B);
    }
    void wait()
    {
        db(0x9B);
    }
    void fwait()
    {
        db(0x9B);
    }
    void wbinvd()
    {
        db(0x0F); db(0x09);
    }
    void wrmsr()
    {
        db(0x0F); db(0x30);
    }
    void xlatb()
    {
        db(0xD7);
    }
    void popf()
    {
        db(0x9D);
    }
    void pushf()
    {
        db(0x9C);
    }
    void stac()
    {
        db(0x0F); db(0x01); db(0xCB);
    }
    void vzeroall()
    {
        db(0xC5); db(0xFC); db(0x77);
    }
    void vzeroupper()
    {
        db(0xC5); db(0xF8); db(0x77);
    }
    void xgetbv()
    {
        db(0x0F); db(0x01); db(0xD0);
    }
    void f2xm1()
    {
        db(0xD9); db(0xF0);
    }
    void fabs()
    {
        db(0xD9); db(0xE1);
    }
    void faddp()
    {
        db(0xDE); db(0xC1);
    }
    void fchs()
    {
        db(0xD9); db(0xE0);
    }
    void fcom()
    {
        db(0xD8); db(0xD1);
    }
    void fcomp()
    {
        db(0xD8); db(0xD9);
    }
    void fcompp()
    {
        db(0xDE); db(0xD9);
    }
    void fcos()
    {
        db(0xD9); db(0xFF);
    }
    void fdecstp()
    {
        db(0xD9); db(0xF6);
    }
    void fdivp()
    {
        db(0xDE); db(0xF9);
    }
    void fdivrp()
    {
        db(0xDE); db(0xF1);
    }
    void fincstp()
    {
        db(0xD9); db(0xF7);
    }
    void finit()
    {
        db(0x9B); db(0xDB); db(0xE3);
    }
    void fninit()
    {
        db(0xDB); db(0xE3);
    }
    void fld1()
    {
        db(0xD9); db(0xE8);
    }
    void fldl2t()
    {
        db(0xD9); db(0xE9);
    }
    void fldl2e()
    {
        db(0xD9); db(0xEA);
    }
    void fldpi()
    {
        db(0xD9); db(0xEB);
    }
    void fldlg2()
    {
        db(0xD9); db(0xEC);
    }
    void fldln2()
    {
        db(0xD9); db(0xED);
    }
    void fldz()
    {
        db(0xD9); db(0xEE);
    }
    void fmulp()
    {
        db(0xDE); db(0xC9);
    }
    void fnop()
    {
        db(0xD9); db(0xD0);
    }
    void fpatan()
    {
        db(0xD9); db(0xF3);
    }
    void fprem()
    {
        db(0xD9); db(0xF8);
    }
    void fprem1()
    {
        db(0xD9); db(0xF5);
    }
    void fptan()
    {
        db(0xD9); db(0xF2);
    }
    void frndint()
    {
        db(0xD9); db(0xFC);
    }
    void fscale()
    {
        db(0xD9); db(0xFD);
    }
    void fsin()
    {
        db(0xD9); db(0xFE);
    }
    void fsincos()
    {
        db(0xD9); db(0xFB);
    }
    void fsqrt()
    {
        db(0xD9); db(0xFA);
    }
    void fsubp()
    {
        db(0xDE); db(0xE9);
    }
    void fsubrp()
    {
        db(0xDE); db(0xE1);
    }
    void ftst()
    {
        db(0xD9); db(0xE4);
    }
    void fucom()
    {
        db(0xDD); db(0xE1);
    }
    void fucomp()
    {
        db(0xDD); db(0xE9);
    }
    void fucompp()
    {
        db(0xDA); db(0xE9);
    }
    void fxam()
    {
        db(0xD9); db(0xE5);
    }
    void fxch()
    {
        db(0xD9); db(0xC9);
    }
    void fxtract()
    {
        db(0xD9); db(0xF4);
    }
    void fyl2x()
    {
        db(0xD9); db(0xF1);
    }
    void fyl2xp1()
    {
        db(0xD9); db(0xF9);
    }
    void adc(Operand op1, Operand op2)
    {
        opRM_RM(op1, op2, 0x10);
    }
    void adc(Operand op, uint32 imm)
    {
        opRM_I(op, imm, 0x10, 2);
    }
    void add(Operand op1, Operand op2)
    {
        opRM_RM(op1, op2, 0x00);
    }
    void add(Operand op, uint32 imm)
    {
        opRM_I(op, imm, 0x00, 0);
    }

    void and(Operand op1, Operand op2)
    {
        opRM_RM(op1, op2, 0x20);
    }
    void and(Operand op, uint32 imm)
    {
        opRM_I(op, imm, 0x20, 4);
    }
    void cmp(Operand op1, Operand op2)
    {
        opRM_RM(op1, op2, 0x38);
    }
    void cmp(Operand op, uint32 imm)
    {
        opRM_I(op, imm, 0x38, 7);
    }

    void or(Operand op1, Operand op2)
    {
        opRM_RM(op1, op2, 0x08);
    }
    void or(Operand op, uint32 imm)
    {
        opRM_I(op, imm, 0x08, 1);
    }

    void sbb(Operand op1, Operand op2)
    {
        opRM_RM(op1, op2, 0x18);
    }
    void sbb(Operand op, uint32 imm)
    {
        opRM_I(op, imm, 0x18, 3);
    }
    void sub(Operand op1, Operand op2)
    {
        opRM_RM(op1, op2, 0x28);
    }
    void sub(Operand op, uint32 imm)
    {
        opRM_I(op, imm, 0x28, 5);
    }

    void xor (Operand op1, Operand op2)
    {
        opRM_RM(op1, op2, 0x30);
    }
    void xor (Operand op, uint32 imm)
    {
        opRM_I(op, imm, 0x30, 6);
    }

    void dec(Operand op)
    {
        opIncDec(op, 0x48, 1);
    }
    void inc(Operand op)
    {
        opIncDec(op, 0x40, 0);
    }
    void bt(Operand op, Reg reg)
    {
        opModRM(reg, op, op.isREG(16 | 32 | 64), op.getBit() == reg.getBit(), op.isMEM(), 0x0f, 0xa3);
    }
    void bt(Operand op, uint8 imm)
    {
        opR_ModM(op, 16 | 32 | 64, 4, 0x0f, 0xba); db(imm);
    }
    void bts(Operand op, Reg reg)
    {
        opModRM(reg, op, op.isREG(16 | 32 | 64), op.getBit() == reg.getBit(), op.isMEM(), 0x0f, 0xab);
    }
    void bts(Operand op, uint8 imm)
    {
        opR_ModM(op, 16 | 32 | 64, 5, 0x0f, 0xba); db(imm);
    }
    void btr(Operand op, Reg reg)
    {
        opModRM(reg, op, op.isREG(16 | 32 | 64), op.getBit() == reg.getBit(), op.isMEM(), 0x0f, 0xb3);
    }
    void btr(Operand op, uint8 imm)
    {
        opR_ModM(op, 16 | 32 | 64, 6, 0x0f, 0xba); db(imm);
    }
    void btc(Operand op, Reg reg)
    {
        opModRM(reg, op, op.isREG(16 | 32 | 64), op.getBit() == reg.getBit(), op.isMEM(), 0x0f, 0xbb);
    }
    void btc(Operand op, uint8 imm)
    {
        opR_ModM(op, 16 | 32 | 64, 7, 0x0f, 0xba); db(imm);
    }
    void div(Operand op)
    {
        opR_ModM(op, 0, 6, 0xF6);
    }
    void idiv(Operand op)
    {
        opR_ModM(op, 0, 7, 0xF6);
    }
    void imul(Operand op)
    {
        opR_ModM(op, 0, 5, 0xF6);
    }
    void mul(Operand op)
    {
        opR_ModM(op, 0, 4, 0xF6);
    }
    void neg(Operand op)
    {
        opR_ModM(op, 0, 3, 0xF6);
    }
    void not (Operand op)
    {
        opR_ModM(op, 0, 2, 0xF6);
    }

    void rcl(Operand op, int imm)
    {
        opShift(op, imm, 2);
    }
    void rcl(Operand op, Reg8 cl)
    {
        opShift(op, cl, 2);
    }
    void rcr(Operand op, int imm)
    {
        opShift(op, imm, 3);
    }
    void rcr(Operand op, Reg8 cl)
    {
        opShift(op, cl, 3);
    }
    void rol(Operand op, int imm)
    {
        opShift(op, imm, 0);
    }
    void rol(Operand op, Reg8 cl)
    {
        opShift(op, cl, 0);
    }
    void ror(Operand op, int imm)
    {
        opShift(op, imm, 1);
    }
    void ror(Operand op, Reg8 cl)
    {
        opShift(op, cl, 1);
    }
    void sar(Operand op, int imm)
    {
        opShift(op, imm, 7);
    }
    void sar(Operand op, Reg8 cl)
    {
        opShift(op, cl, 7);
    }
    void shl(Operand op, int imm)
    {
        opShift(op, imm, 4);
    }
    void shl(Operand op, Reg8 cl)
    {
        opShift(op, cl, 4);
    }
    void shr(Operand op, int imm)
    {
        opShift(op, imm, 5);
    }
    void shr(Operand op, Reg8 cl)
    {
        opShift(op, cl, 5);
    }
    void sal(Operand op, int imm)
    {
        opShift(op, imm, 4);
    }
    void sal(Operand op, Reg8 cl)
    {
        opShift(op, cl, 4);
    }
    void shld(Operand op, Reg reg, uint8 imm)
    {
        opShxd(op, reg, imm, 0xA4);
    }
    void shld(Operand op, Reg reg, Reg8 cl)
    {
        opShxd(op, reg, 0, 0xA4, cl);
    }
    void shrd(Operand op, Reg reg, uint8 imm)
    {
        opShxd(op, reg, imm, 0xAC);
    }
    void shrd(Operand op, Reg reg, Reg8 cl)
    {
        opShxd(op, reg, 0, 0xAC, cl);
    }
    void bsf(Reg reg, Operand op)
    {
        opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0xBC);
    }
    void bsr(Reg reg, Operand op)
    {
        opModRM(reg, op, op.isREG(16 | i32e), op.isMEM(), 0x0F, 0xBD);
    }
    void popcnt(Reg reg, Operand op)
    {
        opSp1(reg, op, 0xF3, 0x0F, 0xB8);
    }
    void tzcnt(Reg reg, Operand op)
    {
        opSp1(reg, op, 0xF3, 0x0F, 0xBC);
    }
    void lzcnt(Reg reg, Operand op)
    {
        opSp1(reg, op, 0xF3, 0x0F, 0xBD);
    }
    void pshufb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x00, 0x66, NONE, 0x38);
    }
    void phaddw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x01, 0x66, NONE, 0x38);
    }
    void phaddd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x02, 0x66, NONE, 0x38);
    }
    void phaddsw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x03, 0x66, NONE, 0x38);
    }
    void pmaddubsw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x04, 0x66, NONE, 0x38);
    }
    void phsubw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x05, 0x66, NONE, 0x38);
    }
    void phsubd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x06, 0x66, NONE, 0x38);
    }
    void phsubsw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x07, 0x66, NONE, 0x38);
    }
    void psignb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x08, 0x66, NONE, 0x38);
    }
    void psignw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x09, 0x66, NONE, 0x38);
    }
    void psignd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x0A, 0x66, NONE, 0x38);
    }
    void pmulhrsw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x0B, 0x66, NONE, 0x38);
    }
    void pabsb(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x1C, 0x66, NONE, 0x38);
    }
    void pabsw(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x1D, 0x66, NONE, 0x38);
    }
    void pabsd(Mmx mmx, Operand op)
    {
        opMMX(mmx, op, 0x1E, 0x66, NONE, 0x38);
    }
    void palignr(Mmx mmx, Operand op, int imm)
    {
        opMMX(mmx, op, 0x0f, 0x66, cast(uint8) (imm), 0x3a);
    }
    void blendvpd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x15, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void blendvps(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x14, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void packusdw(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x2B, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pblendvb(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x10, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pcmpeqq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x29, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void ptest(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x17, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovsxbw(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x20, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovsxbd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x21, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovsxbq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x22, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovsxwd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x23, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovsxwq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x24, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovsxdq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x25, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovzxbw(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x30, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovzxbd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x31, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovzxbq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x32, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovzxwd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x33, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovzxwq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x34, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmovzxdq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x35, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pminsb(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x38, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pminsd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x39, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pminuw(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x3A, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pminud(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x3B, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmaxsb(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x3C, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmaxsd(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x3D, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmaxuw(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x3E, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmaxud(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x3F, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmuldq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x28, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pmulld(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x40, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void phminposuw(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x41, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void pcmpgtq(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0x37, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void aesdec(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0xDE, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void aesdeclast(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0xDF, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void aesenc(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0xDC, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void aesenclast(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0xDD, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void aesimc(Xmm xmm, Operand op)
    {
        opGen(xmm, op, 0xDB, 0x66, isXMM_XMMorMEM(xmm, op), NONE, 0x38);
    }
    void blendpd(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x0D, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void blendps(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x0C, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void dppd(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x41, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void dpps(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x40, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void mpsadbw(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x42, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void pblendw(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x0E, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void roundps(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x08, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void roundpd(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x09, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void roundss(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x0A, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void roundsd(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x0B, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void pcmpestrm(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x60, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void pcmpestri(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x61, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void pcmpistrm(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x62, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void pcmpistri(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x63, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void pclmulqdq(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0x44, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void aeskeygenassist(Xmm xmm, Operand op, int imm)
    {
        opGen(xmm, op, 0xDF, 0x66, isXMM_XMMorMEM(xmm, op), cast(uint8) imm, 0x3A);
    }
    void pclmullqlqdq(Xmm xmm, Operand op)
    {
        pclmulqdq(xmm, op, 0x00);
    }
    void pclmulhqlqdq(Xmm xmm, Operand op)
    {
        pclmulqdq(xmm, op, 0x01);
    }
    void pclmullqhdq(Xmm xmm, Operand op)
    {
        pclmulqdq(xmm, op, 0x10);
    }
    void pclmulhqhdq(Xmm xmm, Operand op)
    {
        pclmulqdq(xmm, op, 0x11);
    }
    void ldmxcsr(Address addr)
    {
        opModM(addr, REG32(2), 0x0F, 0xAE);
    }
    void stmxcsr(Address addr)
    {
        opModM(addr, REG32(3), 0x0F, 0xAE);
    }
    void clflush(Address addr)
    {
        opModM(addr, REG32(7), 0x0F, 0xAE);
    }
    void fldcw(Address addr)
    {
        opModM(addr, REG32(5), 0xD9, 0x100);
    }
    void fstcw(Address addr)
    {
        db(0x9B); opModM(addr, REG32(7), 0xD9, NONE);
    }
    void movntpd(Address addr, Xmm reg)
    {
        opModM(addr, REG16(reg.getIdx), 0x0F, 0x2B);
    }
    void movntdq(Address addr, Xmm reg)
    {
        opModM(addr, REG16(reg.getIdx), 0x0F, 0xE7);
    }
    void movsx(Reg reg, Operand op)
    {
        opMovxx(reg, op, 0xBE);
    }
    void movzx(Reg reg, Operand op)
    {
        opMovxx(reg, op, 0xB6);
    }
    void fadd(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD8, 0xDC, 0, 0);
    }
    void fiadd(Address addr)
    {
        opFpuMem(addr, 0xDE, 0xDA, 0x00, 0, 0);
    }
    void fcom(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD8, 0xDC, 2, 0);
    }
    void fcomp(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD8, 0xDC, 3, 0);
    }
    void fdiv(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD8, 0xDC, 6, 0);
    }
    void fidiv(Address addr)
    {
        opFpuMem(addr, 0xDE, 0xDA, 0x00, 6, 0);
    }
    void fdivr(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD8, 0xDC, 7, 0);
    }
    void fidivr(Address addr)
    {
        opFpuMem(addr, 0xDE, 0xDA, 0x00, 7, 0);
    }
    void ficom(Address addr)
    {
        opFpuMem(addr, 0xDE, 0xDA, 0x00, 2, 0);
    }
    void ficomp(Address addr)
    {
        opFpuMem(addr, 0xDE, 0xDA, 0x00, 3, 0);
    }
    void fild(Address addr)
    {
        opFpuMem(addr, 0xDF, 0xDB, 0xDF, 0, 5);
    }
    void fist(Address addr)
    {
        opFpuMem(addr, 0xDF, 0xDB, 0x00, 2, 0);
    }
    void fistp(Address addr)
    {
        opFpuMem(addr, 0xDF, 0xDB, 0xDF, 3, 7);
    }
    void fisttp(Address addr)
    {
        opFpuMem(addr, 0xDF, 0xDB, 0xDD, 1, 0);
    }
    void fld(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD9, 0xDD, 0, 0);
    }
    void fmul(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD8, 0xDC, 1, 0);
    }
    void fimul(Address addr)
    {
        opFpuMem(addr, 0xDE, 0xDA, 0x00, 1, 0);
    }
    void fst(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD9, 0xDD, 2, 0);
    }
    void fstp(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD9, 0xDD, 3, 0);
    }
    void fsub(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD8, 0xDC, 4, 0);
    }
    void fisub(Address addr)
    {
        opFpuMem(addr, 0xDE, 0xDA, 0x00, 4, 0);
    }
    void fsubr(Address addr)
    {
        opFpuMem(addr, 0x00, 0xD8, 0xDC, 5, 0);
    }
    void fisubr(Address addr)
    {
        opFpuMem(addr, 0xDE, 0xDA, 0x00, 5, 0);
    }
    void fadd(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xD8C0, 0xDCC0);
    }
    void fadd(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xD8C0, 0xDCC0);
    }
    void faddp(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0x0000, 0xDEC0);
    }
    void faddp(Fpu reg1)
    {
        opFpuFpu(reg1, st0, 0x0000, 0xDEC0);
    }
    void fcmovb(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDAC0, 0x00C0);
    }
    void fcmovb(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDAC0, 0x00C0);
    }
    void fcmove(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDAC8, 0x00C8);
    }
    void fcmove(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDAC8, 0x00C8);
    }
    void fcmovbe(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDAD0, 0x00D0);
    }
    void fcmovbe(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDAD0, 0x00D0);
    }
    void fcmovu(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDAD8, 0x00D8);
    }
    void fcmovu(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDAD8, 0x00D8);
    }
    void fcmovnb(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDBC0, 0x00C0);
    }
    void fcmovnb(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDBC0, 0x00C0);
    }
    void fcmovne(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDBC8, 0x00C8);
    }
    void fcmovne(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDBC8, 0x00C8);
    }
    void fcmovnbe(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDBD0, 0x00D0);
    }
    void fcmovnbe(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDBD0, 0x00D0);
    }
    void fcmovnu(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDBD8, 0x00D8);
    }
    void fcmovnu(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDBD8, 0x00D8);
    }
    void fcomi(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDBF0, 0x00F0);
    }
    void fcomi(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDBF0, 0x00F0);
    }
    void fcomip(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDFF0, 0x00F0);
    }
    void fcomip(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDFF0, 0x00F0);
    }
    void fucomi(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDBE8, 0x00E8);
    }
    void fucomi(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDBE8, 0x00E8);
    }
    void fucomip(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xDFE8, 0x00E8);
    }
    void fucomip(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xDFE8, 0x00E8);
    }
    void fdiv(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xD8F0, 0xDCF8);
    }
    void fdiv(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xD8F0, 0xDCF8);
    }
    void fdivp(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0x0000, 0xDEF8);
    }
    void fdivp(Fpu reg1)
    {
        opFpuFpu(reg1, st0, 0x0000, 0xDEF8);
    }
    void fdivr(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xD8F8, 0xDCF0);
    }
    void fdivr(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xD8F8, 0xDCF0);
    }
    void fdivrp(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0x0000, 0xDEF0);
    }
    void fdivrp(Fpu reg1)
    {
        opFpuFpu(reg1, st0, 0x0000, 0xDEF0);
    }
    void fmul(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xD8C8, 0xDCC8);
    }
    void fmul(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xD8C8, 0xDCC8);
    }
    void fmulp(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0x0000, 0xDEC8);
    }
    void fmulp(Fpu reg1)
    {
        opFpuFpu(reg1, st0, 0x0000, 0xDEC8);
    }
    void fsub(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xD8E0, 0xDCE8);
    }
    void fsub(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xD8E0, 0xDCE8);
    }
    void fsubp(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0x0000, 0xDEE8);
    }
    void fsubp(Fpu reg1)
    {
        opFpuFpu(reg1, st0, 0x0000, 0xDEE8);
    }
    void fsubr(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0xD8E8, 0xDCE0);
    }
    void fsubr(Fpu reg1)
    {
        opFpuFpu(st0, reg1, 0xD8E8, 0xDCE0);
    }
    void fsubrp(Fpu reg1, Fpu reg2)
    {
        opFpuFpu(reg1, reg2, 0x0000, 0xDEE0);
    }
    void fsubrp(Fpu reg1)
    {
        opFpuFpu(reg1, st0, 0x0000, 0xDEE0);
    }
    void fcom(Fpu reg)
    {
        opFpu(reg, 0xD8, 0xD0);
    }
    void fcomp(Fpu reg)
    {
        opFpu(reg, 0xD8, 0xD8);
    }
    void ffree(Fpu reg)
    {
        opFpu(reg, 0xDD, 0xC0);
    }
    void fld(Fpu reg)
    {
        opFpu(reg, 0xD9, 0xC0);
    }
    void fst(Fpu reg)
    {
        opFpu(reg, 0xDD, 0xD0);
    }
    void fstp(Fpu reg)
    {
        opFpu(reg, 0xDD, 0xD8);
    }
    void fucom(Fpu reg)
    {
        opFpu(reg, 0xDD, 0xE0);
    }
    void fucomp(Fpu reg)
    {
        opFpu(reg, 0xDD, 0xE8);
    }
    void fxch(Fpu reg)
    {
        opFpu(reg, 0xD9, 0xC8);
    }
    void vaddpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x58, true);
    }
    void vaddps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F, 0x58, true);
    }
    void vaddsd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F2, 0x58, false);
    }
    void vaddss(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F3, 0x58, false);
    }
    void vsubpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x5C, true);
    }
    void vsubps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F, 0x5C, true);
    }
    void vsubsd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F2, 0x5C, false);
    }
    void vsubss(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F3, 0x5C, false);
    }
    void vmulpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x59, true);
    }
    void vmulps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F, 0x59, true);
    }
    void vmulsd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F2, 0x59, false);
    }
    void vmulss(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F3, 0x59, false);
    }
    void vdivpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x5E, true);
    }
    void vdivps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F, 0x5E, true);
    }
    void vdivsd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F2, 0x5E, false);
    }
    void vdivss(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F3, 0x5E, false);
    }
    void vmaxpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x5F, true);
    }
    void vmaxps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F, 0x5F, true);
    }
    void vmaxsd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F2, 0x5F, false);
    }
    void vmaxss(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F3, 0x5F, false);
    }
    void vminpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x5D, true);
    }
    void vminps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F, 0x5D, true);
    }
    void vminsd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F2, 0x5D, false);
    }
    void vminss(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F3, 0x5D, false);
    }
    void vandpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x54, true);
    }
    void vandps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F, 0x54, true);
    }
    void vandnpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x55, true);
    }
    void vandnps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F, 0x55, true);
    }
    void vorpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x56, true);
    }
    void vorps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F, 0x56, true);
    }
    void vxorpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x57, true);
    }
    void vxorps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F, 0x57, true);
    }
    void vblendpd(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x0D, true, 0); db(imm);
    }
    void vblendpd(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x0D, true, 0); db(imm);
    }
    void vblendps(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x0C, true, 0); db(imm);
    }
    void vblendps(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x0C, true, 0); db(imm);
    }
    void vdppd(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x41, false, 0); db(imm);
    }
    void vdppd(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x41, false, 0); db(imm);
    }
    void vdpps(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x40, true, 0); db(imm);
    }
    void vdpps(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x40, true, 0); db(imm);
    }
    void vmpsadbw(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x42, true, 0); db(imm);
    }
    void vmpsadbw(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x42, true, 0); db(imm);
    }
    void vpblendw(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x0E, true, 0); db(imm);
    }
    void vpblendw(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x0E, true, 0); db(imm);
    }
    void vpblendd(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x02, true, 0); db(imm);
    }
    void vpblendd(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x02, true, 0); db(imm);
    }
    void vroundsd(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x0B, false, 0); db(imm);
    }
    void vroundsd(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x0B, false, 0); db(imm);
    }
    void vroundss(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x0A, false, 0); db(imm);
    }
    void vroundss(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x0A, false, 0); db(imm);
    }
    void vpclmulqdq(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x44, false, 0); db(imm);
    }
    void vpclmulqdq(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x44, false, 0); db(imm);
    }
    void vpermilps(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x0C, true, 0);
    }
    void vpermilpd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x0D, true, 0);
    }
    void vpsllvd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x47, true, 0);
    }
    void vpsllvq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x47, true, 1);
    }
    void vpsravd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x46, true, 0);
    }
    void vpsrlvd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x45, true, 0);
    }
    void vpsrlvq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x45, true, 1);
    }
    void vcmppd(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xC2, true, -1); db(imm);
    }
    void vcmppd(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xC2, true, -1); db(imm);
    }
    void vcmpps(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F, 0xC2, true, -1); db(imm);
    }
    void vcmpps(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F, 0xC2, true, -1); db(imm);
    }
    void vcmpsd(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_F2, 0xC2, false, -1); db(imm);
    }
    void vcmpsd(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_F2, 0xC2, false, -1); db(imm);
    }
    void vcmpss(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_F3, 0xC2, false, -1); db(imm);
    }
    void vcmpss(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_F3, 0xC2, false, -1); db(imm);
    }
    void vcvtsd2ss(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_F2, 0x5A, false, -1);
    }
    void vcvtsd2ss(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_F2, 0x5A, false, -1);
    }
    void vcvtss2sd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_F3, 0x5A, false, -1);
    }
    void vcvtss2sd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_F3, 0x5A, false, -1);
    }
    void vinsertps(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x21, false, 0); db(imm);
    }
    void vinsertps(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x21, false, 0); db(imm);
    }
    void vpacksswb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x63, true, -1);
    }
    void vpacksswb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x63, true, -1);
    }
    void vpackssdw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x6B, true, -1);
    }
    void vpackssdw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x6B, true, -1);
    }
    void vpackuswb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x67, true, -1);
    }
    void vpackuswb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x67, true, -1);
    }
    void vpackusdw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x2B, true, -1);
    }
    void vpackusdw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x2B, true, -1);
    }
    void vpaddb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xFC, true, -1);
    }
    void vpaddb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xFC, true, -1);
    }
    void vpaddw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xFD, true, -1);
    }
    void vpaddw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xFD, true, -1);
    }
    void vpaddd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xFE, true, -1);
    }
    void vpaddd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xFE, true, -1);
    }
    void vpaddq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xD4, true, -1);
    }
    void vpaddq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xD4, true, -1);
    }
    void vpaddsb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xEC, true, -1);
    }
    void vpaddsb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xEC, true, -1);
    }
    void vpaddsw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xED, true, -1);
    }
    void vpaddsw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xED, true, -1);
    }
    void vpaddusb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xDC, true, -1);
    }
    void vpaddusb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xDC, true, -1);
    }
    void vpaddusw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xDD, true, -1);
    }
    void vpaddusw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xDD, true, -1);
    }
    void vpalignr(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x0F, true, -1); db(imm);
    }
    void vpalignr(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F3A | PP_66, 0x0F, true, -1); db(imm);
    }
    void vpand(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xDB, true, -1);
    }
    void vpand(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xDB, true, -1);
    }
    void vpandn(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xDF, true, -1);
    }
    void vpandn(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xDF, true, -1);
    }
    void vpavgb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xE0, true, -1);
    }
    void vpavgb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xE0, true, -1);
    }
    void vpavgw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xE3, true, -1);
    }
    void vpavgw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xE3, true, -1);
    }
    void vpcmpeqb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x74, true, -1);
    }
    void vpcmpeqb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x74, true, -1);
    }
    void vpcmpeqw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x75, true, -1);
    }
    void vpcmpeqw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x75, true, -1);
    }
    void vpcmpeqd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x76, true, -1);
    }
    void vpcmpeqd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x76, true, -1);
    }
    void vpcmpeqq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x29, true, -1);
    }
    void vpcmpeqq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x29, true, -1);
    }
    void vpcmpgtb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x64, true, -1);
    }
    void vpcmpgtb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x64, true, -1);
    }
    void vpcmpgtw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x65, true, -1);
    }
    void vpcmpgtw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x65, true, -1);
    }
    void vpcmpgtd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x66, true, -1);
    }
    void vpcmpgtd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x66, true, -1);
    }
    void vpcmpgtq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x37, true, -1);
    }
    void vpcmpgtq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x37, true, -1);
    }
    void vphaddw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x01, true, -1);
    }
    void vphaddw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x01, true, -1);
    }
    void vphaddd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x02, true, -1);
    }
    void vphaddd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x02, true, -1);
    }
    void vphaddsw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x03, true, -1);
    }
    void vphaddsw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x03, true, -1);
    }
    void vphsubw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x05, true, -1);
    }
    void vphsubw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x05, true, -1);
    }
    void vphsubd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x06, true, -1);
    }
    void vphsubd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x06, true, -1);
    }
    void vphsubsw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x07, true, -1);
    }
    void vphsubsw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x07, true, -1);
    }
    void vpmaddwd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xF5, true, -1);
    }
    void vpmaddwd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xF5, true, -1);
    }
    void vpmaddubsw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x04, true, -1);
    }
    void vpmaddubsw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x04, true, -1);
    }
    void vpmaxsb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x3C, true, -1);
    }
    void vpmaxsb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x3C, true, -1);
    }
    void vpmaxsw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xEE, true, -1);
    }
    void vpmaxsw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xEE, true, -1);
    }
    void vpmaxsd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x3D, true, -1);
    }
    void vpmaxsd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x3D, true, -1);
    }
    void vpmaxub(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xDE, true, -1);
    }
    void vpmaxub(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xDE, true, -1);
    }
    void vpmaxuw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x3E, true, -1);
    }
    void vpmaxuw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x3E, true, -1);
    }
    void vpmaxud(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x3F, true, -1);
    }
    void vpmaxud(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x3F, true, -1);
    }
    void vpminsb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x38, true, -1);
    }
    void vpminsb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x38, true, -1);
    }
    void vpminsw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xEA, true, -1);
    }
    void vpminsw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xEA, true, -1);
    }
    void vpminsd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x39, true, -1);
    }
    void vpminsd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x39, true, -1);
    }
    void vpminub(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xDA, true, -1);
    }
    void vpminub(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xDA, true, -1);
    }
    void vpminuw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x3A, true, -1);
    }
    void vpminuw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x3A, true, -1);
    }
    void vpminud(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x3B, true, -1);
    }
    void vpminud(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x3B, true, -1);
    }
    void vpmulhuw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xE4, true, -1);
    }
    void vpmulhuw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xE4, true, -1);
    }
    void vpmulhrsw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x0B, true, -1);
    }
    void vpmulhrsw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x0B, true, -1);
    }
    void vpmulhw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xE5, true, -1);
    }
    void vpmulhw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xE5, true, -1);
    }
    void vpmullw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xD5, true, -1);
    }
    void vpmullw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xD5, true, -1);
    }
    void vpmulld(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x40, true, -1);
    }
    void vpmulld(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x40, true, -1);
    }
    void vpmuludq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xF4, false, -1);
    }
    void vpmuludq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xF4, false, -1);
    }
    void vpmuldq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x28, true, -1);
    }
    void vpmuldq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x28, true, -1);
    }
    void vpor(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xEB, true, -1);
    }
    void vpor(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xEB, true, -1);
    }
    void vpsadbw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xF6, true, -1);
    }
    void vpsadbw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xF6, true, -1);
    }
    void vpshufb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x00, true, -1);
    }
    void vpsignb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x08, true, -1);
    }
    void vpsignb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x08, true, -1);
    }
    void vpsignw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x09, true, -1);
    }
    void vpsignw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x09, true, -1);
    }
    void vpsignd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F38 | PP_66, 0x0A, true, -1);
    }
    void vpsignd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F38 | PP_66, 0x0A, true, -1);
    }
    void vpsllw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xF1, true, -1);
    }
    void vpsllw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xF1, true, -1);
    }
    void vpslld(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xF2, true, -1);
    }
    void vpslld(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xF2, true, -1);
    }
    void vpsllq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xF3, true, -1);
    }
    void vpsllq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xF3, true, -1);
    }
    void vpsraw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xE1, true, -1);
    }
    void vpsraw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xE1, true, -1);
    }
    void vpsrad(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xE2, true, -1);
    }
    void vpsrad(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xE2, true, -1);
    }
    void vpsrlw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xD1, true, -1);
    }
    void vpsrlw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xD1, true, -1);
    }
    void vpsrld(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xD2, true, -1);
    }
    void vpsrld(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xD2, true, -1);
    }
    void vpsrlq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xD3, true, -1);
    }
    void vpsrlq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xD3, true, -1);
    }
    void vpsubb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xF8, true, -1);
    }
    void vpsubb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xF8, true, -1);
    }
    void vpsubw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xF9, true, -1);
    }
    void vpsubw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xF9, true, -1);
    }
    void vpsubd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xFA, true, -1);
    }
    void vpsubd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xFA, true, -1);
    }
    void vpsubq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xFB, true, -1);
    }
    void vpsubq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xFB, true, -1);
    }
    void vpsubsb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xE8, true, -1);
    }
    void vpsubsb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xE8, true, -1);
    }
    void vpsubsw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xE9, true, -1);
    }
    void vpsubsw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xE9, true, -1);
    }
    void vpsubusb(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xD8, true, -1);
    }
    void vpsubusb(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xD8, true, -1);
    }
    void vpsubusw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xD9, true, -1);
    }
    void vpsubusw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xD9, true, -1);
    }
    void vpunpckhbw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x68, true, -1);
    }
    void vpunpckhbw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x68, true, -1);
    }
    void vpunpckhwd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x69, true, -1);
    }
    void vpunpckhwd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x69, true, -1);
    }
    void vpunpckhdq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x6A, true, -1);
    }
    void vpunpckhdq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x6A, true, -1);
    }
    void vpunpckhqdq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x6D, true, -1);
    }
    void vpunpckhqdq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x6D, true, -1);
    }
    void vpunpcklbw(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x60, true, -1);
    }
    void vpunpcklbw(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x60, true, -1);
    }
    void vpunpcklwd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x61, true, -1);
    }
    void vpunpcklwd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x61, true, -1);
    }
    void vpunpckldq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x62, true, -1);
    }
    void vpunpckldq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x62, true, -1);
    }
    void vpunpcklqdq(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x6C, true, -1);
    }
    void vpunpcklqdq(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x6C, true, -1);
    }
    void vpxor(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xEF, true, -1);
    }
    void vpxor(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xEF, true, -1);
    }
    void vrcpss(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_F3, 0x53, false, -1);
    }
    void vrcpss(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_F3, 0x53, false, -1);
    }
    void vrsqrtss(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_F3, 0x52, false, -1);
    }
    void vrsqrtss(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_F3, 0x52, false, -1);
    }
    void vshufpd(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0xC6, true, -1); db(imm);
    }
    void vshufpd(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0xC6, true, -1); db(imm);
    }
    void vshufps(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F, 0xC6, true, -1); db(imm);
    }
    void vshufps(Xmm xmm, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F, 0xC6, true, -1); db(imm);
    }
    void vsqrtsd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_F2, 0x51, false, -1);
    }
    void vsqrtsd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_F2, 0x51, false, -1);
    }
    void vsqrtss(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_F3, 0x51, false, -1);
    }
    void vsqrtss(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_F3, 0x51, false, -1);
    }
    void vunpckhpd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x15, true, -1);
    }
    void vunpckhpd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x15, true, -1);
    }
    void vunpckhps(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F, 0x15, true, -1);
    }
    void vunpckhps(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F, 0x15, true, -1);
    }
    void vunpcklpd(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_66, 0x14, true, -1);
    }
    void vunpcklpd(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F | PP_66, 0x14, true, -1);
    }
    void vunpcklps(Xmm x1, Xmm x2, Operand op)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F, 0x14, true, -1);
    }
    void vunpcklps(Xmm xmm, Operand op)
    {
        opAVX_X_X_XM(xmm, xmm, op, MM_0F, 0x14, true, -1);
    }
    void vaeskeygenassist(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F3A | PP_66, 0xDF, false, 0, imm);
    }
    void vroundpd(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F3A | PP_66, 0x09, true, 0, imm);
    }
    void vroundps(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F3A | PP_66, 0x08, true, 0, imm);
    }
    void vpermilpd(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F3A | PP_66, 0x05, true, 0, imm);
    }
    void vpermilps(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F3A | PP_66, 0x04, true, 0, imm);
    }
    void vpcmpestri(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F3A | PP_66, 0x61, false, 0, imm);
    }
    void vpcmpestrm(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F3A | PP_66, 0x60, false, 0, imm);
    }
    void vpcmpistri(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F3A | PP_66, 0x63, false, 0, imm);
    }
    void vpcmpistrm(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F3A | PP_66, 0x62, false, 0, imm);
    }
    void vtestps(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x0E, true, 0);
    }
    void vtestpd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x0F, true, 0);
    }
    void vcomisd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_66, 0x2F, false, -1);
    }
    void vcomiss(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F, 0x2F, false, -1);
    }
    void vcvtdq2ps(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F, 0x5B, true, -1);
    }
    void vcvtps2dq(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_66, 0x5B, true, -1);
    }
    void vcvttps2dq(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_F3, 0x5B, true, -1);
    }
    void vmovapd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_66, 0x28, true, -1);
    }
    void vmovaps(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F, 0x28, true, -1);
    }
    void vmovddup(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_F2, 0x12, true, -1);
    }
    void vmovdqa(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_66, 0x6F, true, -1);
    }
    void vmovdqu(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_F3, 0x6F, true, -1);
    }
    void vmovshdup(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_F3, 0x16, true, -1);
    }
    void vmovsldup(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_F3, 0x12, true, -1);
    }
    void vmovupd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_66, 0x10, true, -1);
    }
    void vmovups(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F, 0x10, true, -1);
    }
    void vpabsb(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x1C, true, -1);
    }
    void vpabsw(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x1D, true, -1);
    }
    void vpabsd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x1E, true, -1);
    }
    void vphminposuw(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x41, false, -1);
    }
    void vpmovsxbw(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x20, true, -1);
    }
    void vpmovsxbd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x21, true, -1);
    }
    void vpmovsxbq(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x22, true, -1);
    }
    void vpmovsxwd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x23, true, -1);
    }
    void vpmovsxwq(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x24, true, -1);
    }
    void vpmovsxdq(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x25, true, -1);
    }
    void vpmovzxbw(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x30, true, -1);
    }
    void vpmovzxbd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x31, true, -1);
    }
    void vpmovzxbq(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x32, true, -1);
    }
    void vpmovzxwd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x33, true, -1);
    }
    void vpmovzxwq(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x34, true, -1);
    }
    void vpmovzxdq(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x35, true, -1);
    }
    void vpshufd(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_66, 0x70, true, -1, imm);
    }
    void vpshufhw(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_F3, 0x70, true, -1, imm);
    }
    void vpshuflw(Xmm xm, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_F2, 0x70, true, -1, imm);
    }
    void vptest(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F38 | PP_66, 0x17, false, -1);
    }
    void vrcpps(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F, 0x53, true, -1);
    }
    void vrsqrtps(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F, 0x52, true, -1);
    }
    void vsqrtpd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_66, 0x51, true, -1);
    }
    void vsqrtps(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F, 0x51, true, -1);
    }
    void vucomisd(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F | PP_66, 0x2E, false, -1);
    }
    void vucomiss(Xmm xm, Operand op)
    {
        opAVX_X_XM_IMM(xm, op, MM_0F, 0x2E, false, -1);
    }
    void vmovapd(Address addr, Xmm xmm)
    {
        opAVX_X_XM_IMM(xmm, addr, MM_0F | PP_66, 0x29, true, -1);
    }
    void vmovaps(Address addr, Xmm xmm)
    {
        opAVX_X_XM_IMM(xmm, addr, MM_0F, 0x29, true, -1);
    }
    void vmovdqa(Address addr, Xmm xmm)
    {
        opAVX_X_XM_IMM(xmm, addr, MM_0F | PP_66, 0x7F, true, -1);
    }
    void vmovdqu(Address addr, Xmm xmm)
    {
        opAVX_X_XM_IMM(xmm, addr, MM_0F | PP_F3, 0x7F, true, -1);
    }
    void vmovupd(Address addr, Xmm xmm)
    {
        opAVX_X_XM_IMM(xmm, addr, MM_0F | PP_66, 0x11, true, -1);
    }
    void vmovups(Address addr, Xmm xmm)
    {
        opAVX_X_XM_IMM(xmm, addr, MM_0F, 0x11, true, -1);
    }
    void vaddsubpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0xD0, true, -1);
    }
    void vaddsubps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F2, 0xD0, true, -1);
    }
    void vhaddpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x7C, true, -1);
    }
    void vhaddps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F2, 0x7C, true, -1);
    }
    void vhsubpd(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_66, 0x7D, true, -1);
    }
    void vhsubps(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F | PP_F2, 0x7D, true, -1);
    }
    void vaesenc(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xDC, false, 0);
    }
    void vaesenclast(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xDD, false, 0);
    }
    void vaesdec(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xDE, false, 0);
    }
    void vaesdeclast(Xmm xmm, Operand op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xDF, false, 0);
    }
    void vmaskmovps(Xmm x1, Xmm x2, Address addr)
    {
        opAVX_X_X_XM(x1, x2, addr, MM_0F38 | PP_66, 0x2C, true, 0);
    }
    void vmaskmovps(Address addr, Xmm x1, Xmm x2)
    {
        opAVX_X_X_XM(x2, x1, addr, MM_0F38 | PP_66, 0x2E, true, 0);
    }
    void vmaskmovpd(Xmm x1, Xmm x2, Address addr)
    {
        opAVX_X_X_XM(x1, x2, addr, MM_0F38 | PP_66, 0x2D, true, 0);
    }
    void vmaskmovpd(Address addr, Xmm x1, Xmm x2)
    {
        opAVX_X_X_XM(x2, x1, addr, MM_0F38 | PP_66, 0x2F, true, 0);
    }
    void vpmaskmovd(Xmm x1, Xmm x2, Address addr)
    {
        opAVX_X_X_XM(x1, x2, addr, MM_0F38 | PP_66, 0x8C, true, 0);
    }
    void vpmaskmovd(Address addr, Xmm x1, Xmm x2)
    {
        opAVX_X_X_XM(x2, x1, addr, MM_0F38 | PP_66, 0x8E, true, 0);
    }
    void vpmaskmovq(Xmm x1, Xmm x2, Address addr)
    {
        opAVX_X_X_XM(x1, x2, addr, MM_0F38 | PP_66, 0x8C, true, 1);
    }
    void vpmaskmovq(Address addr, Xmm x1, Xmm x2)
    {
        opAVX_X_X_XM(x2, x1, addr, MM_0F38 | PP_66, 0x8E, true, 1);
    }
    void vpermd(Ymm y1, Ymm y2, Operand op)
    {
        opAVX_X_X_XM(y1, y2, op, MM_0F38 | PP_66, 0x36, true, 0);
    }
    void vpermps(Ymm y1, Ymm y2, Operand op)
    {
        opAVX_X_X_XM(y1, y2, op, MM_0F38 | PP_66, 0x16, true, 0);
    }
    void vpermq(Ymm y, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(y, op, MM_0F3A | PP_66, 0x00, true, 1, imm);
    }
    void vpermpd(Ymm y, Operand op, uint8 imm)
    {
        opAVX_X_XM_IMM(y, op, MM_0F3A | PP_66, 0x01, true, 1, imm);
    }
    void cmpeqpd(Xmm x, Operand op)
    {
        cmppd(x, op, 0);
    }
    void vcmpeqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 0);
    }
    void vcmpeqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 0);
    }
    void cmpltpd(Xmm x, Operand op)
    {
        cmppd(x, op, 1);
    }
    void vcmpltpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 1);
    }
    void vcmpltpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 1);
    }
    void cmplepd(Xmm x, Operand op)
    {
        cmppd(x, op, 2);
    }
    void vcmplepd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 2);
    }
    void vcmplepd(Xmm x, Operand op)
    {
        vcmppd(x, op, 2);
    }
    void cmpunordpd(Xmm x, Operand op)
    {
        cmppd(x, op, 3);
    }
    void vcmpunordpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 3);
    }
    void vcmpunordpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 3);
    }
    void cmpneqpd(Xmm x, Operand op)
    {
        cmppd(x, op, 4);
    }
    void vcmpneqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 4);
    }
    void vcmpneqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 4);
    }
    void cmpnltpd(Xmm x, Operand op)
    {
        cmppd(x, op, 5);
    }
    void vcmpnltpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 5);
    }
    void vcmpnltpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 5);
    }
    void cmpnlepd(Xmm x, Operand op)
    {
        cmppd(x, op, 6);
    }
    void vcmpnlepd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 6);
    }
    void vcmpnlepd(Xmm x, Operand op)
    {
        vcmppd(x, op, 6);
    }
    void cmpordpd(Xmm x, Operand op)
    {
        cmppd(x, op, 7);
    }
    void vcmpordpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 7);
    }
    void vcmpordpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 7);
    }
    void vcmpeq_uqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 8);
    }
    void vcmpeq_uqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 8);
    }
    void vcmpngepd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 9);
    }
    void vcmpngepd(Xmm x, Operand op)
    {
        vcmppd(x, op, 9);
    }
    void vcmpngtpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 10);
    }
    void vcmpngtpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 10);
    }
    void vcmpfalsepd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 11);
    }
    void vcmpfalsepd(Xmm x, Operand op)
    {
        vcmppd(x, op, 11);
    }
    void vcmpneq_oqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 12);
    }
    void vcmpneq_oqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 12);
    }
    void vcmpgepd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 13);
    }
    void vcmpgepd(Xmm x, Operand op)
    {
        vcmppd(x, op, 13);
    }
    void vcmpgtpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 14);
    }
    void vcmpgtpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 14);
    }
    void vcmptruepd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 15);
    }
    void vcmptruepd(Xmm x, Operand op)
    {
        vcmppd(x, op, 15);
    }
    void vcmpeq_ospd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 16);
    }
    void vcmpeq_ospd(Xmm x, Operand op)
    {
        vcmppd(x, op, 16);
    }
    void vcmplt_oqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 17);
    }
    void vcmplt_oqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 17);
    }
    void vcmple_oqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 18);
    }
    void vcmple_oqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 18);
    }
    void vcmpunord_spd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 19);
    }
    void vcmpunord_spd(Xmm x, Operand op)
    {
        vcmppd(x, op, 19);
    }
    void vcmpneq_uspd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 20);
    }
    void vcmpneq_uspd(Xmm x, Operand op)
    {
        vcmppd(x, op, 20);
    }
    void vcmpnlt_uqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 21);
    }
    void vcmpnlt_uqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 21);
    }
    void vcmpnle_uqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 22);
    }
    void vcmpnle_uqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 22);
    }
    void vcmpord_spd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 23);
    }
    void vcmpord_spd(Xmm x, Operand op)
    {
        vcmppd(x, op, 23);
    }
    void vcmpeq_uspd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 24);
    }
    void vcmpeq_uspd(Xmm x, Operand op)
    {
        vcmppd(x, op, 24);
    }
    void vcmpnge_uqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 25);
    }
    void vcmpnge_uqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 25);
    }
    void vcmpngt_uqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 26);
    }
    void vcmpngt_uqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 26);
    }
    void vcmpfalse_ospd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 27);
    }
    void vcmpfalse_ospd(Xmm x, Operand op)
    {
        vcmppd(x, op, 27);
    }
    void vcmpneq_ospd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 28);
    }
    void vcmpneq_ospd(Xmm x, Operand op)
    {
        vcmppd(x, op, 28);
    }
    void vcmpge_oqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 29);
    }
    void vcmpge_oqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 29);
    }
    void vcmpgt_oqpd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 30);
    }
    void vcmpgt_oqpd(Xmm x, Operand op)
    {
        vcmppd(x, op, 30);
    }
    void vcmptrue_uspd(Xmm x1, Xmm x2, Operand op)
    {
        vcmppd(x1, x2, op, 31);
    }
    void vcmptrue_uspd(Xmm x, Operand op)
    {
        vcmppd(x, op, 31);
    }
    void cmpeqps(Xmm x, Operand op)
    {
        cmpps(x, op, 0);
    }
    void vcmpeqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 0);
    }
    void vcmpeqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 0);
    }
    void cmpltps(Xmm x, Operand op)
    {
        cmpps(x, op, 1);
    }
    void vcmpltps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 1);
    }
    void vcmpltps(Xmm x, Operand op)
    {
        vcmpps(x, op, 1);
    }
    void cmpleps(Xmm x, Operand op)
    {
        cmpps(x, op, 2);
    }
    void vcmpleps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 2);
    }
    void vcmpleps(Xmm x, Operand op)
    {
        vcmpps(x, op, 2);
    }
    void cmpunordps(Xmm x, Operand op)
    {
        cmpps(x, op, 3);
    }
    void vcmpunordps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 3);
    }
    void vcmpunordps(Xmm x, Operand op)
    {
        vcmpps(x, op, 3);
    }
    void cmpneqps(Xmm x, Operand op)
    {
        cmpps(x, op, 4);
    }
    void vcmpneqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 4);
    }
    void vcmpneqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 4);
    }
    void cmpnltps(Xmm x, Operand op)
    {
        cmpps(x, op, 5);
    }
    void vcmpnltps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 5);
    }
    void vcmpnltps(Xmm x, Operand op)
    {
        vcmpps(x, op, 5);
    }
    void cmpnleps(Xmm x, Operand op)
    {
        cmpps(x, op, 6);
    }
    void vcmpnleps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 6);
    }
    void vcmpnleps(Xmm x, Operand op)
    {
        vcmpps(x, op, 6);
    }
    void cmpordps(Xmm x, Operand op)
    {
        cmpps(x, op, 7);
    }
    void vcmpordps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 7);
    }
    void vcmpordps(Xmm x, Operand op)
    {
        vcmpps(x, op, 7);
    }
    void vcmpeq_uqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 8);
    }
    void vcmpeq_uqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 8);
    }
    void vcmpngeps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 9);
    }
    void vcmpngeps(Xmm x, Operand op)
    {
        vcmpps(x, op, 9);
    }
    void vcmpngtps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 10);
    }
    void vcmpngtps(Xmm x, Operand op)
    {
        vcmpps(x, op, 10);
    }
    void vcmpfalseps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 11);
    }
    void vcmpfalseps(Xmm x, Operand op)
    {
        vcmpps(x, op, 11);
    }
    void vcmpneq_oqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 12);
    }
    void vcmpneq_oqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 12);
    }
    void vcmpgeps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 13);
    }
    void vcmpgeps(Xmm x, Operand op)
    {
        vcmpps(x, op, 13);
    }
    void vcmpgtps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 14);
    }
    void vcmpgtps(Xmm x, Operand op)
    {
        vcmpps(x, op, 14);
    }
    void vcmptrueps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 15);
    }
    void vcmptrueps(Xmm x, Operand op)
    {
        vcmpps(x, op, 15);
    }
    void vcmpeq_osps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 16);
    }
    void vcmpeq_osps(Xmm x, Operand op)
    {
        vcmpps(x, op, 16);
    }
    void vcmplt_oqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 17);
    }
    void vcmplt_oqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 17);
    }
    void vcmple_oqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 18);
    }
    void vcmple_oqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 18);
    }
    void vcmpunord_sps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 19);
    }
    void vcmpunord_sps(Xmm x, Operand op)
    {
        vcmpps(x, op, 19);
    }
    void vcmpneq_usps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 20);
    }
    void vcmpneq_usps(Xmm x, Operand op)
    {
        vcmpps(x, op, 20);
    }
    void vcmpnlt_uqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 21);
    }
    void vcmpnlt_uqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 21);
    }
    void vcmpnle_uqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 22);
    }
    void vcmpnle_uqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 22);
    }
    void vcmpord_sps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 23);
    }
    void vcmpord_sps(Xmm x, Operand op)
    {
        vcmpps(x, op, 23);
    }
    void vcmpeq_usps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 24);
    }
    void vcmpeq_usps(Xmm x, Operand op)
    {
        vcmpps(x, op, 24);
    }
    void vcmpnge_uqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 25);
    }
    void vcmpnge_uqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 25);
    }
    void vcmpngt_uqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 26);
    }
    void vcmpngt_uqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 26);
    }
    void vcmpfalse_osps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 27);
    }
    void vcmpfalse_osps(Xmm x, Operand op)
    {
        vcmpps(x, op, 27);
    }
    void vcmpneq_osps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 28);
    }
    void vcmpneq_osps(Xmm x, Operand op)
    {
        vcmpps(x, op, 28);
    }
    void vcmpge_oqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 29);
    }
    void vcmpge_oqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 29);
    }
    void vcmpgt_oqps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 30);
    }
    void vcmpgt_oqps(Xmm x, Operand op)
    {
        vcmpps(x, op, 30);
    }
    void vcmptrue_usps(Xmm x1, Xmm x2, Operand op)
    {
        vcmpps(x1, x2, op, 31);
    }
    void vcmptrue_usps(Xmm x, Operand op)
    {
        vcmpps(x, op, 31);
    }
    void cmpeqsd(Xmm x, Operand op)
    {
        cmpsd(x, op, 0);
    }
    void vcmpeqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 0);
    }
    void vcmpeqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 0);
    }
    void cmpltsd(Xmm x, Operand op)
    {
        cmpsd(x, op, 1);
    }
    void vcmpltsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 1);
    }
    void vcmpltsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 1);
    }
    void cmplesd(Xmm x, Operand op)
    {
        cmpsd(x, op, 2);
    }
    void vcmplesd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 2);
    }
    void vcmplesd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 2);
    }
    void cmpunordsd(Xmm x, Operand op)
    {
        cmpsd(x, op, 3);
    }
    void vcmpunordsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 3);
    }
    void vcmpunordsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 3);
    }
    void cmpneqsd(Xmm x, Operand op)
    {
        cmpsd(x, op, 4);
    }
    void vcmpneqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 4);
    }
    void vcmpneqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 4);
    }
    void cmpnltsd(Xmm x, Operand op)
    {
        cmpsd(x, op, 5);
    }
    void vcmpnltsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 5);
    }
    void vcmpnltsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 5);
    }
    void cmpnlesd(Xmm x, Operand op)
    {
        cmpsd(x, op, 6);
    }
    void vcmpnlesd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 6);
    }
    void vcmpnlesd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 6);
    }
    void cmpordsd(Xmm x, Operand op)
    {
        cmpsd(x, op, 7);
    }
    void vcmpordsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 7);
    }
    void vcmpordsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 7);
    }
    void vcmpeq_uqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 8);
    }
    void vcmpeq_uqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 8);
    }
    void vcmpngesd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 9);
    }
    void vcmpngesd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 9);
    }
    void vcmpngtsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 10);
    }
    void vcmpngtsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 10);
    }
    void vcmpfalsesd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 11);
    }
    void vcmpfalsesd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 11);
    }
    void vcmpneq_oqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 12);
    }
    void vcmpneq_oqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 12);
    }
    void vcmpgesd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 13);
    }
    void vcmpgesd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 13);
    }
    void vcmpgtsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 14);
    }
    void vcmpgtsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 14);
    }
    void vcmptruesd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 15);
    }
    void vcmptruesd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 15);
    }
    void vcmpeq_ossd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 16);
    }
    void vcmpeq_ossd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 16);
    }
    void vcmplt_oqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 17);
    }
    void vcmplt_oqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 17);
    }
    void vcmple_oqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 18);
    }
    void vcmple_oqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 18);
    }
    void vcmpunord_ssd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 19);
    }
    void vcmpunord_ssd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 19);
    }
    void vcmpneq_ussd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 20);
    }
    void vcmpneq_ussd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 20);
    }
    void vcmpnlt_uqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 21);
    }
    void vcmpnlt_uqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 21);
    }
    void vcmpnle_uqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 22);
    }
    void vcmpnle_uqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 22);
    }
    void vcmpord_ssd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 23);
    }
    void vcmpord_ssd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 23);
    }
    void vcmpeq_ussd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 24);
    }
    void vcmpeq_ussd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 24);
    }
    void vcmpnge_uqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 25);
    }
    void vcmpnge_uqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 25);
    }
    void vcmpngt_uqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 26);
    }
    void vcmpngt_uqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 26);
    }
    void vcmpfalse_ossd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 27);
    }
    void vcmpfalse_ossd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 27);
    }
    void vcmpneq_ossd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 28);
    }
    void vcmpneq_ossd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 28);
    }
    void vcmpge_oqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 29);
    }
    void vcmpge_oqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 29);
    }
    void vcmpgt_oqsd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 30);
    }
    void vcmpgt_oqsd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 30);
    }
    void vcmptrue_ussd(Xmm x1, Xmm x2, Operand op)
    {
        vcmpsd(x1, x2, op, 31);
    }
    void vcmptrue_ussd(Xmm x, Operand op)
    {
        vcmpsd(x, op, 31);
    }
    void cmpeqss(Xmm x, Operand op)
    {
        cmpss(x, op, 0);
    }
    void vcmpeqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 0);
    }
    void vcmpeqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 0);
    }
    void cmpltss(Xmm x, Operand op)
    {
        cmpss(x, op, 1);
    }
    void vcmpltss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 1);
    }
    void vcmpltss(Xmm x, Operand op)
    {
        vcmpss(x, op, 1);
    }
    void cmpless(Xmm x, Operand op)
    {
        cmpss(x, op, 2);
    }
    void vcmpless(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 2);
    }
    void vcmpless(Xmm x, Operand op)
    {
        vcmpss(x, op, 2);
    }
    void cmpunordss(Xmm x, Operand op)
    {
        cmpss(x, op, 3);
    }
    void vcmpunordss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 3);
    }
    void vcmpunordss(Xmm x, Operand op)
    {
        vcmpss(x, op, 3);
    }
    void cmpneqss(Xmm x, Operand op)
    {
        cmpss(x, op, 4);
    }
    void vcmpneqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 4);
    }
    void vcmpneqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 4);
    }
    void cmpnltss(Xmm x, Operand op)
    {
        cmpss(x, op, 5);
    }
    void vcmpnltss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 5);
    }
    void vcmpnltss(Xmm x, Operand op)
    {
        vcmpss(x, op, 5);
    }
    void cmpnless(Xmm x, Operand op)
    {
        cmpss(x, op, 6);
    }
    void vcmpnless(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 6);
    }
    void vcmpnless(Xmm x, Operand op)
    {
        vcmpss(x, op, 6);
    }
    void cmpordss(Xmm x, Operand op)
    {
        cmpss(x, op, 7);
    }
    void vcmpordss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 7);
    }
    void vcmpordss(Xmm x, Operand op)
    {
        vcmpss(x, op, 7);
    }
    void vcmpeq_uqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 8);
    }
    void vcmpeq_uqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 8);
    }
    void vcmpngess(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 9);
    }
    void vcmpngess(Xmm x, Operand op)
    {
        vcmpss(x, op, 9);
    }
    void vcmpngtss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 10);
    }
    void vcmpngtss(Xmm x, Operand op)
    {
        vcmpss(x, op, 10);
    }
    void vcmpfalsess(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 11);
    }
    void vcmpfalsess(Xmm x, Operand op)
    {
        vcmpss(x, op, 11);
    }
    void vcmpneq_oqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 12);
    }
    void vcmpneq_oqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 12);
    }
    void vcmpgess(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 13);
    }
    void vcmpgess(Xmm x, Operand op)
    {
        vcmpss(x, op, 13);
    }
    void vcmpgtss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 14);
    }
    void vcmpgtss(Xmm x, Operand op)
    {
        vcmpss(x, op, 14);
    }
    void vcmptruess(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 15);
    }
    void vcmptruess(Xmm x, Operand op)
    {
        vcmpss(x, op, 15);
    }
    void vcmpeq_osss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 16);
    }
    void vcmpeq_osss(Xmm x, Operand op)
    {
        vcmpss(x, op, 16);
    }
    void vcmplt_oqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 17);
    }
    void vcmplt_oqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 17);
    }
    void vcmple_oqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 18);
    }
    void vcmple_oqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 18);
    }
    void vcmpunord_sss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 19);
    }
    void vcmpunord_sss(Xmm x, Operand op)
    {
        vcmpss(x, op, 19);
    }
    void vcmpneq_usss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 20);
    }
    void vcmpneq_usss(Xmm x, Operand op)
    {
        vcmpss(x, op, 20);
    }
    void vcmpnlt_uqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 21);
    }
    void vcmpnlt_uqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 21);
    }
    void vcmpnle_uqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 22);
    }
    void vcmpnle_uqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 22);
    }
    void vcmpord_sss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 23);
    }
    void vcmpord_sss(Xmm x, Operand op)
    {
        vcmpss(x, op, 23);
    }
    void vcmpeq_usss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 24);
    }
    void vcmpeq_usss(Xmm x, Operand op)
    {
        vcmpss(x, op, 24);
    }
    void vcmpnge_uqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 25);
    }
    void vcmpnge_uqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 25);
    }
    void vcmpngt_uqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 26);
    }
    void vcmpngt_uqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 26);
    }
    void vcmpfalse_osss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 27);
    }
    void vcmpfalse_osss(Xmm x, Operand op)
    {
        vcmpss(x, op, 27);
    }
    void vcmpneq_osss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 28);
    }
    void vcmpneq_osss(Xmm x, Operand op)
    {
        vcmpss(x, op, 28);
    }
    void vcmpge_oqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 29);
    }
    void vcmpge_oqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 29);
    }
    void vcmpgt_oqss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 30);
    }
    void vcmpgt_oqss(Xmm x, Operand op)
    {
        vcmpss(x, op, 30);
    }
    void vcmptrue_usss(Xmm x1, Xmm x2, Operand op)
    {
        vcmpss(x1, x2, op, 31);
    }
    void vcmptrue_usss(Xmm x, Operand op)
    {
        vcmpss(x, op, 31);
    }
    void vmovhpd(Xmm x, Operand op1, Operand op2 = OP())
    {
        if (!op2.isNone() && !op2.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(x, op1, op2, MM_0F | PP_66, 0x16, false);
    }
    void vmovhpd(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F | PP_66, 0x17, false);
    }
    void vmovhps(Xmm x, Operand op1, Operand op2 = OP())
    {
        if (!op2.isNone() && !op2.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(x, op1, op2, MM_0F, 0x16, false);
    }
    void vmovhps(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F, 0x17, false);
    }
    void vmovlpd(Xmm x, Operand op1, Operand op2 = OP())
    {
        if (!op2.isNone() && !op2.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(x, op1, op2, MM_0F | PP_66, 0x12, false);
    }
    void vmovlpd(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F | PP_66, 0x13, false);
    }
    void vmovlps(Xmm x, Operand op1, Operand op2 = OP())
    {
        if (!op2.isNone() && !op2.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(x, op1, op2, MM_0F, 0x12, false);
    }
    void vmovlps(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F, 0x13, false);
    }
    void vfmadd132pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x98, true, 1);
    }
    void vfmadd213pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xA8, true, 1);
    }
    void vfmadd231pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xB8, true, 1);
    }
    void vfmadd132ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x98, true, 0);
    }
    void vfmadd213ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xA8, true, 0);
    }
    void vfmadd231ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xB8, true, 0);
    }
    void vfmadd132sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x99, false, 1);
    }
    void vfmadd213sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xA9, false, 1);
    }
    void vfmadd231sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xB9, false, 1);
    }
    void vfmadd132ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x99, false, 0);
    }
    void vfmadd213ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xA9, false, 0);
    }
    void vfmadd231ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xB9, false, 0);
    }
    void vfmaddsub132pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x96, true, 1);
    }
    void vfmaddsub213pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xA6, true, 1);
    }
    void vfmaddsub231pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xB6, true, 1);
    }
    void vfmaddsub132ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x96, true, 0);
    }
    void vfmaddsub213ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xA6, true, 0);
    }
    void vfmaddsub231ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xB6, true, 0);
    }
    void vfmsubadd132pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x97, true, 1);
    }
    void vfmsubadd213pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xA7, true, 1);
    }
    void vfmsubadd231pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xB7, true, 1);
    }
    void vfmsubadd132ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x97, true, 0);
    }
    void vfmsubadd213ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xA7, true, 0);
    }
    void vfmsubadd231ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xB7, true, 0);
    }
    void vfmsub132pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9A, true, 1);
    }
    void vfmsub213pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAA, true, 1);
    }
    void vfmsub231pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBA, true, 1);
    }
    void vfmsub132ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9A, true, 0);
    }
    void vfmsub213ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAA, true, 0);
    }
    void vfmsub231ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBA, true, 0);
    }
    void vfmsub132sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9B, false, 1);
    }
    void vfmsub213sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAB, false, 1);
    }
    void vfmsub231sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBB, false, 1);
    }
    void vfmsub132ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9B, false, 0);
    }
    void vfmsub213ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAB, false, 0);
    }
    void vfmsub231ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBB, false, 0);
    }
    void vfnmadd132pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9C, true, 1);
    }
    void vfnmadd213pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAC, true, 1);
    }
    void vfnmadd231pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBC, true, 1);
    }
    void vfnmadd132ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9C, true, 0);
    }
    void vfnmadd213ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAC, true, 0);
    }
    void vfnmadd231ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBC, true, 0);
    }
    void vfnmadd132sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9D, false, 1);
    }
    void vfnmadd213sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAD, false, 1);
    }
    void vfnmadd231sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBD, false, 1);
    }
    void vfnmadd132ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9D, false, 0);
    }
    void vfnmadd213ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAD, false, 0);
    }
    void vfnmadd231ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBD, false, 0);
    }
    void vfnmsub132pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9E, true, 1);
    }
    void vfnmsub213pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAE, true, 1);
    }
    void vfnmsub231pd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBE, true, 1);
    }
    void vfnmsub132ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9E, true, 0);
    }
    void vfnmsub213ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAE, true, 0);
    }
    void vfnmsub231ps(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBE, true, 0);
    }
    void vfnmsub132sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9F, false, 1);
    }
    void vfnmsub213sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAF, false, 1);
    }
    void vfnmsub231sd(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBF, false, 1);
    }
    void vfnmsub132ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0x9F, false, 0);
    }
    void vfnmsub213ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xAF, false, 0);
    }
    void vfnmsub231ss(Xmm xmm, Xmm op1, Operand op2 = OP())
    {
        opAVX_X_X_XM(xmm, op1, op2, MM_0F38 | PP_66, 0xBF, false, 0);
    }
    void vaesimc(Xmm x, Operand op)
    {
        opAVX_X_XM_IMM(x, op, MM_0F38 | PP_66, 0xDB, false, 0);
    }
    void vbroadcastf128(Ymm y, Address addr)
    {
        opAVX_X_XM_IMM(y, addr, MM_0F38 | PP_66, 0x1A, true, 0);
    }
    void vbroadcasti128(Ymm y, Address addr)
    {
        opAVX_X_XM_IMM(y, addr, MM_0F38 | PP_66, 0x5A, true, 0);
    }
    void vbroadcastsd(Ymm y, Operand op)
    {
        if (!(op.isXMM() || op.isMEM()))
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_XM_IMM(y, op, MM_0F38 | PP_66, 0x19, true, 0);
    }
    void vbroadcastss(Xmm x, Operand op)
    {
        if (!(op.isXMM() || op.isMEM()))
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_XM_IMM(x, op, MM_0F38 | PP_66, 0x18, true, 0);
    }
    void vpbroadcastb(Xmm x, Operand op)
    {
        if (!(op.isXMM() || op.isMEM()))
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_XM_IMM(x, op, MM_0F38 | PP_66, 0x78, true, 0);
    }
    void vpbroadcastw(Xmm x, Operand op)
    {
        if (!(op.isXMM() || op.isMEM()))
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_XM_IMM(x, op, MM_0F38 | PP_66, 0x79, true, 0);
    }
    void vpbroadcastd(Xmm x, Operand op)
    {
        if (!(op.isXMM() || op.isMEM()))
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_XM_IMM(x, op, MM_0F38 | PP_66, 0x58, true, 0);
    }
    void vpbroadcastq(Xmm x, Operand op)
    {
        if (!(op.isXMM() || op.isMEM()))
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_XM_IMM(x, op, MM_0F38 | PP_66, 0x59, true, 0);
    }
    void vextractf128(Operand op, Ymm y, uint8 imm)
    {
        opAVX_X_X_XMcvt(y, y.isXMM() ? xm0 : ym0, op, op.isXMM(), Kind.YMM, MM_0F3A | PP_66, 0x19, true, 0); db(imm);
    }
    void vextracti128(Operand op, Ymm y, uint8 imm)
    {
        opAVX_X_X_XMcvt(y, y.isXMM() ? xm0 : ym0, op, op.isXMM(), Kind.YMM, MM_0F3A | PP_66, 0x39, true, 0); db(imm);
    }
    void vextractps(Operand op, Xmm x, uint8 imm)
    {
        if (!(op.isREG(32) || op.isMEM()) || x.isYMM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x, x.isXMM() ? xm0 : ym0, op, op.isREG(), Kind.XMM, MM_0F3A | PP_66, 0x17, false, 0); db(imm);
    }
    void vinsertf128(Ymm y1, Ymm y2, Operand op, uint8 imm)
    {
        opAVX_X_X_XMcvt(y1, y2, op, op.isXMM(), Kind.YMM, MM_0F3A | PP_66, 0x18, true, 0); db(imm);
    }
    void vinserti128(Ymm y1, Ymm y2, Operand op, uint8 imm)
    {
        opAVX_X_X_XMcvt(y1, y2, op, op.isXMM(), Kind.YMM, MM_0F3A | PP_66, 0x38, true, 0); db(imm);
    }
    void vperm2f128(Ymm y1, Ymm y2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(y1, y2, op, MM_0F3A | PP_66, 0x06, true, 0); db(imm);
    }
    void vperm2i128(Ymm y1, Ymm y2, Operand op, uint8 imm)
    {
        opAVX_X_X_XM(y1, y2, op, MM_0F3A | PP_66, 0x46, true, 0); db(imm);
    }
    void vlddqu(Xmm x, Address addr)
    {
        opAVX_X_X_XM(x, x.isXMM() ? xm0 : ym0, addr, MM_0F | PP_F2, 0xF0, true, 0);
    }
    void vldmxcsr(Address addr)
    {
        opAVX_X_X_XM(xm2, xm0, addr, MM_0F, 0xAE, false, -1);
    }
    void vstmxcsr(Address addr)
    {
        opAVX_X_X_XM(xm3, xm0, addr, MM_0F, 0xAE, false, -1);
    }
    void vmaskmovdqu(Xmm x1, Xmm x2)
    {
        opAVX_X_X_XM(x1, xm0, x2, MM_0F | PP_66, 0xF7, false, -1);
    }
    void vpextrb(Operand op, Xmm x, uint8 imm)
    {
        if (!op.isREG(i32e) && !op.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x, xm0, op, !op.isMEM(), Kind.XMM, MM_0F3A | PP_66, 0x14, false); db(imm);
    }
    void vpextrw(Reg r, Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(XMM(r.getIdx()), xm0, x, MM_0F | PP_66, 0xC5, false, r.isBit(64) ? 1 : 0); db(imm);
    }
    void vpextrw(Address addr, Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F3A | PP_66, 0x15, false); db(imm);
    }
    void vpextrd(Operand op, Xmm x, uint8 imm)
    {
        if (!op.isREG(32) && !op.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x, xm0, op, !op.isMEM(), Kind.XMM, MM_0F3A | PP_66, 0x16, false, 0); db(imm);
    }
    void vpinsrb(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        if (!op.isREG(32) && !op.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x1, x2, op, !op.isMEM(), Kind.XMM, MM_0F3A | PP_66, 0x20, false); db(imm);
    }
    void vpinsrb(Xmm x, Operand op, uint8 imm)
    {
        if (!op.isREG(32) && !op.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x, x, op, !op.isMEM(), Kind.XMM, MM_0F3A | PP_66, 0x20, false); db(imm);
    }
    void vpinsrw(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        if (!op.isREG(32) && !op.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x1, x2, op, !op.isMEM(), Kind.XMM, MM_0F | PP_66, 0xC4, false); db(imm);
    }
    void vpinsrw(Xmm x, Operand op, uint8 imm)
    {
        if (!op.isREG(32) && !op.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x, x, op, !op.isMEM(), Kind.XMM, MM_0F | PP_66, 0xC4, false); db(imm);
    }
    void vpinsrd(Xmm x1, Xmm x2, Operand op, uint8 imm)
    {
        if (!op.isREG(32) && !op.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x1, x2, op, !op.isMEM(), Kind.XMM, MM_0F3A | PP_66, 0x22, false, 0); db(imm);
    }
    void vpinsrd(Xmm x, Operand op, uint8 imm)
    {
        if (!op.isREG(32) && !op.isMEM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x, x, op, !op.isMEM(), Kind.XMM, MM_0F3A | PP_66, 0x22, false, 0); db(imm);
    }
    void vpmovmskb(Reg32e r, Xmm x)
    {
        bool isYMM = x.isYMM(); opAVX_X_X_XM(isYMM ? YMM(r.getIdx()) : XMM(r.getIdx()), isYMM ? ym0 : xm0, x, MM_0F | PP_66, 0xD7, true);
    }
    void vpslldq(Xmm x1, Xmm x2, uint8 imm)
    {
        opAVX_X_X_XM(x1.isYMM() ? ym7 : xm7, x1, x2, MM_0F | PP_66, 0x73, true); db(imm);
    }
    void vpslldq(Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x.isYMM() ? ym7 : xm7, x, x, MM_0F | PP_66, 0x73, true); db(imm);
    }
    void vpsrldq(Xmm x1, Xmm x2, uint8 imm)
    {
        opAVX_X_X_XM(x1.isYMM() ? ym3 : xm3, x1, x2, MM_0F | PP_66, 0x73, true); db(imm);
    }
    void vpsrldq(Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x.isYMM() ? ym3 : xm3, x, x, MM_0F | PP_66, 0x73, true); db(imm);
    }
    void vpsllw(Xmm x1, Xmm x2, uint8 imm)
    {
        opAVX_X_X_XM(x1.isYMM() ? ym6 : xm6, x1, x2, MM_0F | PP_66, 0x71, true); db(imm);
    }
    void vpsllw(Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x.isYMM() ? ym6 : xm6, x, x, MM_0F | PP_66, 0x71, true); db(imm);
    }
    void vpslld(Xmm x1, Xmm x2, uint8 imm)
    {
        opAVX_X_X_XM(x1.isYMM() ? ym6 : xm6, x1, x2, MM_0F | PP_66, 0x72, true); db(imm);
    }
    void vpslld(Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x.isYMM() ? ym6 : xm6, x, x, MM_0F | PP_66, 0x72, true); db(imm);
    }
    void vpsllq(Xmm x1, Xmm x2, uint8 imm)
    {
        opAVX_X_X_XM(x1.isYMM() ? ym6 : xm6, x1, x2, MM_0F | PP_66, 0x73, true); db(imm);
    }
    void vpsllq(Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x.isYMM() ? ym6 : xm6, x, x, MM_0F | PP_66, 0x73, true); db(imm);
    }
    void vpsraw(Xmm x1, Xmm x2, uint8 imm)
    {
        opAVX_X_X_XM(x1.isYMM() ? ym4 : xm4, x1, x2, MM_0F | PP_66, 0x71, true); db(imm);
    }
    void vpsraw(Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x.isYMM() ? ym4 : xm4, x, x, MM_0F | PP_66, 0x71, true); db(imm);
    }
    void vpsrad(Xmm x1, Xmm x2, uint8 imm)
    {
        opAVX_X_X_XM(x1.isYMM() ? ym4 : xm4, x1, x2, MM_0F | PP_66, 0x72, true); db(imm);
    }
    void vpsrad(Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x.isYMM() ? ym4 : xm4, x, x, MM_0F | PP_66, 0x72, true); db(imm);
    }
    void vpsrlw(Xmm x1, Xmm x2, uint8 imm)
    {
        opAVX_X_X_XM(x1.isYMM() ? ym2 : xm2, x1, x2, MM_0F | PP_66, 0x71, true); db(imm);
    }
    void vpsrlw(Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x.isYMM() ? ym2 : xm2, x, x, MM_0F | PP_66, 0x71, true); db(imm);
    }
    void vpsrld(Xmm x1, Xmm x2, uint8 imm)
    {
        opAVX_X_X_XM(x1.isYMM() ? ym2 : xm2, x1, x2, MM_0F | PP_66, 0x72, true); db(imm);
    }
    void vpsrld(Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x.isYMM() ? ym2 : xm2, x, x, MM_0F | PP_66, 0x72, true); db(imm);
    }
    void vpsrlq(Xmm x1, Xmm x2, uint8 imm)
    {
        opAVX_X_X_XM(x1.isYMM() ? ym2 : xm2, x1, x2, MM_0F | PP_66, 0x73, true); db(imm);
    }
    void vpsrlq(Xmm x, uint8 imm)
    {
        opAVX_X_X_XM(x.isYMM() ? ym2 : xm2, x, x, MM_0F | PP_66, 0x73, true); db(imm);
    }
    void vblendvpd(Xmm x1, Xmm x2, Operand op, Xmm x4)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x4B, true); db(x4.getIdx() << 4);
    }
    void vblendvpd(Xmm x1, Operand op, Xmm x4)
    {
        opAVX_X_X_XM(x1, x1, op, MM_0F3A | PP_66, 0x4B, true); db(x4.getIdx() << 4);
    }
    void vblendvps(Xmm x1, Xmm x2, Operand op, Xmm x4)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x4A, true); db(x4.getIdx() << 4);
    }
    void vblendvps(Xmm x1, Operand op, Xmm x4)
    {
        opAVX_X_X_XM(x1, x1, op, MM_0F3A | PP_66, 0x4A, true); db(x4.getIdx() << 4);
    }
    void vpblendvb(Xmm x1, Xmm x2, Operand op, Xmm x4)
    {
        opAVX_X_X_XM(x1, x2, op, MM_0F3A | PP_66, 0x4C, false); db(x4.getIdx() << 4);
    }
    void vpblendvb(Xmm x1, Operand op, Xmm x4)
    {
        opAVX_X_X_XM(x1, x1, op, MM_0F3A | PP_66, 0x4C, false); db(x4.getIdx() << 4);
    }
    void vmovd(Xmm x, Reg32 reg)
    {
        opAVX_X_X_XM(x, xm0, XMM(reg.getIdx()), MM_0F | PP_66, 0x6E, false, 0);
    }
    void vmovd(Xmm x, Address addr)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F | PP_66, 0x6E, false, 0);
    }
    void vmovd(Reg32 reg, Xmm x)
    {
        opAVX_X_X_XM(x, xm0, XMM(reg.getIdx()), MM_0F | PP_66, 0x7E, false, 0);
    }
    void vmovd(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F | PP_66, 0x7E, false, 0);
    }
    void vmovq(Xmm x, Address addr)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F | PP_F3, 0x7E, false, -1);
    }
    void vmovq(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F | PP_66, 0xD6, false, -1);
    }
    void vmovq(Xmm x1, Xmm x2)
    {
        opAVX_X_X_XM(x1, xm0, x2, MM_0F | PP_F3, 0x7E, false, -1);
    }

    void vmovhlps(Xmm x1, Xmm x2, Operand op = OP())
    {
        if (!op.isNone() && !op.isXMM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(x1, x2, op, MM_0F, 0x12, false);
    }
    void vmovlhps(Xmm x1, Xmm x2, Operand op = OP())
    {
        if (!op.isNone() && !op.isXMM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(x1, x2, op, MM_0F, 0x16, false);
    }
    void vmovmskpd(Reg r, Xmm x)
    {
        if (!r.isBit(i32e))
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(x.isXMM() ? XMM(r.getIdx()) : YMM(r.getIdx()), x.isXMM() ? xm0 : ym0, x, MM_0F | PP_66, 0x50, true, 0);
    }
    void vmovmskps(Reg r, Xmm x)
    {
        if (!r.isBit(i32e))
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(x.isXMM() ? XMM(r.getIdx()) : YMM(r.getIdx()), x.isXMM() ? xm0 : ym0, x, MM_0F, 0x50, true, 0);
    }
    void vmovntdq(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, x.isXMM() ? xm0 : ym0, addr, MM_0F | PP_66, 0xE7, true);
    }
    void vmovntpd(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, x.isXMM() ? xm0 : ym0, addr, MM_0F | PP_66, 0x2B, true);
    }
    void vmovntps(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, x.isXMM() ? xm0 : ym0, addr, MM_0F, 0x2B, true);
    }
    void vmovntdqa(Xmm x, Address addr)
    {
        opAVX_X_X_XM(x, x.isXMM() ? xm0 : ymm0, addr, MM_0F38 | PP_66, 0x2A, true);
    }
    void vmovsd(Xmm x1, Xmm x2, Operand op = OP())
    {
        if (!op.isNone() && !op.isXMM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_F2, 0x10, false);
    }
    void vmovsd(Xmm x, Address addr)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F | PP_F2, 0x10, false);
    }
    void vmovsd(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F | PP_F2, 0x11, false);
    }
    void vmovss(Xmm x1, Xmm x2, Operand op = OP())
    {
        if (!op.isNone() && !op.isXMM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(x1, x2, op, MM_0F | PP_F3, 0x10, false);
    }
    void vmovss(Xmm x, Address addr)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F | PP_F3, 0x10, false);
    }
    void vmovss(Address addr, Xmm x)
    {
        opAVX_X_X_XM(x, xm0, addr, MM_0F | PP_F3, 0x11, false);
    }
    void vcvtss2si(Reg32 r, Operand op)
    {
        opAVX_X_X_XM(XMM(r.getIdx()), xm0, op, MM_0F | PP_F3, 0x2D, false, 0);
    }
    void vcvttss2si(Reg32 r, Operand op)
    {
        opAVX_X_X_XM(XMM(r.getIdx()), xm0, op, MM_0F | PP_F3, 0x2C, false, 0);
    }
    void vcvtsd2si(Reg32 r, Operand op)
    {
        opAVX_X_X_XM(XMM(r.getIdx()), xm0, op, MM_0F | PP_F2, 0x2D, false, 0);
    }
    void vcvttsd2si(Reg32 r, Operand op)
    {
        opAVX_X_X_XM(XMM(r.getIdx()), xm0, op, MM_0F | PP_F2, 0x2C, false, 0);
    }
    void vcvtsi2ss(Xmm x, Operand op1, Operand op2 = OP())
    {
        if (!op2.isNone() && !(op2.isREG(i32e) || op2.isMEM()))
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x, op1, op2, op2.isREG(), Kind.XMM, MM_0F | PP_F3, 0x2A, false, (op1.isMEM() || op2.isMEM()) ? -1 : (op1.isREG(32) || op2.isREG(32)) ? 0 : 1);
    }
    void vcvtsi2sd(Xmm x, Operand op1, Operand op2 = OP())
    {
        if (!op2.isNone() && !(op2.isREG(i32e) || op2.isMEM()))
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x, op1, op2, op2.isREG(), Kind.XMM, MM_0F | PP_F2, 0x2A, false, (op1.isMEM() || op2.isMEM()) ? -1 : (op1.isREG(32) || op2.isREG(32)) ? 0 : 1);
    }
    void vcvtps2pd(Xmm x, Operand op)
    {
        if (!op.isMEM() && !op.isXMM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x, x.isXMM() ? xm0 : ym0, op, !op.isMEM(), x.isXMM() ? Kind.XMM : Kind.YMM, MM_0F, 0x5A, true);
    }
    void vcvtdq2pd(Xmm x, Operand op)
    {
        if (!op.isMEM() && !op.isXMM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XMcvt(x, x.isXMM() ? xm0 : ym0, op, !op.isMEM(), x.isXMM() ? Kind.XMM : Kind.YMM, MM_0F | PP_F3, 0xE6, true);
    }
    void vcvtpd2ps(Xmm x, Operand op)
    {
        if (x.isYMM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(op.isYMM() ? YMM(x.getIdx()) : x, op.isYMM() ? ym0 : xm0, op, MM_0F | PP_66, 0x5A, true);
    }
    void vcvtpd2dq(Xmm x, Operand op)
    {
        if (x.isYMM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(op.isYMM() ? YMM(x.getIdx()) : x, op.isYMM() ? ym0 : xm0, op, MM_0F | PP_F2, 0xE6, true);
    }
    void vcvttpd2dq(Xmm x, Operand op)
    {
        if (x.isYMM())
            throw new XError(ERR.BAD_COMBINATION);
        opAVX_X_X_XM(op.isYMM() ? YMM(x.getIdx()) : x, op.isYMM() ? ym0 : xm0, op, MM_0F | PP_66, 0xE6, true);
    }
    void vcvtph2ps(Xmm x, Operand op)
    {
        if (!op.isMEM() && !op.isXMM())
            throw new XError(ERR.BAD_COMBINATION);
        opVex(x, null, op, MM_0F38 | PP_66, 0x13, 0);
    }
    void vcvtps2ph(Operand op, Xmm x, uint8 imm)
    {
        if (!op.isMEM() && !op.isXMM())
            throw new XError(ERR.BAD_COMBINATION);
        opVex(x, null, op, MM_0F3A | PP_66, 0x1d, 0); db(imm);
    }
    version(XBYAK64)
    {
        void vmovq(Xmm x, Reg64 reg)
        {
            opAVX_X_X_XM(x, xm0, XMM(reg.getIdx()), MM_0F | PP_66, 0x6E, false, 1);
        }
        void vmovq(Reg64 reg, Xmm x)
        {
            opAVX_X_X_XM(x, xm0, XMM(reg.getIdx()), MM_0F | PP_66, 0x7E, false, 1);
        }
        void vpextrq(Operand op, Xmm x, uint8 imm)
        {
            if (!op.isREG(64) && !op.isMEM())
                throw new XError(ERR.BAD_COMBINATION);
            opAVX_X_X_XMcvt(x, xm0, op, !op.isMEM(), Kind.XMM, MM_0F3A | PP_66, 0x16, false, 1); db(imm);
        }
        void vpinsrq(Xmm x1, Xmm x2, Operand op, uint8 imm)
        {
            if (!op.isREG(64) && !op.isMEM())
                throw new XError(ERR.BAD_COMBINATION);
            opAVX_X_X_XMcvt(x1, x2, op, !op.isMEM(), Kind.XMM, MM_0F3A | PP_66, 0x22, false, 1); db(imm);
        }
        void vpinsrq(Xmm x, Operand op, uint8 imm)
        {
            if (!op.isREG(64) && !op.isMEM())
                throw new XError(ERR.BAD_COMBINATION);
            opAVX_X_X_XMcvt(x, x, op, !op.isMEM(), Kind.XMM, MM_0F3A | PP_66, 0x22, false, 1); db(imm);
        }
        void vcvtss2si(Reg64 r, Operand op)
        {
            opAVX_X_X_XM(XMM(r.getIdx()), xm0, op, MM_0F | PP_F3, 0x2D, false, 1);
        }
        void vcvttss2si(Reg64 r, Operand op)
        {
            opAVX_X_X_XM(XMM(r.getIdx()), xm0, op, MM_0F | PP_F3, 0x2C, false, 1);
        }
        void vcvtsd2si(Reg64 r, Operand op)
        {
            opAVX_X_X_XM(XMM(r.getIdx()), xm0, op, MM_0F | PP_F2, 0x2D, false, 1);
        }
        void vcvttsd2si(Reg64 r, Operand op)
        {
            opAVX_X_X_XM(XMM(r.getIdx()), xm0, op, MM_0F | PP_F2, 0x2C, false, 1);
        }
    }
    void andn(Reg32e r1, Reg32e r2, Operand op)
    {
        opGpr(r1, r2, op, MM_0F38, 0xf2, true);
    }
    void mulx(Reg32e r1, Reg32e r2, Operand op)
    {
        opGpr(r1, r2, op, MM_0F38 | PP_F2, 0xf6, true);
    }
    void pdep(Reg32e r1, Reg32e r2, Operand op)
    {
        opGpr(r1, r2, op, MM_0F38 | PP_F2, 0xf5, true);
    }
    void pext(Reg32e r1, Reg32e r2, Operand op)
    {
        opGpr(r1, r2, op, MM_0F38 | PP_F3, 0xf5, true);
    }
    void bextr(Reg32e r1, Operand op, Reg32e r2)
    {
        opGpr(r1, op, r2, MM_0F38, 0xf7, false);
    }
    void bzhi(Reg32e r1, Operand op, Reg32e r2)
    {
        opGpr(r1, op, r2, MM_0F38, 0xf5, false);
    }
    void sarx(Reg32e r1, Operand op, Reg32e r2)
    {
        opGpr(r1, op, r2, MM_0F38 | PP_F3, 0xf7, false);
    }
    void shlx(Reg32e r1, Operand op, Reg32e r2)
    {
        opGpr(r1, op, r2, MM_0F38 | PP_66, 0xf7, false);
    }
    void shrx(Reg32e r1, Operand op, Reg32e r2)
    {
        opGpr(r1, op, r2, MM_0F38 | PP_F2, 0xf7, false);
    }
    void blsi(Reg32e r, Operand op)
    {
        opGpr(REG32E(3, r.getBit), op, r, MM_0F38, 0xf3, false);
    }
    void blsmsk(Reg32e r, Operand op)
    {
        opGpr(REG32E(2, r.getBit), op, r, MM_0F38, 0xf3, false);
    }
    void blsr(Reg32e r, Operand op)
    {
        opGpr(REG32E(1, r.getBit), op, r, MM_0F38, 0xf3, false);
    }
    void vgatherdpd(Xmm x1, Address addr, Xmm x2)
    {
        opGather(x1, addr, x2, MM_0F38 | PP_66, 0x92, 1, 0);
    }
    void vgatherqpd(Xmm x1, Address addr, Xmm x2)
    {
        opGather(x1, addr, x2, MM_0F38 | PP_66, 0x93, 1, 1);
    }
    void vgatherdps(Xmm x1, Address addr, Xmm x2)
    {
        opGather(x1, addr, x2, MM_0F38 | PP_66, 0x92, 0, 1);
    }
    void vgatherqps(Xmm x1, Address addr, Xmm x2)
    {
        opGather(x1, addr, x2, MM_0F38 | PP_66, 0x93, 0, 2);
    }
    void vpgatherdd(Xmm x1, Address addr, Xmm x2)
    {
        opGather(x1, addr, x2, MM_0F38 | PP_66, 0x90, 0, 1);
    }
    void vpgatherqd(Xmm x1, Address addr, Xmm x2)
    {
        opGather(x1, addr, x2, MM_0F38 | PP_66, 0x91, 0, 2);
    }
    void vpgatherdq(Xmm x1, Address addr, Xmm x2)
    {
        opGather(x1, addr, x2, MM_0F38 | PP_66, 0x90, 1, 0);
    }
    void vpgatherqq(Xmm x1, Address addr, Xmm x2)
    {
        opGather(x1, addr, x2, MM_0F38 | PP_66, 0x91, 1, 1);
    }
}// CodeGenerator
