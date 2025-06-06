/**
 * xbyak for the D programming language
 * Version: 0.7250
 * Date: 2025/06/06
 * See_Also:
 * Copyright: Copyright (c) 2007 MITSUNARI Shigeo, Copyright (c) 2019 deepprog
 * License: <http://opensource.org/licenses/BSD-3-Clause>BSD-3-Clause</a>.
 * Authors: herumi, deepprog
 */

module xbyak;

version(X86)    version = XBYAK32;
version(X86_64) version = XBYAK64;

version = XBYAK_ENABLE_OMITTED_OPERAND;
//version = XBYAK_NO_EXCEPTION;

//version = XBYAK_OLD_DISP_CHECK;
//version = XBYAK_NO_OP_NAMES;
//version = XBYAK_USE_MMAP_ALLOCATOR;
//version = XBYAK_USE_MEMFD;
//version = XBYAK_GNUC_PREREQ;
//version = XBYAK_DISABLE_SEGMENT;
//version = XBYAK_DISABLE_AVX512;
//version = XBYAK_TEST;
//version = XBYAK_DONT_READ_LIST;
//version = MIE_INTEGER_TYPE_DEFINED;
//version = XBYAK_VARIADIC_TEMPLATE;

import core.memory;
import core.stdc.stdio;
import core.stdc.stdlib;
import std.algorithm;
import std.array;
import std.conv;
import std.file;
import std.stdint;
import std.stdio;
import std.string;


  version (Windows)
  {
    import core.sys.windows.windows;  // VirtualProtect
  }

  version (Posix)
  {
    import core.sys.posix.fcntl;
    import core.sys.posix.sys.mman;
    import core.sys.posix.sys.stat;
    import core.sys.posix.unistd;
  }

size_t    DEFAULT_MAX_CODE_SIZE = 4096 * 8;
size_t    VERSION               = 0x0742;  // 0xABCD = A.BC(D)


  version(MIE_INTEGER_TYPE_DEFINED)
  {}
  else
  {
    // for backward compatibility
    alias uint64 = uint64_t;
    alias sint64 = int64_t;
    alias unit32 = uint32_t;
    alias int32  = int32_t;
    alias uint16 = uint16_t;
    alias uint8  = uint8_t;
  }

// MIE_ALIGN
T MIE_PACK(T)(T x, T y, T z, T w)
{
    pragma(inline, true);
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
    NOT_SUPPORTED,
    SAME_REGS_ARE_INVALID,
    INVALID_NF,
    INVALID_ZU,
    CANT_USE_REX2,
    INVALID_DFV,
    INVALID_REG_IDX,
    BAD_ENCODING_MODE,
    CANT_USE_ABCDH,
    INTERNAL // Put it at last.
}


string ConvertErrorToString(ERR err)
{
    string[] errTbl = [
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
        "not supported",
        "same regs are invalid",
        "invalid NF",
        "invalid ZU",
        "can't use rex2",
        "invalid dfv",
        "invalid reg index",
        "bad encoding mode",
        "can't use [abcd]h with rex",
        "internal error"
    ];
    
    assert(ERR.INTERNAL + 1 == errTbl.length);
    return err <= ERR.INTERNAL ? errTbl[err] : "unknown err";
}

  version(XBYAK_NO_EXCEPTION)
  {
    struct local
    {
        static ref int GetErrorRef()
        {
            static int err = 0;
            return err;
        }
        static void SetError(int err) {
            if (local.GetErrorRef()) return; // keep the first err code
            local.GetErrorRef() = err;
        }
    } // local
    void ClearError() { local.GetErrorRef() = 0; }
    int GetError() { return local.GetErrorRef(); }
    string XBYAK_THROW(ERR err)
    {
        return "local.SetError(" ~ typeof(err).stringof ~ "." ~ to!string(err) ~ "); return;";
    }
    string XBYAK_THROW_RET(ERR err, string r)
    {
        return "local.SetError(" ~ typeof(err).stringof ~ "." ~ to!string(err) ~ "); return " ~ r ~";";
    }
    string XBYAK_THROW_RET(string err, string r)
    {
        return "local.SetError(" ~ err ~ "); return " ~ r ~";";
    }
  }
  else
  {
    class XError : Exception
    {
        ERR err_;
    public:
        this(ERR err = ERR.NONE, string file = __FILE__, size_t line = __LINE__, Throwable next = null)
        {
            err_ = err;
            if (err_ < 0 || err_ > ERR.INTERNAL) err_ = ERR.INTERNAL;
            super(this.what(), file, line, next);
        }
        int opCast(T : int)() const {
            return err_;
        }
        string what() const
        {
            return ConvertErrorToString(err_);
        }
    }
    string ConvertErrorToString(XError err) {
        return err.what();
    }
    // dummy functions
    void ClearError() { }
    int GetError() { return 0; }


    string XBYAK_THROW(ERR err)
    {
        return "throw new XError(" ~ typeof(err).stringof ~ "." ~ to!string(err) ~ ");";
    }
    string XBYAK_THROW_RET(ERR err, string r)
    {
        return "throw new XError(" ~ typeof(err).stringof ~ "." ~ to!string(err) ~ ");";
    }
    string XBYAK_THROW_RET(string err, string r)
    {
        return "throw new XError(" ~ err ~ ");";
    }
  } //version(XBYAK_NO_EXCEPTION)

  version(CRuntime_Microsoft)
  {
    @nogc nothrow pure private extern(C) void* _aligned_malloc(size_t, size_t);
    @nogc nothrow pure private extern(C) void _aligned_free(void* memblock);
    
    void* AlignedMalloc(size_t size, size_t alignment)
    {
        return _aligned_malloc(size, alignment);
    }
    void AlignedFree(void* p)
    {
        _aligned_free(p);
    }
  }

  version (Posix)
  {
    import core.sys.posix.stdlib : posix_memalign;

    void* AlignedMalloc(size_t size, size_t alignment)
    {
        void* p;
        int ret = posix_memalign(&p, alignment, size);
        return (ret == 0) ? p : null;
    }
    void AlignedFree(void* p)
    {
        free(p);
    }
  }


To CastTo(To, From)(From p)
{
    return cast(const To)cast(size_t)(p);
}

struct inner
{
static:
    size_t getPageSize()
    {
        size_t pageSize = 4096;
  version(Windows)
  {        
        import core.sys.windows.windows;
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        pageSize = sysinfo.dwAllocationGranularity;
  }

  version(Posix)
  {        
        import core.sys.posix.unistd;
        pageSize = cast(size_t) sysconf(_SC_PAGESIZE); 
  }
        return pageSize;
    }
    
    
    bool IsInDisp8(uint32_t x) { return 0xFFFFFF80 <= x || x <= 0x7F; }
    bool IsInInt32(uint64_t x) { return ~uint64_t(0x7fffffffu) <= x || x <= 0x7FFFFFFFu; }

    uint32_t VerifyInInt32(uint64_t x)
    {
        version (XBYAK64)
        {
            if (!IsInInt32(x)) mixin(XBYAK_THROW_RET(ERR.OFFSET_IS_TOO_BIG, "0"));
        }
        return cast(uint32_t)x;
    }

    enum LabelMode
    {
        LasIs, // as is
        Labs, // absolute
        LaddTop // (addr + top) for mov(reg, label) with AutoGrow
    }
}// inner

/*
    custom allocator
*/
class Allocator
{
    this(string = "") {} // same interface with MmapAllocator
    // ~this() {}
    uint8_t* alloc(size_t size)
    {
        void* p = AlignedMalloc(size, inner.getPageSize());
        GC.addRange(p, (p is null ? 0 : size));
        return cast(uint8_t*)p;
    }
    void free(uint8_t* p)
    {
        GC.removeRange(cast(void*)p);
        AlignedFree(p);
    } 
    /* override to return false if you call protect() manually */
    bool useProtect() const { return true; }
}

  version(XBYAK_USE_MEMFD)
  {
    extern(C) int memfd_create(const char*, uint);
  }

  version(XBYAK_USE_MMAP_ALLOCATOR)
  {
    class MmapAllocator : Allocator
    {
        struct Allocation
        {
            size_t size;
            version(XBYAK_USE_MEMFD)
            {
            // fd_ is only used with XBYAK_USE_MEMFD. We keep the file open
            // during the lifetime of each allocation in order to support
            // checkpoint/restore by unprivileged users.
                int fd;
            }    
        }
    
        string name_; // only used with XBYAK_USE_MEMFD
        alias AllocationList = Allocation[uintptr_t];
        AllocationList allocList_;
    
    public:
        this(string name = "xbyak")
        {
            this.name_ = name;
        }

        override uint8_t* alloc(size_t size)
        {
            const size_t alignedSizeM1 = inner.getPageSize() - 1;
            size = (size + alignedSizeM1) & ~alignedSizeM1;
            int mode = MAP_PRIVATE | MAP_ANON;
            int fd = -1; 
      version(XBYAK_USE_MEMFD)
      {
            uint flag = 0;
            fd = memfd_create(name_.toStringz(), flag);
            if (fd != -1)
            {
                mode = MAP_SHARED;
                if (ftruncate(fd, size) != 0)
                {
                    close(fd);
                    mixin(XBYAK_THROW_RET(ERR.CANT_ALLOC, "0"));
                }
            }
      }
            void* p = mmap(null, size, PROT_READ | PROT_WRITE, mode, fd, 0);
            if (p == MAP_FAILED)
            {
                if (fd != -1)
                {
                    close(fd);
                }
                mixin(XBYAK_THROW_RET(ERR.CANT_ALLOC, "0"));
            }
            assert(p);
            uintptr_t uip = cast(uintptr_t)p;
            allocList_[uip] = Allocation();
            Allocation* alloc = &allocList_[uip];
            alloc.size = size;
    
      version(XBYAK_USE_MEMFD)
      {
            alloc.fd = fd;
      }
            GC.addRange(p, (p is null ? 0 : size));
            return cast(uint8_t*)p;
        }

        override void free(uint8_t* p)
        {
            if (p == null) return;
            uintptr_t uip = cast(uintptr_t)p;
            if (null == (uip in allocList_)) mixin(XBYAK_THROW(ERR.BAD_PARAMETER));
            
            GC.removeRange(cast(void*)p);
            if (munmap(cast(void*)uip, allocList_[uip].size) < 0) mixin(XBYAK_THROW(ERR.MUNMAP));

      version(XBYAK_USE_MEMFD)
      {
            if (allocList_[uip].fd != -1)
            {
                close(allocList_[uip].fd);
            }
      }
            allocList_.remove(uip);
    }
}
  }

  version(XBYAK_USE_MMAP_ALLOCATOR)
  {}
  else
  {
    alias MmapAllocator = Allocator;
  }

struct ApxFlagNF
{
    T opBinaryRight(string op:"|", T) (T t)
    {        
        T r = new T(t);
        r.setNF();
        return r;
    }
}

struct ApxFlagZU
{
    T opBinaryRight(string op:"|", T) (T t)
    {        
        T r = new T(t);
        r.setZU();
        return r;
    }
}

// dfv (default flags value) is or operation of these flags
static const int T_of = 8;
static const int T_sf = 4;
static const int T_zf = 2;
static const int T_cf = 1;


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
    BNDREG = 1 << 8,
    TMM = 1 << 9
}


public class Operand
{
private:
    static const uint8_t EXT8BIT = 0x20;
    uint idx_ = 6; // 0..31 + EXT8BIT = 1 if spl/bpl/sil/dil
    uint kind_= 10;
    uint bit_= 14;

protected:
    bool zero_= false;
    uint mask_= 3;
    uint rounding_ = 3;
    uint NF_ = 1;
    uint ZU_= 1; // ND=ZU
    void setIdx(int idx) { idx_ = idx; }

public:
    enum Kind : int
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
        BNDREG = 1 << 8,
        TMM = 1 << 9
    }
    
  version(XBYAK64)
  {
    enum : int //Code
    {
        RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15,
        R16, R17, R18, R19, R20, R21, R22, R23, R24, R25, R26, R27, R28, R29, R30, R31,
        R8D = 8, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
        R16D, R17D, R18D, R19D, R20D, R21D, R22D, R23D, R24D, R25D, R26D, R27D, R28D, R29D, R30D, R31D,
        R8W = 8, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
        R16W, R17W, R18W, R19W, R20W, R21W, R22W, R23W, R24W, R25W, R26W, R27W, R28W, R29W, R30W, R31W,
        R8B = 8, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
        R16B, R17B, R18B, R19B, R20B, R21B, R22B, R23B, R24B, R25B, R26B, R27B, R28B, R29B, R30B, R31B,
        SPL = 4, BPL, SIL, DIL,
    }
  }
    enum : int //Code 
    {
        EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
        AX = 0, CX, DX, BX, SP, BP, SI, DI,
        AL = 0, CL, DL, BL, AH, CH, DH, BH
    }

    this()
    {
        idx_ = 0;
        kind_ = 0;
        bit_ = 0;
        zero_ = false;
        mask_ = 0;
        rounding_ = 0;
        NF_ = 0;
        ZU_ = 0;
    }

    this(int idx, int kind, int bit, bool ext8bit = false)
    {
        idx_ = cast(uint8_t)(idx | (ext8bit ? EXT8BIT : 0));
        kind_ = kind;
        bit_  = bit;
        zero_ = false;
        mask_ = 0;
        rounding_ = 0;
        NF_ = 0;
        ZU_ = 0;
        assert((bit_ & (bit_ - 1)) == 0); // bit must be power of two
    }

    this(Operand op)
    {
        this.idx_ = op.idx_;
        this.kind_ = op.kind_;
        this.bit_  = op.bit_;
        this.zero_ = op.zero_;
        this.mask_ = op.mask_;
        this.rounding_ = op.rounding_;
        this.NF_ = op.NF_;
        this.ZU_ = op.ZU_;
        assert((bit_ & (bit_ - 1)) == 0); // bit must be power of two
    }
    
    static Operand opCall()
    {
        return new Operand();
    }

    int getKind() const { return cast(Kind)kind_; }
    int getIdx () const { return idx_ & (EXT8BIT - 1); }
    bool hasIdxBit(int bit) const { return cast(bool)(idx_ & (1<<bit)); }
    bool isNone () const {return this.kind_ == 0; }
    bool isMMX  () const { return isKind(Kind.MMX); }
    bool isXMM  () const { return isKind(Kind.XMM); }
    bool isYMM  () const { return isKind(Kind.YMM); }
    bool isZMM  () const { return isKind(Kind.ZMM); }
    bool isSIMD() const { return isKind(Kind.XMM | Kind.YMM | Kind.ZMM); }
    bool isTMM() const { return isKind(Kind.TMM); }
    bool isXMEM() const { return isKind(Kind.XMM | Kind.MEM); }
    bool isYMEM() const { return isKind(Kind.YMM | Kind.MEM); }
    bool isZMEM() const { return isKind(Kind.ZMM | Kind.MEM); }
    bool isOPMASK() const { return isKind(Kind.OPMASK); }
    bool isBNDREG() const { return isKind(Kind.BNDREG); }
    bool isREG(int bit = 0) const { return isKind(Kind.REG, bit); }
    bool isMEM(int bit = 0) const { return isKind(Kind.MEM, bit); }
    bool isFPU  () const { return isKind(Kind.FPU);}
    bool isExt8bit() const { return (idx_ & EXT8BIT) != 0; }
    bool isExtIdx() const { return (getIdx() & 8) != 0; }
    bool isExtIdx2() const { return (getIdx() & 16) != 0; }
    bool hasEvex() const { return isZMM() || isExtIdx2() || getOpmaskIdx() || getRounding(); }
    bool hasRex() const { return isExt8bit() || isREG(64) || isExtIdx(); }
    bool hasRex2() const {
        return (isREG() && isExtIdx2()) || (isMEM() && (cast(Address)this).hasRex2());
    }     
    bool hasRex2NF() const { return hasRex2() || NF_; }
    bool hasRex2NFZU() const { return hasRex2() || NF_ || ZU_; }
    bool hasZero() const { return zero_; }
    int getOpmaskIdx() const { return mask_; }
    int getRounding() const { return rounding_; }
    void setKind(int kind)
    {
        if ((kind & (Kind.XMM | Kind.YMM | Kind.ZMM | Kind.TMM)) == 0) return;
        kind_ = kind;
        bit_ = kind == Kind.XMM ? 128 : kind == Kind.YMM ? 256 : kind == Kind.ZMM ? 512 : 8192;
    }
    // err if MMX/FPU/OPMASK/BNDREG
    void setBit(int bit)
    {
        if (bit != 8 && bit != 16 && bit != 32 && bit != 64 &&
            bit != 128 && bit != 256 && bit != 512 && bit != 8192) goto ERR;
        if (isBit(bit)) return;
        if (isKind(Kind.MEM | Kind.OPMASK)) {
            this.bit_ = bit;
            return;
        }
        
        if (isKind(Kind.REG | Kind.XMM | Kind.YMM | Kind.ZMM | Kind.TMM)) {
            int idx = getIdx();
            // err if converting ah, bh, ch, dh
            if (isREG(8) && (4 <= idx && idx < 8) && !isExt8bit) goto ERR;
            Kind kind = Kind.REG;
            switch (bit)
            {
                case 8:
  version(XBYAK32)
  {
                    if (idx >= 4) goto ERR;
  }
  else
  {
                    if (idx >= 32) goto ERR;
                    if (4 <= idx && idx < 8) idx |= EXT8BIT;
  }
                    break;
                case 16:
                case 32:
                case 64:
  version(XBYAK32)
  {
                    if (idx >= 16) goto ERR;
  }
  else
  {
                    if (idx >= 32) goto ERR;
  }    
                    break;
                case 128: kind = Kind.XMM; break;
                case 256: kind = Kind.YMM; break;
                case 512: kind = Kind.ZMM; break;
                case 8192: kind = Kind.TMM; break;
                default:    assert(0);
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
        mixin(XBYAK_THROW(ERR.CANT_CONVERT));
    }
    void setOpmaskIdx(int idx, bool /*ignore_idx0*/ = true)
    {
        if (mask_) mixin(XBYAK_THROW(ERR.OPMASK_IS_ALREADY_SET));
        mask_ = idx;
    }
    void setRounding(int idx)
    {
        if (rounding_) mixin(XBYAK_THROW(ERR.ROUNDING_IS_ALREADY_SET));
        rounding_ = idx;
    }
    void setZero() { zero_ = true; }
    void setNF() { NF_ = true; }
    int getNF() const { return NF_; }
    void setZU() { ZU_ = true; }
    int getZU() const { return ZU_; }
    // ah, ch, dh, bh?
    bool isHigh8bit() const
    {
        if (!isBit(8)) return false;
        if (isExt8bit()) return false;
        const int idx = getIdx();
        return Operand.AH <= idx && idx <= Operand.BH;
    }
    // any bit is accetable if bit == 0
    bool isKind(int kind, uint32_t bit = 0) const
    {
        return (kind == 0 || (kind_ & kind)) && (bit == 0 || (bit_ & bit)); // cf. you can set (8|16)
    }
    bool isBit(uint32_t bit) const { return (bit_ & bit) != 0; }
    uint32_t getBit() const { return bit_;}

    override string toString() const
    {
        const int idx = getIdx();
        if (kind_ == Kind.REG) {
            if (isExt8bit()) {
                string[4] tbl = ["spl", "bpl", "sil", "dil"];
                return tbl[idx - 4];
            }
            string[32][4] tbl = [
                ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
                 "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
                 "r16b", "r17b", "r18b", "r19b", "r20b", "r21b", "r22b", "r23b",
                 "r24b","r25b", "r26b", "r27b", "r28b", "r29b", "r30b", "r31b"],

                ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
                 "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
                 "r16w", "r17w", "r18w", "r19w", "r20w", "r21w", "r22w", "r23w",
                 "r24w", "r25w", "r26w", "r27w", "r28w", "r29w", "r30w", "r31w"],
                
                ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                 "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
                 "r16d", "r17d", "r18d", "r19d", "r20d", "r21d", "r22d", "r23d",
                 "r24d", "r25d", "r26d", "r27d", "r28d", "r29d", "r30d", "r31d"],
                
                ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                 "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
                 "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"],
            ];
            return tbl[bit_ == 8 ? 0 : bit_ == 16 ? 1 : bit_ == 32 ? 2 : 3][idx];
        } else if (isOPMASK()) {
            string[8] tbl = ["k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"];
            return tbl[idx];
        } else if (isTMM()) {
            string[8] tbl = ["tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7"];
            return tbl[idx];
        } else if (isZMM()) {
            string[32] tbl = [ 
                "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
                "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
                "zmm16", "zmm17", "zmm18","zmm19","zmm20", "zmm21", "zmm22", "zmm23", 
                "zmm24", "zmm25" ,"zmm26", "zmm27", "zmm28","zmm29", "zmm30", "zmm31"
            ];
            return tbl[idx];
        } else if (isYMM()) {
            string[32] tbl = [ 
                "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
                "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
                "ymm16", "ymm17", "ymm18","ymm19", "ymm20", "ymm21", "ymm22", "ymm23",
                "ymm24", "ymm25", "ymm26", "ymm27", "ymm28", "ymm29", "ymm30", "ymm31"
            ];
            return tbl[idx];
        } else if (isXMM()) {
            string[32] tbl = [ 
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
                "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
                "xmm16", "xmm17", "xmm18","xmm19", "xmm20", "xmm21", "xmm22", "xmm23",
                "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31"
            ];
            return tbl[idx];
        } else if (isMMX()) {
            string[8] tbl = ["mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"];
            return tbl[idx];
        } else if (isFPU()) {
            string[8] tbl = ["st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"];
            return tbl[idx];
        } else if (isBNDREG()) {
            string[4] tbl = ["bnd0", "bnd1", "bnd2", "bnd3"];
            return tbl[idx];
        }
        mixin(XBYAK_THROW_RET(ERR.INTERNAL, "null"));
    }

    bool isEqualIfNotInherited(Operand rhs) const
    {
        bool Idx_ = this.idx_ == rhs.idx_;
        bool Kind_ = this.kind_ == rhs.kind_;
        bool Bit_ = this.bit_ == rhs.bit_;
        bool Zero_ = this.zero_ == rhs.zero_;
        bool Mask_ = this.mask_ == rhs.mask_;
        bool Rounding_ = this.rounding_ == rhs.rounding_;
        return Idx_ && Kind_ && Bit_ && Zero_ && Mask_ && Rounding_;
    }
    override bool opEquals(Object o) const
    {
        Operand rhs = cast(Operand) o;
        if (this.isMEM() && rhs.isMEM()) return this.getAddress() == rhs.getAddress();
        return isEqualIfNotInherited(rhs);
    }
    Address getAddress() const
    {
        assert(isMEM());
        return cast(Address)this;
    }
    Address getAddress(int immSize) const
    {
        Address addr = getAddress();
        addr.immSize = immSize;
        return addr;
    }
    Reg getReg() const
    {
        assert(!isMEM());
        Reg ret = new Reg(this.getIdx(), this.getKind(), this.getBit(), this.isExt8bit());
        return ret;
    }    
}


public class Reg : Operand
{
public:
    this(){}
    this(int idx, int kind, int bit = 0, bool ext8bit = false)
    {
        super(idx, kind, bit, ext8bit);
    }
    this(Reg r)
    {
        super(cast(Operand)r);
    }
    static Reg opCall()
    {
        return new Reg();
    }
    static Reg opCall(int idx, int kind, int bit = 0, bool ext8bit = false)
    {
        return new Reg(idx, kind, bit, ext8bit);
    }

    // convert to Reg8/Reg16/Reg32/Reg64/XMM/YMM/ZMM
    Reg changeBit(int bit) 
    {
        Reg r = new Reg(this);
        r.setBit(bit);
        return r; 
    }
    Reg8 cvt8()
    {
        Reg r = this.changeBit(8); return new Reg8(r.getIdx(), r.isExt8bit());
    }
    Reg16 cvt16()
    {
        return new Reg16(changeBit(16).getIdx());
    }
    Reg32 cvt32()
    {
        return new Reg32(changeBit(32).getIdx());
    }

  version(XBYAK64)
  {
    Reg64 cvt64()
    {
        return new Reg64(changeBit(64).getIdx());
    }
  }

    Xmm cvt128()
    {
        return new Xmm(changeBit(128).getIdx());
    }
    Ymm cvt256()
    {
        return new Ymm(changeBit(256).getIdx());
    }
    Zmm cvt512()
    {
        return new Zmm(changeBit(512).getIdx());
    }
    
    override Reg getReg() const
    {
        assert(!isMEM());
        Reg r = new Reg(cast(Reg)this);
        return r;
    }

    RegExp opBinary(string op:"+") (Reg b)
    {
        return RegExp(this) + RegExp(b);
    }
    RegExp opBinary(string op:"*") (int scale)
    {
        return RegExp(this, scale);
    }
    RegExp opBinaryRight(string op:"*") (int scale)
    {
        return this * scale;
    }
    RegExp opBinary(string op:"+") (int disp)
    {
        return RegExp(this) + disp;
    }
    RegExp opBinaryRight(string op:"+") (int disp)
    {
        return RegExp(this) + disp;
    }
    RegExp opBinary(string op:"-") (int disp)
    {
        return RegExp(this) - disp;
    }
    RegExp opBinaryRight(string op:"-") (int disp)
    {
        return RegExp(this) - disp;
    }
}


public class Reg8 : Reg
{
public:
    this(int idx, bool ext8bit = false)
    {
        super(idx, Kind.REG, 8, ext8bit);
    }
    this(Reg8 r)
    {
        super(cast(Reg)r);
    }
    static Reg8 opCall(int idx = 0, bool ext8bit = false)
    {
        return new Reg8(idx, ext8bit);
    }
}

public class Reg16 : Reg
{
public:
    this(int idx)
    {
        super(idx, Kind.REG, 16);
    }
    this(Reg16 r)
    {
        super(cast(Reg)r);
    }
    static Reg16 opCall(int idx)
    {
        return new Reg16(idx);
    }
}

public class Mmx : Reg
{
public:
    this(int idx, int kind = Kind.MMX, int bit = 64)
    {
        super(idx, kind, bit);
    }
    this(Mmx m)
    {
        super(cast(Reg)m);
    }
    static Mmx opCall(int idx)
    {
        return new Mmx(idx);
    }
}

struct EvexModifierRounding
{
    enum {
        T_RN_SAE = 1,
        T_RD_SAE = 2,
        T_RU_SAE = 3,
        T_RZ_SAE = 4,
        T_SAE = 5
    }
    
    this(int rounding)
    {
        this.rounding_ = rounding;
    }

    int rounding_;
    
    T opBinaryRight(string op:"|", T)(T x)
    {        
        T r = new T(x);
        r.setRounding(this.rounding_);
        return r;
    }
}

struct EvexModifierZero
{
    T opBinaryRight(string op:"|", T)(T x)
    {
        T r = new T(x);    
        r.setZero();
        return r;
    }
}


public class Xmm : Mmx
{
public:
    this(int idx, int kind = Kind.XMM, int bit = 128)
    {
        super(idx, kind, bit);
    }
    this(Xmm x)
    {
        super(cast(Mmx)x);
    }
    static Xmm opCall(int idx)
    {
        return new Xmm(idx);
    }
    static Xmm opCall(int kind, int idx)
    {
        return new Xmm(idx, kind, kind == Kind.XMM ? 128 : kind == Kind.YMM ? 256 : 512);
    }
    Xmm copyAndSetIdx(int idx)
    {
        Xmm ret = new Xmm(this);
        ret.setIdx(idx);
        return ret;
    }
    Xmm copyAndSetKind(int kind)
    {
        Xmm ret = new Xmm(this);
        ret.setKind(kind);
        return ret;
    }
}


public class Ymm : Xmm
{
public:
    this(int idx, int kind = Kind.YMM, int bit = 256)
    {
        super(idx, kind, bit);
    }
    this(Ymm y)
    {
        super(cast(Xmm)y);
    }
    static Ymm opCall(int idx)
    {
        return new Ymm(idx);
    }
}

public class Zmm : Ymm
{
public:
    this(int idx, int kind = Kind.ZMM, int bit = 512)
    {
        super(idx, kind, bit);
    }
    this(Zmm z)
    {
        super(cast(Ymm)z);
    }
    static Zmm opCall(int idx)
    {
        return new Zmm(idx);
    }
}

  version(XBYAK64)
  {
    public class Tmm : Reg
    {
    public:
        this(int idx, Kind kind = Kind.TMM, int bit = 8192)
        {
            super(idx, kind, bit);
        }
        this(Tmm t)
        {
            super(cast(Reg)t);
        }
        static Tmm opCall(int idx)
        {
            return new Tmm(idx);
        }
    }
  }


class Opmask : Reg
{
    this(int idx)
    {
        super(idx, Kind.OPMASK, 64);
    }
    this(Opmask opmask)
    {
        super(cast(Reg)opmask);
    }
    static Opmask opCall(int idx)
    {
        return new Opmask(idx);
    }
    T opBinaryRight(string op:"|", T)(T x)
    {
        T r = new T(x);
        r.setOpmaskIdx(this.getIdx());
        return r;
    }
}

class BoundsReg : Reg
{
    this(int idx)
    {
        super(idx, Kind.BNDREG, 128);
    }
    this(BoundsReg b)
    {
        super(cast(Reg)b);
    }
    static BoundsReg opCall(int idx)
    {
        return new BoundsReg(idx);
    }
}


public class Fpu : Reg
{
public:
    this(int idx)
    {
        super(idx, Kind.FPU, 32);
    }
    this(Fpu f)
    {
        super(cast(Reg)f);
    }
    static Fpu opCall(int idx)
    {
        return new Fpu(idx);
    }
}


public class Reg32e : Reg
{
    this(int idx, int bit)
    {
        super(idx, Kind.REG, bit);
    }
    this(Reg32e r)
    {
        super(cast(Reg)r);
    }
    static Reg32e opCall(int idx, int bit)
    {
        return new Reg32e(idx, bit);
    }
}


public class Reg32 : Reg32e
{
    this(int idx, int bit = 32)
    {
        super(idx, bit);
    }
    this(Reg32 reg32)
    {
        super(cast(Reg32e)reg32);
    }
    static Reg32 opCall(int idx)
    {
        return new Reg32(idx);
    }
}

  version (XBYAK64)
  {
    public class Reg64 : Reg32e
    {
        this(int idx, int bit = 64)
        {
            super(idx, bit);
        }
        this(Reg64 reg64)
        {
            super(cast(Reg32e)reg64);
        }
        static Reg64 opCall(int idx)
        {
            return new Reg64(idx);
        }
    }

    struct RegRip
    {
        int64_t disp_ = 0;
        Label* label_;
        bool isAddr_;
        
        this(int64_t disp, Label* label = null, bool isAddr = false)
        {
            disp_  = disp;
            label_ = label;
            isAddr_ = isAddr;
        }
        RegRip opBinary(string op:"+") (int disp)
        {
            return RegRip(this.disp_ + disp, this.label_, this.isAddr_);
        }
        RegRip opBinary(string op:"-") (int disp)
        {
            return RegRip(this.disp_ - disp, this.label_, this.isAddr_);
        }
        RegRip opBinary(string op:"+") (int64_t disp)
        {
            return RegRip(this.disp_ + disp, this.label_, this.isAddr_);
        }
        RegRip opBinary(string op:"-") (int64_t disp)
        {
            return RegRip(this.disp_ - disp, this.label_, this.isAddr_);
        }
        RegRip opBinary(string op:"+") (ref Label label)
        {
            if (this.label_ || this.isAddr_) mixin(XBYAK_THROW_RET(ERR.BAD_ADDRESSING, "RegRip()"));
            return RegRip(this.disp_, &label);
        }
        RegRip opBinary(string op:"+")(void* addr)
        {
            if (this.label_ || this.isAddr_) mixin(XBYAK_THROW_RET(ERR.BAD_ADDRESSING, "RegRip()"));
            return RegRip(this.disp_ + cast(int64_t)addr, null, true);
        }
    }
  }

  version(XBYAK_DISABLE_SEGMENT)
  {}
  else
  {
    // not derived from Reg
    struct Segment
    {
        int idx_;
    public:
        enum {
            es, cs, ss, ds, fs, gs
        }
        this(int idx){ assert(0 <= idx_ && idx_ < 6); idx_ = idx; }
        int getIdx() const { return idx_; }
        string toString() const
        {
            string[] tbl = [
                "es", "cs", "ss", "ds", "fs", "gs"
            ];
            return tbl[idx_];
        }
    }
  }

struct RegExp
{
public:
  version(XBYAK64)
  {
    enum { i32e = 32 | 64 }
  }
  else
  {
    enum { i32e = 32 }
  }    
    
    this(size_t disp)
    {
        scale_ = 0;
        disp_ = disp;
    }
    
    this(Reg r, int scale = 1)
    {
        scale_ = scale;
        disp_ = 0;
        if (!r.isREG(i32e) && !r.isKind(Kind.XMM | Kind.YMM | Kind.ZMM | Kind.TMM)) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        if (scale == 0) return;
        if (scale != 1 && scale != 2 && scale != 4 && scale != 8) mixin(XBYAK_THROW(ERR.BAD_SCALE));
        if (r.getBit() >= 128 || scale != 1) { // xmm/ymm is always index
            index_ = r;
        } else {
            base_ = r;
        }
    }
    bool isVsib(int bit = 128 | 256 | 512) const { return index_.isBit(bit); }
    
    RegExp optimize()
    {
        RegExp exp = this;
        // [reg * 2] => [reg + reg]
        if (index_.isBit(i32e) && !base_.getBit() && scale_ == 2) {
            exp.base_ = this.index_;
            exp.scale_ = 1;
        }
        return exp;
    }
    bool opEquals(const ref RegExp rhs) const
    {    
        bool Base_ = this.base_ == rhs.base_;
        bool Index_ = this.index_ == rhs.index_;
        bool Dsip_ = this.disp_ == rhs.disp_;
        bool Scale_ = this.scale_ == rhs.scale_;
        return Base_ && Index_ && Dsip_ && Scale_;
    }
    
    Reg getBase() const { return cast(Reg)base_; }
    Reg getIndex() const { return cast(Reg)index_; }
    int getScale() const { return scale_; }
    size_t getDisp() const { return disp_; }
    
    void verify() const
    {
        if (base_.getBit() >= 128) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        if (index_.getBit() && index_.getBit() <= 64)
        {
            if (index_.getIdx()== Operand.ESP) mixin(XBYAK_THROW(ERR.ESP_CANT_BE_INDEX));
            if (base_.getBit() && base_.getBit() != index_.getBit()) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        }
    }

    RegExp opBinary(string op:"+") (RegExp b)
    {
        if (this.index_.getBit() && b.index_.getBit()) mixin(XBYAK_THROW_RET(ERR.BAD_ADDRESSING, "RegExp()"));
        RegExp ret = this;
        if (!ret.index_.getBit()) { ret.index_ = b.index_; ret.scale_ = b.scale_; }
        if (b.base_.getBit()) {
            if (ret.base_.getBit()) {
                if (ret.index_.getBit()) mixin(XBYAK_THROW_RET(ERR.BAD_ADDRESSING, "RegExp()"));
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
   
    RegExp opBinary(string op:"+") (Reg b)
    {
        return this + RegExp(b);
    }
    RegExp opBinaryRight(string op:"+") (Reg a)
    {
        return RegExp(a) + this;
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
    Reg base_ = Reg();
    Reg index_ = Reg();
    int scale_ = 0;
    size_t disp_ = 0;
}

// 2nd parameter for constructor of CodeArray(maxSize, userPtr, alloc)
enum AutoGrow = cast(void*)1; 
enum DontSetProtectRWE = cast(void*)2;

class CodeArray
{
    enum Type {
        USER_BUF = 1, // use userPtr(non alignment, non protect)
        ALLOC_BUF,    // use new(alignment, protect)
        AUTO_GROW     // automatically move and grow memory if necessary
    }
    
    bool isAllocType() const
    {
        return type_ == Type.ALLOC_BUF || type_ == Type.AUTO_GROW;
    }

    struct AddrInfo
    {
        size_t codeOffset; // position to write
        size_t jmpAddr;    // value to write
        int jmpSize;       // size of jmpAddr
        inner.LabelMode mode;
        this(size_t _codeOffset, size_t _jmpAddr, int _jmpSize, inner.LabelMode _mode)
        {
            this.codeOffset = _codeOffset;
            this.jmpAddr = _jmpAddr;
            this.jmpSize = _jmpSize;
            this.mode = _mode;
        }

        uint64_t getVal(uint8_t* top) const
        {
            uint64_t disp = (mode == inner.LabelMode.LaddTop) ? jmpAddr + cast(size_t) top : (mode == inner.LabelMode.LasIs) ? jmpAddr : jmpAddr - cast(size_t) top;
            if (jmpSize == 4) { disp = inner.VerifyInInt32(disp); }
            return disp;
        }
    }

    alias AddrInfoList = AddrInfo[] ;
    AddrInfoList addrInfoList_;
    Type type_;

  version(XBYAK_USE_MMAP_ALLOCATOR)
  {
    MmapAllocator defaultAllocator_ = new MmapAllocator();
  }
  else
  {
    Allocator defaultAllocator_ = new Allocator();
  }
    Allocator alloc_;
protected:
    size_t maxSize_;
    uint8_t* top_;
    size_t size_;
    bool isCalledCalcJmpAddress_;

    bool useProtect() { return alloc_.useProtect(); }

    /*
        allocate new memory and copy old data to the new area
    */
    void growMemory()
    {
        size_t newSize  = max!(size_t)(DEFAULT_MAX_CODE_SIZE, maxSize_ * 2);
        uint8_t* newTop = alloc_.alloc(newSize);
        if(newTop == null) mixin(XBYAK_THROW(ERR.CANT_ALLOC));
        for (size_t i = 0; i < size_; i++) newTop[i] = top_[i];
        alloc_.free(top_);
        top_     = newTop;
        maxSize_ = newSize;
    }

//    calc jmp address for AutoGrow mode
    void calcJmpAddress()
    {
        if (isCalledCalcJmpAddress_) return;
        foreach (i; addrInfoList_)
        {
            uint64_t disp = i.getVal(top_);
            rewrite(i.codeOffset, disp, i.jmpSize);
        }
        isCalledCalcJmpAddress_ = true;
    }

public:
    enum ProtectMode {
        PROTECT_RW = 0, // read/write
        PROTECT_RWE = 1, // read/write/exec
        PROTECT_RE = 2 // read/exec
    }
    
    this(size_t maxSize, void* userPtr = null, Allocator allocator = null)
    {
        type_ = (userPtr == AutoGrow ? Type.AUTO_GROW : (userPtr == null || userPtr == DontSetProtectRWE) ? Type.ALLOC_BUF : Type.USER_BUF);
        alloc_  = allocator ? allocator : defaultAllocator_;
        maxSize_ = maxSize;
        top_ = type_ == Type.USER_BUF ? cast(uint8_t*)userPtr: alloc_.alloc(max(maxSize, 1));
        size_ = 0;
        isCalledCalcJmpAddress_ = false;

        if (maxSize_ > 0 && top_ == null)    mixin(XBYAK_THROW(ERR.CANT_ALLOC));
        if ((type_ == Type.ALLOC_BUF && userPtr != DontSetProtectRWE && alloc_.useProtect()) && !setProtectMode(ProtectMode.PROTECT_RWE, false))
        {
            alloc_.free(top_);
            mixin(XBYAK_THROW(ERR.CANT_PROTECT));
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
        if (throwException) mixin(XBYAK_THROW_RET(ERR.CANT_PROTECT, "false"));
        return false;
    }
    bool setProtectModeRE(bool throwException = true) { return setProtectMode(ProtectMode.PROTECT_RE, throwException); }
    bool setProtectModeRW(bool throwException = true) { return setProtectMode(ProtectMode.PROTECT_RW, throwException); }
    void resetSize()
    {
        size_ = 0;
        addrInfoList_.length = 0;
        isCalledCalcJmpAddress_ = false;
    }
    void db(int code)
    {
        if (size_ >= maxSize_) {
            if (type_ == Type.AUTO_GROW) {
                growMemory();
            } else {
                mixin(XBYAK_THROW(ERR.CODE_IS_TOO_BIG));
            }
        }
        top_[size_++] = cast(uint8_t)code;
    }
    void db(uint8_t* code, size_t codeSize)
    {
        for (size_t i = 0; i < codeSize; i++) db(code[i]);
    }
    void db(uint64_t code, size_t codeSize)
    {
        if (codeSize > 8) mixin(XBYAK_THROW(ERR.BAD_PARAMETER));
        for (size_t i = 0; i < codeSize; i++) db( cast(uint8_t)(code >> (i * 8)));
    }
    void dw(uint32_t code) { db(code, 2); } 
    void dd(uint32_t code) { db(code, 4); }
    void dq(uint64_t code) { db(code, 8); }
    uint8_t* getCode() { return top_; }
    F getCode(F)() const { return CastTo !(F)(top_); }
    uint8_t* getCurr() { return &top_[size_];}
    F getCurr(F)() const { return CastTo !(F)(&top_[size_]); }
    size_t getSize() const { return size_; }
    void setSize(size_t size)
    {
        if (size > maxSize_) mixin(XBYAK_THROW(ERR.OFFSET_IS_TOO_BIG));
        size_ = size;
    }
    void dump(bool doClear = false) 
    {
        uint8_t* p     = getCode();
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
                if (j < disp) {
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
  version(XBYAK_TEST)
  {
        if (doClear) size_ = 0;
  }    
    }

//  @param data [in] address of jmp data
//  @param disp [in] offset from the next of jmp
//  @param size [in] write size(1, 2, 4, 8)
    void rewrite(size_t offset, uint64_t disp, size_t size)
    {
        assert(offset < maxSize_);
        if (size != 1 && size != 2 && size != 4 && size != 8) mixin(XBYAK_THROW(ERR.BAD_PARAMETER));
        uint8_t* data = top_ + offset;
        for (size_t i = 0; i < size; i++) {
            data[i] = cast(uint8_t)(disp >> (i * 8));
        }
    }
    void save(size_t offset, size_t val, int size, inner.LabelMode mode)
    {
        addrInfoList_ ~= AddrInfo(offset, val, size, mode);
    }
    bool isAutoGrow() const { return type_ == Type.AUTO_GROW; }
    bool isCalledCalcJmpAddress() const { return isCalledCalcJmpAddress_; }
    /*
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
        switch (protectMode_) {
            case ProtectMode.PROTECT_RW: mode = c_rw; break;
            case ProtectMode.PROTECT_RWE: mode = c_rwe; break;
            case ProtectMode.PROTECT_RE: mode = c_re; break;
            default:
                return false;
        }
  version(Windows)
  {
        DWORD oldProtect;
        return VirtualProtect(addr, size, mode, &oldProtect) != 0;
  }
  else
  {   
      version (Posix)
      {
        size_t pageSize = sysconf(_SC_PAGESIZE);
        size_t iaddr = cast(size_t)(addr);
        size_t roundAddr = iaddr & ~(pageSize - cast(size_t)(1));
        return mprotect(cast(void*)(roundAddr), size + (iaddr - roundAddr), mode) == 0;
      }
      else
      {
        return true;
      }
  }
    }
//  get aligned memory pointer
//  @param addr [in] address
//  @param alingedSize [in] power of two
//  @return aligned addr by alingedSize
    uint8_t* getAlignedAddress(uint8_t* addr, size_t alignedSize = 16)
    {
        size_t mask = alignedSize - 1;
        return cast(uint8_t*) ((cast(size_t) addr + mask) & ~mask);
    }
}

class Address : Operand
{
public:
    enum Mode {
        M_ModRM,
        M_64bitDisp,
        M_rip,
        M_ripAddr
    }
    this(Address a)
    {
        super(0, Kind.MEM, a.getBit());
        this.e_ = a.e_;
        this.label_ = a.label_;
        this.mode_ = a.mode_;
        this.immSize = a.immSize;
        this.disp8N = a.disp8N;
        this.permitVsib = a.permitVsib;
        this.broadcast_ = a.broadcast_;
        this.optimize_ = a.optimize_;
    }
    this(uint32_t sizeBit, bool broadcast, RegExp e)
    {
        super(0, Kind.MEM, sizeBit);
        this.e_ = e;
        this.label_ = null;
        this.mode_ = Mode.M_ModRM;
        this.broadcast_ = broadcast;
        this.immSize = 0;
        this.disp8N = 0;
        this.permitVsib = false;
        this.broadcast_ = broadcast;
        this.optimize_ = true;
        e_.verify();
    }

  version(XBYAK64)
  {
    this(size_t disp)
    {
        super(0, Kind.MEM, 64);
        e_ = RegExp(disp);
        label_ = null;
        mode_ = Mode.M_64bitDisp;
        immSize = 0;
        disp8N = 0;
        permitVsib = false;
        broadcast_ = false;
        optimize_ = true;
    }    
    this(uint32_t sizeBit, bool broadcast, RegRip addr)
    {
        super(0, Kind.MEM, sizeBit);
        e_ = RegExp(addr.disp_);
        label_ = addr.label_;
        mode_ = addr.isAddr_ ? Mode.M_ripAddr : Mode.M_rip;
        immSize = 0;
        disp8N = 0;
        permitVsib = false;
        broadcast_ = broadcast;
        optimize_ = true;
    }
  }
    
    RegExp getRegExp(bool optimize = true)
    {
        return optimize ? e_.optimize() : e_;
    }
    Address cloneNoOptimize() { Address addr = new Address(this); addr.optimize_ = false; return addr; }
    Mode getMode() const { return mode_; }
    bool is32bit() const { return e_.getBase().getBit() == 32 || e_.getIndex().getBit() == 32; }
    bool isOnlyDisp() const{ return !e_.getBase().getBit() && !e_.getIndex().getBit(); } // for mov eax
    size_t getDisp() const { return e_.getDisp(); }
    bool is64bitDisp() const { return mode_ == Mode.M_64bitDisp; } // for moffset
    bool isBroadcast() const { return broadcast_; }
    override bool hasRex2() const { return e_.getBase().hasRex2() || e_.getIndex().hasRex2(); }
    Label* getLabel() { return label_; }
    override bool opEquals(Object o) const
    {
        Address rhs = cast(Address) o;
        bool Bit_ = this.getBit() == rhs.getBit();
        bool E_ = this.e_ == rhs.e_;
        bool Label_ = this.label_ == rhs.label_;
        bool Mode_ = this.mode_ == rhs.mode_;
        bool ImmSize = this.immSize == rhs.immSize;
        bool Disp8N_ = this.disp8N == rhs.disp8N;
        bool PermitVsib = this.permitVsib == rhs.permitVsib;
        bool Broadcast_ = this.broadcast_ == rhs.broadcast_;
        bool Optimize_ = this.optimize_ == rhs.optimize_;
        return Bit_ && E_ && Label_ && Mode_ && ImmSize && Disp8N_&& PermitVsib && Broadcast_ && Optimize_;
    }
    bool isVsib() const { return e_.isVsib(); }
    
private:
    RegExp e_;
    Label* label_;
    Mode mode_;
public:
    int immSize; // the size of immediate value of nmemonics (0, 1, 2, 4)
    int disp8N; // 0(normal), 1(force disp32), disp8N = {2, 4, 8}
    bool permitVsib;
private:
    bool broadcast_;
    bool optimize_;
}

struct AddressFrame
{
public:
    uint32_t bit_;
    bool broadcast_;
    
    this(uint32_t bit, bool broadcast = false)
    {
        bit_ = bit;
        broadcast_ = broadcast;
    }
    Address opIndex(RegExp e) const
    {
        return new Address(bit_, broadcast_, e);
    }
    Address opIndex(void* disp) const
    {
        return new Address(bit_, broadcast_, RegExp(cast(size_t)disp));
    }
    Address opIndex(int disp) const
    {
        return new Address(bit_, broadcast_, RegExp(cast(size_t)disp));
    }
    Address opIndex(Reg reg) const
    {
        RegExp ret = RegExp(reg);
        return opIndex(ret);
    }

  version (XBYAK64)
  {
        Address opIndex(uint64_t disp) const
        {
            return new Address(disp);
        }        
        Address opIndex(RegRip addr) const
        {
            return new Address(bit_, broadcast_, addr);
        }
  }
}

struct JmpLabel
{
    size_t endOfJmp; // offset from top to the end address of jmp
    int jmpSize;
    inner.LabelMode mode;
    size_t disp; // disp for [rip + disp]
   
    this(size_t endOfJmp, int jmpSize, inner.LabelMode mode = inner.LabelMode.LasIs, size_t disp = 0)
    {
        this.endOfJmp = endOfJmp;
        this.jmpSize  = jmpSize;
        this.mode     = mode;
        this.disp     = disp;
    }
}

struct Label
{
    LabelManager* mgr = null;
    int id = 0;
public:
    this(ref Label rhs)
    {
        this.id  = rhs.id;
        this.mgr = rhs.mgr;
        if (this.mgr) mgr.incRefCount(id, &this);
    }
    ~this()
    {
        if(id && mgr) mgr.decRefCount(id, &this);
    }

    Label opAssign(ref Label rhs)
    {
        if (id) mixin(XBYAK_THROW_RET(ERR.LABEL_IS_ALREADY_SET_BY_L, "this"));
        id = rhs.id;
        mgr = rhs.mgr;
        if (mgr) mgr.incRefCount(id, &this);
        return this;
    }
    uint8_t* getAddress()
    {
        if (mgr is null) return null;
        if (!mgr.isReady()) return null;
        size_t offset;
        if (!mgr.getOffset(&offset, &this)) return null;
        return mgr.getCode() + offset;
    }
    void clear()
    {
        mgr = null;
        id = 0;
    }
    int getId() const { return id; }
    
    static string toStr(int num)
    {
        return format(".%08x", num);
    }
}


struct LabelManager
{
// for string label
    struct SlabelVal
    {
        size_t offset;
        this(size_t offset)
        {
            this.offset = offset;
        }
    }
    alias SlabelDefList = SlabelVal[string];
    alias SlabelUndefList = JmpLabel[][string];

    struct SlabelState
    {
        SlabelDefList defList;
        SlabelUndefList undefList;
    }
    alias StateList = SlabelState[];

// for Label class
    struct ClabelVal
    {
        size_t offset;
        int refCount;
        this(size_t offset)
        {
            this.offset = offset;
            this.refCount = 1;
        }
    }
    alias ClabelDefList = ClabelVal[int];
    alias ClabelUndefList = JmpLabel[][int];
    alias LabelPtrList = Label*[];
    CodeArray base_;

// global : stateList_[0], local : stateList_[$-1]
    StateList stateList_;
    int labelId_;
    ClabelDefList clabelDefList_;
    ClabelUndefList clabelUndefList_;
    LabelPtrList labelPtrList_;
    
    int getId(Label* label)
    {
        if (label.id == 0) label.id = labelId_++;
        return label.id;
    }
    void define_inner(DefList, UndefList, T)(ref DefList deflist, ref UndefList undeflist, T labelId, size_t addrOffset)
    {
        // add label
        if (labelId in deflist) mixin(XBYAK_THROW(ERR.LABEL_IS_REDEFINED));
        deflist[labelId] = typeof(deflist[labelId])(addrOffset);
        // search undefined label
        if (null == (labelId in undeflist)) return;
        foreach (JmpLabel jmp; undeflist[labelId]) {
            size_t offset = jmp.endOfJmp - jmp.jmpSize;
            size_t disp;
            if (jmp.mode == inner.LabelMode.LaddTop) {
                disp = addrOffset;
            } else if (jmp.mode == inner.LabelMode.Labs) {
                disp = cast(size_t) base_.getCurr;
            } else {
                disp = addrOffset - jmp.endOfJmp + jmp.disp;
  version (XBYAK64)
  {
                if (jmp.jmpSize <= 4 && !inner.IsInInt32(disp)) mixin(XBYAK_THROW(ERR.OFFSET_IS_TOO_BIG));
  }
                if (jmp.jmpSize == 1 && !inner.IsInDisp8(cast(uint32_t) disp)) mixin(XBYAK_THROW(ERR.LABEL_IS_TOO_FAR));
            }
            if (base_.isAutoGrow) {
                base_.save(offset, disp, jmp.jmpSize, jmp.mode);
            } else {
                base_.rewrite(offset, disp, jmp.jmpSize);
            }
            undeflist.remove(labelId);
        }
    }

    bool getOffset_inner(DefList, T)(DefList defList, size_t* offset, T label)
    if(is(T == string) || is(T == int))
    {
        if (null == (label in defList))
        {
            return false;
        }
        *offset = defList[label].offset;
        return true;
    }
    void incRefCount(int id, Label* label)
    {
        clabelDefList_[id].refCount++;
        labelPtrList_ ~= label;
    }
    void decRefCount(int id, Label* label)
    {
        foreach(i, labelptr; labelPtrList_)
        {
            if(labelptr == label) {
                labelPtrList_.remove(i);
            }
        }
        if (null == (id in clabelDefList_)) {
            return;
        }
        if (clabelDefList_[id].refCount == 1) {
            clabelDefList_.remove(id);
        } else {
            clabelDefList_[id].refCount -= 1;
        }
    }

    bool hasUndefinedLabel_inner(T)(T list) const
    {
  debug
  {
        foreach(c; list) {
            writeln("undefined label:", c);
        }
  }
        return !list.empty();
    }
    // detach all labels linked to LabelManager
    void resetLabelPtrList()
    {
        labelPtrList_ = [];
    }
    
public:
    ~this()
    {
        resetLabelPtrList();
    }

    void reset()
    {
        base_ = null;
        labelId_ = 1;
        stateList_ = [];
        stateList_ ~= SlabelState();
        stateList_ ~= SlabelState();
        
        foreach(key; clabelDefList_.keys) {
            clabelDefList_.remove(key);
        }
        foreach(key; clabelUndefList_.keys) {
            clabelUndefList_.remove(key);
        }
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
            mixin(XBYAK_THROW(ERR.UNDER_LOCAL_LABEL));
        }
        if (hasUndefinedLabel_inner(stateList_[$-1].undefList))
        {
            mixin(XBYAK_THROW(ERR.LABEL_IS_NOT_FOUND));
        }
        stateList_.popBack();
    }

    void set(CodeArray base)
    {
        base_ = base;
    }
    void defineSlabel(ref string label)
    {
        if ("@b" == label || "@f" == label) mixin(XBYAK_THROW(ERR.BAD_LABEL_STR));
        if ("@@" == label) {
            if ("@f" in stateList_[0].defList) {
                stateList_[0].defList.remove("@f");
                label = "@b";
            } else {
                if ("@b" in stateList_[0].defList) {
                    stateList_[0].defList.remove("@b");
                }
                label = "@f";
            }
        }
        SlabelState* st = label[0] == '.' ? &stateList_[$-1] : &stateList_[0];
        define_inner(st.defList, st.undefList, label, base_.getSize());
    }
    void defineClabel(Label* label)
    {
        define_inner(clabelDefList_, clabelUndefList_, getId(label), base_.getSize);
        label.mgr = &this;
        labelPtrList_ ~= label;
    }
    void assign(ref Label dst, ref Label src)
    {
        if(null == (src.id in clabelDefList_)) {
            mixin(XBYAK_THROW(ERR.LABEL_ISNOT_SET_BY_L));
        }
        define_inner(clabelDefList_, clabelUndefList_, dst.id, clabelDefList_[src.id].offset);
        dst.mgr = &this;
        Label* dst_ptr = &dst;
        labelPtrList_ ~= dst_ptr;
    }
    bool getOffset(size_t* offset, ref string label)
    {
        SlabelDefList df = stateList_[0].defList;
        if (label == "@b") {
            if ("@f" in df) {
                label = "@f";
            } else if (!("@b" in df)) {
                mixin(XBYAK_THROW_RET(ERR.LABEL_IS_NOT_FOUND, "false"));
            }
        } else if ("@f" == label) {
            if ("@f" in df) label = "@b";
        }
        SlabelState* st = label[0] == '.' ? &stateList_[$-1] : &stateList_[0];
        return getOffset_inner(st.defList, offset, label);
    }
    bool getOffset(size_t* offset, Label* label)
    {
        return getOffset_inner(clabelDefList_, offset, getId(label));
    }
    void addUndefinedLabel(ref string label, ref JmpLabel jmp)
    {
        SlabelState* st = label[0] == '.' ? &stateList_[$-1] : &stateList_[0];
        st.undefList[label] ~= jmp;
    }
    void addUndefinedLabel(Label* label, ref JmpLabel jmp)
    {
        clabelUndefList_[label.id] ~= jmp;
    }
    bool hasUndefSlabel() const
    {
        foreach (st; stateList_) {
            if (hasUndefinedLabel_inner(st.undefList)) return true;
        }
        return false;
    }
    bool hasUndefClabel() const
    {
        return hasUndefinedLabel_inner(clabelUndefList_);
    }
    uint8_t* getCode() { return base_.getCode(); }
    bool isReady() const
    {
        if(base_ is null) return false;
        return !base_.isAutoGrow() || base_.isCalledCalcJmpAddress();
    }    
}    

enum PreferredEncoding
{
    DefaultEncoding,
    VexEncoding,
    EvexEncoding,
    PreAVX10v2Encoding,
    AVX10v2Encoding
}

alias DefaultEncoding    = PreferredEncoding.DefaultEncoding;
alias VexEncoding        = PreferredEncoding.VexEncoding;
alias EvexEncoding       = PreferredEncoding.EvexEncoding;
alias PreAVX10v2Encoding = PreferredEncoding.PreAVX10v2Encoding;
alias AVX10v2Encoding    = PreferredEncoding.AVX10v2Encoding;

public class CodeGenerator : CodeArray
{
public:
    enum LabelType
    {
        T_SHORT,
        T_NEAR,
        T_FAR, // far jump
        T_AUTO // T_SHORT if possible
    }

private:
  version(XBYAK64)
  {
        enum { i32e = 64 | 32, BIT = 64 }
        static const size_t dummyAddr = cast(uint64_t) (0x1122334455667788UL);
        alias NativeReg = Reg64;
  }
  else
  {
        enum { i32e = 32, BIT = 32 }
        static const size_t dummyAddr = 0x12345678;
        alias NativeReg = Reg32;
  }

    // (XMM, XMM|MEM)
    bool isXMM_XMMorMEM(Operand op1, Operand op2)
    {
        return op1.isXMM() && (op2.isXMM() || op2.isMEM());
    }
    // (MMX, MMX|MEM) or (XMM, XMM|MEM)
    bool isXMMorMMX_MEM(Operand op1, Operand op2)
    {
        return (op1.isMMX() && (op2.isMMX() || op2.isMEM())) || isXMM_XMMorMEM(op1, op2);
    } 
    // (XMM, MMX|MEM)
    bool isXMM_MMXorMEM(Operand op1, Operand op2)
    {
        return op1.isXMM() && (op2.isMMX() || op2.isMEM());
    }
    // (MMX, XMM|MEM)
    bool isMMX_XMMorMEM(Operand op1, Operand op2)
    {
        return op1.isMMX() && (op2.isXMM() || op2.isMEM());
    }
    // (XMM, REG32|MEM)
    bool isXMM_REG32orMEM(Operand op1, Operand op2)
    {
        return op1.isXMM() && (op2.isREG(i32e) || op2.isMEM());
    }
    // (REG32, XMM|MEM)
    bool isREG32_XMMorMEM(Operand op1, Operand op2)
    {
        return op1.isREG(i32e) && (op2.isXMM() || op2.isMEM());
    }
    // (REG32, REG32|MEM)
    bool isREG32_REG32orMEM(Operand op1, Operand op2)
    {
        return op1.isREG(i32e) && ((op2.isREG(i32e) && op1.getBit() == op2.getBit()) || op2.isMEM());
    }
    bool isValidSSE(Operand op1)
    {
        // SSE instructions do not support XMM16 - XMM31
        return !(op1.isXMM() && op1.getIdx() >= 16);
    }
    uint8_t rexRXB(int bit, int bit3, Reg r, Reg b, Reg x = Reg())
    {
        int v = bit3 ? 8 : 0;
        if (r.hasIdxBit(bit)) v |= 4;
        if (x.hasIdxBit(bit)) v |= 2;
        if (b.hasIdxBit(bit)) v |= 1;
        return cast(uint8_t)v;
    }
    void rex2(int bit3, int rex4bit, Reg r, Reg b, Reg x = Reg())
    {
        db(0xD5);
        db((rexRXB(4, bit3, r, b, x) << 4) | rex4bit);
    }
    // return true if rex2 is selected
    bool rex(Operand op1, Operand op2 = Reg(), uint64_t type = 0)
    {
        if (op1.getNF() | op2.getNF()) mixin(XBYAK_THROW_RET(ERR.INVALID_NF, "false"));
        if (op1.getZU() | op2.getZU()) mixin(XBYAK_THROW_RET(ERR.INVALID_ZU, "false"));
        uint8_t rex = 0;
        Operand p1 = op1;
        Operand p2 = op2;
        if (p1.isMEM()) swap(p1, p2);
        if (p1.isMEM()) mixin(XBYAK_THROW_RET(ERR.BAD_COMBINATION, "false"));
        // except movsx(16bit, 32/64bit)
        bool p66 = (op1.isBit(16) && !op2.isBit(i32e)) || (op2.isBit(16) && !op1.isBit(i32e));
        if ((type & T_66) || p66){
            db(0x66);
        }
        if (type & T_F2) {
            db(0xF2);
        }
        if (type & T_F3) {
            db(0xF3);
        }
        bool is0F = cast(bool)(type & T_0F);
        if (p2.isMEM()) {
            Reg r = cast(Reg)(p1);
            Address addr = p2.getAddress();
            RegExp e = addr.getRegExp();
            Reg base = e.getBase();
            Reg idx = e.getIndex();
            if (BIT == 64 && addr.is32bit()) {
                db(0x67);
            }
            rex = rexRXB(3, r.isREG(64), r, base, idx);
            if (r.hasRex2() || addr.hasRex2()) {
                if (type & (T_0F38|T_0F3A)) mixin(XBYAK_THROW_RET(ERR.CANT_USE_REX2, "false"));
                rex2(is0F, rex, r, base, idx);
                return true;
            }
            if (rex || r.isExt8bit()) rex |= 0x40;
        } else {
            Reg r1 = cast(Reg)(op1);
            Reg r2 = cast(Reg)(op2);
            // ModRM(reg, base);
            rex = rexRXB(3, r1.isREG(64) || r2.isREG(64), r2, r1);
            if (r1.hasRex2() || r2.hasRex2()) {
                if (type & (T_0F38|T_0F3A)) mixin(XBYAK_THROW_RET(ERR.CANT_USE_REX2, "0"));
                rex2(is0F, rex, r2, r1);
                return true;
            }
            if (rex || r1.isExt8bit() || r2.isExt8bit()) rex |= 0x40;
        }
        if (rex) db(rex);
        return false;
    }

static const uint64_t T_NONE = 0;
// low 3 bit
static const uint64_t T_N1 = 1uL;
static const uint64_t T_N2 = 2uL;
static const uint64_t T_N4 = 3uL;
static const uint64_t T_N8 = 4uL;
static const uint64_t T_N16 = 5uL;
static const uint64_t T_N32 = 6uL;
static const uint64_t T_NX_MASK = 7uL;
static const uint64_t T_DUP = T_NX_MASK; // 1 << 4, // N = (8, 32, 64)
static const uint64_t T_N_VL = 1uL << 3; // N * (1, 2, 4) for VL
static const uint64_t T_APX = 1uL << 4;
static const uint64_t T_66 = 1uL << 5; // pp = 1
static const uint64_t T_F3 = 1uL << 6; // pp = 2
static const uint64_t T_ER_R = 1uL << 7; // reg{er}
static const uint64_t T_0F = 1uL << 8;
static const uint64_t T_0F38 = 1uL << 9;
static const uint64_t T_0F3A = 1uL << 10;
static const uint64_t T_MAP5 = 1uL << 11;
static const uint64_t T_L1 = 1uL << 12;
static const uint64_t T_W0 = 1uL << 13;
static const uint64_t T_W1 = 1uL << 14;
static const uint64_t T_EW0 = 1uL << 15;
static const uint64_t T_EW1 = 1uL << 16;
static const uint64_t T_YMM = 1uL << 17; // support YMM, ZMM
static const uint64_t T_EVEX = 1uL << 18;
static const uint64_t T_ER_X = 1uL << 19; // xmm{er}
static const uint64_t T_ER_Y = 1uL << 20; // ymm{er}
static const uint64_t T_ER_Z = 1uL << 21; // zmm{er}
static const uint64_t T_SAE_X = 1uL << 22; // xmm{sae}
static const uint64_t T_SAE_Y = 1uL << 23; // ymm{sae}
static const uint64_t T_SAE_Z = 1uL << 24; // zmm{sae}
static const uint64_t T_MUST_EVEX = 1uL << 25; // contains T_EVEX
static const uint64_t T_B32 = 1uL << 26; // m32bcst
static const uint64_t T_B64 = 1uL << 27; // m64bcst
static const uint64_t T_B16 = T_B32 | T_B64; // m16bcst (Be carefuL)
static const uint64_t T_M_K = 1uL << 28; // mem{k}
static const uint64_t T_VSIB = 1uL << 29;
static const uint64_t T_MEM_EVEX = 1uL << 30; // use evex if mem
static const uint64_t T_MAP6 = 1uL << 31;
static const uint64_t T_NF = 1uL << 32; // T_nf
static const uint64_t T_CODE1_IF1 = 1uL << 33; // code|=1 if !r.isBit(8)

static const uint64_t T_ND1 = 1uL << 35; // ND=1
static const uint64_t T_ZU = 1uL << 36; // ND=ZU
static const uint64_t T_F2 = 1uL << 37; // pp = 3
static const uint64_t T_SENTRY = (1uL << 38)-1; // attribute(>=T_SENTRY) is for error check
static const uint64_t T_ALLOW_DIFF_SIZE = 1uL << 38; // allow difference reg size
static const uint64_t T_ALLOW_ABCDH = 1uL << 39; // allow [abcd]h reg

    // T_66 = 1, T_F3 = 2, T_F2 = 3
    uint32_t getPP(uint64_t type) { return (type & T_66) ? 1 : (type & T_F3) ? 2 : (type & T_F2) ? 3 : 0; }

    uint32_t getMap(uint64_t type)
    {
        if (type & T_MAP6) return 6;
        if (type & T_MAP5) return 5;
        return (type & T_0F) ? 1 : (type & T_0F38) ? 2 : (type & T_0F3A) ? 3 : 0;
    }
    
    void vex(Reg reg, Reg base, Operand v, uint64_t type, int code, bool x = false)
    {
        int w = (type & T_W1) ? 1 : 0;
        bool is256 = (type & T_L1) ? true : reg.isYMM();
        bool r = reg.isExtIdx();
        bool b = base.isExtIdx();
        int idx = v ? v.getIdx() : 0;
        if ((idx | reg.getIdx() | base.getIdx()) >= 16) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        uint32_t pp = getPP(type);
        uint32_t vvvv = (((~idx) & 15) << 3) | (is256 ? 4 : 0) | pp;
        if (!b && !x && !w && (type & T_0F)) {
            db(0xC5); db((r ? 0 : 0x80) | vvvv);
        } else {
            uint32_t mmmm = getMap(type);
            db(0xC4); db((r ? 0 : 0x80) | (x ? 0 : 0x40) | (b ? 0 : 0x20) | mmmm); db((w << 7) | vvvv);
        }
        db(code);
    }
    // Allow YMM embedded rounding for AVX10.2 to minimize flag modifications
    bool verifySAE(Reg r, Reg b, uint64_t type) const
    {
        if (((type & T_SAE_X) && (r.isYMM() && b.isXMM())) || ((type & T_SAE_Y) && b.isXMM()) || ((type & T_SAE_Z) && b.isYMM()))
        {
            return true;
        }
        if (((type & T_SAE_X) && b.isXMM()) || ((type & T_SAE_Y) && b.isYMM()) || ((type & T_SAE_Z) && b.isZMM()))
        {
            return false;
        }
        mixin(XBYAK_THROW_RET(ERR.SAE_IS_INVALID, "false"));
    }
    bool verifyER(Reg r, Reg b, uint64_t type) const
    {
        if ((type & T_ER_R) && b.isREG(32|64)) return false;
        if (((type & T_ER_X) && (r.isYMM() && b.isXMM())) || ((type & T_ER_Y) && b.isXMM()) || ((type & T_ER_Z) && b.isYMM()))
        {
            return true;
        }
        if (((type & T_ER_X) && b.isXMM()) || ((type & T_ER_Y) && b.isYMM()) || ((type & T_ER_Z) && b.isZMM()))
        {
            return false;
        }
        mixin(XBYAK_THROW_RET(ERR.ER_IS_INVALID, "false"));
    }
    // (a, b, c) contains non zero two or three values then err
    int verifyDuplicate(int a, int b, int c, ERR err)
    {
        int v = a | b | c;
        if ((a > 0 && a != v) + (b > 0 && b != v) + (c > 0 && c != v) > 0)
        {
            mixin(XBYAK_THROW_RET("err", "0"));
        }
        return v;
    }
    int evex(Reg reg, Reg base, Operand v, uint64_t type, int code, Reg x = null, bool b = false, int aaa = 0, uint32_t VL = 0, bool Hi16Vidx = false)
    {
        if (!(type & (T_EVEX | T_MUST_EVEX))) mixin(XBYAK_THROW_RET(ERR.EVEX_IS_INVALID, "0"));
        int w = (type & T_EW1) ? 1 : 0;
        uint32_t mmm = getMap(type);
        uint32_t pp = getPP(type);
        int idx = v ? v.getIdx() : 0;
        uint32_t vvvv = ~idx;
        
        bool R = reg.isExtIdx();
        bool X3 = (x && x.isExtIdx()) || (base.isSIMD() && base.isExtIdx2());
        uint8_t B4 = (base.isREG() && base.isExtIdx2()) ? 8 : 0;
        uint8_t U = (x && (x.isREG() && x.isExtIdx2())) ? 0 : 4;
        bool B = base.isExtIdx();
        bool Rp = reg.isExtIdx2();
        int LL;
        int rounding = verifyDuplicate(reg.getRounding(), base.getRounding(), v ? v.getRounding() : 0, ERR.ROUNDING_IS_ALREADY_SET);
        int disp8N = 1;
        if (rounding) {
            bool isUzero = false;
            if (rounding == EvexModifierRounding.T_SAE) {
                isUzero = verifySAE(reg, base, type); LL = 0;
            } else {
                isUzero = verifyER(reg, base, type); LL = rounding - 1;
            }
            if (isUzero) U = 0; // avx10.2 Evex.U
            b = true;
        } else {
            if (v) VL = max(VL, v.getBit());
            VL = max(max(reg.getBit(), base.getBit()), VL);
            LL = (VL == 512) ? 2 : (VL == 256) ? 1 : 0;
            if (b) {
                disp8N = ((type & T_B16) == T_B16) ? 2 : (type & T_B32) ? 4 : 8;
            } else if ((type & T_NX_MASK) == T_DUP) {
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
        bool V4 = ((v ? v.isExtIdx2() : 0) | Hi16Vidx);
        bool z = reg.hasZero() || base.hasZero() || (v ? v.hasZero() : false);
        if (aaa == 0)
        {
            aaa = verifyDuplicate(base.getOpmaskIdx(), reg.getOpmaskIdx(), (v ? v.getOpmaskIdx() : 0), ERR.OPMASK_IS_ALREADY_SET);
        }
        if (aaa == 0) z = false; // clear T_z if mask is not set
        db(0x62);
        db((R ? 0 : 0x80) | (X3 ? 0 : 0x40) | (B ? 0 : 0x20) | (Rp ? 0 : 0x10) | B4 | mmm);
        db((w == 1 ? 0x80 : 0) | ((vvvv & 15) << 3) | U | (pp & 3));
        db((z ? 0x80 : 0) | ((LL & 3) << 5) | (b ? 0x10 : 0) | (V4 ? 0 : 8) | (aaa & 7));
        db(code);
        return disp8N;
    }
    // evex of Legacy
    void evexLeg(Reg r, Reg b, Reg x, Reg v, uint64_t type, int sc = NONE)
    {
        int M = getMap(type); if (M == 0) M = 4; // legacy
        int R3 = !r.isExtIdx();
        int X3 = !x.isExtIdx();
        int B3 = b.isExtIdx() ? 0 : 0x20;
        int R4 = r.isExtIdx2() ? 0 : 0x10;
        int B4 = b.isExtIdx2() ? 0x08 : 0;
        int w = (type & T_W0) ? 0 : (r.isBit(64) || v.isBit(64) || (type & T_W1));
        int V = (~v.getIdx() & 15) << 3;
        int X4 = x.isExtIdx2() ? 0 : 0x04;
        int pp = (type & (T_F2|T_F3|T_66)) ? getPP(type) : (r.isBit(16) || v.isBit(16));
        int V4 = !v.isExtIdx2();
        int ND = (type & T_ZU) ? (r.getZU() || b.getZU()) : (type & T_ND1) ? 1 : (type & T_APX) ? 0 : v.isREG();
        int NF = r.getNF() | b.getNF() | x.getNF() | v.getNF();
        int L = 0;
        if ((type & T_NF) == 0 && NF) mixin(XBYAK_THROW(ERR.INVALID_NF));
        if ((type & T_ZU) == 0 && r.getZU()) mixin(XBYAK_THROW(ERR.INVALID_ZU));
        db(0x62);
        db((R3<<7) | (X3<<6) | B3 | R4 | B4 | M);
        db((w<<7) | V | X4 | pp);
        if (sc != NONE) {
            db((L<<5) | (ND<<4) | sc);
        } else {
            db((L<<5) | (ND<<4) | (V4<<3) | (NF<<2));
        }
    }
    void setModRM(int mod, int r1, int r2)
    {
        db(cast(uint8_t)((mod << 6) | ((r1 & 7) << 3) | (r2 & 7)));
    }
    void setSIB(RegExp e, int reg, int disp8N = 0)
    {
        size_t disp64 = e.getDisp();
  version (XBYAK64)
  {
      version(XBYAK_OLD_DISP_CHECK)
      {
        // treat 0xffffffff as 0xffffffffffffffff
        uint64_t high = disp64 >> 32;
        if (high != 0 && high != 0xFFFFFFFF) mixin(XBYAK_THROW(ERR.OFFSET_IS_TOO_BIG));
      }
      else
      {
        // displacement should be a signed 32-bit value, so also check sign bit
        uint64_t high = disp64 >> 31;
        if (high != 0 && high != 0x1FFFFFFFF) mixin(XBYAK_THROW(ERR.OFFSET_IS_TOO_BIG));
      }
  }
        uint32_t disp = cast(uint32_t)(disp64);
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
                uint32_t t = cast(uint32_t)(cast(int)(disp) / disp8N);
                if ((disp % disp8N) == 0 && inner.IsInDisp8(t)) {
                    disp = t;
                    mod = mod01;
                }
            }
        }
        const int newBaseIdx = baseBit ? (baseIdx & 7) : Operand.EBP;
        /* ModR/M = [2:3:3] = [Mod:reg/code:R/M] */
        bool hasSIB = indexBit || (baseIdx & 7) == Operand.ESP;
  version(XBYAK64)
  {
        if (!baseBit && !indexBit) hasSIB = true;
  }
        if (hasSIB) {
            setModRM(mod, reg, Operand.ESP);
            /* SIB = [2:3:3] = [SS:index:base(=rm)] */
            const int idx = indexBit ? (index.getIdx() & 7) : Operand.ESP;
            const int scale = e.getScale();
            const int SS = (scale == 8) ? 3 : (scale == 4) ? 2 : (scale == 2) ? 1 : 0;
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
    LabelManager labelMgr_;
    void writeCode(uint64_t type, Reg r, int code, bool rex2 = false)
    {
        if (!(type & T_APX || rex2)) {
            if (type & T_0F) {
                db(0x0F);
            } else if (type & T_0F38) {
                db(0x0F); db(0x38);
            } else if (type & T_0F3A) {
                db(0x0F); db(0x3A);
            }
        }
        db(code | (((type & T_SENTRY) == 0 || (type & T_CODE1_IF1)) && !r.isBit(8)));
    }
    void opRR(Reg r1, Reg r2, uint64_t type, int code)
    {
        if (!(type & T_ALLOW_DIFF_SIZE) && r1.isREG() && r2.isREG() && r1.getBit() != r2.getBit()) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        if (!(type & T_ALLOW_ABCDH) && (isBadCombination(r1, r2) || isBadCombination(r2, r1))) mixin(XBYAK_THROW(ERR.CANT_USE_ABCDH));
        bool rex2 = rex(r2, r1, type);
        writeCode(type, r1, code, rex2);
        setModRM(3, r1.getIdx(), r2.getIdx());
    }
    void opMR(Address addr, Reg r, uint64_t type, int code, uint64_t type2 = 0, int code2 = NONE)
    {
        if (code2 == NONE) code2 = code;
        if (type2 && opROO(Reg(), addr, r, type2, code2)) return;
        if (addr.is64bitDisp()) mixin(XBYAK_THROW(ERR.CANT_USE_64BIT_DISP));
        if (!(type & T_ALLOW_DIFF_SIZE) && r.getBit() <= BIT && addr.getBit() > 0 && addr.getBit() != r.getBit()) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE));
        bool rex2 = rex(addr, r, type);
        writeCode(type, r, code, rex2);
        opAddr(addr, r.getIdx());
    }
    void opLoadSeg(Address addr, Reg reg, uint64_t type, int code)
    {
        if (addr.is64bitDisp()) mixin(XBYAK_THROW(ERR.CANT_USE_64BIT_DISP));
        if (reg.isBit(8)) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        // can't use opMR
        rex(addr, reg, type);
        if (type & T_0F) db(0x0F);
        db(code);
        opAddr(addr, reg.getIdx());
    }
    // for only MPX(bnd*)
    void opMIB(Address addr, Reg reg, uint64_t type, int code)
    {
        if (addr.getMode() != Address.Mode.M_ModRM) mixin(XBYAK_THROW(ERR.INVALID_MIB_ADDRESS));
        opMR(addr.cloneNoOptimize(), reg, type, code);
    }
    void makeJmp(uint32_t disp, LabelType type, uint8_t shortCode, uint8_t longCode, uint8_t longPref)
    {
        int shortJmpSize = 2;
        int longHeaderSize = longPref ? 2 : 1;
        int longJmpSize = longHeaderSize + 4;
        if (type != T_NEAR && inner.IsInDisp8(disp - shortJmpSize)) {
            db(shortCode);
            db(disp - shortJmpSize);
        } else {
            if (type == T_SHORT) mixin(XBYAK_THROW(ERR.LABEL_IS_TOO_FAR));
            if (longPref) db(longPref);
            db(longCode);
            dd(disp - longJmpSize);
        }
    }
    bool isNEAR(LabelType type) const { return type == T_NEAR || (type == T_AUTO && isDefaultJmpNEAR_); }
    void opJmp(string label, LabelType type, uint8_t shortCode, uint8_t longCode, uint8_t longPref)
    {
        if (type == T_FAR) mixin(XBYAK_THROW(ERR.NOT_SUPPORTED));
        if (isAutoGrow() && size_ + 16 >= maxSize_) growMemory(); // avoid splitting code of jmp
        size_t offset = 0;
        if (labelMgr_.getOffset(&offset, label)) {  // label exists
            makeJmp(inner.VerifyInInt32(offset - size_), type, shortCode, longCode, longPref);
        } else {
            int jmpSize = 0;
            if (isNEAR(type)) {
                jmpSize = 4;
                if (longPref) db(longPref);
                db(longCode);
                dd(0);
            } else {
                jmpSize = 1;
                db(shortCode);
                db(0);
            }
            JmpLabel jmp = JmpLabel(size_, jmpSize, inner.LabelMode.LasIs);
            labelMgr_.addUndefinedLabel(label, jmp);
        }
    }
    void opJmp(ref Label label, LabelType type, uint8_t shortCode, uint8_t longCode, uint8_t longPref)
    {
        if (type == T_FAR) mixin(XBYAK_THROW(ERR.NOT_SUPPORTED));
        if (isAutoGrow() && size_ + 16 >= maxSize_) growMemory(); // avoid splitting code of jmp
        size_t offset = 0;
        if (labelMgr_.getOffset(&offset, &label)) { // label exists
            makeJmp(inner.VerifyInInt32(offset - size_), type, shortCode, longCode, longPref);
        } else {
            int jmpSize = 0;
            if (isNEAR(type)) {
                jmpSize = 4;
                if (longPref) db(longPref);
                db(longCode);
                dd(0);
            } else {
                jmpSize = 1;
                db(shortCode);
                db(0);
            }
            JmpLabel jmp = JmpLabel(size_, jmpSize, inner.LabelMode.LasIs);
            labelMgr_.addUndefinedLabel(&label, jmp);
        }
    }
    void opJmpAbs(const void* addr, LabelType type, uint8_t shortCode, uint8_t longCode, uint8_t longPref = 0)
    {
        if (type == T_FAR) mixin(XBYAK_THROW(ERR.NOT_SUPPORTED));
        if (isAutoGrow()) {
            if (type != T_NEAR) mixin(XBYAK_THROW(ERR.ONLY_T_NEAR_IS_SUPPORTED_IN_AUTO_GROW));
            if (size_ + 16 >= maxSize_) growMemory();
            if (longPref) db(longPref);
            db(longCode);
            dd(0);
            save(size_ - 4, cast(size_t) addr - size_, 4, inner.LabelMode.Labs);
        } else {
            makeJmp(inner.VerifyInInt32(cast(uint8_t*) addr - getCurr), type, shortCode, longCode, longPref);
        }
    }
    void opJmpOp(Operand op, LabelType type, int ext)
    {
        const int bit = 16|i32e;
        if (type == T_FAR) {
            if (!op.isMEM(bit)) mixin(XBYAK_THROW(ERR.NOT_SUPPORTED));
            opRext(op, bit, ext + 1, 0, 0xFF, false);
        } else {
            opRext(op, bit, ext, 0, 0xFF, true);
        }
    }
    // reg is reg field of ModRM
    // immSize is the size for immediate value
    void opAddr(Address addr, int reg)
    {
        if (!addr.permitVsib && addr.isVsib()) mixin(XBYAK_THROW(ERR.BAD_VSIB_ADDRESSING));
        if (addr.getMode() == Address.Mode.M_ModRM) {
            setSIB(addr.getRegExp(), reg, addr.disp8N);
        } else if (addr.getMode() == Address.Mode.M_rip || addr.getMode() == Address.Mode.M_ripAddr) {
            setModRM(0, reg, 5);
            if (addr.getLabel()) { // [rip + Label]
                putL_inner(addr.getLabel(), true, addr.getDisp() - addr.immSize);
            } else {
                size_t disp = addr.getDisp();
                if (addr.getMode() == Address.Mode.M_ripAddr) {
                    if (isAutoGrow()) mixin(XBYAK_THROW(ERR.INVALID_RIP_IN_AUTO_GROW));
                    disp -= cast(size_t)getCurr() + 4 + addr.immSize;
                }
                dd(inner.VerifyInInt32(disp));
            }
        }
    }
    void opSSE(Reg r, Operand op, uint64_t type, int code, bool delegate(Operand, Operand)isValid = null, int imm8 = NONE)
    {
        if (isValid && !isValid(r, op)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        if (!isValidSSE(r) || !isValidSSE(op)) mixin(XBYAK_THROW(ERR.NOT_SUPPORTED));
        opRO(r, op, type, code, true, (imm8 != NONE) ? 1 : 0);
        if (imm8 != NONE) db(imm8);
    }
    void opMMX_IMM(Mmx mmx, int imm8, int code, int ext)
    {
        if (!isValidSSE(mmx)) mixin(XBYAK_THROW(ERR.NOT_SUPPORTED));
        uint64_t type = T_0F;
        if (mmx.isXMM()) type |= T_66;
        opRR(Reg32(ext), mmx, type, code);
        db(imm8);
    }
    void opMMX(Mmx mmx, Operand op, int code, uint64_t type = T_0F, uint64_t pref = T_66, int imm8 = NONE)
    {
        if (mmx.isXMM()) type |= pref;
        opSSE(mmx, op, type, code, &isXMMorMMX_MEM, imm8);
    }
    void opMovXMM(Operand op1, Operand op2, uint64_t type, int code)
    {
        if (!isValidSSE(op1) || !isValidSSE(op2)) mixin(XBYAK_THROW(ERR.NOT_SUPPORTED));
        if (op1.isXMM() && op2.isMEM()) {
            opMR(op2.getAddress(), op1.getReg(), type, code);
        } else if (op1.isMEM() && op2.isXMM()) {
            opMR(op1.getAddress(), op2.getReg(), type, code | 1);
        } else {
            mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        }
    }
    void opExt(Operand op, Mmx mmx, int code, int imm, bool hasMMX2 = false)
    {
        if (!isValidSSE(op) || !isValidSSE(mmx)) mixin(XBYAK_THROW(ERR.NOT_SUPPORTED));
        if (hasMMX2 && op.isREG(i32e)) {    // pextrw is special
            if (mmx.isXMM) db(0x66);
            opRR(op.getReg(), mmx, T_0F, 0xC5);
            db(imm);
        } else {
            opSSE(mmx, op, T_66 | T_0F3A, code, &isXMM_REG32orMEM, imm);
        }
    }
    // r1 is [abcd]h and r2 is reg with rex
    bool isBadCombination(Reg r1, Reg r2) const
    {
        if (!r1.isHigh8bit()) return false;
        if (r2.isExt8bit() || r2.getIdx() >= 8) return true;
        return false;
    }
    // (r, r, m) or (r, m, r)
    bool opROO(Reg d, Operand op1, Operand op2, uint64_t type, int code, int immSize = 0, int sc = NONE)
    {
        if (!(type & T_MUST_EVEX) && !d.isREG() && !(d.hasRex2NFZU() || op1.hasRex2NFZU() || op2.hasRex2NFZU())) return false;
        Operand p1 = op1, p2 = op2;
        if (p1.isMEM()) { swap(p1, p2); } else { if (p2.isMEM()) code |= 2; }
        if (p1.isMEM()) mixin(XBYAK_THROW_RET(ERR.BAD_COMBINATION, "false"));
        if (p2.isMEM()) {
            Reg r = cast(Reg)(p1);
            Address addr = p2.getAddress();
            RegExp e = addr.getRegExp();
            evexLeg(r, e.getBase(), e.getIndex(), d, type, sc);
            writeCode(type, d, code);
            addr.immSize = immSize;
            opAddr(addr, r.getIdx());
        } else {
            evexLeg(cast(Reg)op2, cast(Reg)op1, Reg(), d, type, sc);
            writeCode(type, d, code);
            setModRM(3, op2.getIdx(), op1.getIdx());
        }
        return true;
    }
    void opRext(Operand op, int bit, int ext, uint64_t type, int code, bool disableRex = false, int immSize = 0, Reg d = null)
    {
        int opBit = op.getBit();
        if (disableRex && opBit == 64) opBit = 32;
        Reg r = Reg(ext, Kind.REG, opBit);
        if ((type & T_APX) && (d !is null || op.hasRex2NFZU()) && opROO(d ? d : Reg(0, Kind.REG, opBit), op, r, type, code)) return;
        if (op.isMEM()) {
            opMR(op.getAddress(immSize), r, type, code);
        } else if (op.isREG(bit)) {
            opRR(r, op.getReg().changeBit(opBit), type | T_ALLOW_ABCDH, code);
        } else {
            mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        }
    }
    void opSetCC(Operand op, int ext)
    {
        if (opROO(Reg(), op, Reg(), T_APX|T_ZU|T_F2, 0x40 | ext)) return;
        opRext(op, 8, 0, T_0F, 0x90 | ext);
    }
    void opShift(Operand op, int imm, int ext, Reg d = null)
    {
        if (d is null) verifyMemHasSize(op);
        if (d && op.getBit() != 0 && d.getBit() != op.getBit()) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        uint64_t type = T_APX|T_CODE1_IF1; if (ext & 8) type |= T_NF; if (d) type |= T_ND1;
        opRext(op, 0, ext&7, type, (0xC0 | ((imm == 1 ? 1 : 0) << 4)), false, (imm != 1) ? 1 : 0, d);
        if (imm != 1) db(imm);
    }
    void opShift(Operand op, Reg8 _cl, int ext, Reg d = null)
    {
        if (_cl.getIdx() != Operand.CL) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        if (d && op.getBit() != 0 && d.getBit() != op.getBit()) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        uint64_t type = T_APX|T_CODE1_IF1; if (ext & 8) type |= T_NF; if (d) type |= T_ND1;
        opRext(op, 0, ext&7, type, 0xD2, false, 0, d);
    }
    // condR assumes that op.isREG() is true
    void opRO(Reg r, Operand op, uint64_t type, int code, bool condR = true, int immSize = 0)
    {
        if (op.isMEM()) {
            opMR(op.getAddress(immSize), r, type, code);
        } else if (condR) {
            opRR(r, op.getReg(), type, code);
        } else {
            mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        }
    }
    void opShxd(Reg d, Operand op, Reg reg, uint8_t imm, int code, int code2, Reg8 _cl = null)
    {
        if (_cl && _cl.getIdx() != Operand.CL) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        if (!reg.isREG(16|i32e)) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        int immSize = _cl ? 0 : 1;
        if (_cl) code |= 1;
        uint64_t type = T_APX | T_NF;
        if (d.isREG()) type |= T_ND1;
        if (!opROO(d, op, reg, type, _cl ? code : code2, immSize)) {
            opRO(reg, op, T_0F, code, true, immSize);
        }
        if (!_cl) db(imm);
    }
    // (REG, REG|MEM), (MEM, REG)
    void opRO_MR(Operand op1, Operand op2, int code)
    {
        if (op2.isMEM()) {
            if (!op1.isREG()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
            opMR(op2.getAddress(), op1.getReg(), 0, code | 2);
        } else {
            opRO(cast(Reg)(op2), op1, 0, code, op1.getKind() == op2.getKind());
        }
    }
    bool isInDisp16(uint32_t x) const { return 0xFFFF8000 <= x || x <= 0x7FFF; }
    // allow add(ax, 0x8000);
    bool isInDisp16relaxed(uint32_t x) const { uint32_t v = x & 0xffff0000; return v == 0 || v == 0xffff0000; }
    uint32_t getImmBit(Operand op, uint32_t imm)
    {
        verifyMemHasSize(op);
        uint32_t immBit = inner.IsInDisp8(imm) ? 8 : isInDisp16relaxed(imm) ? 16 : 32;
        if (op.isBit(8)) immBit = 8;
        if (op.getBit() < immBit) mixin(XBYAK_THROW_RET(ERR.IMM_IS_TOO_BIG, "0"));
        if (op.isBit(32|64) && immBit == 16) immBit = 32; /* don't use MEM16 if 32/64bit mode */
        return immBit;
    }
    // (REG|MEM, IMM)
    void opOI(Operand op, uint32_t imm, int code, int ext)
    {
        uint32_t immBit = getImmBit(op, imm);
        if (op.isREG() && op.getIdx() == 0 && (op.getBit() == immBit || (op.isBit(64) && immBit == 32))) { // rax, eax, ax, al
            rex(op);
            db(code | 4 | (immBit == 8 ? 0 : 1));
        } else {
            int tmp = immBit < min(op.getBit(), 32U) ? 2 : 0;
            opRext(op, 0, ext, 0, 0x80 | tmp, false, immBit / 8);
        }
        db(imm, immBit / 8);
    }
    // (r, r/m, imm)
    void opROI(Reg d, Operand op, uint32_t imm, uint64_t type, int ext)
    {
        uint32_t immBit = getImmBit(d, imm);
        int code = immBit < min(d.getBit(), 32U) ? 2 : 0;
        opROO(d, op, Reg(ext, Kind.REG, d.getBit()), type, 0x80 | code, immBit / 8);
        db(imm, immBit / 8);
    }
    void opIncDec(Reg d, Operand op, int ext)
    {
  version(XBYAK64)
  {
        if (d.isREG()) {
            int code = d.isBit(8) ? 0xFE : 0xFF;
            uint64_t type = T_APX|T_NF|T_ND1;
            if (d.isBit(16)) type |= T_66;
            opROO(d, op, Reg(ext, Kind.REG, d.getBit()), type, code);
            return;
        }
  }
  else
  {
        cast(void)d;
  }
        verifyMemHasSize(op);
  version(XBYAK64)
  {}
  else
  {
        if (op.isREG() && !op.isBit(8)) {
            rex(op);
            db((ext ? 0x48 : 0x40) | op.getIdx());
            return;
        }
  }
        opRext(op, op.getBit(), ext, 0, 0xFE);
    }
    void opPushPop(Operand op, int code, int ext, int alt)
    {
        if (op.isREG() && op.hasRex2()) {
            Reg r = cast(Reg)op;
            rex2(0, rexRXB(3, 0, Reg(), r), Reg(), r);
            db(alt | (r.getIdx() & 7));
            return;
        }
        int bit = op.getBit();
        if (bit == 16 || bit == BIT) {
            if (bit == 16) db(0x66);
            if (op.isREG()) {
                if (op.getReg().getIdx() >= 8) db(0x41);
                db(alt | (op.getIdx() & 7));
                return;
            }
            if (op.isMEM()) {
                opMR(op.getAddress(), Reg(ext, Kind.REG, 32), T_ALLOW_DIFF_SIZE, code);
                return;
            }
        }
        mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    }
    void verifyMemHasSize(Operand op) const
    {
        if (op.isMEM && op.getBit == 0) mixin(XBYAK_THROW(ERR.MEM_SIZE_IS_NOT_SPECIFIED));
    }
    //    mov(r, imm) = db(imm, mov_imm(r, imm))
    int mov_imm(Reg reg, uint64_t imm)
    {
        int bit = reg.getBit();
        const int idx  = reg.getIdx();
        int code = 0xB0 | ((bit == 8 ? 0 : 1) << 3);
        if (bit == 64 && (imm & ~cast(uint64_t) (0xffff_ffffu)) == 0) {
            rex(Reg32(idx));
            bit = 32;
        } else {
            rex(reg);
            if (bit == 64 && inner.IsInInt32(imm)) {
                db(0xC7);
                code = 0xC0;
                bit = 32;
            }
        }
        db(code | (idx & 7));
        return bit / 8;
    }
    void putL_inner(T)(T label, bool relative = false, size_t disp = 0) if(is(T == string) || is(T == Label*))
    {
        const int jmpSize = relative ? 4 : cast(int) size_t.sizeof;
        if (isAutoGrow() && size_ + 16 >= maxSize_) growMemory();
        size_t offset = 0;
        if (labelMgr_.getOffset(&offset, label))
        {
            if (relative) {
                db(inner.VerifyInInt32(offset + disp - size_ - jmpSize), jmpSize);
            } else if (isAutoGrow()) {
                db(cast(uint64_t)0, jmpSize);
                save(size_ - jmpSize, offset, jmpSize, inner.LabelMode.LaddTop);
            } else {
                db(cast(size_t) top_ + offset, jmpSize);
            }
            return;
        }
        db(cast(uint64_t)0, jmpSize);
        JmpLabel jmp = JmpLabel(size_, jmpSize, (relative ? inner.LabelMode.LasIs : isAutoGrow() ? inner.LabelMode.LaddTop : inner.LabelMode.Labs), disp);
        labelMgr_.addUndefinedLabel(label, jmp);
    }
    void opMovxx(Reg reg, Operand op, uint8_t code)
    {
        if (op.isBit(32)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        int w = op.isBit(16);
        if (!(reg.isREG() && (reg.getBit() > op.getBit()))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        opRO(reg, op, T_0F | T_ALLOW_DIFF_SIZE, code | w);
    }
    void opFpuMem(Address addr, uint8_t m16, uint8_t m32, uint8_t m64, uint8_t ext, uint8_t m64ext)
    {
        if (addr.is64bitDisp) mixin(XBYAK_THROW(ERR.CANT_USE_64BIT_DISP));
        uint8_t code = addr.isBit(16) ? m16 : addr.isBit(32) ? m32 : addr.isBit(64) ? m64 : 0;
        if (!code) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE));
        if (m64ext && addr.isBit(64)) ext = m64ext;
        rex(addr, st0);
        db(code);
        opAddr(addr, ext);
    }
    // use code1 if reg1 == st0
    // use code2 if reg1 != st0 && reg2 == st0
    void opFpuFpu(Fpu reg1, Fpu reg2, uint32_t code1, uint32_t code2)
    {
        uint32_t code = reg1.getIdx == 0 ? code1 : reg2.getIdx == 0 ? code2 : 0;
        if (!code) mixin(XBYAK_THROW(ERR.BAD_ST_COMBINATION));
        db(cast(uint8_t) (code >> 8));
        db(cast(uint8_t) (code | (reg1.getIdx | reg2.getIdx)));
    }
    void opFpu(Fpu reg, uint8_t code1, uint8_t code2)
    {
        db(code1);
        db(code2 | reg.getIdx);
    }
    void opVex(Reg r, Operand p1, Operand op2, in uint64_t type, int code, int imm8 = NONE)
    {
        if (op2.isMEM()) {
            Address addr = op2.getAddress();
            RegExp regExp = addr.getRegExp();
            Reg base = regExp.getBase();
            Reg index = regExp.getIndex();
            if (BIT == 64 && addr.is32bit()) db(0x67);
            int disp8N = 0;
            if ((type & (T_MUST_EVEX|T_MEM_EVEX)) || r.hasEvex() || (p1 && p1.hasEvex()) || addr.isBroadcast() || addr.getOpmaskIdx() || addr.hasRex2()) {
                int aaa = addr.getOpmaskIdx();
                if (aaa && !(type & T_M_K)) mixin(XBYAK_THROW(ERR.INVALID_OPMASK_WITH_MEMORY));
                bool b = false;
                if (addr.isBroadcast()) {
                    if (!(type & (T_B32 | T_B64))) mixin(XBYAK_THROW(ERR.INVALID_BROADCAST));
                    b = true;
                }
                int VL = regExp.isVsib() ? index.getBit() : 0;
                disp8N = evex(r, base, p1, type, code, index, b, aaa, VL, index.isSIMD() && index.isExtIdx2());
            } else {
                vex(r, base, p1, type, code, index.isExtIdx());
            }
            if (type & T_VSIB) addr.permitVsib = true;
            if (disp8N) addr.disp8N = disp8N;
            if (imm8 != NONE) addr.immSize = 1;
            opAddr(addr, r.getIdx());
        } else {
            Reg base = op2.getReg();
            if ((type & T_MUST_EVEX) || r.hasEvex() || (p1 && p1.hasEvex()) || base.hasEvex()) {
                evex(r, base, p1, type, code);
            } else {
                vex(r, base, p1, type, code);
            }
            setModRM(3, r.getIdx(), base.getIdx());
        }
        if (imm8 != NONE) db(imm8);
    }
    // (r, r, r/m)
    // opRRO(a, b, c) == opROO(b, c, a)
    void opRRO(Reg d, Reg r1, Operand op2, uint64_t type, uint8_t code, int imm8 = NONE)
    {
        const uint bit = d.getBit();
        if (r1.getBit() != bit || (op2.isREG() && op2.getBit() != bit)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        type |= (bit == 64) ? T_W1 : T_W0;
        if (d.hasRex2() || r1.hasRex2() || op2.hasRex2() || d.getNF()) {
            opROO(r1, op2, d, type, code);
            if (imm8 != NONE) db(imm8);
        } else {
            opVex(d, r1, op2, type, code, imm8);
        }
    }
    void opAVX_X_X_XM(Xmm x1, Operand op1, Operand op2, uint64_t type, int code0, int imm8 = NONE)
    {
        Xmm x2 = cast(Xmm)op1;
        Operand op = op2;
        if (op2.isNone()) { // (x1, op1) -> (x1, x1, op1)
            x2 = x1;
            op = op1;
        }
        // (x1, x2, op)
        if (!((x1.isXMM && x2.isXMM) || ((type & T_YMM) && ((x1.isYMM && x2.isYMM) || (x1.isZMM && x2.isZMM))))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        opVex(x1, x2, op, type, code0, imm8);
    }
    void opAVX_K_X_XM(Opmask k, Xmm x2, Operand op3, uint64_t type, int code0, int imm8 = NONE)
    {
        if (!op3.isMEM() && (x2.getKind() != op3.getKind())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        opVex(k, x2, op3, type, code0, imm8);
    }
    // (x, x/m), (y, x/m256), (z, y/m)
    void checkCvt1(Operand x, Operand op)
    {
        if (!op.isMEM() && !(x.isKind(Kind.XMM | Kind.YMM) && op.isXMM()) && !(x.isZMM() && op.isYMM()))
        {
            mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        }
    }
    // (x, x/m), (x, y/m256), (y, z/m)
    void checkCvt2(Xmm x, Operand op)
    {
        if (!(x.isXMM() && op.isKind(Kind.XMM | Kind.YMM | Kind.MEM)) && !(x.isYMM() && op.isKind(Kind.ZMM | Kind.MEM)))
        {
            mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        }
    }
    void opCvt(Xmm x, Operand op, uint64_t type, int code)
    {
        Kind kind = x.isXMM() ? (op.isBit(256) ? Kind.YMM : Kind.XMM) : Kind.ZMM;
        opVex(x.copyAndSetKind(kind), xm0, op, type, code);
    }
    void opCvt2(Xmm x, Operand op, uint64_t type, int code)
    {
        checkCvt2(x, op);
        opCvt(x, op, type, code);
    }
    void opCvt3(Xmm x1, Xmm x2, Operand op, uint64_t type, uint64_t type64, uint64_t type32, uint8_t code)
    {
        if (!(x1.isXMM() && x2.isXMM() && (op.isREG(i32e) || op.isMEM()))) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        Xmm x = Xmm(op.getIdx());
        Operand p = op.isREG() ? x : op;
        opVex(x1, x2, p, (type | (op.isBit(64) ? type64 : type32)), code);
    }
    // (x, x/y/xword/yword), (y, z/m)
    void checkCvt4(Xmm x, Operand op) const
    {
        if (!(x.isXMM() && op.isKind(Kind.XMM | Kind.YMM | Kind.MEM) && op.isBit(128|256)) && !(x.isYMM() && op.isKind(Kind.ZMM | Kind.MEM)))
        {
            mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        }
    }
    // (x, x/y/z/xword/yword/zword)
    void opCvt5(Xmm x, Operand op, uint64_t type, int code)
    {
        if (!(x.isXMM() && op.isBit(128|256|512))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        Kind kind = op.isBit(128) ? Kind.XMM : op.isBit(256) ? Kind.YMM : Kind.ZMM;
        opVex(x.copyAndSetKind(kind), xm0, op, type, code);
    }
    // (x, x, x/m), (x, y, y/m), (y, z, z/m)
    void opCvt6(Xmm x1, Xmm x2, Operand op, uint64_t type, int code)
    {
        const int b1 = x1.getBit();
        const int b2 = x2.getBit();
        const int b3 = op.getBit();
        if ((b1 == 128 && (b2 == 128 || b2 == 256) && (b2 == b3 || op.isMEM())) || (b1 == 256 && b2 == 512 && (b3 == b2 || op.isMEM())))
        {
            opVex(x1, x2, op, type, code);
            return;
        }
        mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    }
    Xmm cvtIdx0(Operand x)
    {
        return x.isZMM() ? zm0 : x.isYMM() ? ym0 : xm0;
    }
    // support (x, x/m, imm), (y, y/m, imm)
    void opAVX_X_XM_IMM(Xmm x, Operand op, uint64_t type, int code, int imm8 = NONE)
    {
        opAVX_X_X_XM(x, cvtIdx0(x), op, type, code, imm8);
    }
    void opCnt(Reg reg, Operand op, uint8_t code)
    {
        if (reg.isBit(8)) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        bool is16bit = reg.isREG(16) && (op.isREG(16) || op.isMEM());
        if (!is16bit && !(reg.isREG(i32e) && (op.isREG(reg.getBit()) || op.isMEM())))
        {
            mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        }
        opRO(reg, op, T_F3 | T_0F, code);
    }
    void opGather(Xmm x1, Address addr, Xmm x2, uint64_t type, uint8_t code, int mode)
    {
        RegExp regExp = addr.getRegExp();
        if (!regExp.isVsib(128 | 256)) mixin(XBYAK_THROW(ERR.BAD_VSIB_ADDRESSING));
        const int y_vx_y = 0;
        const int y_vy_y = 1;
//      const int x_vy_x = 2;
        bool isAddrYMM = regExp.getIndex().getBit() == 256;
        if (!x1.isXMM() || isAddrYMM || !x2.isXMM()) {
            bool isOK = false;
            if (mode == y_vx_y) {
                isOK = x1.isYMM() && !isAddrYMM && x2.isYMM();
            } else if (mode == y_vy_y) {
                isOK = x1.isYMM() && isAddrYMM && x2.isYMM();
            } else {    // x_vy_x
                isOK = !x1.isYMM() && isAddrYMM && !x2.isYMM();
            }
            if (!isOK) mixin(XBYAK_THROW(ERR.BAD_VSIB_ADDRESSING));
        }
        int i1 = x1.getIdx();
        int i2 = regExp.getIndex().getIdx();
        int i3 = x2.getIdx();
        if (i1 == i2 || i1 == i3 || i2 == i3) mixin(XBYAK_THROW(ERR.SAME_REGS_ARE_INVALID));
        opAVX_X_X_XM(isAddrYMM ? Ymm(i1) : x1, isAddrYMM ? Ymm(i3) : x2, addr, type, code);
    }
    enum {
        xx_yy_zz = 0,
        xx_yx_zy = 1,
        xx_xy_yz = 2
    }
    void checkGather2(Xmm x1, Reg x2, int mode) const
    {
        if (x1.isXMM() && x2.isXMM()) return;
        final switch (mode) {
            case xx_yy_zz: if ((x1.isYMM() && x2.isYMM()) || (x1.isZMM() && x2.isZMM())) return;
                break;
            case xx_yx_zy: if ((x1.isYMM() && x2.isXMM()) || (x1.isZMM() && x2.isYMM())) return;
                break;
            case xx_xy_yz: if ((x1.isXMM() && x2.isYMM()) || (x1.isYMM() && x2.isZMM())) return;
                break;
        }
        mixin(XBYAK_THROW(ERR.BAD_VSIB_ADDRESSING));
    }
    void opGather2(Xmm x, Address addr, uint64_t type, uint8_t code, int mode)
    {
        if (x.hasZero()) mixin(XBYAK_THROW(ERR.INVALID_ZERO));
        RegExp regExp = addr.getRegExp();
        checkGather2(x, regExp.getIndex(), mode);
        int maskIdx = x.getOpmaskIdx();
        if ((type & T_M_K) && addr.getOpmaskIdx()) maskIdx = addr.getOpmaskIdx();
        if (maskIdx == 0) mixin(XBYAK_THROW(ERR.K0_IS_INVALID));
        if (!(type & T_M_K) && x.getIdx() == regExp.getIndex().getIdx()) mixin(XBYAK_THROW(ERR.SAME_REGS_ARE_INVALID));
        opVex(x, null, addr, type, code);
    }
    /*
        xx_xy_yz ; mode = true
        xx_xy_xz ; mode = false
    */
    void opVmov(Operand op, Xmm x, uint64_t type, uint8_t code, bool mode)
    {
        if (mode) {
            if (!op.isMEM() && !((op.isXMM() && x.isXMM()) || (op.isXMM() && x.isYMM()) || (op.isYMM() && x.isZMM()))) {
                mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
            }
        } else {
            if (!op.isMEM() && !op.isXMM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        }
        opVex(x, null, op, type, code);
    }
    void opGatherFetch(Address addr, Xmm x, uint64_t type, uint8_t code, Kind kind)
    {
        if (addr.hasZero()) mixin(XBYAK_THROW(ERR.INVALID_ZERO));
        if (addr.getRegExp().getIndex().getKind() != kind) mixin(XBYAK_THROW(ERR.BAD_VSIB_ADDRESSING));
        opVex(x, null, addr, type, code);
    }
    void opEncoding(Xmm x1, Xmm x2, Operand op, uint64_t type, int code, PreferredEncoding encoding, int imm = NONE, uint64_t typeVex = 0, uint64_t typeEvex = 0, int sel = 0)
    {
        opAVX_X_X_XM(x1, x2, op, type | orEvexIf(encoding, typeVex, typeEvex, sel), code, imm);
    }
    PreferredEncoding getEncoding(PreferredEncoding enc, int sel)
    {
        if (enc == DefaultEncoding) {
            enc = defaultEncoding_[sel];
        }
        if ((sel == 0 && enc != VexEncoding && enc != EvexEncoding) ||
            (sel == 1 && enc != PreAVX10v2Encoding && enc != AVX10v2Encoding))
        {
            mixin(XBYAK_THROW_RET(ERR.BAD_ENCODING_MODE, "PreferredEncoding.VexEncoding"));
        }
  version(XBYAK_DISABLE_AVX512)
  {
        if (enc == EvexEncoding || enc == AVX10v2Encoding) mixin(XBYAK_THROW_RET(ERR.EVEX_IS_INVALID, VexEncoding));
  }
        return enc;
    }
    uint64_t orEvexIf(PreferredEncoding enc, uint64_t typeVex, uint64_t typeEvex, int sel)
    {
        enc = getEncoding(enc, sel);
        return ((sel == 0 && enc == VexEncoding) || (sel == 1 && enc != AVX10v2Encoding)) ? typeVex : (T_MUST_EVEX | typeEvex);
    }
    void opInOut(Reg a, Reg d, uint8_t code)
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
        mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    }
    void opInOut(Reg a, uint8_t code, uint8_t v)
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
        mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    }
    void opCcmp(Operand op1, Operand op2, int dfv, int code, int sc) // cmp = 0x38, test = 0x84
    {
        if (dfv < 0 || 15 < dfv) mixin(XBYAK_THROW(ERR.INVALID_DFV));
        opROO(Reg(15 - dfv, Kind.REG, (op1.getBit() | op2.getBit())), op1, op2, T_APX|T_CODE1_IF1, code, 0, sc);
    }
    void opCcmpi(Operand op, int imm, int dfv, int sc)
    {
        if (dfv < 0 || 15 < dfv) mixin(XBYAK_THROW(ERR.INVALID_DFV));
        uint32_t immBit = getImmBit(op, imm);
        uint32_t opBit = op.getBit();
        int tmp = immBit < min(opBit, 32U) ? 2 : 0;
        opROO(Reg(15 - dfv, Kind.REG, opBit), op, Reg(15, Kind.REG, opBit), T_APX|T_CODE1_IF1, 0x80 | tmp, immBit / 8, sc);
        db(imm, immBit / 8);
    }
    void opTesti(Operand op, int imm, int dfv, int sc)
    {
        if (dfv < 0 || 15 < dfv) mixin(XBYAK_THROW(ERR.INVALID_DFV));
        uint32_t opBit = op.getBit();
        if (opBit == 0) mixin(XBYAK_THROW(ERR.MEM_SIZE_IS_NOT_SPECIFIED));
        int immBit = min(opBit, 32U);
        opROO(Reg(15 - dfv, Kind.REG, opBit), op, Reg(0, Kind.REG, opBit), T_APX|T_CODE1_IF1, 0xF6, immBit / 8, sc);
        db(imm, immBit / 8);
    }
    void opCfcmov(Reg d, Operand op1, Operand op2, int code)
    {
        const int dBit = d.getBit();
        const int op2Bit = op2.getBit();
        if (dBit > 0 && op2Bit > 0 && dBit != op2Bit) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        if (op1.isBit(8) || op2Bit == 8) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        if (op2.isMEM()) {
            if (op1.isMEM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
            uint64_t type = dBit > 0 ? (T_MUST_EVEX|T_NF) : T_MUST_EVEX;
            opROO(d, op2, op1, type, code);
        } else {
            opROO(d, op1, cast(Reg)op2|T_nf, T_MUST_EVEX|T_NF, code);
        }
    }
  version(XBYAK64)
  {
    void opAMX(Tmm t1, Address addr, uint64_t type, int code)
    {
        // require both base and index
        Address addr2 = addr.cloneNoOptimize();
        RegExp exp = addr2.getRegExp();
        if (exp.getBase().getBit() == 0 || exp.getIndex().getBit() == 0) mixin(XBYAK_THROW(ERR.NOT_SUPPORTED));
        if (opROO(Reg(), addr2, t1, T_APX|type, code)) return;
        opVex(t1, tmm0, addr2, type, code);
    }
  }
    // (reg32e/mem, k) if rev else (k, k/mem/reg32e)
    // size = 8, 16, 32, 64
    void opKmov(Opmask k, Operand op, bool rev, int size)
    {
        int code = 0;
        bool isReg = op.isREG(size < 64 ? 32 : 64);
        if (rev) {
            code = isReg ? 0x93 : op.isMEM() ? 0x91 : 0;
        } else {
            code = op.isOPMASK() || op.isMEM() ? 0x90 : isReg ? 0x92 : 0;
        }
        if (code == 0) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        uint64_t type = T_0F;
        switch (size) {
            case 8:  type |= T_W0|T_66; break;
            case 16: type |= T_W0; break;
            case 32: type |= isReg ? T_W0|T_F2 : T_W1|T_66; break;
            case 64: type |= isReg ? T_W1|T_F2 : T_W1; break;
            default: assert(0);
        }
        Operand p1 = k;
        Operand p2 = op;
        if (code == 0x93) { swap(p1, p2); }
        if (opROO(Reg(), p2, p1, T_APX|type, code)) return;
        opVex(cast(Reg)p1, null, p2, type, code);
    }
    void opEncodeKey(Reg32 r1, Reg32 r2, uint8_t code1, uint8_t code2)
    {
        if (r1.getIdx() < 8 && r2.getIdx() < 8) {
            db(0xF3); db(0x0F); db(0x38); db(code1); setModRM(3, r1.getIdx(), r2.getIdx());
            return;
        }
        opROO(Reg(), r2, r1, T_MUST_EVEX|T_F3, code2);
    }
    void opSSE_APX(Xmm x, Operand op, uint64_t type1, uint8_t code1, uint64_t type2, uint8_t code2, int imm = NONE)
    {
        if (x.getIdx() <= 15 && op.hasRex2() && opROO(Reg(), op, x, type2, code2, imm != NONE ? 1 : 0)) {
            if (imm != NONE) db(imm);
            return;
        }
        opSSE(x, op, type1, code1, &isXMM_XMMorMEM, imm);
    }
    // AVX10 zero-extending for vmovd, vmovw
    void opAVX10ZeroExt(Operand op1, Operand op2, uint64_t[4] typeTbl, int[4] codeTbl, PreferredEncoding enc, int bit)
    {
        Operand p1 = op1;
        Operand p2 = op2;
        bool rev = false;
        if (p1.isMEM()) {
            swap(p1, p2);
            rev = true;
        }
        if (p1.isMEM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        if (p1.isXMM()) {
            swap(p1, p2);
            rev = !rev;
        }
        enc = getEncoding(enc, 1);
        int sel = -1;
        if (p1.isXMM() || (p1.isMEM() && enc == AVX10v2Encoding)) {
            sel = 2 + cast(int)rev;
        } else if (p1.isREG(bit) || p1.isMEM()) {
            sel = cast(int)rev;
        }
        if (sel == -1) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        opAVX_X_X_XM(cast(Xmm)p2, xm0, p1, typeTbl[sel], codeTbl[sel]);
    }
public:
    size_t getVersion() const { return xbyak.VERSION; }
    enum
    {
        mm0 = Mmx(0), mm1 = Mmx(1), mm2 = Mmx(2), mm3 = Mmx(3),
        mm4 = Mmx(4), mm5 = Mmx(5), mm6 = Mmx(6), mm7 = Mmx(7),
        xmm0 = Xmm(0), xmm1 = Xmm(1), xmm2 = Xmm(2), xmm3 = Xmm(3),
        xmm4 = Xmm(4), xmm5 = Xmm(5), xmm6 = Xmm(6), xmm7 = Xmm(7),
        ymm0 = Ymm(0), ymm1 = Ymm(1), ymm2 = Ymm(2), ymm3 = Ymm(3),
        ymm4 = Ymm(4), ymm5 = Ymm(5), ymm6 = Ymm(6), ymm7 = Ymm(7),
        zmm0 = Zmm(0), zmm1 = Zmm(1), zmm2 = Zmm(2), zmm3 = Zmm(3),
        zmm4 = Zmm(4), zmm5 = Zmm(5), zmm6 = Zmm(6), zmm7 = Zmm(7),
        // for my convenience
        xm0 = xmm0, xm1 = xmm1, xm2 = xmm2, xm3 = xmm3, xm4 = xmm4, xm5 = xmm5, xm6 = xmm6, xm7 = xmm7,
        ym0 = ymm0, ym1 = ymm1, ym2 = ymm2, ym3 = ymm3, ym4 = ymm4, ym5 = ymm5, ym6 = ymm6, ym7 = ymm7,
        zm0 = zmm0, zm1 = zmm1, zm2 = zmm2, zm3 = zmm3, zm4 = zmm4, zm5 = zmm5, zm6 = zmm6, zm7 = zmm7,
        
        eax = Reg32(Operand.EAX), ecx = Reg32(Operand.ECX), edx = Reg32(Operand.EDX), ebx = Reg32(Operand.EBX),
        esp = Reg32(Operand.ESP), ebp = Reg32(Operand.EBP), esi = Reg32(Operand.ESI), edi = Reg32(Operand.EDI),
        ax = Reg16(Operand.EAX), cx = Reg16(Operand.ECX), dx = Reg16(Operand.EDX), bx = Reg16(Operand.EBX),
        sp = Reg16(Operand.ESP), bp = Reg16(Operand.EBP), si = Reg16(Operand.ESI), di = Reg16(Operand.EDI),
        al = Reg8(Operand.AL), cl = Reg8(Operand.CL), dl = Reg8(Operand.DL), bl = Reg8(Operand.BL),
        ah = Reg8(Operand.AH), ch = Reg8(Operand.CH), dh = Reg8(Operand.DH), bh = Reg8(Operand.BH),
        
        ptr = AddressFrame(0),
        byte_ = AddressFrame(8),
        word  = AddressFrame(16),
        dword = AddressFrame(32),
        qword = AddressFrame(64),
        xword = AddressFrame(128),
        yword = AddressFrame(256),
        zword = AddressFrame(512),
        
        ptr_b = AddressFrame(0, true),
        xword_b = AddressFrame(128, true),
        yword_b = AddressFrame(256, true),
        zword_b = AddressFrame(512, true),
        
        st0 = Fpu(0), st1 = Fpu(1), st2 = Fpu(2), st3 = Fpu(3),
        st4 = Fpu(4), st5 = Fpu(5), st6 = Fpu(6), st7 = Fpu(7),
        
        k0 = Opmask(0), k1 = Opmask(1), k2 = Opmask(2), k3 = Opmask(3),
        k4 = Opmask(4), k5 = Opmask(5), k6 = Opmask(6), k7 = Opmask(7),
        
        bnd0 = BoundsReg(0), bnd1 = BoundsReg(1), bnd2 = BoundsReg(2), bnd3 = BoundsReg(3),
        T_sae = EvexModifierRounding(EvexModifierRounding.T_SAE),
        T_rn_sae = EvexModifierRounding(EvexModifierRounding.T_RN_SAE),
        T_rd_sae = EvexModifierRounding(EvexModifierRounding.T_RD_SAE),
        T_ru_sae = EvexModifierRounding(EvexModifierRounding.T_RU_SAE),
        T_rz_sae = EvexModifierRounding(EvexModifierRounding.T_RZ_SAE),
        T_z = EvexModifierZero(),
        T_nf = ApxFlagNF(),
        T_zu = ApxFlagZU()
    }

  version (XBYAK64)
  {
    enum
    {
        rax = Reg64(Operand.RAX), rcx = Reg64(Operand.RCX), rdx = Reg64(Operand.RDX), rbx = Reg64(Operand.RBX),
        rsp = Reg64(Operand.RSP), rbp = Reg64(Operand.RBP), rsi = Reg64(Operand.RSI), rdi = Reg64(Operand.RDI),
        r8 = Reg64(Operand.R8), r9 = Reg64(Operand.R9), r10 = Reg64(Operand.R10), r11 = Reg64(Operand.R11),
        r12 = Reg64(Operand.R12), r13 = Reg64(Operand.R13), r14 = Reg64(Operand.R14), r15 = Reg64(Operand.R15),
        r16 = Reg64(Operand.R16), r17 = Reg64(Operand.R17), r18 = Reg64(Operand.R18), r19 = Reg64(Operand.R19),
        r20 = Reg64(Operand.R20), r21 = Reg64(Operand.R21), r22 = Reg64(Operand.R22), r23 = Reg64(Operand.R23),
        r24 = Reg64(Operand.R24), r25 = Reg64(Operand.R25), r26 = Reg64(Operand.R26), r27 = Reg64(Operand.R27),
        r28 = Reg64(Operand.R28), r29 = Reg64(Operand.R29), r30 = Reg64(Operand.R30), r31 = Reg64(Operand.R31),

        r8d = Reg32(Operand.R8D), r9d = Reg32(Operand.R9D), r10d = Reg32(Operand.R10D), r11d = Reg32(Operand.R11D),
        r12d = Reg32(Operand.R12D), r13d = Reg32(Operand.R13D), r14d = Reg32(Operand.R14D), r15d = Reg32(Operand.R15D),
        r16d = Reg32(Operand.R16D), r17d = Reg32(Operand.R17D), r18d = Reg32(Operand.R18D), r19d = Reg32(Operand.R19D),
        r20d = Reg32(Operand.R20D), r21d = Reg32(Operand.R21D), r22d = Reg32(Operand.R22D), r23d = Reg32(Operand.R23D),
        r24d = Reg32(Operand.R24D), r25d = Reg32(Operand.R25D), r26d = Reg32(Operand.R26D), r27d = Reg32(Operand.R27D),
        r28d = Reg32(Operand.R28D), r29d = Reg32(Operand.R29D), r30d = Reg32(Operand.R30D), r31d = Reg32(Operand.R31D),

        r8w = Reg16(Operand.R8W), r9w = Reg16(Operand.R9W), r10w = Reg16(Operand.R10W), r11w = Reg16(Operand.R11W),
        r12w = Reg16(Operand.R12W), r13w = Reg16(Operand.R13W), r14w = Reg16(Operand.R14W), r15w = Reg16(Operand.R15W),
        r16w = Reg16(Operand.R16W), r17w = Reg16(Operand.R17W), r18w = Reg16(Operand.R18W), r19w = Reg16(Operand.R19W),
        r20w = Reg16(Operand.R20W), r21w = Reg16(Operand.R21W), r22w = Reg16(Operand.R22W), r23w = Reg16(Operand.R23W),
        r24w = Reg16(Operand.R24W), r25w = Reg16(Operand.R25W), r26w = Reg16(Operand.R26W), r27w = Reg16(Operand.R27W),
        r28w = Reg16(Operand.R28W), r29w = Reg16(Operand.R29W), r30w = Reg16(Operand.R30W), r31w = Reg16(Operand.R31W),

        r8b = Reg8(Operand.R8B), r9b = Reg8(Operand.R9B), r10b = Reg8(Operand.R10B), r11b = Reg8(Operand.R11B),
        r12b = Reg8(Operand.R12B), r13b = Reg8(Operand.R13B), r14b = Reg8(Operand.R14B), r15b = Reg8(Operand.R15B),
        r16b = Reg8(Operand.R16B), r17b = Reg8(Operand.R17B), r18b = Reg8(Operand.R18B), r19b = Reg8(Operand.R19B),
        r20b = Reg8(Operand.R20B), r21b = Reg8(Operand.R21B), r22b = Reg8(Operand.R22B), r23b = Reg8(Operand.R23B),
        r24b = Reg8(Operand.R24B), r25b = Reg8(Operand.R25B), r26b = Reg8(Operand.R26B), r27b = Reg8(Operand.R27B),
        r28b = Reg8(Operand.R28B), r29b = Reg8(Operand.R29B), r30b = Reg8(Operand.R30B), r31b = Reg8(Operand.R31B),

        spl = Reg8(Operand.SPL, true),
        bpl = Reg8(Operand.BPL, true),
        sil = Reg8(Operand.SIL, true),
        dil = Reg8(Operand.DIL, true),

        xmm8 = Xmm(8), xmm9 = Xmm(9), xmm10 = Xmm(10), xmm11 = Xmm(11),
        xmm12 = Xmm(12), xmm13 = Xmm(13), xmm14 = Xmm(14), xmm15 = Xmm(15),
        xmm16 = Xmm(16), xmm17 = Xmm(17), xmm18 = Xmm(18), xmm19 = Xmm(19),
        xmm20 = Xmm(20), xmm21 = Xmm(21), xmm22 = Xmm(22), xmm23 = Xmm(23),
        xmm24 = Xmm(24), xmm25 = Xmm(25), xmm26 = Xmm(26), xmm27 = Xmm(27),
        xmm28 = Xmm(28), xmm29 = Xmm(29), xmm30 = Xmm(30), xmm31 = Xmm(31),

        ymm8 = Ymm(8), ymm9 = Ymm(9), ymm10 = Ymm(10), ymm11 = Ymm(11),
        ymm12 = Ymm(12), ymm13 = Ymm(13), ymm14 = Ymm(14), ymm15 = Ymm(15),
        ymm16 = Ymm(16), ymm17 = Ymm(17), ymm18 = Ymm(18), ymm19 = Ymm(19),
        ymm20 = Ymm(20), ymm21 = Ymm(21), ymm22 = Ymm(22), ymm23 = Ymm(23),
        ymm24 = Ymm(24), ymm25 = Ymm(25), ymm26 = Ymm(26), ymm27 = Ymm(27),
        ymm28 = Ymm(28), ymm29 = Ymm(29), ymm30 = Ymm(30),ymm31 = Ymm(31),

        zmm8 = Zmm(8), zmm9 = Zmm(9), zmm10 = Zmm(10), zmm11 = Zmm(11),
        zmm12 = Zmm(12), zmm13 = Zmm(13), zmm14 = Zmm(14), zmm15 = Zmm(15),
        zmm16 = Zmm(16), zmm17 = Zmm(17), zmm18 = Zmm(18), zmm19 = Zmm(19),
        zmm20 = Zmm(20), zmm21 = Zmm(21), zmm22 = Zmm(22), zmm23 = Zmm(23),
        zmm24 = Zmm(24), zmm25 = Zmm(25), zmm26 = Zmm(26), zmm27 = Zmm(27),
        zmm28 = Zmm(28), zmm29 = Zmm(29), zmm30 = Zmm(30), zmm31 = Zmm(31),

        tmm0 = Tmm(0), tmm1 = Tmm(1), tmm2 = Tmm(2), tmm3 = Tmm(3),
        tmm4 = Tmm(4), tmm5 = Tmm(5), tmm6 = Tmm(6), tmm7 = Tmm(7),

        // for my convenience
        xm8 = xmm8, xm9 = xmm9, xm10 = xmm10, xm11 = xmm11,
        xm12 = xmm12, xm13 = xmm13, xm14 = xmm14, xm15 = xmm15,
        xm16 = xmm16, xm17 = xmm17, xm18 = xmm18, xm19 = xmm19,
        xm20 = xmm20, xm21 = xmm21, xm22 = xmm22, xm23 = xmm23,
        xm24 = xmm24, xm25 = xmm25, xm26 = xmm26, xm27 = xmm28,
        xm29 = xmm29, xm30 = xmm30, xm31 = xmm31,

        ym8 = ymm8, ym9 = ymm9, ym10 = ymm10, ym11 = ymm11,
        ym12 = ymm12, ym13 = ymm13, ym14 = ymm14, ym15 = ymm15,
        ym16 = ymm16, ym17 = ymm17, ym18 = ymm18, ym19 = ymm19,
        ym20 = ymm20, ym21 = ymm21, ym22 = ymm22, ym23 = ymm23,
        ym24 = ymm24, ym25 = ymm25, ym26 = ymm26, ym27 = ymm28,
        ym29 = ymm29, ym30 = ymm30, ym31 = ymm31,

        zm8 = zmm8, zm9 = zmm9, zm10 = zmm10, zm11 = zmm11,
        zm12 = zmm12, zm13 = zmm13, zm14 = zmm14, zm15 = zmm15,
        zm16 = zmm16, zm17 = zmm17, zm18 = zmm18, zm19 = zmm19,
        zm20 = zmm20, zm21 = zmm21, zm22 = zmm22, zm23 = zmm23,
        zm24 = zmm24, zm25 = zmm25, zm26 = zmm26, zm27 = zmm28,
        zm29 = zmm29, zm30 = zmm30, zm31 = zmm31,

        rip = RegRip()
    }

      version(XBYAK_DISABLE_SEGMENT)
      {}
      else
      {
        enum {
            es = Segment(Segment.es),
            cs = Segment(Segment.cs),
            ss = Segment(Segment.ss),
            ds = Segment(Segment.ds),
            fs = Segment(Segment.fs),
            gs = Segment(Segment.gs)
        }
      }
  }

private:
    bool isDefaultJmpNEAR_;
    PreferredEncoding[2] defaultEncoding_; // 0:vnni, 1:vmpsadbw
public:
    void L(string label) { labelMgr_.defineSlabel(label); }
    void L(ref Label label) { labelMgr_.defineClabel(&label); }
    Label L(){ Label label; L(label); return label; }
    void inLocalLabel() { labelMgr_.enterLocal; }
    void outLocalLabel() { labelMgr_.leaveLocal; }
    // assign src to dst
    // require
    // dst : does not used by L()
    // src : used by L()
    void assignL(ref Label dst, Label src) { labelMgr_.assign(dst, src); }
    /*
        put address of label to buffer
        @note the put size is 4(32-bit), 8(64-bit)
    */
    void putL(string label) { putL_inner(label); }
    void putL(ref Label label) { putL_inner(&label); }

    // set default type of `jmp` of undefined label to T_NEAR
    void setDefaultJmpNEAR(bool isNear) { isDefaultJmpNEAR_ = isNear; }
    void jmp(Operand op, LabelType type = T_AUTO) { opJmpOp(op, type, 4); }
    void jmp(string label, LabelType type = T_AUTO) { opJmp(label, type, 0xEB, 0xE9, 0); }
    void jmp(const char* label, LabelType type = T_AUTO) { jmp(to!string(label), type); }
    void jmp(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0xEB, 0xE9, 0); }
    void jmp(const void* addr, LabelType type = T_AUTO) { opJmpAbs(addr, type, 0xEB, 0xE9); }

    void call(Operand op, LabelType type = T_AUTO) { opJmpOp(op, type, 2); }
    // call(string label), not string
    void call(string label) { opJmp(label, T_NEAR, 0, 0xE8, 0); }
    void call(const char* label) { call(to!string(label)); }
    void call(ref Label label) { opJmp(label, T_NEAR, 0, 0xE8, 0); }

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
        opRO(reg, op, 0, 0x84, op.getKind() == reg.getKind());
    }
    void test(Operand op, uint32_t imm)
    {
        verifyMemHasSize(op);
        int immSize = min(op.getBit / 8, 4U);
        if (op.isREG && op.getIdx == 0) {    // al, ax, eax
            rex(op);
            db(0xA8 | (op.isBit(8) ? 0 : 1));
        } else {
            opRext(op, 0, 0, 0, 0xF6, false, immSize);
        }
        db(imm, immSize);
    }
    void imul(Reg reg, Operand op, int imm)
    {
        int s = inner.IsInDisp8(imm) ? 1 : 0;
        int immSize = s ? 1 : reg.isREG(16) ? 2 : 4;
        uint8_t code = cast(uint8_t)(0x69 | (s << 1));
        if (!opROO(Reg(), op, reg, T_APX|T_NF|T_ZU, code, immSize)) {
            opRO(reg, op, 0, code, reg.getKind() == op.getKind(), immSize);
        }
        db(imm, immSize);
    }
    void push(Operand op) { opPushPop(op, 0xFF, 6, 0x50); }
    void pop(Operand op) { opPushPop(op, 0x8F, 0, 0x58); }
    void push(AddressFrame af, uint32_t imm)
    {
        if (af.bit_ == 8) {
            db(0x6A); db(imm);
        } else if (af.bit_ == 16) {
            db(0x66); db(0x68); dw(imm);
        } else {
            db(0x68); dd(imm);
        }
    }
    // use "push(word, 4)" if you want "push word 4"
    void push(uint32_t imm)
    {
        if (inner.IsInDisp8(imm)) {
            push(byte_, imm);
        } else {
            push(dword, imm);
        }
    }
  
  version (XBYAK64)
  {    
    void mov(Operand op1, Operand op2)
    {
        Reg reg = null;
        Address addr = null;
        uint8_t code = 0;
        if (op1.isREG() && op1.getIdx() == 0 && op2.isMEM())   // mov eax|ax|al, [disp]
        {
            reg  = op1.getReg();
            addr = op2.getAddress();
            code = 0xA0;
        } else
        if (op1.isMEM() && op2.isREG() && op2.getIdx() == 0)     // mov [disp], eax|ax|al
        {
            reg  = op2.getReg();
            addr = op1.getAddress();
            code = 0xA2;
        }

        if (addr && addr.is64bitDisp())
        {
            if (code) {
                rex(reg);
                db(op1.isREG(8) ? 0xA0 : op1.isREG() ? 0xA1 : op2.isREG(8) ? 0xA2 : 0xA3);
                db(addr.getDisp(), 8);
            } else {
                mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
            }
        }
        else
        {
            opRO_MR(op1, op2, 0x88);
        }
    }
  }
  else
  {
    void mov(Operand op1, Operand op2)
    {
        Reg reg = null;
        Address addr = null;
        uint8_t code = 0;
        if (op1.isREG() && op1.getIdx() == 0 && op2.isMEM())   // mov eax|ax|al, [disp]
        {
            reg  = op1.getReg();
            addr = op2.getAddress();
            code = 0xA0;
        } else
        if (op1.isMEM() && op2.isREG() && op2.getIdx() == 0)     // mov [disp], eax|ax|al
        {
            reg  = op2.getReg();
            addr = op1.getAddress();
            code = 0xA2;
        }

        if (code && addr.isOnlyDisp())
        {
            rex(reg, addr);
            db(code | (reg.isBit(8) ? 0 : 1));
            dd(cast(uint32_t) (addr.getDisp()));
        }
        else
        {
            opRO_MR(op1, op2, 0x88);
        }
    }
  }


    void mov(Operand op, uint64_t imm)
    {
        if (op.isREG()) {
            const int size = mov_imm(op.getReg(), imm);
            db(imm, size);
        } else if (op.isMEM()) {
            verifyMemHasSize(op);
            int immSize = op.getBit() / 8;
            if (immSize <= 4) {
                int64_t s = cast(int64_t)imm >> (immSize * 8);
                if (s != 0 && s != -1) mixin(XBYAK_THROW(ERR.IMM_IS_TOO_BIG));
            } else {
                if (!inner.IsInInt32(imm)) mixin(XBYAK_THROW(ERR.IMM_IS_TOO_BIG));
                immSize = 4;
            }
            opMR(op.getAddress(immSize), Reg(0, Kind.REG, op.getBit()), 0, 0xC6);
            db(cast(uint32_t)imm, immSize);
        } else {
            mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        }
    }
    
    // The template is used to avoid ambiguity when the 2nd argument is 0.
    // When the 2nd argument is 0 the call goes to
    // `void mov(const Operand& op, uint64_t imm)`.
    //    template <typename T1, typename T2>
    //    void mov(const T1&, const T2 *) { T1::unexpected; }
    void mov(NativeReg reg, ref Label label)
    {
        mov_imm(reg, dummyAddr);
        putL(label);
    }
    void mov(NativeReg reg, string label)
    {
        mov_imm(reg, dummyAddr);
        putL(label);
    }
    void xchg(Operand op1, Operand op2)
    {
        Operand p1 = op1;
        Operand p2 = op2;
        if (p1.isMEM() || (p2.isREG(16 | i32e) && p2.getIdx() == 0))
        {
            p1 = op2; p2 = op1;
        }
        if (p1.isMEM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
        bool BL = true;
  version (XBYAK64)
  {
        BL = (p2.getIdx != 0 || !p1.isREG(32));
  }
        if (p2.isREG && (p1.isREG(16 | i32e) && p1.getIdx == 0) && BL)
        {
            rex(p2, p1);
            db(0x90 | (p2.getIdx() & 7));
            return;
        }
        if (p1.isREG() && p2.isREG()) swap(p1, p2); // adapt to NASM 2.16.03 behavior to pass tests
        opRO(cast(Reg)p1, p2, 0, 0x86 | (p1.isBit(8) ? 0 : 1), (p1.isREG() && (p1.getBit() == p2.getBit())));
    }

  version(XBYAK_DISABLE_SEGMENT)
  {}
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
        case Segment.cs: mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
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
        opRO(Reg8(seg.getIdx()), op, T_ALLOW_DIFF_SIZE | T_ALLOW_ABCDH, 0x8C, op.isREG(16|i32e));
    }
    void mov(Segment seg, Operand op)
    {
        opRO(Reg8(seg.getIdx()), op.isREG(16|i32e) ? cast(Operand)(op.getReg().cvt32()) : op, T_ALLOW_DIFF_SIZE | T_ALLOW_ABCDH, 0x8E, op.isREG(16|i32e));
    }
  }
    enum { NONE = 256 }
public:
    this(size_t maxSize = DEFAULT_MAX_CODE_SIZE, void* userPtr = null, Allocator allocator = null)
    {
        super(maxSize, userPtr, allocator);
        this.isDefaultJmpNEAR_ = false;
        setDefaultEncoding();
        setDefaultEncodingAVX10();
        
        labelMgr_.reset();
        labelMgr_.set(this);
    }
    void reset()
    {
        ClearError();
        resetSize();
        labelMgr_.reset();
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
        if (hasUndefinedLabel()) mixin(XBYAK_THROW(ERR.LABEL_IS_NOT_FOUND));
        if (isAutoGrow()) {
            calcJmpAddress();
            if (useProtect()) setProtectMode(mode);
        }
    }
    // set read/exec
    void readyRE() { return ready(ProtectMode.PROTECT_RE); }

  version(XBYAK_TEST)
  {
    override void dump(bool doClear = true)
    {
        xbyak.CodeArray.dump(doClear);
    }
  }
    // set default encoding of VNNI
    // EvexEncoding : AVX512_VNNI, VexEncoding : AVX-VNNI
    void setDefaultEncoding(PreferredEncoding enc = EvexEncoding)
    {
        if (enc != VexEncoding && enc != EvexEncoding) mixin(XBYAK_THROW(ERR.BAD_ENCODING_MODE));
        defaultEncoding_[0] = enc;
    }
    // default : PreferredEncoding : AVX-VNNI-INT8/AVX512-FP16
    void setDefaultEncodingAVX10(PreferredEncoding enc = PreAVX10v2Encoding)
    {
        if (enc != PreAVX10v2Encoding && enc != AVX10v2Encoding) mixin(XBYAK_THROW(ERR.BAD_ENCODING_MODE));
        defaultEncoding_[1] = enc;
    }
    void bswap(Reg32e r)
    {
        int idx = r.getIdx();
        uint8_t rex = (r.isREG(64) ? 8 : 0) | ((idx & 8) ? 1 : 0);
        if (idx >= 16) {
            db(0xD5); db((1<<7) | (idx & 16) | rex);
        } else {
            if (rex) db(0x40 | rex);
            db(0x0F);
        }
        db(0xC8 + (idx & 7));
    }
    void vmovd(Operand op1, Operand op2, PreferredEncoding enc = DefaultEncoding)
    {
        uint64_t[4] typeTbl = [
            T_EVEX|T_66|T_0F|T_W0|T_N4, T_EVEX|T_66|T_0F|T_W0|T_N4, // legacy, avx, avx512
            T_MUST_EVEX|T_66|T_0F|T_EW0|T_N4, T_MUST_EVEX|T_F3|T_0F|T_EW0|T_N4, // avx10.2
        ];
        int[4] codeTbl = [ 0x7E, 0x6E, 0xD6, 0x7E ];
        opAVX10ZeroExt(op1, op2, typeTbl, codeTbl, enc, 32);
    }
    void vmovw(Operand op1, Operand op2, PreferredEncoding enc = DefaultEncoding)
    {
        uint64_t[4] typeTbl = [
            T_MUST_EVEX|T_66|T_MAP5|T_N2, T_MUST_EVEX|T_66|T_MAP5|T_N2, // avx512-fp16
            T_MUST_EVEX|T_F3|T_MAP5|T_EW0|T_N2, T_MUST_EVEX|T_F3|T_MAP5|T_EW0|T_N2, // avx10.2
        ];
        int[4] codeTbl = [ 0x7E, 0x6E, 0x7E, 0x6E ];
        opAVX10ZeroExt(op1, op2, typeTbl, codeTbl, enc, 16|32|64);
    }
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
        uint8_t[][] nopTbl = [
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
            uint8_t* seq = nopTbl[len - 1].ptr;
            db(seq, len);
            size -= len;
        }
    }

  version(XBYAK_DONT_READ_LIST)
  {}
  else
  {
    /*
        use single byte nop if useMultiByteNop = false
    */
    void xbayk_align(size_t x = 16, bool useMultiByteNop = true)
    {
        if (x == 1) return;
        if (x < 1 || (x & (x - 1))) mixin(XBYAK_THROW(ERR.BAD_ALIGN));
        if (isAutoGrow() && inner.getPageSize() % x != 0) mixin(XBYAK_THROW(ERR.BAD_ALIGN));
        size_t remain = cast(size_t)(getCurr()) % x;
        if (remain) {
            nop(x - remain, useMultiByteNop);
        }
    }
  }

version(XBYAK_DONT_READ_LIST)
{}
else
{

string getVersionString() const { return "0.7250"; }
void aadd(Address addr, Reg32e reg) { opMR(addr, reg, T_0F38, 0x0FC, T_APX); }
void aand(Address addr, Reg32e reg) { opMR(addr, reg, T_0F38|T_66, 0x0FC, T_APX|T_66); }
void adc(Operand op, uint32_t imm) { opOI(op, imm, 0x10, 2); }
void adc(Operand op1, Operand op2) { opRO_MR(op1, op2, 0x10); }
void adc(Reg d, Operand op, uint32_t imm) { opROI(d, op, imm, T_NONE, 2); }
void adc(Reg d, Operand op1, Operand op2) { opROO(d, op1, op2, T_NONE, 0x10); }
void adcx(Reg32e d, Reg32e reg, Operand op) { opROO(d, op, reg, T_66, 0x66); }
void adcx(Reg32e reg, Operand op) { if (!reg.isREG(16|i32e) && reg.getBit() == op.getBit()) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER)); if (opROO(Reg(), op, reg, T_66, 0x66)) return; opRO(reg, op, T_66 | T_0F38, 0xF6); }
void add(Operand op, uint32_t imm) { opOI(op, imm, 0x00, 0); }
void add(Operand op1, Operand op2) { opRO_MR(op1, op2, 0x00); }
void add(Reg d, Operand op, uint32_t imm) { opROI(d, op, imm, T_NF|T_CODE1_IF1, 0); }
void add(Reg d, Operand op1, Operand op2) { opROO(d, op1, op2, T_NF|T_CODE1_IF1, 0x00); }
void addpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x58, &isXMM_XMMorMEM); }
void addps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x58, &isXMM_XMMorMEM); }
void addsd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F2, 0x58, &isXMM_XMMorMEM); }
void addss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F3, 0x58, &isXMM_XMMorMEM); }
void addsubpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F|T_YMM, 0xD0, &isXMM_XMMorMEM); }
void addsubps(Xmm xmm, Operand op) { opSSE(xmm, op, T_F2|T_0F|T_YMM, 0xD0, &isXMM_XMMorMEM); }
void adox(Reg32e d, Reg32e reg, Operand op) { opROO(d, op, reg, T_F3, 0x66); }
void adox(Reg32e reg, Operand op)
{
    if (!reg.isREG(16|i32e) && reg.getBit() == op.getBit()) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
    if (opROO(Reg(), op, reg, T_F3, 0x66)) return;
    opRO(reg, op, T_F3 | T_0F38, 0xF6);
}
void aesdec(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F38|T_YMM|T_EVEX, 0xDE, &isXMM_XMMorMEM); }
void aesdeclast(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F38|T_YMM|T_EVEX, 0xDF, &isXMM_XMMorMEM); }
void aesenc(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F38|T_YMM|T_EVEX, 0xDC, &isXMM_XMMorMEM); }
void aesenclast(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F38|T_YMM|T_EVEX, 0xDD, &isXMM_XMMorMEM); }
void aesimc(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F38|T_W0, 0xDB, &isXMM_XMMorMEM, NONE); }
void aeskeygenassist(Xmm xmm, Operand op, uint8_t imm) { opSSE(xmm, op, T_66|T_0F3A, 0xDF, &isXMM_XMMorMEM, imm); }
void and_(Operand op, uint32_t imm) { opOI(op, imm, 0x20, 4); }
void and_(Operand op1, Operand op2) { opRO_MR(op1, op2, 0x20); }
void and_(Reg d, Operand op, uint32_t imm) { opROI(d, op, imm, T_NF|T_CODE1_IF1, 4); }
void and_(Reg d, Operand op1, Operand op2) { opROO(d, op1, op2, T_NF|T_CODE1_IF1, 0x20); }
void andn(Reg32e r1, Reg32e r2, Operand op) { opRRO(r1, r2, op, T_APX|T_0F38|T_NF, 0xf2); }
void andnpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x55, &isXMM_XMMorMEM); }
void andnps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x55, &isXMM_XMMorMEM); }
void andpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x54, &isXMM_XMMorMEM); }
void andps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x54, &isXMM_XMMorMEM); }
void aor(Address addr, Reg32e reg) { opMR(addr, reg, T_0F38|T_F2, 0x0FC, T_APX|T_F2); }
void axor(Address addr, Reg32e reg) { opMR(addr, reg, T_0F38|T_F3, 0x0FC, T_APX|T_F3); }

void bextr(Reg32e r1, Operand op, Reg32e r2) { opRRO(r1, r2, op, T_APX|T_0F38|T_NF, 0xf7); }
void blendpd(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x0D, &isXMM_XMMorMEM, cast(uint8_t)imm); }
void blendps(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x0C, &isXMM_XMMorMEM, cast(uint8_t)imm); }
void blendvpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F38, 0x15, &isXMM_XMMorMEM, NONE); }
void blendvps(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F38, 0x14, &isXMM_XMMorMEM, NONE); }
void blsi(Reg32e r, Operand op) { opRRO(Reg32e(3, r.getBit()), r, op, T_APX|T_0F38|T_NF, 0xf3); }
void blsmsk(Reg32e r, Operand op) { opRRO(Reg32e(2, r.getBit()), r, op, T_APX|T_0F38|T_NF, 0xf3); }
void blsr(Reg32e r, Operand op) { opRRO(Reg32e(1, r.getBit()), r, op, T_APX|T_0F38|T_NF, 0xf3); }
void bnd() { db(0xF2); }
void bndcl(BoundsReg bnd, Operand op) { opRext(op, i32e, bnd.getIdx(), T_F3 | T_0F, 0x1A, !op.isMEM()); }
void bndcn(BoundsReg bnd, Operand op) { opRext(op, i32e, bnd.getIdx(), T_F2 | T_0F, 0x1B, !op.isMEM()); }
void bndcu(BoundsReg bnd, Operand op) { opRext(op, i32e, bnd.getIdx(), T_F2 | T_0F, 0x1A, !op.isMEM()); }
void bndldx(BoundsReg bnd, Address addr) { opMIB(addr, bnd, T_0F, 0x1A); }
void bndmk(BoundsReg bnd, Address addr) { opMR(addr, bnd, T_F3 | T_0F, 0x1B); }
void bndmov(Address addr, BoundsReg bnd) { opMR(addr, bnd, T_66 | T_0F, 0x1B); }
void bndmov(BoundsReg bnd, Operand op) { opRO(bnd, op, T_66 | T_0F, 0x1A, op.isBNDREG()); }
void bndstx(Address addr, BoundsReg bnd) { opMIB(addr, bnd, T_0F, 0x1B); }
void bsf(Reg reg, Operand op) { opRO(reg, op, T_0F, 0xBC, op.isREG(16|i32e)); }
void bsr(Reg reg, Operand op) { opRO(reg, op, T_0F, 0xBD, op.isREG(16|i32e)); }
void bt(Operand op, Reg reg) { opRO(reg, op, T_0F, 0xA3, op.isREG(16|i32e) && op.getBit() == reg.getBit()); }
void bt(Operand op, uint8_t imm) { opRext(op, 16|i32e, 4, T_0F, 0xba, false, 1); db(imm); }
void btc(Operand op, Reg reg) { opRO(reg, op, T_0F, 0xBB, op.isREG(16|i32e) && op.getBit() == reg.getBit()); }
void btc(Operand op, uint8_t imm) { opRext(op, 16|i32e, 7, T_0F, 0xba, false, 1); db(imm); }
void btr(Operand op, Reg reg) { opRO(reg, op, T_0F, 0xB3, op.isREG(16|i32e) && op.getBit() == reg.getBit()); }
void btr(Operand op, uint8_t imm) { opRext(op, 16|i32e, 6, T_0F, 0xba, false, 1); db(imm); }
void bts(Operand op, Reg reg) { opRO(reg, op, T_0F, 0xAB, op.isREG(16|i32e) && op.getBit() == reg.getBit()); }
void bts(Operand op, uint8_t imm) { opRext(op, 16|i32e, 5, T_0F, 0xba, false, 1); db(imm); }
void bzhi(Reg32e r1, Operand op, Reg32e r2) { opRRO(r1, r2, op, T_APX|T_0F38|T_NF, 0xf5); }

void cbw() { db(0x66); db(0x98); }
void ccmpa(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 7); }
void ccmpa(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 7); }
void ccmpae(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 3); }
void ccmpae(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 3); }
void ccmpb(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 2); }
void ccmpb(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 2); }
void ccmpbe(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 6); }
void ccmpbe(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 6); }
void ccmpc(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 2); }
void ccmpc(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 2); }
void ccmpe(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 4); }
void ccmpe(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 4); }
void ccmpf(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 11); }
void ccmpf(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 11); }
void ccmpg(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 15); }
void ccmpg(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 15); }
void ccmpge(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 13); }
void ccmpge(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 13); }
void ccmpl(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 12); }
void ccmpl(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 12); }
void ccmple(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 14); }
void ccmple(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 14); }
void ccmpna(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 6); }
void ccmpna(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 6); }
void ccmpnae(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 2); }
void ccmpnae(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 2); }
void ccmpnb(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 3); }
void ccmpnb(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 3); }
void ccmpnbe(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 7); }
void ccmpnbe(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 7); }
void ccmpnc(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 3); }
void ccmpnc(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 3); }
void ccmpne(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 5); }
void ccmpne(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 5); }
void ccmpng(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 14); }
void ccmpng(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 14); }
void ccmpnge(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 12); }
void ccmpnge(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 12); }
void ccmpnl(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 13); }
void ccmpnl(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 13); }
void ccmpnle(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 15); }
void ccmpnle(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 15); }
void ccmpno(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 1); }
void ccmpno(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 1); }
void ccmpns(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 9); }
void ccmpns(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 9); }
void ccmpnz(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 5); }
void ccmpnz(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 5); }
void ccmpo(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 0); }
void ccmpo(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 0); }
void ccmps(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 8); }
void ccmps(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 8); }
void ccmpt(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 10); }
void ccmpt(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 10); }
void ccmpz(Operand op, int imm, int dfv = 0) { opCcmpi(op, imm, dfv, 4); }
void ccmpz(Operand op1, Operand op2, int dfv = 0) { opCcmp(op1, op2, dfv, 0x38, 4); }
void cdq() { db(0x99); }
void cfcmovb(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x42); }
void cfcmovb(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x42); }
void cfcmovbe(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x46); }
void cfcmovbe(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x46); }
void cfcmovl(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x4C); }
void cfcmovl(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x4C); }
void cfcmovle(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x4E); }
void cfcmovle(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x4E); }
void cfcmovnb(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x43); }
void cfcmovnb(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x43); }
void cfcmovnbe(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x47); }
void cfcmovnbe(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x47); }
void cfcmovnl(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x4D); }
void cfcmovnl(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x4D); }
void cfcmovnle(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x4F); }
void cfcmovnle(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x4F); }
void cfcmovno(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x41); }
void cfcmovno(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x41); }
void cfcmovnp(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x4B); }
void cfcmovnp(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x4B); }
void cfcmovns(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x49); }
void cfcmovns(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x49); }
void cfcmovnz(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x45); }
void cfcmovnz(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x45); }
void cfcmovo(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x40); }
void cfcmovo(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x40); }
void cfcmovp(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x4A); }
void cfcmovp(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x4A); }
void cfcmovs(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x48); }
void cfcmovs(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x48); }
void cfcmovz(Operand op1, Operand op2) { opCfcmov(Reg(), op1, op2, 0x44); }
void cfcmovz(Reg d, Reg r, Operand op) { opCfcmov(d|T_nf, op, r, 0x44); }
void clc() { db(0xF8); }
void cld() { db(0xFC); }
void cldemote(Address addr) { opMR(addr, eax, T_0F, 0x1C); }
void clflush(Address addr) { opMR(addr, Reg32(7), T_0F, 0xAE); }
void clflushopt(Address addr) { opMR(addr, Reg32(7), T_66 | T_0F, 0xAE); }
void cli() { db(0xFA); }
void clwb(Address addr) { opMR(addr, esi, T_66 | T_0F, 0xAE); }
void clzero() { db(0x0F); db(0x01); db(0xFC); }
void cmc() { db(0xF5); }
void cmova(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 7); }
void cmova(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 7, op.isREG(16|i32e)); }
void cmovae(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 3); }
void cmovae(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 3, op.isREG(16|i32e)); }
void cmovb(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 2); }
void cmovb(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 2, op.isREG(16|i32e)); }
void cmovbe(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 6); }
void cmovbe(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 6, op.isREG(16|i32e)); }
void cmovc(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 2); }
void cmovc(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 2, op.isREG(16|i32e)); }
void cmove(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 4); }
void cmove(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 4, op.isREG(16|i32e)); }
void cmovg(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 15); }
void cmovg(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 15, op.isREG(16|i32e)); }
void cmovge(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 13); }
void cmovge(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 13, op.isREG(16|i32e)); }
void cmovl(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 12); }
void cmovl(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 12, op.isREG(16|i32e)); }
void cmovle(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 14); }
void cmovle(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 14, op.isREG(16|i32e)); }
void cmovna(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 6); }
void cmovna(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 6, op.isREG(16|i32e)); }
void cmovnae(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 2); }
void cmovnae(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 2, op.isREG(16|i32e)); }
void cmovnb(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 3); }
void cmovnb(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 3, op.isREG(16|i32e)); }
void cmovnbe(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 7); }
void cmovnbe(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 7, op.isREG(16|i32e)); }
void cmovnc(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 3); }
void cmovnc(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 3, op.isREG(16|i32e)); }
void cmovne(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 5); }
void cmovne(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 5, op.isREG(16|i32e)); }
void cmovng(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 14); }
void cmovng(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 14, op.isREG(16|i32e)); }
void cmovnge(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 12); }
void cmovnge(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 12, op.isREG(16|i32e)); }
void cmovnl(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 13); }
void cmovnl(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 13, op.isREG(16|i32e)); }
void cmovnle(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 15); }
void cmovnle(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 15, op.isREG(16|i32e)); }
void cmovno(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 1); }
void cmovno(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 1, op.isREG(16|i32e)); }
void cmovnp(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 11); }
void cmovnp(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 11, op.isREG(16|i32e)); }
void cmovns(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 9); }
void cmovns(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 9, op.isREG(16|i32e)); }
void cmovnz(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 5); }
void cmovnz(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 5, op.isREG(16|i32e)); }
void cmovo(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 0); }
void cmovo(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 0, op.isREG(16|i32e)); }
void cmovp(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 10); }
void cmovp(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 10, op.isREG(16|i32e)); }
void cmovpe(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 10); }
void cmovpe(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 10, op.isREG(16|i32e)); }
void cmovpo(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 11); }
void cmovpo(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 11, op.isREG(16|i32e)); }
void cmovs(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 8); }
void cmovs(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 8, op.isREG(16|i32e)); }
void cmovz(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1, 0x40 | 4); }
void cmovz(Reg reg, Operand op) { opRO(reg, op, T_0F, 0x40 | 4, op.isREG(16|i32e)); }
void cmp(Operand op, uint32_t imm) { opOI(op, imm, 0x38, 7); }
void cmp(Operand op1, Operand op2) { opRO_MR(op1, op2, 0x38); }
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
void cmppd(Xmm xmm, Operand op, uint8_t imm8) { opSSE(xmm, op, T_0F | T_66, 0xC2, &isXMM_XMMorMEM, imm8); }
void cmpps(Xmm xmm, Operand op, uint8_t imm8) { opSSE(xmm, op, T_0F, 0xC2, &isXMM_XMMorMEM, imm8); }
void cmpsb() { db(0xA6); }
void cmpsd() { db(0xA7); }
void cmpsd(Xmm xmm, Operand op, uint8_t imm8) { opSSE(xmm, op, T_0F | T_F2, 0xC2, &isXMM_XMMorMEM, imm8); }
void cmpss(Xmm xmm, Operand op, uint8_t imm8) { opSSE(xmm, op, T_0F | T_F3, 0xC2, &isXMM_XMMorMEM, imm8); }
void cmpsw() { db(0x66); db(0xA7); }
void cmpunordpd(Xmm x, Operand op) { cmppd(x, op, 3); }
void cmpunordps(Xmm x, Operand op) { cmpps(x, op, 3); }
void cmpunordsd(Xmm x, Operand op) { cmpsd(x, op, 3); }
void cmpunordss(Xmm x, Operand op) { cmpss(x, op, 3); }
void cmpxchg(Operand op, Reg reg) { opRO(reg, op, T_0F, 0xB0 | (reg.isBit(8) ? 0 : 1), op.getBit() == reg.getBit()); }
void cmpxchg8b(Address addr) { opMR(addr, Reg32(1), T_0F, 0xC7); }
void comisd(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F, 0x2F, &isXMM_XMMorMEM); }
void comiss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x2F, &isXMM_XMMorMEM); }
void cpuid() { db(0x0F); db(0xA2); }
void crc32(Reg32e r, Operand op)
{
    if (!((r.isBit(32) && op.isBit(8|16|32)) || (r.isBit(64) && op.isBit(8|64))))
    {
        mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
    }
    int code = 0xF0 | (op.isBit(8) ? 0 : 1);
    uint64_t type = op.isBit(16) ? T_66:0; type |= T_ALLOW_DIFF_SIZE;
    if (opROO(Reg(), op, cast(Reg)(r), T_APX|type, code)) return;
    opRO(r, op, T_F2|T_0F38|type, code);
}
void ctesta(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 7); }
void ctesta(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 7); }
void ctestae(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 3); }
void ctestae(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 3); }
void ctestb(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 2); }
void ctestb(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 2); }
void ctestbe(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 6); }
void ctestbe(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 6); }
void ctestc(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 2); }
void ctestc(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 2); }
void cteste(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 4); }
void cteste(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 4); }
void ctestf(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 11); }
void ctestf(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 11); }
void ctestg(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 15); }
void ctestg(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 15); }
void ctestge(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 13); }
void ctestge(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 13); }
void ctestl(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 12); }
void ctestl(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 12); }
void ctestle(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 14); }
void ctestle(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 14); }
void ctestna(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 6); }
void ctestna(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 6); }
void ctestnae(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 2); }
void ctestnae(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 2); }
void ctestnb(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 3); }
void ctestnb(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 3); }
void ctestnbe(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 7); }
void ctestnbe(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 7); }
void ctestnc(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 3); }
void ctestnc(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 3); }
void ctestne(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 5); }
void ctestne(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 5); }
void ctestng(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 14); }
void ctestng(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 14); }
void ctestnge(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 12); }
void ctestnge(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 12); }
void ctestnl(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 13); }
void ctestnl(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 13); }
void ctestnle(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 15); }
void ctestnle(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 15); }
void ctestno(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 1); }
void ctestno(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 1); }
void ctestns(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 9); }
void ctestns(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 9); }
void ctestnz(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 5); }
void ctestnz(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 5); }
void ctesto(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 0); }
void ctesto(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 0); }
void ctests(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 8); }
void ctests(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 8); }
void ctestt(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 10); }
void ctestt(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 10); }
void ctestz(Operand op, Reg r, int dfv = 0) { opCcmp(op, r, dfv, 0x84, 4); }
void ctestz(Operand op, int imm, int dfv = 0) { opTesti(op, imm, dfv, 4); }
void cvtdq2pd(Xmm xmm, Operand op) { opSSE(xmm, op, T_F3|T_0F, 0xE6, &isXMM_XMMorMEM); }
void cvtdq2ps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x5B, &isXMM_XMMorMEM); }
void cvtpd2dq(Xmm xmm, Operand op) { opSSE(xmm, op, T_F2|T_0F, 0xE6, &isXMM_XMMorMEM); }
void cvtpd2pi(Reg reg, Operand op) { opSSE(reg, op, T_66|T_0F, 0x2D, &isMMX_XMMorMEM); }
void cvtpd2ps(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F, 0x5A, &isXMM_XMMorMEM); }
void cvtpi2pd(Reg reg, Operand op) { opSSE(reg, op, T_66|T_0F, 0x2A, &isXMM_MMXorMEM); }
void cvtpi2ps(Reg reg, Operand op) { opSSE(reg, op, T_0F, 0x2A, &isXMM_MMXorMEM); }
void cvtps2dq(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F, 0x5B, &isXMM_XMMorMEM); }
void cvtps2pd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x5A, &isXMM_XMMorMEM); }
void cvtps2pi(Reg reg, Operand op) { opSSE(reg, op, T_0F, 0x2D, &isMMX_XMMorMEM); }
void cvtsd2si(Reg reg, Operand op) { opSSE(reg, op, T_F2|T_0F, 0x2D, &isREG32_XMMorMEM); }
void cvtsd2ss(Xmm xmm, Operand op) { opSSE(xmm, op, T_F2|T_0F, 0x5A, &isXMM_XMMorMEM); }
void cvtsi2sd(Reg reg, Operand op) { opSSE(reg, op, T_F2|T_0F, 0x2A, &isXMM_REG32orMEM); }
void cvtsi2ss(Reg reg, Operand op) { opSSE(reg, op, T_F3|T_0F, 0x2A, &isXMM_REG32orMEM); }
void cvtss2sd(Xmm xmm, Operand op) { opSSE(xmm, op, T_F3|T_0F, 0x5A, &isXMM_XMMorMEM); }
void cvtss2si(Reg reg, Operand op) { opSSE(reg, op, T_F3|T_0F, 0x2D, &isREG32_XMMorMEM); }
void cvttpd2dq(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F, 0xE6, &isXMM_XMMorMEM); }
void cvttpd2pi(Reg reg, Operand op) { opSSE(reg, op, T_66|T_0F, 0x2C, &isMMX_XMMorMEM); }
void cvttps2dq(Xmm xmm, Operand op) { opSSE(xmm, op, T_F3|T_0F, 0x5B, &isXMM_XMMorMEM); }
void cvttps2pi(Reg reg, Operand op) { opSSE(reg, op, T_0F, 0x2C, &isMMX_XMMorMEM); }
void cvttsd2si(Reg reg, Operand op) { opSSE(reg, op, T_F2|T_0F, 0x2C, &isREG32_XMMorMEM); }
void cvttss2si(Reg reg, Operand op) { opSSE(reg, op, T_F3|T_0F, 0x2C, &isREG32_XMMorMEM); }
void cwd() { db(0x66); db(0x99); }
void cwde() { db(0x98); }

void dec(Operand op) { opIncDec(Reg(), op, 1); }
void dec(Reg d, Operand op) { opIncDec(d, op, 1); }
void div(Operand op) { opRext(op, 0, 6, T_APX|T_NF|T_CODE1_IF1, 0xF6); }
void divpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x5E, &isXMM_XMMorMEM); }
void divps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x5E, &isXMM_XMMorMEM); }
void divsd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F2, 0x5E, &isXMM_XMMorMEM); }
void divss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F3, 0x5E, &isXMM_XMMorMEM); }
void dppd(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x41, &isXMM_XMMorMEM, cast(uint8_t)imm); }
void dpps(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x40, &isXMM_XMMorMEM, cast(uint8_t)imm); }

void emms() { db(0x0F); db(0x77); }
void endbr32() { db(0xF3); db(0x0F); db(0x1E); db(0xFB); }
void endbr64() { db(0xF3); db(0x0F); db(0x1E); db(0xFA); }
void enter(uint16_t x, uint8_t y) { db(0xC8); dw(x); db(y); }
void extractps(Operand op, Xmm xmm, uint8_t imm) { opExt(op, xmm, 0x17, imm); }

void f2xm1() { db(0xD9); db(0xF0); }
void fabs() { db(0xD9); db(0xE1); }
void fadd(Address addr) { opFpuMem(addr, 0x00, 0xD8, 0xDC, 0, 0); }
void fadd(Fpu reg1) { opFpuFpu(st0, reg1, 0xD8C0, 0xDCC0); }
void fadd(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0xD8C0, 0xDCC0); }
void faddp() { db(0xDE); db(0xC1); }
void faddp(Fpu reg1) { opFpuFpu(reg1, st0, 0x0000, 0xDEC0); }
void faddp(Fpu reg1, Fpu reg2) { opFpuFpu(reg1, reg2, 0x0000, 0xDEC0); }
void fbld(Address addr) { opMR(addr, Reg32(4), 0, 0xDF); }
void fbstp(Address addr) { opMR(addr, Reg32(6), 0, 0xDF); }
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
void fldcw(Address addr) { opMR(addr, Reg32(5), 0, 0xD9); }
void fldenv(Address addr) { opMR(addr, Reg32(4), 0, 0xD9); }
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
void fnsave(Address addr) { opMR(addr, Reg32(6), 0, 0xDD); }
void fnstcw(Address addr) { opMR(addr, Reg32(7), 0, 0xD9); }
void fnstenv(Address addr) { opMR(addr, Reg32(6), 0, 0xD9); }
void fnstsw(Address addr) { opMR(addr, Reg32(7), 0, 0xDD); }
void fnstsw(Reg16 r) { if (r.getIdx() != Operand.AX) mixin(XBYAK_THROW(ERR.BAD_PARAMETER)); db(0xDF); db(0xE0); }
void fpatan() { db(0xD9); db(0xF3); }
void fprem() { db(0xD9); db(0xF8); }
void fprem1() { db(0xD9); db(0xF5); }
void fptan() { db(0xD9); db(0xF2); }
void frndint() { db(0xD9); db(0xFC); }
void frstor(Address addr) { opMR(addr, Reg32(4), 0, 0xDD); }
void fsave(Address addr) { db(0x9B); opMR(addr, Reg32(6), 0, 0xDD); }
void fscale() { db(0xD9); db(0xFD); }
void fsin() { db(0xD9); db(0xFE); }
void fsincos() { db(0xD9); db(0xFB); }
void fsqrt() { db(0xD9); db(0xFA); }
void fst(Address addr) { opFpuMem(addr, 0x00, 0xD9, 0xDD, 2, 0); }
void fst(Fpu reg) { opFpu(reg, 0xDD, 0xD0); }
void fstcw(Address addr) { db(0x9B); opMR(addr, Reg32(7), 0, 0xD9); }
void fstenv(Address addr) { db(0x9B); opMR(addr, Reg32(6), 0, 0xD9); }
void fstp(Address addr) { opFpuMem(addr, 0x00, 0xD9, 0xDD, 3, 0); }
void fstp(Fpu reg) { opFpu(reg, 0xDD, 0xD8); }
void fstsw(Address addr) { db(0x9B); opMR(addr, Reg32(7), 0, 0xDD); }
void fstsw(Reg16 r) { if (r.getIdx() != Operand.AX) mixin(XBYAK_THROW(ERR.BAD_PARAMETER)); db(0x9B); db(0xDF); db(0xE0); }
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
void fxrstor(Address addr) { opMR(addr, Reg32(1), T_0F, 0xAE); }
void fxtract() { db(0xD9); db(0xF4); }
void fyl2x() { db(0xD9); db(0xF1); }
void fyl2xp1() { db(0xD9); db(0xF9); }

void gf2p8affineinvqb(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0xCF, &isXMM_XMMorMEM, cast(uint8_t)imm); }
void gf2p8affineqb(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0xCE, &isXMM_XMMorMEM, cast(uint8_t)imm); }
void gf2p8mulb(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0xCF, &isXMM_XMMorMEM); }

void haddpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F|T_YMM, 0x7C, &isXMM_XMMorMEM); }
void haddps(Xmm xmm, Operand op) { opSSE(xmm, op, T_F2|T_0F|T_YMM, 0x7C, &isXMM_XMMorMEM); }
void hlt() { db(0xF4); }
void hsubpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F|T_YMM, 0x7D, &isXMM_XMMorMEM); }
void hsubps(Xmm xmm, Operand op) { opSSE(xmm, op, T_F2|T_0F|T_YMM, 0x7D, &isXMM_XMMorMEM); }

void idiv(Operand op) { opRext(op, 0, 7, T_APX|T_NF|T_CODE1_IF1, 0xF6); }
void imul(Operand op) { opRext(op, 0, 5, T_APX|T_NF|T_CODE1_IF1, 0xF6); }
void imul(Reg d, Reg reg, Operand op) { opROO(d, op, reg, T_APX|T_ND1|T_NF, 0xAF); }
void imul(Reg reg, Operand op) { if (opROO(Reg(), op, reg, T_APX|T_NF, 0xAF)) return; opRO(reg, op, T_0F, 0xAF, reg.getKind() == op.getKind()); }
void in_(Reg a, Reg d) { opInOut(a, d, 0xEC); }
void in_(Reg a, uint8_t v) { opInOut(a, 0xE4, v); }
void inc(Operand op) { opIncDec(Reg(), op, 0); }
void inc(Reg d, Operand op) { opIncDec(d, op, 0); }
void insertps(Xmm xmm, Operand op, uint8_t imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x21, &isXMM_XMMorMEM, imm); }
void int3() { db(0xCC); }
void int_(uint8_t x) { db(0xCD); db(x); }

void ja(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x77, 0x87, 0x0F); }
void ja(const char* label, LabelType type = T_AUTO) { ja(to!string(label), type); }
void ja(const void* addr) { opJmpAbs(addr, T_NEAR, 0x77, 0x87, 0x0F); }
void ja(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x77, 0x87, 0x0F); }
void jae(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x73, 0x83, 0x0F); }
void jae(const char* label, LabelType type = T_AUTO) { jae(to!string(label), type); }
void jae(const void* addr) { opJmpAbs(addr, T_NEAR, 0x73, 0x83, 0x0F); }
void jae(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x73, 0x83, 0x0F); }
void jb(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x72, 0x82, 0x0F); }
void jb(const char* label, LabelType type = T_AUTO) { jb(to!string(label), type); }
void jb(const void* addr) { opJmpAbs(addr, T_NEAR, 0x72, 0x82, 0x0F); }
void jb(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x72, 0x82, 0x0F); }
void jbe(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x76, 0x86, 0x0F); }
void jbe(const char* label, LabelType type = T_AUTO) { jbe(to!string(label), type); }
void jbe(const void* addr) { opJmpAbs(addr, T_NEAR, 0x76, 0x86, 0x0F); }
void jbe(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x76, 0x86, 0x0F); }
void jc(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x72, 0x82, 0x0F); }
void jc(const char* label, LabelType type = T_AUTO) { jc(to!string(label), type); }
void jc(const void* addr) { opJmpAbs(addr, T_NEAR, 0x72, 0x82, 0x0F); }
void jc(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x72, 0x82, 0x0F); }
void je(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x74, 0x84, 0x0F); }
void je(const char* label, LabelType type = T_AUTO) { je(to!string(label), type); }
void je(const void* addr) { opJmpAbs(addr, T_NEAR, 0x74, 0x84, 0x0F); }
void je(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x74, 0x84, 0x0F); }
void jg(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7F, 0x8F, 0x0F); }
void jg(const char* label, LabelType type = T_AUTO) { jg(to!string(label), type); }
void jg(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7F, 0x8F, 0x0F); }
void jg(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7F, 0x8F, 0x0F); }
void jge(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7D, 0x8D, 0x0F); }
void jge(const char* label, LabelType type = T_AUTO) { jge(to!string(label), type); }
void jge(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7D, 0x8D, 0x0F); }
void jge(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7D, 0x8D, 0x0F); }
void jl(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7C, 0x8C, 0x0F); }
void jl(const char* label, LabelType type = T_AUTO) { jl(to!string(label), type); }
void jl(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7C, 0x8C, 0x0F); }
void jl(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7C, 0x8C, 0x0F); }
void jle(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7E, 0x8E, 0x0F); }
void jle(const char* label, LabelType type = T_AUTO) { jle(to!string(label), type); }
void jle(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7E, 0x8E, 0x0F); }
void jle(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7E, 0x8E, 0x0F); }
void jna(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x76, 0x86, 0x0F); }
void jna(const char* label, LabelType type = T_AUTO) { jna(to!string(label), type); }
void jna(const void* addr) { opJmpAbs(addr, T_NEAR, 0x76, 0x86, 0x0F); }
void jna(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x76, 0x86, 0x0F); }
void jnae(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x72, 0x82, 0x0F); }
void jnae(const char* label, LabelType type = T_AUTO) { jnae(to!string(label), type); }
void jnae(const void* addr) { opJmpAbs(addr, T_NEAR, 0x72, 0x82, 0x0F); }
void jnae(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x72, 0x82, 0x0F); }
void jnb(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x73, 0x83, 0x0F); }
void jnb(const char* label, LabelType type = T_AUTO) { jnb(to!string(label), type); }
void jnb(const void* addr) { opJmpAbs(addr, T_NEAR, 0x73, 0x83, 0x0F); }
void jnb(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x73, 0x83, 0x0F); }
void jnbe(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x77, 0x87, 0x0F); }
void jnbe(const char* label, LabelType type = T_AUTO) { jnbe(to!string(label), type); }
void jnbe(const void* addr) { opJmpAbs(addr, T_NEAR, 0x77, 0x87, 0x0F); }
void jnbe(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x77, 0x87, 0x0F); }
void jnc(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x73, 0x83, 0x0F); }
void jnc(const char* label, LabelType type = T_AUTO) { jnc(to!string(label), type); }
void jnc(const void* addr) { opJmpAbs(addr, T_NEAR, 0x73, 0x83, 0x0F); }
void jnc(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x73, 0x83, 0x0F); }
void jne(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x75, 0x85, 0x0F); }
void jne(const char* label, LabelType type = T_AUTO) { jne(to!string(label), type); }
void jne(const void* addr) { opJmpAbs(addr, T_NEAR, 0x75, 0x85, 0x0F); }
void jne(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x75, 0x85, 0x0F); }
void jng(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7E, 0x8E, 0x0F); }
void jng(const char* label, LabelType type = T_AUTO) { jng(to!string(label), type); }
void jng(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7E, 0x8E, 0x0F); }
void jng(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7E, 0x8E, 0x0F); }
void jnge(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7C, 0x8C, 0x0F); }
void jnge(const char* label, LabelType type = T_AUTO) { jnge(to!string(label), type); }
void jnge(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7C, 0x8C, 0x0F); }
void jnge(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7C, 0x8C, 0x0F); }
void jnl(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7D, 0x8D, 0x0F); }
void jnl(const char* label, LabelType type = T_AUTO) { jnl(to!string(label), type); }
void jnl(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7D, 0x8D, 0x0F); }
void jnl(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7D, 0x8D, 0x0F); }
void jnle(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7F, 0x8F, 0x0F); }
void jnle(const char* label, LabelType type = T_AUTO) { jnle(to!string(label), type); }
void jnle(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7F, 0x8F, 0x0F); }
void jnle(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7F, 0x8F, 0x0F); }
void jno(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x71, 0x81, 0x0F); }
void jno(const char* label, LabelType type = T_AUTO) { jno(to!string(label), type); }
void jno(const void* addr) { opJmpAbs(addr, T_NEAR, 0x71, 0x81, 0x0F); }
void jno(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x71, 0x81, 0x0F); }
void jnp(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7B, 0x8B, 0x0F); }
void jnp(const char* label, LabelType type = T_AUTO) { jnp(to!string(label), type); }
void jnp(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7B, 0x8B, 0x0F); }
void jnp(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7B, 0x8B, 0x0F); }
void jns(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x79, 0x89, 0x0F); }
void jns(const char* label, LabelType type = T_AUTO) { jns(to!string(label), type); }
void jns(const void* addr) { opJmpAbs(addr, T_NEAR, 0x79, 0x89, 0x0F); }
void jns(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x79, 0x89, 0x0F); }
void jnz(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x75, 0x85, 0x0F); }
void jnz(const char* label, LabelType type = T_AUTO) { jnz(to!string(label), type); }
void jnz(const void* addr) { opJmpAbs(addr, T_NEAR, 0x75, 0x85, 0x0F); }
void jnz(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x75, 0x85, 0x0F); }
void jo(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x70, 0x80, 0x0F); }
void jo(const char* label, LabelType type = T_AUTO) { jo(to!string(label), type); }
void jo(const void* addr) { opJmpAbs(addr, T_NEAR, 0x70, 0x80, 0x0F); }
void jo(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x70, 0x80, 0x0F); }
void jp(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7A, 0x8A, 0x0F); }
void jp(const char* label, LabelType type = T_AUTO) { jp(to!string(label), type); }
void jp(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7A, 0x8A, 0x0F); }
void jp(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7A, 0x8A, 0x0F); }
void jpe(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7A, 0x8A, 0x0F); }
void jpe(const char* label, LabelType type = T_AUTO) { jpe(to!string(label), type); }
void jpe(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7A, 0x8A, 0x0F); }
void jpe(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7A, 0x8A, 0x0F); }
void jpo(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x7B, 0x8B, 0x0F); }
void jpo(const char* label, LabelType type = T_AUTO) { jpo(to!string(label), type); }
void jpo(const void* addr) { opJmpAbs(addr, T_NEAR, 0x7B, 0x8B, 0x0F); }
void jpo(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x7B, 0x8B, 0x0F); }
void js(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x78, 0x88, 0x0F); }
void js(const char* label, LabelType type = T_AUTO) { js(to!string(label), type); }
void js(const void* addr) { opJmpAbs(addr, T_NEAR, 0x78, 0x88, 0x0F); }
void js(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x78, 0x88, 0x0F); }
void jz(ref Label label, LabelType type = T_AUTO) { opJmp(label, type, 0x74, 0x84, 0x0F); }
void jz(const char* label, LabelType type = T_AUTO) { jz(to!string(label), type); }
void jz(const void* addr) { opJmpAbs(addr, T_NEAR, 0x74, 0x84, 0x0F); }
void jz(string label, LabelType type = T_AUTO) { opJmp(label, type, 0x74, 0x84, 0x0F); }

void lahf() { db(0x9F); }
void lddqu(Xmm xmm, Address addr) { opSSE(xmm, addr, T_F2 | T_0F, 0xF0); }
void ldmxcsr(Address addr) { opMR(addr, Reg32(2), T_0F, 0xAE); }
void lea(Reg reg, Address addr) { if (!reg.isBit(16 | i32e)) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER)); opMR(addr, reg, 0, 0x8D); }
void leave() { db(0xC9); }
void lfence() { db(0x0F); db(0xAE); db(0xE8); }
void lfs(Reg reg, Address addr) { opLoadSeg(addr, reg, T_0F, 0xB4); }
void lgs(Reg reg, Address addr) { opLoadSeg(addr, reg, T_0F, 0xB5); }
void lock() { db(0xF0); }
void lodsb() { db(0xAC); }
void lodsd() { db(0xAD); }
void lodsw() { db(0x66); db(0xAD); }
void loop(ref Label label) { opJmp(label, T_SHORT, 0xE2, 0, 0); }
void loop(const char* label) { loop(to!string(label)); }
void loop(string label) { opJmp(label, T_SHORT, 0xE2, 0, 0); }
void loope(ref Label label) { opJmp(label, T_SHORT, 0xE1, 0, 0); }
void loope(const char* label) { loope(to!string(label)); }
void loope(string label) { opJmp(label, T_SHORT, 0xE1, 0, 0); }
void loopne(ref Label label) { opJmp(label, T_SHORT, 0xE0, 0, 0); }
void loopne(const char* label) { loopne(to!string(label)); }
void loopne(string label) { opJmp(label, T_SHORT, 0xE0, 0, 0); }
void lss(Reg reg, Address addr) { opLoadSeg(addr, reg, T_0F, 0xB2); }
void lzcnt(Reg reg, Operand op) { if (opROO(Reg(), op, reg, T_APX|T_NF, 0xF5)) return; opCnt(reg, op, 0xBD); }

void maskmovdqu(Xmm reg1, Xmm reg2) { opSSE(reg1, reg2, T_66|T_0F, 0xF7); }
void maskmovq(Mmx reg1, Mmx reg2) { opSSE(reg1, reg2, T_0F, 0xF7); }
void maxpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x5F, &isXMM_XMMorMEM); }
void maxps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x5F, &isXMM_XMMorMEM); }
void maxsd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F2, 0x5F, &isXMM_XMMorMEM); }
void maxss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F3, 0x5F, &isXMM_XMMorMEM); }
void mfence() { db(0x0F); db(0xAE); db(0xF0); }
void minpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x5D, &isXMM_XMMorMEM); }
void minps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x5D, &isXMM_XMMorMEM); }
void minsd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F2, 0x5D, &isXMM_XMMorMEM); }
void minss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F3, 0x5D, &isXMM_XMMorMEM); }
void monitor() { db(0x0F); db(0x01); db(0xC8); }
void monitorx() { db(0x0F); db(0x01); db(0xFA); }
void movapd(Address addr, Xmm xmm) { opSSE(xmm, addr, T_0F|T_66, 0x29); }
void movapd(Xmm xmm, Operand op) { opMMX(xmm, op, 0x28, T_0F, T_66); }
void movaps(Address addr, Xmm xmm) { opSSE(xmm, addr, T_0F|T_NONE, 0x29); }
void movaps(Xmm xmm, Operand op) { opMMX(xmm, op, 0x28, T_0F, T_NONE); }
void movbe(Address addr, Reg reg) { opMR(addr, reg, T_0F38, 0xF1, T_APX, 0x61); }
void movbe(Reg reg, Address addr) { opMR(addr, reg, T_0F38, 0xF0, T_APX, 0x60); }
void movd(Mmx mmx, Operand op) { if (!(op.isMEM() || op.isREG(32))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); if (mmx.isXMM()) db(0x66); opSSE(mmx, op, T_0F | T_ALLOW_DIFF_SIZE, 0x6E); }
void movd(Operand op, Mmx mmx) { if (!(op.isMEM() || op.isREG(32))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); if (mmx.isXMM()) db(0x66); opSSE(mmx, op, T_0F | T_ALLOW_DIFF_SIZE, 0x7E); }
void movddup(Xmm xmm, Operand op) { opSSE(xmm, op, T_DUP|T_F2|T_0F|T_EW1|T_YMM|T_EVEX|T_ER_X|T_ER_Y|T_ER_Z, 0x12, &isXMM_XMMorMEM, NONE); }
void movdir64b(Reg reg, Address addr) { opMR(addr, reg.cvt32(), T_66|T_0F38, 0xF8, T_APX|T_66); }
void movdiri(Address addr, Reg32e reg) { opMR(addr, reg, T_0F38, 0xF9, T_APX); }
void movdq2q(Mmx mmx, Xmm xmm) { opSSE(mmx, xmm, T_F2 | T_0F, 0xD6); }
void movdqa(Address addr, Xmm xmm) { opSSE(xmm, addr, T_0F|T_66, 0x7F); }
void movdqa(Xmm xmm, Operand op) { opMMX(xmm, op, 0x6F, T_0F, T_66); }
void movdqu(Address addr, Xmm xmm) { opSSE(xmm, addr, T_0F|T_F3, 0x7F); }
void movdqu(Xmm xmm, Operand op) { opMMX(xmm, op, 0x6F, T_0F, T_F3); }
void movhlps(Xmm reg1, Xmm reg2) { opSSE(reg1, reg2, T_0F, 0x12); }
void movhpd(Operand op1, Operand op2) { opMovXMM(op1, op2, T_66|T_0F, 0x16); }
void movhps(Operand op1, Operand op2) { opMovXMM(op1, op2, T_0F, 0x16); }
void movlhps(Xmm reg1, Xmm reg2) { opSSE(reg1, reg2, T_0F, 0x16); }
void movlpd(Operand op1, Operand op2) { opMovXMM(op1, op2, T_66|T_0F, 0x12); }
void movlps(Operand op1, Operand op2) { opMovXMM(op1, op2, T_0F, 0x12); }
void movmskpd(Reg32e reg, Xmm xmm) { db(0x66); movmskps(reg, xmm); }
void movmskps(Reg32e reg, Xmm xmm) { opSSE(reg, xmm, T_0F, 0x50); }
void movntdq(Address addr, Xmm reg) { if (reg.getIdx() >= 16) mixin(XBYAK_THROW(ERR.BAD_PARAMETER)); opSSE(Reg16(reg.getIdx()), addr, T_0F, 0xE7); }
void movntdqa(Xmm xmm, Address addr) { opSSE(xmm, addr, T_66 | T_0F38, 0x2A); }
void movnti(Address addr, Reg32e reg) { opMR(addr, reg, T_0F, 0xC3); }
void movntpd(Address addr, Xmm reg) { if (reg.getIdx() >= 16) mixin(XBYAK_THROW(ERR.BAD_PARAMETER)); opSSE(Reg16(reg.getIdx()), addr, T_0F, 0x2B); }
void movntps(Address addr, Xmm xmm) { opSSE(Xmm(xmm.getIdx()), addr, T_0F, 0x2B); }
void movntq(Address addr, Mmx mmx) { if (!mmx.isMMX()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opSSE(mmx, addr, T_0F, 0xE7); }
void movq(Address addr, Mmx mmx) { if (mmx.isXMM()) db(0x66); opSSE(mmx, addr, T_0F | T_ALLOW_DIFF_SIZE, mmx.isXMM() ? 0xD6 : 0x7F); }
void movq(Mmx mmx, Operand op) { if (!op.isMEM() && mmx.getKind() != op.getKind()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); if (mmx.isXMM()) db(0xF3); opSSE(mmx, op, T_0F | T_ALLOW_DIFF_SIZE, mmx.isXMM() ? 0x7E : 0x6F); }
void movq2dq(Xmm xmm, Mmx mmx) { opSSE(xmm, mmx, T_F3 | T_0F, 0xD6); }
void movsb() { db(0xA4); }
void movsd() { db(0xA5); }
void movsd(Address addr, Xmm xmm) { opSSE(xmm, addr, T_0F|T_F2, 0x11); }
void movsd(Xmm xmm, Operand op) { opMMX(xmm, op, 0x10, T_0F, T_F2); }
void movshdup(Xmm xmm, Operand op) { opSSE(xmm, op, T_F3|T_0F|T_EW0|T_YMM|T_EVEX, 0x16, &isXMM_XMMorMEM, NONE); }
void movsldup(Xmm xmm, Operand op) { opSSE(xmm, op, T_F3|T_0F|T_EW0|T_YMM|T_EVEX, 0x12, &isXMM_XMMorMEM, NONE); }
void movss(Address addr, Xmm xmm) { opSSE(xmm, addr, T_0F|T_F3, 0x11); }
void movss(Xmm xmm, Operand op) { opMMX(xmm, op, 0x10, T_0F, T_F3); }
void movsw() { db(0x66); db(0xA5); }
void movsx(Reg reg, Operand op) { opMovxx(reg, op, 0xBE); }
void movupd(Address addr, Xmm xmm) { opSSE(xmm, addr, T_0F|T_66, 0x11); }
void movupd(Xmm xmm, Operand op) { opMMX(xmm, op, 0x10, T_0F, T_66); }
void movups(Address addr, Xmm xmm) { opSSE(xmm, addr, T_0F|T_NONE, 0x11); }
void movups(Xmm xmm, Operand op) { opMMX(xmm, op, 0x10, T_0F, T_NONE); }
void movzx(Reg reg, Operand op) { opMovxx(reg, op, 0xB6); }
void mpsadbw(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x42, &isXMM_XMMorMEM, cast(uint8_t)imm); }
void mul(Operand op) { opRext(op, 0, 4, T_APX|T_NF|T_CODE1_IF1, 0xF6); }
void mulpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x59, &isXMM_XMMorMEM); }
void mulps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x59, &isXMM_XMMorMEM); }
void mulsd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F2, 0x59, &isXMM_XMMorMEM); }
void mulss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F3, 0x59, &isXMM_XMMorMEM); }
void mulx(Reg32e r1, Reg32e r2, Operand op) { opRRO(r1, r2, op, T_APX|T_F2|T_0F38, 0xf6); }
void mwait() { db(0x0F); db(0x01); db(0xC9); }
void mwaitx() { db(0x0F); db(0x01); db(0xFB); }

void neg(Operand op) { opRext(op, 0, 3, T_APX|T_NF|T_CODE1_IF1, 0xF6); }
void neg(Reg d, Operand op) { opROO(d, op, Reg(3, Kind.REG, d.getBit()), T_APX|T_NF|T_CODE1_IF1|T_ND1, 0xF6); }
void not_(Operand op) { opRext(op, 0, 2, T_APX|T_CODE1_IF1, 0xF6); }
void not_(Reg d, Operand op) { opROO(d, op, Reg(2, Kind.REG, d.getBit()), T_APX|T_CODE1_IF1|T_ND1, 0xF6); }

void or_(Operand op, uint32_t imm) { opOI(op, imm, 0x08, 1); }
void or_(Operand op1, Operand op2) { opRO_MR(op1, op2, 0x08); }
void or_(Reg d, Operand op, uint32_t imm) { opROI(d, op, imm, T_NF|T_CODE1_IF1, 1); }
void or_(Reg d, Operand op1, Operand op2) { opROO(d, op1, op2, T_NF|T_CODE1_IF1, 0x08); }
void orpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x56, &isXMM_XMMorMEM); }
void orps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x56, &isXMM_XMMorMEM); }
void out_(Reg d, Reg a) { opInOut(a, d, 0xEE); }
void out_(uint8_t v, Reg a) { opInOut(a, 0xE6, v); }
void outsb() { db(0x6E); }
void outsd() { db(0x6F); }
void outsw() { db(0x66); db(0x6F); }

void pabsb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x1C, T_0F38, T_66); }
void pabsd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x1E, T_0F38, T_66); }
void pabsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x1D, T_0F38, T_66); }
void packssdw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x6B); }
void packsswb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x63); }
void packusdw(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x2B, &isXMM_XMMorMEM); }
void packuswb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x67); }
void paddb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xFC); }
void paddd(Mmx mmx, Operand op) { opMMX(mmx, op, 0xFE); }
void paddq(Mmx mmx, Operand op) { opMMX(mmx, op, 0xD4); }
void paddsb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xEC); }
void paddsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xED); }
void paddusb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDC); }
void paddusw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDD); }
void paddw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xFD); }
void palignr(Mmx mmx, Operand op, int imm) { opMMX(mmx, op, 0x0F, T_0F3A, T_66, cast(uint8_t)imm); }
void pand(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDB); }
void pandn(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDF); }
void pause() { db(0xF3); db(0x90); }
void pavgb(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE0); }
void pavgw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE3); }
void pblendvb(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F38, 0x10, &isXMM_XMMorMEM, NONE); }
void pblendw(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x0E, &isXMM_XMMorMEM, cast(uint8_t)imm); }
void pclmulhqhqdq(Xmm xmm, Operand op) { pclmulqdq(xmm, op, 0x11); }
void pclmulhqlqdq(Xmm xmm, Operand op) { pclmulqdq(xmm, op, 0x01); }
void pclmullqhqdq(Xmm xmm, Operand op) { pclmulqdq(xmm, op, 0x10); }
void pclmullqlqdq(Xmm xmm, Operand op) { pclmulqdq(xmm, op, 0x00); }
void pclmulqdq(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x44, &isXMM_XMMorMEM, cast(uint8_t)imm); }
void pcmpeqb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x74); }
void pcmpeqd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x76); }
void pcmpeqq(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x29, &isXMM_XMMorMEM); }
void pcmpeqw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x75); }
void pcmpestri(Xmm xmm, Operand op, uint8_t imm) { opSSE(xmm, op, T_66|T_0F3A, 0x61, &isXMM_XMMorMEM, imm); }
void pcmpestrm(Xmm xmm, Operand op, uint8_t imm) { opSSE(xmm, op, T_66|T_0F3A, 0x60, &isXMM_XMMorMEM, imm); }
void pcmpgtb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x64); }
void pcmpgtd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x66); }
void pcmpgtq(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x37, &isXMM_XMMorMEM); }
void pcmpgtw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x65); }
void pcmpistri(Xmm xmm, Operand op, uint8_t imm) { opSSE(xmm, op, T_66|T_0F3A, 0x63, &isXMM_XMMorMEM, imm); }
void pcmpistrm(Xmm xmm, Operand op, uint8_t imm) { opSSE(xmm, op, T_66|T_0F3A, 0x62, &isXMM_XMMorMEM, imm); }
void pdep(Reg32e r1, Reg32e r2, Operand op) { opRRO(r1, r2, op, T_APX|T_F2|T_0F38, 0xf5); }
void pext(Reg32e r1, Reg32e r2, Operand op) { opRRO(r1, r2, op, T_APX|T_F3|T_0F38, 0xf5); }
void pextrb(Operand op, Xmm xmm, uint8_t imm) { opExt(op, xmm, 0x14, imm); }
void pextrd(Operand op, Xmm xmm, uint8_t imm) { opExt(op, xmm, 0x16, imm); }
void pextrw(Operand op, Mmx xmm, uint8_t imm) { opExt(op, xmm, 0x15, imm, true); }
void phaddd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x02, T_0F38, T_66); }
void phaddsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x03, T_0F38, T_66); }
void phaddw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x01, T_0F38, T_66); }
void phminposuw(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F38, 0x41, &isXMM_XMMorMEM, NONE); }
void phsubd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x06, T_0F38, T_66); }
void phsubsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x07, T_0F38, T_66); }
void phsubw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x05, T_0F38, T_66); }
void pinsrb(Xmm xmm, Operand op, uint8_t imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x20, &isXMM_REG32orMEM, imm); }
void pinsrd(Xmm xmm, Operand op, uint8_t imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x22, &isXMM_REG32orMEM, imm); }
void pinsrw(Mmx mmx, Operand op, int imm) { if (!op.isREG(32) && !op.isMEM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opSSE(mmx, op, T_0F | (mmx.isXMM() ? T_66 : T_NONE), 0xC4, null, imm); }
void pmaddubsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x04, T_0F38, T_66); }
void pmaddwd(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF5); }
void pmaxsb(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x3C, &isXMM_XMMorMEM); }
void pmaxsd(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x3D, &isXMM_XMMorMEM); }
void pmaxsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xEE); }
void pmaxub(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDE); }
void pmaxud(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x3F, &isXMM_XMMorMEM); }
void pmaxuw(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x3E, &isXMM_XMMorMEM); }
void pminsb(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x38, &isXMM_XMMorMEM); }
void pminsd(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x39, &isXMM_XMMorMEM); }
void pminsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xEA); }
void pminub(Mmx mmx, Operand op) { opMMX(mmx, op, 0xDA); }
void pminud(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x3B, &isXMM_XMMorMEM); }
void pminuw(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x3A, &isXMM_XMMorMEM); }
void pmovmskb(Reg32e reg, Mmx mmx) { if (mmx.isXMM()) db(0x66); opSSE(reg, mmx, T_0F, 0xD7); }
void pmovsxbd(Xmm xmm, Operand op) { opSSE(xmm, op, T_N4|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x21, &isXMM_XMMorMEM, NONE); }
void pmovsxbq(Xmm xmm, Operand op) { opSSE(xmm, op, T_N2|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x22, &isXMM_XMMorMEM, NONE); }
void pmovsxbw(Xmm xmm, Operand op) { opSSE(xmm, op, T_N8|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x20, &isXMM_XMMorMEM, NONE); }
void pmovsxdq(Xmm xmm, Operand op) { opSSE(xmm, op, T_N8|T_N_VL|T_66|T_0F38|T_EW0|T_YMM|T_EVEX, 0x25, &isXMM_XMMorMEM, NONE); }
void pmovsxwd(Xmm xmm, Operand op) { opSSE(xmm, op, T_N8|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x23, &isXMM_XMMorMEM, NONE); }
void pmovsxwq(Xmm xmm, Operand op) { opSSE(xmm, op, T_N4|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x24, &isXMM_XMMorMEM, NONE); }
void pmovzxbd(Xmm xmm, Operand op) { opSSE(xmm, op, T_N4|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x31, &isXMM_XMMorMEM, NONE); }
void pmovzxbq(Xmm xmm, Operand op) { opSSE(xmm, op, T_N2|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x32, &isXMM_XMMorMEM, NONE); }
void pmovzxbw(Xmm xmm, Operand op) { opSSE(xmm, op, T_N8|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x30, &isXMM_XMMorMEM, NONE); }
void pmovzxdq(Xmm xmm, Operand op) { opSSE(xmm, op, T_N8|T_N_VL|T_66|T_0F38|T_EW0|T_YMM|T_EVEX, 0x35, &isXMM_XMMorMEM, NONE); }
void pmovzxwd(Xmm xmm, Operand op) { opSSE(xmm, op, T_N8|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x33, &isXMM_XMMorMEM, NONE); }
void pmovzxwq(Xmm xmm, Operand op) { opSSE(xmm, op, T_N4|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x34, &isXMM_XMMorMEM, NONE); }
void pmuldq(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x28, &isXMM_XMMorMEM); }
void pmulhrsw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x0B, T_0F38, T_66); }
void pmulhuw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE4); }
void pmulhw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xE5); }
void pmulld(Xmm xmm, Operand op) { opSSE(xmm, op, T_66 | T_0F38, 0x40, &isXMM_XMMorMEM); }
void pmullw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xD5); }
void pmuludq(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF4); }
void popcnt(Reg reg, Operand op) { opCnt(reg, op, 0xB8); }
void popf() { db(0x9D); }
void por(Mmx mmx, Operand op) { opMMX(mmx, op, 0xEB); }
void prefetchit0(Address addr) { opMR(addr, Reg32(7), T_0F, 0x18); }
void prefetchit1(Address addr) { opMR(addr, Reg32(6), T_0F, 0x18); }
void prefetchnta(Address addr) { opMR(addr, Reg32(0), T_0F, 0x18); }
void prefetcht0(Address addr) { opMR(addr, Reg32(1), T_0F, 0x18); }
void prefetcht1(Address addr) { opMR(addr, Reg32(2), T_0F, 0x18); }
void prefetcht2(Address addr) { opMR(addr, Reg32(3), T_0F, 0x18); }
void prefetchw(Address addr) { opMR(addr, Reg32(1), T_0F, 0x0D); }
void prefetchwt1(Address addr) { opMR(addr, Reg32(2), T_0F, 0x0D); }
void psadbw(Mmx mmx, Operand op) { opMMX(mmx, op, 0xF6); }
void pshufb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x00, T_0F38, T_66); }
void pshufd(Mmx mmx, Operand op, uint8_t imm8) { opMMX(mmx, op, 0x70, T_0F, T_66, imm8); }
void pshufhw(Mmx mmx, Operand op, uint8_t imm8) { opMMX(mmx, op, 0x70, T_0F, T_F3, imm8); }
void pshuflw(Mmx mmx, Operand op, uint8_t imm8) { opMMX(mmx, op, 0x70, T_0F, T_F2, imm8); }
void pshufw(Mmx mmx, Operand op, uint8_t imm8) { opMMX(mmx, op, 0x70, T_0F, T_NONE, imm8); }
void psignb(Mmx mmx, Operand op) { opMMX(mmx, op, 0x08, T_0F38, T_66); }
void psignd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x0A, T_0F38, T_66); }
void psignw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x09, T_0F38, T_66); }
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
void ptest(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F38|T_YMM, 0x17, &isXMM_XMMorMEM, NONE); }
void punpckhbw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x68); }
void punpckhdq(Mmx mmx, Operand op) { opMMX(mmx, op, 0x6A); }
void punpckhqdq(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F, 0x6D, &isXMM_XMMorMEM); }
void punpckhwd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x69); }
void punpcklbw(Mmx mmx, Operand op) { opMMX(mmx, op, 0x60); }
void punpckldq(Mmx mmx, Operand op) { opMMX(mmx, op, 0x62); }
void punpcklqdq(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F, 0x6C, &isXMM_XMMorMEM); }
void punpcklwd(Mmx mmx, Operand op) { opMMX(mmx, op, 0x61); }
void pushf() { db(0x9C); }
void pxor(Mmx mmx, Operand op) { opMMX(mmx, op, 0xEF); }

void rcl(Operand op, Reg8 _cl) { opShift(op, _cl, 2); }
void rcl(Operand op, int imm) { opShift(op, imm, 2); }
void rcl(Reg d, Operand op, Reg8 _cl) { opShift(op, _cl, 2, d); }
void rcl(Reg d, Operand op, int imm) { opShift(op, imm, 2, d); }
void rcpps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x53, &isXMM_XMMorMEM); }
void rcpss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F3, 0x53, &isXMM_XMMorMEM); }
void rcr(Operand op, Reg8 _cl) { opShift(op, _cl, 3); }
void rcr(Operand op, int imm) { opShift(op, imm, 3); }
void rcr(Reg d, Operand op, Reg8 _cl) { opShift(op, _cl, 3, d); }
void rcr(Reg d, Operand op, int imm) { opShift(op, imm, 3, d); }
void rdmsr() { db(0x0F); db(0x32); }
void rdpmc() { db(0x0F); db(0x33); }
void rdrand(Reg r)
{
    if (r.isBit(8)) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
    opRR(Reg(6, Kind.REG, r.getBit()), r, T_0F, 0xC7);
}
void rdseed(Reg r)
{
    if (r.isBit(8)) mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
    opRR(Reg(7, Kind.REG, r.getBit()), r, T_0F, 0xC7);
}
void rdtsc() { db(0x0F); db(0x31); }
void rdtscp() { db(0x0F); db(0x01); db(0xF9); }
void rep() { db(0xF3); }
void repe() { db(0xF3); }
void repne() { db(0xF2); }
void repnz() { db(0xF2); }
void repz() { db(0xF3); }
void ret(int imm = 0) { if (imm) { db(0xC2); dw(imm); } else { db(0xC3); } }
void retf(int imm = 0) { if (imm) { db(0xCA); dw(imm); } else { db(0xCB); } }
void rol(Operand op, Reg8 _cl) { opShift(op, _cl, 8); }
void rol(Operand op, int imm) { opShift(op, imm, 8); }
void rol(Reg d, Operand op, Reg8 _cl) { opShift(op, _cl, 8, d); }
void rol(Reg d, Operand op, int imm) { opShift(op, imm, 8, d); }
void ror(Operand op, Reg8 _cl) { opShift(op, _cl, 9); }
void ror(Operand op, int imm) { opShift(op, imm, 9); }
void ror(Reg d, Operand op, Reg8 _cl) { opShift(op, _cl, 9, d); }
void ror(Reg d, Operand op, int imm) { opShift(op, imm, 9, d); }
void rorx(Reg32e r, Operand op, uint8_t imm) { opRRO(r, Reg32e(0, r.getBit()), op, T_0F3A|T_F2|T_APX, 0xF0, imm); }
void roundpd(Xmm xmm, Operand op, uint8_t imm) { opSSE(xmm, op, T_66|T_0F3A|T_YMM, 0x09, &isXMM_XMMorMEM, imm); }
void roundps(Xmm xmm, Operand op, uint8_t imm) { opSSE(xmm, op, T_66|T_0F3A|T_YMM, 0x08, &isXMM_XMMorMEM, imm); }
void roundsd(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x0B, &isXMM_XMMorMEM, cast(uint8_t)imm); }
void roundss(Xmm xmm, Operand op, int imm) { opSSE(xmm, op, T_66 | T_0F3A, 0x0A, &isXMM_XMMorMEM, cast(uint8_t)imm); }
void rsqrtps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x52, &isXMM_XMMorMEM); }
void rsqrtss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F3, 0x52, &isXMM_XMMorMEM); }

void sahf() { db(0x9E); }
void sal(Operand op, Reg8 _cl) { opShift(op, _cl, 12); }
void sal(Operand op, int imm) { opShift(op, imm, 12); }
void sal(Reg d, Operand op, Reg8 _cl) { opShift(op, _cl, 12, d); }
void sal(Reg d, Operand op, int imm) { opShift(op, imm, 12, d); }
void sar(Operand op, Reg8 _cl) { opShift(op, _cl, 15); }
void sar(Operand op, int imm) { opShift(op, imm, 15); }
void sar(Reg d, Operand op, Reg8 _cl) { opShift(op, _cl, 15, d); }
void sar(Reg d, Operand op, int imm) { opShift(op, imm, 15, d); }
void sarx(Reg32e r1, Operand op, Reg32e r2) { opRRO(r1, r2, op, T_APX|T_F3|T_0F38, 0xf7); }
void sbb(Operand op, uint32_t imm) { opOI(op, imm, 0x18, 3); }
void sbb(Operand op1, Operand op2) { opRO_MR(op1, op2, 0x18); }
void sbb(Reg d, Operand op, uint32_t imm) { opROI(d, op, imm, T_NONE, 3); }
void sbb(Reg d, Operand op1, Operand op2) { opROO(d, op1, op2, T_NONE, 0x18); }
void scasb() { db(0xAE); }
void scasd() { db(0xAF); }
void scasw() { db(0x66); db(0xAF); }
void serialize() { db(0x0F); db(0x01); db(0xE8); }
void seta(Operand op) { opSetCC(op, 7); }
void setae(Operand op) { opSetCC(op, 3); }
void setb(Operand op) { opSetCC(op, 2); }
void setbe(Operand op) { opSetCC(op, 6); }
void setc(Operand op) { opSetCC(op, 2); }
void sete(Operand op) { opSetCC(op, 4); }
void setg(Operand op) { opSetCC(op, 15); }
void setge(Operand op) { opSetCC(op, 13); }
void setl(Operand op) { opSetCC(op, 12); }
void setle(Operand op) { opSetCC(op, 14); }
void setna(Operand op) { opSetCC(op, 6); }
void setnae(Operand op) { opSetCC(op, 2); }
void setnb(Operand op) { opSetCC(op, 3); }
void setnbe(Operand op) { opSetCC(op, 7); }
void setnc(Operand op) { opSetCC(op, 3); }
void setne(Operand op) { opSetCC(op, 5); }
void setng(Operand op) { opSetCC(op, 14); }
void setnge(Operand op) { opSetCC(op, 12); }
void setnl(Operand op) { opSetCC(op, 13); }
void setnle(Operand op) { opSetCC(op, 15); }
void setno(Operand op) { opSetCC(op, 1); }
void setnp(Operand op) { opSetCC(op, 11); }
void setns(Operand op) { opSetCC(op, 9); }
void setnz(Operand op) { opSetCC(op, 5); }
void seto(Operand op) { opSetCC(op, 0); }
void setp(Operand op) { opSetCC(op, 10); }
void setpe(Operand op) { opSetCC(op, 10); }
void setpo(Operand op) { opSetCC(op, 11); }
void sets(Operand op) { opSetCC(op, 8); }
void setz(Operand op) { opSetCC(op, 4); }
void sfence() { db(0x0F); db(0xAE); db(0xF8); }
void sha1msg1(Xmm x, Operand op) { opSSE_APX(x, op, T_0F38, 0xC9, T_MUST_EVEX, 0xD9); }
void sha1msg2(Xmm x, Operand op) { opSSE_APX(x, op, T_0F38, 0xCA, T_MUST_EVEX, 0xDA); }
void sha1nexte(Xmm x, Operand op) { opSSE_APX(x, op, T_0F38, 0xC8, T_MUST_EVEX, 0xD8); }
void sha1rnds4(Xmm x, Operand op, uint8_t imm) { opSSE_APX(x, op, T_0F3A, 0xCC, T_MUST_EVEX, 0xD4, imm); }
void sha256msg1(Xmm x, Operand op) { opSSE_APX(x, op, T_0F38, 0xCC, T_MUST_EVEX, 0xDC); }
void sha256msg2(Xmm x, Operand op) { opSSE_APX(x, op, T_0F38, 0xCD, T_MUST_EVEX, 0xDD); }
void sha256rnds2(Xmm x, Operand op) { opSSE_APX(x, op, T_0F38, 0xCB, T_MUST_EVEX, 0xDB); }
void shl(Operand op, Reg8 _cl) { opShift(op, _cl, 12); }
void shl(Operand op, int imm) { opShift(op, imm, 12); }
void shl(Reg d, Operand op, Reg8 _cl) { opShift(op, _cl, 12, d); }
void shl(Reg d, Operand op, int imm) { opShift(op, imm, 12, d); }
void shld(Operand op, Reg reg, Reg8 _cl) { opShxd(Reg(), op, reg, 0, 0xA4, 0x24, _cl); }
void shld(Operand op, Reg reg, uint8_t imm) { opShxd(Reg(), op, reg, imm, 0xA4, 0x24); }
void shld(Reg d, Operand op, Reg reg, Reg8 _cl) { opShxd(d, op, reg, 0, 0xA4, 0x24, _cl); }
void shld(Reg d, Operand op, Reg reg, uint8_t imm) { opShxd(d, op, reg, imm, 0xA4, 0x24); }
void shlx(Reg32e r1, Operand op, Reg32e r2) { opRRO(r1, r2, op, T_APX|T_66|T_0F38, 0xf7); }
void shr(Operand op, Reg8 _cl) { opShift(op, _cl, 13); }
void shr(Operand op, int imm) { opShift(op, imm, 13); }
void shr(Reg d, Operand op, Reg8 _cl) { opShift(op, _cl, 13, d); }
void shr(Reg d, Operand op, int imm) { opShift(op, imm, 13, d); }
void shrd(Operand op, Reg reg, Reg8 _cl) { opShxd(Reg(), op, reg, 0, 0xAC, 0x2C, _cl); }
void shrd(Operand op, Reg reg, uint8_t imm) { opShxd(Reg(), op, reg, imm, 0xAC, 0x2C); }
void shrd(Reg d, Operand op, Reg reg, Reg8 _cl) { opShxd(d, op, reg, 0, 0xAC, 0x2C, _cl); }
void shrd(Reg d, Operand op, Reg reg, uint8_t imm) { opShxd(d, op, reg, imm, 0xAC, 0x2C); }
void shrx(Reg32e r1, Operand op, Reg32e r2) { opRRO(r1, r2, op, T_APX|T_F2|T_0F38, 0xf7); }
void shufpd(Xmm xmm, Operand op, uint8_t imm8) { opSSE(xmm, op, T_0F | T_66, 0xC6, &isXMM_XMMorMEM, imm8); }
void shufps(Xmm xmm, Operand op, uint8_t imm8) { opSSE(xmm, op, T_0F, 0xC6, &isXMM_XMMorMEM, imm8); }
void sqrtpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x51, &isXMM_XMMorMEM); }
void sqrtps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x51, &isXMM_XMMorMEM); }
void sqrtsd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F2, 0x51, &isXMM_XMMorMEM); }
void sqrtss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F3, 0x51, &isXMM_XMMorMEM); }
void stac() { db(0x0F); db(0x01); db(0xCB); }
void stc() { db(0xF9); }
void std() { db(0xFD); }
void sti() { db(0xFB); }
void stmxcsr(Address addr) { opMR(addr, Reg32(3), T_0F, 0xAE); }
void stosb() { db(0xAA); }
void stosd() { db(0xAB); }
void stosw() { db(0x66); db(0xAB); }
void sub(Operand op, uint32_t imm) { opOI(op, imm, 0x28, 5); }
void sub(Operand op1, Operand op2) { opRO_MR(op1, op2, 0x28); }
void sub(Reg d, Operand op, uint32_t imm) { opROI(d, op, imm, T_NF|T_CODE1_IF1, 5); }
void sub(Reg d, Operand op1, Operand op2) { opROO(d, op1, op2, T_NF|T_CODE1_IF1, 0x28); }
void subpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x5C, &isXMM_XMMorMEM); }
void subps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x5C, &isXMM_XMMorMEM); }
void subsd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F2, 0x5C, &isXMM_XMMorMEM); }
void subss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_F3, 0x5C, &isXMM_XMMorMEM); }
void sysenter() { db(0x0F); db(0x34); }
void sysexit() { db(0x0F); db(0x35); }

void tpause(Reg32 r)
{
    int idx = r.getIdx();
    if (idx > 7) mixin(XBYAK_THROW(ERR.BAD_PARAMETER));
    db(0x66); db(0x0F); db(0xAE);
    setModRM(3, 6, idx);
}
void tzcnt(Reg reg, Operand op)
{
    if (opROO(Reg(), op, reg, T_APX|T_NF, 0xF4)) return;
    opCnt(reg, op, 0xBC);
}

void ucomisd(Xmm xmm, Operand op) { opSSE(xmm, op, T_66|T_0F, 0x2E, &isXMM_XMMorMEM); }
void ucomiss(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x2E, &isXMM_XMMorMEM); }
void ud2() { db(0x0F); db(0x0B); }
void umonitor(Reg r)
{
    int idx = r.getIdx();
    if (idx > 7) mixin(XBYAK_THROW(ERR.BAD_PARAMETER));
    int bit = r.getBit();
    if (BIT != bit)
    {
        if ((BIT == 32 && bit == 16) || (BIT == 64 && bit == 32))
        {
            db(0x67);
        }
        else
        {
            mixin(XBYAK_THROW(ERR.BAD_SIZE_OF_REGISTER));
        }
    }
    db(0xF3); db(0x0F); db(0xAE);
    setModRM(3, 6, idx);
}
void umwait(Reg32 r)
{
    int idx = r.getIdx();
    if (idx > 7) mixin(XBYAK_THROW(ERR.BAD_PARAMETER));
    db(0xF2); db(0x0F); db(0xAE);
    setModRM(3, 6, idx);
}
void unpckhpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x15, &isXMM_XMMorMEM); }
void unpckhps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x15, &isXMM_XMMorMEM); }
void unpcklpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x14, &isXMM_XMMorMEM); }
void unpcklps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x14, &isXMM_XMMorMEM); }

void vaddpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x58); }
void vaddps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x58); }
void vaddsd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_ER_X | T_N8, 0x58); }
void vaddss(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_ER_X | T_N4, 0x58); }
void vaddsubpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66|T_0F|T_YMM, 0xD0); }
void vaddsubps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_F2|T_0F|T_YMM, 0xD0); }
void vaesdec(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66|T_0F38|T_YMM|T_EVEX, 0xDE); }
void vaesdeclast(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66|T_0F38|T_YMM|T_EVEX, 0xDF); }
void vaesenc(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66|T_0F38|T_YMM|T_EVEX, 0xDC); }
void vaesenclast(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66|T_0F38|T_YMM|T_EVEX, 0xDD); }
void vaesimc(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F38|T_W0, 0xDB); }
void vaeskeygenassist(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_66|T_0F3A, 0xDF, imm); }
void vandnpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x55); }
void vandnps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x55); }
void vandpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x54); }
void vandps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x54); }
void vbcstnebf162ps(Xmm x, Address addr) { opVex(x, null, addr, T_F3|T_0F38|T_W0|T_YMM|T_B16, 0xB1); }
void vbcstnesh2ps(Xmm x, Address addr) { opVex(x, null, addr, T_66|T_0F38|T_W0|T_YMM|T_B16, 0xB1); }
void vblendpd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W0|T_YMM, 0x0D, imm); }
void vblendps(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W0|T_YMM, 0x0C, imm); }
void vblendvpd(Xmm x1, Xmm x2, Operand op, Xmm x4) { opAVX_X_X_XM(x1, x2, op, T_0F3A | T_66 | T_YMM, 0x4B, x4.getIdx() << 4); }
void vblendvps(Xmm x1, Xmm x2, Operand op, Xmm x4) { opAVX_X_X_XM(x1, x2, op, T_0F3A | T_66 | T_YMM, 0x4A, x4.getIdx() << 4); }
void vbroadcastf128(Ymm y, Address addr) { opAVX_X_XM_IMM(y, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x1A); }
void vbroadcasti128(Ymm y, Address addr) { opAVX_X_XM_IMM(y, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x5A); }
void vbroadcastsd(Ymm y, Operand op)
{
    if (!op.isMEM() && !(y.isYMM() && op.isXMM()) && !(y.isZMM() && op.isXMM()))
    {
        mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    }
    opAVX_X_XM_IMM(y, op, T_0F38 | T_66 | T_W0 | T_YMM | T_EVEX | T_EW1 | T_N8, 0x19);
}
void vbroadcastss(Xmm x, Operand op)
{
    if (!(op.isXMM() || op.isMEM()))
    {
        mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    }
    opAVX_X_XM_IMM(x, op, T_N4|T_66|T_0F38|T_W0|T_YMM|T_EVEX, 0x18);
}
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
void vcmppd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0xC2, imm); }
void vcmpps(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_0F|T_YMM, 0xC2, imm); }
void vcmpsd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_F2|T_0F, 0xC2, imm); }
void vcmpss(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_F3|T_0F, 0xC2, imm); }
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
void vcomisd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8|T_66|T_0F|T_EW1|T_EVEX|T_SAE_X, 0x2F); }
void vcomiss(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4|T_0F|T_EW0|T_EVEX|T_SAE_X, 0x2F); }
void vcvtdq2pd(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_0F | T_F3 | T_YMM | T_EVEX | T_EW0 | T_B32 | T_N8 | T_N_VL, 0xE6); }
void vcvtdq2ps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0x5B); }
void vcvtneebf162ps(Xmm x, Address addr) { opVex(x, null, addr, T_F3|T_0F38|T_W0|T_YMM, 0xB0); }
void vcvtneeph2ps(Xmm x, Address addr) { opVex(x, null, addr, T_66|T_0F38|T_W0|T_YMM, 0xB0); }
void vcvtneobf162ps(Xmm x, Address addr) { opVex(x, null, addr, T_F2|T_0F38|T_W0|T_YMM, 0xB0); }
void vcvtneoph2ps(Xmm x, Address addr) { opVex(x, null, addr, T_0F38|T_W0|T_YMM, 0xB0); }
void vcvtneps2bf16(Xmm x, Operand op, PreferredEncoding encoding = DefaultEncoding) { opCvt2(x, op, T_F3|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_B32|orEvexIf(encoding, 0, T_MUST_EVEX, 0), 0x72); }
void vcvtpd2dq(Xmm x, Operand op) { opCvt2(x, op, T_0F | T_F2 | T_YMM | T_EVEX | T_EW1 | T_B64 | T_ER_Z, 0xE6); }
void vcvtpd2ps(Xmm x, Operand op) { opCvt2(x, op, T_0F | T_66 | T_YMM | T_EVEX | T_EW1 | T_B64 | T_ER_Z, 0x5A); }
void vcvtph2ps(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_0F38 | T_66 | T_W0 | T_EVEX | T_EW0 | T_N8 | T_N_VL | T_SAE_Y, 0x13); }
void vcvtps2dq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0x5B); }
void vcvtps2pd(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_0F | T_YMM | T_EVEX | T_EW0 | T_B32 | T_N8 | T_N_VL | T_SAE_Y, 0x5A); }
void vcvtps2ph(Operand op, Xmm x, uint8_t imm) { checkCvt1(x, op); opVex(x, null, op, T_0F3A | T_66 | T_W0 | T_EVEX | T_EW0 | T_N8 | T_N_VL | T_SAE_Y | T_M_K, 0x1D, imm); }
void vcvtsd2si(Reg32 r, Operand op) { opAVX_X_X_XM(Xmm(r.getIdx()), xm0, op, T_0F | T_F2 | T_W0 | T_EVEX | T_EW0 | T_N4 | T_ER_X, 0x2D); }
void vcvtsd2ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_F2|T_0F|T_EW1|T_EVEX|T_ER_X, 0x5A); }
void vcvtsi2sd(Xmm x1, Xmm x2, Operand op) { opCvt3(x1, x2, op, T_0F | T_F2 | T_EVEX, T_W1 | T_EW1 | T_ER_X | T_N8, T_W0 | T_EW0 | T_N4, 0x2A); }
void vcvtsi2ss(Xmm x1, Xmm x2, Operand op) { opCvt3(x1, x2, op, T_0F | T_F3 | T_EVEX | T_ER_X, T_W1 | T_EW1 | T_N8, T_W0 | T_EW0 | T_N4, 0x2A); }
void vcvtss2sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_F3|T_0F|T_EW0|T_EVEX|T_SAE_X, 0x5A); }
void vcvtss2si(Reg32 r, Operand op) { opAVX_X_X_XM(Xmm(r.getIdx()), xm0, op, T_0F | T_F3 | T_W0 | T_EVEX | T_EW0 | T_ER_X | T_N8, 0x2D); }
void vcvttpd2dq(Xmm x, Operand op) { opCvt2(x, op, T_66 | T_0F | T_YMM | T_EVEX |T_EW1 | T_B64 | T_SAE_Z, 0xE6); }
void vcvttps2dq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_F3|T_0F|T_EW0|T_YMM|T_EVEX|T_SAE_Z|T_B32, 0x5B); }
void vcvttsd2si(Reg32 r, Operand op) { opAVX_X_X_XM(Xmm(r.getIdx()), xm0, op, T_0F | T_F2 | T_W0 | T_EVEX | T_EW0 | T_N4 | T_SAE_X, 0x2C); }
void vcvttss2si(Reg32 r, Operand op) { opAVX_X_X_XM(Xmm(r.getIdx()), xm0, op, T_0F | T_F3 | T_W0 | T_EVEX | T_EW0 | T_SAE_X | T_N8, 0x2C); }
void vdivpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x5E); }
void vdivps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x5E); }
void vdivsd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_ER_X | T_N8, 0x5E); }
void vdivss(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_ER_X | T_N4, 0x5E); }
void vdppd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W0, 0x41, imm); }
void vdpps(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W0|T_YMM, 0x40, imm); }
void vextractf128(Operand op, Ymm y, uint8_t imm)
{
    if (!(op.isXMEM() && y.isYMM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    opVex(y, null, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x19, imm);
}
void vextracti128(Operand op, Ymm y, uint8_t imm)
{
    if (!(op.isXMEM() && y.isYMM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    opVex(y, null, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x39, imm);
}
void vextractps(Operand op, Xmm x, uint8_t imm)
{
    if (!((op.isREG(32) || op.isMEM()) && x.isXMM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    opVex(x, null, op, T_0F3A | T_66 | T_W0 | T_EVEX | T_N4, 0x17, imm);
}
void vfmadd132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0x98); }
void vfmadd132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0x98); }
void vfmadd132sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0x99); }
void vfmadd132ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0x99); }
void vfmadd213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xA8); }
void vfmadd213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xA8); }
void vfmadd213sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0xA9); }
void vfmadd213ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0xA9); }
void vfmadd231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xB8); }
void vfmadd231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xB8); }
void vfmadd231sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0xB9); }
void vfmadd231ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0xB9); }
void vfmaddsub132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0x96); }
void vfmaddsub132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0x96); }
void vfmaddsub213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xA6); }
void vfmaddsub213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xA6); }
void vfmaddsub231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xB6); }
void vfmaddsub231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xB6); }
void vfmsub132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0x9A); }
void vfmsub132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0x9A); }
void vfmsub132sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0x9B); }
void vfmsub132ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0x9B); }
void vfmsub213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xAA); }
void vfmsub213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xAA); }
void vfmsub213sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0xAB); }
void vfmsub213ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0xAB); }
void vfmsub231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xBA); }
void vfmsub231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xBA); }
void vfmsub231sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0xBB); }
void vfmsub231ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0xBB); }
void vfmsubadd132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0x97); }
void vfmsubadd132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0x97); }
void vfmsubadd213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xA7); }
void vfmsubadd213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xA7); }
void vfmsubadd231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xB7); }
void vfmsubadd231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xB7); }
void vfnmadd132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0x9C); }
void vfnmadd132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0x9C); }
void vfnmadd132sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0x9D); }
void vfnmadd132ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0x9D); }
void vfnmadd213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xAC); }
void vfnmadd213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xAC); }
void vfnmadd213sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0xAD); }
void vfnmadd213ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0xAD); }
void vfnmadd231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xBC); }
void vfnmadd231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xBC); }
void vfnmadd231sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0xBD); }
void vfnmadd231ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0xBD); }
void vfnmsub132pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0x9E); }
void vfnmsub132ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0x9E); }
void vfnmsub132sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0x9F); }
void vfnmsub132ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0x9F); }
void vfnmsub213pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xAE); }
void vfnmsub213ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xAE); }
void vfnmsub213sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0xAF); }
void vfnmsub213ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0xAF); }
void vfnmsub231pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0xBE); }
void vfnmsub231ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0xBE); }
void vfnmsub231sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_W1|T_EW1|T_EVEX|T_ER_X, 0xBF); }
void vfnmsub231ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_W0|T_EW0|T_EVEX|T_ER_X, 0xBF); }
void vgatherdpd(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W1, 0x92, 0); }
void vgatherdps(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W0, 0x92, 1); }
void vgatherqpd(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W1, 0x93, 1); }
void vgatherqps(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W0, 0x93, 2); }
void vgf2p8affineinvqb(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W1|T_EW1|T_YMM|T_EVEX|T_SAE_Z|T_B64, 0xCF, imm); }
void vgf2p8affineqb(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W1|T_EW1|T_YMM|T_EVEX|T_SAE_Z|T_B64, 0xCE, imm); }
void vgf2p8mulb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_SAE_Z, 0xCF); }
void vhaddpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66|T_0F|T_YMM, 0x7C); }
void vhaddps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_F2|T_0F|T_YMM, 0x7C); }
void vhsubpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_66|T_0F|T_YMM, 0x7D); }
void vhsubps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_F2|T_0F|T_YMM, 0x7D); }
void vinsertf128(Ymm y1, Ymm y2, Operand op, uint8_t imm)
{
    if (!(y1.isYMM() && y2.isYMM() && op.isXMEM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    opVex(y1, y2, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x18, imm);
}
void vinserti128(Ymm y1, Ymm y2, Operand op, uint8_t imm)
{
    if (!(y1.isYMM() && y2.isYMM() && op.isXMEM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    opVex(y1, y2, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x38, imm);
}
void vinsertps(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F3A|T_W0|T_EW0|T_EVEX, 0x21, imm); }
void vlddqu(Xmm x, Address addr) { opAVX_X_X_XM(x, cvtIdx0(x), addr, T_0F | T_F2 | T_W0 | T_YMM, 0xF0); }
void vldmxcsr(Address addr) { opAVX_X_X_XM(xm2, xm0, addr, T_0F, 0xAE); }
void vmaskmovdqu(Xmm x1, Xmm x2) { opAVX_X_X_XM(x1, xm0, x2, T_0F | T_66, 0xF7); }
void vmaskmovpd(Address addr, Xmm x1, Xmm x2) { opAVX_X_X_XM(x2, x1, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x2F); }
void vmaskmovpd(Xmm x1, Xmm x2, Address addr) { opAVX_X_X_XM(x1, x2, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x2D); }
void vmaskmovps(Address addr, Xmm x1, Xmm x2) { opAVX_X_X_XM(x2, x1, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x2E); }
void vmaskmovps(Xmm x1, Xmm x2, Address addr) { opAVX_X_X_XM(x1, x2, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x2C); }
void vmaxpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_SAE_Z | T_B64, 0x5F); }
void vmaxps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_SAE_Z | T_B32, 0x5F); }
void vmaxsd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_SAE_X | T_N8, 0x5F); }
void vmaxss(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_SAE_X | T_N4, 0x5F); }
void vminpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_SAE_Z | T_B64, 0x5D); }
void vminps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_SAE_Z | T_B32, 0x5D); }
void vminsd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_SAE_X | T_N8, 0x5D); }
void vminss(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_SAE_X | T_N4, 0x5D); }
void vmovapd(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_M_K, 0x29); }
void vmovapd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX, 0x28); }
void vmovaps(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_0F|T_EW0|T_YMM|T_EVEX|T_M_K, 0x29); }
void vmovaps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F|T_EW0|T_YMM|T_EVEX, 0x28); }
void vmovddup(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_DUP|T_F2|T_0F|T_EW1|T_YMM|T_EVEX|T_ER_X|T_ER_Y|T_ER_Z, 0x12); }
void vmovdqa(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_66|T_0F|T_YMM, 0x7F); }
void vmovdqa(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F|T_YMM, 0x6F); }
void vmovdqu(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_F3|T_0F|T_YMM, 0x7F); }
void vmovdqu(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_F3|T_0F|T_YMM, 0x6F); }
void vmovhlps(Xmm x1, Xmm x2, Operand op = Operand())
{
    if (!op.isNone() && !op.isXMM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    opAVX_X_X_XM(x1, x2, op, T_0F | T_EVEX | T_EW0, 0x12);
}
void vmovhpd(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_N8|T_66|T_0F|T_EW1|T_EVEX, 0x17); }
void vmovhpd(Xmm x, Operand op1, Operand op2 = Operand())
{
    if (!op2.isNone() && !op2.isMEM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    opAVX_X_X_XM(x, op1, op2, T_N8|T_66|T_0F|T_EW1|T_EVEX, 0x16);
}
void vmovhps(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_N8|T_0F|T_EW0|T_EVEX, 0x17); }
void vmovhps(Xmm x, Operand op1, Operand op2 = Operand())
{
    if (!op2.isNone() && !op2.isMEM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));
    opAVX_X_X_XM(x, op1, op2, T_N8|T_0F|T_EW0|T_EVEX, 0x16);
}
void vmovlhps(Xmm x1, Xmm x2, Operand op = Operand()) { if (!op.isNone() && !op.isXMM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_X_XM(x1, x2, op, T_0F | T_EVEX | T_EW0, 0x16); }
void vmovlpd(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_N8|T_66|T_0F|T_EW1|T_EVEX, 0x13); }
void vmovlpd(Xmm x, Operand op1, Operand op2 = Operand()) { if (!op2.isNone() && !op2.isMEM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_X_XM(x, op1, op2, T_N8|T_66|T_0F|T_EW1|T_EVEX, 0x12); }
void vmovlps(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_N8|T_0F|T_EW0|T_EVEX, 0x13); }
void vmovlps(Xmm x, Operand op1, Operand op2 = Operand()) { if (!op2.isNone() && !op2.isMEM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_X_XM(x, op1, op2, T_N8|T_0F|T_EW0|T_EVEX, 0x12); }
void vmovmskpd(Reg r, Xmm x) { if (!r.isBit(i32e)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_X_XM(x.isXMM() ? Xmm(r.getIdx()) : Ymm(r.getIdx()), cvtIdx0(x), x, T_0F | T_66 | T_W0 | T_YMM, 0x50); }
void vmovmskps(Reg r, Xmm x) { if (!r.isBit(i32e)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_X_XM(x.isXMM() ? Xmm(r.getIdx()) : Ymm(r.getIdx()), cvtIdx0(x), x, T_0F | T_W0 | T_YMM, 0x50); }
void vmovntdq(Address addr, Xmm x) { opVex(x, null, addr, T_0F | T_66 | T_YMM | T_EVEX | T_EW0, 0xE7); }
void vmovntdqa(Xmm x, Address addr) { opVex(x, null, addr, T_0F38 | T_66 | T_YMM | T_EVEX | T_EW0, 0x2A); }
void vmovntpd(Address addr, Xmm x) { opVex(x, null, addr, T_0F | T_66 | T_YMM | T_EVEX | T_EW1, 0x2B); }
void vmovntps(Address addr, Xmm x) { opVex(x, null, addr, T_0F | T_YMM | T_EVEX | T_EW0, 0x2B); }
void vmovq(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_0F | T_66 | T_EVEX | T_EW1 | T_N8, x.getIdx() < 16 ? 0xD6 : 0x7E); }
void vmovq(Xmm x, Address addr) { uint64_t type; uint8_t code; if (x.getIdx() < 16) { type = T_0F | T_F3; code = 0x7E; } else { type = T_0F | T_66 | T_EVEX | T_EW1 | T_N8; code = 0x6E; } opAVX_X_X_XM(x, xm0, addr, type, code); }
void vmovq(Xmm x1, Xmm x2) { opAVX_X_X_XM(x1, xm0, x2, T_0F | T_F3 | T_EVEX | T_EW1 | T_N8, 0x7E); }
void vmovsd(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_N8|T_F2|T_0F|T_EW1|T_EVEX | T_M_K, 0x11); }
void vmovsd(Xmm x, Address addr) { opAVX_X_X_XM(x, xm0, addr, T_N8|T_F2|T_0F|T_EW1|T_EVEX, 0x10); }
void vmovsd(Xmm x1, Xmm x2, Operand op = Operand()) { if (!op.isNone() && !op.isXMM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_X_XM(x1, x2, op, T_N8|T_F2|T_0F|T_EW1|T_EVEX, 0x10); }
void vmovshdup(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_F3|T_0F|T_EW0|T_YMM|T_EVEX, 0x16); }
void vmovsldup(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_F3|T_0F|T_EW0|T_YMM|T_EVEX, 0x12); }
void vmovss(Address addr, Xmm x) { opAVX_X_X_XM(x, xm0, addr, T_N4|T_F3|T_0F|T_EW0|T_EVEX | T_M_K, 0x11); }
void vmovss(Xmm x, Address addr) { opAVX_X_X_XM(x, xm0, addr, T_N4|T_F3|T_0F|T_EW0|T_EVEX, 0x10); }
void vmovss(Xmm x1, Xmm x2, Operand op = Operand()) { if (!op.isNone() && !op.isXMM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_X_XM(x1, x2, op, T_N4|T_F3|T_0F|T_EW0|T_EVEX, 0x10); }
void vmovupd(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_M_K, 0x11); }
void vmovupd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX, 0x10); }
void vmovups(Address addr, Xmm xmm) { opAVX_X_XM_IMM(xmm, addr, T_0F|T_EW0|T_YMM|T_EVEX|T_M_K, 0x11); }
void vmovups(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F|T_EW0|T_YMM|T_EVEX, 0x10); }
void vmulpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x59); }
void vmulps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x59); }
void vmulsd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_ER_X | T_N8, 0x59); }
void vmulss(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_ER_X | T_N4, 0x59); }
void vorpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x56); }
void vorps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x56); }
void vpabsb(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F38|T_YMM|T_EVEX, 0x1C); }
void vpabsd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F38|T_EW0|T_YMM|T_EVEX|T_B32, 0x1E); }
void vpabsw(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F38|T_YMM|T_EVEX, 0x1D); }
void vpackssdw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW0|T_YMM|T_EVEX|T_B32, 0x6B); }
void vpacksswb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0x63); }
void vpackusdw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_EVEX|T_B32, 0x2B); }
void vpackuswb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0x67); }
void vpaddb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xFC); }
void vpaddd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW0|T_YMM|T_EVEX|T_B32, 0xFE); }
void vpaddq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_B64, 0xD4); }
void vpaddsb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xEC); }
void vpaddsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xED); }
void vpaddusb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xDC); }
void vpaddusw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xDD); }
void vpaddw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xFD); }
void vpalignr(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_YMM|T_EVEX, 0x0F, imm); }
void vpand(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0xDB); }
void vpandn(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0xDF); }
void vpavgb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xE0); }
void vpavgw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xE3); }
void vpblendd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W0|T_YMM, 0x02, imm); }
void vpblendvb(Xmm x1, Xmm x2, Operand op, Xmm x4) { opAVX_X_X_XM(x1, x2, op, T_0F3A | T_66 | T_YMM, 0x4C, x4.getIdx() << 4); }
void vpblendw(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W0|T_YMM, 0x0E, imm); }
void vpbroadcastb(Xmm x, Operand op) { if (!(op.isXMM() || op.isMEM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_XM_IMM(x, op, T_N1|T_66|T_0F38|T_W0|T_YMM|T_EVEX, 0x78); }
void vpbroadcastd(Xmm x, Operand op) { if (!(op.isXMM() || op.isMEM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_XM_IMM(x, op, T_N4|T_66|T_0F38|T_W0|T_YMM|T_EVEX, 0x58); }
void vpbroadcastq(Xmm x, Operand op) { if (!(op.isXMM() || op.isMEM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_XM_IMM(x, op, T_N8|T_66|T_0F38|T_W0|T_EW1|T_YMM|T_EVEX, 0x59); }
void vpbroadcastw(Xmm x, Operand op) { if (!(op.isXMM() || op.isMEM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opAVX_X_XM_IMM(x, op, T_N2|T_66|T_0F38|T_W0|T_YMM|T_EVEX, 0x79); }
void vpclmulhqhqdq(Xmm x1, Xmm x2, Operand op) { vpclmulqdq(x1, x2, op, 0x11); }
void vpclmulhqlqdq(Xmm x1, Xmm x2, Operand op) { vpclmulqdq(x1, x2, op, 0x01); }
void vpclmullqhqdq(Xmm x1, Xmm x2, Operand op) { vpclmulqdq(x1, x2, op, 0x10); }
void vpclmullqlqdq(Xmm x1, Xmm x2, Operand op) { vpclmulqdq(x1, x2, op, 0x00); }
void vpclmulqdq(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W0|T_YMM|T_EVEX, 0x44, imm); }
void vpcmpeqb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0x74); }
void vpcmpeqd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0x76); }
void vpcmpeqq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x29); }
void vpcmpeqw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0x75); }
void vpcmpestri(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_66|T_0F3A, 0x61, imm); }
void vpcmpestrm(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_66|T_0F3A, 0x60, imm); }
void vpcmpgtb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0x64); }
void vpcmpgtd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0x66); }
void vpcmpgtq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x37); }
void vpcmpgtw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0x65); }
void vpcmpistri(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_66|T_0F3A, 0x63, imm); }
void vpcmpistrm(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_66|T_0F3A, 0x62, imm); }
void vpdpbusd(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_B32, 0x50, encoding); }
void vpdpbusds(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_B32, 0x51, encoding); }
void vpdpwssd(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_B32, 0x52, encoding); }
void vpdpwssds(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_B32, 0x53, encoding); }
void vperm2f128(Ymm y1, Ymm y2, Operand op, uint8_t imm) { if (!(y1.isYMM() && y2.isYMM() && op.isYMEM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opVex(y1, y2, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x06, imm); }
void vperm2i128(Ymm y1, Ymm y2, Operand op, uint8_t imm) { if (!(y1.isYMM() && y2.isYMM() && op.isYMEM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opVex(y1, y2, op, T_0F3A | T_66 | T_W0 | T_YMM, 0x46, imm); }
void vpermd(Ymm y1, Ymm y2, Operand op) { opAVX_X_X_XM(y1, y2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_B32, 0x36); }
void vpermilpd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW1|T_YMM|T_EVEX|T_B64, 0x0D); }
void vpermilpd(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_66|T_0F3A|T_EW1|T_YMM|T_EVEX|T_B64, 0x05, imm); }
void vpermilps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_B32, 0x0C); }
void vpermilps(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_66|T_0F3A|T_EW0|T_YMM|T_EVEX|T_B32, 0x04, imm); }
void vpermpd(Ymm y, Operand op, uint8_t imm) { opAVX_X_XM_IMM(y, op, T_66|T_0F3A|T_W1|T_EW1|T_YMM|T_EVEX|T_B64, 0x01, imm); }
void vpermpd(Ymm y1, Ymm y2, Operand op) { opAVX_X_X_XM(y1, y2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x16); }
void vpermps(Ymm y1, Ymm y2, Operand op) { opAVX_X_X_XM(y1, y2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_B32, 0x16); }
void vpermq(Ymm y, Operand op, uint8_t imm) { opAVX_X_XM_IMM(y, op, T_66|T_0F3A|T_W1|T_EW1|T_YMM|T_EVEX|T_B64, 0x00, imm); }
void vpermq(Ymm y1, Ymm y2, Operand op) { opAVX_X_X_XM(y1, y2, op, T_66|T_0F38|T_W0|T_EW1|T_YMM|T_EVEX|T_B64, 0x36); }
void vpextrb(Operand op, Xmm x, uint8_t imm) { if (!((op.isREG(8|16|i32e) || op.isMEM()) && x.isXMM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opVex(x, null, op, T_0F3A | T_66 | T_EVEX | T_N1, 0x14, imm); }
void vpextrd(Operand op, Xmm x, uint8_t imm) { if (!((op.isREG(32) || op.isMEM()) && x.isXMM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opVex(x, null, op, T_0F3A | T_66 | T_W0 | T_EVEX | T_EW0 | T_N4, 0x16, imm); }
void vpextrq(Operand op, Xmm x, uint8_t imm) { if (!((op.isREG(64) || op.isMEM()) && x.isXMM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opVex(x, null, op, T_0F3A | T_66 | T_W1 | T_EVEX | T_EW1 | T_N8, 0x16, imm); }
void vpextrw(Operand op, Xmm x, uint8_t imm) { if (!((op.isREG(16|i32e) || op.isMEM()) && x.isXMM())) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); if (op.isREG() && x.getIdx() < 16) { opAVX_X_X_XM(Xmm(op.getIdx()), xm0, x, T_0F | T_66, 0xC5, imm); } else { opVex(x, null, op, T_0F3A | T_66 | T_EVEX | T_N2, 0x15, imm); } }
void vpgatherdd(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W0, 0x90, 1); }
void vpgatherdq(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W1, 0x90, 0); }
void vpgatherqd(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W0, 0x91, 2); }
void vpgatherqq(Xmm x1, Address addr, Xmm x2) { opGather(x1, addr, x2, T_0F38 | T_66 | T_YMM | T_VSIB | T_W1, 0x91, 1); }
void vphaddd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x02); }
void vphaddsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x03); }
void vphaddw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x01); }
void vphminposuw(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F38, 0x41); }
void vphsubd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x06); }
void vphsubsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x07); }
void vphsubw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x05); }
void vpinsrb(Xmm x1, Xmm x2, Operand op, uint8_t imm) { if (!(x1.isXMM() && x2.isXMM() && (op.isREG(32) || op.isMEM()))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opVex(x1, x2, op, T_0F3A | T_66 | T_EVEX | T_N1, 0x20, imm); }
void vpinsrd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { if (!(x1.isXMM() && x2.isXMM() && (op.isREG(32) || op.isMEM()))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opVex(x1, x2, op, T_0F3A | T_66 | T_W0 | T_EVEX | T_EW0 | T_N4, 0x22, imm); }
void vpinsrq(Xmm x1, Xmm x2, Operand op, uint8_t imm) { if (!(x1.isXMM() && x2.isXMM() && (op.isREG(64) || op.isMEM()))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opVex(x1, x2, op, T_0F3A | T_66 | T_W1 | T_EVEX | T_EW1 | T_N8, 0x22, imm); }
void vpinsrw(Xmm x1, Xmm x2, Operand op, uint8_t imm) { if (!(x1.isXMM() && x2.isXMM() && (op.isREG(32) || op.isMEM()))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opVex(x1, x2, op, T_0F | T_66 | T_EVEX | T_N2, 0xC4, imm); }
void vpmaddubsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM|T_EVEX, 0x04); }
void vpmaddwd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xF5); }
void vpmaskmovd(Address addr, Xmm x1, Xmm x2) { opAVX_X_X_XM(x2, x1, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x8E); }
void vpmaskmovd(Xmm x1, Xmm x2, Address addr) { opAVX_X_X_XM(x1, x2, addr, T_0F38 | T_66 | T_W0 | T_YMM, 0x8C); }
void vpmaskmovq(Address addr, Xmm x1, Xmm x2) { opAVX_X_X_XM(x2, x1, addr, T_0F38 | T_66 | T_W1 | T_YMM, 0x8E); }
void vpmaskmovq(Xmm x1, Xmm x2, Address addr) { opAVX_X_X_XM(x1, x2, addr, T_0F38 | T_66 | T_W1 | T_YMM, 0x8C); }
void vpmaxsb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM|T_EVEX, 0x3C); }
void vpmaxsd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_EVEX|T_B32, 0x3D); }
void vpmaxsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xEE); }
void vpmaxub(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xDE); }
void vpmaxud(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_EVEX|T_B32, 0x3F); }
void vpmaxuw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM|T_EVEX, 0x3E); }
void vpminsb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM|T_EVEX, 0x38); }
void vpminsd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_EVEX|T_B32, 0x39); }
void vpminsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xEA); }
void vpminub(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xDA); }
void vpminud(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_EVEX|T_B32, 0x3B); }
void vpminuw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM|T_EVEX, 0x3A); }
void vpmovmskb(Reg32e r, Xmm x) { if (!x.isKind(Kind.XMM | Kind.YMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opVex(x.isYMM() ? Ymm(r.getIdx()) : Xmm(r.getIdx()), null, x, T_0F | T_66 | T_YMM, 0xD7); }
void vpmovsxbd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x21); }
void vpmovsxbq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N2|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x22); }
void vpmovsxbw(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x20); }
void vpmovsxdq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8|T_N_VL|T_66|T_0F38|T_EW0|T_YMM|T_EVEX, 0x25); }
void vpmovsxwd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x23); }
void vpmovsxwq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x24); }
void vpmovzxbd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x31); }
void vpmovzxbq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N2|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x32); }
void vpmovzxbw(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x30); }
void vpmovzxdq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8|T_N_VL|T_66|T_0F38|T_EW0|T_YMM|T_EVEX, 0x35); }
void vpmovzxwd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x33); }
void vpmovzxwq(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4|T_N_VL|T_66|T_0F38|T_YMM|T_EVEX, 0x34); }
void vpmuldq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_EVEX|T_B64, 0x28); }
void vpmulhrsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM|T_EVEX, 0x0B); }
void vpmulhuw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xE4); }
void vpmulhw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xE5); }
void vpmulld(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_EVEX|T_B32, 0x40); }
void vpmullw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xD5); }
void vpmuludq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_B64, 0xF4); }
void vpor(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0xEB); }
void vpsadbw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xF6); }
void vpshufb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM|T_EVEX, 0x00); }
void vpshufd(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_66|T_0F|T_EW0|T_YMM|T_EVEX|T_B32, 0x70, imm); }
void vpshufhw(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_F3|T_0F|T_YMM|T_EVEX, 0x70, imm); }
void vpshuflw(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_F2|T_0F|T_YMM|T_EVEX, 0x70, imm); }
void vpsignb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x08); }
void vpsignd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x0A); }
void vpsignw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_YMM, 0x09); }
void vpslld(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 6), x, op, T_66|T_0F|T_EW0|T_YMM|T_EVEX|T_B32|T_MEM_EVEX, 0x72, imm); }
void vpslld(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16|T_66|T_0F|T_EW0|T_YMM|T_EVEX, 0xF2); }
void vpslldq(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 7), x, op, T_66|T_0F|T_YMM|T_EVEX|T_MEM_EVEX, 0x73, imm); }
void vpsllq(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 6), x, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_B64|T_MEM_EVEX, 0x73, imm); }
void vpsllq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16|T_66|T_0F|T_EW1|T_YMM|T_EVEX, 0xF3); }
void vpsllvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_B32, 0x47); }
void vpsllvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_B64, 0x47); }
void vpsllw(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 6), x, op, T_66|T_0F|T_YMM|T_EVEX|T_MEM_EVEX, 0x71, imm); }
void vpsllw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16|T_66|T_0F|T_YMM|T_EVEX, 0xF1); }
void vpsrad(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 4), x, op, T_66|T_0F|T_EW0|T_YMM|T_EVEX|T_B32|T_MEM_EVEX, 0x72, imm); }
void vpsrad(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16|T_66|T_0F|T_EW0|T_YMM|T_EVEX, 0xE2); }
void vpsravd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_B32, 0x46); }
void vpsraw(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 4), x, op, T_66|T_0F|T_YMM|T_EVEX|T_MEM_EVEX, 0x71, imm); }
void vpsraw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16|T_66|T_0F|T_YMM|T_EVEX, 0xE1); }
void vpsrld(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 2), x, op, T_66|T_0F|T_EW0|T_YMM|T_EVEX|T_B32|T_MEM_EVEX, 0x72, imm); }
void vpsrld(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16|T_66|T_0F|T_EW0|T_YMM|T_EVEX, 0xD2); }
void vpsrldq(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 3), x, op, T_66|T_0F|T_YMM|T_EVEX|T_MEM_EVEX, 0x73, imm); }
void vpsrlq(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 2), x, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_B64|T_MEM_EVEX, 0x73, imm); }
void vpsrlq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16|T_66|T_0F|T_EW1|T_YMM|T_EVEX, 0xD3); }
void vpsrlvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_YMM|T_EVEX|T_B32, 0x45); }
void vpsrlvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W1|T_EW1|T_YMM|T_EVEX|T_B64, 0x45); }
void vpsrlw(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 2), x, op, T_66|T_0F|T_YMM|T_EVEX|T_MEM_EVEX, 0x71, imm); }
void vpsrlw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16|T_66|T_0F|T_YMM|T_EVEX, 0xD1); }
void vpsubb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xF8); }
void vpsubd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW0|T_YMM|T_EVEX|T_B32, 0xFA); }
void vpsubq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_B64, 0xFB); }
void vpsubsb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xE8); }
void vpsubsw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xE9); }
void vpsubusb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xD8); }
void vpsubusw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xD9); }
void vpsubw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0xF9); }
void vptest(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F38|T_YMM, 0x17); }
void vpunpckhbw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0x68); }
void vpunpckhdq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW0|T_YMM|T_EVEX|T_B32, 0x6A); }
void vpunpckhqdq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_B64, 0x6D); }
void vpunpckhwd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0x69); }
void vpunpcklbw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0x60); }
void vpunpckldq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW0|T_YMM|T_EVEX|T_B32, 0x62); }
void vpunpcklqdq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_B64, 0x6C); }
void vpunpcklwd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM|T_EVEX, 0x61); }
void vpxor(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_YMM, 0xEF); }
void vrcpps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F|T_YMM, 0x53); }
void vrcpss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F3|T_0F, 0x53); }
void vroundpd(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_66|T_0F3A|T_YMM, 0x09, imm); }
void vroundps(Xmm xm, Operand op, uint8_t imm) { opAVX_X_XM_IMM(xm, op, T_66|T_0F3A|T_YMM, 0x08, imm); }
void vroundsd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W0, 0x0B, imm); }
void vroundss(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W0, 0x0A, imm); }
void vrsqrtps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F|T_YMM, 0x52); }
void vrsqrtss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F3|T_0F, 0x52); }
void vsha512msg1(Ymm y, Xmm x) { if (!(y.isYMM() && x.isXMM())) mixin(XBYAK_THROW(ERR.BAD_PARAMETER)); opVex(y, null, x, T_F2 | T_0F38 | T_W0 | T_YMM, 0xCC); }
void vsha512msg2(Ymm y1, Ymm y2) { if (!(y1.isYMM() && y2.isYMM())) mixin(XBYAK_THROW(ERR.BAD_PARAMETER)); opVex(y1, null, y2, T_F2 | T_0F38 | T_W0 | T_YMM, 0xCD); }
void vsha512rnds2(Ymm y1, Ymm y2, Xmm x) { if (!(y1.isYMM() && y2.isYMM() && x.isXMM())) mixin(XBYAK_THROW(ERR.BAD_PARAMETER)); opVex(y1, y2, x, T_F2 | T_0F38 | T_W0 | T_YMM, 0xCB); }
void vshufpd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_B64, 0xC6, imm); }
void vshufps(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_0F|T_EW0|T_YMM|T_EVEX|T_B32, 0xC6, imm); }
void vsm3msg1(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_0F38|T_W0|T_EW0|T_EVEX, 0xDA); }
void vsm3msg2(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_W0|T_EW0|T_EVEX, 0xDA); }
void vsm3rnds2(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_W0|T_EW0|T_EVEX, 0xDE, imm); }
void vsm4key4(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F3|T_0F38|T_W0|T_EW0|T_EVEX, 0xDA); }
void vsm4rnds4(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F2|T_0F38|T_W0|T_EW0|T_EVEX, 0xDA); }
void vsqrtpd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_ER_Z|T_B64, 0x51); }
void vsqrtps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_0F|T_EW0|T_YMM|T_EVEX|T_ER_Z|T_B32, 0x51); }
void vsqrtsd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_F2|T_0F|T_EW1|T_EVEX|T_ER_X, 0x51); }
void vsqrtss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_F3|T_0F|T_EW0|T_EVEX|T_ER_X, 0x51); }
void vstmxcsr(Address addr) { opAVX_X_X_XM(xm3, xm0, addr, T_0F, 0xAE); }
void vsubpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x5C); }
void vsubps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x5C); }
void vsubsd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F2 | T_EW1 | T_EVEX | T_ER_X | T_N8, 0x5C); }
void vsubss(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_F3 | T_EW0 | T_EVEX | T_ER_X | T_N4, 0x5C); }
void vtestpd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F38|T_YMM, 0x0F); }
void vtestps(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_66|T_0F38|T_YMM, 0x0E); }
void vucomisd(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N8|T_66|T_0F|T_EW1|T_EVEX|T_SAE_X, 0x2E); }
void vucomiss(Xmm xm, Operand op) { opAVX_X_XM_IMM(xm, op, T_N4|T_0F|T_EW0|T_EVEX|T_SAE_X, 0x2E); }
void vunpckhpd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_B64, 0x15); }
void vunpckhps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_0F|T_EW0|T_YMM|T_EVEX|T_B32, 0x15); }
void vunpcklpd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_EVEX|T_B64, 0x14); }
void vunpcklps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_0F|T_EW0|T_YMM|T_EVEX|T_B32, 0x14); }
void vxorpd(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_66 | T_EW1 | T_YMM | T_EVEX | T_ER_Z | T_B64, 0x57); }
void vxorps(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_0F | T_EW0 | T_YMM | T_EVEX | T_ER_Z | T_B32, 0x57); }
void vzeroall() { db(0xC5); db(0xFC); db(0x77); }
void vzeroupper() { db(0xC5); db(0xF8); db(0x77); }

void wait() { db(0x9B); }
void wbinvd() { db(0x0F); db(0x09); }
void wrmsr() { db(0x0F); db(0x30); }

void xabort(uint8_t imm) { db(0xC6); db(0xF8); db(imm); }
void xadd(Operand op, Reg reg) { opRO(reg, op, T_0F, 0xC0 | (reg.isBit(8) ? 0 : 1), op.getBit() == reg.getBit()); }
void xbegin(uint32_t rel) { db(0xC7); db(0xF8); dd(rel); }
void xend() { db(0x0F); db(0x01); db(0xD5); }
void xgetbv() { db(0x0F); db(0x01); db(0xD0); }
void xlatb() { db(0xD7); }
void xor_(Operand op, uint32_t imm) { opOI(op, imm, 0x30, 6); }
void xor_(Operand op1, Operand op2) { opRO_MR(op1, op2, 0x30); }
void xor_(Reg d, Operand op, uint32_t imm) { opROI(d, op, imm, T_NF|T_CODE1_IF1, 6); }
void xor_(Reg d, Operand op1, Operand op2) { opROO(d, op1, op2, T_NF|T_CODE1_IF1, 0x30); }
void xorpd(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F | T_66, 0x57, &isXMM_XMMorMEM); }
void xorps(Xmm xmm, Operand op) { opSSE(xmm, op, T_0F, 0x57, &isXMM_XMMorMEM); }
void xresldtrk() { db(0xF2); db(0x0F); db(0x01); db(0xE9); }
void xsusldtrk() { db(0xF2); db(0x0F); db(0x01); db(0xE8); }

  version(XBYAK_ENABLE_OMITTED_OPERAND)
  {
    void vblendpd(Xmm x, Operand op, uint8_t imm) { vblendpd(x, x, op, imm); }
    void vblendps(Xmm x, Operand op, uint8_t imm) { vblendps(x, x, op, imm); }
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
    void vcmppd(Xmm x, Operand op, uint8_t imm) { vcmppd(x, x, op, imm); }
    void vcmpps(Xmm x, Operand op, uint8_t imm) { vcmpps(x, x, op, imm); }
    void vcmpsd(Xmm x, Operand op, uint8_t imm) { vcmpsd(x, x, op, imm); }
    void vcmpss(Xmm x, Operand op, uint8_t imm) { vcmpss(x, x, op, imm); }
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
    void vdppd(Xmm x, Operand op, uint8_t imm) { vdppd(x, x, op, imm); }
    void vdpps(Xmm x, Operand op, uint8_t imm) { vdpps(x, x, op, imm); }
    void vinsertps(Xmm x, Operand op, uint8_t imm) { vinsertps(x, x, op, imm); }
    void vmpsadbw(Xmm x, Operand op, uint8_t imm) { vmpsadbw(x, x, op, imm); }
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
    void vpalignr(Xmm x, Operand op, uint8_t imm) { vpalignr(x, x, op, imm); }
    void vpand(Xmm x, Operand op) { vpand(x, x, op); }
    void vpandn(Xmm x, Operand op) { vpandn(x, x, op); }
    void vpavgb(Xmm x, Operand op) { vpavgb(x, x, op); }
    void vpavgw(Xmm x, Operand op) { vpavgw(x, x, op); }
    void vpblendd(Xmm x, Operand op, uint8_t imm) { vpblendd(x, x, op, imm); }
    void vpblendvb(Xmm x1, Operand op, Xmm x4) { vpblendvb(x1, x1, op, x4); }
    void vpblendw(Xmm x, Operand op, uint8_t imm) { vpblendw(x, x, op, imm); }
    void vpclmulqdq(Xmm x, Operand op, uint8_t imm) { vpclmulqdq(x, x, op, imm); }
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
    void vpinsrb(Xmm x, Operand op, uint8_t imm) { vpinsrb(x, x, op, imm); }
    void vpinsrd(Xmm x, Operand op, uint8_t imm) { vpinsrd(x, x, op, imm); }
    void vpinsrq(Xmm x, Operand op, uint8_t imm) { vpinsrq(x, x, op, imm); }
    void vpinsrw(Xmm x, Operand op, uint8_t imm) { vpinsrw(x, x, op, imm); }
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
    void vpslld(Xmm x, uint8_t imm) { vpslld(x, x, imm); }
    void vpslldq(Xmm x, uint8_t imm) { vpslldq(x, x, imm); }
    void vpsllq(Xmm x, Operand op) { vpsllq(x, x, op); }
    void vpsllq(Xmm x, uint8_t imm) { vpsllq(x, x, imm); }
    void vpsllw(Xmm x, Operand op) { vpsllw(x, x, op); }
    void vpsllw(Xmm x, uint8_t imm) { vpsllw(x, x, imm); }
    void vpsrad(Xmm x, Operand op) { vpsrad(x, x, op); }
    void vpsrad(Xmm x, uint8_t imm) { vpsrad(x, x, imm); }
    void vpsraw(Xmm x, Operand op) { vpsraw(x, x, op); }
    void vpsraw(Xmm x, uint8_t imm) { vpsraw(x, x, imm); }
    void vpsrld(Xmm x, Operand op) { vpsrld(x, x, op); }
    void vpsrld(Xmm x, uint8_t imm) { vpsrld(x, x, imm); }
    void vpsrldq(Xmm x, uint8_t imm) { vpsrldq(x, x, imm); }
    void vpsrlq(Xmm x, Operand op) { vpsrlq(x, x, op); }
    void vpsrlq(Xmm x, uint8_t imm) { vpsrlq(x, x, imm); }
    void vpsrlw(Xmm x, Operand op) { vpsrlw(x, x, op); }
    void vpsrlw(Xmm x, uint8_t imm) { vpsrlw(x, x, imm); }
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
    void vroundsd(Xmm x, Operand op, uint8_t imm) { vroundsd(x, x, op, imm); }
    void vroundss(Xmm x, Operand op, uint8_t imm) { vroundss(x, x, op, imm); }
    void vrsqrtss(Xmm x, Operand op) { vrsqrtss(x, x, op); }
    void vshufpd(Xmm x, Operand op, uint8_t imm) { vshufpd(x, x, op, imm); }
    void vshufps(Xmm x, Operand op, uint8_t imm) { vshufps(x, x, op, imm); }
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
    void jecxz(ref Label label) { db(0x67); opJmp(label, T_SHORT, 0xe3, 0, 0); }
    void jrcxz(string label) { opJmp(label, T_SHORT, 0xe3, 0, 0); }
    void jrcxz(ref Label label) { opJmp(label, T_SHORT, 0xe3, 0, 0); }
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
    void clui() { db(0xF3); db(0x0F); db(0x01); db(0xEE); }
    void stui() { db(0xF3); db(0x0F); db(0x01); db(0xEF); }
    void testui() { db(0xF3); db(0x0F); db(0x01); db(0xED); }
    void uiret() { db(0xF3); db(0x0F); db(0x01); db(0xEC); }
    void cmpxchg16b(Address addr) { opMR(addr, Reg64(1), T_0F, 0xC7); }
    void fxrstor64(Address addr) { opMR(addr, Reg64(1), T_0F, 0xAE); }
    void movq(Reg64 reg, Mmx mmx) { if (mmx.isXMM()) db(0x66); opSSE(mmx, reg, T_0F, 0x7E); }
    void movq(Mmx mmx, Reg64 reg) { if (mmx.isXMM()) db(0x66); opSSE(mmx, reg, T_0F, 0x6E); }
    void movsxd(Reg64 reg, Operand op) { if (!op.isBit(32)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opRO(reg, op, T_ALLOW_DIFF_SIZE, 0x63); }
    void pextrq(Operand op, Xmm xmm, uint8_t imm) { if (!op.isREG(64) && !op.isMEM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opSSE(Reg64(xmm.getIdx()), op, T_66 | T_0F3A, 0x16, null, imm); }
    void pinsrq(Xmm xmm, Operand op, uint8_t imm) { if (!op.isREG(64) && !op.isMEM()) mixin(XBYAK_THROW(ERR.BAD_COMBINATION)); opSSE(Reg64(xmm.getIdx()), op, T_66 | T_0F3A, 0x22, null, imm); }
    void senduipi(Reg64 r) { opRR(Reg32(6), r.cvt32(), T_F3 | T_0F, 0xC7); }
    void vcvtss2si(Reg64 r, Operand op) { opAVX_X_X_XM(Xmm(r.getIdx()), xm0, op, T_0F | T_F3 | T_W1 | T_EVEX | T_EW1 | T_ER_X | T_N8, 0x2D); }
    void vcvttss2si(Reg64 r, Operand op) { opAVX_X_X_XM(Xmm(r.getIdx()), xm0, op, T_0F | T_F3 | T_W1 | T_EVEX | T_EW1 | T_SAE_X | T_N8, 0x2C); }
    void vcvtsd2si(Reg64 r, Operand op) { opAVX_X_X_XM(Xmm(r.getIdx()), xm0, op, T_0F | T_F2 | T_W1 | T_EVEX | T_EW1 | T_N4 | T_ER_X, 0x2D); }
    void vcvttsd2si(Reg64 r, Operand op) { opAVX_X_X_XM(Xmm(r.getIdx()), xm0, op, T_0F | T_F2 | T_W1 | T_EVEX | T_EW1 | T_N4 | T_SAE_X, 0x2C); }
    void vmovq(Xmm x, Reg64 r) { opAVX_X_X_XM(x, xm0, Xmm(r.getIdx()), T_66 | T_0F | T_W1 | T_EVEX | T_EW1, 0x6E); }
    void vmovq(Reg64 r, Xmm x) { opAVX_X_X_XM(x, xm0, Xmm(r.getIdx()), T_66 | T_0F | T_W1 | T_EVEX | T_EW1, 0x7E); }
    void jmpabs(uint64_t addr) { db(0xD5); db(0x00); db(0xA1); dq(addr); }
    void push2(Reg64 r1, Reg64 r2) { opROO(r1, r2, Reg64(6), T_APX|T_ND1|T_W0, 0xFF); }
    void push2p(Reg64 r1, Reg64 r2) { opROO(r1, r2, Reg64(6), T_APX|T_ND1|T_W1, 0xFF); }
    void pop2(Reg64 r1, Reg64 r2) { opROO(r1, r2, Reg64(0), T_APX|T_ND1|T_W0, 0x8F); }
    void pop2p(Reg64 r1, Reg64 r2) { opROO(r1, r2, Reg64(0), T_APX|T_ND1|T_W1, 0x8F); }
    void cmpbexadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xE6); }
    void cmpbxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xE2); }
    void cmplexadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xEE); }
    void cmplxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xEC); }
    void cmpnbexadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xE7); }
    void cmpnbxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xE3); }
    void cmpnlexadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xEF); }
    void cmpnlxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xED); }
    void cmpnoxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xE1); }
    void cmpnpxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xEB); }
    void cmpnsxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xE9); }
    void cmpnzxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xE5); }
    void cmpoxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xE0); }
    void cmppxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xEA); }
    void cmpsxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xE8); }
    void cmpzxadd(Address addr, Reg32e r1, Reg32e r2) { opRRO(r1, r2, addr, T_APX|T_66|T_0F38, 0xE4); }
    void aesdec128kl(Xmm x, Address addr) { opSSE_APX(x, addr, T_F3|T_0F38, 0xDD, T_F3|T_MUST_EVEX, 0xDD); }
    void aesdec256kl(Xmm x, Address addr) { opSSE_APX(x, addr, T_F3|T_0F38, 0xDF, T_F3|T_MUST_EVEX, 0xDF); }
    void aesdecwide128kl(Address addr) { opSSE_APX(xmm1, addr, T_F3|T_0F38, 0xD8, T_F3|T_MUST_EVEX, 0xD8); }
    void aesdecwide256kl(Address addr) { opSSE_APX(xmm3, addr, T_F3|T_0F38, 0xD8, T_F3|T_MUST_EVEX, 0xD8); }
    void aesenc128kl(Xmm x, Address addr) { opSSE_APX(x, addr, T_F3|T_0F38, 0xDC, T_F3|T_MUST_EVEX, 0xDC); }
    void aesenc256kl(Xmm x, Address addr) { opSSE_APX(x, addr, T_F3|T_0F38, 0xDE, T_F3|T_MUST_EVEX, 0xDE); }
    void aesencwide128kl(Address addr) { opSSE_APX(xmm0, addr, T_F3|T_0F38, 0xD8, T_F3|T_MUST_EVEX, 0xD8); }
    void aesencwide256kl(Address addr) { opSSE_APX(xmm2, addr, T_F3|T_0F38, 0xD8, T_F3|T_MUST_EVEX, 0xD8); }
    void encodekey128(Reg32 r1, Reg32 r2) { opEncodeKey(r1, r2, 0xFA, 0xDA); }
    void encodekey256(Reg32 r1, Reg32 r2) { opEncodeKey(r1, r2, 0xFB, 0xDB); }    
    void rdfsbase(Reg32e r) { opRR(eax, r, T_F3|T_0F|T_ALLOW_DIFF_SIZE, 0xAE); }
    void rdgsbase(Reg32e r) { opRR(ecx, r, T_F3|T_0F|T_ALLOW_DIFF_SIZE, 0xAE); }
    void wrfsbase(Reg32e r) { opRR(edx, r, T_F3|T_0F|T_ALLOW_DIFF_SIZE, 0xAE); }
    void wrgsbase(Reg32e r) { opRR(ebx, r, T_F3|T_0F|T_ALLOW_DIFF_SIZE, 0xAE); }
    void ldtilecfg(Address addr) { if (opROO(Reg(), addr, tmm0, T_APX|T_0F38|T_W0, 0x49)) return; opVex(tmm0, tmm0, addr, T_0F38|T_W0, 0x49); }
    void sttilecfg(Address addr) { if (opROO(Reg(), addr, tmm0, T_APX|T_66|T_0F38|T_W0, 0x49)) return; opVex(tmm0, tmm0, addr, T_66|T_0F38 | T_W0, 0x49); }
    void tileloadd(Tmm tm, Address addr) { opAMX(tm, addr, T_F2|T_0F38|T_W0, 0x4B); }
    void tileloaddt1(Tmm tm, Address addr) { opAMX(tm, addr, T_66|T_0F38|T_W0, 0x4B); }
    void tilerelease() { db(0xc4); db(0xe2); db(0x78); db(0x49); db(0xc0); }
    void tilestored(Address addr, Tmm tm) { if (opROO(Reg(), addr, tm, T_APX|T_F3|T_0F38|T_W0, 0x4B)) return; opVex(tm, tmm0, addr, T_F3|T_0F38|T_W0, 0x4B); }
    void tilezero(Tmm Tmm) { opVex(Tmm, tmm0, tmm0, T_F2 | T_0F38 | T_W0, 0x49); }
    void tdpbssd(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_F2 | T_0F38 | T_W0, 0x5e); }
    void tdpbsud(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_F3 | T_0F38 | T_W0, 0x5e); }
    void tdpbusd(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_66 | T_0F38 | T_W0, 0x5e); }
    void tdpbuud(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_0F38 | T_W0, 0x5e); }
    void tdpfp16ps(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_F2 | T_0F38 | T_W0, 0x5c); }
    void tdpbf16ps(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_F3 | T_0F38 | T_W0, 0x5c); }
    void tileloaddrs(Tmm tm, Address addr) { opAMX(tm, addr, T_F2|T_0F38|T_W0, 0x4A); }
    void tileloaddrst1(Tmm tm, Address addr) { opAMX(tm, addr, T_66|T_0F38|T_W0, 0x4A); }
    void tdpbf8ps(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_MAP5|T_W0, 0xFD); }
    void tdpbhf8ps(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_F2|T_MAP5|T_W0, 0xFD); }
    void tdphbf8ps(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_F3|T_MAP5|T_W0, 0xFD); }
    void tdphf8ps(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_66|T_MAP5|T_W0, 0xFD); }
    void tmmultf32ps(Tmm x1, Tmm x2, Tmm x3) { opVex(x1, x3, x2, T_66 | T_0F38 | T_W0, 0x48); }
  }
  else
  {
    void jcxz(string label) { db(0x67); opJmp(label, T_SHORT, 0xe3, 0, 0); }
    void jcxz(ref Label label) { db(0x67); opJmp(label, T_SHORT, 0xe3, 0, 0); }
    void jecxz(string label) { opJmp(label, T_SHORT, 0xe3, 0, 0); }
    void jecxz(ref Label label) { opJmp(label, T_SHORT, 0xe3, 0, 0); }
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
    void lds(Reg reg, Address addr) { opLoadSeg(addr, reg, T_NONE, 0xC5); }
    void les(Reg reg, Address addr) { opLoadSeg(addr, reg, T_NONE, 0xC4); }
  }

  version(XBYAK_NO_OP_NAMES)
  {}
  else
  {
    void and(Operand op1, Operand op2) { and_(op1, op2); }
    void and(Operand op, uint32_t imm) { and_(op, imm); }
    void and(Reg d, Operand op, uint32_t imm) { and_(d, op, imm); }
    void and(Reg d, Operand op1, Operand op2) { and_(d, op1, op2); }

    void or(Operand op1, Operand op2) { or_(op1, op2); }
    void or(Operand op, uint32_t imm) { or_(op, imm); }
    void or(Reg d, Operand op, uint32_t imm) { or_(d, op, imm); }
    void or(Reg d, Operand op1, Operand op2) { or_(d, op1, op2); }

    void xor(Operand op1, Operand op2) { xor_(op1, op2); }
    void xor(Operand op, uint32_t imm) { xor_(op, imm); }
    void xor(Reg d, Operand op, uint32_t imm) { xor_(d, op, imm); }
    void xor(Reg d, Operand op1, Operand op2) { xor_(d, op1, op2); }
    
    void not(Operand op) { not_(op); }
    void not(Reg d, Operand op) { not_(d, op); }
  }

  version(XBYAK_DISABLE_AVX512)
  {}
  else
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
    void kmovb(Address addr, Opmask k) { opKmov(k, addr, true, 8); }
    void kmovb(Opmask k, Operand op) { opKmov(k, op, false, 8); }
    void kmovb(Reg32 r, Opmask k) { opKmov(k, r, true, 8); }
    void kmovd(Address addr, Opmask k) { opKmov(k, addr, true, 32); }
    void kmovd(Opmask k, Operand op) { opKmov(k, op, false, 32); }
    void kmovd(Reg32 r, Opmask k) { opKmov(k, r, true, 32); }
    void kmovq(Address addr, Opmask k) { opKmov(k, addr, true, 64); }
    void kmovq(Opmask k, Operand op) { opKmov(k, op, false, 64); }
    void kmovw(Address addr, Opmask k) { opKmov(k, addr, true, 16); }
    void kmovw(Opmask k, Operand op) { opKmov(k, op, false, 16); }
    void kmovw(Reg32 r, Opmask k) { opKmov(k, r, true, 16); }
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
    void kshiftlb(Opmask r1, Opmask r2, uint8_t imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W0, 0x32, imm); }
    void kshiftld(Opmask r1, Opmask r2, uint8_t imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W0, 0x33, imm); }
    void kshiftlq(Opmask r1, Opmask r2, uint8_t imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W1, 0x33, imm); }
    void kshiftlw(Opmask r1, Opmask r2, uint8_t imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W1, 0x32, imm); }
    void kshiftrb(Opmask r1, Opmask r2, uint8_t imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W0, 0x30, imm); }
    void kshiftrd(Opmask r1, Opmask r2, uint8_t imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W0, 0x31, imm); }
    void kshiftrq(Opmask r1, Opmask r2, uint8_t imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W1, 0x31, imm); }
    void kshiftrw(Opmask r1, Opmask r2, uint8_t imm) { opVex(r1, null, r2, T_66 | T_0F3A | T_W1, 0x30, imm); }
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
    void vaddbf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x58); }
    void vaddph(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_EW0 | T_YMM | T_MUST_EVEX | T_ER_Z | T_B16, 0x58); }
    void vaddsh(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_F3 | T_EW0 | T_MUST_EVEX | T_ER_X | T_N2, 0x58); }
    void valignd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x03, imm); }
    void valignq(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x03, imm); }
    void vblendmpd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x65); }
    void vblendmps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x65); }
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
    void vcmpbf16(Opmask k, Xmm x, Operand op, uint8_t imm) { opVex(k, x, op, T_MUST_EVEX|T_F2|T_0F3A|T_EW0|T_YMM|T_B16, 0xC2, imm); }
    void vcmpeq_ospd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 16); }
    void vcmpeq_osps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 16); }
    void vcmpeq_ossd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 16); }
    void vcmpeq_osss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 16); }
    void vcmpeq_uqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 8); }
    void vcmpeq_uqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 8); }
    void vcmpeq_uqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 8); }
    void vcmpeq_uqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 8); }
    void vcmpeq_uspd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 24); }
    void vcmpeq_usps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 24); }
    void vcmpeq_ussd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 24); }
    void vcmpeq_usss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 24); }
    void vcmpeqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 0); }
    void vcmpeqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 0); }
    void vcmpeqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 0); }
    void vcmpeqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 0); }
    void vcmpfalse_ospd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 27); }
    void vcmpfalse_osps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 27); }
    void vcmpfalse_ossd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 27); }
    void vcmpfalse_osss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 27); }
    void vcmpfalsepd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 11); }
    void vcmpfalseps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 11); }
    void vcmpfalsesd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 11); }
    void vcmpfalsess(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 11); }
    void vcmpge_oqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 29); }
    void vcmpge_oqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 29); }
    void vcmpge_oqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 29); }
    void vcmpge_oqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 29); }
    void vcmpgepd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 13); }
    void vcmpgeps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 13); }
    void vcmpgesd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 13); }
    void vcmpgess(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 13); }
    void vcmpgt_oqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 30); }
    void vcmpgt_oqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 30); }
    void vcmpgt_oqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 30); }
    void vcmpgt_oqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 30); }
    void vcmpgtpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 14); }
    void vcmpgtps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 14); }
    void vcmpgtsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 14); }
    void vcmpgtss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 14); }
    void vcmple_oqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 18); }
    void vcmple_oqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 18); }
    void vcmple_oqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 18); }
    void vcmple_oqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 18); }
    void vcmplepd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 2); }
    void vcmpleps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 2); }
    void vcmplesd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 2); }
    void vcmpless(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 2); }
    void vcmplt_oqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 17); }
    void vcmplt_oqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 17); }
    void vcmplt_oqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 17); }
    void vcmplt_oqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 17); }
    void vcmpltpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 1); }
    void vcmpltps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 1); }
    void vcmpltsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 1); }
    void vcmpltss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 1); }
    void vcmpneq_oqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 12); }
    void vcmpneq_oqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 12); }
    void vcmpneq_oqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 12); }
    void vcmpneq_oqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 12); }
    void vcmpneq_ospd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 28); }
    void vcmpneq_osps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 28); }
    void vcmpneq_ossd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 28); }
    void vcmpneq_osss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 28); }
    void vcmpneq_uspd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 20); }
    void vcmpneq_usps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 20); }
    void vcmpneq_ussd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 20); }
    void vcmpneq_usss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 20); }
    void vcmpneqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 4); }
    void vcmpneqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 4); }
    void vcmpneqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 4); }
    void vcmpneqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 4); }
    void vcmpnge_uqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 25); }
    void vcmpnge_uqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 25); }
    void vcmpnge_uqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 25); }
    void vcmpnge_uqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 25); }
    void vcmpngepd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 9); }
    void vcmpngeps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 9); }
    void vcmpngesd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 9); }
    void vcmpngess(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 9); }
    void vcmpngt_uqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 26); }
    void vcmpngt_uqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 26); }
    void vcmpngt_uqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 26); }
    void vcmpngt_uqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 26); }
    void vcmpngtpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 10); }
    void vcmpngtps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 10); }
    void vcmpngtsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 10); }
    void vcmpngtss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 10); }
    void vcmpnle_uqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 22); }
    void vcmpnle_uqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 22); }
    void vcmpnle_uqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 22); }
    void vcmpnle_uqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 22); }
    void vcmpnlepd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 6); }
    void vcmpnleps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 6); }
    void vcmpnlesd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 6); }
    void vcmpnless(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 6); }
    void vcmpnlt_uqpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 21); }
    void vcmpnlt_uqps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 21); }
    void vcmpnlt_uqsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 21); }
    void vcmpnlt_uqss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 21); }
    void vcmpnltpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 5); }
    void vcmpnltps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 5); }
    void vcmpnltsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 5); }
    void vcmpnltss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 5); }
    void vcmpord_spd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 23); }
    void vcmpord_sps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 23); }
    void vcmpord_ssd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 23); }
    void vcmpord_sss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 23); }
    void vcmpordpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 7); }
    void vcmpordps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 7); }
    void vcmpordsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 7); }
    void vcmpordss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 7); }
    void vcmppd(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_66|T_0F|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0xC2, imm); }
    void vcmpph(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B16, 0xC2, imm); }
    void vcmpps(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_0F|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0xC2, imm); }
    void vcmpsd(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_N8|T_F2|T_0F|T_EW1|T_SAE_Z|T_MUST_EVEX, 0xC2, imm); }
    void vcmpsh(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_N2|T_F3|T_0F3A|T_EW0|T_SAE_X|T_MUST_EVEX, 0xC2, imm); }
    void vcmpss(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_N4|T_F3|T_0F|T_EW0|T_SAE_Z|T_MUST_EVEX, 0xC2, imm); }
    void vcmptrue_uspd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 31); }
    void vcmptrue_usps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 31); }
    void vcmptrue_ussd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 31); }
    void vcmptrue_usss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 31); }
    void vcmptruepd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 15); }
    void vcmptrueps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 15); }
    void vcmptruesd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 15); }
    void vcmptruess(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 15); }
    void vcmpunord_spd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 19); }
    void vcmpunord_sps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 19); }
    void vcmpunord_ssd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 19); }
    void vcmpunord_sss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 19); }
    void vcmpunordpd(Opmask k, Xmm x, Operand op) { vcmppd(k, x, op, 3); }
    void vcmpunordps(Opmask k, Xmm x, Operand op) { vcmpps(k, x, op, 3); }
    void vcmpunordsd(Opmask k, Xmm x, Operand op) { vcmpsd(k, x, op, 3); }
    void vcmpunordss(Opmask k, Xmm x, Operand op) { vcmpss(k, x, op, 3); }
    void vcomisbf16(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N2|T_66|T_MAP5|T_EW0|T_MUST_EVEX, 0x2F); }
    void vcomish(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N2|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX, 0x2F); }
    void vcompresspd(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x8A); }
    void vcompressps(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x8A); }
    void vcomxsd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N8|T_F2|T_0F|T_EW1|T_SAE_X|T_MUST_EVEX, 0x2F); }
    void vcomxsh(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N2|T_F3|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX, 0x2F); }
    void vcomxss(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N4|T_F3|T_0F|T_EW0|T_SAE_X|T_MUST_EVEX, 0x2F); }
    void vcvt2ph2bf8(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N1|T_F2|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x74); }
    void vcvt2ph2bf8s(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N1|T_F2|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x74); }
    void vcvt2ph2hf8(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N1|T_F2|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x18); }
    void vcvt2ph2hf8s(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N1|T_F2|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x1B); }
    void vcvt2ps2phx(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_B32, 0x67); }
    void vcvtbf162ibs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x69); }
    void vcvtbf162iubs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x6B); }
    void vcvtbiasph2bf8(Xmm x1, Xmm x2, Operand op) { opCvt6(x1, x2, op, T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x74); }
    void vcvtbiasph2bf8s(Xmm x1, Xmm x2, Operand op) { opCvt6(x1, x2, op, T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x74); }
    void vcvtbiasph2hf8(Xmm x1, Xmm x2, Operand op) { opCvt6(x1, x2, op, T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x18); }
    void vcvtbiasph2hf8s(Xmm x1, Xmm x2, Operand op) { opCvt6(x1, x2, op, T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x1B); }
    void vcvtdq2ph(Xmm x, Operand op) { checkCvt4(x, op); opCvt(x, op, T_N16|T_N_VL|T_MAP5|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B32, 0x5B); }
    void vcvthf82ph(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_MUST_EVEX | T_F2 | T_MAP5 | T_EW0 | T_YMM | T_N1, 0x1E); }
    void vcvtne2ps2bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F2|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x72); }
    void vcvtpd2ph(Xmm x, Operand op) { opCvt5(x, op, T_N16|T_N_VL|T_66|T_MAP5|T_EW1|T_ER_Z|T_MUST_EVEX|T_B64, 0x5A); }
    void vcvtpd2qq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F|T_EW1|T_YMM|T_ER_Z|T_MUST_EVEX|T_B64, 0x7B); }
    void vcvtpd2udq(Xmm x, Operand op) { opCvt2(x, op, T_0F|T_EW1|T_YMM|T_ER_Z|T_MUST_EVEX|T_B64, 0x79); }
    void vcvtpd2uqq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F|T_EW1|T_YMM|T_ER_Z|T_MUST_EVEX|T_B64, 0x79); } 
    void vcvtph2bf8(Xmm x, Operand op) { opCvt2(x, op, T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x74); }
    void vcvtph2bf8s(Xmm x, Operand op) { opCvt2(x, op, T_F3|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x74); }
    void vcvtph2dq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_66|T_MAP5|T_EW0|T_YMM|T_ER_Y|T_MUST_EVEX|T_B16, 0x5B); }
    void vcvtph2hf8(Xmm x, Operand op) { opCvt2(x, op, T_F3|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x18); }
    void vcvtph2hf8s(Xmm x, Operand op) { opCvt2(x, op, T_F3|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x1B); }
    void vcvtph2ibs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP5|T_EW0|T_YMM|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_B16, 0x69); }
    void vcvtph2iubs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP5|T_EW0|T_YMM|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_B16, 0x6B); }
    void vcvtph2pd(Xmm x, Operand op) { if (!op.isXMM() && !op.isMEM()) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(x, null, op, T_N4|T_N_VL|T_MAP5|T_EW0|T_YMM|T_SAE_X|T_MUST_EVEX|T_B16, 0x5A); }
    void vcvtph2psx(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_66|T_MAP6|T_EW0|T_YMM|T_SAE_Y|T_MUST_EVEX|T_B16, 0x13); }
    void vcvtph2qq(Xmm x, Operand op) { if (!op.isXMM() && !op.isMEM()) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(x, null, op, T_N4|T_N_VL|T_66|T_MAP5|T_EW0|T_YMM|T_ER_X|T_MUST_EVEX|T_B16, 0x7B); }
    void vcvtph2udq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_MAP5|T_EW0|T_YMM|T_ER_Y|T_MUST_EVEX|T_B16, 0x79); }
    void vcvtph2uqq(Xmm x, Operand op) { if (!op.isXMM() && !op.isMEM()) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(x, null, op, T_N4|T_N_VL|T_66|T_MAP5|T_EW0|T_YMM|T_ER_X|T_MUST_EVEX|T_B16, 0x79); }
    void vcvtph2uw(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP5|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x7D); }
    void vcvtph2w(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP5|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x7D); }
    void vcvtps2ibs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP5|T_EW0|T_YMM|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_B32, 0x69); }
    void vcvtps2iubs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP5|T_EW0|T_YMM|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_B32, 0x6B); }
    void vcvtps2phx(Xmm x, Operand op) { checkCvt4(x, op); opCvt(x, op, T_N16|T_N_VL|T_66|T_MAP5|T_EW0|T_ER_Z|T_MUST_EVEX|T_B32, 0x1D); }
    void vcvtps2qq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_66|T_0F|T_EW0|T_YMM|T_ER_Y|T_MUST_EVEX|T_B32, 0x7B); }
    void vcvtps2udq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_0F|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B32, 0x79); }
    void vcvtps2uqq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_66|T_0F|T_EW0|T_YMM|T_ER_Y|T_MUST_EVEX|T_B32, 0x79); }
    void vcvtqq2pd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F3|T_0F|T_EW1|T_YMM|T_ER_Z|T_MUST_EVEX|T_B64, 0xE6); }
    void vcvtqq2ph(Xmm x, Operand op) { opCvt5(x, op, T_N16|T_N_VL|T_MAP5|T_EW1|T_ER_Z|T_MUST_EVEX|T_B64, 0x5B); }
    void vcvtqq2ps(Xmm x, Operand op) { opCvt2(x, op, T_0F|T_EW1|T_YMM|T_ER_Z|T_MUST_EVEX|T_B64, 0x5B); }
    void vcvtsd2sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_F2|T_MAP5|T_EW1|T_ER_X|T_MUST_EVEX, 0x5A); }
    void vcvtsd2usi(Reg32e r, Operand op) { uint64_t type = (T_N8|T_F2|T_0F|T_ER_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x79); }
    void vcvtsh2sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_F3|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX, 0x5A); }
    void vcvtsh2si(Reg32e r, Operand op) { uint64_t type = (T_N2|T_F3|T_MAP5|T_ER_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x2D); }
    void vcvtsh2ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_MAP6|T_EW0|T_SAE_X|T_MUST_EVEX, 0x13); }
    void vcvtsh2usi(Reg32e r, Operand op) { uint64_t type = (T_N2|T_F3|T_MAP5|T_ER_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x79); }
    void vcvtsi2sh(Xmm x1, Xmm x2, Operand op) { if (!(x1.isXMM() && x2.isXMM() && op.isBit(32|64))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION) );uint64_t type = (T_F3|T_MAP5|T_ER_R|T_MUST_EVEX|T_M_K) | (op.isBit(32) ? (T_EW0 | T_N4) : (T_EW1 | T_N8)); opVex(x1, x2, op, type, 0x2A); }
    void vcvtss2sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_MAP5|T_EW0|T_ER_X|T_MUST_EVEX, 0x1D); }
    void vcvtss2usi(Reg32e r, Operand op) { uint64_t type = (T_N4|T_F3|T_0F|T_ER_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x79); }
    void vcvttbf162ibs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x68); }
    void vcvttbf162iubs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x6A); }
    void vcvttpd2dqs(Xmm x, Operand op) { opCvt2(x, op, T_MAP5|T_EW1|T_YMM|T_SAE_Y|T_SAE_Z|T_MUST_EVEX|T_B64, 0x6D); }
    void vcvttpd2qq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x7A); }
    void vcvttpd2qqs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP5|T_EW1|T_YMM|T_SAE_Y|T_SAE_Z|T_MUST_EVEX|T_B64, 0x6D); }
    void vcvttpd2udq(Xmm x, Operand op) { opCvt2(x, op, T_0F|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x78); }
    void vcvttpd2udqs(Xmm x, Operand op) { opCvt2(x, op, T_MAP5|T_EW1|T_YMM|T_SAE_Y|T_SAE_Z|T_MUST_EVEX|T_B64, 0x6C); }
    void vcvttpd2uqq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x78); }
    void vcvttpd2uqqs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP5|T_EW1|T_YMM|T_SAE_Y|T_SAE_Z|T_MUST_EVEX|T_B64, 0x6C); }
    void vcvttph2dq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_F3|T_MAP5|T_EW0|T_YMM|T_SAE_Y|T_MUST_EVEX|T_B16, 0x5B); }
    void vcvttph2ibs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP5|T_EW0|T_YMM|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_B16, 0x68); }
    void vcvttph2iubs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP5|T_EW0|T_YMM|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_B16, 0x6A); }
    void vcvttph2qq(Xmm x, Operand op) { if (!op.isXMM() && !op.isMEM()) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(x, null, op, T_N4|T_N_VL|T_66|T_MAP5|T_EW0|T_YMM|T_SAE_X|T_MUST_EVEX|T_B16, 0x7A); }
    void vcvttph2udq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_MAP5|T_EW0|T_YMM|T_SAE_Y|T_MUST_EVEX|T_B16, 0x78); }
    void vcvttph2uqq(Xmm x, Operand op) { if (!op.isXMM() && !op.isMEM()) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(x, null, op, T_N4|T_N_VL|T_66|T_MAP5|T_EW0|T_YMM|T_SAE_X|T_MUST_EVEX|T_B16, 0x78); }
    void vcvttph2uw(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP5|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B16, 0x7C); }
    void vcvttph2w(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP5|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B16, 0x7C); }
    void vcvttps2dqs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP5|T_EW0|T_YMM|T_SAE_Y|T_SAE_Z|T_MUST_EVEX|T_B32, 0x6D); }
    void vcvttps2ibs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP5|T_EW0|T_YMM|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_B32, 0x68); }
    void vcvttps2iubs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP5|T_EW0|T_YMM|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_B32, 0x6A); }
    void vcvttps2qq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_66|T_0F|T_EW0|T_YMM|T_SAE_Y|T_MUST_EVEX|T_B32, 0x7A); }
    void vcvttps2qqs(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_66|T_MAP5|T_EW0|T_YMM|T_SAE_X|T_SAE_Y|T_MUST_EVEX|T_B32, 0x6D); }
    void vcvttps2udq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_0F|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x78); }
    void vcvttps2udqs(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP5|T_EW0|T_YMM|T_SAE_Y|T_SAE_Z|T_MUST_EVEX|T_B32, 0x6C); }
    void vcvttps2uqq(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_66|T_0F|T_EW0|T_YMM|T_SAE_Y|T_MUST_EVEX|T_B32, 0x78); }
    void vcvttps2uqqs(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_66|T_MAP5|T_EW0|T_YMM|T_SAE_X|T_SAE_Y|T_MUST_EVEX|T_B32, 0x6C); }
    void vcvttsd2sis(Reg32e r, Operand op) { uint64_t type = (T_N8|T_F2|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x6D); }
    void vcvttsd2usi(Reg32e r, Operand op) { uint64_t type = (T_N8|T_F2|T_0F|T_SAE_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x78); }
    void vcvttsd2usis(Reg32e r, Operand op) { uint64_t type = (T_N8|T_F2|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x6C); }
    void vcvttsh2si(Reg32e r, Operand op) { uint64_t type = (T_N2|T_F3|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x2C); }
    void vcvttsh2usi(Reg32e r, Operand op) { uint64_t type = (T_N2|T_F3|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x78); }
    void vcvttss2sis(Reg32e r, Operand op) { uint64_t type = (T_N4|T_F3|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x6D); }
    void vcvttss2usi(Reg32e r, Operand op) { uint64_t type = (T_N4|T_F3|T_0F|T_SAE_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x78); }
    void vcvttss2usis(Reg32e r, Operand op) { uint64_t type = (T_N4|T_F3|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX) | (r.isREG(64) ? T_EW1 : T_EW0); opVex(r, xm0, op, type, 0x6C); }
    void vcvtudq2pd(Xmm x, Operand op) { checkCvt1(x, op); opVex(x, null, op, T_N8|T_N_VL|T_F3|T_0F|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x7A); }
    void vcvtudq2ph(Xmm x, Operand op) { checkCvt4(x, op); opCvt(x, op, T_N16|T_N_VL|T_F2|T_MAP5|T_EW0|T_ER_Z|T_MUST_EVEX|T_B32, 0x7A); }
    void vcvtudq2ps(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2|T_0F|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B32, 0x7A); }
    void vcvtuqq2pd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F3|T_0F|T_EW1|T_YMM|T_ER_Z|T_MUST_EVEX|T_B64, 0x7A); }
    void vcvtuqq2ph(Xmm x, Operand op) { opCvt5(x, op, T_N16|T_N_VL|T_F2|T_MAP5|T_EW1|T_ER_Z|T_MUST_EVEX|T_B64, 0x7A); }
    void vcvtuqq2ps(Xmm x, Operand op) { opCvt2(x, op, T_F2|T_0F|T_EW1|T_YMM|T_ER_Z|T_MUST_EVEX|T_B64, 0x7A); }
    void vcvtusi2sd(Xmm x1, Xmm x2, Operand op) { opCvt3(x1, x2, op, T_F2 | T_0F | T_MUST_EVEX, T_W1 | T_EW1 | T_ER_X | T_N8, T_W0 | T_EW0 | T_N4, 0x7B); }
    void vcvtusi2sh(Xmm x1, Xmm x2, Operand op) { if (!(x1.isXMM() && x2.isXMM() && op.isBit(32|64))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION) );uint64_t type = (T_F3|T_MAP5|T_ER_R|T_MUST_EVEX|T_M_K) | (op.isBit(32) ? (T_EW0 | T_N4) : (T_EW1 | T_N8)); opVex(x1, x2, op, type, 0x7B); }
    void vcvtusi2ss(Xmm x1, Xmm x2, Operand op) { opCvt3(x1, x2, op, T_F3 | T_0F | T_MUST_EVEX | T_ER_X, T_W1 | T_EW1 | T_N8, T_W0 | T_EW0 | T_N4, 0x7B); }
    void vcvtuw2ph(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2|T_MAP5|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x7D); }
    void vcvtw2ph(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F3|T_MAP5|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x7D); }
    void vdbpsadbw(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x42, imm); }
    void vdivbf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x5E); }
    void vdivph(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_EW0 | T_YMM | T_MUST_EVEX | T_ER_Z | T_B16, 0x5E); }
    void vdivsh(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_F3 | T_EW0 | T_MUST_EVEX | T_ER_X | T_N2, 0x5E); }
    void vdpbf16ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F3|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x52); }
    void vdpphps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_0F38|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x52); }
    void vexp2pd(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1 | T_B64 | T_SAE_Z, 0xC8); }
    void vexp2ps(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0 | T_B32 | T_SAE_Z, 0xC8); }
    void vexpandpd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x88); }
    void vexpandps(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x88); }
    void vextractf32x4(Operand op, Ymm r, uint8_t imm) { if (!op.isKind(Kind.MEM | Kind.XMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r, null, op, T_N16|T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x19, imm); }
    void vextractf32x8(Operand op, Zmm r, uint8_t imm) { if (!op.isKind(Kind.MEM | Kind.YMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r, null, op, T_N32|T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x1B, imm); }
    void vextractf64x2(Operand op, Ymm r, uint8_t imm) { if (!op.isKind(Kind.MEM | Kind.XMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r, null, op, T_N16|T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x19, imm); }
    void vextractf64x4(Operand op, Zmm r, uint8_t imm) { if (!op.isKind(Kind.MEM | Kind.YMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r, null, op, T_N32|T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x1B, imm); }
    void vextracti32x4(Operand op, Ymm r, uint8_t imm) { if (!op.isKind(Kind.MEM | Kind.XMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r, null, op, T_N16|T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x39, imm); }
    void vextracti32x8(Operand op, Zmm r, uint8_t imm) { if (!op.isKind(Kind.MEM | Kind.YMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r, null, op, T_N32|T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x3B, imm); }
    void vextracti64x2(Operand op, Ymm r, uint8_t imm) { if (!op.isKind(Kind.MEM | Kind.XMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r, null, op, T_N16|T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x39, imm); }
    void vextracti64x4(Operand op, Zmm r, uint8_t imm) { if (!op.isKind(Kind.MEM | Kind.YMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r, null, op, T_N32|T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x3B, imm); }
    void vfcmaddcph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F2|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B32, 0x56); }
    void vfcmulcph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F2|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B32, 0xD6); }
    void vfixupimmpd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x54, imm); }
    void vfixupimmps(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x54, imm); }
    void vfixupimmsd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F3A|T_EW1|T_SAE_Z|T_MUST_EVEX, 0x55, imm); }
    void vfixupimmss(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F3A|T_EW0|T_SAE_Z|T_MUST_EVEX, 0x55, imm); }
    void vfmadd132bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x98); }
    void vfmadd132ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x98); }
    void vfmadd132sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0x99); }
    void vfmadd213bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0xA8); }
    void vfmadd213ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xA8); }
    void vfmadd213sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0xA9); }
    void vfmadd231bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0xB8); }
    void vfmadd231ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xB8); }
    void vfmadd231sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0xB9); }
    void vfmaddcph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F3|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B32, 0x56); }
    void vfmaddsub132ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x96); }
    void vfmaddsub213ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xA6); }
    void vfmaddsub231ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xB6); }
    void vfmsub132bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x9A); }
    void vfmsub132ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x9A); }
    void vfmsub132sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0x9B); }
    void vfmsub213bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0xAA); }
    void vfmsub213ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xAA); }
    void vfmsub213sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0xAB); }
    void vfmsub231bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0xBA); }
    void vfmsub231ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xBA); }
    void vfmsub231sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0xBB); }
    void vfmsubadd132ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x97); }
    void vfmsubadd213ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xA7); }
    void vfmsubadd231ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xB7); }
    void vfmulcph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_F3|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B32, 0xD6); }
    void vfnmadd132bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x9C); }
    void vfnmadd132ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x9C); }
    void vfnmadd132sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0x9D); }
    void vfnmadd213bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0xAC); }
    void vfnmadd213ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xAC); }
    void vfnmadd213sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0xAD); }
    void vfnmadd231bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0xBC); }
    void vfnmadd231ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xBC); }
    void vfnmadd231sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0xBD); }
    void vfnmsub132bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x9E); }
    void vfnmsub132ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x9E); }
    void vfnmsub132sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0x9F); }
    void vfnmsub213bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0xAE); }
    void vfnmsub213ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xAE); }
    void vfnmsub213sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0xAF); }
    void vfnmsub231bf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0xBE); }
    void vfnmsub231ph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0xBE); }
    void vfnmsub231sh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0xBF); }
    void vfpclassbf16(Opmask k, Operand op, uint8_t imm) { opVex(k.changeBit(op.getBit()), null, op, T_MUST_EVEX|T_F2|T_0F3A|T_EW0|T_YMM|T_B16, 0x66, imm); }
    void vfpclasspd(Opmask k, Operand op, uint8_t imm) { if (!op.isBit(128|256|512)) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(k.changeBit(op.getBit()), null, op, T_66 | T_0F3A | T_MUST_EVEX | T_YMM | T_EW1 | T_B64, 0x66, imm); }
    void vfpclassph(Opmask k, Operand op, uint8_t imm) { if (!op.isBit(128|256|512)) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(k.changeBit(op.getBit()), null, op, T_0F3A | T_MUST_EVEX | T_YMM | T_EW0 | T_B16, 0x66, imm); }
    void vfpclassps(Opmask k, Operand op, uint8_t imm) { if (!op.isBit(128|256|512)) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(k.changeBit(op.getBit()), null, op, T_66 | T_0F3A | T_MUST_EVEX | T_YMM | T_EW0 | T_B32, 0x66, imm); }
    void vfpclasssd(Opmask k, Operand op, uint8_t imm) { if (!op.isXMEM()) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(k, null, op, T_66 | T_0F3A | T_MUST_EVEX | T_EW1 | T_N8, 0x67, imm); }
    void vfpclasssh(Opmask k, Operand op, uint8_t imm) { if (!op.isXMEM()) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(k, null, op, T_0F3A | T_MUST_EVEX | T_EW0 | T_N2, 0x67, imm); }
    void vfpclassss(Opmask k, Operand op, uint8_t imm) { if (!op.isXMEM()) mixin(XBYAK_THROW(ERR.BAD_MEM_SIZE)); opVex(k, null, op, T_66 | T_0F3A | T_MUST_EVEX | T_EW0 | T_N4, 0x67, imm); }
    void vgatherdpd(Xmm x, Address addr) { opGather2(x, addr, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_VSIB, 0x92, 1); }
    void vgatherdps(Xmm x, Address addr) { opGather2(x, addr, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_VSIB, 0x92, 0); }
    void vgatherpf0dpd(Address addr) { opGatherFetch(addr, zm1, T_N8|T_66|T_0F38|T_EW1|T_MUST_EVEX|T_M_K|T_VSIB, 0xC6, Kind.YMM); }
    void vgatherpf0dps(Address addr) { opGatherFetch(addr, zm1, T_N4|T_66|T_0F38|T_EW0|T_MUST_EVEX|T_M_K|T_VSIB, 0xC6, Kind.ZMM); }
    void vgatherpf0qpd(Address addr) { opGatherFetch(addr, zm1, T_N8|T_66|T_0F38|T_EW1|T_MUST_EVEX|T_M_K|T_VSIB, 0xC7, Kind.ZMM); }
    void vgatherpf0qps(Address addr) { opGatherFetch(addr, zm1, T_N4|T_66|T_0F38|T_EW0|T_MUST_EVEX|T_M_K|T_VSIB, 0xC7, Kind.ZMM); }
    void vgatherpf1dpd(Address addr) { opGatherFetch(addr, zm2, T_N8|T_66|T_0F38|T_EW1|T_MUST_EVEX|T_M_K|T_VSIB, 0xC6, Kind.YMM); }
    void vgatherpf1dps(Address addr) { opGatherFetch(addr, zm2, T_N4|T_66|T_0F38|T_EW0|T_MUST_EVEX|T_M_K|T_VSIB, 0xC6, Kind.ZMM); }
    void vgatherpf1qpd(Address addr) { opGatherFetch(addr, zm2, T_N8|T_66|T_0F38|T_EW1|T_MUST_EVEX|T_M_K|T_VSIB, 0xC7, Kind.ZMM); }
    void vgatherpf1qps(Address addr) { opGatherFetch(addr, zm2, T_N4|T_66|T_0F38|T_EW0|T_MUST_EVEX|T_M_K|T_VSIB, 0xC7, Kind.ZMM); }
    void vgatherqpd(Xmm x, Address addr) { opGather2(x, addr, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_VSIB, 0x93, 0); }
    void vgatherqps(Xmm x, Address addr) { opGather2(x, addr, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_VSIB, 0x93, 2); }
    void vgetexpbf16(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x42); }
    void vgetexppd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x42); }
    void vgetexpph(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP6|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B16, 0x42); }
    void vgetexpps(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x42); }
    void vgetexpsd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_EW1|T_SAE_X|T_MUST_EVEX, 0x43); }
    void vgetexpsh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_SAE_X|T_MUST_EVEX, 0x43); }
    void vgetexpss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_EW0|T_SAE_X|T_MUST_EVEX, 0x43); }
    void vgetmantbf16(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_F2|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x26, imm); }
    void vgetmantpd(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_66|T_0F3A|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x26, imm); }
    void vgetmantph(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B16, 0x26, imm); }
    void vgetmantps(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_66|T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x26, imm); }
    void vgetmantsd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F3A|T_EW1|T_SAE_X|T_MUST_EVEX, 0x27, imm); }
    void vgetmantsh(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N2|T_0F3A|T_EW0|T_SAE_X|T_MUST_EVEX, 0x27, imm); }
    void vgetmantss(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F3A|T_EW0|T_SAE_X|T_MUST_EVEX, 0x27, imm); }
    void vinsertf32x4(Ymm r1, Ymm r2, Operand op, uint8_t imm) {if (!(r1.getKind() == r2.getKind() && op.isKind(Kind.MEM | Kind.XMM))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r1, r2, op, T_N16|T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x18, imm); }
    void vinsertf32x8(Zmm r1, Zmm r2, Operand op, uint8_t imm) {if (!op.isKind(Kind.MEM | Kind.YMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r1, r2, op, T_N32|T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x1A, imm); }
    void vinsertf64x2(Ymm r1, Ymm r2, Operand op, uint8_t imm) {if (!(r1.getKind() == r2.getKind() && op.isKind(Kind.MEM | Kind.XMM))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r1, r2, op, T_N16|T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x18, imm); }
    void vinsertf64x4(Zmm r1, Zmm r2, Operand op, uint8_t imm) {if (!op.isKind(Kind.MEM | Kind.YMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r1, r2, op, T_N32|T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x1A, imm); }
    void vinserti32x4(Ymm r1, Ymm r2, Operand op, uint8_t imm) {if (!(r1.getKind() == r2.getKind() && op.isKind(Kind.MEM | Kind.XMM))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r1, r2, op, T_N16|T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x38, imm); }
    void vinserti32x8(Zmm r1, Zmm r2, Operand op, uint8_t imm) {if (!op.isKind(Kind.MEM | Kind.YMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r1, r2, op, T_N32|T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x3A, imm); }
    void vinserti64x2(Ymm r1, Ymm r2, Operand op, uint8_t imm) {if (!(r1.getKind() == r2.getKind() && op.isKind(Kind.MEM | Kind.XMM))) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r1, r2, op, T_N16|T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x38, imm); }
    void vinserti64x4(Zmm r1, Zmm r2, Operand op, uint8_t imm) {if (!op.isKind(Kind.MEM | Kind.YMM)) mixin(XBYAK_THROW(ERR.BAD_COMBINATION));opVex(r1, r2, op, T_N32|T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x3A, imm); }
    void vmaxbf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x5F); }
    void vmaxph(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_EW0 | T_YMM | T_MUST_EVEX | T_SAE_Z | T_B16, 0x5F); }
    void vmaxsh(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_F3 | T_EW0 | T_MUST_EVEX | T_SAE_X | T_N2, 0x5F); }
    void vminbf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x5D); }
    void vminmaxbf16(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_F2|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x52, imm); }    
    void vminmaxpd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW1|T_YMM|T_SAE_Y|T_SAE_Z|T_MUST_EVEX|T_B64, 0x52, imm); }
    void vminmaxph(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_0F3A|T_EW0|T_YMM|T_SAE_Y|T_SAE_Z|T_MUST_EVEX|T_B16, 0x52, imm); }
    void vminmaxps(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW0|T_YMM|T_SAE_Y|T_SAE_Z|T_MUST_EVEX|T_B32, 0x52, imm); }
    void vminmaxsd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F3A|T_EW1|T_SAE_X|T_MUST_EVEX, 0x53, imm); }
    void vminmaxsh(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N2|T_0F3A|T_EW0|T_SAE_X|T_MUST_EVEX, 0x53, imm); }
    void vminmaxss(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F3A|T_EW0|T_SAE_X|T_MUST_EVEX, 0x53, imm); }
    void vminph(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_EW0 | T_YMM | T_MUST_EVEX | T_SAE_Z | T_B16, 0x5D); }
    void vminsh(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_F3 | T_EW0 | T_MUST_EVEX | T_SAE_X | T_N2, 0x5D); }
    void vmovdqa32(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_66|T_0F|T_EW0|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_M_K, 0x7F); }
    void vmovdqa32(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F|T_EW0|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX, 0x6F); }
    void vmovdqa64(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_66|T_0F|T_EW1|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_M_K, 0x7F); }
    void vmovdqa64(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F|T_EW1|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX, 0x6F); }
    void vmovdqu16(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_F2|T_0F|T_EW1|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_M_K, 0x7F); }
    void vmovdqu16(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2|T_0F|T_EW1|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX, 0x6F); }
    void vmovdqu32(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_F3|T_0F|T_EW0|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_M_K, 0x7F); }
    void vmovdqu32(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F3|T_0F|T_EW0|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX, 0x6F); }
    void vmovdqu64(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_F3|T_0F|T_EW1|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_M_K, 0x7F); }
    void vmovdqu64(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F3|T_0F|T_EW1|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX, 0x6F); }
    void vmovdqu8(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_F2|T_0F|T_EW0|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX|T_M_K, 0x7F); }
    void vmovdqu8(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_F2|T_0F|T_EW0|T_YMM|T_ER_X|T_ER_Y|T_ER_Z|T_MUST_EVEX, 0x6F); }
    void vmovsh(Address addr, Xmm x) { opAVX_X_XM_IMM(x, addr, T_N2|T_F3|T_MAP5|T_EW0|T_MUST_EVEX|T_M_K, 0x11); }
    void vmovsh(Xmm x, Address addr) { opAVX_X_X_XM(x, xm0, addr, T_N2|T_F3|T_MAP5|T_EW0|T_MUST_EVEX, 0x10); }
    void vmovsh(Xmm x1, Xmm x2, Xmm x3) { opAVX_X_X_XM(x1, x2, x3, T_N2|T_F3|T_MAP5|T_EW0|T_MUST_EVEX, 0x10); }
    void vmpsadbw(Xmm x1, Xmm x2, Operand op, uint8_t imm, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_0F3A|T_YMM, 0x42, encoding, imm, T_66|T_W0|T_YMM, T_F3|T_0F3A|T_EW0|T_B32, 1); }
    void vmulbf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x59); }
    void vmulph(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_EW0 | T_YMM | T_MUST_EVEX | T_ER_Z | T_B16, 0x59); }
    void vmulsh(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_F3 | T_EW0 | T_MUST_EVEX | T_ER_X | T_N2, 0x59); }
    void vp2intersectd(Opmask k, Xmm x, Operand op) { if (k.getOpmaskIdx() != 0) mixin(XBYAK_THROW(ERR.OPMASK_IS_ALREADY_SET)); opAVX_K_X_XM(k, x, op, T_F2 | T_0F38 | T_YMM | T_EVEX | T_EW0 | T_B32, 0x68); }
    void vp2intersectq(Opmask k, Xmm x, Operand op) { if (k.getOpmaskIdx() != 0) mixin(XBYAK_THROW(ERR.OPMASK_IS_ALREADY_SET)); opAVX_K_X_XM(k, x, op, T_F2 | T_0F38 | T_YMM | T_EVEX | T_EW1 | T_B64, 0x68); }
    void vp4dpwssd(Zmm z1, Zmm z2, Address addr) { opAVX_X_X_XM(z1, z2, addr, T_0F38 | T_F2 | T_EW0 | T_YMM | T_MUST_EVEX | T_N16, 0x52); }
    void vp4dpwssds(Zmm z1, Zmm z2, Address addr) { opAVX_X_X_XM(z1, z2, addr, T_0F38 | T_F2 | T_EW0 | T_YMM | T_MUST_EVEX | T_N16, 0x53); }
    void vpabsq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66 | T_0F38 | T_MUST_EVEX | T_EW1 | T_B64 | T_YMM, 0x1F); }
    void vpandd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0xDB); }
    void vpandnd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0xDF); }
    void vpandnq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0xDF); }
    void vpandq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0xDB); }
    void vpblendmb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x66); }
    void vpblendmd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x64); }
    void vpblendmq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x64); }
    void vpblendmw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x66); }
    void vpbroadcastb(Xmm x, Reg8 r) { opVex(x, null, r, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x7A); }
    void vpbroadcastd(Xmm x, Reg32 r) { opVex(x, null, r, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x7C); }
    void vpbroadcastmb2q(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW1, 0x2A); }
    void vpbroadcastmw2d(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_YMM | T_MUST_EVEX | T_EW0, 0x3A); }
    void vpbroadcastw(Xmm x, Reg16 r) { opVex(x, null, r, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x7B); }
    void vpcmpb(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x3F, imm); }
    void vpcmpd(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x1F, imm); }
    void vpcmpeqb(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F|T_YMM|T_MUST_EVEX, 0x74); }
    void vpcmpeqd(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F|T_YMM|T_MUST_EVEX|T_B32, 0x76); }
    void vpcmpeqq(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x29); }
    void vpcmpeqw(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F|T_YMM|T_MUST_EVEX, 0x75); }
    void vpcmpgtb(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F|T_YMM|T_MUST_EVEX, 0x64); }
    void vpcmpgtd(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x66); }
    void vpcmpgtq(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x37); }
    void vpcmpgtw(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F|T_YMM|T_MUST_EVEX, 0x65); }
    void vpcmpq(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x1F, imm); }
    void vpcmpub(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX, 0x3E, imm); }
    void vpcmpud(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x1E, imm); }
    void vpcmpuq(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x1E, imm); }
    void vpcmpuw(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x3E, imm); }
    void vpcmpw(Opmask k, Xmm x, Operand op, uint8_t imm) { opAVX_K_X_XM(k, x, op, T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX, 0x3F, imm); }
    void vpcompressb(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N1|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x63); }
    void vpcompressd(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x8B); }
    void vpcompressq(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x8B); }
    void vpcompressw(Operand op, Xmm x) { opAVX_X_XM_IMM(x, op, T_N2|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x63); }
    void vpconflictd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0xC4); }
    void vpconflictq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0xC4); }
    void vpdpbssd(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_F2|T_0F38|T_YMM, 0x50, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpbssds(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_F2|T_0F38|T_YMM, 0x51, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpbsud(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_F3|T_0F38|T_YMM, 0x50, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpbsuds(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_F3|T_0F38|T_YMM, 0x51, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpbuud(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_0F38|T_YMM, 0x50, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpbuuds(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_0F38|T_YMM, 0x51, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpwsud(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_F3|T_0F38|T_YMM, 0xD2, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpwsuds(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_F3|T_0F38|T_YMM, 0xD3, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpwusd(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_66|T_0F38|T_YMM, 0xD2, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpwusds(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_66|T_0F38|T_YMM, 0xD3, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpwuud(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_0F38|T_YMM, 0xD2, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpdpwuuds(Xmm x1, Xmm x2, Operand op, PreferredEncoding encoding = DefaultEncoding) { opEncoding(x1, x2, op, T_0F38|T_YMM, 0xD3, encoding, NONE, T_W0, T_EW0|T_B32, 1); }
    void vpermb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x8D); }
    void vpermi2b(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x75); }
    void vpermi2d(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x76); }
    void vpermi2pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x77); }
    void vpermi2ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x77); }
    void vpermi2q(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x76); }
    void vpermi2w(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x75); }
    void vpermt2b(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x7D); }
    void vpermt2d(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x7E); }
    void vpermt2pd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x7F); }
    void vpermt2ps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x7F); }
    void vpermt2q(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x7E); }
    void vpermt2w(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x7D); }
    void vpermw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x8D); }
    void vpexpandb(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N1|T_66|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX, 0x62); }
    void vpexpandd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x89); }
    void vpexpandq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x89); }
    void vpexpandw(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N2|T_66|T_0F38|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX, 0x62); }
    void vpgatherdd(Xmm x, Address addr) { opGather2(x, addr, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_VSIB, 0x90, 0); }
    void vpgatherdq(Xmm x, Address addr) { opGather2(x, addr, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_VSIB, 0x90, 1); }
    void vpgatherqd(Xmm x, Address addr) { opGather2(x, addr, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_VSIB, 0x91, 2); }
    void vpgatherqq(Xmm x, Address addr) { opGather2(x, addr, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_VSIB, 0x91, 0); }
    void vplzcntd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x44); }
    void vplzcntq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x44); }
    void vpmadd52huq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0xB5); }
    void vpmadd52luq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0xB4); }
    void vpmaxsq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x3D); }
    void vpmaxuq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x3F); }
    void vpminsq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x39); }
    void vpminuq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x3B); }
    void vpmovb2m(Opmask k, Xmm x) { opVex(k, null, x, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0, 0x29); }
    void vpmovd2m(Opmask k, Xmm x) { opVex(k, null, x, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0, 0x39); }
    void vpmovdb(Operand op, Xmm x) { opVmov(op, x, T_N4|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x31, false); }
    void vpmovdw(Operand op, Xmm x) { opVmov(op, x, T_N8|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x33, true); }
    void vpmovm2b(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0, 0x28); }
    void vpmovm2d(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0, 0x38); }
    void vpmovm2q(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1, 0x38); }
    void vpmovm2w(Xmm x, Opmask k) { opVex(x, null, k, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1, 0x28); }
    void vpmovq2m(Opmask k, Xmm x) { opVex(k, null, x, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1, 0x39); }
    void vpmovqb(Operand op, Xmm x) { opVmov(op, x, T_N2|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x32, false); }
    void vpmovqd(Operand op, Xmm x) { opVmov(op, x, T_N8|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x35, true); }
    void vpmovqw(Operand op, Xmm x) { opVmov(op, x, T_N4|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x34, false); }
    void vpmovsdb(Operand op, Xmm x) { opVmov(op, x, T_N4|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x21, false); }
    void vpmovsdw(Operand op, Xmm x) { opVmov(op, x, T_N8|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x23, true); }
    void vpmovsqb(Operand op, Xmm x) { opVmov(op, x, T_N2|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x22, false); }
    void vpmovsqd(Operand op, Xmm x) { opVmov(op, x, T_N8|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x25, true); }
    void vpmovsqw(Operand op, Xmm x) { opVmov(op, x, T_N4|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x24, false); }
    void vpmovswb(Operand op, Xmm x) { opVmov(op, x, T_N8|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x20, true); }
    void vpmovusdb(Operand op, Xmm x) { opVmov(op, x, T_N4|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x11, false); }
    void vpmovusdw(Operand op, Xmm x) { opVmov(op, x, T_N8|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x13, true); }
    void vpmovusqb(Operand op, Xmm x) { opVmov(op, x, T_N2|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x12, false); }
    void vpmovusqd(Operand op, Xmm x) { opVmov(op, x, T_N8|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x15, true); }
    void vpmovusqw(Operand op, Xmm x) { opVmov(op, x, T_N4|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x14, false); }
    void vpmovuswb(Operand op, Xmm x) { opVmov(op, x, T_N8|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x10, true); }
    void vpmovw2m(Opmask k, Xmm x) { opVex(k, null, x, T_F3 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1, 0x29); }
    void vpmovwb(Operand op, Xmm x) { opVmov(op, x, T_N8|T_N_VL|T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K, 0x30, true); }
    void vpmullq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x40); }
    void vpmultishiftqb(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x83); }
    void vpopcntb(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX, 0x54); }
    void vpopcntd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x55); }
    void vpopcntq(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x55); }
    void vpopcntw(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX, 0x54); }
    void vpord(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0xEB); }
    void vporq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0xEB); }
    void vprold(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 1), x, op, T_66|T_0F|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x72, imm); }
    void vprolq(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 1), x, op, T_66|T_0F|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x72, imm); }
    void vprolvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x15); }
    void vprolvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x15); }
    void vprord(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 0), x, op, T_66|T_0F|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x72, imm); }
    void vprorq(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 0), x, op, T_66|T_0F|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x72, imm); }
    void vprorvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x14); }
    void vprorvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x14); }
    void vpscatterdd(Address addr, Xmm x) { opGather2(x, addr, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K|T_VSIB, 0xA0, 0); }
    void vpscatterdq(Address addr, Xmm x) { opGather2(x, addr, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_M_K|T_VSIB, 0xA0, 1); }
    void vpscatterqd(Address addr, Xmm x) { opGather2(x, addr, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K|T_VSIB, 0xA1, 2); }
    void vpscatterqq(Address addr, Xmm x) { opGather2(x, addr, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_M_K|T_VSIB, 0xA1, 0); }
    void vpshldd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x71, imm); }
    void vpshldq(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x71, imm); }
    void vpshldvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x71); }
    void vpshldvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x71); }
    void vpshldvw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX, 0x70); }
    void vpshldw(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX, 0x70, imm); }
    void vpshrdd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x73, imm); }
    void vpshrdq(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x73, imm); }
    void vpshrdvd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x73); }
    void vpshrdvq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x73); }
    void vpshrdvw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX, 0x72); }
    void vpshrdw(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX, 0x72, imm); }
    void vpshufbitqmb(Opmask k, Xmm x, Operand op) { opVex(k, x, op, T_66 | T_0F38 | T_EW0 | T_YMM | T_MUST_EVEX, 0x8F); }
    void vpsllvw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x12); }
    void vpsraq(Xmm x, Operand op, uint8_t imm) { opAVX_X_X_XM(Xmm(x.getKind(), 4), x, op, T_66|T_0F|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x72, imm); }
    void vpsraq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N16|T_66|T_0F|T_EW1|T_YMM|T_MUST_EVEX, 0xE2); }
    void vpsravq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x46); }
    void vpsravw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x11); }
    void vpsrlvw(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x10); }
    void vpternlogd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x25, imm); }
    void vpternlogq(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x25, imm); }
    void vptestmb(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x26); }
    void vptestmd(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x27); }
    void vptestmq(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x27); }
    void vptestmw(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x26); }
    void vptestnmb(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x26); }
    void vptestnmd(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_F3|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x27); }
    void vptestnmq(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_F3|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x27); }
    void vptestnmw(Opmask k, Xmm x, Operand op) { opAVX_K_X_XM(k, x, op, T_F3|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x26); }
    void vpxord(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0xEF); }
    void vpxorq(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0xEF); }
    void vrangepd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x50, imm); }
    void vrangeps(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x50, imm); }
    void vrangesd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F3A|T_EW1|T_SAE_X|T_MUST_EVEX, 0x51, imm); }
    void vrangess(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F3A|T_EW0|T_SAE_X|T_MUST_EVEX, 0x51, imm); }
    void vrcp14pd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x4C); }
    void vrcp14ps(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x4C); }
    void vrcp14sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_EW1|T_MUST_EVEX, 0x4D); }
    void vrcp14ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_EW0|T_MUST_EVEX, 0x4D); }
    void vrcp28pd(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1 | T_B64 | T_SAE_Z, 0xCA); }
    void vrcp28ps(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0 | T_B32 | T_SAE_Z, 0xCA); }
    void vrcp28sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_EW1|T_SAE_X|T_MUST_EVEX, 0xCB); }
    void vrcp28ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_EW0|T_SAE_X|T_MUST_EVEX, 0xCB); }
    void vrcpbf16(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x4C); }
    void vrcpph(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x4C); }
    void vrcpsh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_MUST_EVEX, 0x4D); }
    void vreducebf16(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_F2|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x56, imm); }
    void vreducepd(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_66|T_0F3A|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x56, imm); }
    void vreduceph(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B16, 0x56, imm); }
    void vreduceps(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_66|T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x56, imm); }
    void vreducesd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F3A|T_EW1|T_SAE_X|T_MUST_EVEX, 0x57, imm); }
    void vreducesh(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N2|T_0F3A|T_EW0|T_SAE_X|T_MUST_EVEX, 0x57, imm); }
    void vreducess(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F3A|T_EW0|T_SAE_X|T_MUST_EVEX, 0x57, imm); }
    void vrndscalebf16(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_F2|T_0F3A|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x08, imm); }
    void vrndscalepd(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_66|T_0F3A|T_EW1|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B64, 0x09, imm); }
    void vrndscaleph(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B16, 0x08, imm); }
    void vrndscaleps(Xmm x, Operand op, uint8_t imm) { opAVX_X_XM_IMM(x, op, T_66|T_0F3A|T_EW0|T_YMM|T_SAE_Z|T_MUST_EVEX|T_B32, 0x08, imm); }
    void vrndscalesd(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F3A|T_EW1|T_SAE_X|T_MUST_EVEX, 0x0B, imm); }
    void vrndscalesh(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N2|T_0F3A|T_EW0|T_SAE_X|T_MUST_EVEX, 0x0A, imm); }
    void vrndscaless(Xmm x1, Xmm x2, Operand op, uint8_t imm) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F3A|T_EW0|T_SAE_X|T_MUST_EVEX, 0x0A, imm); }
    void vrsqrt14pd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_B64, 0x4E); }
    void vrsqrt14ps(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_B32, 0x4E); }
    void vrsqrt14sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x4F); }
    void vrsqrt14ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX, 0x4F); }
    void vrsqrt28pd(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW1 | T_B64 | T_SAE_Z, 0xCC); }
    void vrsqrt28ps(Zmm z, Operand op) { opAVX_X_XM_IMM(z, op, T_66 | T_0F38 | T_MUST_EVEX | T_YMM | T_EW0 | T_B32 | T_SAE_Z, 0xCC); }
    void vrsqrt28sd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_EW1|T_SAE_X|T_MUST_EVEX, 0xCD); }
    void vrsqrt28ss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_EW0|T_SAE_X|T_MUST_EVEX, 0xCD); }
    void vrsqrtbf16(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x4E); }
    void vrsqrtph(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x4E); }
    void vrsqrtsh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_MUST_EVEX, 0x4F); }
    void vscalefbf16(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x2C); }
    void vscalefbf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_MAP6|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x2C); }
    void vscalefpd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW1|T_YMM|T_ER_Z|T_MUST_EVEX|T_B64, 0x2C); }
    void vscalefph(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP6|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x2C); }
    void vscalefps(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_0F38|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B32, 0x2C); }
    void vscalefsd(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N8|T_66|T_0F38|T_EW1|T_ER_X|T_MUST_EVEX, 0x2D); }
    void vscalefsh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_66|T_MAP6|T_EW0|T_ER_X|T_MUST_EVEX, 0x2D); }
    void vscalefss(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N4|T_66|T_0F38|T_EW0|T_ER_X|T_MUST_EVEX, 0x2D); }
    void vscatterdpd(Address addr, Xmm x) { opGather2(x, addr, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_M_K|T_VSIB, 0xA2, 1); }
    void vscatterdps(Address addr, Xmm x) { opGather2(x, addr, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K|T_VSIB, 0xA2, 0); }
    void vscatterpf0dpd(Address addr) { opGatherFetch(addr, zm5, T_N8|T_66|T_0F38|T_EW1|T_MUST_EVEX|T_M_K|T_VSIB, 0xC6, Kind.YMM); }
    void vscatterpf0dps(Address addr) { opGatherFetch(addr, zm5, T_N4|T_66|T_0F38|T_EW0|T_MUST_EVEX|T_M_K|T_VSIB, 0xC6, Kind.ZMM); }
    void vscatterpf0qpd(Address addr) { opGatherFetch(addr, zm5, T_N8|T_66|T_0F38|T_EW1|T_MUST_EVEX|T_M_K|T_VSIB, 0xC7, Kind.ZMM); }
    void vscatterpf0qps(Address addr) { opGatherFetch(addr, zm5, T_N4|T_66|T_0F38|T_EW0|T_MUST_EVEX|T_M_K|T_VSIB, 0xC7, Kind.ZMM); }
    void vscatterpf1dpd(Address addr) { opGatherFetch(addr, zm6, T_N8|T_66|T_0F38|T_EW1|T_MUST_EVEX|T_M_K|T_VSIB, 0xC6, Kind.YMM); }
    void vscatterpf1dps(Address addr) { opGatherFetch(addr, zm6, T_N4|T_66|T_0F38|T_EW0|T_MUST_EVEX|T_M_K|T_VSIB, 0xC6, Kind.ZMM); }
    void vscatterpf1qpd(Address addr) { opGatherFetch(addr, zm6, T_N8|T_66|T_0F38|T_EW1|T_MUST_EVEX|T_M_K|T_VSIB, 0xC7, Kind.ZMM); }
    void vscatterpf1qps(Address addr) { opGatherFetch(addr, zm6, T_N4|T_66|T_0F38|T_EW0|T_MUST_EVEX|T_M_K|T_VSIB, 0xC7, Kind.ZMM); }
    void vscatterqpd(Address addr, Xmm x) { opGather2(x, addr, T_N8|T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX|T_M_K|T_VSIB, 0xA3, 0); }
    void vscatterqps(Address addr, Xmm x) { opGather2(x, addr, T_N4|T_66|T_0F38|T_EW0|T_YMM|T_MUST_EVEX|T_M_K|T_VSIB, 0xA3, 2); }
    void vshuff32x4(Ymm y1, Ymm y2, Operand op, uint8_t imm) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F3A | T_YMM | T_MUST_EVEX | T_EW0 | T_B32, 0x23, imm); }
    void vshuff64x2(Ymm y1, Ymm y2, Operand op, uint8_t imm) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F3A | T_YMM | T_MUST_EVEX | T_EW1 | T_B64, 0x23, imm); }
    void vshufi32x4(Ymm y1, Ymm y2, Operand op, uint8_t imm) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F3A | T_YMM | T_MUST_EVEX | T_EW0 | T_B32, 0x43, imm); }
    void vshufi64x2(Ymm y1, Ymm y2, Operand op, uint8_t imm) { opAVX_X_X_XM(y1, y2, op, T_66 | T_0F3A | T_YMM | T_MUST_EVEX | T_EW1 | T_B64, 0x43, imm); }
    void vsqrtbf16(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_66|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x51); }
    void vsqrtph(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_MAP5|T_EW0|T_YMM|T_ER_Z|T_MUST_EVEX|T_B16, 0x51); }
    void vsqrtsh(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_N2|T_F3|T_MAP5|T_EW0|T_ER_X|T_MUST_EVEX, 0x51); }
    void vsubbf16(Xmm x1, Xmm x2, Operand op) { opAVX_X_X_XM(x1, x2, op, T_66|T_MAP5|T_EW0|T_YMM|T_MUST_EVEX|T_B16, 0x5C); }
    void vsubph(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_EW0 | T_YMM | T_MUST_EVEX | T_ER_Z | T_B16, 0x5C); }
    void vsubsh(Xmm xmm, Operand op1, Operand op2 = Operand()) { opAVX_X_X_XM(xmm, op1, op2, T_MAP5 | T_F3 | T_EW0 | T_MUST_EVEX | T_ER_X | T_N2, 0x5C); }
    void vucomish(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N2|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX, 0x2E); }
    void vucomxsd(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N8|T_F2|T_0F|T_EW1|T_SAE_X|T_MUST_EVEX, 0x2E); }
    void vucomxsh(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N2|T_F3|T_MAP5|T_EW0|T_SAE_X|T_MUST_EVEX, 0x2E); }
    void vucomxss(Xmm x, Operand op) { opAVX_X_XM_IMM(x, op, T_N4|T_F3|T_0F|T_EW0|T_SAE_X|T_MUST_EVEX, 0x2E); }
      version(XBYAK64)
      {
        void kmovq(Reg64 r, Opmask k) { opKmov(k, r, true, 64); }
        void vpbroadcastq(Xmm x, Reg64 r) { opVex(x, null, r, T_66|T_0F38|T_EW1|T_YMM|T_MUST_EVEX, 0x7C); }
      }
  }
}// version(XBYAK_DONT_READ_LIST) else

}// CodeGenerator

alias T_SHORT = CodeGenerator.LabelType.T_SHORT;
alias T_NEAR  = CodeGenerator.LabelType.T_NEAR;
alias T_FAR  = CodeGenerator.LabelType.T_FAR;
alias T_AUTO  = CodeGenerator.LabelType.T_AUTO;

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
mixin(["zmm0","zmm1","zmm2","zmm3","zmm4","zmm5","zmm6","zmm7"].def_alias);

mixin(["eax","ecx","edx","ebx","esp","ebp","esi","edi"].def_alias);
mixin(["ax","cx","dx","bx","sp","bp","si","di"].def_alias);
mixin(["al","cl","dl","bl","ah","ch","dh","bh"].def_alias);
mixin(["ptr","byte_","word","dword","qword", "xword", "yword", "zword"].def_alias);
mixin(["ptr_b", "xword_b", "yword_b", "zword_b"].def_alias);

mixin(["st0","st1","st2","st3","st4","st5","st6","st7"].def_alias);
mixin(["k0","k1","k2","k3","k4","k5","k6","k7"].def_alias);
mixin(["bnd0","bnd1","bnd2","bnd3"].def_alias);
mixin(["T_sae","T_rn_sae","T_rd_sae","T_ru_sae","T_rz_sae"].def_alias);

mixin(["T_z"].def_alias);

  version (XBYAK64)
  {
    mixin(["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"].def_alias);
    mixin(["r8","r9","r10","r11","r12","r13","r14","r15"].def_alias);
    mixin(["r16","r17","r18","r19","r20","r21","r22","r23"].def_alias);
    mixin(["r24","r25","r26","r27","r28","r29","r30","r31"].def_alias);

    mixin(["r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"].def_alias);
    mixin(["r16d","r17d","r18d","r19d","r20d","r21d","r22d","r23d"].def_alias);
    mixin(["r24d","r25d","r26d","r27d","r28d","r29d","r30d","r31d"].def_alias);

    mixin(["r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"].def_alias);
    mixin(["r16w","r17w","r18w","r19w","r20w","r21w","r22w","r23w"].def_alias);
    mixin(["r24w","r25w","r26w","r27w","r28w","r29w","r30w","r31w"].def_alias);
    
    mixin(["r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"].def_alias);
    mixin(["r16b","r17b","r18b","r19b","r20b","r21b","r22b","r23b"].def_alias);
    mixin(["r24b","r25b","r26b","r27b","r28b","r29b","r30b","r31b"].def_alias);
    mixin(["spl","bpl","sil","dil"].def_alias);
    
    mixin(["xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"].def_alias);
    mixin(["xmm16","xmm17","xmm18","xmm19","xmm20","xmm21","xmm22","xmm23"].def_alias);
    mixin(["xmm24","xmm25","xmm26","xmm27","xmm28","xmm29","xmm30","xmm31"].def_alias);

    mixin(["ymm8","ymm9","ymm10","ymm11","ymm12","ymm13","ymm14","ymm15"].def_alias);
    mixin(["ymm16","ymm17","ymm18","ymm19","ymm20","ymm21","ymm22","ymm23"].def_alias);
    mixin(["ymm24","ymm25","ymm26","ymm27","ymm28","ymm29","ymm30","ymm31"].def_alias);

    mixin(["zmm8","zmm9","zmm10","zmm11","zmm12","zmm13","zmm14","zmm15"].def_alias);
    mixin(["zmm16","zmm17","zmm18","zmm19","zmm20","zmm21","zmm22","zmm23"].def_alias);
    mixin(["zmm24","zmm25","zmm26","zmm27","zmm28","zmm29","zmm30","zmm31"].def_alias);

    mixin(["tmm0","tmm1","tmm2","tmm3","tmm4","tmm5","tmm6","tmm7"].def_alias);
    mixin(["rip"].def_alias);
    mixin(["T_nf"].def_alias);
    mixin(["T_zu"].def_alias);
  }

  version(XBYAK_DISABLE_SEGMENT)
  {}
  else
  {
    alias es = Segment.es;
    alias cs = Segment.cs;
    alias ss = Segment.ss;
    alias ds = Segment.ds;
    alias fs = Segment.fs;
    alias gs = Segment.gs;
  }

@("test_toString")
unittest
{
    string def_string(string[] names)
    {
        string result;
        foreach(name; names){
            result ~= "assert(" ~ name ~ ".stringof == " ~ name ~ ".toString);\n";
        }
        return result;
    }

    mixin(def_string(["mm0","mm1","mm2","mm3","mm4","mm5","mm6","mm7"]));
    mixin(def_string(["xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7"]));
    mixin(def_string(["ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7"]));
    mixin(def_string(["zmm0","zmm1","zmm2","zmm3","zmm4","zmm5","zmm6","zmm7"]));

    mixin(def_string(["eax","ecx","edx","ebx","esp","ebp","esi","edi"]));
    mixin(def_string(["ax","cx","dx","bx","sp","bp","si","di"]));
    mixin(def_string(["al","cl","dl","bl","ah","ch","dh","bh"]));

    mixin(def_string(["st0","st1","st2","st3","st4","st5","st6","st7"]));
    mixin(def_string(["k0","k1","k2","k3","k4","k5","k6","k7"]));
    mixin(def_string(["bnd0","bnd1","bnd2","bnd3"]));

  version (XBYAK64)
  {
    mixin(def_string(["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"]));
    mixin(def_string(["r8","r9","r10","r11","r12","r13","r14","r15"]));
    mixin(def_string(["r16","r17","r18","r19","r20","r21","r22","r23"]));
    mixin(def_string(["r24","r25","r26","r27","r28","r29","r30","r31"]));

    mixin(def_string(["r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"]));
    mixin(def_string(["r16d","r17d","r18d","r19d","r20d","r21d","r22d","r23d"]));
    mixin(def_string(["r24d","r25d","r26d","r27d","r28d","r29d","r30d","r31d"]));

    mixin(def_string(["r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"]));
    mixin(def_string(["r16w","r17w","r18w","r19w","r20w","r21w","r22w","r23w"]));
    mixin(def_string(["r24w","r25w","r26w","r27w","r28w","r29w","r30w","r31w"]));
    
    mixin(def_string(["r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"]));
    mixin(def_string(["r16b","r17b","r18b","r19b","r20b","r21b","r22b","r23b"]));
    mixin(def_string(["r24b","r25b","r26b","r27b","r28b","r29b","r30b","r31b"]));
    mixin(def_string(["spl","bpl","sil","dil"]));
    
    mixin(def_string(["xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"]));
    mixin(def_string(["xmm16","xmm17","xmm18","xmm19","xmm20","xmm21","xmm22","xmm23"]));
    mixin(def_string(["xmm24","xmm25","xmm26","xmm27","xmm28","xmm29","xmm30","xmm31"]));

    mixin(def_string(["ymm8","ymm9","ymm10","ymm11","ymm12","ymm13","ymm14","ymm15"]));
    mixin(def_string(["ymm16","ymm17","ymm18","ymm19","ymm20","ymm21","ymm22","ymm23"]));
    mixin(def_string(["ymm24","ymm25","ymm26","ymm27","ymm28","ymm29","ymm30","ymm31"]));

    mixin(def_string(["zmm8","zmm9","zmm10","zmm11","zmm12","zmm13","zmm14","zmm15"]));
    mixin(def_string(["zmm16","zmm17","zmm18","zmm19","zmm20","zmm21","zmm22","zmm23"]));
    mixin(def_string(["zmm24","zmm25","zmm26","zmm27","zmm28","zmm29","zmm30","zmm31"]));

    mixin(def_string(["tmm0","tmm1","tmm2","tmm3","tmm4","tmm5","tmm6","tmm7"]));
  }

}