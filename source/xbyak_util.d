module xbayk_util;

import core.stdc.stdlib;
import core.stdc.stdio : stderr, fprintf;
import std.stdint;
import std.stdio;
import std.string;

import xbyak;

version = XBYAK64;
version = XBYAK64_WIN;

  version(X86_64)
  {
    version = XBYAK_INTEL_CPU_SPECIFIC;
  }

struct local
{
    static T max_(T)(T x, T y) { return x >= y ? x : y; }
    static T min_(T)(T x, T y) { return x < y ? x : y; }
}


struct Clock
{
    public:
        static uint64_t getRdtsc()
        {
  version(XBYAK_INTEL_CPU_SPECIFIC)
  {
            asm
            {
                naked;
                rdtsc;
                ret;
            }
  }
  else
  {
            // TODO: Need another impl of Clock or rdtsc-equivalent for non-x86 cpu
            return 0;
  }
        }
        void begin()
        {
            clock_ -= getRdtsc();
        }
        void end()
        {
            clock_ += getRdtsc();
            count_++;
        }
        int getCount() const { return count_; }
        uint64_t getClock() const { return clock_; }
        void clear() { count_ = 0; clock_ = 0; }
    private:
        uint64_t clock_ = 0;
        int count_ = 0;
}

@("clock")
unittest
{
    writeln("unittest clock");
    writeln("loop n : clock");
    Clock cl;
    const n1 = 123456;
    cl.begin();
    for(int i=0; i<n1; i++){}
    cl.end();
    writeln(n1, " : ", cl.getClock());

    Clock cl2;
    const n2 = 1234567;
    cl2.begin();
    for(int i=0; i<n2; i++){}
    cl2.end();
    writeln(n2, " : ", cl2.getClock());
	
	assert( cl.getClock() < cl2.getClock() );
}


  version(XBYAK64)
  {
const int UseRCX = 1 << 6;
const int UseRDX = 1 << 7;

struct Pack
{
    static const size_t maxTblNum = 15;
    Reg64[maxTblNum] tbl_;
    size_t n_;

public:
    this(Reg64[] tbl, size_t n)
    {
        init(tbl, n);
    }
    this(ref Pack rhs)
    {
        n_ = rhs.n_;
        for (size_t i = 0; i < n_; i++) tbl_[i] = rhs.tbl_[i];
    }
    ref Pack opAssign(ref Pack rhs)
    {
        n_ = rhs.n_;
        for (size_t i = 0; i < n_; i++) tbl_[i] = rhs.tbl_[i];
        return this;
    }
    this(Reg64 t0)
    { n_ = 1; tbl_[0] = t0; }
    this(Reg64 t1, Reg64 t0)
    { n_ = 2; tbl_[0] = t0; tbl_[1] = t1; }
    this(Reg64 t2, Reg64 t1, Reg64 t0)
    { n_ = 3; tbl_[0] = t0; tbl_[1] = t1; tbl_[2] = t2; }
    this(Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
    { n_ = 4; tbl_[0] = t0; tbl_[1] = t1; tbl_[2] = t2; tbl_[3] = t3; }
    this(Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
    { n_ = 5; tbl_[0] = t0; tbl_[1] = t1; tbl_[2] = t2; tbl_[3] = t3; tbl_[4] = t4; }
    this(Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
    { n_ = 6; tbl_[0] = t0; tbl_[1] = t1; tbl_[2] = t2; tbl_[3] = t3; tbl_[4] = t4; tbl_[5] = t5; }
    this(Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
    { n_ = 7; tbl_[0] = t0; tbl_[1] = t1; tbl_[2] = t2; tbl_[3] = t3; tbl_[4] = t4; tbl_[5] = t5; tbl_[6] = t6; }
    this(Reg64 t7, Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
    { n_ = 8; tbl_[0] = t0; tbl_[1] = t1; tbl_[2] = t2; tbl_[3] = t3; tbl_[4] = t4; tbl_[5] = t5; tbl_[6] = t6; tbl_[7] = t7; }
    this(Reg64 t8, Reg64 t7, Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
    { n_ = 9; tbl_[0] = t0; tbl_[1] = t1; tbl_[2] = t2; tbl_[3] = t3; tbl_[4] = t4; tbl_[5] = t5; tbl_[6] = t6; tbl_[7] = t7; tbl_[8] = t8; }
    this(Reg64 t9, Reg64 t8, Reg64 t7, Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
    { n_ = 10; tbl_[0] = t0; tbl_[1] = t1; tbl_[2] = t2; tbl_[3] = t3; tbl_[4] = t4; tbl_[5] = t5; tbl_[6] = t6; tbl_[7] = t7; tbl_[8] = t8; tbl_[9] = t9; }
    this(Reg64 ta, Reg64 t9, Reg64 t8, Reg64 t7, Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
    { n_ = 11; tbl_[0] = t0; tbl_[1] = t1; tbl_[2] = t2; tbl_[3] = t3; tbl_[4] = t4; tbl_[5] = t5; tbl_[6] = t6; tbl_[7] = t7; tbl_[8] = t8; tbl_[9] = t9; tbl_[10] = ta; }
    this(Reg64 tb, Reg64 ta, Reg64 t9, Reg64 t8, Reg64 t7, Reg64 t6, Reg64 t5, Reg64 t4, Reg64 t3, Reg64 t2, Reg64 t1, Reg64 t0)
    { n_ = 12; tbl_[0] = t0; tbl_[1] = t1; tbl_[2] = t2; tbl_[3] = t3; tbl_[4] = t4; tbl_[5] = t5; tbl_[6] = t6; tbl_[7] = t7; tbl_[8] = t8; tbl_[9] = t9; tbl_[10] = ta; tbl_[11] = tb; }

    ref Pack append(Reg64 t)
    {
        if (n_ == maxTblNum) {
            fprintf(stderr, "ERR Pack.can't append\n");
            mixin(XBYAK_THROW_RET(ERR.BAD_PARAMETER, "this"));
        }
        tbl_[n_++] = t;
        return this;
    }
    void init(Reg64[] tbl, size_t n)
    {
        if (n > maxTblNum) {
            fprintf(stderr, "ERR Pack::init bad n=%d\n", cast(int)n);
            mixin(XBYAK_THROW(ERR.BAD_PARAMETER));
        }
        n_ = n;
        for (size_t i = 0; i < n; i++) {
            tbl_[i] = tbl[i];
        }
    }
    Reg64 opIndex(size_t n)
    {
        if (n >= n_) {
            fprintf(stderr, "ERR Pack bad n=%d(%d)\n", cast(int)n, cast(int)n_);
            mixin(XBYAK_THROW_RET(ERR.BAD_PARAMETER, "rax"));
        }
        return tbl_[n];
    }
    size_t size() const { return n_; }
    /*
        get tbl[pos, pos + num)
    */
    Pack sub(size_t pos, size_t num = cast(size_t)(-1))
    {
        if (num == cast(size_t)(-1)) num = n_ - pos;
        if (pos + num > n_) {
            fprintf(stderr, "ERR Pack.sub bad pos=%d, num=%d\n", cast(int)pos, cast(int)num);
            mixin(XBYAK_THROW_RET(ERR.BAD_PARAMETER, "Pack()"));
        }
        Pack pack;
        pack.n_ = num;
        for (size_t i = 0; i < num; i++) {
            pack.tbl_[i] = tbl_[pos + i];
        }
        return pack;
    }
    void put() const
    {
        for (size_t i = 0; i < n_; i++) {
            write(tbl_[i], " ");
        }
        writeln();
    }
}


struct StackFrame
{
  version(XBYAK64_WIN)
  {
    static const int noSaveNum = 6;
    static const int rcxPos = 0;
    static const int rdxPos = 1;
  }
  else
  {
    static const int noSaveNum = 8;
    static const int rcxPos = 3;
    static const int rdxPos = 2;
  }
    static const int maxRegNum = 14; // maxRegNum = 16 - rsp - rax
    CodeGenerator code_;
    int pNum_;
    int tNum_;
    bool useRcx_;
    bool useRdx_;
    int saveNum_;
    int P_;
    bool makeEpilog_;
    Reg64[4] pTbl_;
    Reg64[maxRegNum] tTbl_;
public:
    Pack p; //= Pack();
    Pack t; //= Pack();

    /*
        make stack frame
        @param sf [in] this
        @param pNum [in] num of function parameter(0 <= pNum <= 4)
        @param tNum [in] num of temporary register(0 <= tNum, with UseRCX, UseRDX) #{pNum + tNum [+rcx] + [rdx]} <= 14
        @param stackSizeByte [in] local stack size
        @param makeEpilog [in] automatically call close() if true

        you can use
        rax
        gp0, ..., gp(pNum - 1)
        gt0, ..., gt(tNum-1)
        rcx if tNum & UseRCX
        rdx if tNum & UseRDX
        rsp[0..stackSizeByte - 1]
    */
    this(CodeGenerator code, int pNum, int tNum = 0, int stackSizeByte = 0, bool makeEpilog = true)
    {
        code_ = code;
        pNum_ = pNum;
        tNum_ = (tNum & ~(UseRCX | UseRDX));
        useRcx_ = ((tNum & UseRCX) != 0);
        useRdx_ = ((tNum & UseRDX) != 0);
        saveNum_ = 0;
        P_ = 0;
        makeEpilog_ = makeEpilog;
    
        if (pNum < 0 || pNum > 4) mixin(XBYAK_THROW(ERR.BAD_PNUM));
        const int allRegNum = pNum + tNum_ + (useRcx_ ? 1 : 0) + (useRdx_ ? 1 : 0);
        if (tNum_ < 0 || allRegNum > maxRegNum) mixin(XBYAK_THROW(ERR.BAD_TNUM));
        Reg64 _rsp = code.rsp;
        saveNum_ = local.max_(0, allRegNum - noSaveNum);
        int[] tbl = getOrderTbl(noSaveNum);
        for (int i = 0; i < saveNum_; i++) {
            code.push(new Reg64(tbl[i]));
        }

        P_ = (stackSizeByte + 7) / 8;
        if (P_ > 0 && (P_ & 1) == (saveNum_ & 1)) P_++; // (rsp % 16) == 8, then increment P_ for 16 byte alignment
        
        P_ *= 8;
        if (P_ > 0) code.sub(_rsp, P_);
        
        int pos = 0;
        for (int i = 0; i < pNum; i++) {
            pTbl_[i] = new Reg64(getRegIdx(pos));
        }
        
        for (int i = 0; i < tNum_; i++) {
            tTbl_[i] = new Reg64(getRegIdx(pos));
        }
        
        if (useRcx_ && rcxPos < pNum) code_.mov(code_.r10, code_.rcx);
        if (useRdx_ && rdxPos < pNum) code_.mov(code_.r11, code_.rdx);

        p.init(pTbl_, pNum);
        t.init(tTbl_, tNum_);
    }
    /*
        make epilog manually
        @param callRet [in] call ret() if true
    */
    void close(bool callRet = true)
    {
        Reg64 _rsp = code_.rsp;
        int[] tbl = getOrderTbl(noSaveNum);
        if (P_ > 0) code_.add(_rsp, P_);
        for (int i = 0; i < saveNum_; i++) {
            code_.pop(new Reg64(tbl[saveNum_ - 1 - i]));
        }

        if (callRet) code_.ret();
    }
    ~this()
    {
        if (!makeEpilog_) return;
        close();
    }

private:
    int[] getOrderTbl(size_t n = 0)
    {
  version(XBYAK64_WIN)
  {
        static int[] tbl = [
            Operand.RCX, Operand.RDX, Operand.R8, Operand.R9, Operand.R10, Operand.R11, Operand.RDI, Operand.RSI,
            Operand.RBX, Operand.RBP, Operand.R12, Operand.R13, Operand.R14, Operand.R15
        ];
  }
  else
  {
        static int[] tbl = [
            Operand.RDI, Operand.RSI, Operand.RDX, Operand.RCX, Operand.R8, Operand.R9, Operand.R10, Operand.R11,
            Operand.RBX, Operand.RBP, Operand.R12, Operand.R13, Operand.R14, Operand.R15
        ];
  }
        return tbl[n..$];
    }

    int getRegIdx(ref int pos)
    {
        assert(pos < maxRegNum);
    
        int[] tbl = getOrderTbl();
        int r = tbl[pos++];
        if (useRcx_) {
            if (r == Operand.RCX) { return Operand.R10; }
            if (r == Operand.R10) { r = tbl[pos++]; }
        }
        if (useRdx_) {
            if (r == Operand.RDX) { return Operand.R11; }
            if (r == Operand.R11) { return tbl[pos++]; }
        }
        return r;
    }
}

  }
