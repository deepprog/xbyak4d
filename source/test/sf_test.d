module sf_test;

import core.stdc.stdio;
import core.stdc.stdlib;
import std.stdint;
import std.stdio;
import std.string;

import xbyak;
import xbyak_util;

version(X86)    version = XBYAK32;
version(X86_64) version = XBYAK64;

struct AutoRun
{
    void reset()
    {
        okCount_ = 0;
        ngCount_ = 0;
    }

    void set(bool isOK)
    {
        if (isOK) {
            okCount_++;
        } else {
            ngCount_++;
        }
    }

    void test(bool ret, string msg, string param, string file, size_t line)
    {
        this.set(ret);
        if (!ret) {
            writefln("%s(%d): AutoRun.%s(%s);", file, line, msg, param);
        }
    }

    void TEST_EQUAL(T)(T x, T y, string file = __FILE__, size_t line = __LINE__)
    {
        auto isEqual = (x == y);
        this.test(isEqual, "TEST_EQUAL", x.stringof ~ ", " ~ y.stringof, file, line);

        if (!isEqual) {
            writeln("test: lhs = ", x);
            writeln("test: rhs = ", y);
        }
    }

    void end(string name = "")
    {
        writeln(name, " OK:", okCount_, " NG:", ngCount_);
        assert(ngCount_ == 0);
    }

private:
    int okCount_;
    int ngCount_;
}








version(XBYAK64)
{


class Code : CodeGenerator
{
    this()
    {
        super();
    }
    
    void gen1()
    {
        StackFrame sf = StackFrame(this, 1);
        mov(rax, sf.p[0]);
    }

    void gen2()
    {
        StackFrame sf = StackFrame(this, 2);
        lea(rax, ptr [sf.p[0] + sf.p[1]]);
    }
    void gen3()
    {
        StackFrame sf = StackFrame(this, 3);
        mov(rax, sf.p[0]);
        add(rax, sf.p[1]);
        add(rax, sf.p[2]);
    }

    void gen4()
    {
        StackFrame sf = StackFrame(this, 4);
        mov(rax, sf.p[0]);
        add(rax, sf.p[1]);
        add(rax, sf.p[2]);
        add(rax, sf.p[3]);
    }

    void gen5()
    {
        StackFrame sf = StackFrame(this, 4, UseRCX);
        xor(rcx, rcx);
        mov(rax, sf.p[0]);
        add(rax, sf.p[1]);
        add(rax, sf.p[2]);
        add(rax, sf.p[3]);
    }

    void gen6()
    {
        StackFrame sf = StackFrame(this, 4, UseRCX | UseRDX);
        xor(rcx, rcx);
        xor(rdx, rdx);
        mov(rax, sf.p[0]);
        add(rax, sf.p[1]);
        add(rax, sf.p[2]);
        add(rax, sf.p[3]);
    }

    void gen7()
    {
        StackFrame sf = StackFrame(this, 3, UseRCX | UseRDX);
        xor(rcx, rcx);
        xor(rdx, rdx);
        mov(rax, sf.p[0]);
        add(rax, sf.p[1]);
        add(rax, sf.p[2]);
    }

    void gen8()
    {
        StackFrame sf = StackFrame(this, 3, 3 | UseRCX | UseRDX);
        xor(rcx, rcx);
        xor(rdx, rdx);
        mov(sf.t[0], 1);
        mov(sf.t[1], 2);
        mov(sf.t[2], 3);
        mov(rax, sf.p[0]);
        add(rax, sf.p[1]);
        add(rax, sf.p[2]);
    }

    void gen9()
    {
        StackFrame sf = StackFrame(this, 3, 3 | UseRCX | UseRDX, 32);
        xor(rcx, rcx);
        xor(rdx, rdx);
        mov(sf.t[0], 1);
        mov(sf.t[1], 2);
        mov(sf.t[2], 3);
        mov(rax, sf.p[0]);
        add(rax, sf.p[1]);
        add(rax, sf.p[2]);
        mov(ptr [rsp + 8 * 0], rax);
        mov(ptr [rsp + 8 * 1], rax);
        mov(ptr [rsp + 8 * 2], rax);
        mov(ptr [rsp + 8 * 3], rax);
    }

    void gen10()
    {
        StackFrame sf = StackFrame(this, 4, 8 | UseRCX | UseRDX, 32);
        xor(rcx, rcx);
        xor(rdx, rdx);
        for (int i = 0; i < 8; i++) {
            mov(sf.t[i], i);
        }
        mov(rax, sf.p[0]);
        add(rax, sf.p[1]);
        add(rax, sf.p[2]);
        add(rax, sf.p[3]);
        mov(ptr [rsp + 8 * 0], rax);
        mov(ptr [rsp + 8 * 1], rax);
        mov(ptr [rsp + 8 * 2], rax);
        mov(ptr [rsp + 8 * 3], rax);
    }

    void gen11()
    {
        StackFrame sf = StackFrame(this, 0, UseRCX);
        xor(rcx, rcx);
        mov(rax, 3);
    }

    void gen12()
    {
        StackFrame sf = StackFrame(this, 4, UseRDX);
        xor(rdx, rdx);
        mov(rax, sf.p[0]);
        add(rax, sf.p[1]);
        add(rax, sf.p[2]);
        add(rax, sf.p[3]);
    }

    /*
        int64_t f(const int64_t a[13]) { return sum-of-a[]; }
    */
    void gen13()
    {
        StackFrame sf = StackFrame(this, 1, 13);
        for (int i = 0; i < 13; i++) {
            mov(sf.t[i], ptr[sf.p[0] + i * 8]);
        }
        mov(rax, sf.t[0]);
        for (int i = 1; i < 13; i++) {
            add(rax, sf.t[i]);
        }
    }
    /*
        same as gen13
    */
    void gen14()
    {
        StackFrame sf = StackFrame(this, 1, 11 | UseRCX | UseRDX);
        Pack t = sf.t;
        t.append(rcx);
        t.append(rdx);
        for (int i = 0; i < 13; i++) {
            mov(t[i], ptr[sf.p[0] + i * 8]);
        }
        mov(rax, t[0]);
        for (int i = 1; i < 13; i++) {
            add(rax, t[i]);
        }
    }
    /*
        return (1 << 15) - 1;
    */
    void gen15()
    {
        StackFrame sf = StackFrame(this, 0, 14, 8);
        Pack t = sf.t;
        t.append(rax);
        for (int i = 0; i < 15; i++) {
            mov(t[i], 1 << i);
        }
        mov(qword[rsp], 0);
        for (int i = 0; i < 15; i++) {
            add(ptr[rsp], t[i]);
        }
        mov(rax, ptr[rsp]);
    }
}

class Code2 : CodeGenerator
{
    this()
    {
        super(4096 * 32);
    }

    void gen(int pNum, int tNum, int stackSizeByte)
    {
        StackFrame sf = StackFrame(this, pNum, tNum, stackSizeByte);
        if (tNum & UseRCX) xor(rcx, rcx);
        if (tNum & UseRDX) xor(rdx, rdx);
        for (int i = 0, n = tNum & ~(UseRCX | UseRDX); i < n; i++) {
            mov(sf.t[i], 5);
        }
        for (int i = 0; i < stackSizeByte; i++) {
            mov(byte_[rsp + i], 0);
        }
        mov(rax, 1);
        for (int i = 0; i < pNum; i++) {
            add(rax, sf.p[i]);
        }
    }

    void gen2(int pNum, int tNum, int stackSizeByte)
    {
        StackFrame sf = StackFrame(this, pNum, tNum, stackSizeByte);
        mov(rax, rsp);
    }
}

void verify(uint8_t* _f, int pNum)
{
    uint8_t* f = cast(uint8_t*)(_f);
    switch (pNum) {
    case 0:
        auto r0 =  cast(int* function()) f;
        assert( 1 == cast(int) r0() );
        return;
    case 1:
        auto r1 =  cast(int* function(int)) f;
        assert( 11 == cast(int) r1(10) );
        return;
    case 2:
        auto r2 =  cast(int* function(int, int)) f;
        assert( 111 == cast(int) r2(10, 100) );
        return;
    case 3:
        auto r3 =  cast(int* function(int, int, int)) f;
        assert( 1111 == cast(int) r3(10, 100, 1000) );
        return;
    case 4:
        auto r4 =  cast(int* function(int, int, int, int)) f;
        assert( 1_1111 == cast(int) r4(10, 100, 1000, 1_0000) );
        return;
    default:
        printf("ERR pNum=%d\n", pNum);
        exit(1);
    }
}


@("param")
unittest
{
    AutoRun autoRun;
    autoRun.reset();
    scope(exit) autoRun.end("param");
    
    scope Code2 code = new Code2;
    for (int stackSize = 0; stackSize < 32; stackSize += 7) {
        for (int pNum = 0; pNum < 4; pNum++) {
            for (int mode = 0; mode < 4; mode++) {
                int maxNum = 0;
                int opt = 0;
                if (mode == 0) {
                    maxNum = 10;
                } else if (mode == 1) {
                    maxNum = 9;
                    opt = UseRCX;
                } else if (mode == 2) {
                    maxNum = 9;
                    opt = UseRDX;
                } else {
                    maxNum = 8;
                    opt = UseRCX | UseRDX;
                }
                for (int tNum = 0; tNum < maxNum; tNum++) {
//                    printf("pNum=%d, tNum=%d, stackSize=%d\n", pNum, tNum | opt, stackSize);
                    uint8_t* f = code.getCurr();
                    code.gen(pNum, tNum | opt, stackSize);
                    verify(f, pNum);
                    /*
                        check rsp is 16-byte aligned if stackSize > 0
                    */
                    if (stackSize > 0) {
                        scope Code2 c2 = new Code2();
                        c2.gen2(pNum, tNum | opt, stackSize);
                        uint64_t addr = cast(uint64_t) c2.getCode!(uint64_t* function())();
                        autoRun.TEST_EQUAL(addr % 16, 0);
                    }
                }
            }
        }
    }
}

@("args")
unittest
{
    AutoRun autoRun;
    autoRun.reset();
    scope(exit) autoRun.end("args");

    scope Code code = new Code();
    auto f1 = code.getCurr!(int function(int))();
    code.gen1();
    autoRun.TEST_EQUAL(5, f1(5));

    auto f2 = code.getCurr!(int function(int, int))();
    code.gen2();
    autoRun.TEST_EQUAL(9, f2(3, 6));

    auto f3 = code.getCurr!(int function(int, int, int))();
    code.gen3();
    autoRun.TEST_EQUAL(14, f3(1, 4, 9));

    auto f4  = code.getCurr!(int function(int, int, int, int))();
    code.gen4();
    autoRun.TEST_EQUAL(30, f4(1, 4, 9, 16));

    auto f5 = code.getCurr!(int function(int, int, int, int))();
    code.gen5();
    autoRun.TEST_EQUAL(23, f5(2, 5, 7, 9));

    auto f6 = code.getCurr!(int function(int, int, int, int))();
    code.gen6();
    autoRun.TEST_EQUAL(18, f6(3, 4, 5, 6));

    auto f7 = code.getCurr!(int function(int, int, int))();
    code.gen7();
    autoRun.TEST_EQUAL(12, f7(3, 4, 5));

    auto f8 = code.getCurr!(int function(int, int, int))();
    code.gen8();
    autoRun.TEST_EQUAL(23, f8(5, 8, 10));
 
    auto f9 = code.getCurr!(int function(int, int, int))();
    code.gen9();
    autoRun.TEST_EQUAL(60, f9(10, 20, 30));

    auto f10 = code.getCurr!(int function(int, int, int, int))();
    code.gen10();
    autoRun.TEST_EQUAL(100, f10(10, 20, 30, 40));

    auto f11 = code.getCurr!(int function())();
    code.gen11();
    autoRun.TEST_EQUAL(3, f11());

    auto f12 = code.getCurr!(int function(int, int, int, int))();
    code.gen12();
    autoRun.TEST_EQUAL(24, f12(3, 5, 7, 9));

    {
        const int64_t[] tbl = [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 ];
        auto f13 = code.getCurr!(int64_t function(const int64_t*))();
        code.gen13();
        autoRun.TEST_EQUAL(91, f13(&tbl[0]));

        auto f14 = code.getCurr!(int64_t function(const int64_t*))();
        code.gen14();
        autoRun.TEST_EQUAL(91, f14(&tbl[0]));
    }

    auto f15 = code.getCurr!(int function())();
    code.gen15();
    autoRun.TEST_EQUAL((1 << 15) - 1, f15());
}


void put(Pack p)
{
    for (size_t i = 0, n = p.size(); i < n; i++) {
        printf("%s ", p[i].toString().ptr);
    }
    printf("\n");
}

void verifyPack(Pack p, int[] tbl, size_t tblNum, ref AutoRun ar)
{
    for (size_t i = 0; i < tblNum; i++) {
        ar.TEST_EQUAL(p[i].getIdx, tbl[i]);
    }
}


@("pack")
unittest
{
    AutoRun autoRun;
    autoRun.reset();
    scope(exit) autoRun.end("pack");

    const int N = 10;
    Reg64[N] regTbl;
    for (int i = 0; i < N; i++) {
        regTbl[i] = new Reg64(i);
    }
    Pack p = Pack(regTbl, N);
    struct Tbl
    {
        int pos;
        int num;
        int[] tbl;

        this(int p, int n, int[] t)
        {
            pos = p;
            num = n;
            tbl = t;
        }

    }
    
    Tbl[] tbl = [
        Tbl( 0, 10, [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 ] ),
        Tbl( 1, 9, [ 1, 2, 3, 4, 5, 6, 7, 8, 9 ] ),
        Tbl( 2, 8, [ 2, 3, 4, 5, 6, 7, 8, 9 ] ),
        Tbl( 3, 7, [ 3, 4, 5, 6, 7, 8, 9 ] ),
        Tbl( 4, 6, [ 4, 5, 6, 7, 8, 9 ] ),
        Tbl( 5, 5, [ 5, 6, 7, 8, 9 ] ),
        Tbl( 6, 4, [ 6, 7, 8, 9 ] ),
        Tbl( 7, 3, [ 7, 8, 9 ] ),
        Tbl( 8, 2, [ 8, 9 ] ),
        Tbl( 9, 1, [ 9 ] ),
        Tbl( 3, 5, [ 3, 4, 5, 6, 7 ] ),
    ];
    for (size_t i = 0; i < tbl.length; i++) {
        const int pos = tbl[i].pos;
        const int num = tbl[i].num;
        verifyPack(p.sub(pos, num), tbl[i].tbl, num, autoRun) ;
        if (pos + num == N) {
            verifyPack(p.sub(pos), tbl[i].tbl, num, autoRun);
        }
    }
}

class CloseCode : CodeGenerator
{
    this(size_t mode)
    {
        super();
        switch (mode) {
        case 0:
            {
                StackFrame sf = StackFrame(this, 0);
                // close() is automatically called.
            }
            break;

        case 1:
            {
                StackFrame sf = StackFrame(this, 0, 0, 0, false);
                sf.close(); // Explicitly call close().
                setProtectModeRE(); // Ensure that no writes occur in destructor by setting read-exec
            }
            break;

        case 2:
            {
                StackFrame sf = StackFrame(this, 0, 0, 0, false);
                sf.close(); // Explicitly call close().
                sf.close(); // Explicitly call close().
                setProtectModeRE(); // Ensure that no writes occur in destructor by setting read-exec
            }
            break;
        default:
            assert(false);
        }
    }
}


@("close")
unittest
{
    AutoRun autoRun;
    autoRun.reset();
    scope(exit) autoRun.end("close");

    const size_t[] expectedTbl = [
        1, 1, 2,
    ];
    for (size_t i = 0; i < expectedTbl.length; i++) {
        scope CloseCode c = new CloseCode(i);
        autoRun.TEST_EQUAL(c.getSize(), expectedTbl[i]);
    }
}



}
