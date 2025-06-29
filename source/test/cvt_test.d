module cvt_test;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

import std.stdio;
import xbyak;
import test.test_count;

version (XBYAK64)
{
    struct Ptn
    {
        Reg8 reg8;
        Reg16 reg16;
        Reg32 reg32;
        Reg64 reg64;
        Xmm x;
        Ymm y;
        Zmm z;
    }

    Ptn[] tbl = [
        Ptn(al, ax, eax, rax, xmm0, ymm0, zmm0),
        Ptn(bl, bx, ebx, rbx, xmm3, ymm3, zmm3),
        Ptn(cl, cx, ecx, rcx, xmm1, ymm1, zmm1),
        Ptn(dl, dx, edx, rdx, xmm2, ymm2, zmm2),
        Ptn(sil, si, esi, rsi, xmm6, ymm6, zmm6),
        Ptn(dil, di, edi, rdi, xmm7, ymm7, zmm7),
        Ptn(bpl, bp, ebp, rbp, xmm5, ymm5, zmm5),
        Ptn(spl, sp, esp, rsp, xmm4, ymm4, zmm4),
        Ptn(r8b, r8w, r8d, r8, xmm8, ymm8, zmm8),
        Ptn(r9b, r9w, r9d, r9, xmm9, ymm9, zmm9),
        Ptn(r10b, r10w, r10d, r10, xmm10, ymm10, zmm10),
        Ptn(r11b, r11w, r11d, r11, xmm11, ymm11, zmm11),
        Ptn(r12b, r12w, r12d, r12, xmm12, ymm12, zmm12),
        Ptn(r13b, r13w, r13d, r13, xmm13, ymm13, zmm13),
        Ptn(r14b, r14w, r14d, r14, xmm14, ymm14, zmm14),
        Ptn(r15b, r15w, r15d, r15, xmm15, ymm15, zmm15),
        Ptn(r31b, r31w, r31d, r31, xmm31, ymm31, zmm31),
    ];
}
else
{
    struct Ptn
    {
        Reg8 reg8;
        Reg16 reg16;
        Reg32 reg32;
        Xmm x;
        Ymm y;
        Zmm z;
    }

    Ptn[] tbl = [
        Ptn(al, ax, eax, xmm0, ymm0, zmm0),
        Ptn(bl, bx, ebx, xmm3, ymm3, zmm3),
        Ptn(cl, cx, ecx, xmm1, ymm1, zmm1),
        Ptn(dl, dx, edx, xmm2, ymm2, zmm2),
        Ptn(null, si, esi, xmm6, ymm6, zmm6),
        Ptn(null, di, edi, xmm7, ymm7, zmm7),
        Ptn(null, bp, ebp, xmm5, ymm5, zmm5),
        Ptn(null, sp, esp, xmm4, ymm4, zmm4),
    ];
}

@("cvt")
unittest
{
    cvt();
}

void cvt(size_t line = __LINE__)
{
    TestCount tc;
    tc.reset();

    scope (exit)
    {
        writef("%s(%d) : ", __FILE__, line);
        tc.end("cvt");
    }

    for (size_t i = 0; i < tbl.length; i++)
    {
        if (tbl[i].reg8)
        {
            tc.TEST_ASSERT(tbl[i].reg8.cvt8() == tbl[i].reg8);
            tc.TEST_ASSERT(tbl[i].reg8.cvt16() == tbl[i].reg16);
            tc.TEST_ASSERT(tbl[i].reg8.cvt32() == tbl[i].reg32);
            tc.TEST_ASSERT(tbl[i].reg8.cvt128() == tbl[i].x);
            tc.TEST_ASSERT(tbl[i].reg8.cvt256() == tbl[i].y);
            tc.TEST_ASSERT(tbl[i].reg8.cvt512() == tbl[i].z);
            tc.TEST_ASSERT(tbl[i].reg16.cvt8() == tbl[i].reg8);
            tc.TEST_ASSERT(tbl[i].reg32.cvt8() == tbl[i].reg8);
            tc.TEST_ASSERT(tbl[i].x.cvt8() == tbl[i].reg8);
            tc.TEST_ASSERT(tbl[i].y.cvt8() == tbl[i].reg8);
            tc.TEST_ASSERT(tbl[i].z.cvt8() == tbl[i].reg8);
        }
        tc.TEST_ASSERT(tbl[i].reg16.cvt16() == tbl[i].reg16);
        tc.TEST_ASSERT(tbl[i].reg16.cvt32() == tbl[i].reg32);
        tc.TEST_ASSERT(tbl[i].reg16.cvt128() == tbl[i].x);
        tc.TEST_ASSERT(tbl[i].reg16.cvt256() == tbl[i].y);
        tc.TEST_ASSERT(tbl[i].reg16.cvt512() == tbl[i].z);
        tc.TEST_ASSERT(tbl[i].reg32.cvt16() == tbl[i].reg16);
        tc.TEST_ASSERT(tbl[i].reg32.cvt32() == tbl[i].reg32);
        tc.TEST_ASSERT(tbl[i].reg32.cvt128() == tbl[i].x);
        tc.TEST_ASSERT(tbl[i].reg32.cvt256() == tbl[i].y);
        tc.TEST_ASSERT(tbl[i].reg32.cvt512() == tbl[i].z);
        tc.TEST_ASSERT(tbl[i].x.cvt16() == tbl[i].reg16);
        tc.TEST_ASSERT(tbl[i].x.cvt32() == tbl[i].reg32);
        tc.TEST_ASSERT(tbl[i].x.cvt128() == tbl[i].x);
        tc.TEST_ASSERT(tbl[i].x.cvt256() == tbl[i].y);
        tc.TEST_ASSERT(tbl[i].x.cvt512() == tbl[i].z);
        tc.TEST_ASSERT(tbl[i].y.cvt16() == tbl[i].reg16);
        tc.TEST_ASSERT(tbl[i].y.cvt32() == tbl[i].reg32);
        tc.TEST_ASSERT(tbl[i].y.cvt128() == tbl[i].x);
        tc.TEST_ASSERT(tbl[i].y.cvt256() == tbl[i].y);
        tc.TEST_ASSERT(tbl[i].y.cvt512() == tbl[i].z);
        tc.TEST_ASSERT(tbl[i].z.cvt16() == tbl[i].reg16);
        tc.TEST_ASSERT(tbl[i].z.cvt32() == tbl[i].reg32);
        tc.TEST_ASSERT(tbl[i].z.cvt128() == tbl[i].x);
        tc.TEST_ASSERT(tbl[i].z.cvt256() == tbl[i].y);
        tc.TEST_ASSERT(tbl[i].y.cvt512() == tbl[i].z);
        version (XBYAK64)
        {
            if (tbl[i].reg8)
            {
                tc.TEST_ASSERT(tbl[i].reg64.cvt8() == tbl[i].reg8);
                tc.TEST_ASSERT(tbl[i].reg8.cvt64() == tbl[i].reg64);
            }
            tc.TEST_ASSERT(tbl[i].reg64.cvt16() == tbl[i].reg16);
            tc.TEST_ASSERT(tbl[i].reg64.cvt32() == tbl[i].reg32);
            tc.TEST_ASSERT(tbl[i].reg64.cvt64() == tbl[i].reg64);
            tc.TEST_ASSERT(tbl[i].reg64.cvt128() == tbl[i].x);
            tc.TEST_ASSERT(tbl[i].reg64.cvt256() == tbl[i].y);
            tc.TEST_ASSERT(tbl[i].reg64.cvt512() == tbl[i].z);
            tc.TEST_ASSERT(tbl[i].reg16.cvt64() == tbl[i].reg64);
            tc.TEST_ASSERT(tbl[i].reg32.cvt64() == tbl[i].reg64);
            tc.TEST_ASSERT(tbl[i].x.cvt64() == tbl[i].reg64);
            tc.TEST_ASSERT(tbl[i].y.cvt64() == tbl[i].reg64);
            tc.TEST_ASSERT(tbl[i].z.cvt64() == tbl[i].reg64);
        }
    }
    {
        Reg8[] errTbl = [ah, bh, ch, dh];
        for (size_t i = 0; i < errTbl.length; i++)
        {
            tc.TEST_EXCEPTION!Exception({ errTbl[i].cvt16(); });
        }
    }
    version (XBYAK32)
    {
        {
            Reg16[] errTbl = [si, di, bp, sp];
            for (size_t i = 0; i < errTbl.length; i++)
            {
                tc.TEST_EXCEPTION!Exception({ errTbl[i].cvt8(); });
            }
        }
    }
}

@("changeBit")
unittest
{
    changeBit();
}

void changeBit(size_t line = __LINE__)
{
    TestCount tc;
    tc.reset();

    scope (exit)
    {
        writef("%s(%d) : ", __FILE__, line);
        tc.end("changeBit");
    }

    version (XBYAK64)
    {
        const size_t N = 7;
        Reg[N][] tbl = [
            [al, ax, eax, rax, xmm0, ymm0, zmm0],
            [cl, cx, ecx, rcx, xmm1, ymm1, zmm1],
            [dl, dx, edx, rdx, xmm2, ymm2, zmm2],
            [bl, bx, ebx, rbx, xmm3, ymm3, zmm3],
            [spl, sp, esp, rsp, xmm4, ymm4, zmm4],
            [bpl, bp, ebp, rbp, xmm5, ymm5, zmm5],
            [sil, si, esi, rsi, xmm6, ymm6, zmm6],
            [dil, di, edi, rdi, xmm7, ymm7, zmm7],
            [r8b, r8w, r8d, r8, xmm8, ymm8, zmm8],
            [r15b, r15w, r15d, r15, xmm15, ymm15, zmm15],
            [r16b, r16w, r16d, r16, xmm16, ymm16, zmm16],
            [r31b, r31w, r31d, r31, xmm31, ymm31, zmm31],
        ];
        const int[N] bitTbl = [8, 16, 32, 64, 128, 256, 512];
    }
    else
    {
        const size_t N = 6;
        Reg[N][] tbl = [
            [al, ax, eax, xmm0, ymm0, zmm0],
            [cl, cx, ecx, xmm1, ymm1, zmm1],
            [dl, dx, edx, xmm2, ymm2, zmm2],
            [bl, bx, ebx, xmm3, ymm3, zmm3],
            [null, sp, esp, xmm4, ymm4, zmm4],
            [null, bp, ebp, xmm5, ymm5, zmm5],
            [null, si, esi, xmm6, ymm6, zmm6],
            [null, di, edi, xmm7, ymm7, zmm7],
        ];
        const int[N] bitTbl = [8, 16, 32, 128, 256, 512];
    }

    for (size_t i = 0; i < tbl[].length; i++)
    {
        for (size_t j = 0; j < N; j++)
        {
            Reg r1 = tbl[i][j];
            if (r1 is null)
                continue;
            for (size_t k = 0; k < N; k++)
            {
                if (tbl[i][k])
                {
                    // writefln("i:%d j:%d k:%d", i, j, k);
                    tc.TEST_EQUAL(tbl[i][k], r1.changeBit(bitTbl[k]));
                }
                else
                {
                    tc.TEST_EXCEPTION!Exception({ r1.changeBit(bitTbl[k]); });
                }
            }
        }
    }

    version (XBYAK64)
    {
        Reg8[] special8bitTbl = [ah, bh, ch, dh];
        for (size_t i = 0; i < special8bitTbl.length; i++)
        {
            tc.TEST_EXCEPTION!Exception({ special8bitTbl[i].changeBit(16); });
        }
    }
}
