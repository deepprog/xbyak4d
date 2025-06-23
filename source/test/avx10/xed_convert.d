module xed_convert;

import std.stdio;
import std.string;
import std.algorithm;
import std.stdint;
import std.exception;
import xbyak;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

version (XBYAK64)
{

    @("xed_convert")
    unittest
    {
        xed_convert();
    }

    void xed_convert()
    {
        writeln("xed_convert");
        scope Code c = new Code();
    }

    class Code : CodeGenerator
    {
        this()
        {
            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);
            vcvt2ps2phx(xm1 | k5, xm2, xm3);
            vcvt2ps2phx(xm1 | k5, xm2, ptr[rax + 128]);
            vcvt2ps2phx(xm1 | k5, xm2, ptr_b[rax + 128]);

            vcvt2ps2phx(ym1 | k5, ym2, ym3);
            vcvt2ps2phx(ym1 | k5, ym2, ptr[rax + 128]);
            vcvt2ps2phx(ym1 | k5, ym2, ptr_b[rax + 128]);

            vcvt2ps2phx(zm1 | k5, zm2, zm3);
            vcvt2ps2phx(zm1 | k5, zm2, ptr[rax + 128]);
            vcvt2ps2phx(zm1 | k5, zm2, ptr_b[rax + 128]);

            // vcvtbiasph2hf8
            vcvtbiasph2bf8(xm1 | k2, xm3, xm5);
            vcvtbiasph2bf8(xm1 | k2, xm3, ptr[rax + 128]);
            vcvtbiasph2bf8(xm1 | k2, xm3, ptr_b[rax + 128]);

            vcvtbiasph2bf8(xm1 | k2, ym3, ym5);
            vcvtbiasph2bf8(xm1 | k2, ym3, ptr[rax + 128]);
            vcvtbiasph2bf8(xm1 | k2, ym3, ptr_b[rax + 128]);

            vcvtbiasph2bf8(ym1 | k2, zm3, zm5);
            vcvtbiasph2bf8(ym1 | k2, zm3, ptr[rax + 128]);
            vcvtbiasph2bf8(ym1 | k2, zm3, ptr_b[rax + 128]);

            // vcvtbiasph2bf8s
            vcvtbiasph2bf8s(xm1 | k2, xm3, xm5);
            vcvtbiasph2bf8s(xm1 | k2, xm3, ptr[rax + 128]);
            vcvtbiasph2bf8s(xm1 | k2, xm3, ptr_b[rax + 128]);

            vcvtbiasph2bf8s(xm1 | k2, ym3, ym5);
            vcvtbiasph2bf8s(xm1 | k2, ym3, ptr[rax + 128]);
            vcvtbiasph2bf8s(xm1 | k2, ym3, ptr_b[rax + 128]);

            vcvtbiasph2bf8s(ym1 | k2, zm3, zm5);
            vcvtbiasph2bf8s(ym1 | k2, zm3, ptr[rax + 128]);
            vcvtbiasph2bf8s(ym1 | k2, zm3, ptr_b[rax + 128]);

            // vcvtbiasph2hf8
            vcvtbiasph2hf8(xm1 | k2, xm3, xm5);
            vcvtbiasph2hf8(xm1 | k2, xm3, ptr[rax + 128]);
            vcvtbiasph2hf8(xm1 | k2, xm3, ptr_b[rax + 128]);

            vcvtbiasph2hf8(xm1 | k2, ym3, ym5);
            vcvtbiasph2hf8(xm1 | k2, ym3, ptr[rax + 128]);
            vcvtbiasph2hf8(xm1 | k2, ym3, ptr_b[rax + 128]);

            vcvtbiasph2hf8(ym1 | k2, zm3, zm5);
            vcvtbiasph2hf8(ym1 | k2, zm3, ptr[rax + 128]);
            vcvtbiasph2hf8(ym1 | k2, zm3, ptr_b[rax + 128]);

            // vcvtbiasph2hf8s
            vcvtbiasph2hf8s(xm1 | k2, xm3, xm5);
            vcvtbiasph2hf8s(xm1 | k2, xm3, ptr[rax + 128]);
            vcvtbiasph2hf8s(xm1 | k2, xm3, ptr_b[rax + 128]);

            vcvtbiasph2hf8s(xm1 | k2, ym3, ym5);
            vcvtbiasph2hf8s(xm1 | k2, ym3, ptr[rax + 128]);
            vcvtbiasph2hf8s(xm1 | k2, ym3, ptr_b[rax + 128]);

            vcvtbiasph2hf8s(ym1 | k2, zm3, zm5);
            vcvtbiasph2hf8s(ym1 | k2, zm3, ptr[rax + 128]);
            vcvtbiasph2hf8s(ym1 | k2, zm3, ptr_b[rax + 128]);

            vcvthf82ph(xm1 | k5 | T_z, xm2);
            vcvthf82ph(xm1 | k5 | T_z, ptr[rax + 128]);

            vcvthf82ph(ym1 | k5 | T_z, xm2);
            vcvthf82ph(ym1 | k5 | T_z, ptr[rax + 128]);

            vcvthf82ph(zm1 | k5 | T_z, ym2);
            vcvthf82ph(zm1 | k5 | T_z, ptr[rax + 128]);

            //
            vcvt2ph2bf8(xm1 | k4 | T_z, xm2, xm3);
            vcvt2ph2bf8(xm1 | k4, xm2, ptr[rax + 128]);
            vcvt2ph2bf8(xm1 | T_z, xm2, ptr_b[rax + 128]);

            vcvt2ph2bf8(ym1 | k4 | T_z, ym2, ym3);
            vcvt2ph2bf8(ym1 | k4, ym2, ptr[rax + 128]);
            vcvt2ph2bf8(ym1 | T_z, ym2, ptr_b[rax + 128]);

            vcvt2ph2bf8(zm1 | k4 | T_z, zm2, zm3);
            vcvt2ph2bf8(zm1 | k4, zm2, ptr[rax + 128]);
            vcvt2ph2bf8(zm1 | T_z, zm2, ptr_b[rax + 128]);

            //
            vcvt2ph2bf8s(xm1 | k4 | T_z, xm2, xm3);
            vcvt2ph2bf8s(xm1 | k4, xm2, ptr[rax + 128]);
            vcvt2ph2bf8s(xm1 | T_z, xm2, ptr_b[rax + 128]);

            vcvt2ph2bf8s(ym1 | k4 | T_z, ym2, ym3);
            vcvt2ph2bf8s(ym1 | k4, ym2, ptr[rax + 128]);
            vcvt2ph2bf8s(ym1 | T_z, ym2, ptr_b[rax + 128]);

            vcvt2ph2bf8s(zm1 | k4 | T_z, zm2, zm3);
            vcvt2ph2bf8s(zm1 | k4, zm2, ptr[rax + 128]);
            vcvt2ph2bf8s(zm1 | T_z, zm2, ptr_b[rax + 128]);

            //
            vcvt2ph2hf8(xm1 | k4 | T_z, xm2, xm3);
            vcvt2ph2hf8(xm1 | k4, xm2, ptr[rax + 128]);
            vcvt2ph2hf8(xm1 | T_z, xm2, ptr_b[rax + 128]);

            vcvt2ph2hf8(ym1 | k4 | T_z, ym2, ym3);
            vcvt2ph2hf8(ym1 | k4, ym2, ptr[rax + 128]);
            vcvt2ph2hf8(ym1 | T_z, ym2, ptr_b[rax + 128]);

            vcvt2ph2hf8(zm1 | k4 | T_z, zm2, zm3);
            vcvt2ph2hf8(zm1 | k4, zm2, ptr[rax + 128]);
            vcvt2ph2hf8(zm1 | T_z, zm2, ptr_b[rax + 128]);

            //
            vcvt2ph2hf8s(xm1 | k4 | T_z, xm2, xm3);
            vcvt2ph2hf8s(xm1 | k4, xm2, ptr[rax + 128]);
            vcvt2ph2hf8s(xm1 | T_z, xm2, ptr_b[rax + 128]);

            vcvt2ph2hf8s(ym1 | k4 | T_z, ym2, ym3);
            vcvt2ph2hf8s(ym1 | k4, ym2, ptr[rax + 128]);
            vcvt2ph2hf8s(ym1 | T_z, ym2, ptr_b[rax + 128]);

            vcvt2ph2hf8s(zm1 | k4 | T_z, zm2, zm3);
            vcvt2ph2hf8s(zm1 | k4, zm2, ptr[rax + 128]);
            vcvt2ph2hf8s(zm1 | T_z, zm2, ptr_b[rax + 128]);

            // vcvtph2bf8
            vcvtph2bf8(xmm1 | k2 | T_z, xmm2);
            vcvtph2bf8(xmm1 | k2 | T_z, xword[rax + 128]);
            vcvtph2bf8(xmm1 | k2 | T_z, xword_b[rax + 128]);

            vcvtph2bf8(xmm1 | k2 | T_z, ymm2);
            vcvtph2bf8(xmm1 | k2 | T_z, yword[rax + 128]);
            vcvtph2bf8(xmm1 | k2 | T_z, yword_b[rax + 128]);

            vcvtph2bf8(ymm1 | k2 | T_z, zmm2);
            vcvtph2bf8(ymm1 | k2 | T_z, zword[rax + 128]);
            vcvtph2bf8(ymm1 | k2 | T_z, zword_b[rax + 128]);

            // vcvtph2bf8s
            vcvtph2bf8s(xmm1 | k2 | T_z, xmm2);
            vcvtph2bf8s(xmm1 | k2 | T_z, xword[rax + 128]);
            vcvtph2bf8s(xmm1 | k2 | T_z, xword_b[rax + 128]);

            vcvtph2bf8s(xmm1 | k2 | T_z, ymm2);
            vcvtph2bf8s(xmm1 | k2 | T_z, yword[rax + 128]);
            vcvtph2bf8s(xmm1 | k2 | T_z, yword_b[rax + 128]);

            vcvtph2bf8s(ymm1 | k2 | T_z, zmm2);
            vcvtph2bf8s(ymm1 | k2 | T_z, zword[rax + 128]);
            vcvtph2bf8s(ymm1 | k2 | T_z, zword_b[rax + 128]);

            // vcvtph2hf8
            vcvtph2hf8(xmm1 | k2 | T_z, xmm2);
            vcvtph2hf8(xmm1 | k2 | T_z, xword[rax + 128]);
            vcvtph2hf8(xmm1 | k2 | T_z, xword_b[rax + 128]);

            vcvtph2hf8(xmm1 | k2 | T_z, ymm2);
            vcvtph2hf8(xmm1 | k2 | T_z, yword[rax + 128]);
            vcvtph2hf8(xmm1 | k2 | T_z, yword_b[rax + 128]);

            vcvtph2hf8(ymm1 | k2 | T_z, zmm2);
            vcvtph2hf8(ymm1 | k2 | T_z, zword[rax + 128]);
            vcvtph2hf8(ymm1 | k2 | T_z, zword_b[rax + 128]);

            // vcvtph2hf8s
            vcvtph2hf8s(xmm1 | k2 | T_z, xmm2);
            vcvtph2hf8s(xmm1 | k2 | T_z, xword[rax + 128]);
            vcvtph2hf8s(xmm1 | k2 | T_z, xword_b[rax + 128]);

            vcvtph2hf8s(xmm1 | k2 | T_z, ymm2);
            vcvtph2hf8s(xmm1 | k2 | T_z, yword[rax + 128]);
            vcvtph2hf8s(xmm1 | k2 | T_z, yword_b[rax + 128]);

            vcvtph2hf8s(ymm1 | k2 | T_z, zmm2);
            vcvtph2hf8s(ymm1 | k2 | T_z, zword[rax + 128]);
            vcvtph2hf8s(ymm1 | k2 | T_z, zword_b[rax + 128]);

            // AVX-NE-CONVERT
            vbcstnebf162ps(xmm15, ptr[rax + 128]);
            vbcstnebf162ps(xmm15, ptr[rax + 128]);

            vbcstnesh2ps(ymm15, ptr[rax + 128]);
            vbcstnesh2ps(ymm15, ptr[rax + 128]);

            vcvtneebf162ps(xmm15, ptr[rax + 128]);
            vcvtneebf162ps(ymm15, ptr[rax + 128]);

            vcvtneeph2ps(xmm15, ptr[rax + 128]);
            vcvtneeph2ps(ymm15, ptr[rax + 128]);

            vcvtneobf162ps(xmm15, ptr[rax + 128]);
            vcvtneobf162ps(ymm15, ptr[rax + 128]);

            vcvtneoph2ps(xmm15, ptr[rax + 128]);
            vcvtneoph2ps(ymm15, ptr[rax + 128]);

            vcvtneps2bf16(xmm15, xmm3, VexEncoding);
            vcvtneps2bf16(xmm15, ptr[rax + 128], VexEncoding);
            vcvtneps2bf16(xmm15, ymm3, VexEncoding);
            vcvtneps2bf16(xmm15, ptr[rax + 128], VexEncoding);
        }
    }
}
