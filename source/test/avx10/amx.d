module test.avx10.amx;

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

    @("amx")
    unittest
    {
        amx();
    }

    void amx()
    {
        writeln("amx");
        scope Code c = new Code();
    }

    class Code : CodeGenerator
    {
        this()
        {
            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            ldtilecfg(ptr[rax + rcx * 4 + 64]);
            ldtilecfg(ptr[r30 + r29 * 4 + 0x12]);
            sttilecfg(ptr[rsp + rax * 8 + 128]);
            sttilecfg(ptr[r30 + r29 * 4 + 0x12]);
            tileloadd(tmm3, ptr[rdi + rdx * 2 + 8]);
            tileloadd(tmm2, ptr[r30 + r29 * 4 + 0x12]);
            tileloaddt1(tmm4, ptr[r8 + r9 + 32]);
            tileloaddt1(tmm7, ptr[r30 + r29 * 4 + 0x12]);
            tilerelease();
            tilestored(ptr[r10 + r11 * 2 + 32], tmm2);
            tilestored(ptr[r30 + r29 * 4 + 0x12], tmm1);
            tilezero(tmm7);
            tdpbssd(tmm1, tmm2, tmm3);
            tdpbsud(tmm2, tmm3, tmm4);
            tdpbusd(tmm3, tmm4, tmm5);
            tdpbuud(tmm4, tmm5, tmm6);
            tdpfp16ps(tmm5, tmm6, tmm7);
            tdpbf16ps(tmm5, tmm6, tmm7);
            tileloadd(tmm1, ptr[r8 + r8]);
            tileloadd(tmm1, ptr[rax + rcx * 4]);
            tileloadd(tmm1, ptr[r8 + r9 * 1 + 0x40]);
            tileloadd(tmm1, ptr[r30 + r29 * 1 + 0x80]);
            tileloaddrs(tmm3, ptr[rdi + rdx * 2 + 8]);
            tileloaddrs(tmm7, ptr[r31 + rdx * 2 + 8]);
            tileloaddrst1(tmm4, ptr[r8 + r9 + 32]);
            tileloaddrst1(tmm4, ptr[r25 + r9 + 32]);

            tdpbf8ps(tmm1, tmm2, tmm3);
            tdpbhf8ps(tmm1, tmm2, tmm3);
            tdphbf8ps(tmm1, tmm2, tmm3);
            tdphf8ps(tmm1, tmm2, tmm3);

            tmmultf32ps(tmm1, tmm2, tmm3);

            t2rpntlvwz0(tmm1, ptr[rax + r8 * 2 + 0x80]);
            t2rpntlvwz0(tmm7, ptr[r30 + r8 * 2 + 0x80]);

            t2rpntlvwz0t1(tmm1, ptr[rax + r8 * 2 + 0x80]);
            t2rpntlvwz0t1(tmm7, ptr[r30 + r8 * 2 + 0x80]);

            t2rpntlvwz1(tmm1, ptr[rax + r8 * 2 + 0x80]);
            t2rpntlvwz1(tmm7, ptr[r30 + r8 * 2 + 0x80]);

            t2rpntlvwz1t1(tmm1, ptr[rax + r8 * 2 + 0x80]);
            t2rpntlvwz1t1(tmm7, ptr[r30 + r8 * 2 + 0x80]);

            t2rpntlvwz0rs(tmm1, ptr[rax + r8 * 2 + 0x80]);
            t2rpntlvwz0rs(tmm7, ptr[r30 + r8 * 2 + 0x80]);

            t2rpntlvwz0rst1(tmm1, ptr[rax + r8 * 2 + 0x80]);
            t2rpntlvwz0rst1(tmm7, ptr[r30 + r8 * 2 + 0x80]);

            t2rpntlvwz1rs(tmm1, ptr[rax + r8 * 2 + 0x80]);
            t2rpntlvwz1rs(tmm7, ptr[r30 + r8 * 2 + 0x80]);

            t2rpntlvwz1rst1(tmm1, ptr[rax + r8 * 2 + 0x80]);
            t2rpntlvwz1rst1(tmm7, ptr[r30 + r8 * 2 + 0x80]);

            tcmmimfp16ps(tmm1, tmm2, tmm3);
            tcmmrlfp16ps(tmm1, tmm2, tmm3);
        }
    }
}
