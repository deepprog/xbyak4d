module xed_minmax;

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
    @("xed_minmax")
    unittest
    {
        xed_minmax();
    }

    void xed_minmax()
    {
        writeln("xed_minmax");
        scope Code c = new Code();
    }

    class Code : CodeGenerator
    {
        this()
        {
            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            vminmaxbf16(xm1 | k3 | T_z, xm2, xm3, 5);
            vminmaxbf16(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            vminmaxbf16(xm1 | k3 | T_z, xm2, ptr_b[rax + 128], 5);

            vminmaxbf16(ym1 | k3 | T_z, ym2, ym3, 5);
            vminmaxbf16(ym1 | k3 | T_z, ym2, ptr[rax + 128], 5);
            vminmaxbf16(ym1 | k3 | T_z, ym2, ptr_b[rax + 128], 5);

            vminmaxbf16(zm1 | k3 | T_z, zm2, zm3, 5);
            vminmaxbf16(zm1 | k3 | T_z, zm2, ptr[rax + 128], 5);
            vminmaxbf16(zm1 | k3 | T_z, zm2, ptr_b[rax + 128], 5);
            //
            vminmaxpd(xm1 | k3 | T_z, xm2, xm3, 5);
            vminmaxpd(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            vminmaxpd(xm1 | k3 | T_z, xm2, ptr_b[rax + 128], 5);

            vminmaxpd(ym1 | k3 | T_z, ym2, ym3, 5);
            vminmaxpd(ym1 | k3 | T_z, ym2, ym3 | T_sae, 5);
            vminmaxpd(ym1 | k3 | T_z, ym2, ptr[rax + 128], 5);
            vminmaxpd(ym1 | k3 | T_z, ym2, ptr_b[rax + 128], 5);

            vminmaxpd(zm1 | k3 | T_z, zm2, zm3, 5);
            vminmaxpd(zm1 | k3 | T_z, zm2, zm3 | T_sae, 5);
            vminmaxpd(zm1 | k3 | T_z, zm2, ptr[rax + 128], 5);
            vminmaxpd(zm1 | k3 | T_z, zm2, ptr_b[rax + 128], 5);
            //
            vminmaxph(xm1 | k3 | T_z, xm2, xm3, 5);
            vminmaxph(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            vminmaxph(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            vminmaxph(xm1 | k3 | T_z, xm2, ptr_b[rax + 128], 5);

            vminmaxph(ym1 | k3 | T_z, ym2, ym3, 5);
            vminmaxph(ym1 | k3 | T_z, ym2, ym3 | T_sae, 5);
            vminmaxph(ym1 | k3 | T_z, ym2, ptr[rax + 128], 5);
            vminmaxph(ym1 | k3 | T_z, ym2, ptr_b[rax + 128], 5);

            vminmaxph(zm1 | k3 | T_z, zm2, zm3, 5);
            vminmaxph(zm1 | k3 | T_z, zm2, zm3 | T_sae, 5);
            vminmaxph(zm1 | k3 | T_z, zm2, ptr[rax + 128], 5);
            vminmaxph(zm1 | k3 | T_z, zm2, ptr_b[rax + 128], 5);
            //
            vminmaxps(xm1 | k3 | T_z, xm2, xm3, 5);
            vminmaxps(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            vminmaxps(xm1 | k3 | T_z, xm2, ptr_b[rax + 128], 5);

            vminmaxps(ym1 | k3 | T_z, ym2, ym3, 5);
            vminmaxps(ym1 | k3 | T_z, ym2, ym3 | T_sae, 5);
            vminmaxps(ym1 | k3 | T_z, ym2, ptr[rax + 128], 5);
            vminmaxps(ym1 | k3 | T_z, ym2, ptr_b[rax + 128], 5);

            vminmaxps(zm1 | k3 | T_z, zm2, zm3, 5);
            vminmaxps(zm1 | k3 | T_z, zm2, zm3 | T_sae, 5);
            vminmaxps(zm1 | k3 | T_z, zm2, ptr[rax + 128], 5);
            vminmaxps(zm1 | k3 | T_z, zm2, ptr_b[rax + 128], 5);
            //
            vminmaxsd(xm1 | k3 | T_z, xm2, xm3, 5);
            vminmaxsd(xm1 | k3 | T_z, xm2, xm3 | T_sae, 5);
            vminmaxsd(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            //
            vminmaxsh(xm1 | k3 | T_z, xm2, xm3, 5);
            vminmaxsh(xm1 | k3 | T_z, xm2, xm3 | T_sae, 5);
            vminmaxsh(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            //
            vminmaxss(xm1 | k3 | T_z, xm2, xm3, 5);
            vminmaxss(xm1 | k3 | T_z, xm2, xm3 | T_sae, 5);
            vminmaxss(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
        }
    }
}
