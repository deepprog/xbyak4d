module xed_bf16;

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

    @("xed_bf16")
    unittest
    {
        xed_bf16();
    }

    void xed_bf16()
    {
        writeln("bf16");
        scope Code c = new Code();
    }


    class Code : CodeGenerator
    {
        this()
        {
            super(4096*8);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            vaddbf16(xm1, xm2, xm3);
            vaddbf16(ym1|k1, ym2, ptr[rax+128]);
            vaddbf16(ym1|k1, ym2, ptr_b[rax+128]);
            vaddbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vdivbf16(xm1, xm2, xm3);
            vdivbf16(ym1|k1, ym2, ptr[rax+128]);
            vdivbf16(ym1|k1, ym2, ptr_b[rax+128]);
            vdivbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vmaxbf16(xm1, xm2, xm3);
            vmaxbf16(ym1|k1, ym2, ptr[rax+128]);
            vmaxbf16(ym1|k1, ym2, ptr_b[rax+128]);
            vmaxbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vminbf16(xm1, xm2, xm3);
            vminbf16(ym1|k1, ym2, ptr[rax+128]);
            vminbf16(ym1|k1, ym2, ptr_b[rax+128]);
            vminbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vmulbf16(xm1, xm2, xm3);
            vmulbf16(ym1|k1, ym2, ptr[rax+128]);
            vmulbf16(ym1|k1, ym2, ptr_b[rax+128]);
            vmulbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vscalefbf16(xm1, xm2, xm3);
            vscalefbf16(ym1|k1, ym2, ptr[rax+128]);
            vscalefbf16(ym1|k1, ym2, ptr_b[rax+128]);
            vscalefbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vsubbf16(xm1, xm2, xm3);
            vsubbf16(ym1|k1, ym2, ptr[rax+128]);
            vsubbf16(ym1|k1, ym2, ptr_b[rax+128]);
            vsubbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);
            // madd
            vfmadd132bf16(xm1, xm2, xm3);
            vfmadd132bf16(ym1|k1, ym2, ptr[rax+128]);
            vfmadd132bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfmadd132bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vfmadd213bf16(xm1, xm2, xm3);
            vfmadd213bf16(ym1|k1, ym2, ptr[rax+128]);
            vfmadd213bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfmadd213bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vfmadd231bf16(xm1, xm2, xm3);
            vfmadd231bf16(ym1|k1, ym2, ptr[rax+128]);
            vfmadd231bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfmadd231bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);
            // nmadd
            vfnmadd132bf16(xm1, xm2, xm3);
            vfnmadd132bf16(ym1|k1, ym2, ptr[rax+128]);
            vfnmadd132bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfnmadd132bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vfnmadd213bf16(xm1, xm2, xm3);
            vfnmadd213bf16(ym1|k1, ym2, ptr[rax+128]);
            vfnmadd213bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfnmadd213bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vfnmadd231bf16(xm1, xm2, xm3);
            vfnmadd231bf16(ym1|k1, ym2, ptr[rax+128]);
            vfnmadd231bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfnmadd231bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);
            // msub
            vfmsub132bf16(xm1, xm2, xm3);
            vfmsub132bf16(ym1|k1, ym2, ptr[rax+128]);
            vfmsub132bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfmsub132bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vfmsub213bf16(xm1, xm2, xm3);
            vfmsub213bf16(ym1|k1, ym2, ptr[rax+128]);
            vfmsub213bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfmsub213bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vfmsub231bf16(xm1, xm2, xm3);
            vfmsub231bf16(ym1|k1, ym2, ptr[rax+128]);
            vfmsub231bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfmsub231bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);
            // nmsub
            vfnmsub132bf16(xm1, xm2, xm3);
            vfnmsub132bf16(ym1|k1, ym2, ptr[rax+128]);
            vfnmsub132bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfnmsub132bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vfnmsub213bf16(xm1, xm2, xm3);
            vfnmsub213bf16(ym1|k1, ym2, ptr[rax+128]);
            vfnmsub213bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfnmsub213bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vfnmsub231bf16(xm1, xm2, xm3);
            vfnmsub231bf16(ym1|k1, ym2, ptr[rax+128]);
            vfnmsub231bf16(ym1|k1, ym2, ptr_b[rax+128]);
            vfnmsub231bf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);

            vcmpbf16(k1, xm5, xm4, 5);
            vcmpbf16(k2, ym5, ym4, 6);
            vcmpbf16(k3, ym15, ptr_b[rax+128], 7);
            vcmpbf16(k4, zm30, zm20, 8);
            vcmpbf16(k5, zm1, ptr[rax+128], 9);
            vcmpbf16(k6, zm10, ptr_b[rax+128], 10);

            vfpclassbf16(k1, xm4, 5);
            vfpclassbf16(k2|k5, ym4, 6);
            vfpclassbf16(k3|k5, zm20, 7);
            vfpclassbf16(k3|k5, xword[rax+128], 8);
            vfpclassbf16(k3, xword_b[rax+128], 9);
            vfpclassbf16(k5|k5, yword[rax+128], 10);
            vfpclassbf16(k6|k5, yword_b[rax+128], 11);
            vfpclassbf16(k7|k5, zword[rax+128], 12);
            vfpclassbf16(k7|k5, zword_b[rax+128], 13);

            vcomisbf16(xm2, xm3);
            vcomisbf16(xm2, ptr[rax+128]);

            vgetexpbf16(xm1|k3, xmm2);
            vgetexpbf16(xm1|k3, ptr[rax+128]);
            vgetexpbf16(xm1|k3, ptr_b[rax+128]);

            vgetexpbf16(ym1|k3, ymm2);
            vgetexpbf16(ym1|k3, ptr[rax+128]);
            vgetexpbf16(ym1|k3, ptr_b[rax+128]);

            vgetexpbf16(zm1|k3, zmm2);
            vgetexpbf16(zm1|k3, ptr[rax+128]);
            vgetexpbf16(zm1|k3, ptr_b[rax+128]);

            vgetmantbf16(xm1|k3, xmm2, 3);
            vgetmantbf16(xm1|k3, ptr[rax+128], 5);
            vgetmantbf16(xm1|k3, ptr_b[rax+128], 9);

            vgetmantbf16(ym1|k3, ymm2, 3);
            vgetmantbf16(ym1|k3, ptr[rax+128], 5);
            vgetmantbf16(ym1|k3, ptr_b[rax+128], 9);

            vgetmantbf16(zm1|k3, zmm2, 3);
            vgetmantbf16(zm1|k3, ptr[rax+128], 5);
            vgetmantbf16(zm1|k3, ptr_b[rax+128], 9);

            vrcpbf16(xm1|k5, xm2);
            vrcpbf16(xm1|k5, ptr[rcx+128]);
            vrcpbf16(xm1|k5, ptr_b[rcx+128]);

            vrcpbf16(ym1|k5, ym2);
            vrcpbf16(ym1|k5, ptr[rcx+128]);
            vrcpbf16(ym1|k5, ptr_b[rcx+128]);

            vrcpbf16(zm1|k5, zm2);
            vrcpbf16(zm1|k5, ptr[rcx+128]);
            vrcpbf16(zm1|k5, ptr_b[rcx+128]);

            vreducebf16(xm1|k4, xm2, 1);
            vreducebf16(xm1|k4, ptr[rax+128], 1);
            vreducebf16(xm1|k4, ptr_b[rax+128], 1);

            vreducebf16(ym1|k4, ym2, 1);
            vreducebf16(ym1|k4, ptr[rax+128], 1);
            vreducebf16(ym1|k4, ptr_b[rax+128], 1);

            vreducebf16(zm1|k4, zm2, 1);
            vreducebf16(zm1|k4, ptr[rax+128], 1);
            vreducebf16(zm1|k4, ptr_b[rax+128], 1);

            vrndscalebf16(xm1|k4, xm2, 1);
            vrndscalebf16(xm1|k4, ptr[rax+128], 1);
            vrndscalebf16(xm1|k4, ptr_b[rax+128], 1);

            vrndscalebf16(ym1|k4, ym2, 1);
            vrndscalebf16(ym1|k4, ptr[rax+128], 1);
            vrndscalebf16(ym1|k4, ptr_b[rax+128], 1);

            vrndscalebf16(zm1|k4, zm2, 1);
            vrndscalebf16(zm1|k4, ptr[rax+128], 1);
            vrndscalebf16(zm1|k4, ptr_b[rax+128], 1);

            vrsqrtbf16(xm1|k5, xm2);
            vrsqrtbf16(xm1|k5, ptr[rcx+128]);
            vrsqrtbf16(xm1|k5, ptr_b[rcx+128]);

            vrsqrtbf16(ym1|k5, ym2);
            vrsqrtbf16(ym1|k5, ptr[rcx+128]);
            vrsqrtbf16(ym1|k5, ptr_b[rcx+128]);

            vrsqrtbf16(zm1|k5, zm2);
            vrsqrtbf16(zm1|k5, ptr[rcx+128]);
            vrsqrtbf16(zm1|k5, ptr_b[rcx+128]);

            vscalefbf16(xm1|k5, xm5, xm2);
            vscalefbf16(xm1|k5, xm5, ptr[rcx+128]);
            vscalefbf16(xm1|k5, xm5, ptr_b[rcx+128]);

            vscalefbf16(ym1|k5, ym9, ym2);
            vscalefbf16(ym1|k5, ym9, ptr[rcx+128]);
            vscalefbf16(ym1|k5, ym9, ptr_b[rcx+128]);

            vscalefbf16(zm1|k5, zm30, zm2);
            vscalefbf16(zm1|k5, zm30, ptr[rcx+128]);
            vscalefbf16(zm1|k5, zm30, ptr_b[rcx+128]);

            vsqrtbf16(xm5|k3, xmm4);
            vsqrtbf16(xm5|k3, ptr[rax+128]);
            vsqrtbf16(xm5|k3, ptr_b[rax+128]);

            vsqrtbf16(ym5|k3, ymm4);
            vsqrtbf16(ym5|k3, ptr[rax+128]);
            vsqrtbf16(ym5|k3, ptr_b[rax+128]);

            vsqrtbf16(zm5|k3, zmm4);
            vsqrtbf16(zm5|k3, ptr[rax+128]);
            vsqrtbf16(zm5|k3, ptr_b[rax+128]);
        }
    }
}
