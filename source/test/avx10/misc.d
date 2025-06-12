module xed_misc;

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
    @("xed_misc")
    unittest
    {
        xed_misc();
    }

    void xed_misc()
    {
        writeln("xed_misc");
        scope Code c = new Code();
    }

    class Code : CodeGenerator
    {
        this()
        {
            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            // AVX10 integer and FP16 VNNI, media and zero-extending
            vdpphps(xm1, xm2, xm3);
            vdpphps(xm1, xm2, ptr[rax + 128]);
            vdpphps(xm1, xm2, ptr_b[rax + 128]);

            vdpphps(ym1, ym2, ym3);
            vdpphps(ym1, ym2, ptr[rax + 128]);
            vdpphps(ym1, ym2, ptr_b[rax + 128]);

            vdpphps(zm1, zm2, zm3);
            vdpphps(zm1, zm2, ptr[rax + 128]);
            vdpphps(zm1, zm2, ptr_b[rax + 128]);
            //
            vmpsadbw(xm1, xm3, xm15, 3);
            vmpsadbw(xm1 | T_z, xm4, ptr[rax + 128], 5);

            vmpsadbw(ym1 | k4, ym3, ym15, 3);
            vmpsadbw(ym1, ym4, ptr[rax + 128], 5);

            vmpsadbw(zm1 | k4, zm3, zm15, 3);
            vmpsadbw(zm1, zm4, ptr[rax + 128], 5);
            //
            vpdpbssd(xm1, xm2, xm3);
            vpdpbssd(xm1, xm2, ptr[rax + 128]);
            vpdpbssd(xm1, xm2, ptr_b[rax + 128]);

            vpdpbssd(ym1, ym2, ym3);
            vpdpbssd(ym1, ym2, ptr[rax + 128]);
            vpdpbssd(ym1, ym2, ptr_b[rax + 128]);

            vpdpbssd(zm1, zm2, zm3);
            vpdpbssd(zm1, zm2, ptr[rax + 128]);
            vpdpbssd(zm1, zm2, ptr_b[rax + 128]);
            //
            vpdpbssds(xm1, xm2, xm3);
            vpdpbssds(xm1, xm2, ptr[rax + 128]);
            vpdpbssds(xm1, xm2, ptr_b[rax + 128]);

            vpdpbssds(ym1, ym2, ym3);
            vpdpbssds(ym1, ym2, ptr[rax + 128]);
            vpdpbssds(ym1, ym2, ptr_b[rax + 128]);

            vpdpbssds(zm1, zm2, zm3);
            vpdpbssds(zm1, zm2, ptr[rax + 128]);
            vpdpbssds(zm1, zm2, ptr_b[rax + 128]);
            //
            vpdpbsud(xm1, xm2, xm3);
            vpdpbsud(xm1, xm2, ptr[rax + 128]);
            vpdpbsud(xm1, xm2, ptr_b[rax + 128]);

            vpdpbsud(ym1, ym2, ym3);
            vpdpbsud(ym1, ym2, ptr[rax + 128]);
            vpdpbsud(ym1, ym2, ptr_b[rax + 128]);

            vpdpbsud(zm1, zm2, zm3);
            vpdpbsud(zm1, zm2, ptr[rax + 128]);
            vpdpbsud(zm1, zm2, ptr_b[rax + 128]);
            //
            vpdpbsuds(xm1, xm2, xm3);
            vpdpbsuds(xm1, xm2, ptr[rax + 128]);
            vpdpbsuds(xm1, xm2, ptr_b[rax + 128]);

            vpdpbsuds(ym1, ym2, ym3);
            vpdpbsuds(ym1, ym2, ptr[rax + 128]);
            vpdpbsuds(ym1, ym2, ptr_b[rax + 128]);

            vpdpbsuds(zm1, zm2, zm3);
            vpdpbsuds(zm1, zm2, ptr[rax + 128]);
            vpdpbsuds(zm1, zm2, ptr_b[rax + 128]);

            //
            vpdpbuud(xm1, xm2, xm3);
            vpdpbuud(xm1, xm2, ptr[rax + 128]);
            vpdpbuud(xm1, xm2, ptr_b[rax + 128]);

            vpdpbuud(ym1, ym2, ym3);
            vpdpbuud(ym1, ym2, ptr[rax + 128]);
            vpdpbuud(ym1, ym2, ptr_b[rax + 128]);

            vpdpbuud(zm1, zm2, zm3);
            vpdpbuud(zm1, zm2, ptr[rax + 128]);
            vpdpbuud(zm1, zm2, ptr_b[rax + 128]);
            //
            vpdpbuuds(xm1, xm2, xm3);
            vpdpbuuds(xm1, xm2, ptr[rax + 128]);
            vpdpbuuds(xm1, xm2, ptr_b[rax + 128]);

            vpdpbuuds(ym1, ym2, ym3);
            vpdpbuuds(ym1, ym2, ptr[rax + 128]);
            vpdpbuuds(ym1, ym2, ptr_b[rax + 128]);

            vpdpbuuds(zm1, zm2, zm3);
            vpdpbuuds(zm1, zm2, ptr[rax + 128]);
            vpdpbuuds(zm1, zm2, ptr_b[rax + 128]);

            //
            vpdpwsud(xm1, xm2, xm3);
            vpdpwsud(xm1, xm2, ptr[rax + 128]);
            vpdpwsud(xm1, xm2, ptr_b[rax + 128]);

            vpdpwsud(ym1, ym2, ym3);
            vpdpwsud(ym1, ym2, ptr[rax + 128]);
            vpdpwsud(ym1, ym2, ptr_b[rax + 128]);

            vpdpwsud(zm1, zm2, zm3);
            vpdpwsud(zm1, zm2, ptr[rax + 128]);
            vpdpwsud(zm1, zm2, ptr_b[rax + 128]);
            //
            vpdpwsuds(xm1, xm2, xm3);
            vpdpwsuds(xm1, xm2, ptr[rax + 128]);
            vpdpwsuds(xm1, xm2, ptr_b[rax + 128]);

            vpdpwsuds(ym1, ym2, ym3);
            vpdpwsuds(ym1, ym2, ptr[rax + 128]);
            vpdpwsuds(ym1, ym2, ptr_b[rax + 128]);

            vpdpwsuds(zm1, zm2, zm3);
            vpdpwsuds(zm1, zm2, ptr[rax + 128]);
            vpdpwsuds(zm1, zm2, ptr_b[rax + 128]);
            //
            vpdpwsud(xm1, xm2, xm3);
            vpdpwsud(xm1, xm2, ptr[rax + 128]);
            vpdpwsud(xm1, xm2, ptr_b[rax + 128]);

            vpdpwsud(ym1, ym2, ym3);
            vpdpwsud(ym1, ym2, ptr[rax + 128]);
            vpdpwsud(ym1, ym2, ptr_b[rax + 128]);

            vpdpwsud(zm1, zm2, zm3);
            vpdpwsud(zm1, zm2, ptr[rax + 128]);
            vpdpwsud(zm1, zm2, ptr_b[rax + 128]);
            //
            vpdpwsuds(xm1, xm2, xm3);
            vpdpwsuds(xm1, xm2, ptr[rax + 128]);
            vpdpwsuds(xm1, xm2, ptr_b[rax + 128]);

            vpdpwsuds(ym1, ym2, ym3);
            vpdpwsuds(ym1, ym2, ptr[rax + 128]);
            vpdpwsuds(ym1, ym2, ptr_b[rax + 128]);

            vpdpwsuds(zm1, zm2, zm3);
            vpdpwsuds(zm1, zm2, ptr[rax + 128]);
            vpdpwsuds(zm1, zm2, ptr_b[rax + 128]);

            //
            vpdpwuud(xm1, xm2, xm3);
            vpdpwuud(xm1, xm2, ptr[rax + 128]);
            vpdpwuud(xm1, xm2, ptr_b[rax + 128]);

            vpdpwuud(ym1, ym2, ym3);
            vpdpwuud(ym1, ym2, ptr[rax + 128]);
            vpdpwuud(ym1, ym2, ptr_b[rax + 128]);

            vpdpwuud(zm1, zm2, zm3);
            vpdpwuud(zm1, zm2, ptr[rax + 128]);
            vpdpwuud(zm1, zm2, ptr_b[rax + 128]);
            //
            vpdpwuuds(xm1, xm2, xm3);
            vpdpwuuds(xm1, xm2, ptr[rax + 128]);
            vpdpwuuds(xm1, xm2, ptr_b[rax + 128]);

            vpdpwuuds(ym1, ym2, ym3);
            vpdpwuuds(ym1, ym2, ptr[rax + 128]);
            vpdpwuuds(ym1, ym2, ptr_b[rax + 128]);

            vpdpwuuds(zm1, zm2, zm3);
            vpdpwuuds(zm1, zm2, ptr[rax + 128]);
            vpdpwuuds(zm1, zm2, ptr_b[rax + 128]);

            //
            vmovd(xm10, xm20);
            vmovd(xm1, xm2);
            vmovd(xm10, ptr[rax + 128]);
            vmovd(ptr[rax + 128], xm30);
            //
            vmovw(xm1, xm20);
            vmovw(xm1, xm2);
            vmovw(xm3, ptr[rax + 0x40]);
            vmovw(ptr[rax + 0x40], xm7);
        }
    }
}
