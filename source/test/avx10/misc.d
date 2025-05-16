module xed_misc;

import std.stdio;
import std.string;
import std.algorithm;
import std.stdint;
import std.exception;
import xbyak;


class Code : CodeGenerator
{
    this()
    {
        super(4096*8);
        setDefaultEncodingAVX10(AVX10v2Encoding);

        // AVX10 integer and FP16 VNNI, media and zero-extending
        vdpphps(xm1, xm2, xm3);  dump(); size_ = 0;
        vdpphps(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vdpphps(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vdpphps(ym1, ym2, ym3);  dump(); size_ = 0;
        vdpphps(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vdpphps(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vdpphps(zm1, zm2, zm3);  dump(); size_ = 0;
        vdpphps(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vdpphps(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vmpsadbw(xm1, xm3, xm15, 3);  dump(); size_ = 0;
        vmpsadbw(xm1|T_z, xm4, ptr[rax+128], 5);  dump(); size_ = 0;

        vmpsadbw(ym1|k4, ym3, ym15, 3);  dump(); size_ = 0;
        vmpsadbw(ym1, ym4, ptr[rax+128], 5);  dump(); size_ = 0;

        vmpsadbw(zm1|k4, zm3, zm15, 3);  dump(); size_ = 0;
        vmpsadbw(zm1, zm4, ptr[rax+128], 5);  dump(); size_ = 0;
        //
        vpdpbssd(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpbssd(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbssd(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbssd(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpbssd(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbssd(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbssd(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpbssd(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbssd(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vpdpbssds(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpbssds(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbssds(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbssds(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpbssds(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbssds(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbssds(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpbssds(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbssds(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vpdpbsud(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpbsud(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbsud(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbsud(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpbsud(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbsud(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbsud(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpbsud(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbsud(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vpdpbsuds(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpbsuds(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbsuds(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbsuds(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpbsuds(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbsuds(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbsuds(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpbsuds(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbsuds(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;

        //
        vpdpbuud(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpbuud(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbuud(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbuud(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpbuud(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbuud(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbuud(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpbuud(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbuud(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vpdpbuuds(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpbuuds(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbuuds(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbuuds(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpbuuds(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbuuds(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpbuuds(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpbuuds(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpbuuds(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;

        //
        vpdpwsud(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpwsud(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsud(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwsud(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpwsud(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsud(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwsud(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpwsud(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsud(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vpdpwsuds(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpwsuds(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsuds(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwsuds(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpwsuds(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsuds(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwsuds(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpwsuds(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsuds(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vpdpwsud(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpwsud(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsud(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwsud(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpwsud(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsud(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwsud(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpwsud(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsud(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vpdpwsuds(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpwsuds(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsuds(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwsuds(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpwsuds(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsuds(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwsuds(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpwsuds(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwsuds(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;

        //
        vpdpwuud(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpwuud(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwuud(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwuud(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpwuud(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwuud(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwuud(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpwuud(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwuud(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vpdpwuuds(xm1, xm2, xm3);  dump(); size_ = 0;
        vpdpwuuds(xm1, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwuuds(xm1, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwuuds(ym1, ym2, ym3);  dump(); size_ = 0;
        vpdpwuuds(ym1, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwuuds(ym1, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vpdpwuuds(zm1, zm2, zm3);  dump(); size_ = 0;
        vpdpwuuds(zm1, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vpdpwuuds(zm1, zm2, ptr_b[rax+128]);  dump(); size_ = 0;

        //
        vmovd(xm10, xm20);  dump(); size_ = 0;
        vmovd(xm1, xm2);  dump(); size_ = 0;
        vmovd(xm10, ptr[rax+128]);  dump(); size_ = 0;
        vmovd(ptr[rax+128], xm30);  dump(); size_ = 0;
        //
        vmovw(xm1, xm20);  dump(); size_ = 0;
        vmovw(xm1, xm2);  dump(); size_ = 0;
        vmovw(xm3, ptr [rax+0x40]);  dump(); size_ = 0;
        vmovw(ptr [rax+0x40], xm7);  dump(); size_ = 0;
    }
}

void Xdump(uint8_t* p, size_t bufSize) 
{
    size_t remain  = bufSize;
    for (int i = 0; i < 4; i++) {
        size_t disp = 16;
        if (remain < 16) {
            disp = remain;
        }
        for (size_t j = 0; j < 16; j++) {
            if (j < disp) {
                write(format("%02X", p[i * 16 + j]));
            }
        }
        writeln();
        remain -= disp;
        if (remain <= 0) {
            break;
        }
    }
}

@("xed_misc")
unittest
{
    xed_misc();
}

void xed_misc()
{
    //try
    //{
    //    writeln("xed_misc");
        Code c = new Code();
        auto tbl = c.getCode();
    
        //writeln(c.getSize());    
        //Xdump(tbl, c.getSize());

    //    writeln("end xed_misc");
    //    FILE *fp = fopen("bin", "wb");
    //    if (fp) {
    //        fwrite(c.getCode(), 1, c.getSize(), fp);
    //        fclose(fp);
    //} 
    //catch (Exception e)
    //{
    //    printf("ERR %s\n", e.what());
    //}
}

