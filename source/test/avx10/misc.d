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
vdpphps(xm1, xm2, xm3);  dump();
vdpphps(xm1, xm2, ptr[rax+128]);  dump();
vdpphps(xm1, xm2, ptr_b[rax+128]);  dump();

vdpphps(ym1, ym2, ym3);  dump();
vdpphps(ym1, ym2, ptr[rax+128]);  dump();
vdpphps(ym1, ym2, ptr_b[rax+128]);  dump();

vdpphps(zm1, zm2, zm3);  dump();
vdpphps(zm1, zm2, ptr[rax+128]);  dump();
vdpphps(zm1, zm2, ptr_b[rax+128]);  dump();
//
vmpsadbw(xm1, xm3, xm15, 3);  dump();
vmpsadbw(xm1|T_z, xm4, ptr[rax+128], 5);  dump();

vmpsadbw(ym1|k4, ym3, ym15, 3);  dump();
vmpsadbw(ym1, ym4, ptr[rax+128], 5);  dump();

vmpsadbw(zm1|k4, zm3, zm15, 3);  dump();
vmpsadbw(zm1, zm4, ptr[rax+128], 5);  dump();
//
vpdpbssd(xm1, xm2, xm3);  dump();
vpdpbssd(xm1, xm2, ptr[rax+128]);  dump();
vpdpbssd(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpbssd(ym1, ym2, ym3);  dump();
vpdpbssd(ym1, ym2, ptr[rax+128]);  dump();
vpdpbssd(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpbssd(zm1, zm2, zm3);  dump();
vpdpbssd(zm1, zm2, ptr[rax+128]);  dump();
vpdpbssd(zm1, zm2, ptr_b[rax+128]);  dump();
//
vpdpbssds(xm1, xm2, xm3);  dump();
vpdpbssds(xm1, xm2, ptr[rax+128]);  dump();
vpdpbssds(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpbssds(ym1, ym2, ym3);  dump();
vpdpbssds(ym1, ym2, ptr[rax+128]);  dump();
vpdpbssds(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpbssds(zm1, zm2, zm3);  dump();
vpdpbssds(zm1, zm2, ptr[rax+128]);  dump();
vpdpbssds(zm1, zm2, ptr_b[rax+128]);  dump();
//
vpdpbsud(xm1, xm2, xm3);  dump();
vpdpbsud(xm1, xm2, ptr[rax+128]);  dump();
vpdpbsud(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpbsud(ym1, ym2, ym3);  dump();
vpdpbsud(ym1, ym2, ptr[rax+128]);  dump();
vpdpbsud(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpbsud(zm1, zm2, zm3);  dump();
vpdpbsud(zm1, zm2, ptr[rax+128]);  dump();
vpdpbsud(zm1, zm2, ptr_b[rax+128]);  dump();
//
vpdpbsuds(xm1, xm2, xm3);  dump();
vpdpbsuds(xm1, xm2, ptr[rax+128]);  dump();
vpdpbsuds(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpbsuds(ym1, ym2, ym3);  dump();
vpdpbsuds(ym1, ym2, ptr[rax+128]);  dump();
vpdpbsuds(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpbsuds(zm1, zm2, zm3);  dump();
vpdpbsuds(zm1, zm2, ptr[rax+128]);  dump();
vpdpbsuds(zm1, zm2, ptr_b[rax+128]);  dump();

//
vpdpbuud(xm1, xm2, xm3);  dump();
vpdpbuud(xm1, xm2, ptr[rax+128]);  dump();
vpdpbuud(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpbuud(ym1, ym2, ym3);  dump();
vpdpbuud(ym1, ym2, ptr[rax+128]);  dump();
vpdpbuud(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpbuud(zm1, zm2, zm3);  dump();
vpdpbuud(zm1, zm2, ptr[rax+128]);  dump();
vpdpbuud(zm1, zm2, ptr_b[rax+128]);  dump();
//
vpdpbuuds(xm1, xm2, xm3);  dump();
vpdpbuuds(xm1, xm2, ptr[rax+128]);  dump();
vpdpbuuds(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpbuuds(ym1, ym2, ym3);  dump();
vpdpbuuds(ym1, ym2, ptr[rax+128]);  dump();
vpdpbuuds(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpbuuds(zm1, zm2, zm3);  dump();
vpdpbuuds(zm1, zm2, ptr[rax+128]);  dump();
vpdpbuuds(zm1, zm2, ptr_b[rax+128]);  dump();

//
vpdpwsud(xm1, xm2, xm3);  dump();
vpdpwsud(xm1, xm2, ptr[rax+128]);  dump();
vpdpwsud(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpwsud(ym1, ym2, ym3);  dump();
vpdpwsud(ym1, ym2, ptr[rax+128]);  dump();
vpdpwsud(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpwsud(zm1, zm2, zm3);  dump();
vpdpwsud(zm1, zm2, ptr[rax+128]);  dump();
vpdpwsud(zm1, zm2, ptr_b[rax+128]);  dump();
//
vpdpwsuds(xm1, xm2, xm3);  dump();
vpdpwsuds(xm1, xm2, ptr[rax+128]);  dump();
vpdpwsuds(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpwsuds(ym1, ym2, ym3);  dump();
vpdpwsuds(ym1, ym2, ptr[rax+128]);  dump();
vpdpwsuds(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpwsuds(zm1, zm2, zm3);  dump();
vpdpwsuds(zm1, zm2, ptr[rax+128]);  dump();
vpdpwsuds(zm1, zm2, ptr_b[rax+128]);  dump();
//
vpdpwsud(xm1, xm2, xm3);  dump();
vpdpwsud(xm1, xm2, ptr[rax+128]);  dump();
vpdpwsud(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpwsud(ym1, ym2, ym3);  dump();
vpdpwsud(ym1, ym2, ptr[rax+128]);  dump();
vpdpwsud(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpwsud(zm1, zm2, zm3);  dump();
vpdpwsud(zm1, zm2, ptr[rax+128]);  dump();
vpdpwsud(zm1, zm2, ptr_b[rax+128]);  dump();
//
vpdpwsuds(xm1, xm2, xm3);  dump();
vpdpwsuds(xm1, xm2, ptr[rax+128]);  dump();
vpdpwsuds(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpwsuds(ym1, ym2, ym3);  dump();
vpdpwsuds(ym1, ym2, ptr[rax+128]);  dump();
vpdpwsuds(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpwsuds(zm1, zm2, zm3);  dump();
vpdpwsuds(zm1, zm2, ptr[rax+128]);  dump();
vpdpwsuds(zm1, zm2, ptr_b[rax+128]);  dump();

//
vpdpwuud(xm1, xm2, xm3);  dump();
vpdpwuud(xm1, xm2, ptr[rax+128]);  dump();
vpdpwuud(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpwuud(ym1, ym2, ym3);  dump();
vpdpwuud(ym1, ym2, ptr[rax+128]);  dump();
vpdpwuud(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpwuud(zm1, zm2, zm3);  dump();
vpdpwuud(zm1, zm2, ptr[rax+128]);  dump();
vpdpwuud(zm1, zm2, ptr_b[rax+128]);  dump();
//
vpdpwuuds(xm1, xm2, xm3);  dump();
vpdpwuuds(xm1, xm2, ptr[rax+128]);  dump();
vpdpwuuds(xm1, xm2, ptr_b[rax+128]);  dump();

vpdpwuuds(ym1, ym2, ym3);  dump();
vpdpwuuds(ym1, ym2, ptr[rax+128]);  dump();
vpdpwuuds(ym1, ym2, ptr_b[rax+128]);  dump();

vpdpwuuds(zm1, zm2, zm3);  dump();
vpdpwuuds(zm1, zm2, ptr[rax+128]);  dump();
vpdpwuuds(zm1, zm2, ptr_b[rax+128]);  dump();

//
vmovd(xm10, xm20);  dump();
vmovd(xm1, xm2);  dump();
vmovd(xm10, ptr[rax+128]);  dump();
vmovd(ptr[rax+128], xm30);  dump();
//
vmovw(xm1, xm20);  dump();
vmovw(xm1, xm2);  dump();
vmovw(xm3, ptr [rax+0x40]);  dump();
vmovw(ptr [rax+0x40], xm7);  dump();


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
        writeln("comp");
        Code c = new Code();
        auto tbl = c.getCode();
    
        //writeln(c.getSize());    
        //Xdump(tbl, c.getSize());

        writeln("end comp");
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

