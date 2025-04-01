module 
import std.stdio;xed_bf16;

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

vaddnepbf16(xm1, xm2, xm3); dump();
vaddnepbf16(ym1|k1, ym2, ptr[rax+128]); dump();
vaddnepbf16(ym1|k1, ym2, ptr_b[rax+128]); dump();
vaddnepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]); dump();

vdivnepbf16(xm1, xm2, xm3); dump();
vdivnepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vdivnepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vdivnepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vmaxpbf16(xm1, xm2, xm3);  dump();
vmaxpbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vmaxpbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vmaxpbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vminpbf16(xm1, xm2, xm3);  dump();
vminpbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vminpbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vminpbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vmulnepbf16(xm1, xm2, xm3);  dump();
vmulnepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vmulnepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vmulnepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vscalefpbf16(xm1, xm2, xm3);  dump();
vscalefpbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vscalefpbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vscalefpbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vsubnepbf16(xm1, xm2, xm3);  dump();
vsubnepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vsubnepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vsubnepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();
// madd
vfmadd132nepbf16(xm1, xm2, xm3);  dump();
vfmadd132nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfmadd132nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfmadd132nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vfmadd213nepbf16(xm1, xm2, xm3);  dump();
vfmadd213nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfmadd213nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfmadd213nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vfmadd231nepbf16(xm1, xm2, xm3);  dump();
vfmadd231nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfmadd231nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfmadd231nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();
// nmadd
vfnmadd132nepbf16(xm1, xm2, xm3);  dump();
vfnmadd132nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfnmadd132nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfnmadd132nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vfnmadd213nepbf16(xm1, xm2, xm3);  dump();
vfnmadd213nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfnmadd213nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfnmadd213nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vfnmadd231nepbf16(xm1, xm2, xm3);  dump();
vfnmadd231nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfnmadd231nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfnmadd231nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();
// msub
vfmsub132nepbf16(xm1, xm2, xm3);  dump();
vfmsub132nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfmsub132nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfmsub132nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vfmsub213nepbf16(xm1, xm2, xm3);  dump();
vfmsub213nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfmsub213nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfmsub213nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vfmsub231nepbf16(xm1, xm2, xm3);  dump();
vfmsub231nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfmsub231nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfmsub231nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();
// nmsub
vfnmsub132nepbf16(xm1, xm2, xm3);  dump();
vfnmsub132nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfnmsub132nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfnmsub132nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vfnmsub213nepbf16(xm1, xm2, xm3);  dump();
vfnmsub213nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfnmsub213nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfnmsub213nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vfnmsub231nepbf16(xm1, xm2, xm3);  dump();
vfnmsub231nepbf16(ym1|k1, ym2, ptr[rax+128]);  dump();
vfnmsub231nepbf16(ym1|k1, ym2, ptr_b[rax+128]);  dump();
vfnmsub231nepbf16(zm1|k2|T_z, zm2, ptr_b[rax+128]);  dump();

vcmppbf16(k1, xm5, xm4, 5);  dump();
vcmppbf16(k2, ym5, ym4, 6);  dump();
vcmppbf16(k3, ym15, ptr_b[rax+128], 7);  dump();
vcmppbf16(k4, zm30, zm20, 8);  dump();
vcmppbf16(k5, zm1, ptr[rax+128], 9);  dump();
vcmppbf16(k6, zm10, ptr_b[rax+128], 10);  dump();

vfpclasspbf16(k1, xm4, 5);  dump();
vfpclasspbf16(k2|k5, ym4, 6);  dump();
vfpclasspbf16(k3|k5, zm20, 7);  dump();
vfpclasspbf16(k3|k5, xword[rax+128], 8);  dump();
vfpclasspbf16(k3, xword_b[rax+128], 9);  dump();
vfpclasspbf16(k5|k5, yword[rax+128], 10);  dump();
vfpclasspbf16(k6|k5, yword_b[rax+128], 11);  dump();
vfpclasspbf16(k7|k5, zword[rax+128], 12);  dump();
vfpclasspbf16(k7|k5, zword_b[rax+128], 13);  dump();

vcomsbf16(xm2, xm3);  dump();
vcomsbf16(xm2, ptr[rax+128]);  dump();

vgetexppbf16(xm1|k3, xmm2);  dump();
vgetexppbf16(xm1|k3, ptr[rax+128]);  dump();
vgetexppbf16(xm1|k3, ptr_b[rax+128]);  dump();

vgetexppbf16(ym1|k3, ymm2);  dump();
vgetexppbf16(ym1|k3, ptr[rax+128]);  dump();
vgetexppbf16(ym1|k3, ptr_b[rax+128]);  dump();

vgetexppbf16(zm1|k3, zmm2);  dump();
vgetexppbf16(zm1|k3, ptr[rax+128]);  dump();
vgetexppbf16(zm1|k3, ptr_b[rax+128]);  dump();

vgetmantpbf16(xm1|k3, xmm2, 3);  dump();
vgetmantpbf16(xm1|k3, ptr[rax+128], 5);  dump();
vgetmantpbf16(xm1|k3, ptr_b[rax+128], 9);  dump();

vgetmantpbf16(ym1|k3, ymm2, 3);  dump();
vgetmantpbf16(ym1|k3, ptr[rax+128], 5);  dump();
vgetmantpbf16(ym1|k3, ptr_b[rax+128], 9);  dump();

vgetmantpbf16(zm1|k3, zmm2, 3);  dump();
vgetmantpbf16(zm1|k3, ptr[rax+128], 5);  dump();
vgetmantpbf16(zm1|k3, ptr_b[rax+128], 9);  dump();

vrcppbf16(xm1|k5, xm2);  dump();
vrcppbf16(xm1|k5, ptr[rcx+128]);  dump();
vrcppbf16(xm1|k5, ptr_b[rcx+128]);  dump();

vrcppbf16(ym1|k5, ym2);  dump();
vrcppbf16(ym1|k5, ptr[rcx+128]);  dump();
vrcppbf16(ym1|k5, ptr_b[rcx+128]);  dump();

vrcppbf16(zm1|k5, zm2);  dump();
vrcppbf16(zm1|k5, ptr[rcx+128]);  dump();
vrcppbf16(zm1|k5, ptr_b[rcx+128]);  dump();

vreducenepbf16(xm1|k4, xm2, 1);  dump();
vreducenepbf16(xm1|k4, ptr[rax+128], 1);  dump();
vreducenepbf16(xm1|k4, ptr_b[rax+128], 1);  dump();

vreducenepbf16(ym1|k4, ym2, 1);  dump();
vreducenepbf16(ym1|k4, ptr[rax+128], 1);  dump();
vreducenepbf16(ym1|k4, ptr_b[rax+128], 1);  dump();

vreducenepbf16(zm1|k4, zm2, 1);  dump();
vreducenepbf16(zm1|k4, ptr[rax+128], 1);  dump();
vreducenepbf16(zm1|k4, ptr_b[rax+128], 1);  dump();

vrndscalenepbf16(xm1|k4, xm2, 1);  dump();
vrndscalenepbf16(xm1|k4, ptr[rax+128], 1);  dump();
vrndscalenepbf16(xm1|k4, ptr_b[rax+128], 1);  dump();

vrndscalenepbf16(ym1|k4, ym2, 1);  dump();
vrndscalenepbf16(ym1|k4, ptr[rax+128], 1);  dump();
vrndscalenepbf16(ym1|k4, ptr_b[rax+128], 1);  dump();

vrndscalenepbf16(zm1|k4, zm2, 1);  dump();
vrndscalenepbf16(zm1|k4, ptr[rax+128], 1);  dump();
vrndscalenepbf16(zm1|k4, ptr_b[rax+128], 1);  dump();

vrsqrtpbf16(xm1|k5, xm2);  dump();
vrsqrtpbf16(xm1|k5, ptr[rcx+128]);  dump();
vrsqrtpbf16(xm1|k5, ptr_b[rcx+128]);  dump();

vrsqrtpbf16(ym1|k5, ym2);  dump();
vrsqrtpbf16(ym1|k5, ptr[rcx+128]);  dump();
vrsqrtpbf16(ym1|k5, ptr_b[rcx+128]);  dump();

vrsqrtpbf16(zm1|k5, zm2);  dump();
vrsqrtpbf16(zm1|k5, ptr[rcx+128]);  dump();
vrsqrtpbf16(zm1|k5, ptr_b[rcx+128]);  dump();

vscalefpbf16(xm1|k5, xm5, xm2);  dump();
vscalefpbf16(xm1|k5, xm5, ptr[rcx+128]);  dump();
vscalefpbf16(xm1|k5, xm5, ptr_b[rcx+128]);  dump();

vscalefpbf16(ym1|k5, ym9, ym2);  dump();
vscalefpbf16(ym1|k5, ym9, ptr[rcx+128]);  dump();
vscalefpbf16(ym1|k5, ym9, ptr_b[rcx+128]);  dump();

vscalefpbf16(zm1|k5, zm30, zm2);  dump();
vscalefpbf16(zm1|k5, zm30, ptr[rcx+128]);  dump();
vscalefpbf16(zm1|k5, zm30, ptr_b[rcx+128]);  dump();

vsqrtnepbf16(xm5|k3, xmm4);  dump();
vsqrtnepbf16(xm5|k3, ptr[rax+128]);  dump();
vsqrtnepbf16(xm5|k3, ptr_b[rax+128]);  dump();

vsqrtnepbf16(ym5|k3, ymm4);  dump();
vsqrtnepbf16(ym5|k3, ptr[rax+128]);  dump();
vsqrtnepbf16(ym5|k3, ptr_b[rax+128]);  dump();

vsqrtnepbf16(zm5|k3, zmm4);  dump();
vsqrtnepbf16(zm5|k3, ptr[rax+128]);  dump();
vsqrtnepbf16(zm5|k3, ptr_b[rax+128]);  dump();

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
    //            write(format("%02X", p[i * 16 + j]));
            }
        }
        writeln();
        remain -= disp;
        if (remain <= 0) {
            break;
        }
    }
}

@("xed_bf16")
unittest
{
    xed_bf16();
}

void xed_bf16()
{
    //try
    //{
        writeln("bf16");
        Code c = new Code();
        auto tbl = c.getCode();
    
        //writeln(c.getSize());    
        //Xdump(tbl, c.getSize());

//        writeln("end bf16");
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

