module xed_minmax;

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

        vminmaxbf16(xm1|k3|T_z, xm2, xm3, 5);  dump(); size_ = 0;
        vminmaxbf16(xm1|k3|T_z, xm2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxbf16(xm1|k3|T_z, xm2, ptr_b[rax+128], 5);  dump(); size_ = 0;

        vminmaxbf16(ym1|k3|T_z, ym2, ym3, 5);  dump(); size_ = 0;
        vminmaxbf16(ym1|k3|T_z, ym2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxbf16(ym1|k3|T_z, ym2, ptr_b[rax+128], 5);  dump(); size_ = 0;

        vminmaxbf16(zm1|k3|T_z, zm2, zm3, 5);  dump(); size_ = 0;
        vminmaxbf16(zm1|k3|T_z, zm2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxbf16(zm1|k3|T_z, zm2, ptr_b[rax+128], 5);  dump(); size_ = 0;
        //
        vminmaxpd(xm1|k3|T_z, xm2, xm3, 5);  dump(); size_ = 0;
        vminmaxpd(xm1|k3|T_z, xm2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxpd(xm1|k3|T_z, xm2, ptr_b[rax+128], 5);  dump(); size_ = 0;

        vminmaxpd(ym1|k3|T_z, ym2, ym3, 5);  dump(); size_ = 0;
        vminmaxpd(ym1|k3|T_z, ym2, ym3|T_sae, 5);  dump(); size_ = 0;
        vminmaxpd(ym1|k3|T_z, ym2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxpd(ym1|k3|T_z, ym2, ptr_b[rax+128], 5);  dump(); size_ = 0;

        vminmaxpd(zm1|k3|T_z, zm2, zm3, 5);  dump(); size_ = 0;
        vminmaxpd(zm1|k3|T_z, zm2, zm3|T_sae, 5);  dump(); size_ = 0;
        vminmaxpd(zm1|k3|T_z, zm2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxpd(zm1|k3|T_z, zm2, ptr_b[rax+128], 5);  dump(); size_ = 0;
        //
        vminmaxph(xm1|k3|T_z, xm2, xm3, 5);  dump(); size_ = 0;
        vminmaxph(xm1|k3|T_z, xm2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxph(xm1|k3|T_z, xm2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxph(xm1|k3|T_z, xm2, ptr_b[rax+128], 5);  dump(); size_ = 0;

        vminmaxph(ym1|k3|T_z, ym2, ym3, 5);  dump(); size_ = 0;
        vminmaxph(ym1|k3|T_z, ym2, ym3|T_sae, 5);  dump(); size_ = 0;
        vminmaxph(ym1|k3|T_z, ym2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxph(ym1|k3|T_z, ym2, ptr_b[rax+128], 5);  dump(); size_ = 0;

        vminmaxph(zm1|k3|T_z, zm2, zm3, 5);  dump(); size_ = 0;
        vminmaxph(zm1|k3|T_z, zm2, zm3|T_sae, 5);  dump(); size_ = 0;
        vminmaxph(zm1|k3|T_z, zm2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxph(zm1|k3|T_z, zm2, ptr_b[rax+128], 5);  dump(); size_ = 0;
        //
        vminmaxps(xm1|k3|T_z, xm2, xm3, 5);  dump(); size_ = 0;
        vminmaxps(xm1|k3|T_z, xm2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxps(xm1|k3|T_z, xm2, ptr_b[rax+128], 5);  dump(); size_ = 0;

        vminmaxps(ym1|k3|T_z, ym2, ym3, 5);  dump(); size_ = 0;
        vminmaxps(ym1|k3|T_z, ym2, ym3|T_sae, 5);  dump(); size_ = 0;
        vminmaxps(ym1|k3|T_z, ym2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxps(ym1|k3|T_z, ym2, ptr_b[rax+128], 5);  dump(); size_ = 0;

        vminmaxps(zm1|k3|T_z, zm2, zm3, 5);  dump(); size_ = 0;
        vminmaxps(zm1|k3|T_z, zm2, zm3|T_sae, 5);  dump(); size_ = 0;
        vminmaxps(zm1|k3|T_z, zm2, ptr[rax+128], 5);  dump(); size_ = 0;
        vminmaxps(zm1|k3|T_z, zm2, ptr_b[rax+128], 5);  dump(); size_ = 0;
        //
        vminmaxsd(xm1|k3|T_z, xm2, xm3, 5);  dump(); size_ = 0;
        vminmaxsd(xm1|k3|T_z, xm2, xm3|T_sae, 5);  dump(); size_ = 0;
        vminmaxsd(xm1|k3|T_z, xm2, ptr[rax+128], 5);  dump(); size_ = 0;
        //
        vminmaxsh(xm1|k3|T_z, xm2, xm3, 5);  dump(); size_ = 0;
        vminmaxsh(xm1|k3|T_z, xm2, xm3|T_sae, 5);  dump(); size_ = 0;
        vminmaxsh(xm1|k3|T_z, xm2, ptr[rax+128], 5);  dump(); size_ = 0;
        //
        vminmaxss(xm1|k3|T_z, xm2, xm3, 5);  dump(); size_ = 0;
        vminmaxss(xm1|k3|T_z, xm2, xm3|T_sae, 5);  dump(); size_ = 0;
        vminmaxss(xm1|k3|T_z, xm2, ptr[rax+128], 5);  dump(); size_ = 0;
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

@("xed_minmax")
unittest
{
    xed_minmax();
}

void xed_minmax()
{
    //try
    //{
    //    writeln("xed_minmax");
        scope Code c = new Code();
        auto tbl = c.getCode();
    
        //writeln(c.getSize());
        //Xdump(tbl, c.getSize());

    //    writeln("end xed_minmax");
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

