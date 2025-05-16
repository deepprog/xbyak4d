module xed_convert;

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
        vcvt2ps2phx(xm1|k5, xm2, xm3);  dump(); size_ = 0;
        vcvt2ps2phx(xm1|k5, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vcvt2ps2phx(xm1|k5, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvt2ps2phx(ym1|k5, ym2, ym3);  dump(); size_ = 0;
        vcvt2ps2phx(ym1|k5, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vcvt2ps2phx(ym1|k5, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvt2ps2phx(zm1|k5, zm2, zm3);  dump(); size_ = 0;
        vcvt2ps2phx(zm1|k5, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vcvt2ps2phx(zm1|k5, zm2, ptr_b[rax+128]);  dump(); size_ = 0;

        // vcvtbiasph2hf8
        vcvtbiasph2bf8(xm1|k2, xm3, xm5);  dump(); size_ = 0;
        vcvtbiasph2bf8(xm1|k2, xm3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2bf8(xm1|k2, xm3, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtbiasph2bf8(xm1|k2, ym3, ym5);  dump(); size_ = 0;
        vcvtbiasph2bf8(xm1|k2, ym3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2bf8(xm1|k2, ym3, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtbiasph2bf8(ym1|k2, zm3, zm5);  dump(); size_ = 0;
        vcvtbiasph2bf8(ym1|k2, zm3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2bf8(ym1|k2, zm3, ptr_b[rax+128]);  dump(); size_ = 0;

        // vcvtbiasph2bf8s
        vcvtbiasph2bf8s(xm1|k2, xm3, xm5);  dump(); size_ = 0;
        vcvtbiasph2bf8s(xm1|k2, xm3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2bf8s(xm1|k2, xm3, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtbiasph2bf8s(xm1|k2, ym3, ym5);  dump(); size_ = 0;
        vcvtbiasph2bf8s(xm1|k2, ym3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2bf8s(xm1|k2, ym3, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtbiasph2bf8s(ym1|k2, zm3, zm5);  dump(); size_ = 0;
        vcvtbiasph2bf8s(ym1|k2, zm3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2bf8s(ym1|k2, zm3, ptr_b[rax+128]);  dump(); size_ = 0;

        // vcvtbiasph2hf8
        vcvtbiasph2hf8(xm1|k2, xm3, xm5);  dump(); size_ = 0;
        vcvtbiasph2hf8(xm1|k2, xm3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2hf8(xm1|k2, xm3, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtbiasph2hf8(xm1|k2, ym3, ym5);  dump(); size_ = 0;
        vcvtbiasph2hf8(xm1|k2, ym3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2hf8(xm1|k2, ym3, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtbiasph2hf8(ym1|k2, zm3, zm5);  dump(); size_ = 0;
        vcvtbiasph2hf8(ym1|k2, zm3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2hf8(ym1|k2, zm3, ptr_b[rax+128]);  dump(); size_ = 0;

        // vcvtbiasph2hf8s
        vcvtbiasph2hf8s(xm1|k2, xm3, xm5);  dump(); size_ = 0;
        vcvtbiasph2hf8s(xm1|k2, xm3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2hf8s(xm1|k2, xm3, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtbiasph2hf8s(xm1|k2, ym3, ym5);  dump(); size_ = 0;
        vcvtbiasph2hf8s(xm1|k2, ym3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2hf8s(xm1|k2, ym3, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtbiasph2hf8s(ym1|k2, zm3, zm5);  dump(); size_ = 0;
        vcvtbiasph2hf8s(ym1|k2, zm3, ptr[rax+128]);  dump(); size_ = 0;
        vcvtbiasph2hf8s(ym1|k2, zm3, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvthf82ph(xm1|k5|T_z, xm2);  dump(); size_ = 0;
        vcvthf82ph(xm1|k5|T_z, ptr[rax+128]);  dump(); size_ = 0;

        vcvthf82ph(ym1|k5|T_z, xm2);  dump(); size_ = 0;
        vcvthf82ph(ym1|k5|T_z, ptr[rax+128]);  dump(); size_ = 0;

        vcvthf82ph(zm1|k5|T_z, ym2);  dump(); size_ = 0;
        vcvthf82ph(zm1|k5|T_z, ptr[rax+128]);  dump(); size_ = 0;

        //
        vcvtne2ph2bf8(xm1|k4|T_z, xm2, xm3);  dump(); size_ = 0;
        vcvtne2ph2bf8(xm1|k4, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2bf8(xm1|T_z, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtne2ph2bf8(ym1|k4|T_z, ym2, ym3);  dump(); size_ = 0;
        vcvtne2ph2bf8(ym1|k4, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2bf8(ym1|T_z, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtne2ph2bf8(zm1|k4|T_z, zm2, zm3);  dump(); size_ = 0;
        vcvtne2ph2bf8(zm1|k4, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2bf8(zm1|T_z, zm2, ptr_b[rax+128]);  dump(); size_ = 0;

        //
        vcvtne2ph2bf8s(xm1|k4|T_z, xm2, xm3);  dump(); size_ = 0;
        vcvtne2ph2bf8s(xm1|k4, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2bf8s(xm1|T_z, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtne2ph2bf8s(ym1|k4|T_z, ym2, ym3);  dump(); size_ = 0;
        vcvtne2ph2bf8s(ym1|k4, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2bf8s(ym1|T_z, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtne2ph2bf8s(zm1|k4|T_z, zm2, zm3);  dump(); size_ = 0;
        vcvtne2ph2bf8s(zm1|k4, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2bf8s(zm1|T_z, zm2, ptr_b[rax+128]);  dump(); size_ = 0;

        //
        vcvtne2ph2hf8(xm1|k4|T_z, xm2, xm3);  dump(); size_ = 0;
        vcvtne2ph2hf8(xm1|k4, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2hf8(xm1|T_z, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtne2ph2hf8(ym1|k4|T_z, ym2, ym3);  dump(); size_ = 0;
        vcvtne2ph2hf8(ym1|k4, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2hf8(ym1|T_z, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtne2ph2hf8(zm1|k4|T_z, zm2, zm3);  dump(); size_ = 0;
        vcvtne2ph2hf8(zm1|k4, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2hf8(zm1|T_z, zm2, ptr_b[rax+128]);  dump(); size_ = 0;

        //
        vcvtne2ph2hf8s(xm1|k4|T_z, xm2, xm3);  dump(); size_ = 0;
        vcvtne2ph2hf8s(xm1|k4, xm2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2hf8s(xm1|T_z, xm2, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtne2ph2hf8s(ym1|k4|T_z, ym2, ym3);  dump(); size_ = 0;
        vcvtne2ph2hf8s(ym1|k4, ym2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2hf8s(ym1|T_z, ym2, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtne2ph2hf8s(zm1|k4|T_z, zm2, zm3);  dump(); size_ = 0;
        vcvtne2ph2hf8s(zm1|k4, zm2, ptr[rax+128]);  dump(); size_ = 0;
        vcvtne2ph2hf8s(zm1|T_z, zm2, ptr_b[rax+128]);  dump(); size_ = 0;

        // vcvtneph2bf8
        vcvtneph2bf8(xmm1|k2|T_z, xmm2);  dump(); size_ = 0;
        vcvtneph2bf8(xmm1|k2|T_z, xword [rax+128]);  dump(); size_ = 0;
        vcvtneph2bf8(xmm1|k2|T_z, xword_b[rax+128]);  dump(); size_ = 0;

        vcvtneph2bf8(xmm1|k2|T_z, ymm2);  dump(); size_ = 0;
        vcvtneph2bf8(xmm1|k2|T_z, yword[rax+128]);  dump(); size_ = 0;
        vcvtneph2bf8(xmm1|k2|T_z, yword_b[rax+128]);  dump(); size_ = 0;

        vcvtneph2bf8(ymm1|k2|T_z, zmm2);  dump(); size_ = 0;
        vcvtneph2bf8(ymm1|k2|T_z, zword[rax+128]);  dump(); size_ = 0;
        vcvtneph2bf8(ymm1|k2|T_z, zword_b[rax+128]);  dump(); size_ = 0;

        // vcvtneph2bf8s
        vcvtneph2bf8s(xmm1|k2|T_z, xmm2);  dump(); size_ = 0;
        vcvtneph2bf8s(xmm1|k2|T_z, xword [rax+128]);  dump(); size_ = 0;
        vcvtneph2bf8s(xmm1|k2|T_z, xword_b[rax+128]);  dump(); size_ = 0;

        vcvtneph2bf8s(xmm1|k2|T_z, ymm2);  dump(); size_ = 0;
        vcvtneph2bf8s(xmm1|k2|T_z, yword[rax+128]);  dump(); size_ = 0;
        vcvtneph2bf8s(xmm1|k2|T_z, yword_b[rax+128]);  dump(); size_ = 0;

        vcvtneph2bf8s(ymm1|k2|T_z, zmm2);  dump(); size_ = 0;
        vcvtneph2bf8s(ymm1|k2|T_z, zword[rax+128]);  dump(); size_ = 0;
        vcvtneph2bf8s(ymm1|k2|T_z, zword_b[rax+128]);  dump(); size_ = 0;

        // vcvtneph2hf8
        vcvtneph2hf8(xmm1|k2|T_z, xmm2);  dump(); size_ = 0;
        vcvtneph2hf8(xmm1|k2|T_z, xword [rax+128]);  dump(); size_ = 0;
        vcvtneph2hf8(xmm1|k2|T_z, xword_b[rax+128]);  dump(); size_ = 0;

        vcvtneph2hf8(xmm1|k2|T_z, ymm2);  dump(); size_ = 0;
        vcvtneph2hf8(xmm1|k2|T_z, yword[rax+128]);  dump(); size_ = 0;
        vcvtneph2hf8(xmm1|k2|T_z, yword_b[rax+128]);  dump(); size_ = 0;

        vcvtneph2hf8(ymm1|k2|T_z, zmm2);  dump(); size_ = 0;
        vcvtneph2hf8(ymm1|k2|T_z, zword[rax+128]);  dump(); size_ = 0;
        vcvtneph2hf8(ymm1|k2|T_z, zword_b[rax+128]);  dump(); size_ = 0;

        // vcvtneph2hf8s
        vcvtneph2hf8s(xmm1|k2|T_z, xmm2);  dump(); size_ = 0;
        vcvtneph2hf8s(xmm1|k2|T_z, xword [rax+128]);  dump(); size_ = 0;
        vcvtneph2hf8s(xmm1|k2|T_z, xword_b[rax+128]);  dump(); size_ = 0;

        vcvtneph2hf8s(xmm1|k2|T_z, ymm2);  dump(); size_ = 0;
        vcvtneph2hf8s(xmm1|k2|T_z, yword[rax+128]);  dump(); size_ = 0;
        vcvtneph2hf8s(xmm1|k2|T_z, yword_b[rax+128]);  dump(); size_ = 0;

        vcvtneph2hf8s(ymm1|k2|T_z, zmm2);  dump(); size_ = 0;
        vcvtneph2hf8s(ymm1|k2|T_z, zword[rax+128]);  dump(); size_ = 0;
        vcvtneph2hf8s(ymm1|k2|T_z, zword_b[rax+128]);  dump(); size_ = 0;
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

@("xed_convert")
unittest
{
    xed_convert();
}

void xed_convert()
{
    //try
    //{
    //    writeln("xed_convert");
        Code c = new Code();
        auto tbl = c.getCode();
    
        //writeln(c.getSize());    
        //Xdump(tbl, c.getSize());

    //    writeln("end xed_convert");
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

