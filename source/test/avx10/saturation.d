module xed_saturation;

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

        //
        vcvtnebf162ibs(xm1, xm2);  dump(); size_ = 0;
        vcvtnebf162ibs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtnebf162ibs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtnebf162ibs(ym1, ym2);  dump(); size_ = 0;
        vcvtnebf162ibs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtnebf162ibs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtnebf162ibs(zm1, zm2);  dump(); size_ = 0;
        vcvtnebf162ibs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtnebf162ibs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvtnebf162iubs(xm1, xm2);  dump(); size_ = 0;
        vcvtnebf162iubs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtnebf162iubs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtnebf162iubs(ym1, ym2);  dump(); size_ = 0;
        vcvtnebf162iubs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtnebf162iubs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtnebf162iubs(zm1, zm2);  dump(); size_ = 0;
        vcvtnebf162iubs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtnebf162iubs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttnebf162ibs(xm1, xm2);  dump(); size_ = 0;
        vcvttnebf162ibs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttnebf162ibs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttnebf162ibs(ym1, ym2);  dump(); size_ = 0;
        vcvttnebf162ibs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttnebf162ibs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttnebf162ibs(zm1, zm2);  dump(); size_ = 0;
        vcvttnebf162ibs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttnebf162ibs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttnebf162iubs(xm1, xm2);  dump(); size_ = 0;
        vcvttnebf162iubs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttnebf162iubs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttnebf162iubs(ym1, ym2);  dump(); size_ = 0;
        vcvttnebf162iubs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttnebf162iubs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttnebf162iubs(zm1, zm2);  dump(); size_ = 0;
        vcvttnebf162iubs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttnebf162iubs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttpd2qqs(xm1, xm2);  dump(); size_ = 0;
        vcvttpd2qqs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttpd2qqs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttpd2qqs(ym1, ym2);  dump(); size_ = 0;
        vcvttpd2qqs(ym1, ym2|T_sae);  dump(); size_ = 0;
        vcvttpd2qqs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttpd2qqs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttpd2qqs(zm1, zm2);  dump(); size_ = 0;
        vcvttpd2qqs(zm1, zm2|T_sae);  dump(); size_ = 0;
        vcvttpd2qqs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttpd2qqs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttpd2uqqs(xm1, xm2);  dump(); size_ = 0;
        vcvttpd2uqqs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttpd2uqqs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttpd2uqqs(ym1, ym2);  dump(); size_ = 0;
        vcvttpd2uqqs(ym1, ym2|T_sae);  dump(); size_ = 0;
        vcvttpd2uqqs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttpd2uqqs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttpd2uqqs(zm1, zm2);  dump(); size_ = 0;
        vcvttpd2uqqs(zm1, zm2|T_sae);  dump(); size_ = 0;
        vcvttpd2uqqs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttpd2uqqs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvtph2ibs(xm1, xm2);  dump(); size_ = 0;
        vcvtph2ibs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtph2ibs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtph2ibs(ym1, ym2);  dump(); size_ = 0;
        vcvtph2ibs(ym1, ym2|T_rd_sae);  dump(); size_ = 0;
        vcvtph2ibs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtph2ibs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtph2ibs(zm1, zm2);  dump(); size_ = 0;
        vcvtph2ibs(zm1, zm2|T_ru_sae);  dump(); size_ = 0;
        vcvtph2ibs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtph2ibs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvtph2iubs(xm1, xm2);  dump(); size_ = 0;
        vcvtph2iubs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtph2iubs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtph2iubs(ym1, ym2);  dump(); size_ = 0;
        vcvtph2iubs(ym1, ym2|T_rd_sae);  dump(); size_ = 0;
        vcvtph2iubs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtph2iubs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtph2iubs(zm1, zm2);  dump(); size_ = 0;
        vcvtph2iubs(zm1, zm2|T_ru_sae);  dump(); size_ = 0;
        vcvtph2iubs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtph2iubs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttph2ibs(xm1, xm2);  dump(); size_ = 0;
        vcvttph2ibs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttph2ibs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttph2ibs(ym1, ym2);  dump(); size_ = 0;
        vcvttph2ibs(ym1, ym2|T_rd_sae);  dump(); size_ = 0;
        vcvttph2ibs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttph2ibs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttph2ibs(zm1, zm2);  dump(); size_ = 0;
        vcvttph2ibs(zm1, zm2|T_ru_sae);  dump(); size_ = 0;
        vcvttph2ibs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttph2ibs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttph2iubs(xm1, xm2);  dump(); size_ = 0;
        vcvttph2iubs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttph2iubs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttph2iubs(ym1, ym2);  dump(); size_ = 0;
        vcvttph2iubs(ym1, ym2|T_rd_sae);  dump(); size_ = 0;
        vcvttph2iubs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttph2iubs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttph2iubs(zm1, zm2);  dump(); size_ = 0;
        vcvttph2iubs(zm1, zm2|T_ru_sae);  dump(); size_ = 0;
        vcvttph2iubs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttph2iubs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttps2dqs(xm1, xm2);  dump(); size_ = 0;
        vcvttps2dqs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2dqs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2dqs(ym1, ym2);  dump(); size_ = 0;
        vcvttps2dqs(ym1, ym2|T_sae);  dump(); size_ = 0;
        vcvttps2dqs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2dqs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2dqs(zm1, zm2);  dump(); size_ = 0;
        vcvttps2dqs(zm1, zm2|T_sae);  dump(); size_ = 0;
        vcvttps2dqs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2dqs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvtps2ibs(xm1, xm2);  dump(); size_ = 0;
        vcvtps2ibs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtps2ibs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtps2ibs(ym1, ym2);  dump(); size_ = 0;
        vcvtps2ibs(ym1, ym2|T_rd_sae);  dump(); size_ = 0;
        vcvtps2ibs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtps2ibs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtps2ibs(zm1, zm2);  dump(); size_ = 0;
        vcvtps2ibs(zm1, zm2|T_ru_sae);  dump(); size_ = 0;
        vcvtps2ibs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtps2ibs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvtps2iubs(xm1, xm2);  dump(); size_ = 0;
        vcvtps2iubs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtps2iubs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtps2iubs(ym1, ym2);  dump(); size_ = 0;
        vcvtps2iubs(ym1, ym2|T_rd_sae);  dump(); size_ = 0;
        vcvtps2iubs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtps2iubs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvtps2iubs(zm1, zm2);  dump(); size_ = 0;
        vcvtps2iubs(zm1, zm2|T_ru_sae);  dump(); size_ = 0;
        vcvtps2iubs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvtps2iubs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttps2ibs(xm1, xm2);  dump(); size_ = 0;
        vcvttps2ibs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2ibs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2ibs(ym1, ym2);  dump(); size_ = 0;
        vcvttps2ibs(ym1, ym2|T_rd_sae);  dump(); size_ = 0;
        vcvttps2ibs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2ibs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2ibs(zm1, zm2);  dump(); size_ = 0;
        vcvttps2ibs(zm1, zm2|T_ru_sae);  dump(); size_ = 0;
        vcvttps2ibs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2ibs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttps2iubs(xm1, xm2);  dump(); size_ = 0;
        vcvttps2iubs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2iubs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2iubs(ym1, ym2);  dump(); size_ = 0;
        vcvttps2iubs(ym1, ym2|T_rd_sae);  dump(); size_ = 0;
        vcvttps2iubs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2iubs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2iubs(zm1, zm2);  dump(); size_ = 0;
        vcvttps2iubs(zm1, zm2|T_ru_sae);  dump(); size_ = 0;
        vcvttps2iubs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2iubs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttps2udqs(xm1, xm2);  dump(); size_ = 0;
        vcvttps2udqs(xm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2udqs(xm1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2udqs(ym1, ym2);  dump(); size_ = 0;
        vcvttps2udqs(ym1, ym2|T_sae);  dump(); size_ = 0;
        vcvttps2udqs(ym1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2udqs(ym1, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2udqs(zm1, zm2);  dump(); size_ = 0;
        vcvttps2udqs(zm1, zm2|T_sae);  dump(); size_ = 0;
        vcvttps2udqs(zm1, ptr[rax+128]);  dump(); size_ = 0;
        vcvttps2udqs(zm1, ptr_b[rax+128]);  dump(); size_ = 0;

        //
        vcvttpd2dqs(xm1|k1|T_z, xm2);  dump(); size_ = 0;
        vcvttpd2dqs(xm1|k1|T_z, xword [rax+128]);  dump(); size_ = 0;
        vcvttpd2dqs(xm1|k1|T_z, xword_b[rax+128]);  dump(); size_ = 0;

        vcvttpd2dqs(xm1|k1|T_z, ym2);  dump(); size_ = 0;
        vcvttpd2dqs(xm1|k1|T_z, ym2|T_sae);  dump(); size_ = 0;
        vcvttpd2dqs(xm1|k1|T_z, yword [rax+128]);  dump(); size_ = 0;
        vcvttpd2dqs(xm1|k1|T_z, yword_b[rax+128]);  dump(); size_ = 0;

        vcvttpd2dqs(ym1|k1|T_z, zm2);  dump(); size_ = 0;
        vcvttpd2dqs(ym1|k1|T_z, zm2|T_sae);  dump(); size_ = 0;
        vcvttpd2dqs(ym1|k1|T_z, zword [rax+128]);  dump(); size_ = 0;
        vcvttpd2dqs(ym1|k1|T_z, zword_b[rax+128]);  dump(); size_ = 0;

        //
        vcvttpd2udqs(xm1|k1|T_z, xm2);  dump(); size_ = 0;
        vcvttpd2udqs(xm1|k1|T_z, xword [rax+128]);  dump(); size_ = 0;
        vcvttpd2udqs(xm1|k1|T_z, xword_b[rax+128]);  dump(); size_ = 0;

        vcvttpd2udqs(xm1|k1|T_z, ym2);  dump(); size_ = 0;
        vcvttpd2udqs(xm1|k1|T_z, ym2|T_sae);  dump(); size_ = 0;
        vcvttpd2udqs(xm1|k1|T_z, yword [rax+128]);  dump(); size_ = 0;
        vcvttpd2udqs(xm1|k1|T_z, yword_b[rax+128]);  dump(); size_ = 0;

        vcvttpd2udqs(ym1|k1|T_z, zm2);  dump(); size_ = 0;
        vcvttpd2udqs(ym1|k1|T_z, zm2|T_sae);  dump(); size_ = 0;
        vcvttpd2udqs(ym1|k1|T_z, zword [rax+128]);  dump(); size_ = 0;
        vcvttpd2udqs(ym1|k1|T_z, zword_b[rax+128]);  dump(); size_ = 0;
        //
        vcvttps2qqs(xm1|k1|T_z, xm2);  dump(); size_ = 0;
        vcvttps2qqs(xm1|k1|T_z, ptr [rax+128]);  dump(); size_ = 0;
        vcvttps2qqs(xm1|k1|T_z, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2qqs(ym1|k1|T_z, xm2);  dump(); size_ = 0;
        vcvttps2qqs(ym1|k1|T_z, xm2|T_sae);  dump(); size_ = 0;
        vcvttps2qqs(ym1|k1|T_z, ptr [rax+128]);  dump(); size_ = 0;
        vcvttps2qqs(ym1|k1|T_z, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2qqs(zm1, ym2);  dump(); size_ = 0;
        vcvttps2qqs(zm1|k1|T_z, ym2);  dump(); size_ = 0;
        vcvttps2qqs(zm1|k1|T_z|T_sae, ym2);  dump(); size_ = 0;
        vcvttps2qqs(zm1|k1|T_z, ptr [rax+128]);  dump(); size_ = 0;
        vcvttps2qqs(zm1|k1|T_z, ptr_b[rax+128]);  dump(); size_ = 0;

        //
        vcvttps2uqqs(xm1|k1|T_z, xm2);  dump(); size_ = 0;
        vcvttps2uqqs(xm1|k1|T_z, ptr [rax+128]);  dump(); size_ = 0;
        vcvttps2uqqs(xm1|k1|T_z, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2uqqs(ym1|k1|T_z, xm2);  dump(); size_ = 0;
        vcvttps2uqqs(ym1|k1|T_z, xm2|T_sae);  dump(); size_ = 0;
        vcvttps2uqqs(ym1|k1|T_z, ptr [rax+128]);  dump(); size_ = 0;
        vcvttps2uqqs(ym1|k1|T_z, ptr_b[rax+128]);  dump(); size_ = 0;

        vcvttps2uqqs(zm1, ym2);  dump(); size_ = 0;
        vcvttps2uqqs(zm1|k1|T_z, ym2);  dump(); size_ = 0;
        vcvttps2uqqs(zm1|k1|T_z|T_sae, ym2);  dump(); size_ = 0;
        vcvttps2uqqs(zm1|k1|T_z, ptr [rax+128]);  dump(); size_ = 0;
        vcvttps2uqqs(zm1|k1|T_z, ptr_b[rax+128]);  dump(); size_ = 0;

        //
        vcvttsd2sis(eax, xm1);  dump(); size_ = 0;
        vcvttsd2sis(eax, xm1|T_sae);  dump(); size_ = 0;
        vcvttsd2sis(eax, ptr[rax+128]);  dump(); size_ = 0;

        vcvttsd2sis(r30, xm1);  dump(); size_ = 0;
        vcvttsd2sis(r30, xm1|T_sae);  dump(); size_ = 0;
        vcvttsd2sis(r30, ptr[rax+128]);  dump(); size_ = 0;
        //
        vcvttsd2usis(eax, xm1);  dump(); size_ = 0;
        vcvttsd2usis(eax, xm1|T_sae);  dump(); size_ = 0;
        vcvttsd2usis(eax, ptr[rax+128]);  dump(); size_ = 0;

        vcvttsd2usis(r30, xm1);  dump(); size_ = 0;
        vcvttsd2usis(r30, xm1|T_sae);  dump(); size_ = 0;
        vcvttsd2usis(r30, ptr[rax+128]);  dump(); size_ = 0;
        //
        vcvttss2sis(eax, xm1);  dump(); size_ = 0;
        vcvttss2sis(eax, xm1|T_sae);  dump(); size_ = 0;
        vcvttss2sis(eax, ptr[rax+128]);  dump(); size_ = 0;

        vcvttss2sis(r30, xm1);  dump(); size_ = 0;
        vcvttss2sis(r30, xm1|T_sae);  dump(); size_ = 0;
        vcvttss2sis(r30, ptr[rax+128]);  dump(); size_ = 0;
        //
        vcvttss2usis(eax, xm1);  dump(); size_ = 0;
        vcvttss2usis(eax, xm1|T_sae);  dump(); size_ = 0;
        vcvttss2usis(eax, ptr[rax+128]);  dump(); size_ = 0;

        vcvttss2usis(r30, xm1);  dump(); size_ = 0;
        vcvttss2usis(r30, xm1|T_sae);  dump(); size_ = 0;
        vcvttss2usis(r30, ptr[rax+128]);  dump(); size_ = 0;
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

@("xed_saturation")
unittest
{
    xed_saturation();
}

void xed_saturation()
{
    //try
    //{
    //    writeln("xed_saturation");
        Code c = new Code();
        auto tbl = c.getCode();
    
        //writeln(c.getSize());    
        //Xdump(tbl, c.getSize());

    //    writeln("end xed_saturation");
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

