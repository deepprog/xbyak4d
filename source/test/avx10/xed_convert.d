module xed_convert;

import std.stdio;
import std.string;
import std.algorithm;
import std.stdint;
import std.exception;
import xbyak;

import test.test_count;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

version (XBYAK64)
{

    @("xed_convert")
    unittest
    {
        xed_convert();
    }

    void xed_convert()
    {
        scope Code c = new Code();
    }

    class Code : CodeGenerator
    {
        TestCount testCount;

        void sdump(string hexStr, string file = __FILE__, size_t line = __LINE__)
        {
            if (hexStr.length == 0)
            {
                dump();
                size_ = 0;
                return;
            }

            const size_t n = this.getSize();
            auto ctbl = this.getCode();

            string hexCode;
            for (size_t i = 0; i < n; i++)
            {
                hexCode ~= format("%02X", ctbl[i]);
            }

            testCount.TEST_EQUAL(hexCode, hexStr, file, line);
            size_ = 0;
            return;
        }

        ~this()
        {
            testCount.end("xed_convert");
        }

        this()
        {
            testCount.reset();

            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            vcvt2ps2phx(xm1 | k5, xm2, xm3);
            sdump("62F26D0D67CB");
            vcvt2ps2phx(xm1 | k5, xm2, ptr[rax + 128]);
            sdump("62F26D0D674808");
            vcvt2ps2phx(xm1 | k5, xm2, ptr_b[rax + 128]);
            sdump("62F26D1D674820");

            vcvt2ps2phx(ym1 | k5, ym2, ym3);
            sdump("62F26D2D67CB");
            vcvt2ps2phx(ym1 | k5, ym2, ptr[rax + 128]);
            sdump("62F26D2D674804");
            vcvt2ps2phx(ym1 | k5, ym2, ptr_b[rax + 128]);
            sdump("62F26D3D674820");

            vcvt2ps2phx(zm1 | k5, zm2, zm3);
            sdump("62F26D4D67CB");
            vcvt2ps2phx(zm1 | k5, zm2, ptr[rax + 128]);
            sdump("62F26D4D674802");
            vcvt2ps2phx(zm1 | k5, zm2, ptr_b[rax + 128]);
            sdump("62F26D5D674820");

            // vcvtbiasph2hf8
            vcvtbiasph2bf8(xm1 | k2, xm3, xm5);
            sdump("62F2640A74CD");
            vcvtbiasph2bf8(xm1 | k2, xm3, ptr[rax + 128]);
            sdump("62F2640A744808");
            vcvtbiasph2bf8(xm1 | k2, xm3, ptr_b[rax + 128]);
            sdump("62F2641A744840");

            vcvtbiasph2bf8(xm1 | k2, ym3, ym5);
            sdump("62F2642A74CD");
            vcvtbiasph2bf8(xm1 | k2, ym3, ptr[rax + 128]);
            sdump("62F2642A744804");
            vcvtbiasph2bf8(xm1 | k2, ym3, ptr_b[rax + 128]);
            sdump("62F2643A744840");

            vcvtbiasph2bf8(ym1 | k2, zm3, zm5);
            sdump("62F2644A74CD");
            vcvtbiasph2bf8(ym1 | k2, zm3, ptr[rax + 128]);
            sdump("62F2644A744802");
            vcvtbiasph2bf8(ym1 | k2, zm3, ptr_b[rax + 128]);
            sdump("62F2645A744840");

            // vcvtbiasph2bf8s
            vcvtbiasph2bf8s(xm1 | k2, xm3, xm5);
            sdump("62F5640A74CD");
            vcvtbiasph2bf8s(xm1 | k2, xm3, ptr[rax + 128]);
            sdump("62F5640A744808");
            vcvtbiasph2bf8s(xm1 | k2, xm3, ptr_b[rax + 128]);
            sdump("62F5641A744840");

            vcvtbiasph2bf8s(xm1 | k2, ym3, ym5);
            sdump("62F5642A74CD");
            vcvtbiasph2bf8s(xm1 | k2, ym3, ptr[rax + 128]);
            sdump("62F5642A744804");
            vcvtbiasph2bf8s(xm1 | k2, ym3, ptr_b[rax + 128]);
            sdump("62F5643A744840");

            vcvtbiasph2bf8s(ym1 | k2, zm3, zm5);
            sdump("62F5644A74CD");
            vcvtbiasph2bf8s(ym1 | k2, zm3, ptr[rax + 128]);
            sdump("62F5644A744802");
            vcvtbiasph2bf8s(ym1 | k2, zm3, ptr_b[rax + 128]);
            sdump("62F5645A744840");

            // vcvtbiasph2hf8
            vcvtbiasph2hf8(xm1 | k2, xm3, xm5);
            sdump("62F5640A18CD");
            vcvtbiasph2hf8(xm1 | k2, xm3, ptr[rax + 128]);
            sdump("62F5640A184808");
            vcvtbiasph2hf8(xm1 | k2, xm3, ptr_b[rax + 128]);
            sdump("62F5641A184840");

            vcvtbiasph2hf8(xm1 | k2, ym3, ym5);
            sdump("62F5642A18CD");
            vcvtbiasph2hf8(xm1 | k2, ym3, ptr[rax + 128]);
            sdump("62F5642A184804");
            vcvtbiasph2hf8(xm1 | k2, ym3, ptr_b[rax + 128]);
            sdump("62F5643A184840");

            vcvtbiasph2hf8(ym1 | k2, zm3, zm5);
            sdump("62F5644A18CD");
            vcvtbiasph2hf8(ym1 | k2, zm3, ptr[rax + 128]);
            sdump("62F5644A184802");
            vcvtbiasph2hf8(ym1 | k2, zm3, ptr_b[rax + 128]);
            sdump("62F5645A184840");

            // vcvtbiasph2hf8s
            vcvtbiasph2hf8s(xm1 | k2, xm3, xm5);
            sdump("62F5640A1BCD");
            vcvtbiasph2hf8s(xm1 | k2, xm3, ptr[rax + 128]);
            sdump("62F5640A1B4808");
            vcvtbiasph2hf8s(xm1 | k2, xm3, ptr_b[rax + 128]);
            sdump("62F5641A1B4840");

            vcvtbiasph2hf8s(xm1 | k2, ym3, ym5);
            sdump("62F5642A1BCD");
            vcvtbiasph2hf8s(xm1 | k2, ym3, ptr[rax + 128]);
            sdump("62F5642A1B4804");
            vcvtbiasph2hf8s(xm1 | k2, ym3, ptr_b[rax + 128]);
            sdump("62F5643A1B4840");

            vcvtbiasph2hf8s(ym1 | k2, zm3, zm5);
            sdump("62F5644A1BCD");
            vcvtbiasph2hf8s(ym1 | k2, zm3, ptr[rax + 128]);
            sdump("62F5644A1B4802");
            vcvtbiasph2hf8s(ym1 | k2, zm3, ptr_b[rax + 128]);
            sdump("62F5645A1B4840");

            vcvthf82ph(xm1 | k5 | T_z, xm2);
            sdump("62F57F8D1ECA");
            vcvthf82ph(xm1 | k5 | T_z, ptr[rax + 128]);
            sdump("62F57F8D1E8880000000");

            vcvthf82ph(ym1 | k5 | T_z, xm2);
            sdump("62F57FAD1ECA");
            vcvthf82ph(ym1 | k5 | T_z, ptr[rax + 128]);
            sdump("62F57FAD1E8880000000");

            vcvthf82ph(zm1 | k5 | T_z, ym2);
            sdump("62F57FCD1ECA");
            vcvthf82ph(zm1 | k5 | T_z, ptr[rax + 128]);
            sdump("62F57FCD1E8880000000");

            //
            vcvt2ph2bf8(xm1 | k4 | T_z, xm2, xm3);
            sdump("62F26F8C74CB");
            vcvt2ph2bf8(xm1 | k4, xm2, ptr[rax + 128]);
            sdump("62F26F0C748880000000");
            vcvt2ph2bf8(xm1 | T_z, xm2, ptr_b[rax + 128]);
            sdump("62F26F18744840");

            vcvt2ph2bf8(ym1 | k4 | T_z, ym2, ym3);
            sdump("62F26FAC74CB");
            vcvt2ph2bf8(ym1 | k4, ym2, ptr[rax + 128]);
            sdump("62F26F2C748880000000");
            vcvt2ph2bf8(ym1 | T_z, ym2, ptr_b[rax + 128]);
            sdump("62F26F38744840");

            vcvt2ph2bf8(zm1 | k4 | T_z, zm2, zm3);
            sdump("62F26FCC74CB");
            vcvt2ph2bf8(zm1 | k4, zm2, ptr[rax + 128]);
            sdump("62F26F4C748880000000");
            vcvt2ph2bf8(zm1 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F26F58744840");

            //
            vcvt2ph2bf8s(xm1 | k4 | T_z, xm2, xm3);
            sdump("62F56F8C74CB");
            vcvt2ph2bf8s(xm1 | k4, xm2, ptr[rax + 128]);
            sdump("62F56F0C748880000000");
            vcvt2ph2bf8s(xm1 | T_z, xm2, ptr_b[rax + 128]);
            sdump("62F56F18744840");

            vcvt2ph2bf8s(ym1 | k4 | T_z, ym2, ym3);
            sdump("62F56FAC74CB");
            vcvt2ph2bf8s(ym1 | k4, ym2, ptr[rax + 128]);
            sdump("62F56F2C748880000000");
            vcvt2ph2bf8s(ym1 | T_z, ym2, ptr_b[rax + 128]);
            sdump("62F56F38744840");

            vcvt2ph2bf8s(zm1 | k4 | T_z, zm2, zm3);
            sdump("62F56FCC74CB");
            vcvt2ph2bf8s(zm1 | k4, zm2, ptr[rax + 128]);
            sdump("62F56F4C748880000000");
            vcvt2ph2bf8s(zm1 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F56F58744840");

            //
            vcvt2ph2hf8(xm1 | k4 | T_z, xm2, xm3);
            sdump("62F56F8C18CB");
            vcvt2ph2hf8(xm1 | k4, xm2, ptr[rax + 128]);
            sdump("62F56F0C188880000000");
            vcvt2ph2hf8(xm1 | T_z, xm2, ptr_b[rax + 128]);
            sdump("62F56F18184840");

            vcvt2ph2hf8(ym1 | k4 | T_z, ym2, ym3);
            sdump("62F56FAC18CB");
            vcvt2ph2hf8(ym1 | k4, ym2, ptr[rax + 128]);
            sdump("62F56F2C188880000000");
            vcvt2ph2hf8(ym1 | T_z, ym2, ptr_b[rax + 128]);
            sdump("62F56F38184840");

            vcvt2ph2hf8(zm1 | k4 | T_z, zm2, zm3);
            sdump("62F56FCC18CB");
            vcvt2ph2hf8(zm1 | k4, zm2, ptr[rax + 128]);
            sdump("62F56F4C188880000000");
            vcvt2ph2hf8(zm1 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F56F58184840");

            //
            vcvt2ph2hf8s(xm1 | k4 | T_z, xm2, xm3);
            sdump("62F56F8C1BCB");
            vcvt2ph2hf8s(xm1 | k4, xm2, ptr[rax + 128]);
            sdump("62F56F0C1B8880000000");
            vcvt2ph2hf8s(xm1 | T_z, xm2, ptr_b[rax + 128]);
            sdump("62F56F181B4840");

            vcvt2ph2hf8s(ym1 | k4 | T_z, ym2, ym3);
            sdump("62F56FAC1BCB");
            vcvt2ph2hf8s(ym1 | k4, ym2, ptr[rax + 128]);
            sdump("62F56F2C1B8880000000");
            vcvt2ph2hf8s(ym1 | T_z, ym2, ptr_b[rax + 128]);
            sdump("62F56F381B4840");

            vcvt2ph2hf8s(zm1 | k4 | T_z, zm2, zm3);
            sdump("62F56FCC1BCB");
            vcvt2ph2hf8s(zm1 | k4, zm2, ptr[rax + 128]);
            sdump("62F56F4C1B8880000000");
            vcvt2ph2hf8s(zm1 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F56F581B4840");

            // vcvtph2bf8
            vcvtph2bf8(xmm1 | k2 | T_z, xmm2);
            sdump("62F27E8A74CA");
            vcvtph2bf8(xmm1 | k2 | T_z, xword[rax + 128]);
            sdump("62F27E8A744808");
            vcvtph2bf8(xmm1 | k2 | T_z, xword_b[rax + 128]);
            sdump("62F27E9A744840");

            vcvtph2bf8(xmm1 | k2 | T_z, ymm2);
            sdump("62F27EAA74CA");
            vcvtph2bf8(xmm1 | k2 | T_z, yword[rax + 128]);
            sdump("62F27EAA744804");
            vcvtph2bf8(xmm1 | k2 | T_z, yword_b[rax + 128]);
            sdump("62F27EBA744840");

            vcvtph2bf8(ymm1 | k2 | T_z, zmm2);
            sdump("62F27ECA74CA");
            vcvtph2bf8(ymm1 | k2 | T_z, zword[rax + 128]);
            sdump("62F27ECA744802");
            vcvtph2bf8(ymm1 | k2 | T_z, zword_b[rax + 128]);
            sdump("62F27EDA744840");

            // vcvtph2bf8s
            vcvtph2bf8s(xmm1 | k2 | T_z, xmm2);
            sdump("62F57E8A74CA");
            vcvtph2bf8s(xmm1 | k2 | T_z, xword[rax + 128]);
            sdump("62F57E8A744808");
            vcvtph2bf8s(xmm1 | k2 | T_z, xword_b[rax + 128]);
            sdump("62F57E9A744840");

            vcvtph2bf8s(xmm1 | k2 | T_z, ymm2);
            sdump("62F57EAA74CA");
            vcvtph2bf8s(xmm1 | k2 | T_z, yword[rax + 128]);
            sdump("62F57EAA744804");
            vcvtph2bf8s(xmm1 | k2 | T_z, yword_b[rax + 128]);
            sdump("62F57EBA744840");

            vcvtph2bf8s(ymm1 | k2 | T_z, zmm2);
            sdump("62F57ECA74CA");
            vcvtph2bf8s(ymm1 | k2 | T_z, zword[rax + 128]);
            sdump("62F57ECA744802");
            vcvtph2bf8s(ymm1 | k2 | T_z, zword_b[rax + 128]);
            sdump("62F57EDA744840");

            // vcvtph2hf8                                        
            vcvtph2hf8(xmm1 | k2 | T_z, xmm2);
            sdump("62F57E8A18CA");
            vcvtph2hf8(xmm1 | k2 | T_z, xword[rax + 128]);
            sdump("62F57E8A184808");
            vcvtph2hf8(xmm1 | k2 | T_z, xword_b[rax + 128]);
            sdump("62F57E9A184840");

            vcvtph2hf8(xmm1 | k2 | T_z, ymm2);
            sdump("62F57EAA18CA");
            vcvtph2hf8(xmm1 | k2 | T_z, yword[rax + 128]);
            sdump("62F57EAA184804");
            vcvtph2hf8(xmm1 | k2 | T_z, yword_b[rax + 128]);
            sdump("62F57EBA184840");

            vcvtph2hf8(ymm1 | k2 | T_z, zmm2);
            sdump("62F57ECA18CA");
            vcvtph2hf8(ymm1 | k2 | T_z, zword[rax + 128]);
            sdump("62F57ECA184802");
            vcvtph2hf8(ymm1 | k2 | T_z, zword_b[rax + 128]);
            sdump("62F57EDA184840");

            // vcvtph2hf8s                                      
            vcvtph2hf8s(xmm1 | k2 | T_z, xmm2);
            sdump("62F57E8A1BCA");
            vcvtph2hf8s(xmm1 | k2 | T_z, xword[rax + 128]);
            sdump("62F57E8A1B4808");
            vcvtph2hf8s(xmm1 | k2 | T_z, xword_b[rax + 128]);
            sdump("62F57E9A1B4840");

            vcvtph2hf8s(xmm1 | k2 | T_z, ymm2);
            sdump("62F57EAA1BCA");
            vcvtph2hf8s(xmm1 | k2 | T_z, yword[rax + 128]);
            sdump("62F57EAA1B4804");
            vcvtph2hf8s(xmm1 | k2 | T_z, yword_b[rax + 128]);
            sdump("62F57EBA1B4840");

            vcvtph2hf8s(ymm1 | k2 | T_z, zmm2);
            sdump("62F57ECA1BCA");
            vcvtph2hf8s(ymm1 | k2 | T_z, zword[rax + 128]);
            sdump("62F57ECA1B4802");
            vcvtph2hf8s(ymm1 | k2 | T_z, zword_b[rax + 128]);
            sdump("62F57EDA1B4840");

            // AVX-NE-CONVERT
            vbcstnebf162ps(xmm15, ptr[rax + 128]);
            sdump("C4627AB1B880000000");
            vbcstnebf162ps(xmm15, ptr[rax + 128]);
            sdump("C4627AB1B880000000");

            vbcstnesh2ps(ymm15, ptr[rax + 128]);
            sdump("C4627DB1B880000000");
            vbcstnesh2ps(ymm15, ptr[rax + 128]);
            sdump("C4627DB1B880000000");

            vcvtneebf162ps(xmm15, ptr[rax + 128]);
            sdump("C4627AB0B880000000");
            vcvtneebf162ps(ymm15, ptr[rax + 128]);
            sdump("C4627EB0B880000000");

            vcvtneeph2ps(xmm15, ptr[rax + 128]);
            sdump("C46279B0B880000000");
            vcvtneeph2ps(ymm15, ptr[rax + 128]);
            sdump("C4627DB0B880000000");

            vcvtneobf162ps(xmm15, ptr[rax + 128]);
            sdump("C4627BB0B880000000");
            vcvtneobf162ps(ymm15, ptr[rax + 128]);
            sdump("C4627FB0B880000000");

            vcvtneoph2ps(xmm15, ptr[rax + 128]);
            sdump("C46278B0B880000000");
            vcvtneoph2ps(ymm15, ptr[rax + 128]);
            sdump("C4627CB0B880000000");

            vcvtneps2bf16(xmm15, xmm3, VexEncoding);
            sdump("C4627A72FB");
            vcvtneps2bf16(xmm15, ptr[rax + 128], VexEncoding);
            sdump("C4627A72B880000000");
            vcvtneps2bf16(xmm15, ymm3, VexEncoding);
            sdump("C4627E72FB");
            vcvtneps2bf16(xmm15, ptr[rax + 128], VexEncoding);
            sdump("C4627A72B880000000");

        }
    }
}
