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
        scope Code c = new Code("xed_convert");
    }

    class Code : TestCode
    {
       this(string name)
        {
            super(name);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            vcvt2ps2phx(xm1 | k5, xm2, xm3);
            sdump("62F26D0D67CB");
            vcvt2ps2phx(xm1 | k5, xm2, ptr[rax + 64]);
            sdump("62F26D0D674804");
            vcvt2ps2phx(xm1 | k5, xm2, ptr_b[rax + 64]);
            sdump("62F26D1D674810");

            vcvt2ps2phx(ym1 | k5, ym2, ym3);
            sdump("62F26D2D67CB");
            vcvt2ps2phx(ym1 | k5, ym2, ptr[rax + 64]);
            sdump("62F26D2D674802");
            vcvt2ps2phx(ym1 | k5, ym2, ptr_b[rax + 64]);
            sdump("62F26D3D674810");

            vcvt2ps2phx(zm1 | k5, zm2, zm3);
            sdump("62F26D4D67CB");
            vcvt2ps2phx(zm1 | k5, zm2, ptr[rax + 64]);
            sdump("62F26D4D674801");
            vcvt2ps2phx(zm1 | k5, zm2, ptr_b[rax + 64]);
            sdump("62F26D5D674810");

            // vcvtbiasph2hf8
            vcvtbiasph2bf8(xm1 | k2, xm3, xm5);
            sdump("62F2640A74CD");
            vcvtbiasph2bf8(xm1 | k2, xm3, ptr[rax + 64]);
            sdump("62F2640A744804");
            vcvtbiasph2bf8(xm1 | k2, xm3, ptr_b[rax + 64]);
            sdump("62F2641A744820");

            vcvtbiasph2bf8(xm1 | k2, ym3, ym5);
            sdump("62F2642A74CD");
            vcvtbiasph2bf8(xm1 | k2, ym3, ptr[rax + 64]);
            sdump("62F2642A744802");
            vcvtbiasph2bf8(xm1 | k2, ym3, ptr_b[rax + 64]);
            sdump("62F2643A744820");

            vcvtbiasph2bf8(ym1 | k2, zm3, zm5);
            sdump("62F2644A74CD");
            vcvtbiasph2bf8(ym1 | k2, zm3, ptr[rax + 64]);
            sdump("62F2644A744801");
            vcvtbiasph2bf8(ym1 | k2, zm3, ptr_b[rax + 64]);
            sdump("62F2645A744820");

            // vcvtbiasph2bf8s
            vcvtbiasph2bf8s(xm1 | k2, xm3, xm5);
            sdump("62F5640A74CD");
            vcvtbiasph2bf8s(xm1 | k2, xm3, ptr[rax + 64]);
            sdump("62F5640A744804");
            vcvtbiasph2bf8s(xm1 | k2, xm3, ptr_b[rax + 64]);
            sdump("62F5641A744820");

            vcvtbiasph2bf8s(xm1 | k2, ym3, ym5);
            sdump("62F5642A74CD");
            vcvtbiasph2bf8s(xm1 | k2, ym3, ptr[rax + 64]);
            sdump("62F5642A744802");
            vcvtbiasph2bf8s(xm1 | k2, ym3, ptr_b[rax + 64]);
            sdump("62F5643A744820");

            vcvtbiasph2bf8s(ym1 | k2, zm3, zm5);
            sdump("62F5644A74CD");
            vcvtbiasph2bf8s(ym1 | k2, zm3, ptr[rax + 64]);
            sdump("62F5644A744801");
            vcvtbiasph2bf8s(ym1 | k2, zm3, ptr_b[rax + 64]);
            sdump("62F5645A744820");

            // vcvtbiasph2hf8
            vcvtbiasph2hf8(xm1 | k2, xm3, xm5);
            sdump("62F5640A18CD");
            vcvtbiasph2hf8(xm1 | k2, xm3, ptr[rax + 64]);
            sdump("62F5640A184804");
            vcvtbiasph2hf8(xm1 | k2, xm3, ptr_b[rax + 64]);
            sdump("62F5641A184820");

            vcvtbiasph2hf8(xm1 | k2, ym3, ym5);
            sdump("62F5642A18CD");
            vcvtbiasph2hf8(xm1 | k2, ym3, ptr[rax + 64]);
            sdump("62F5642A184802");
            vcvtbiasph2hf8(xm1 | k2, ym3, ptr_b[rax + 64]);
            sdump("62F5643A184820");

            vcvtbiasph2hf8(ym1 | k2, zm3, zm5);
            sdump("62F5644A18CD");
            vcvtbiasph2hf8(ym1 | k2, zm3, ptr[rax + 64]);
            sdump("62F5644A184801");
            vcvtbiasph2hf8(ym1 | k2, zm3, ptr_b[rax + 64]);
            sdump("62F5645A184820");

            // vcvtbiasph2hf8s
            vcvtbiasph2hf8s(xm1 | k2, xm3, xm5);
            sdump("62F5640A1BCD");
            vcvtbiasph2hf8s(xm1 | k2, xm3, ptr[rax + 64]);
            sdump("62F5640A1B4804");
            vcvtbiasph2hf8s(xm1 | k2, xm3, ptr_b[rax + 64]);
            sdump("62F5641A1B4820");

            vcvtbiasph2hf8s(xm1 | k2, ym3, ym5);
            sdump("62F5642A1BCD");
            vcvtbiasph2hf8s(xm1 | k2, ym3, ptr[rax + 64]);
            sdump("62F5642A1B4802");
            vcvtbiasph2hf8s(xm1 | k2, ym3, ptr_b[rax + 64]);
            sdump("62F5643A1B4820");

            vcvtbiasph2hf8s(ym1 | k2, zm3, zm5);
            sdump("62F5644A1BCD");
            vcvtbiasph2hf8s(ym1 | k2, zm3, ptr[rax + 64]);
            sdump("62F5644A1B4801");
            vcvtbiasph2hf8s(ym1 | k2, zm3, ptr_b[rax + 64]);
            sdump("62F5645A1B4820");

            vcvthf82ph(xm1 | k5 | T_z, xm2);
            sdump("62F57F8D1ECA");
            vcvthf82ph(xm1 | k5 | T_z, ptr[rax + 64]);
            sdump("62F57F8D1E4808");

            vcvthf82ph(ym1 | k5 | T_z, xm2);
            sdump("62F57FAD1ECA");
            vcvthf82ph(ym1 | k5 | T_z, ptr[rax + 64]);
            sdump("62F57FAD1E4804");

            vcvthf82ph(zm1 | k5 | T_z, ym2);
            sdump("62F57FCD1ECA");
            vcvthf82ph(zm1 | k5 | T_z, ptr[rax + 64]);
            sdump("62F57FCD1E4802");

            //
            vcvt2ph2bf8(xm1 | k4 | T_z, xm2, xm3);
            sdump("62F26F8C74CB");
            vcvt2ph2bf8(xm1 | k4, xm2, ptr[rax + 64]);
            sdump("62F26F0C744804");
            vcvt2ph2bf8(xm1 | T_z, xm2, ptr_b[rax + 64]);
            sdump("62F26F18744820");

            vcvt2ph2bf8(ym1 | k4 | T_z, ym2, ym3);
            sdump("62F26FAC74CB");
            vcvt2ph2bf8(ym1 | k4, ym2, ptr[rax + 64]);
            sdump("62F26F2C744802");
            vcvt2ph2bf8(ym1 | T_z, ym2, ptr_b[rax + 64]);
            sdump("62F26F38744820");

            vcvt2ph2bf8(zm1 | k4 | T_z, zm2, zm3);
            sdump("62F26FCC74CB");
            vcvt2ph2bf8(zm1 | k4, zm2, ptr[rax + 64]);
            sdump("62F26F4C744801");
            vcvt2ph2bf8(zm1 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F26F58744820");

            //
            vcvt2ph2bf8s(xm1 | k4 | T_z, xm2, xm3);
            sdump("62F56F8C74CB");
            vcvt2ph2bf8s(xm1 | k4, xm2, ptr[rax + 64]);
            sdump("62F56F0C744804");
            vcvt2ph2bf8s(xm1 | T_z, xm2, ptr_b[rax + 64]);
            sdump("62F56F18744820");

            vcvt2ph2bf8s(ym1 | k4 | T_z, ym2, ym3);
            sdump("62F56FAC74CB");
            vcvt2ph2bf8s(ym1 | k4, ym2, ptr[rax + 64]);
            sdump("62F56F2C744802");
            vcvt2ph2bf8s(ym1 | T_z, ym2, ptr_b[rax + 64]);
            sdump("62F56F38744820");

            vcvt2ph2bf8s(zm1 | k4 | T_z, zm2, zm3);
            sdump("62F56FCC74CB");
            vcvt2ph2bf8s(zm1 | k4, zm2, ptr[rax + 64]);
            sdump("62F56F4C744801");
            vcvt2ph2bf8s(zm1 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F56F58744820");

            //
            vcvt2ph2hf8(xm1 | k4 | T_z, xm2, xm3);
            sdump("62F56F8C18CB");
            vcvt2ph2hf8(xm1 | k4, xm2, ptr[rax + 64]);
            sdump("62F56F0C184804");
            vcvt2ph2hf8(xm1 | T_z, xm2, ptr_b[rax + 64]);
            sdump("62F56F18184820");

            vcvt2ph2hf8(ym1 | k4 | T_z, ym2, ym3);
            sdump("62F56FAC18CB");
            vcvt2ph2hf8(ym1 | k4, ym2, ptr[rax + 64]);
            sdump("62F56F2C184802");
            vcvt2ph2hf8(ym1 | T_z, ym2, ptr_b[rax + 64]);
            sdump("62F56F38184820");

            vcvt2ph2hf8(zm1 | k4 | T_z, zm2, zm3);
            sdump("62F56FCC18CB");
            vcvt2ph2hf8(zm1 | k4, zm2, ptr[rax + 64]);
            sdump("62F56F4C184801");
            vcvt2ph2hf8(zm1 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F56F58184820");

            //
            vcvt2ph2hf8s(xm1 | k4 | T_z, xm2, xm3);
            sdump("62F56F8C1BCB");
            vcvt2ph2hf8s(xm1 | k4, xm2, ptr[rax + 64]);
            sdump("62F56F0C1B4804");
            vcvt2ph2hf8s(xm1 | T_z, xm2, ptr_b[rax + 64]);
            sdump("62F56F181B4820");

            vcvt2ph2hf8s(ym1 | k4 | T_z, ym2, ym3);
            sdump("62F56FAC1BCB");
            vcvt2ph2hf8s(ym1 | k4, ym2, ptr[rax + 64]);
            sdump("62F56F2C1B4802");
            vcvt2ph2hf8s(ym1 | T_z, ym2, ptr_b[rax + 64]);
            sdump("62F56F381B4820");

            vcvt2ph2hf8s(zm1 | k4 | T_z, zm2, zm3);
            sdump("62F56FCC1BCB");
            vcvt2ph2hf8s(zm1 | k4, zm2, ptr[rax + 64]);
            sdump("62F56F4C1B4801");
            vcvt2ph2hf8s(zm1 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F56F581B4820");

            // vcvtph2bf8
            vcvtph2bf8(xmm1 | k2 | T_z, xmm2);
            sdump("62F27E8A74CA");
            vcvtph2bf8(xmm1 | k2 | T_z, xword[rax + 64]);
            sdump("62F27E8A744804");
            vcvtph2bf8(xmm1 | k2 | T_z, xword_b[rax + 64]);
            sdump("62F27E9A744820");

            vcvtph2bf8(xmm1 | k2 | T_z, ymm2);
            sdump("62F27EAA74CA");
            vcvtph2bf8(xmm1 | k2 | T_z, yword[rax + 64]);
            sdump("62F27EAA744802");
            vcvtph2bf8(xmm1 | k2 | T_z, yword_b[rax + 64]);
            sdump("62F27EBA744820");

            vcvtph2bf8(ymm1 | k2 | T_z, zmm2);
            sdump("62F27ECA74CA");
            vcvtph2bf8(ymm1 | k2 | T_z, zword[rax + 64]);
            sdump("62F27ECA744801");
            vcvtph2bf8(ymm1 | k2 | T_z, zword_b[rax + 64]);
            sdump("62F27EDA744820");

            // vcvtph2bf8s
            vcvtph2bf8s(xmm1 | k2 | T_z, xmm2);
            sdump("62F57E8A74CA");
            vcvtph2bf8s(xmm1 | k2 | T_z, xword[rax + 64]);
            sdump("62F57E8A744804");
            vcvtph2bf8s(xmm1 | k2 | T_z, xword_b[rax + 64]);
            sdump("62F57E9A744820");

            vcvtph2bf8s(xmm1 | k2 | T_z, ymm2);
            sdump("62F57EAA74CA");
            vcvtph2bf8s(xmm1 | k2 | T_z, yword[rax + 64]);
            sdump("62F57EAA744802");
            vcvtph2bf8s(xmm1 | k2 | T_z, yword_b[rax + 64]);
            sdump("62F57EBA744820");

            vcvtph2bf8s(ymm1 | k2 | T_z, zmm2);
            sdump("62F57ECA74CA");
            vcvtph2bf8s(ymm1 | k2 | T_z, zword[rax + 64]);
            sdump("62F57ECA744801");
            vcvtph2bf8s(ymm1 | k2 | T_z, zword_b[rax + 64]);
            sdump("62F57EDA744820");

            // vcvtph2hf8
            vcvtph2hf8(xmm1 | k2 | T_z, xmm2);
            sdump("62F57E8A18CA");
            vcvtph2hf8(xmm1 | k2 | T_z, xword[rax + 64]);
            sdump("62F57E8A184804");
            vcvtph2hf8(xmm1 | k2 | T_z, xword_b[rax + 64]);
            sdump("62F57E9A184820");

            vcvtph2hf8(xmm1 | k2 | T_z, ymm2);
            sdump("62F57EAA18CA");
            vcvtph2hf8(xmm1 | k2 | T_z, yword[rax + 64]);
            sdump("62F57EAA184802");
            vcvtph2hf8(xmm1 | k2 | T_z, yword_b[rax + 64]);
            sdump("62F57EBA184820");

            vcvtph2hf8(ymm1 | k2 | T_z, zmm2);
            sdump("62F57ECA18CA");
            vcvtph2hf8(ymm1 | k2 | T_z, zword[rax + 64]);
            sdump("62F57ECA184801");
            vcvtph2hf8(ymm1 | k2 | T_z, zword_b[rax + 64]);
            sdump("62F57EDA184820");

            // vcvtph2hf8s
            vcvtph2hf8s(xmm1 | k2 | T_z, xmm2);
            sdump("62F57E8A1BCA");
            vcvtph2hf8s(xmm1 | k2 | T_z, xword[rax + 64]);
            sdump("62F57E8A1B4804");
            vcvtph2hf8s(xmm1 | k2 | T_z, xword_b[rax + 64]);
            sdump("62F57E9A1B4820");

            vcvtph2hf8s(xmm1 | k2 | T_z, ymm2);
            sdump("62F57EAA1BCA");
            vcvtph2hf8s(xmm1 | k2 | T_z, yword[rax + 64]);
            sdump("62F57EAA1B4802");
            vcvtph2hf8s(xmm1 | k2 | T_z, yword_b[rax + 64]);
            sdump("62F57EBA1B4820");

            vcvtph2hf8s(ymm1 | k2 | T_z, zmm2);
            sdump("62F57ECA1BCA");
            vcvtph2hf8s(ymm1 | k2 | T_z, zword[rax + 64]);
            sdump("62F57ECA1B4801");
            vcvtph2hf8s(ymm1 | k2 | T_z, zword_b[rax + 64]);
            sdump("62F57EDA1B4820");

            // AVX-NE-CONVERT
            vbcstnebf162ps(xmm15, ptr[rax + 64]);
            sdump("C4627AB17840");
            vbcstnebf162ps(ymm15, ptr[rax + 64]);
            sdump("C4627EB17840");

            vbcstnesh2ps(xmm15, ptr[rax + 64]);
            sdump("C46279B17840");
            vbcstnesh2ps(ymm15, ptr[rax + 64]);
            sdump("C4627DB17840");

            vcvtneebf162ps(xmm15, ptr[rax + 64]);
            sdump("C4627AB07840");
            vcvtneebf162ps(ymm15, ptr[rax + 64]);
            sdump("C4627EB07840");

            vcvtneeph2ps(xmm15, ptr[rax + 64]);
            sdump("C46279B07840");
            vcvtneeph2ps(ymm15, ptr[rax + 64]);
            sdump("C4627DB07840");

            vcvtneobf162ps(xmm15, ptr[rax + 64]);
            sdump("C4627BB07840");
            vcvtneobf162ps(ymm15, ptr[rax + 64]);
            sdump("C4627FB07840");

            vcvtneoph2ps(xmm15, ptr[rax + 64]);
            sdump("C46278B07840");
            vcvtneoph2ps(ymm15, ptr[rax + 64]);
            sdump("C4627CB07840");

            vcvtneps2bf16(xmm15, xmm3, VexEncoding);
            sdump("C4627A72FB");
            vcvtneps2bf16(xmm15, ptr[rax + 64], VexEncoding);
            sdump("C4627A727840");
            vcvtneps2bf16(xmm15, ymm3, VexEncoding);
            sdump("C4627E72FB");
            vcvtneps2bf16(xmm15, ptr[rax + 64], VexEncoding);
            sdump("C4627A727840");

            // GPR-source cvt: EGPR (r16-r31) and {er} (EVEX is forced by T_rd_sae)
            vcvtsi2sd(xm1, xm2, rax); sdump("C4E1EB2AC8");
            vcvtsi2sd(xm1, xm2, r8); sdump("C4C1EB2AC8");
            vcvtsi2sd(xm1, xm2, r16); sdump("62F9EF082AC8");
            vcvtsi2sd(xm1, xm2, r24); sdump("62D9EF082AC8");
            vcvtsi2sd(xm16, xm17, eax); sdump("62E177002AC0");
            vcvtsi2sd(xm18, xm19, r8d); sdump("62C167002AD0");
            vcvtsi2sd(xm24, xm25, r16d); sdump("626937002AC0");
            vcvtsi2sd(xm26, xm27, r24d); sdump("624927002AD0");
            vcvtsi2sd(xm1|T_rd_sae, xm2, rax); sdump("62F1EF382AC8");
            vcvtsi2sd(xm1|T_rd_sae, xm2, r9); sdump("62D1EF382AC9");

            vcvtsi2ss(xm1, xm2, rax); sdump("C4E1EA2AC8");
            vcvtsi2ss(xm1, xm2, r8); sdump("C4C1EA2AC8");
            vcvtsi2ss(xm1, xm2, r16); sdump("62F9EE082AC8");
            vcvtsi2ss(xm1, xm2, r24); sdump("62D9EE082AC8");
            vcvtsi2ss(xm16, xm17, eax); sdump("62E176002AC0");
            vcvtsi2ss(xm18, xm19, r8d); sdump("62C166002AD0");
            vcvtsi2ss(xm24, xm25, r16d); sdump("626936002AC0");
            vcvtsi2ss(xm26, xm27, r24d); sdump("624926002AD0");
            vcvtsi2ss(xm1|T_rd_sae, xm2, rax); sdump("62F1EE382AC8");
            vcvtsi2ss(xm1|T_rd_sae, xm2, r9); sdump("62D1EE382AC9");

            vcvtusi2sd(xm1, xm2, rax); sdump("62F1EF087BC8");
            vcvtusi2sd(xm1, xm2, r8); sdump("62D1EF087BC8");
            vcvtusi2sd(xm1, xm2, r16); sdump("62F9EF087BC8");
            vcvtusi2sd(xm1, xm2, r24); sdump("62D9EF087BC8");
            vcvtusi2sd(xm16, xm17, eax); sdump("62E177007BC0");
            vcvtusi2sd(xm18, xm19, r8d); sdump("62C167007BD0");
            vcvtusi2sd(xm24, xm25, r16d); sdump("626937007BC0");
            vcvtusi2sd(xm26, xm27, r24d); sdump("624927007BD0");
            vcvtusi2sd(xm1|T_rd_sae, xm2, rax); sdump("62F1EF387BC8");
            vcvtusi2sd(xm1|T_rd_sae, xm2, r9); sdump("62D1EF387BC9");

            vcvtusi2ss(xm1, xm2, rax); sdump("62F1EE087BC8");
            vcvtusi2ss(xm1, xm2, r8); sdump("62D1EE087BC8");
            vcvtusi2ss(xm1, xm2, r16); sdump("62F9EE087BC8");
            vcvtusi2ss(xm1, xm2, r24); sdump("62D9EE087BC8");
            vcvtusi2ss(xm16, xm17, eax); sdump("62E176007BC0");
            vcvtusi2ss(xm18, xm19, r8d); sdump("62C166007BD0");
            vcvtusi2ss(xm24, xm25, r16d); sdump("626936007BC0");
            vcvtusi2ss(xm26, xm27, r24d); sdump("624926007BD0");
            vcvtusi2ss(xm1|T_rd_sae, xm2, rax); sdump("62F1EE387BC8");
            vcvtusi2ss(xm1|T_rd_sae, xm2, r9); sdump("62D1EE387BC9");

            // vmovq with EGPR
            vmovq(xm0, rax); sdump("C4E1F96EC0");
            vmovq(xm8, r8); sdump("C441F96EC0");
            vmovq(xm16, r16); sdump("62E9FD086EC0");
            vmovq(xm24, r24); sdump("6249FD086EC0");
            vmovq(xm0, r24); sdump("62D9FD086EC0");
            vmovq(xm8, r16); sdump("6279FD086EC0");
            vmovq(xm16, r8); sdump("62C1FD086EC0");
            vmovq(xm24, rax); sdump("6261FD086EC0");

            vmovq(rax, xm0); sdump("C4E1F97EC0");
            vmovq(r8, xm8); sdump("C441F97EC0");
            vmovq(r16, xm16); sdump("62E9FD087EC0");
            vmovq(r24, xm24); sdump("6249FD087EC0");
            vmovq(r24, xm0); sdump("62D9FD087EC0");
            vmovq(r16, xm8); sdump("6279FD087EC0");
            vmovq(r8, xm16); sdump("62C1FD087EC0");
            vmovq(rax, xm24); sdump("6261FD087EC0");

            // vpextrw with EGPR
            vpextrw(eax, xm1, 0); sdump("C5F9C5C100");
            vpextrw(r8d, xm1, 1); sdump("C579C5C101");
            vpextrw(r16d, xm1, 2); sdump("62FB7D0815C802");
            vpextrw(r24d, xm1, 3); sdump("62DB7D0815C803");
            vpextrw(eax, xm16, 4); sdump("62E37D0815C004");
            vpextrw(r16d, xm24, 5); sdump("626B7D0815C005");
            vpextrw(eax, xm2, 6); sdump("C5F9C5C206");
            vpextrw(ptr[rax+rcx*1], xm3, 7); sdump("C4E379151C0807");

        }
    }
}
