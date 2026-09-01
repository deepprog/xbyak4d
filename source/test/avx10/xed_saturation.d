module xed_saturation;

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
    @("xed_saturation")
    unittest
    {
        scope Code c = new Code("xed_saturation");
    }

    class Code : TestCode
    {
        this(string name)
        {
            super(name);
            setDefaultEncodingAVX10(AVX10v2Encoding);
            //
            vcvtbf162ibs(xm1, xm2);
            sdump("62F57F0869CA");
            vcvtbf162ibs(xm1, ptr[rax + 64]);
            sdump("62F57F08694804");
            vcvtbf162ibs(xm1, ptr_b[rax + 64]);
            sdump("62F57F18694820");

            vcvtbf162ibs(ym1, ym2);
            sdump("62F57F2869CA");
            vcvtbf162ibs(ym1, ptr[rax + 64]);
            sdump("62F57F28694802");
            vcvtbf162ibs(ym1, ptr_b[rax + 64]);
            sdump("62F57F38694820");

            vcvtbf162ibs(zm1, zm2);
            sdump("62F57F4869CA");
            vcvtbf162ibs(zm1, ptr[rax + 64]);
            sdump("62F57F48694801");
            vcvtbf162ibs(zm1, ptr_b[rax + 64]);
            sdump("62F57F58694820");
            //
            vcvtbf162iubs(xm1, xm2);
            sdump("62F57F086BCA");
            vcvtbf162iubs(xm1, ptr[rax + 64]);
            sdump("62F57F086B4804");
            vcvtbf162iubs(xm1, ptr_b[rax + 64]);
            sdump("62F57F186B4820");

            vcvtbf162iubs(ym1, ym2);
            sdump("62F57F286BCA");
            vcvtbf162iubs(ym1, ptr[rax + 64]);
            sdump("62F57F286B4802");
            vcvtbf162iubs(ym1, ptr_b[rax + 64]);
            sdump("62F57F386B4820");

            vcvtbf162iubs(zm1, zm2);
            sdump("62F57F486BCA");
            vcvtbf162iubs(zm1, ptr[rax + 64]);
            sdump("62F57F486B4801");
            vcvtbf162iubs(zm1, ptr_b[rax + 64]);
            sdump("62F57F586B4820");
            //
            vcvttbf162ibs(xm1, xm2);
            sdump("62F57F0868CA");
            vcvttbf162ibs(xm1, ptr[rax + 64]);
            sdump("62F57F08684804");
            vcvttbf162ibs(xm1, ptr_b[rax + 64]);
            sdump("62F57F18684820");

            vcvttbf162ibs(ym1, ym2);
            sdump("62F57F2868CA");
            vcvttbf162ibs(ym1, ptr[rax + 64]);
            sdump("62F57F28684802");
            vcvttbf162ibs(ym1, ptr_b[rax + 64]);
            sdump("62F57F38684820");

            vcvttbf162ibs(zm1, zm2);
            sdump("62F57F4868CA");
            vcvttbf162ibs(zm1, ptr[rax + 64]);
            sdump("62F57F48684801");
            vcvttbf162ibs(zm1, ptr_b[rax + 64]);
            sdump("62F57F58684820");
            //
            vcvttbf162iubs(xm1, xm2);
            sdump("62F57F086ACA");
            vcvttbf162iubs(xm1, ptr[rax + 64]);
            sdump("62F57F086A4804");
            vcvttbf162iubs(xm1, ptr_b[rax + 64]);
            sdump("62F57F186A4820");

            vcvttbf162iubs(ym1, ym2);
            sdump("62F57F286ACA");
            vcvttbf162iubs(ym1, ptr[rax + 64]);
            sdump("62F57F286A4802");
            vcvttbf162iubs(ym1, ptr_b[rax + 64]);
            sdump("62F57F386A4820");

            vcvttbf162iubs(zm1, zm2);
            sdump("62F57F486ACA");
            vcvttbf162iubs(zm1, ptr[rax + 64]);
            sdump("62F57F486A4801");
            vcvttbf162iubs(zm1, ptr_b[rax + 64]);
            sdump("62F57F586A4820");
            //
            vcvttpd2qqs(xm1, xm2);
            sdump("62F5FD086DCA");
            vcvttpd2qqs(xm1, ptr[rax + 64]);
            sdump("62F5FD086D4804");
            vcvttpd2qqs(xm1, ptr_b[rax + 64]);
            sdump("62F5FD186D4808");

            vcvttpd2qqs(ym1, ym2);
            sdump("62F5FD286DCA");
            vcvttpd2qqs(ym1, ptr[rax + 64]);
            sdump("62F5FD286D4802");
            vcvttpd2qqs(ym1, ptr_b[rax + 64]);
            sdump("62F5FD386D4808");

            vcvttpd2qqs(zm1, zm2);
            sdump("62F5FD486DCA");
            vcvttpd2qqs(zm1, zm2 | T_sae);
            sdump("62F5FD186DCA");
            vcvttpd2qqs(zm1, ptr[rax + 64]);
            sdump("62F5FD486D4801");
            vcvttpd2qqs(zm1, ptr_b[rax + 64]);
            sdump("62F5FD586D4808");
            //
            vcvttpd2uqqs(xm1, xm2);
            sdump("62F5FD086CCA");
            vcvttpd2uqqs(xm1, ptr[rax + 64]);
            sdump("62F5FD086C4804");
            vcvttpd2uqqs(xm1, ptr_b[rax + 64]);
            sdump("62F5FD186C4808");

            vcvttpd2uqqs(ym1, ym2);
            sdump("62F5FD286CCA");
            vcvttpd2uqqs(ym1, ptr[rax + 64]);
            sdump("62F5FD286C4802");
            vcvttpd2uqqs(ym1, ptr_b[rax + 64]);
            sdump("62F5FD386C4808");

            vcvttpd2uqqs(zm1, zm2);
            sdump("62F5FD486CCA");
            vcvttpd2uqqs(zm1, zm2 | T_sae);
            sdump("62F5FD186CCA");
            vcvttpd2uqqs(zm1, ptr[rax + 64]);
            sdump("62F5FD486C4801");
            vcvttpd2uqqs(zm1, ptr_b[rax + 64]);
            sdump("62F5FD586C4808");
            //
            vcvtph2ibs(xm1, xm2);
            sdump("62F57C0869CA");
            vcvtph2ibs(xm1, ptr[rax + 64]);
            sdump("62F57C08694804");
            vcvtph2ibs(xm1, ptr_b[rax + 64]);
            sdump("62F57C18694820");

            vcvtph2ibs(ym1, ym2);
            sdump("62F57C2869CA");
            vcvtph2ibs(ym1, ptr[rax + 64]);
            sdump("62F57C28694802");
            vcvtph2ibs(ym1, ptr_b[rax + 64]);
            sdump("62F57C38694820");

            vcvtph2ibs(zm1, zm2);
            sdump("62F57C4869CA");
            vcvtph2ibs(zm1, zm2 | T_ru_sae);
            sdump("62F57C5869CA");
            vcvtph2ibs(zm1, ptr[rax + 64]);
            sdump("62F57C48694801");
            vcvtph2ibs(zm1, ptr_b[rax + 64]);
            sdump("62F57C58694820");
            //
            vcvtph2iubs(xm1, xm2);
            sdump("62F57C086BCA");
            vcvtph2iubs(xm1, ptr[rax + 64]);
            sdump("62F57C086B4804");
            vcvtph2iubs(xm1, ptr_b[rax + 64]);
            sdump("62F57C186B4820");

            vcvtph2iubs(ym1, ym2);
            sdump("62F57C286BCA");
            vcvtph2iubs(ym1, ptr[rax + 64]);
            sdump("62F57C286B4802");
            vcvtph2iubs(ym1, ptr_b[rax + 64]);
            sdump("62F57C386B4820");

            vcvtph2iubs(zm1, zm2);
            sdump("62F57C486BCA");
            vcvtph2iubs(zm1, zm2 | T_ru_sae);
            sdump("62F57C586BCA");
            vcvtph2iubs(zm1, ptr[rax + 64]);
            sdump("62F57C486B4801");
            vcvtph2iubs(zm1, ptr_b[rax + 64]);
            sdump("62F57C586B4820");
            //
            vcvttph2ibs(xm1, xm2);
            sdump("62F57C0868CA");
            vcvttph2ibs(xm1, ptr[rax + 64]);
            sdump("62F57C08684804");
            vcvttph2ibs(xm1, ptr_b[rax + 64]);
            sdump("62F57C18684820");

            vcvttph2ibs(ym1, ym2);
            sdump("62F57C2868CA");
            vcvttph2ibs(ym1, ptr[rax + 64]);
            sdump("62F57C28684802");
            vcvttph2ibs(ym1, ptr_b[rax + 64]);
            sdump("62F57C38684820");

            vcvttph2ibs(zm1, zm2);
            sdump("62F57C4868CA");
            vcvttph2ibs(zm1, zm2 | T_ru_sae);
            sdump("62F57C5868CA");
            vcvttph2ibs(zm1, ptr[rax + 64]);
            sdump("62F57C48684801");
            vcvttph2ibs(zm1, ptr_b[rax + 64]);
            sdump("62F57C58684820");
            //
            vcvttph2iubs(xm1, xm2);
            sdump("62F57C086ACA");
            vcvttph2iubs(xm1, ptr[rax + 64]);
            sdump("62F57C086A4804");
            vcvttph2iubs(xm1, ptr_b[rax + 64]);
            sdump("62F57C186A4820");

            vcvttph2iubs(ym1, ym2);
            sdump("62F57C286ACA");
            vcvttph2iubs(ym1, ptr[rax + 64]);
            sdump("62F57C286A4802");
            vcvttph2iubs(ym1, ptr_b[rax + 64]);
            sdump("62F57C386A4820");

            vcvttph2iubs(zm1, zm2);
            sdump("62F57C486ACA");
            vcvttph2iubs(zm1, zm2 | T_ru_sae);
            sdump("62F57C586ACA");
            vcvttph2iubs(zm1, ptr[rax + 64]);
            sdump("62F57C486A4801");
            vcvttph2iubs(zm1, ptr_b[rax + 64]);
            sdump("62F57C586A4820");
            //
            vcvttps2dqs(xm1, xm2);
            sdump("62F57C086DCA");
            vcvttps2dqs(xm1, ptr[rax + 64]);
            sdump("62F57C086D4804");
            vcvttps2dqs(xm1, ptr_b[rax + 64]);
            sdump("62F57C186D4810");

            vcvttps2dqs(ym1, ym2);
            sdump("62F57C286DCA");
            vcvttps2dqs(ym1, ptr[rax + 64]);
            sdump("62F57C286D4802");
            vcvttps2dqs(ym1, ptr_b[rax + 64]);
            sdump("62F57C386D4810");

            vcvttps2dqs(zm1, zm2);
            sdump("62F57C486DCA");
            vcvttps2dqs(zm1, zm2 | T_sae);
            sdump("62F57C186DCA");
            vcvttps2dqs(zm1, ptr[rax + 64]);
            sdump("62F57C486D4801");
            vcvttps2dqs(zm1, ptr_b[rax + 64]);
            sdump("62F57C586D4810");
            //
            vcvtps2ibs(xm1, xm2);
            sdump("62F57D0869CA");
            vcvtps2ibs(xm1, ptr[rax + 64]);
            sdump("62F57D08694804");
            vcvtps2ibs(xm1, ptr_b[rax + 64]);
            sdump("62F57D18694810");

            vcvtps2ibs(ym1, ym2);
            sdump("62F57D2869CA");
            vcvtps2ibs(ym1, ptr[rax + 64]);
            sdump("62F57D28694802");
            vcvtps2ibs(ym1, ptr_b[rax + 64]);
            sdump("62F57D38694810");

            vcvtps2ibs(zm1, zm2);
            sdump("62F57D4869CA");
            vcvtps2ibs(zm1, zm2 | T_ru_sae);
            sdump("62F57D5869CA");
            vcvtps2ibs(zm1, ptr[rax + 64]);
            sdump("62F57D48694801");
            vcvtps2ibs(zm1, ptr_b[rax + 64]);
            sdump("62F57D58694810");
            //
            vcvtps2iubs(xm1, xm2);
            sdump("62F57D086BCA");
            vcvtps2iubs(xm1, ptr[rax + 64]);
            sdump("62F57D086B4804");
            vcvtps2iubs(xm1, ptr_b[rax + 64]);
            sdump("62F57D186B4810");

            vcvtps2iubs(ym1, ym2);
            sdump("62F57D286BCA");
            vcvtps2iubs(ym1, ptr[rax + 64]);
            sdump("62F57D286B4802");
            vcvtps2iubs(ym1, ptr_b[rax + 64]);
            sdump("62F57D386B4810");

            vcvtps2iubs(zm1, zm2);
            sdump("62F57D486BCA");
            vcvtps2iubs(zm1, zm2 | T_ru_sae);
            sdump("62F57D586BCA");
            vcvtps2iubs(zm1, ptr[rax + 64]);
            sdump("62F57D486B4801");
            vcvtps2iubs(zm1, ptr_b[rax + 64]);
            sdump("62F57D586B4810");
            //
            vcvttps2ibs(xm1, xm2);
            sdump("62F57D0868CA");
            vcvttps2ibs(xm1, ptr[rax + 64]);
            sdump("62F57D08684804");
            vcvttps2ibs(xm1, ptr_b[rax + 64]);
            sdump("62F57D18684810");

            vcvttps2ibs(ym1, ym2);
            sdump("62F57D2868CA");
            vcvttps2ibs(ym1, ptr[rax + 64]);
            sdump("62F57D28684802");
            vcvttps2ibs(ym1, ptr_b[rax + 64]);
            sdump("62F57D38684810");

            vcvttps2ibs(zm1, zm2);
            sdump("62F57D4868CA");
            vcvttps2ibs(zm1, zm2 | T_ru_sae);
            sdump("62F57D5868CA");
            vcvttps2ibs(zm1, ptr[rax + 64]);
            sdump("62F57D48684801");
            vcvttps2ibs(zm1, ptr_b[rax + 64]);
            sdump("62F57D58684810");
            //
            vcvttps2iubs(xm1, xm2);
            sdump("62F57D086ACA");
            vcvttps2iubs(xm1, ptr[rax + 64]);
            sdump("62F57D086A4804");
            vcvttps2iubs(xm1, ptr_b[rax + 64]);
            sdump("62F57D186A4810");

            vcvttps2iubs(ym1, ym2);
            sdump("62F57D286ACA");
            vcvttps2iubs(ym1, ptr[rax + 64]);
            sdump("62F57D286A4802");
            vcvttps2iubs(ym1, ptr_b[rax + 64]);
            sdump("62F57D386A4810");

            vcvttps2iubs(zm1, zm2);
            sdump("62F57D486ACA");
            vcvttps2iubs(zm1, zm2 | T_ru_sae);
            sdump("62F57D586ACA");
            vcvttps2iubs(zm1, ptr[rax + 64]);
            sdump("62F57D486A4801");
            vcvttps2iubs(zm1, ptr_b[rax + 64]);
            sdump("62F57D586A4810");
            //
            vcvttps2udqs(xm1, xm2);
            sdump("62F57C086CCA");
            vcvttps2udqs(xm1, ptr[rax + 64]);
            sdump("62F57C086C4804");
            vcvttps2udqs(xm1, ptr_b[rax + 64]);
            sdump("62F57C186C4810");

            vcvttps2udqs(ym1, ym2);
            sdump("62F57C286CCA");
            vcvttps2udqs(ym1, ptr[rax + 64]);
            sdump("62F57C286C4802");
            vcvttps2udqs(ym1, ptr_b[rax + 64]);
            sdump("62F57C386C4810");

            vcvttps2udqs(zm1, zm2);
            sdump("62F57C486CCA");
            vcvttps2udqs(zm1, zm2 | T_sae);
            sdump("62F57C186CCA");
            vcvttps2udqs(zm1, ptr[rax + 64]);
            sdump("62F57C486C4801");
            vcvttps2udqs(zm1, ptr_b[rax + 64]);
            sdump("62F57C586C4810");

            //
            vcvttpd2dqs(xm1 | k1 | T_z, xm2);
            sdump("62F5FC896DCA");
            vcvttpd2dqs(xm1 | k1 | T_z, xword[rax + 64]);
            sdump("62F5FC896D4804");
            vcvttpd2dqs(xm1 | k1 | T_z, xword_b[rax + 64]);
            sdump("62F5FC996D4808");

            vcvttpd2dqs(xm1 | k1 | T_z, ym2);
            sdump("62F5FCA96DCA");
            vcvttpd2dqs(xm1 | k1 | T_z, yword[rax + 64]);
            sdump("62F5FCA96D4802");
            vcvttpd2dqs(xm1 | k1 | T_z, yword_b[rax + 64]);
            sdump("62F5FCB96D4808");

            vcvttpd2dqs(ym1 | k1 | T_z, zm2);
            sdump("62F5FCC96DCA");
            vcvttpd2dqs(ym1 | k1 | T_z, zm2 | T_sae);
            sdump("62F5FC996DCA");
            vcvttpd2dqs(ym1 | k1 | T_z, zword[rax + 64]);
            sdump("62F5FCC96D4801");
            vcvttpd2dqs(ym1 | k1 | T_z, zword_b[rax + 64]);
            sdump("62F5FCD96D4808");

            //
            vcvttpd2udqs(xm1 | k1 | T_z, xm2);
            sdump("62F5FC896CCA");
            vcvttpd2udqs(xm1 | k1 | T_z, xword[rax + 64]);
            sdump("62F5FC896C4804");
            vcvttpd2udqs(xm1 | k1 | T_z, xword_b[rax + 64]);
            sdump("62F5FC996C4808");

            vcvttpd2udqs(xm1 | k1 | T_z, ym2);
            sdump("62F5FCA96CCA");
            vcvttpd2udqs(xm1 | k1 | T_z, yword[rax + 64]);
            sdump("62F5FCA96C4802");
            vcvttpd2udqs(xm1 | k1 | T_z, yword_b[rax + 64]);
            sdump("62F5FCB96C4808");

            vcvttpd2udqs(ym1 | k1 | T_z, zm2);
            sdump("62F5FCC96CCA");
            vcvttpd2udqs(ym1 | k1 | T_z, zm2 | T_sae);
            sdump("62F5FC996CCA");
            vcvttpd2udqs(ym1 | k1 | T_z, zword[rax + 64]);
            sdump("62F5FCC96C4801");
            vcvttpd2udqs(ym1 | k1 | T_z, zword_b[rax + 64]);
            sdump("62F5FCD96C4808");
            //
            vcvttps2qqs(xm1 | k1 | T_z, xm2);
            sdump("62F57D896DCA");
            vcvttps2qqs(xm1 | k1 | T_z, ptr[rax + 64]);
            sdump("62F57D896D4808");
            vcvttps2qqs(xm1 | k1 | T_z, ptr_b[rax + 64]);
            sdump("62F57D996D4810");

            vcvttps2qqs(ym1 | k1 | T_z, xm2);
            sdump("62F57DA96DCA");
            vcvttps2qqs(ym1 | k1 | T_z, ptr[rax + 64]);
            sdump("62F57DA96D4804");
            vcvttps2qqs(ym1 | k1 | T_z, ptr_b[rax + 64]);
            sdump("62F57DB96D4810");

            vcvttps2qqs(zm1, ym2);
            sdump("62F57D486DCA");
            vcvttps2qqs(zm1 | k1 | T_z, ym2);
            sdump("62F57DC96DCA");
            vcvttps2qqs(zm1 | k1 | T_z | T_sae, ym2);
            sdump("62F57D996DCA");
            vcvttps2qqs(zm1 | k1 | T_z, ptr[rax + 64]);
            sdump("62F57DC96D4802");
            vcvttps2qqs(zm1 | k1 | T_z, ptr_b[rax + 64]);
            sdump("62F57DD96D4810");

            //
            vcvttps2uqqs(xm1 | k1 | T_z, xm2);
            sdump("62F57D896CCA");
            vcvttps2uqqs(xm1 | k1 | T_z, ptr[rax + 64]);
            sdump("62F57D896C4808");
            vcvttps2uqqs(xm1 | k1 | T_z, ptr_b[rax + 64]);
            sdump("62F57D996C4810");

            vcvttps2uqqs(ym1 | k1 | T_z, xm2);
            sdump("62F57DA96CCA");
            vcvttps2uqqs(ym1 | k1 | T_z, ptr[rax + 64]);
            sdump("62F57DA96C4804");
            vcvttps2uqqs(ym1 | k1 | T_z, ptr_b[rax + 64]);
            sdump("62F57DB96C4810");

            vcvttps2uqqs(zm1, ym2);
            sdump("62F57D486CCA");
            vcvttps2uqqs(zm1 | k1 | T_z, ym2);
            sdump("62F57DC96CCA");
            vcvttps2uqqs(zm1 | k1 | T_z | T_sae, ym2);
            sdump("62F57D996CCA");
            vcvttps2uqqs(zm1 | k1 | T_z, ptr[rax + 64]);
            sdump("62F57DC96C4802");
            vcvttps2uqqs(zm1 | k1 | T_z, ptr_b[rax + 64]);
            sdump("62F57DD96C4810");

            //
            vcvttsd2sis(eax, xm1);
            sdump("62F57F086DC1");
            vcvttsd2sis(eax, xm1 | T_sae);
            sdump("62F57F186DC1");
            vcvttsd2sis(eax, ptr[rax + 64]);
            sdump("62F57F086D4008");

            vcvttsd2sis(r30, xm1);
            sdump("6265FF086DF1");
            vcvttsd2sis(r30, xm1 | T_sae);
            sdump("6265FF186DF1");
            vcvttsd2sis(r30, ptr[rax + 64]);
            sdump("6265FF086D7008");
            //
            vcvttsd2usis(eax, xm1);
            sdump("62F57F086CC1");
            vcvttsd2usis(eax, xm1 | T_sae);
            sdump("62F57F186CC1");
            vcvttsd2usis(eax, ptr[rax + 64]);
            sdump("62F57F086C4008");

            vcvttsd2usis(r30, xm1);
            sdump("6265FF086CF1");
            vcvttsd2usis(r30, xm1 | T_sae);
            sdump("6265FF186CF1");
            vcvttsd2usis(r30, ptr[rax + 64]);
            sdump("6265FF086C7008");
            //
            vcvttss2sis(eax, xm1);
            sdump("62F57E086DC1");
            vcvttss2sis(eax, xm1 | T_sae);
            sdump("62F57E186DC1");
            vcvttss2sis(eax, ptr[rax + 64]);
            sdump("62F57E086D4010");

            vcvttss2sis(r30, xm1);
            sdump("6265FE086DF1");
            vcvttss2sis(r30, xm1 | T_sae);
            sdump("6265FE186DF1");
            vcvttss2sis(r30, ptr[rax + 64]);
            sdump("6265FE086D7010");
            //
            vcvttss2usis(eax, xm1);
            sdump("62F57E086CC1");
            vcvttss2usis(eax, xm1 | T_sae);
            sdump("62F57E186CC1");
            vcvttss2usis(eax, ptr[rax + 64]);
            sdump("62F57E086C4010");

            vcvttss2usis(r30, xm1);
            sdump("6265FE086CF1");
            vcvttss2usis(r30, xm1 | T_sae);
            sdump("6265FE186CF1");
            vcvttss2usis(r30, ptr[rax + 64]);
            sdump("6265FE086C7010");

        }
    }
}
