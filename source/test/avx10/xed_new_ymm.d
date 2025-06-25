module xed_new_ymm;

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
    @("xed_new_ymm")
    unittest
    {
        xed_new_ymm();
    }

    void xed_new_ymm()
    {
        scope Code c = new Code();
    }

    class TestCode : CodeGenerator
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

        this()
        {
            testCount.reset();

            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);
        }

        ~this()
        {
            testCount.end(__FILE__);
        }

    }

    class Code : TestCode
    {
        this()
        {
            vaddpd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F1E91858CB");
            vaddph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F5681858CB");
            vaddps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F1681858CB");
            vcmppd(k1, ymm2, ymm3 | T_sae, 3);
            sdump("62F1E918C2CB03");
            vcmpph(k1, ymm2, ymm3 | T_sae, 3);
            sdump("62F36818C2CB03");
            vcmpps(k1, ymm2, ymm3 | T_sae, 3);
            sdump("62F16818C2CB03");
            vcvtdq2ph(xmm1, ymm2 | T_rn_sae);
            sdump("62F578185BCA");
            vcvtdq2ps(ymm1, ymm2 | T_rn_sae);
            sdump("62F178185BCA");
            vcvtpd2dq(xmm1, ymm2 | T_rn_sae);
            sdump("62F1FB18E6CA");
            vcvtpd2ph(xmm1, ymm2 | T_rn_sae);
            sdump("62F5F9185ACA");
            vcvtpd2ps(xmm1, ymm2 | T_rn_sae);
            sdump("62F1F9185ACA");
            vcvtpd2qq(ymm1, ymm2 | T_rn_sae);
            sdump("62F1F9187BCA");
            vcvtpd2udq(xmm1, ymm2 | T_rn_sae);
            sdump("62F1F81879CA");
            vcvtpd2uqq(ymm1, ymm2 | T_rn_sae);
            sdump("62F1F91879CA");
            vcvtph2dq(ymm1, xmm2 | T_rn_sae);
            sdump("62F579185BCA");
            vcvtph2pd(ymm1, xmm2 | T_sae);
            sdump("62F578185ACA");
            vcvtph2ps(ymm1, xmm2 | T_sae);
            sdump("62F2791813CA");
            vcvtph2psx(ymm1, xmm2 | T_sae);
            sdump("62F6791813CA");
            vcvtph2qq(ymm1, xmm2 | T_rn_sae);
            sdump("62F579187BCA");
            vcvtph2udq(ymm1, xmm2 | T_rn_sae);
            sdump("62F5781879CA");
            vcvtph2uqq(ymm1, xmm2 | T_rn_sae);
            sdump("62F5791879CA");
            vcvtph2uw(ymm1, ymm2 | T_rn_sae);
            sdump("62F578187DCA");
            vcvtph2w(ymm1, ymm2 | T_rn_sae);
            sdump("62F579187DCA");
            vcvtps2dq(ymm1, ymm2 | T_rn_sae);
            sdump("62F179185BCA");
            vcvtps2pd(ymm1, xmm2 | T_sae);
            sdump("62F178185ACA");
            vcvtps2ph(xmm1, ymm2 | T_sae, 3);
            sdump("62F379181DD103");
            vcvtps2phx(xmm1, ymm2 | T_rn_sae);
            sdump("62F579181DCA");
            vcvtps2qq(ymm1, xmm2 | T_rn_sae);
            sdump("62F179187BCA");
            vcvtps2udq(ymm1, ymm2 | T_rn_sae);
            sdump("62F1781879CA");
            vcvtps2uqq(ymm1, xmm2 | T_rn_sae);
            sdump("62F1791879CA");
            vcvtqq2pd(ymm1, ymm2 | T_rn_sae);
            sdump("62F1FA18E6CA");
            vcvtqq2ph(xmm1, ymm2 | T_rn_sae);
            sdump("62F5F8185BCA");
            vcvtqq2ps(xmm1, ymm2 | T_rn_sae);
            sdump("62F1F8185BCA");
            vcvttpd2dq(xmm1, ymm2 | T_sae);
            sdump("62F1F918E6CA");
            vcvttpd2qq(ymm1, ymm2 | T_sae);
            sdump("62F1F9187ACA");
            vcvttpd2udq(xmm1, ymm2 | T_sae);
            sdump("62F1F81878CA");
            vcvttpd2uqq(ymm1, ymm2 | T_sae);
            sdump("62F1F91878CA");
            vcvttph2dq(ymm1, xmm2 | T_sae);
            sdump("62F57A185BCA");
            vcvttph2qq(ymm1, xmm2 | T_sae);
            sdump("62F579187ACA");
            vcvttph2udq(ymm1, xmm2 | T_sae);
            sdump("62F5781878CA");
            vcvttph2uqq(ymm1, xmm2 | T_sae);
            sdump("62F5791878CA");
            vcvttph2uw(ymm1, ymm2 | T_sae);
            sdump("62F578187CCA");
            vcvttph2w(ymm1, ymm2 | T_sae);
            sdump("62F579187CCA");
            vcvttps2dq(ymm1, ymm2 | T_sae);
            sdump("62F17A185BCA");
            vcvttps2qq(ymm1, xmm2 | T_sae);
            sdump("62F179187ACA");
            vcvttps2udq(ymm1, ymm2 | T_sae);
            sdump("62F1781878CA");
            vcvttps2uqq(ymm1, xmm2 | T_sae);
            sdump("62F1791878CA");
            vcvtudq2ph(xmm1, ymm2 | T_rn_sae);
            sdump("62F57B187ACA");
            vcvtudq2ps(ymm1, ymm2 | T_rn_sae);
            sdump("62F17B187ACA");
            vcvtuqq2pd(ymm1, ymm2 | T_rn_sae);
            sdump("62F1FA187ACA");
            vcvtuqq2ph(xmm1, ymm2 | T_rn_sae);
            sdump("62F5FB187ACA");
            vcvtuqq2ps(xmm1, ymm2 | T_rn_sae);
            sdump("62F1FB187ACA");
            vcvtuw2ph(ymm1, ymm2 | T_rn_sae);
            sdump("62F57B187DCA");
            vcvtw2ph(ymm1, ymm2 | T_rn_sae);
            sdump("62F57A187DCA");
            vdivpd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F1E9185ECB");
            vdivph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F568185ECB");
            vdivps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F168185ECB");
            vfcmaddcph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66B1856CB");
            vfcmulcph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66B18D6CB");
            vfixupimmpd(ymm1, ymm2, ymm3 | T_sae, 3);
            sdump("62F3E91854CB03");
            vfixupimmps(ymm1, ymm2, ymm3 | T_sae, 3);
            sdump("62F3691854CB03");
            vfmadd132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E91898CB");
            vfmadd132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F6691898CB");
            vfmadd132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2691898CB");
            vfmadd213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918A8CB");
            vfmadd213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918A8CB");
            vfmadd213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918A8CB");
            vfmadd231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918B8CB");
            vfmadd231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918B8CB");
            vfmadd231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918B8CB");
            vfmaddcph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66A1856CB");
            vfmaddsub132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E91896CB");
            vfmaddsub132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F6691896CB");
            vfmaddsub132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2691896CB");
            vfmaddsub213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918A6CB");
            vfmaddsub213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918A6CB");
            vfmaddsub213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918A6CB");
            vfmaddsub231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918B6CB");
            vfmaddsub231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918B6CB");
            vfmaddsub231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918B6CB");
            vfmsub132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E9189ACB");
            vfmsub132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F669189ACB");
            vfmsub132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F269189ACB");
            vfmsub213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918AACB");
            vfmsub213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918AACB");
            vfmsub213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918AACB");
            vfmsub231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918BACB");
            vfmsub231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918BACB");
            vfmsub231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918BACB");
            vfmsubadd132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E91897CB");
            vfmsubadd132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F6691897CB");
            vfmsubadd132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2691897CB");
            vfmsubadd213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918A7CB");
            vfmsubadd213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918A7CB");
            vfmsubadd213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918A7CB");
            vfmsubadd231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918B7CB");
            vfmsubadd231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918B7CB");
            vfmsubadd231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918B7CB");
            vfmulcph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66A18D6CB");
            vfnmadd132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E9189CCB");
            vfnmadd132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F669189CCB");
            vfnmadd132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F269189CCB");
            vfnmadd213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918ACCB");
            vfnmadd213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918ACCB");
            vfnmadd213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918ACCB");
            vfnmadd231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918BCCB");
            vfnmadd231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918BCCB");
            vfnmadd231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918BCCB");
            vfnmsub132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E9189ECB");
            vfnmsub132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F669189ECB");
            vfnmsub132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F269189ECB");
            vfnmsub213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918AECB");
            vfnmsub213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918AECB");
            vfnmsub213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918AECB");
            vfnmsub231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E918BECB");
            vfnmsub231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F66918BECB");
            vfnmsub231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F26918BECB");
            vgetexppd(ymm1, ymm2 | T_sae);
            sdump("62F2F91842CA");
            vgetexpph(ymm1, ymm2 | T_sae);
            sdump("62F6791842CA");
            vgetexpps(ymm1, ymm2 | T_sae);
            sdump("62F2791842CA");
            vgetmantpd(ymm1, ymm2 | T_sae, 3);
            sdump("62F3F91826CA03");
            vgetmantph(ymm1, ymm2 | T_sae, 3);
            sdump("62F3781826CA03");
            vgetmantps(ymm1, ymm2 | T_sae, 3);
            sdump("62F3791826CA03");
            vmaxpd(ymm1, ymm2, ymm3 | T_sae);
            sdump("62F1E9185FCB");
            vmaxph(ymm1, ymm2, ymm3 | T_sae);
            sdump("62F568185FCB");
            vmaxps(ymm1, ymm2, ymm3 | T_sae);
            sdump("62F168185FCB");
            vminpd(ymm1, ymm2, ymm3 | T_sae);
            sdump("62F1E9185DCB");
            vminph(ymm1, ymm2, ymm3 | T_sae);
            sdump("62F568185DCB");
            vminps(ymm1, ymm2, ymm3 | T_sae);
            sdump("62F168185DCB");
            vmulpd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F1E91859CB");
            vmulph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F5681859CB");
            vmulps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F1681859CB");
            vrangepd(ymm1, ymm2, ymm3 | T_sae, 3);
            sdump("62F3E91850CB03");
            vrangeps(ymm1, ymm2, ymm3 | T_sae, 3);
            sdump("62F3691850CB03");
            vreducepd(ymm1, ymm2 | T_sae, 3);
            sdump("62F3F91856CA03");
            vreduceph(ymm1, ymm2 | T_sae, 3);
            sdump("62F3781856CA03");
            vreduceps(ymm1, ymm2 | T_sae, 3);
            sdump("62F3791856CA03");
            vrndscalepd(ymm1, ymm2 | T_sae, 3);
            sdump("62F3F91809CA03");
            vrndscaleph(ymm1, ymm2 | T_sae, 3);
            sdump("62F3781808CA03");
            vrndscaleps(ymm1, ymm2 | T_sae, 3);
            sdump("62F3791808CA03");
            vscalefpd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F2E9182CCB");
            vscalefph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F669182CCB");
            vscalefps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F269182CCB");
            vsqrtpd(ymm1, ymm2 | T_rn_sae);
            sdump("62F1F91851CA");
            vsqrtph(ymm1, ymm2 | T_rn_sae);
            sdump("62F5781851CA");
            vsqrtps(ymm1, ymm2 | T_rn_sae);
            sdump("62F1781851CA");
            vsubpd(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F1E9185CCB");
            vsubph(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F568185CCB");
            vsubps(ymm1, ymm2, ymm3 | T_rn_sae);
            sdump("62F168185CCB");

        }
    }
}
