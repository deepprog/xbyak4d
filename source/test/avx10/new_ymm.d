module xed_new_ymm;

import std.stdio;
import std.string;
import std.algorithm;
import std.stdint;
import std.exception;
import xbyak;

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

        writeln("xed_new_ymm");
        scope Code c = new Code();
    }

    class Code : CodeGenerator
    {
        this()
        {
            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            vaddpd(ymm1, ymm2, ymm3 | T_rn_sae);
            vaddph(ymm1, ymm2, ymm3 | T_rn_sae);
            vaddps(ymm1, ymm2, ymm3 | T_rn_sae);
            vcmppd(k1, ymm2, ymm3 | T_sae, 3);
            vcmpph(k1, ymm2, ymm3 | T_sae, 3);
            vcmpps(k1, ymm2, ymm3 | T_sae, 3);
            vcvtdq2ph(xmm1, ymm2 | T_rn_sae);
            vcvtdq2ps(ymm1, ymm2 | T_rn_sae);
            vcvtpd2dq(xmm1, ymm2 | T_rn_sae);
            vcvtpd2ph(xmm1, ymm2 | T_rn_sae);
            vcvtpd2ps(xmm1, ymm2 | T_rn_sae);
            vcvtpd2qq(ymm1, ymm2 | T_rn_sae);
            vcvtpd2udq(xmm1, ymm2 | T_rn_sae);
            vcvtpd2uqq(ymm1, ymm2 | T_rn_sae);
            vcvtph2dq(ymm1, xmm2 | T_rn_sae);
            vcvtph2pd(ymm1, xmm2 | T_sae);
            vcvtph2ps(ymm1, xmm2 | T_sae);
            vcvtph2psx(ymm1, xmm2 | T_sae);
            vcvtph2qq(ymm1, xmm2 | T_rn_sae);
            vcvtph2udq(ymm1, xmm2 | T_rn_sae);
            vcvtph2uqq(ymm1, xmm2 | T_rn_sae);
            vcvtph2uw(ymm1, ymm2 | T_rn_sae);
            vcvtph2w(ymm1, ymm2 | T_rn_sae);
            vcvtps2dq(ymm1, ymm2 | T_rn_sae);
            vcvtps2pd(ymm1, xmm2 | T_sae);
            vcvtps2ph(xmm1, ymm2 | T_sae, 3);
            vcvtps2phx(xmm1, ymm2 | T_rn_sae);
            vcvtps2qq(ymm1, xmm2 | T_rn_sae);
            vcvtps2udq(ymm1, ymm2 | T_rn_sae);
            vcvtps2uqq(ymm1, xmm2 | T_rn_sae);
            vcvtqq2pd(ymm1, ymm2 | T_rn_sae);
            vcvtqq2ph(xmm1, ymm2 | T_rn_sae);
            vcvtqq2ps(xmm1, ymm2 | T_rn_sae);
            vcvttpd2dq(xmm1, ymm2 | T_sae);
            vcvttpd2qq(ymm1, ymm2 | T_sae);
            vcvttpd2udq(xmm1, ymm2 | T_sae);
            vcvttpd2uqq(ymm1, ymm2 | T_sae);
            vcvttph2dq(ymm1, xmm2 | T_sae);
            vcvttph2qq(ymm1, xmm2 | T_sae);
            vcvttph2udq(ymm1, xmm2 | T_sae);
            vcvttph2uqq(ymm1, xmm2 | T_sae);
            vcvttph2uw(ymm1, ymm2 | T_sae);
            vcvttph2w(ymm1, ymm2 | T_sae);
            vcvttps2dq(ymm1, ymm2 | T_sae);
            vcvttps2qq(ymm1, xmm2 | T_sae);
            vcvttps2udq(ymm1, ymm2 | T_sae);
            vcvttps2uqq(ymm1, xmm2 | T_sae);
            vcvtudq2ph(xmm1, ymm2 | T_rn_sae);
            vcvtudq2ps(ymm1, ymm2 | T_rn_sae);
            vcvtuqq2pd(ymm1, ymm2 | T_rn_sae);
            vcvtuqq2ph(xmm1, ymm2 | T_rn_sae);
            vcvtuqq2ps(xmm1, ymm2 | T_rn_sae);
            vcvtuw2ph(ymm1, ymm2 | T_rn_sae);
            vcvtw2ph(ymm1, ymm2 | T_rn_sae);
            vdivpd(ymm1, ymm2, ymm3 | T_rn_sae);
            vdivph(ymm1, ymm2, ymm3 | T_rn_sae);
            vdivps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfcmaddcph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfcmulcph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfixupimmpd(ymm1, ymm2, ymm3 | T_sae, 3);
            vfixupimmps(ymm1, ymm2, ymm3 | T_sae, 3);
            vfmadd132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmadd132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmadd132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmadd213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmadd213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmadd213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmadd231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmadd231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmadd231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmaddcph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmaddsub132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmaddsub132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmaddsub132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmaddsub213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmaddsub213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmaddsub213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmaddsub231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmaddsub231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmaddsub231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsub132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsub132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsub132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsub213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsub213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsub213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsub231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsub231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsub231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsubadd132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsubadd132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsubadd132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsubadd213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsubadd213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsubadd213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsubadd231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsubadd231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmsubadd231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfmulcph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmadd132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmadd132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmadd132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmadd213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmadd213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmadd213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmadd231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmadd231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmadd231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmsub132pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmsub132ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmsub132ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmsub213pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmsub213ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmsub213ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmsub231pd(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmsub231ph(ymm1, ymm2, ymm3 | T_rn_sae);
            vfnmsub231ps(ymm1, ymm2, ymm3 | T_rn_sae);
            vgetexppd(ymm1, ymm2 | T_sae);
            vgetexpph(ymm1, ymm2 | T_sae);
            vgetexpps(ymm1, ymm2 | T_sae);
            vgetmantpd(ymm1, ymm2 | T_sae, 3);
            vgetmantph(ymm1, ymm2 | T_sae, 3);
            vgetmantps(ymm1, ymm2 | T_sae, 3);
            vmaxpd(ymm1, ymm2, ymm3 | T_sae);
            vmaxph(ymm1, ymm2, ymm3 | T_sae);
            vmaxps(ymm1, ymm2, ymm3 | T_sae);
            vminpd(ymm1, ymm2, ymm3 | T_sae);
            vminph(ymm1, ymm2, ymm3 | T_sae);
            vminps(ymm1, ymm2, ymm3 | T_sae);
            vmulpd(ymm1, ymm2, ymm3 | T_rn_sae);
            vmulph(ymm1, ymm2, ymm3 | T_rn_sae);
            vmulps(ymm1, ymm2, ymm3 | T_rn_sae);
            vrangepd(ymm1, ymm2, ymm3 | T_sae, 3);
            vrangeps(ymm1, ymm2, ymm3 | T_sae, 3);
            vreducepd(ymm1, ymm2 | T_sae, 3);
            vreduceph(ymm1, ymm2 | T_sae, 3);
            vreduceps(ymm1, ymm2 | T_sae, 3);
            vrndscalepd(ymm1, ymm2 | T_sae, 3);
            vrndscaleph(ymm1, ymm2 | T_sae, 3);
            vrndscaleps(ymm1, ymm2 | T_sae, 3);
            vscalefpd(ymm1, ymm2, ymm3 | T_rn_sae);
            vscalefph(ymm1, ymm2, ymm3 | T_rn_sae);
            vscalefps(ymm1, ymm2, ymm3 | T_rn_sae);
            vsqrtpd(ymm1, ymm2 | T_rn_sae);
            vsqrtph(ymm1, ymm2 | T_rn_sae);
            vsqrtps(ymm1, ymm2 | T_rn_sae);
            vsubpd(ymm1, ymm2, ymm3 | T_rn_sae);
            vsubph(ymm1, ymm2, ymm3 | T_rn_sae);
            vsubps(ymm1, ymm2, ymm3 | T_rn_sae);
        }
    }
}

