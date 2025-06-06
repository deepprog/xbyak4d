module xed_new_ymm;

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

        vaddpd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vaddph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vaddps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vcmppd(k1, ymm2, ymm3 |T_sae, 3);  dump(); size_ = 0;
        vcmpph(k1, ymm2, ymm3 |T_sae, 3);  dump(); size_ = 0;
        vcmpps(k1, ymm2, ymm3 |T_sae, 3);  dump(); size_ = 0;
        vcvtdq2ph(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtdq2ps(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtpd2dq(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtpd2ph(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtpd2ps(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtpd2qq(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtpd2udq(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtpd2uqq(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtph2dq(ymm1, xmm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtph2pd(ymm1, xmm2 |T_sae);  dump(); size_ = 0;
        vcvtph2ps(ymm1, xmm2 |T_sae);  dump(); size_ = 0;
        vcvtph2psx(ymm1, xmm2 |T_sae);  dump(); size_ = 0;
        vcvtph2qq(ymm1, xmm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtph2udq(ymm1, xmm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtph2uqq(ymm1, xmm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtph2uw(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtph2w(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtps2dq(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtps2pd(ymm1, xmm2 |T_sae);  dump(); size_ = 0;
        vcvtps2ph(xmm1, ymm2 |T_sae, 3);  dump(); size_ = 0;
        vcvtps2phx(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtps2qq(ymm1, xmm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtps2udq(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtps2uqq(ymm1, xmm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtqq2pd(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtqq2ph(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtqq2ps(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvttpd2dq(xmm1, ymm2 |T_sae);  dump(); size_ = 0;
        vcvttpd2qq(ymm1, ymm2 |T_sae);  dump(); size_ = 0;
        vcvttpd2udq(xmm1, ymm2 |T_sae);  dump(); size_ = 0;
        vcvttpd2uqq(ymm1, ymm2 |T_sae);  dump(); size_ = 0;
        vcvttph2dq(ymm1, xmm2 |T_sae);  dump(); size_ = 0;
        vcvttph2qq(ymm1, xmm2 |T_sae);  dump(); size_ = 0;
        vcvttph2udq(ymm1, xmm2 |T_sae);  dump(); size_ = 0;
        vcvttph2uqq(ymm1, xmm2 |T_sae);  dump(); size_ = 0;
        vcvttph2uw(ymm1, ymm2 |T_sae);  dump(); size_ = 0;
        vcvttph2w(ymm1, ymm2 |T_sae);  dump(); size_ = 0;
        vcvttps2dq(ymm1, ymm2 |T_sae);  dump(); size_ = 0;
        vcvttps2qq(ymm1, xmm2 |T_sae);  dump(); size_ = 0;
        vcvttps2udq(ymm1, ymm2 |T_sae);  dump(); size_ = 0;
        vcvttps2uqq(ymm1, xmm2 |T_sae);  dump(); size_ = 0;
        vcvtudq2ph(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtudq2ps(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtuqq2pd(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtuqq2ph(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtuqq2ps(xmm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtuw2ph(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vcvtw2ph(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vdivpd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vdivph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vdivps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfcmaddcph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfcmulcph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfixupimmpd(ymm1, ymm2, ymm3 |T_sae, 3);  dump(); size_ = 0;
        vfixupimmps(ymm1, ymm2, ymm3 |T_sae, 3);  dump(); size_ = 0;
        vfmadd132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmadd132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmadd132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmadd213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmadd213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmadd213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmadd231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmadd231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmadd231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmaddcph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmaddsub132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmaddsub132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmaddsub132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmaddsub213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmaddsub213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmaddsub213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmaddsub231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmaddsub231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmaddsub231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsub132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsub132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsub132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsub213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsub213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsub213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsub231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsub231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsub231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsubadd132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsubadd132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsubadd132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsubadd213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsubadd213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsubadd213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsubadd231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsubadd231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmsubadd231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfmulcph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmadd132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmadd132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmadd132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmadd213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmadd213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmadd213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmadd231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmadd231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmadd231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmsub132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmsub132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmsub132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmsub213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmsub213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmsub213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmsub231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmsub231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vfnmsub231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vgetexppd(ymm1, ymm2 |T_sae);  dump(); size_ = 0;
        vgetexpph(ymm1, ymm2 |T_sae);  dump(); size_ = 0;
        vgetexpps(ymm1, ymm2 |T_sae);  dump(); size_ = 0;
        vgetmantpd(ymm1, ymm2 |T_sae, 3);  dump(); size_ = 0;
        vgetmantph(ymm1, ymm2 |T_sae, 3);  dump(); size_ = 0;
        vgetmantps(ymm1, ymm2 |T_sae, 3);  dump(); size_ = 0;
        vmaxpd(ymm1, ymm2, ymm3 |T_sae);  dump(); size_ = 0;
        vmaxph(ymm1, ymm2, ymm3 |T_sae);  dump(); size_ = 0;
        vmaxps(ymm1, ymm2, ymm3 |T_sae);  dump(); size_ = 0;
        vminpd(ymm1, ymm2, ymm3 |T_sae);  dump(); size_ = 0;
        vminph(ymm1, ymm2, ymm3 |T_sae);  dump(); size_ = 0;
        vminps(ymm1, ymm2, ymm3 |T_sae);  dump(); size_ = 0;
        vmulpd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vmulph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vmulps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vrangepd(ymm1, ymm2, ymm3 |T_sae, 3);  dump(); size_ = 0;
        vrangeps(ymm1, ymm2, ymm3 |T_sae, 3);  dump(); size_ = 0;
        vreducepd(ymm1, ymm2 |T_sae, 3);  dump(); size_ = 0;
        vreduceph(ymm1, ymm2 |T_sae, 3);  dump(); size_ = 0;
        vreduceps(ymm1, ymm2 |T_sae, 3);  dump(); size_ = 0;
        vrndscalepd(ymm1, ymm2 |T_sae, 3);  dump(); size_ = 0;
        vrndscaleph(ymm1, ymm2 |T_sae, 3);  dump(); size_ = 0;
        vrndscaleps(ymm1, ymm2 |T_sae, 3);  dump(); size_ = 0;
        vscalefpd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vscalefph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vscalefps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vsqrtpd(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vsqrtph(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vsqrtps(ymm1, ymm2 |T_rn_sae);  dump(); size_ = 0;
        vsubpd(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vsubph(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
        vsubps(ymm1, ymm2, ymm3 |T_rn_sae);  dump(); size_ = 0;
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

@("xed_new_ymm")
unittest
{
    xed_new_ymm();
}

void xed_new_ymm()
{
    //try
    //{
    //    writeln("xed_new_ymm");
        scope Code c = new Code();
        auto tbl = c.getCode();
    
        //writeln(c.getSize());    
        //Xdump(tbl, c.getSize());

    //    writeln("end xed_new_ymm");
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

