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

vaddpd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vaddph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vaddps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vcmppd(k1, ymm2, ymm3 |T_sae, 3);  dump();
vcmpph(k1, ymm2, ymm3 |T_sae, 3);  dump();
vcmpps(k1, ymm2, ymm3 |T_sae, 3);  dump();
vcvtdq2ph(xmm1, ymm2 |T_rn_sae);  dump();
vcvtdq2ps(ymm1, ymm2 |T_rn_sae);  dump();
vcvtpd2dq(xmm1, ymm2 |T_rn_sae);  dump();
vcvtpd2ph(xmm1, ymm2 |T_rn_sae);  dump();
vcvtpd2ps(xmm1, ymm2 |T_rn_sae);  dump();
vcvtpd2qq(ymm1, ymm2 |T_rn_sae);  dump();
vcvtpd2udq(xmm1, ymm2 |T_rn_sae);  dump();
vcvtpd2uqq(ymm1, ymm2 |T_rn_sae);  dump();
vcvtph2dq(ymm1, xmm2 |T_rn_sae);  dump();
vcvtph2pd(ymm1, xmm2 |T_sae);  dump();
vcvtph2ps(ymm1, xmm2 |T_sae);  dump();
vcvtph2psx(ymm1, xmm2 |T_sae);  dump();
vcvtph2qq(ymm1, xmm2 |T_rn_sae);  dump();
vcvtph2udq(ymm1, xmm2 |T_rn_sae);  dump();
vcvtph2uqq(ymm1, xmm2 |T_rn_sae);  dump();
vcvtph2uw(ymm1, ymm2 |T_rn_sae);  dump();
vcvtph2w(ymm1, ymm2 |T_rn_sae);  dump();
vcvtps2dq(ymm1, ymm2 |T_rn_sae);  dump();
vcvtps2pd(ymm1, xmm2 |T_sae);  dump();
vcvtps2ph(xmm1, ymm2 |T_sae, 3);  dump();
vcvtps2phx(xmm1, ymm2 |T_rn_sae);  dump();
vcvtps2qq(ymm1, xmm2 |T_rn_sae);  dump();
vcvtps2udq(ymm1, ymm2 |T_rn_sae);  dump();
vcvtps2uqq(ymm1, xmm2 |T_rn_sae);  dump();
vcvtqq2pd(ymm1, ymm2 |T_rn_sae);  dump();
vcvtqq2ph(xmm1, ymm2 |T_rn_sae);  dump();
vcvtqq2ps(xmm1, ymm2 |T_rn_sae);  dump();
vcvttpd2dq(xmm1, ymm2 |T_sae);  dump();
vcvttpd2qq(ymm1, ymm2 |T_sae);  dump();
vcvttpd2udq(xmm1, ymm2 |T_sae);  dump();
vcvttpd2uqq(ymm1, ymm2 |T_sae);  dump();
vcvttph2dq(ymm1, xmm2 |T_sae);  dump();
vcvttph2qq(ymm1, xmm2 |T_sae);  dump();
vcvttph2udq(ymm1, xmm2 |T_sae);  dump();
vcvttph2uqq(ymm1, xmm2 |T_sae);  dump();
vcvttph2uw(ymm1, ymm2 |T_sae);  dump();
vcvttph2w(ymm1, ymm2 |T_sae);  dump();
vcvttps2dq(ymm1, ymm2 |T_sae);  dump();
vcvttps2qq(ymm1, xmm2 |T_sae);  dump();
vcvttps2udq(ymm1, ymm2 |T_sae);  dump();
vcvttps2uqq(ymm1, xmm2 |T_sae);  dump();
vcvtudq2ph(xmm1, ymm2 |T_rn_sae);  dump();
vcvtudq2ps(ymm1, ymm2 |T_rn_sae);  dump();
vcvtuqq2pd(ymm1, ymm2 |T_rn_sae);  dump();
vcvtuqq2ph(xmm1, ymm2 |T_rn_sae);  dump();
vcvtuqq2ps(xmm1, ymm2 |T_rn_sae);  dump();
vcvtuw2ph(ymm1, ymm2 |T_rn_sae);  dump();
vcvtw2ph(ymm1, ymm2 |T_rn_sae);  dump();
vdivpd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vdivph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vdivps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfcmaddcph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfcmulcph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfixupimmpd(ymm1, ymm2, ymm3 |T_sae, 3);  dump();
vfixupimmps(ymm1, ymm2, ymm3 |T_sae, 3);  dump();
vfmadd132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmadd132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmadd132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmadd213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmadd213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmadd213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmadd231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmadd231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmadd231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmaddcph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmaddsub132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmaddsub132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmaddsub132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmaddsub213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmaddsub213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmaddsub213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmaddsub231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmaddsub231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmaddsub231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsub132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsub132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsub132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsub213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsub213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsub213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsub231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsub231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsub231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsubadd132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsubadd132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsubadd132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsubadd213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsubadd213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsubadd213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsubadd231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsubadd231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmsubadd231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfmulcph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmadd132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmadd132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmadd132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmadd213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmadd213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmadd213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmadd231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmadd231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmadd231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmsub132pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmsub132ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmsub132ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmsub213pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmsub213ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmsub213ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmsub231pd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmsub231ph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vfnmsub231ps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vgetexppd(ymm1, ymm2 |T_sae);  dump();
vgetexpph(ymm1, ymm2 |T_sae);  dump();
vgetexpps(ymm1, ymm2 |T_sae);  dump();
vgetmantpd(ymm1, ymm2 |T_sae, 3);  dump();
vgetmantph(ymm1, ymm2 |T_sae, 3);  dump();
vgetmantps(ymm1, ymm2 |T_sae, 3);  dump();
vmaxpd(ymm1, ymm2, ymm3 |T_sae);  dump();
vmaxph(ymm1, ymm2, ymm3 |T_sae);  dump();
vmaxps(ymm1, ymm2, ymm3 |T_sae);  dump();
vminpd(ymm1, ymm2, ymm3 |T_sae);  dump();
vminph(ymm1, ymm2, ymm3 |T_sae);  dump();
vminps(ymm1, ymm2, ymm3 |T_sae);  dump();
vmulpd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vmulph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vmulps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vrangepd(ymm1, ymm2, ymm3 |T_sae, 3);  dump();
vrangeps(ymm1, ymm2, ymm3 |T_sae, 3);  dump();
vreducepd(ymm1, ymm2 |T_sae, 3);  dump();
vreduceph(ymm1, ymm2 |T_sae, 3);  dump();
vreduceps(ymm1, ymm2 |T_sae, 3);  dump();
vrndscalepd(ymm1, ymm2 |T_sae, 3);  dump();
vrndscaleph(ymm1, ymm2 |T_sae, 3);  dump();
vrndscaleps(ymm1, ymm2 |T_sae, 3);  dump();
vscalefpd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vscalefph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vscalefps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vsqrtpd(ymm1, ymm2 |T_rn_sae);  dump();
vsqrtph(ymm1, ymm2 |T_rn_sae);  dump();
vsqrtps(ymm1, ymm2 |T_rn_sae);  dump();
vsubpd(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vsubph(ymm1, ymm2, ymm3 |T_rn_sae);  dump();
vsubps(ymm1, ymm2, ymm3 |T_rn_sae);  dump();


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
        writeln("comp");
        Code c = new Code();
        auto tbl = c.getCode();
    
        //writeln(c.getSize());    
        //Xdump(tbl, c.getSize());

        writeln("end comp");
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

