module xed_minmax;

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
    @("xed_minmax")
    unittest
    {
        scope Code c = new Code("xed_minmax");
    }

    class Code : TestCode
    {
        this(string name)
        {
            super(name);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            vminmaxbf16(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F36F8B52CB05");
            vminmaxbf16(xm1 | k3 | T_z, xm2, ptr[rax + 64], 5);
            sdump("62F36F8B52480405");
            vminmaxbf16(xm1 | k3 | T_z, xm2, ptr_b[rax + 64], 5);
            sdump("62F36F9B52482005");

            vminmaxbf16(ym1 | k3 | T_z, ym2, ym3, 5);
            sdump("62F36FAB52CB05");
            vminmaxbf16(ym1 | k3 | T_z, ym2, ptr[rax + 64], 5);
            sdump("62F36FAB52480205");
            vminmaxbf16(ym1 | k3 | T_z, ym2, ptr_b[rax + 64], 5);
            sdump("62F36FBB52482005");

            vminmaxbf16(zm1 | k3 | T_z, zm2, zm3, 5);
            sdump("62F36FCB52CB05");
            vminmaxbf16(zm1 | k3 | T_z, zm2, ptr[rax + 64], 5);
            sdump("62F36FCB52480105");
            vminmaxbf16(zm1 | k3 | T_z, zm2, ptr_b[rax + 64], 5);
            sdump("62F36FDB52482005");
            //
            vminmaxpd(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F3ED8B52CB05");
            vminmaxpd(xm1 | k3 | T_z, xm2, ptr[rax + 64], 5);
            sdump("62F3ED8B52480405");
            vminmaxpd(xm1 | k3 | T_z, xm2, ptr_b[rax + 64], 5);
            sdump("62F3ED9B52480805");

            vminmaxpd(ym1 | k3 | T_z, ym2, ym3, 5);
            sdump("62F3EDAB52CB05");
        //    vminmaxpd(ym1 | k3 | T_z, ym2, ym3 | T_sae, 5);
        //    sdump("62F3E99B52CB05");
            vminmaxpd(ym1 | k3 | T_z, ym2, ptr[rax + 64], 5);
            sdump("62F3EDAB52480205");
            vminmaxpd(ym1 | k3 | T_z, ym2, ptr_b[rax + 64], 5);
            sdump("62F3EDBB52480805");

            vminmaxpd(zm1 | k3 | T_z, zm2, zm3, 5);
            sdump("62F3EDCB52CB05");
            vminmaxpd(zm1 | k3 | T_z, zm2, zm3 | T_sae, 5);
            sdump("62F3ED9B52CB05");
            vminmaxpd(zm1 | k3 | T_z, zm2, ptr[rax + 64], 5);
            sdump("62F3EDCB52480105");
            vminmaxpd(zm1 | k3 | T_z, zm2, ptr_b[rax + 64], 5);
            sdump("62F3EDDB52480805");
            //
            vminmaxph(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F36C8B52CB05");
            vminmaxph(xm1 | k3 | T_z, xm2, ptr[rax + 64], 5);
            sdump("62F36C8B52480405");
            vminmaxph(xm1 | k3 | T_z, xm2, ptr[rax + 64], 5);
            sdump("62F36C8B52480405");
            vminmaxph(xm1 | k3 | T_z, xm2, ptr_b[rax + 64], 5);
            sdump("62F36C9B52482005");

            vminmaxph(ym1 | k3 | T_z, ym2, ym3, 5);
            sdump("62F36CAB52CB05");
        //    vminmaxph(ym1 | k3 | T_z, ym2, ym3 | T_sae, 5);
        //    sdump("62F3689B52CB05");
            vminmaxph(ym1 | k3 | T_z, ym2, ptr[rax + 64], 5);
            sdump("62F36CAB52480205");
            vminmaxph(ym1 | k3 | T_z, ym2, ptr_b[rax + 64], 5);
            sdump("62F36CBB52482005");

            vminmaxph(zm1 | k3 | T_z, zm2, zm3, 5);
            sdump("62F36CCB52CB05");
            vminmaxph(zm1 | k3 | T_z, zm2, zm3 | T_sae, 5);
            sdump("62F36C9B52CB05");
            vminmaxph(zm1 | k3 | T_z, zm2, ptr[rax + 64], 5);
            sdump("62F36CCB52480105");
            vminmaxph(zm1 | k3 | T_z, zm2, ptr_b[rax + 64], 5);
            sdump("62F36CDB52482005");
            //
            vminmaxps(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F36D8B52CB05");
            vminmaxps(xm1 | k3 | T_z, xm2, ptr[rax + 64], 5);
            sdump("62F36D8B52480405");
            vminmaxps(xm1 | k3 | T_z, xm2, ptr_b[rax + 64], 5);
            sdump("62F36D9B52481005");

            vminmaxps(ym1 | k3 | T_z, ym2, ym3, 5);
            sdump("62F36DAB52CB05");
        //    vminmaxps(ym1 | k3 | T_z, ym2, ym3 | T_sae, 5);
        //    sdump("62F3699B52CB05");
            vminmaxps(ym1 | k3 | T_z, ym2, ptr[rax + 64], 5);
            sdump("62F36DAB52480205");
            vminmaxps(ym1 | k3 | T_z, ym2, ptr_b[rax + 64], 5);
            sdump("62F36DBB52481005");

            vminmaxps(zm1 | k3 | T_z, zm2, zm3, 5);
            sdump("62F36DCB52CB05");
            vminmaxps(zm1 | k3 | T_z, zm2, zm3 | T_sae, 5);
            sdump("62F36D9B52CB05");
            vminmaxps(zm1 | k3 | T_z, zm2, ptr[rax + 64], 5);
            sdump("62F36DCB52480105");
            vminmaxps(zm1 | k3 | T_z, zm2, ptr_b[rax + 64], 5);
            sdump("62F36DDB52481005");
            //
            vminmaxsd(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F3ED8B53CB05");
            vminmaxsd(xm1 | k3 | T_z, xm2, xm3 | T_sae, 5);
            sdump("62F3ED9B53CB05");
            vminmaxsd(xm1 | k3 | T_z, xm2, ptr[rax + 64], 5);
            sdump("62F3ED8B53480805");
            //
            vminmaxsh(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F36C8B53CB05");
            vminmaxsh(xm1 | k3 | T_z, xm2, xm3 | T_sae, 5);
            sdump("62F36C9B53CB05");
            vminmaxsh(xm1 | k3 | T_z, xm2, ptr[rax + 64], 5);
            sdump("62F36C8B53482005");
            //
            vminmaxss(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F36D8B53CB05");
            vminmaxss(xm1 | k3 | T_z, xm2, xm3 | T_sae, 5);
            sdump("62F36D9B53CB05");
            vminmaxss(xm1 | k3 | T_z, xm2, ptr[rax + 64], 5);
            sdump("62F36D8B53481005");

        }
    }
}
