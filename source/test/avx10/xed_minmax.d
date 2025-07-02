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
        xed_minmax();
    }

    void xed_minmax()
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
            vminmaxbf16(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F36F8B52CB05");
            vminmaxbf16(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            sdump("62F36F8B52480805");
            vminmaxbf16(xm1 | k3 | T_z, xm2, ptr_b[rax + 128], 5);
            sdump("62F36F9B52484005");

            vminmaxbf16(ym1 | k3 | T_z, ym2, ym3, 5);
            sdump("62F36FAB52CB05");
            vminmaxbf16(ym1 | k3 | T_z, ym2, ptr[rax + 128], 5);
            sdump("62F36FAB52480405");
            vminmaxbf16(ym1 | k3 | T_z, ym2, ptr_b[rax + 128], 5);
            sdump("62F36FBB52484005");

            vminmaxbf16(zm1 | k3 | T_z, zm2, zm3, 5);
            sdump("62F36FCB52CB05");
            vminmaxbf16(zm1 | k3 | T_z, zm2, ptr[rax + 128], 5);
            sdump("62F36FCB52480205");
            vminmaxbf16(zm1 | k3 | T_z, zm2, ptr_b[rax + 128], 5);
            sdump("62F36FDB52484005");
            //
            vminmaxpd(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F3ED8B52CB05");
            vminmaxpd(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            sdump("62F3ED8B52480805");
            vminmaxpd(xm1 | k3 | T_z, xm2, ptr_b[rax + 128], 5);
            sdump("62F3ED9B52481005");

            vminmaxpd(ym1 | k3 | T_z, ym2, ym3, 5);
            sdump("62F3EDAB52CB05");
            vminmaxpd(ym1 | k3 | T_z, ym2, ptr[rax + 128], 5);
            sdump("62F3EDAB52480405");
            vminmaxpd(ym1 | k3 | T_z, ym2, ptr_b[rax + 128], 5);
            sdump("62F3EDBB52481005");

            vminmaxpd(zm1 | k3 | T_z, zm2, zm3, 5);
            sdump("62F3EDCB52CB05");
            vminmaxpd(zm1 | k3 | T_z, zm2, zm3 | T_sae, 5);
            sdump("62F3ED9B52CB05");
            vminmaxpd(zm1 | k3 | T_z, zm2, ptr[rax + 128], 5);
            sdump("62F3EDCB52480205");
            vminmaxpd(zm1 | k3 | T_z, zm2, ptr_b[rax + 128], 5);
            sdump("62F3EDDB52481005");
            //
            vminmaxph(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F36C8B52CB05");
            vminmaxph(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            sdump("62F36C8B52480805");
            vminmaxph(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            sdump("62F36C8B52480805");
            vminmaxph(xm1 | k3 | T_z, xm2, ptr_b[rax + 128], 5);
            sdump("62F36C9B52484005");

            vminmaxph(ym1 | k3 | T_z, ym2, ym3, 5);
            sdump("62F36CAB52CB05");
            vminmaxph(ym1 | k3 | T_z, ym2, ptr[rax + 128], 5);
            sdump("62F36CAB52480405");
            vminmaxph(ym1 | k3 | T_z, ym2, ptr_b[rax + 128], 5);
            sdump("62F36CBB52484005");

            vminmaxph(zm1 | k3 | T_z, zm2, zm3, 5);
            sdump("62F36CCB52CB05");
            vminmaxph(zm1 | k3 | T_z, zm2, zm3 | T_sae, 5);
            sdump("62F36C9B52CB05");
            vminmaxph(zm1 | k3 | T_z, zm2, ptr[rax + 128], 5);
            sdump("62F36CCB52480205");
            vminmaxph(zm1 | k3 | T_z, zm2, ptr_b[rax + 128], 5);
            sdump("62F36CDB52484005");
            //
            vminmaxps(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F36D8B52CB05");
            vminmaxps(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            sdump("62F36D8B52480805");
            vminmaxps(xm1 | k3 | T_z, xm2, ptr_b[rax + 128], 5);
            sdump("62F36D9B52482005");

            vminmaxps(ym1 | k3 | T_z, ym2, ym3, 5);
            sdump("62F36DAB52CB05");
            vminmaxps(ym1 | k3 | T_z, ym2, ptr[rax + 128], 5);
            sdump("62F36DAB52480405");
            vminmaxps(ym1 | k3 | T_z, ym2, ptr_b[rax + 128], 5);
            sdump("62F36DBB52482005");

            vminmaxps(zm1 | k3 | T_z, zm2, zm3, 5);
            sdump("62F36DCB52CB05");
            vminmaxps(zm1 | k3 | T_z, zm2, zm3 | T_sae, 5);
            sdump("62F36D9B52CB05");
            vminmaxps(zm1 | k3 | T_z, zm2, ptr[rax + 128], 5);
            sdump("62F36DCB52480205");
            vminmaxps(zm1 | k3 | T_z, zm2, ptr_b[rax + 128], 5);
            sdump("62F36DDB52482005");
            //
            vminmaxsd(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F3ED8B53CB05");
            vminmaxsd(xm1 | k3 | T_z, xm2, xm3 | T_sae, 5);
            sdump("62F3ED9B53CB05");
            vminmaxsd(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            sdump("62F3ED8B53481005");
            //
            vminmaxsh(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F36C8B53CB05");
            vminmaxsh(xm1 | k3 | T_z, xm2, xm3 | T_sae, 5);
            sdump("62F36C9B53CB05");
            vminmaxsh(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            sdump("62F36C8B53484005");
            //
            vminmaxss(xm1 | k3 | T_z, xm2, xm3, 5);
            sdump("62F36D8B53CB05");
            vminmaxss(xm1 | k3 | T_z, xm2, xm3 | T_sae, 5);
            sdump("62F36D9B53CB05");
            vminmaxss(xm1 | k3 | T_z, xm2, ptr[rax + 128], 5);
            sdump("62F36D8B53482005");

        }
    }
}
