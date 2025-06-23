module xed_bf16;

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

    @("xed_bf16")
    unittest
    {
        xed_bf16();
    }

    void xed_bf16()
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
            testCount.end("xed_bf16");
        }

        this()
        {
            testCount.reset();

            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            vaddbf16(xm1, xm2, xm3);
            sdump("62F56D0858CB");
            vaddbf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F56D29584804");
            vaddbf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F56D39584840");
            vaddbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F56DDA584840");

            vdivbf16(xm1, xm2, xm3);
            sdump("62F56D085ECB");
            vdivbf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F56D295E4804");
            vdivbf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F56D395E4840");
            vdivbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F56DDA5E4840");

            vmaxbf16(xm1, xm2, xm3);
            sdump("62F56D085FCB");
            vmaxbf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F56D295F4804");
            vmaxbf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F56D395F4840");
            vmaxbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F56DDA5F4840");

            vminbf16(xm1, xm2, xm3);
            sdump("62F56D085DCB");
            vminbf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F56D295D4804");
            vminbf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F56D395D4840");
            vminbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F56DDA5D4840");

            vmulbf16(xm1, xm2, xm3);
            sdump("62F56D0859CB");
            vmulbf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F56D29594804");
            vmulbf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F56D39594840");
            vmulbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F56DDA594840");

            vscalefbf16(xm1, xm2, xm3);
            sdump("62F66C082CCB");
            vscalefbf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C292C4804");
            vscalefbf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C392C4840");
            vscalefbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDA2C4840");

            vsubbf16(xm1, xm2, xm3);
            sdump("62F56D085CCB");
            vsubbf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F56D295C4804");
            vsubbf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F56D395C4840");
            vsubbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F56DDA5C4840");
            // madd
            vfmadd132bf16(xm1, xm2, xm3);
            sdump("62F66C0898CB");
            vfmadd132bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C29984804");
            vfmadd132bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C39984840");
            vfmadd132bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDA984840");

            vfmadd213bf16(xm1, xm2, xm3);
            sdump("62F66C08A8CB");
            vfmadd213bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C29A84804");
            vfmadd213bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C39A84840");
            vfmadd213bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDAA84840");

            vfmadd231bf16(xm1, xm2, xm3);
            sdump("62F66C08B8CB");
            vfmadd231bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C29B84804");
            vfmadd231bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C39B84840");
            vfmadd231bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDAB84840");
            // nmadd
            vfnmadd132bf16(xm1, xm2, xm3);
            sdump("62F66C089CCB");
            vfnmadd132bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C299C4804");
            vfnmadd132bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C399C4840");
            vfnmadd132bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDA9C4840");

            vfnmadd213bf16(xm1, xm2, xm3);
            sdump("62F66C08ACCB");
            vfnmadd213bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C29AC4804");
            vfnmadd213bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C39AC4840");
            vfnmadd213bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDAAC4840");

            vfnmadd231bf16(xm1, xm2, xm3);
            sdump("62F66C08BCCB");
            vfnmadd231bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C29BC4804");
            vfnmadd231bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C39BC4840");
            vfnmadd231bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDABC4840");
            // msub
            vfmsub132bf16(xm1, xm2, xm3);
            sdump("62F66C089ACB");
            vfmsub132bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C299A4804");
            vfmsub132bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C399A4840");
            vfmsub132bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDA9A4840");

            vfmsub213bf16(xm1, xm2, xm3);
            sdump("62F66C08AACB");
            vfmsub213bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C29AA4804");
            vfmsub213bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C39AA4840");
            vfmsub213bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDAAA4840");

            vfmsub231bf16(xm1, xm2, xm3);
            sdump("62F66C08BACB");
            vfmsub231bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C29BA4804");
            vfmsub231bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C39BA4840");
            vfmsub231bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDABA4840");
            // nmsub
            vfnmsub132bf16(xm1, xm2, xm3);
            sdump("62F66C089ECB");
            vfnmsub132bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C299E4804");
            vfnmsub132bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C399E4840");
            vfnmsub132bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDA9E4840");

            vfnmsub213bf16(xm1, xm2, xm3);
            sdump("62F66C08AECB");
            vfnmsub213bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C29AE4804");
            vfnmsub213bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C39AE4840");
            vfnmsub213bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDAAE4840");

            vfnmsub231bf16(xm1, xm2, xm3);
            sdump("62F66C08BECB");
            vfnmsub231bf16(ym1 | k1, ym2, ptr[rax + 128]);
            sdump("62F66C29BE4804");
            vfnmsub231bf16(ym1 | k1, ym2, ptr_b[rax + 128]);
            sdump("62F66C39BE4840");
            vfnmsub231bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 128]);
            sdump("62F66CDABE4840");

            vcmpbf16(k1, xm5, xm4, 5);
            sdump("62F35708C2CC05");
            vcmpbf16(k2, ym5, ym4, 6);
            sdump("62F35728C2D406");
            vcmpbf16(k3, ym15, ptr_b[rax + 128], 7);
            sdump("62F30738C2584007");
            vcmpbf16(k4, zm30, zm20, 8);
            sdump("62B30F40C2E408");
            vcmpbf16(k5, zm1, ptr[rax + 128], 9);
            sdump("62F37748C2680209");
            vcmpbf16(k6, zm10, ptr_b[rax + 128], 10);
            sdump("62F32F58C270400A");

            vfpclassbf16(k1, xm4, 5);
            sdump("62F37F0866CC05");
            vfpclassbf16(k2 | k5, ym4, 6);
            sdump("62F37F2D66D406");
            vfpclassbf16(k3 | k5, zm20, 7);
            sdump("62B37F4D66DC07");
            vfpclassbf16(k3 | k5, xword[rax + 128], 8);
            sdump("62F37F0D66580808");
            vfpclassbf16(k3, xword_b[rax + 128], 9);
            sdump("62F37F1866584009");
            vfpclassbf16(k5 | k5, yword[rax + 128], 10);
            sdump("62F37F2D6668040A");
            vfpclassbf16(k6 | k5, yword_b[rax + 128], 11);
            sdump("62F37F3D6670400B");
            vfpclassbf16(k7 | k5, zword[rax + 128], 12);
            sdump("62F37F4D6678020C");
            vfpclassbf16(k7 | k5, zword_b[rax + 128], 13);
            sdump("62F37F5D6678400D");

            vcomisbf16(xm2, xm3);
            sdump("62F57D082FD3");
            vcomisbf16(xm2, ptr[rax + 128]);
            sdump("62F57D082F5040");

            vgetexpbf16(xm1 | k3, xmm2);
            sdump("62F67C0B42CA");
            vgetexpbf16(xm1 | k3, ptr[rax + 128]);
            sdump("62F67C0B424808");
            vgetexpbf16(xm1 | k3, ptr_b[rax + 128]);
            sdump("62F67C1B424840");

            vgetexpbf16(ym1 | k3, ymm2);
            sdump("62F67C2B42CA");
            vgetexpbf16(ym1 | k3, ptr[rax + 128]);
            sdump("62F67C2B424804");
            vgetexpbf16(ym1 | k3, ptr_b[rax + 128]);
            sdump("62F67C3B424840");

            vgetexpbf16(zm1 | k3, zmm2);
            sdump("62F67C4B42CA");
            vgetexpbf16(zm1 | k3, ptr[rax + 128]);
            sdump("62F67C4B424802");
            vgetexpbf16(zm1 | k3, ptr_b[rax + 128]);
            sdump("62F67C5B424840");

            vgetmantbf16(xm1 | k3, xmm2, 3);
            sdump("62F37F0B26CA03");
            vgetmantbf16(xm1 | k3, ptr[rax + 128], 5);
            sdump("62F37F0B26480805");
            vgetmantbf16(xm1 | k3, ptr_b[rax + 128], 9);
            sdump("62F37F1B26484009");

            vgetmantbf16(ym1 | k3, ymm2, 3);
            sdump("62F37F2B26CA03");
            vgetmantbf16(ym1 | k3, ptr[rax + 128], 5);
            sdump("62F37F2B26480405");
            vgetmantbf16(ym1 | k3, ptr_b[rax + 128], 9);
            sdump("62F37F3B26484009");

            vgetmantbf16(zm1 | k3, zmm2, 3);
            sdump("62F37F4B26CA03");
            vgetmantbf16(zm1 | k3, ptr[rax + 128], 5);
            sdump("62F37F4B26480205");
            vgetmantbf16(zm1 | k3, ptr_b[rax + 128], 9);
            sdump("62F37F5B26484009");

            vrcpbf16(xm1 | k5, xm2);
            sdump("62F67C0D4CCA");
            vrcpbf16(xm1 | k5, ptr[rcx + 128]);
            sdump("62F67C0D4C4908");
            vrcpbf16(xm1 | k5, ptr_b[rcx + 128]);
            sdump("62F67C1D4C4940");

            vrcpbf16(ym1 | k5, ym2);
            sdump("62F67C2D4CCA");
            vrcpbf16(ym1 | k5, ptr[rcx + 128]);
            sdump("62F67C2D4C4904");
            vrcpbf16(ym1 | k5, ptr_b[rcx + 128]);
            sdump("62F67C3D4C4940");

            vrcpbf16(zm1 | k5, zm2);
            sdump("62F67C4D4CCA");
            vrcpbf16(zm1 | k5, ptr[rcx + 128]);
            sdump("62F67C4D4C4902");
            vrcpbf16(zm1 | k5, ptr_b[rcx + 128]);
            sdump("62F67C5D4C4940");

            vreducebf16(xm1 | k4, xm2, 1);
            sdump("62F37F0C56CA01");
            vreducebf16(xm1 | k4, ptr[rax + 128], 1);
            sdump("62F37F0C56480801");
            vreducebf16(xm1 | k4, ptr_b[rax + 128], 1);
            sdump("62F37F1C56484001");

            vreducebf16(ym1 | k4, ym2, 1);
            sdump("62F37F2C56CA01");
            vreducebf16(ym1 | k4, ptr[rax + 128], 1);
            sdump("62F37F2C56480401");
            vreducebf16(ym1 | k4, ptr_b[rax + 128], 1);
            sdump("62F37F3C56484001");

            vreducebf16(zm1 | k4, zm2, 1);
            sdump("62F37F4C56CA01");
            vreducebf16(zm1 | k4, ptr[rax + 128], 1);
            sdump("62F37F4C56480201");
            vreducebf16(zm1 | k4, ptr_b[rax + 128], 1);
            sdump("62F37F5C56484001");

            vrndscalebf16(xm1 | k4, xm2, 1);
            sdump("62F37F0C08CA01");
            vrndscalebf16(xm1 | k4, ptr[rax + 128], 1);
            sdump("62F37F0C08480801");
            vrndscalebf16(xm1 | k4, ptr_b[rax + 128], 1);
            sdump("62F37F1C08484001");

            vrndscalebf16(ym1 | k4, ym2, 1);
            sdump("62F37F2C08CA01");
            vrndscalebf16(ym1 | k4, ptr[rax + 128], 1);
            sdump("62F37F2C08480401");
            vrndscalebf16(ym1 | k4, ptr_b[rax + 128], 1);
            sdump("62F37F3C08484001");

            vrndscalebf16(zm1 | k4, zm2, 1);
            sdump("62F37F4C08CA01");
            vrndscalebf16(zm1 | k4, ptr[rax + 128], 1);
            sdump("62F37F4C08480201");
            vrndscalebf16(zm1 | k4, ptr_b[rax + 128], 1);
            sdump("62F37F5C08484001");

            vrsqrtbf16(xm1 | k5, xm2);
            sdump("62F67C0D4ECA");
            vrsqrtbf16(xm1 | k5, ptr[rcx + 128]);
            sdump("62F67C0D4E4908");
            vrsqrtbf16(xm1 | k5, ptr_b[rcx + 128]);
            sdump("62F67C1D4E4940");

            vrsqrtbf16(ym1 | k5, ym2);
            sdump("62F67C2D4ECA");
            vrsqrtbf16(ym1 | k5, ptr[rcx + 128]);
            sdump("62F67C2D4E4904");
            vrsqrtbf16(ym1 | k5, ptr_b[rcx + 128]);
            sdump("62F67C3D4E4940");

            vrsqrtbf16(zm1 | k5, zm2);
            sdump("62F67C4D4ECA");
            vrsqrtbf16(zm1 | k5, ptr[rcx + 128]);
            sdump("62F67C4D4E4902");
            vrsqrtbf16(zm1 | k5, ptr_b[rcx + 128]);
            sdump("62F67C5D4E4940");

            vscalefbf16(xm1 | k5, xm5, xm2);
            sdump("62F6540D2CCA");
            vscalefbf16(xm1 | k5, xm5, ptr[rcx + 128]);
            sdump("62F6540D2C4908");
            vscalefbf16(xm1 | k5, xm5, ptr_b[rcx + 128]);
            sdump("62F6541D2C4940");

            vscalefbf16(ym1 | k5, ym9, ym2);
            sdump("62F6342D2CCA");
            vscalefbf16(ym1 | k5, ym9, ptr[rcx + 128]);
            sdump("62F6342D2C4904");
            vscalefbf16(ym1 | k5, ym9, ptr_b[rcx + 128]);
            sdump("62F6343D2C4940");

            vscalefbf16(zm1 | k5, zm30, zm2);
            sdump("62F60C452CCA");
            vscalefbf16(zm1 | k5, zm30, ptr[rcx + 128]);
            sdump("62F60C452C4902");
            vscalefbf16(zm1 | k5, zm30, ptr_b[rcx + 128]);
            sdump("62F60C552C4940");

            vsqrtbf16(xm5 | k3, xmm4);
            sdump("62F57D0B51EC");
            vsqrtbf16(xm5 | k3, ptr[rax + 128]);
            sdump("62F57D0B516808");
            vsqrtbf16(xm5 | k3, ptr_b[rax + 128]);
            sdump("62F57D1B516840");

            vsqrtbf16(ym5 | k3, ymm4);
            sdump("62F57D2B51EC");
            vsqrtbf16(ym5 | k3, ptr[rax + 128]);
            sdump("62F57D2B516804");
            vsqrtbf16(ym5 | k3, ptr_b[rax + 128]);
            sdump("62F57D3B516840");

            vsqrtbf16(zm5 | k3, zmm4);
            sdump("62F57D4B51EC");
            vsqrtbf16(zm5 | k3, ptr[rax + 128]);
            sdump("62F57D4B516802");
            vsqrtbf16(zm5 | k3, ptr_b[rax + 128]);
            sdump("62F57D5B516840");

        }
    }
}
