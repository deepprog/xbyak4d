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
        scope Code c = new Code("xed_bf16");
    }

    class Code : TestCode
    {
        this(string name)
        {
            super(name);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            vaddbf16(xm1, xm2, xm3);
            sdump("62F56D0858CB");
            vaddbf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F56D29584802");
            vaddbf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F56D39584820");
            vaddbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F56DDA584820");

            vdivbf16(xm1, xm2, xm3);
            sdump("62F56D085ECB");
            vdivbf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F56D295E4802");
            vdivbf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F56D395E4820");
            vdivbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F56DDA5E4820");

            vmaxbf16(xm1, xm2, xm3);
            sdump("62F56D085FCB");
            vmaxbf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F56D295F4802");
            vmaxbf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F56D395F4820");
            vmaxbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F56DDA5F4820");

            vminbf16(xm1, xm2, xm3);
            sdump("62F56D085DCB");
            vminbf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F56D295D4802");
            vminbf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F56D395D4820");
            vminbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F56DDA5D4820");

            vmulbf16(xm1, xm2, xm3);
            sdump("62F56D0859CB");
            vmulbf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F56D29594802");
            vmulbf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F56D39594820");
            vmulbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F56DDA594820");

            vscalefbf16(xm1, xm2, xm3);
            sdump("62F66C082CCB");
            vscalefbf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C292C4802");
            vscalefbf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C392C4820");
            vscalefbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDA2C4820");

            vsubbf16(xm1, xm2, xm3);
            sdump("62F56D085CCB");
            vsubbf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F56D295C4802");
            vsubbf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F56D395C4820");
            vsubbf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F56DDA5C4820");
            // madd
            vfmadd132bf16(xm1, xm2, xm3);
            sdump("62F66C0898CB");
            vfmadd132bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C29984802");
            vfmadd132bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C39984820");
            vfmadd132bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDA984820");

            vfmadd213bf16(xm1, xm2, xm3);
            sdump("62F66C08A8CB");
            vfmadd213bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C29A84802");
            vfmadd213bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C39A84820");
            vfmadd213bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDAA84820");

            vfmadd231bf16(xm1, xm2, xm3);
            sdump("62F66C08B8CB");
            vfmadd231bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C29B84802");
            vfmadd231bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C39B84820");
            vfmadd231bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDAB84820");
            // nmadd
            vfnmadd132bf16(xm1, xm2, xm3);
            sdump("62F66C089CCB");
            vfnmadd132bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C299C4802");
            vfnmadd132bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C399C4820");
            vfnmadd132bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDA9C4820");

            vfnmadd213bf16(xm1, xm2, xm3);
            sdump("62F66C08ACCB");
            vfnmadd213bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C29AC4802");
            vfnmadd213bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C39AC4820");
            vfnmadd213bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDAAC4820");

            vfnmadd231bf16(xm1, xm2, xm3);
            sdump("62F66C08BCCB");
            vfnmadd231bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C29BC4802");
            vfnmadd231bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C39BC4820");
            vfnmadd231bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDABC4820");
            // msub
            vfmsub132bf16(xm1, xm2, xm3);
            sdump("62F66C089ACB");
            vfmsub132bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C299A4802");
            vfmsub132bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C399A4820");
            vfmsub132bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDA9A4820");

            vfmsub213bf16(xm1, xm2, xm3);
            sdump("62F66C08AACB");
            vfmsub213bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C29AA4802");
            vfmsub213bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C39AA4820");
            vfmsub213bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDAAA4820");

            vfmsub231bf16(xm1, xm2, xm3);
            sdump("62F66C08BACB");
            vfmsub231bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C29BA4802");
            vfmsub231bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C39BA4820");
            vfmsub231bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDABA4820");
            // nmsub
            vfnmsub132bf16(xm1, xm2, xm3);
            sdump("62F66C089ECB");
            vfnmsub132bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C299E4802");
            vfnmsub132bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C399E4820");
            vfnmsub132bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDA9E4820");

            vfnmsub213bf16(xm1, xm2, xm3);
            sdump("62F66C08AECB");
            vfnmsub213bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C29AE4802");
            vfnmsub213bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C39AE4820");
            vfnmsub213bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDAAE4820");

            vfnmsub231bf16(xm1, xm2, xm3);
            sdump("62F66C08BECB");
            vfnmsub231bf16(ym1 | k1, ym2, ptr[rax + 64]);
            sdump("62F66C29BE4802");
            vfnmsub231bf16(ym1 | k1, ym2, ptr_b[rax + 64]);
            sdump("62F66C39BE4820");
            vfnmsub231bf16(zm1 | k2 | T_z, zm2, ptr_b[rax + 64]);
            sdump("62F66CDABE4820");

            vcmpbf16(k1, xm5, xm4, 5);
            sdump("62F35708C2CC05");
            vcmpbf16(k2, ym5, ym4, 6);
            sdump("62F35728C2D406");
            vcmpbf16(k3, ym15, ptr_b[rax + 64], 7);
            sdump("62F30738C2582007");
            vcmpbf16(k4, zm30, zm20, 8);
            sdump("62B30F40C2E408");
            vcmpbf16(k5, zm1, ptr[rax + 64], 9);
            sdump("62F37748C2680109");
            vcmpbf16(k6, zm10, ptr_b[rax + 64], 10);
            sdump("62F32F58C270200A");

            vfpclassbf16(k1, xm4, 5);
            sdump("62F37F0866CC05");
            vfpclassbf16(k2 | k5, ym4, 6);
            sdump("62F37F2D66D406");
            vfpclassbf16(k3 | k5, zm20, 7);
            sdump("62B37F4D66DC07");
            vfpclassbf16(k3 | k5, xword[rax + 64], 8);
            sdump("62F37F0D66580408");
            vfpclassbf16(k3, xword_b[rax + 64], 9);
            sdump("62F37F1866582009");
            vfpclassbf16(k5 | k5, yword[rax + 64], 10);
            sdump("62F37F2D6668020A");
            vfpclassbf16(k6 | k5, yword_b[rax + 64], 11);
            sdump("62F37F3D6670200B");
            vfpclassbf16(k7 | k5, zword[rax + 64], 12);
            sdump("62F37F4D6678010C");
            vfpclassbf16(k7 | k5, zword_b[rax + 64], 13);
            sdump("62F37F5D6678200D");

            vcomisbf16(xm2, xm3);
            sdump("62F57D082FD3");
            vcomisbf16(xm2, ptr[rax + 64]);
            sdump("62F57D082F5020");

            vgetexpbf16(xm1 | k3, xmm2);
            sdump("62F67C0B42CA");
            vgetexpbf16(xm1 | k3, ptr[rax + 64]);
            sdump("62F67C0B424804");
            vgetexpbf16(xm1 | k3, ptr_b[rax + 64]);
            sdump("62F67C1B424820");

            vgetexpbf16(ym1 | k3, ymm2);
            sdump("62F67C2B42CA");
            vgetexpbf16(ym1 | k3, ptr[rax + 64]);
            sdump("62F67C2B424802");
            vgetexpbf16(ym1 | k3, ptr_b[rax + 64]);
            sdump("62F67C3B424820");

            vgetexpbf16(zm1 | k3, zmm2);
            sdump("62F67C4B42CA");
            vgetexpbf16(zm1 | k3, ptr[rax + 64]);
            sdump("62F67C4B424801");
            vgetexpbf16(zm1 | k3, ptr_b[rax + 64]);
            sdump("62F67C5B424820");

            vgetmantbf16(xm1 | k3, xmm2, 3);
            sdump("62F37F0B26CA03");
            vgetmantbf16(xm1 | k3, ptr[rax + 64], 5);
            sdump("62F37F0B26480405");
            vgetmantbf16(xm1 | k3, ptr_b[rax + 64], 9);
            sdump("62F37F1B26482009");

            vgetmantbf16(ym1 | k3, ymm2, 3);
            sdump("62F37F2B26CA03");
            vgetmantbf16(ym1 | k3, ptr[rax + 64], 5);
            sdump("62F37F2B26480205");
            vgetmantbf16(ym1 | k3, ptr_b[rax + 64], 9);
            sdump("62F37F3B26482009");

            vgetmantbf16(zm1 | k3, zmm2, 3);
            sdump("62F37F4B26CA03");
            vgetmantbf16(zm1 | k3, ptr[rax + 64], 5);
            sdump("62F37F4B26480105");
            vgetmantbf16(zm1 | k3, ptr_b[rax + 64], 9);
            sdump("62F37F5B26482009");

            vrcpbf16(xm1 | k5, xm2);
            sdump("62F67C0D4CCA");
            vrcpbf16(xm1 | k5, ptr[rcx + 64]);
            sdump("62F67C0D4C4904");
            vrcpbf16(xm1 | k5, ptr_b[rcx + 64]);
            sdump("62F67C1D4C4920");

            vrcpbf16(ym1 | k5, ym2);
            sdump("62F67C2D4CCA");
            vrcpbf16(ym1 | k5, ptr[rcx + 64]);
            sdump("62F67C2D4C4902");
            vrcpbf16(ym1 | k5, ptr_b[rcx + 64]);
            sdump("62F67C3D4C4920");

            vrcpbf16(zm1 | k5, zm2);
            sdump("62F67C4D4CCA");
            vrcpbf16(zm1 | k5, ptr[rcx + 64]);
            sdump("62F67C4D4C4901");
            vrcpbf16(zm1 | k5, ptr_b[rcx + 64]);
            sdump("62F67C5D4C4920");

            vreducebf16(xm1 | k4, xm2, 1);
            sdump("62F37F0C56CA01");
            vreducebf16(xm1 | k4, ptr[rax + 64], 1);
            sdump("62F37F0C56480401");
            vreducebf16(xm1 | k4, ptr_b[rax + 64], 1);
            sdump("62F37F1C56482001");

            vreducebf16(ym1 | k4, ym2, 1);
            sdump("62F37F2C56CA01");
            vreducebf16(ym1 | k4, ptr[rax + 64], 1);
            sdump("62F37F2C56480201");
            vreducebf16(ym1 | k4, ptr_b[rax + 64], 1);
            sdump("62F37F3C56482001");

            vreducebf16(zm1 | k4, zm2, 1);
            sdump("62F37F4C56CA01");
            vreducebf16(zm1 | k4, ptr[rax + 64], 1);
            sdump("62F37F4C56480101");
            vreducebf16(zm1 | k4, ptr_b[rax + 64], 1);
            sdump("62F37F5C56482001");

            vrndscalebf16(xm1 | k4, xm2, 1);
            sdump("62F37F0C08CA01");
            vrndscalebf16(xm1 | k4, ptr[rax + 64], 1);
            sdump("62F37F0C08480401");
            vrndscalebf16(xm1 | k4, ptr_b[rax + 64], 1);
            sdump("62F37F1C08482001");

            vrndscalebf16(ym1 | k4, ym2, 1);
            sdump("62F37F2C08CA01");
            vrndscalebf16(ym1 | k4, ptr[rax + 64], 1);
            sdump("62F37F2C08480201");
            vrndscalebf16(ym1 | k4, ptr_b[rax + 64], 1);
            sdump("62F37F3C08482001");

            vrndscalebf16(zm1 | k4, zm2, 1);
            sdump("62F37F4C08CA01");
            vrndscalebf16(zm1 | k4, ptr[rax + 64], 1);
            sdump("62F37F4C08480101");
            vrndscalebf16(zm1 | k4, ptr_b[rax + 64], 1);
            sdump("62F37F5C08482001");

            vrsqrtbf16(xm1 | k5, xm2);
            sdump("62F67C0D4ECA");
            vrsqrtbf16(xm1 | k5, ptr[rcx + 64]);
            sdump("62F67C0D4E4904");
            vrsqrtbf16(xm1 | k5, ptr_b[rcx + 64]);
            sdump("62F67C1D4E4920");

            vrsqrtbf16(ym1 | k5, ym2);
            sdump("62F67C2D4ECA");
            vrsqrtbf16(ym1 | k5, ptr[rcx + 64]);
            sdump("62F67C2D4E4902");
            vrsqrtbf16(ym1 | k5, ptr_b[rcx + 64]);
            sdump("62F67C3D4E4920");

            vrsqrtbf16(zm1 | k5, zm2);
            sdump("62F67C4D4ECA");
            vrsqrtbf16(zm1 | k5, ptr[rcx + 64]);
            sdump("62F67C4D4E4901");
            vrsqrtbf16(zm1 | k5, ptr_b[rcx + 64]);
            sdump("62F67C5D4E4920");

            vscalefbf16(xm1 | k5, xm5, xm2);
            sdump("62F6540D2CCA");
            vscalefbf16(xm1 | k5, xm5, ptr[rcx + 64]);
            sdump("62F6540D2C4904");
            vscalefbf16(xm1 | k5, xm5, ptr_b[rcx + 64]);
            sdump("62F6541D2C4920");

            vscalefbf16(ym1 | k5, ym9, ym2);
            sdump("62F6342D2CCA");
            vscalefbf16(ym1 | k5, ym9, ptr[rcx + 64]);
            sdump("62F6342D2C4902");
            vscalefbf16(ym1 | k5, ym9, ptr_b[rcx + 64]);
            sdump("62F6343D2C4920");

            vscalefbf16(zm1 | k5, zm30, zm2);
            sdump("62F60C452CCA");
            vscalefbf16(zm1 | k5, zm30, ptr[rcx + 64]);
            sdump("62F60C452C4901");
            vscalefbf16(zm1 | k5, zm30, ptr_b[rcx + 64]);
            sdump("62F60C552C4920");

            vsqrtbf16(xm5 | k3, xmm4);
            sdump("62F57D0B51EC");
            vsqrtbf16(xm5 | k3, ptr[rax + 64]);
            sdump("62F57D0B516804");
            vsqrtbf16(xm5 | k3, ptr_b[rax + 64]);
            sdump("62F57D1B516820");

            vsqrtbf16(ym5 | k3, ymm4);
            sdump("62F57D2B51EC");
            vsqrtbf16(ym5 | k3, ptr[rax + 64]);
            sdump("62F57D2B516802");
            vsqrtbf16(ym5 | k3, ptr_b[rax + 64]);
            sdump("62F57D3B516820");

            vsqrtbf16(zm5 | k3, zmm4);
            sdump("62F57D4B51EC");
            vsqrtbf16(zm5 | k3, ptr[rax + 64]);
            sdump("62F57D4B516801");
            vsqrtbf16(zm5 | k3, ptr_b[rax + 64]);
            sdump("62F57D5B516820");

        }
    }
}
