module xed_misc;

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
    @("xed_misc")
    unittest
    {
        xed_misc();
    }

    void xed_misc()
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
            // AVX10 integer and FP16 VNNI, media and zero-extending
            vdpphps(xm1, xm2, xm3);
            sdump("62F26C0852CB");
            vdpphps(xm1, xm2, ptr[rax + 128]);
            sdump("62F26C08524808");
            vdpphps(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26C18524820");

            vdpphps(ym1, ym2, ym3);
            sdump("62F26C2852CB");
            vdpphps(ym1, ym2, ptr[rax + 128]);
            sdump("62F26C28524804");
            vdpphps(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26C38524820");

            vdpphps(zm1, zm2, zm3);
            sdump("62F26C4852CB");
            vdpphps(zm1, zm2, ptr[rax + 128]);
            sdump("62F26C48524802");
            vdpphps(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26C58524820");
            //
            vmpsadbw(xm1, xm3, xm15, 3);
            sdump("62D3660842CF03");
            vmpsadbw(xm1 | T_z, xm4, ptr[rax + 128], 5);
            sdump("62F35E0842480805");

            vmpsadbw(ym1 | k4, ym3, ym15, 3);
            sdump("62D3662C42CF03");
            vmpsadbw(ym1, ym4, ptr[rax + 128], 5);
            sdump("62F35E2842480405");

            vmpsadbw(zm1 | k4, zm3, zm15, 3);
            sdump("62D3664C42CF03");
            vmpsadbw(zm1, zm4, ptr[rax + 128], 5);
            sdump("62F35E4842480205");
            //
            vpdpbssd(xm1, xm2, xm3);
            sdump("62F26F0850CB");
            vpdpbssd(xm1, xm2, ptr[rax + 128]);
            sdump("62F26F08504808");
            vpdpbssd(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26F18504820");

            vpdpbssd(ym1, ym2, ym3);
            sdump("62F26F2850CB");
            vpdpbssd(ym1, ym2, ptr[rax + 128]);
            sdump("62F26F28504804");
            vpdpbssd(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26F38504820");

            vpdpbssd(zm1, zm2, zm3);
            sdump("62F26F4850CB");
            vpdpbssd(zm1, zm2, ptr[rax + 128]);
            sdump("62F26F48504802");
            vpdpbssd(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26F58504820");
            //
            vpdpbssds(xm1, xm2, xm3);
            sdump("62F26F0851CB");
            vpdpbssds(xm1, xm2, ptr[rax + 128]);
            sdump("62F26F08514808");
            vpdpbssds(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26F18514820");

            vpdpbssds(ym1, ym2, ym3);
            sdump("62F26F2851CB");
            vpdpbssds(ym1, ym2, ptr[rax + 128]);
            sdump("62F26F28514804");
            vpdpbssds(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26F38514820");

            vpdpbssds(zm1, zm2, zm3);
            sdump("62F26F4851CB");
            vpdpbssds(zm1, zm2, ptr[rax + 128]);
            sdump("62F26F48514802");
            vpdpbssds(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26F58514820");
            //
            vpdpbsud(xm1, xm2, xm3);
            sdump("62F26E0850CB");
            vpdpbsud(xm1, xm2, ptr[rax + 128]);
            sdump("62F26E08504808");
            vpdpbsud(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26E18504820");

            vpdpbsud(ym1, ym2, ym3);
            sdump("62F26E2850CB");
            vpdpbsud(ym1, ym2, ptr[rax + 128]);
            sdump("62F26E28504804");
            vpdpbsud(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26E38504820");

            vpdpbsud(zm1, zm2, zm3);
            sdump("62F26E4850CB");
            vpdpbsud(zm1, zm2, ptr[rax + 128]);
            sdump("62F26E48504802");
            vpdpbsud(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26E58504820");
            //
            vpdpbsuds(xm1, xm2, xm3);
            sdump("62F26E0851CB");
            vpdpbsuds(xm1, xm2, ptr[rax + 128]);
            sdump("62F26E08514808");
            vpdpbsuds(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26E18514820");

            vpdpbsuds(ym1, ym2, ym3);
            sdump("62F26E2851CB");
            vpdpbsuds(ym1, ym2, ptr[rax + 128]);
            sdump("62F26E28514804");
            vpdpbsuds(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26E38514820");

            vpdpbsuds(zm1, zm2, zm3);
            sdump("62F26E4851CB");
            vpdpbsuds(zm1, zm2, ptr[rax + 128]);
            sdump("62F26E48514802");
            vpdpbsuds(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26E58514820");

            //
            vpdpbuud(xm1, xm2, xm3);
            sdump("62F26C0850CB");
            vpdpbuud(xm1, xm2, ptr[rax + 128]);
            sdump("62F26C08504808");
            vpdpbuud(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26C18504820");

            vpdpbuud(ym1, ym2, ym3);
            sdump("62F26C2850CB");
            vpdpbuud(ym1, ym2, ptr[rax + 128]);
            sdump("62F26C28504804");
            vpdpbuud(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26C38504820");

            vpdpbuud(zm1, zm2, zm3);
            sdump("62F26C4850CB");
            vpdpbuud(zm1, zm2, ptr[rax + 128]);
            sdump("62F26C48504802");
            vpdpbuud(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26C58504820");
            //
            vpdpbuuds(xm1, xm2, xm3);
            sdump("62F26C0851CB");
            vpdpbuuds(xm1, xm2, ptr[rax + 128]);
            sdump("62F26C08514808");
            vpdpbuuds(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26C18514820");

            vpdpbuuds(ym1, ym2, ym3);
            sdump("62F26C2851CB");
            vpdpbuuds(ym1, ym2, ptr[rax + 128]);
            sdump("62F26C28514804");
            vpdpbuuds(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26C38514820");

            vpdpbuuds(zm1, zm2, zm3);
            sdump("62F26C4851CB");
            vpdpbuuds(zm1, zm2, ptr[rax + 128]);
            sdump("62F26C48514802");
            vpdpbuuds(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26C58514820");

            //
            vpdpwsud(xm1, xm2, xm3);
            sdump("62F26E08D2CB");
            vpdpwsud(xm1, xm2, ptr[rax + 128]);
            sdump("62F26E08D24808");
            vpdpwsud(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26E18D24820");

            vpdpwsud(ym1, ym2, ym3);
            sdump("62F26E28D2CB");
            vpdpwsud(ym1, ym2, ptr[rax + 128]);
            sdump("62F26E28D24804");
            vpdpwsud(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26E38D24820");

            vpdpwsud(zm1, zm2, zm3);
            sdump("62F26E48D2CB");
            vpdpwsud(zm1, zm2, ptr[rax + 128]);
            sdump("62F26E48D24802");
            vpdpwsud(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26E58D24820");
            //
            vpdpwsuds(xm1, xm2, xm3);
            sdump("62F26E08D3CB");
            vpdpwsuds(xm1, xm2, ptr[rax + 128]);
            sdump("62F26E08D34808");
            vpdpwsuds(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26E18D34820");

            vpdpwsuds(ym1, ym2, ym3);
            sdump("62F26E28D3CB");
            vpdpwsuds(ym1, ym2, ptr[rax + 128]);
            sdump("62F26E28D34804");
            vpdpwsuds(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26E38D34820");

            vpdpwsuds(zm1, zm2, zm3);
            sdump("62F26E48D3CB");
            vpdpwsuds(zm1, zm2, ptr[rax + 128]);
            sdump("62F26E48D34802");
            vpdpwsuds(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26E58D34820");
            //
            vpdpwsud(xm1, xm2, xm3);
            sdump("62F26E08D2CB");
            vpdpwsud(xm1, xm2, ptr[rax + 128]);
            sdump("62F26E08D24808");
            vpdpwsud(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26E18D24820");

            vpdpwsud(ym1, ym2, ym3);
            sdump("62F26E28D2CB");
            vpdpwsud(ym1, ym2, ptr[rax + 128]);
            sdump("62F26E28D24804");
            vpdpwsud(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26E38D24820");

            vpdpwsud(zm1, zm2, zm3);
            sdump("62F26E48D2CB");
            vpdpwsud(zm1, zm2, ptr[rax + 128]);
            sdump("62F26E48D24802");
            vpdpwsud(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26E58D24820");
            //
            vpdpwsuds(xm1, xm2, xm3);
            sdump("62F26E08D3CB");
            vpdpwsuds(xm1, xm2, ptr[rax + 128]);
            sdump("62F26E08D34808");
            vpdpwsuds(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26E18D34820");

            vpdpwsuds(ym1, ym2, ym3);
            sdump("62F26E28D3CB");
            vpdpwsuds(ym1, ym2, ptr[rax + 128]);
            sdump("62F26E28D34804");
            vpdpwsuds(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26E38D34820");

            vpdpwsuds(zm1, zm2, zm3);
            sdump("62F26E48D3CB");
            vpdpwsuds(zm1, zm2, ptr[rax + 128]);
            sdump("62F26E48D34802");
            vpdpwsuds(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26E58D34820");

            //
            vpdpwuud(xm1, xm2, xm3);
            sdump("62F26C08D2CB");
            vpdpwuud(xm1, xm2, ptr[rax + 128]);
            sdump("62F26C08D24808");
            vpdpwuud(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26C18D24820");

            vpdpwuud(ym1, ym2, ym3);
            sdump("62F26C28D2CB");
            vpdpwuud(ym1, ym2, ptr[rax + 128]);
            sdump("62F26C28D24804");
            vpdpwuud(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26C38D24820");

            vpdpwuud(zm1, zm2, zm3);
            sdump("62F26C48D2CB");
            vpdpwuud(zm1, zm2, ptr[rax + 128]);
            sdump("62F26C48D24802");
            vpdpwuud(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26C58D24820");
            //
            vpdpwuuds(xm1, xm2, xm3);
            sdump("62F26C08D3CB");
            vpdpwuuds(xm1, xm2, ptr[rax + 128]);
            sdump("62F26C08D34808");
            vpdpwuuds(xm1, xm2, ptr_b[rax + 128]);
            sdump("62F26C18D34820");

            vpdpwuuds(ym1, ym2, ym3);
            sdump("62F26C28D3CB");
            vpdpwuuds(ym1, ym2, ptr[rax + 128]);
            sdump("62F26C28D34804");
            vpdpwuuds(ym1, ym2, ptr_b[rax + 128]);
            sdump("62F26C38D34820");

            vpdpwuuds(zm1, zm2, zm3);
            sdump("62F26C48D3CB");
            vpdpwuuds(zm1, zm2, ptr[rax + 128]);
            sdump("62F26C48D34802");
            vpdpwuuds(zm1, zm2, ptr_b[rax + 128]);
            sdump("62F26C58D34820");

            //
            vmovd(xm10, xm20);
            sdump("62317E087ED4");
            vmovd(xm1, xm2);
            sdump("62F17E087ECA");
            vmovd(xm10, ptr[rax + 128]);
            sdump("62717E087E5020");
            vmovd(ptr[rax + 128], xm30);
            sdump("62617D08D67020");
            //
            vmovw(xm1, xm20);
            sdump("62B57E086ECC");
            vmovw(xm1, xm2);
            sdump("62F57E086ECA");
            vmovw(xm3, ptr[rax + 0x40]);
            sdump("62F57E086E5820");
            vmovw(ptr[rax + 0x40], xm7);
            sdump("62F57E087E7820");
            //
            push(rax);
            sdump("50");
            push(rcx);
            sdump("51");
            push(rdx);
            sdump("52");
            push(rbx);
            sdump("53");
            push(rsp);
            sdump("54");
            push(rbp);
            sdump("55");
            push(rsi);
            sdump("56");
            push(rdi);
            sdump("57");
            push(r8);
            sdump("4150");
            push(r9);
            sdump("4151");
            push(r10);
            sdump("4152");
            push(r11);
            sdump("4153");
            push(r12);
            sdump("4154");
            push(r13);
            sdump("4155");
            push(r14);
            sdump("4156");
            push(r15);
            sdump("4157");
            push(r16);
            sdump("D51050");
            push(r17);
            sdump("D51051");
            push(r18);
            sdump("D51052");
            push(r19);
            sdump("D51053");
            push(r20);
            sdump("D51054");
            push(r21);
            sdump("D51055");
            push(r22);
            sdump("D51056");
            push(r23);
            sdump("D51057");
            push(r24);
            sdump("D51150");
            push(r25);
            sdump("D51151");
            push(r26);
            sdump("D51152");
            push(r27);
            sdump("D51153");
            push(r28);
            sdump("D51154");
            push(r29);
            sdump("D51155");
            push(r30);
            sdump("D51156");
            push(r31);
            sdump("D51157");
            pop(rax);
            sdump("58");
            pop(rcx);
            sdump("59");
            pop(rdx);
            sdump("5A");
            pop(rbx);
            sdump("5B");
            pop(rsp);
            sdump("5C");
            pop(rbp);
            sdump("5D");
            pop(rsi);
            sdump("5E");
            pop(rdi);
            sdump("5F");
            pop(r8);
            sdump("4158");
            pop(r9);
            sdump("4159");
            pop(r10);
            sdump("415A");
            pop(r11);
            sdump("415B");
            pop(r12);
            sdump("415C");
            pop(r13);
            sdump("415D");
            pop(r14);
            sdump("415E");
            pop(r15);
            sdump("415F");
            pop(r16);
            sdump("D51058");
            pop(r17);
            sdump("D51059");
            pop(r18);
            sdump("D5105A");
            pop(r19);
            sdump("D5105B");
            pop(r20);
            sdump("D5105C");
            pop(r21);
            sdump("D5105D");
            pop(r22);
            sdump("D5105E");
            pop(r23);
            sdump("D5105F");
            pop(r24);
            sdump("D51158");
            pop(r25);
            sdump("D51159");
            pop(r26);
            sdump("D5115A");
            pop(r27);
            sdump("D5115B");
            pop(r28);
            sdump("D5115C");
            pop(r29);
            sdump("D5115D");
            pop(r30);
            sdump("D5115E");
            pop(r31);
            sdump("D5115F");

        }
    }
}
