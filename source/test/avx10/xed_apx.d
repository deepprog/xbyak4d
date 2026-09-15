module xed_apx;

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

    @("xed_apx")
    unittest
    {
        scope Code c = new Code("xed_apx");
    }

    class Code : TestCode
    {
        this(string name)
        {
            super(name);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            sal(rax, r8, 1);
            sdump("62D4FC18D1E0");
            sar(rax, r9, 4);
            sdump("62D4FC18C1F904");
            shl(rax, rdi, 8);
            sdump("62F4FC18C1E708");
            shr(rax, rsi, 12);
            sdump("62F4FC18C1EE0C");
            rcl(rax, r10, 16);
            sdump("62D4FC18C1D210");
            rcr(rax, r11, 20);
            sdump("62D4FC18C1DB14");
            rol(rax, r14, 24);
            sdump("62D4FC18C1C618");
            ror(rax, r15, 28);
            sdump("62D4FC18C1CF1C");
            sal(rcx, qword[r8], 32);
            sdump("62D4F418C12020");
            sar(rcx, qword[r9], 36);
            sdump("62D4F418C13924");
            sal(rcx, qword[rdi], 40);
            sdump("62F4F418C12728");
            sar(rcx, qword[rsi], 44);
            sdump("62F4F418C13E2C");
            rcl(rcx, qword[r10], 48);
            sdump("62D4F418C11230");
            rcr(rcx, qword[r11], 52);
            sdump("62D4F418C11B34");
            rol(rcx, qword[r14], 56);
            sdump("62D4F418C10638");
            ror(rcx, qword[r15], 60);
            sdump("62D4F418C10F3C");

            imul(rax, rdx, r10);
            sdump("62D4FC18AFD2");
            imul(rcx, r15, qword[rdi]);
            sdump("6274F418AF3F");

            pushp(rax);
            sdump("D50850");
            pushp(r8);
            sdump("D50950");
            pushp(r16);
            sdump("D51850");
            pushp(r24);
            sdump("D51950");
            pushp(r31);
            sdump("D51957");
            popp(rax);
            sdump("D50858");
            popp(r8);
            sdump("D50958");
            popp(r16);
            sdump("D51858");
            popp(r24);
            sdump("D51958");
            popp(r31);
            sdump("D5195F");

            // lss/lfs/lgs with EGPR (REX2)
            lss(r30, ptr[r29]); sdump("D5DDB27500");
            lss(r8d, ptr[r24]); sdump("D595B200");
            lfs(eax, ptr[r16]); sdump("D590B400");
            lfs(r16d, ptr[rax]); sdump("D5C0B400");
            lfs(r16w, ptr[rax]); sdump("66D5C0B400");
            lfs(r16, ptr[rax]); sdump("D5C8B400");
            lfs(r31d, ptr[r16+r17*8+0x40]); sdump("D5F4B47CC840");
            lgs(r20d, ptr[r21]); sdump("D5D0B56500");
            lgs(ax, ptr[r18+r19]); sdump("66D5B0B5041A");

            // reg_rm
            adc(r17, ptr [rax]); sdump("");
            adc(ptr [r18], rdx); sdump("");
            adc(r30, rcx); sdump("");
            add(r17, ptr [rax]); sdump("");
            add(ptr [r18], rdx); sdump("");
            add(r30, rcx); sdump("");
            and_(r17, ptr [rax]); sdump("");
            and_(ptr [r18], rdx); sdump("");
            and_(r30, rcx); sdump("");
            cmp(r17, ptr [rax]); sdump("");
            cmp(ptr [r18], rdx); sdump("");
            cmp(r30, rcx); sdump("");
            or_(r17, ptr [rax]); sdump("");
            or_(ptr [r18], rdx); sdump("");
            or_(r30, rcx); sdump("");
            sbb(r17, ptr [rax]); sdump("");
            sbb(ptr [r18], rdx); sdump("");
            sbb(r30, rcx); sdump("");
            sub(r17, ptr [rax]); sdump("");
            sub(ptr [r18], rdx); sdump("");
            sub(r30, rcx); sdump("");
            xor_(r17, ptr [rax]); sdump("");
            xor_(ptr [r18], rdx); sdump("");
            xor_(r30, rcx); sdump("");
            add(r30, ptr [rbx+rcx*4]); sdump("");
            add(rax, ptr [r30+rcx*4]); sdump("");
            add(rax, ptr [rbx+r30*4]); sdump("");

            // reg64
            adc(r30, rax); sdump("");
            adc(r30, rcx); sdump("");
            adc(r30, rdx); sdump("");
            adc(r30, rbx); sdump("");
            adc(r30, rsp); sdump("");
            adc(r30, rbp); sdump("");
            adc(r30, rsi); sdump("");
            adc(r30, rdi); sdump("");
            adc(r30, r8); sdump("");
            adc(r30, r9); sdump("");
            adc(r30, r10); sdump("");
            adc(r30, r11); sdump("");
            adc(r30, r12); sdump("");
            adc(r30, r13); sdump("");
            adc(r30, r14); sdump("");
            adc(r30, r15); sdump("");
            adc(r30, r16); sdump("");
            adc(r30, r17); sdump("");
            adc(r30, r18); sdump("");
            adc(r30, r19); sdump("");
            adc(r30, r20); sdump("");
            adc(r30, r21); sdump("");
            adc(r30, r22); sdump("");
            adc(r30, r23); sdump("");
            adc(r30, r24); sdump("");
            adc(r30, r25); sdump("");
            adc(r30, r26); sdump("");
            adc(r30, r27); sdump("");
            adc(r30, r28); sdump("");
            adc(r30, r29); sdump("");
            adc(r30, r30); sdump("");
            adc(r30, r31); sdump("");
            adc(rax, r30); sdump("");
            adc(rcx, r30); sdump("");
            adc(rdx, r30); sdump("");
            adc(rbx, r30); sdump("");
            adc(rsp, r30); sdump("");
            adc(rbp, r30); sdump("");
            adc(rsi, r30); sdump("");
            adc(rdi, r30); sdump("");
            adc(r8, r30); sdump("");
            adc(r9, r30); sdump("");
            adc(r10, r30); sdump("");
            adc(r11, r30); sdump("");
            adc(r12, r30); sdump("");
            adc(r13, r30); sdump("");
            adc(r14, r30); sdump("");
            adc(r15, r30); sdump("");
            adc(r16, r30); sdump("");
            adc(r17, r30); sdump("");
            adc(r18, r30); sdump("");
            adc(r19, r30); sdump("");
            adc(r20, r30); sdump("");
            adc(r21, r30); sdump("");
            adc(r22, r30); sdump("");
            adc(r23, r30); sdump("");
            adc(r24, r30); sdump("");
            adc(r25, r30); sdump("");
            adc(r26, r30); sdump("");
            adc(r27, r30); sdump("");
            adc(r28, r30); sdump("");
            adc(r29, r30); sdump("");
            adc(r30, r30); sdump("");
            adc(r31, r30); sdump("");

            // reg32
            adc(r30d, eax); sdump("");
            adc(r30d, ecx); sdump("");
            adc(r30d, edx); sdump("");
            adc(r30d, ebx); sdump("");
            adc(r30d, esp); sdump("");
            adc(r30d, ebp); sdump("");
            adc(r30d, esi); sdump("");
            adc(r30d, edi); sdump("");
            adc(r30d, r8d); sdump("");
            adc(r30d, r9d); sdump("");
            adc(r30d, r10d); sdump("");
            adc(r30d, r11d); sdump("");
            adc(r30d, r12d); sdump("");
            adc(r30d, r13d); sdump("");
            adc(r30d, r14d); sdump("");
            adc(r30d, r15d); sdump("");
            adc(r30d, r16d); sdump("");
            adc(r30d, r17d); sdump("");
            adc(r30d, r18d); sdump("");
            adc(r30d, r19d); sdump("");
            adc(r30d, r20d); sdump("");
            adc(r30d, r21d); sdump("");
            adc(r30d, r22d); sdump("");
            adc(r30d, r23d); sdump("");
            adc(r30d, r24d); sdump("");
            adc(r30d, r25d); sdump("");
            adc(r30d, r26d); sdump("");
            adc(r30d, r27d); sdump("");
            adc(r30d, r28d); sdump("");
            adc(r30d, r29d); sdump("");
            adc(r30d, r30d); sdump("");
            adc(r30d, r31d); sdump("");
            adc(eax, r29d); sdump("");
            adc(ecx, r29d); sdump("");
            adc(edx, r29d); sdump("");
            adc(ebx, r29d); sdump("");
            adc(esp, r29d); sdump("");
            adc(ebp, r29d); sdump("");
            adc(esi, r29d); sdump("");
            adc(edi, r29d); sdump("");
            adc(r8d, r29d); sdump("");
            adc(r9d, r29d); sdump("");
            adc(r10d, r29d); sdump("");
            adc(r11d, r29d); sdump("");
            adc(r12d, r29d); sdump("");
            adc(r13d, r29d); sdump("");
            adc(r14d, r29d); sdump("");
            adc(r15d, r29d); sdump("");
            adc(r16d, r29d); sdump("");
            adc(r17d, r29d); sdump("");
            adc(r18d, r29d); sdump("");
            adc(r19d, r29d); sdump("");
            adc(r20d, r29d); sdump("");
            adc(r21d, r29d); sdump("");
            adc(r22d, r29d); sdump("");
            adc(r23d, r29d); sdump("");
            adc(r24d, r29d); sdump("");
            adc(r25d, r29d); sdump("");
            adc(r26d, r29d); sdump("");
            adc(r27d, r29d); sdump("");
            adc(r28d, r29d); sdump("");
            adc(r29d, r29d); sdump("");
            adc(r30d, r29d); sdump("");
            adc(r31d, r29d); sdump("");

            // reg16
            adc(r30w, ax); sdump("");
            adc(r30w, cx); sdump("");
            adc(r30w, dx); sdump("");
            adc(r30w, bx); sdump("");
            adc(r30w, sp); sdump("");
            adc(r30w, bp); sdump("");
            adc(r30w, si); sdump("");
            adc(r30w, di); sdump("");
            adc(r30w, r8w); sdump("");
            adc(r30w, r9w); sdump("");
            adc(r30w, r10w); sdump("");
            adc(r30w, r11w); sdump("");
            adc(r30w, r12w); sdump("");
            adc(r30w, r13w); sdump("");
            adc(r30w, r14w); sdump("");
            adc(r30w, r15w); sdump("");
            adc(r30w, r16w); sdump("");
            adc(r30w, r17w); sdump("");
            adc(r30w, r18w); sdump("");
            adc(r30w, r19w); sdump("");
            adc(r30w, r20w); sdump("");
            adc(r30w, r21w); sdump("");
            adc(r30w, r22w); sdump("");
            adc(r30w, r23w); sdump("");
            adc(r30w, r24w); sdump("");
            adc(r30w, r25w); sdump("");
            adc(r30w, r26w); sdump("");
            adc(r30w, r27w); sdump("");
            adc(r30w, r28w); sdump("");
            adc(r30w, r29w); sdump("");
            adc(r30w, r30w); sdump("");
            adc(r30w, r31w); sdump("");
            adc(ax, r29w); sdump("");
            adc(cx, r29w); sdump("");
            adc(dx, r29w); sdump("");
            adc(bx, r29w); sdump("");
            adc(sp, r29w); sdump("");
            adc(bp, r29w); sdump("");
            adc(si, r29w); sdump("");
            adc(di, r29w); sdump("");
            adc(r8w, r29w); sdump("");
            adc(r9w, r29w); sdump("");
            adc(r10w, r29w); sdump("");
            adc(r11w, r29w); sdump("");
            adc(r12w, r29w); sdump("");
            adc(r13w, r29w); sdump("");
            adc(r14w, r29w); sdump("");
            adc(r15w, r29w); sdump("");
            adc(r16w, r29w); sdump("");
            adc(r17w, r29w); sdump("");
            adc(r18w, r29w); sdump("");
            adc(r19w, r29w); sdump("");
            adc(r20w, r29w); sdump("");
            adc(r21w, r29w); sdump("");
            adc(r22w, r29w); sdump("");
            adc(r23w, r29w); sdump("");
            adc(r24w, r29w); sdump("");
            adc(r25w, r29w); sdump("");
            adc(r26w, r29w); sdump("");
            adc(r27w, r29w); sdump("");
            adc(r28w, r29w); sdump("");
            adc(r29w, r29w); sdump("");
            adc(r30w, r29w); sdump("");
            adc(r31w, r29w); sdump("");

            // reg8
            adc(r17b, al); sdump("");
            adc(r17b, cl); sdump("");
            adc(r17b, dl); sdump("");
            adc(r17b, bl); sdump("");
            adc(r17b, spl); sdump("");
            adc(r17b, bpl); sdump("");
            adc(r17b, sil); sdump("");
            adc(r17b, dil); sdump("");
            adc(r17b, r8b); sdump("");
            adc(r17b, r9b); sdump("");
            adc(r17b, r10b); sdump("");
            adc(r17b, r11b); sdump("");
            adc(r17b, r12b); sdump("");
            adc(r17b, r13b); sdump("");
            adc(r17b, r14b); sdump("");
            adc(r17b, r15b); sdump("");
            adc(r17b, r16b); sdump("");
            adc(r17b, r17b); sdump("");
            adc(r17b, r18b); sdump("");
            adc(r17b, r19b); sdump("");
            adc(r17b, r20b); sdump("");
            adc(r17b, r21b); sdump("");
            adc(r17b, r22b); sdump("");
            adc(r17b, r23b); sdump("");
            adc(r17b, r24b); sdump("");
            adc(r17b, r25b); sdump("");
            adc(r17b, r26b); sdump("");
            adc(r17b, r27b); sdump("");
            adc(r17b, r28b); sdump("");
            adc(r17b, r29b); sdump("");
            adc(r17b, r30b); sdump("");
            adc(r17b, r31b); sdump("");
            adc(al, r20b); sdump("");
            adc(cl, r20b); sdump("");
            adc(dl, r20b); sdump("");
            adc(bl, r20b); sdump("");
            adc(spl, r20b); sdump("");
            adc(bpl, r20b); sdump("");
            adc(sil, r20b); sdump("");
            adc(dil, r20b); sdump("");
            adc(r8b, r20b); sdump("");
            adc(r9b, r20b); sdump("");
            adc(r10b, r20b); sdump("");
            adc(r11b, r20b); sdump("");
            adc(r12b, r20b); sdump("");
            adc(r13b, r20b); sdump("");
            adc(r14b, r20b); sdump("");
            adc(r15b, r20b); sdump("");
            adc(r16b, r20b); sdump("");
            adc(r17b, r20b); sdump("");
            adc(r18b, r20b); sdump("");
            adc(r19b, r20b); sdump("");
            adc(r20b, r20b); sdump("");
            adc(r21b, r20b); sdump("");
            adc(r22b, r20b); sdump("");
            adc(r23b, r20b); sdump("");
            adc(r24b, r20b); sdump("");
            adc(r25b, r20b); sdump("");
            adc(r26b, r20b); sdump("");
            adc(r27b, r20b); sdump("");
            adc(r28b, r20b); sdump("");
            adc(r29b, r20b); sdump("");
            adc(r30b, r20b); sdump("");
            adc(r31b, r20b); sdump("");

            // rm
            adc(r16, ptr [r17+0x40]); sdump("");
            adc(ptr [r17+0x40], r16); sdump("");
            adc(r16d, ptr [r17+0x40]); sdump("");
            adc(ptr [r17+0x40], r16d); sdump("");
            adc(r16w, ptr [r17+0x40]); sdump("");
            adc(ptr [r17+0x40], r16w); sdump("");
            adc(r16b, ptr [r17+0x40]); sdump("");
            adc(ptr [r17+0x40], r16b); sdump("");
            adc(r16, ptr [r18*4+0x40]); sdump("");
            adc(ptr [r18*4+0x40], r16); sdump("");
            adc(r16d, ptr [r18*4+0x40]); sdump("");
            adc(ptr [r18*4+0x40], r16d); sdump("");
            adc(r16w, ptr [r18*4+0x40]); sdump("");
            adc(ptr [r18*4+0x40], r16w); sdump("");
            adc(r16b, ptr [r18*4+0x40]); sdump("");
            adc(ptr [r18*4+0x40], r16b); sdump("");
            adc(r16, ptr [r17+r18*4+0x40]); sdump("");
            adc(ptr [r17+r18*4+0x40], r16); sdump("");
            adc(r16d, ptr [r17+r18*4+0x40]); sdump("");
            adc(ptr [r17+r18*4+0x40], r16d); sdump("");
            adc(r16w, ptr [r17+r18*4+0x40]); sdump("");
            adc(ptr [r17+r18*4+0x40], r16w); sdump("");
            adc(r16b, ptr [r17+r18*4+0x40]); sdump("");
            adc(ptr [r17+r18*4+0x40], r16b); sdump("");

            // r3
            adc(r20b, r21b, r23b); sdump("");
            adc(r20w, r21w, r23w); sdump("");
            adc(r20d, r21d, r23d); sdump("");
            adc(r20, r21, r23); sdump("");

            // rm3
            adc(rax, r18, ptr [rbx+rcx*4+0x123]); sdump("");
            adc(rax, ptr [rbx+rcx*4+0x123], r20); sdump("");
            adc(rax, ptr [r30], r29); sdump("");
            adc(r11, r13, ptr [r10]); sdump("");
            adc(r11, r13, ptr [r10*4]); sdump("");
            adc(r11, ptr [r10*8], r9); sdump("");

            // rm3_2
            adc(r20b, r21b, r23b); sdump("");
            adc(r20w, r21w, r23w); sdump("");
            adc(r20d, r21d, r23d); sdump("");
            adc(r20, r21, r23); sdump("");
            adc(r20b, ptr [rax+rcx*4+0x7fffffff], 0x12); sdump("");
            adc(r20w, ptr [rax+rcx*4+0x7fffffff], 0x1234); sdump("");
            adc(r20d, ptr [rax+rcx*4+0x7fffffff], 0x12345678); sdump("");
            adc(r20, ptr [rax+rcx*4+0x7fffffff], 0x12345678); sdump("");
            adc(r20b, al, 0x12); sdump("");
            adc(r20w, ax, 0x1234); sdump("");
            adc(r20d, eax, 0x12345678); sdump("");
            adc(r20, rax, 0x12345678); sdump("");

            // adcx_adox
            adcx(rax, r30); sdump("");
            adcx(ecx, r20d); sdump("");
            adcx(ecx, ptr [r31+r29*4]); sdump("");
            adcx(r20d, ptr [rax]); sdump("");
            adcx(r16, ptr [r31+r29*4]); sdump("");
            adcx(r17, ptr [rax]); sdump("");
            adcx(rax, rcx, rdx); sdump("");
            adox(rax, r30); sdump("");
            adox(ecx, r20d); sdump("");
            adox(ecx, ptr [r31+r29*4]); sdump("");
            adox(r20d, ptr [rax]); sdump("");
            adox(r16, ptr [r31+r29*4]); sdump("");
            adox(r17, ptr [rax]); sdump("");
            adox(rax, rcx, rdx); sdump("");

            // r3_2
            add(rax, rcx, rdx); sdump("");
            adc(rax, rcx, rdx); sdump("");
            and_(rax, rcx, rdx); sdump("");
            or_(rax, rcx, rdx); sdump("");
            sbb(rax, rcx, rdx); sdump("");
            sub(rax, rcx, rdx); sdump("");
            xor_(rax, rcx, rdx); sdump("");
            add(r30, ptr [r20], r9); sdump("");
            adc(r30, ptr [r20], r9); sdump("");
            and_(r30, ptr [r20], r9); sdump("");
            or_(r30, ptr [r20], r9); sdump("");
            sbb(r30, ptr [r20], r9); sdump("");
            sub(r30, ptr [r20], r9); sdump("");
            xor_(r30, ptr [r20], r9); sdump("");

            // andn_etc
            andn(r29, r30, r31); sdump("");
            andn(eax, ecx, r17d); sdump("");
            andn(r29, r30, ptr [r31+r20*4]); sdump("");
            mulx(eax, ecx, r17d); sdump("");
            mulx(r29, r30, r31); sdump("");
            mulx(r29, r30, ptr [r31+r20*4]); sdump("");
            pdep(eax, ecx, r17d); sdump("");
            pdep(r29, r30, r31); sdump("");
            pdep(r29, r30, ptr [r31+r20*4]); sdump("");
            pext(eax, ecx, r17d); sdump("");
            pext(r29, r30, r31); sdump("");
            pext(r29, r30, ptr [r31+r20*4]); sdump("");

            // bextr_etc
            bextr(r29, r30, r31); sdump("");
            bextr(eax, ecx, r17d); sdump("");
            bextr(r29, ptr [r31+r20*4], r30); sdump("");
            bzhi(r29, r30, r31); sdump("");
            bzhi(eax, ecx, r17d); sdump("");
            bzhi(r29, ptr [r31+r20*4], r30); sdump("");
            sarx(r29, r30, r31); sdump("");
            sarx(eax, ecx, r17d); sdump("");
            sarx(r29, ptr [r31+r20*4], r30); sdump("");
            shlx(r29, r30, r31); sdump("");
            shlx(eax, ecx, r17d); sdump("");
            shlx(r29, ptr [r31+r20*4], r30); sdump("");
            shrx(r29, r30, r31); sdump("");
            shrx(eax, ecx, r17d); sdump("");
            shrx(r29, ptr [r31+r20*4], r30); sdump("");
            blsi(r30, r31); sdump("");
            blsi(ecx, r17d); sdump("");
            blsi(r30, ptr [r31+r20*4]); sdump("");
            blsmsk(r30, r31); sdump("");
            blsmsk(ecx, r17d); sdump("");
            blsmsk(r30, ptr [r31+r20*4]); sdump("");
            blsr(r30, r31); sdump("");
            blsr(ecx, r17d); sdump("");
            blsr(r30, ptr [r31+r20*4]); sdump("");
            rorx(r30, r31, 3); sdump("");
            rorx(ecx, r17d, 5); sdump("");
            rorx(r30, ptr [r31+r20*4], 4); sdump("");

            // bit
            adc(r20b, r21b, r22b); sdump("");
            adc(r20w, r21w, r22w); sdump("");
            adc(r20d, r21d, r22d); sdump("");
            adc(r20, r21, r22); sdump("");
            adc(r20b, r21b); sdump("");
            adc(r20w, r21w); sdump("");
            adc(r20d, r21d); sdump("");
            adc(r20, r21); sdump("");
            adc(r20b, r21b, 0x3); sdump("");
            adc(r20w, r21w, 0x3); sdump("");
            adc(r20d, r21d, 0x3); sdump("");
            adc(r20, r21, 0x3); sdump("");
            adc(r20b, 0x3); sdump("");
            adc(r20w, 0x3); sdump("");
            adc(r20d, 0x3); sdump("");
            adc(r20, 0x3); sdump("");
            add(r20b, r21b, r22b); sdump("");
            add(r20w, r21w, r22w); sdump("");
            add(r20d, r21d, r22d); sdump("");
            add(r20, r21, r22); sdump("");
            add(r20b, r21b); sdump("");
            add(r20w, r21w); sdump("");
            add(r20d, r21d); sdump("");
            add(r20, r21); sdump("");
            add(r20b, r21b, 0x3); sdump("");
            add(r20w, r21w, 0x3); sdump("");
            add(r20d, r21d, 0x3); sdump("");
            add(r20, r21, 0x3); sdump("");
            add(r20b, 0x3); sdump("");
            add(r20w, 0x3); sdump("");
            add(r20d, 0x3); sdump("");
            add(r20, 0x3); sdump("");

            // inc_dec
            inc(r30b); sdump("");
            inc(r30w); sdump("");
            inc(r30d); sdump("");
            inc(r30); sdump("");
            inc(r30b, r31b); sdump("");
            inc(r30w, r31w); sdump("");
            inc(r30d, r31d); sdump("");
            inc(r30, r31); sdump("");
            inc(r30, ptr [r31]); sdump("");
            dec(r30b); sdump("");
            dec(r30w); sdump("");
            dec(r30d); sdump("");
            dec(r30); sdump("");
            dec(r30b, r31b); sdump("");
            dec(r30w, r31w); sdump("");
            dec(r30d, r31d); sdump("");
            dec(r30, r31); sdump("");
            dec(r30, ptr [r31]); sdump("");

            // div_op1
            div(r20b); sdump("");
            div(r20d); sdump("");
            div(r20w); sdump("");
            div(r20); sdump("");
            div(byte_ [r20+r30*1]); sdump("");
            div(word [r20+r30*1]); sdump("");
            div(dword [r20+r30*1]); sdump("");
            div(qword [r20+r30*1]); sdump("");
            idiv(r20b); sdump("");
            idiv(r20d); sdump("");
            idiv(r20w); sdump("");
            idiv(r20); sdump("");
            idiv(byte_ [r20+r30*1]); sdump("");
            idiv(word [r20+r30*1]); sdump("");
            idiv(dword [r20+r30*1]); sdump("");
            idiv(qword [r20+r30*1]); sdump("");
            imul(r20b); sdump("");
            imul(r20d); sdump("");
            imul(r20w); sdump("");
            imul(r20); sdump("");
            imul(byte_ [r20+r30*1]); sdump("");
            imul(word [r20+r30*1]); sdump("");
            imul(dword [r20+r30*1]); sdump("");
            imul(qword [r20+r30*1]); sdump("");
            mul(r20b); sdump("");
            mul(r20d); sdump("");
            mul(r20w); sdump("");
            mul(r20); sdump("");
            mul(byte_ [r20+r30*1]); sdump("");
            mul(word [r20+r30*1]); sdump("");
            mul(dword [r20+r30*1]); sdump("");
            mul(qword [r20+r30*1]); sdump("");
            neg(r20b); sdump("");
            neg(r20d); sdump("");
            neg(r20w); sdump("");
            neg(r20); sdump("");
            neg(byte_ [r20+r30*1]); sdump("");
            neg(word [r20+r30*1]); sdump("");
            neg(dword [r20+r30*1]); sdump("");
            neg(qword [r20+r30*1]); sdump("");
            not_(r20b); sdump("");
            not_(r20d); sdump("");
            not_(r20w); sdump("");
            not_(r20); sdump("");
            not_(byte_ [r20+r30*1]); sdump("");
            not_(word [r20+r30*1]); sdump("");
            not_(dword [r20+r30*1]); sdump("");
            not_(qword [r20+r30*1]); sdump("");

            // imul_2op
            imul(r30w, ax); sdump("");
            imul(r30d, eax); sdump("");
            imul(r30, rax); sdump("");
            imul(rcx, ptr [r30]); sdump("");
            neg(r30b, al); sdump("");
            neg(r30w, ax); sdump("");
            neg(r30d, eax); sdump("");
            neg(r30, rax); sdump("");
            neg(rcx, ptr [r30]); sdump("");
            not_(r30b, al); sdump("");
            not_(r30w, ax); sdump("");
            not_(r30d, eax); sdump("");
            not_(r30, rax); sdump("");
            not_(rcx, ptr [r30]); sdump("");

            // imul_zu
            imul(r30w, ax, 0x1234); sdump("");
            imul(r30d, eax, 0x12345678); sdump("");
            imul(r30, rax, 0x12345678); sdump("");
            imul(rcx, ptr [r30], 0x12345678); sdump("");

            // lzcnt
            lzcnt(r16w, r17w); sdump("");
            lzcnt(r16d, r17d); sdump("");
            lzcnt(r16, r17); sdump("");
            lzcnt(rax, ptr [r18]); sdump("");
            tzcnt(r16w, r17w); sdump("");
            tzcnt(r16d, r17d); sdump("");
            tzcnt(r16, r17); sdump("");
            tzcnt(rax, ptr [r18]); sdump("");
            popcnt(r16w, r17w); sdump("");
            popcnt(r16d, r17d); sdump("");
            popcnt(r16, r17); sdump("");
            popcnt(rax, ptr [r18]); sdump("");

            // shld
            shld(r16, rcx, cl); sdump("");
            shld(r16, rcx, 0x9); sdump("");
            shld(r20, r16, rcx, cl); sdump("");
            shld(r20, r16, rcx, 0x9); sdump("");
            shld(r20, ptr [r21], rcx, 0x9); sdump("");
            shrd(r16, rcx, cl); sdump("");
            shrd(r16, rcx, 0x9); sdump("");
            shrd(r20, r16, rcx, cl); sdump("");
            shrd(r20, r16, rcx, 0x9); sdump("");
            shrd(r20, ptr [r21], rcx, 0x9); sdump("");

            // base
            lea(r30, ptr[r20+r21]); sdump("");
            add(r30, r20); sdump("");
            add(r30, ptr[r20]); sdump("");
            cmp(r30, ptr[r20]); sdump("");

            // mov_misc
            movdir64b(r16, ptr [r20+r21*8+0x4]); sdump("");
            movdiri(ptr [r20+r21*8+0x4], r16); sdump("");
            movbe(ptr [r16], r30w); sdump("");
            movbe(ptr [r16], r30d); sdump("");
            movbe(ptr [r16], r30); sdump("");
            movbe(r30w, ptr [r16]); sdump("");
            movbe(r30d, ptr [r16]); sdump("");
            movbe(r30, ptr [r16]); sdump("");
            crc32(r30d, r8b); sdump("");
            crc32(r30d, r8w); sdump("");
            crc32(r30d, r8d); sdump("");
            crc32(r30, r8b); sdump("");
            crc32(r30, r8); sdump("");
            jmpabs(0x12345678aabbccdd); sdump("");
            cmpbexadd(ptr [r20+r30*8], r21, r22); sdump("");
            cmpbexadd(ptr [r20+r30*8], r21d, r22d); sdump("");
            cmovb(r8, r9, r10); sdump("");
            cmovb(r8d, r9d, r10d); sdump("");
            setb(r31b); sdump("");
            setb(ptr [r30]); sdump("");
            bswap(eax); sdump("");
            bswap(r8d); sdump("");
            bswap(r16d); sdump("");
            bswap(rcx); sdump("");
            bswap(r9); sdump("");
            bswap(r17); sdump("");

            // shift_2op
            shl(r16b, cl); sdump("");
            shl(r16w, cl); sdump("");
            shl(r16d, cl); sdump("");
            shl(r16, cl); sdump("");
            shl(r16b, 0x3); sdump("");
            shl(r16w, 0x5); sdump("");
            shl(r16d, 0x7); sdump("");
            shl(r16, 0x9); sdump("");
            shl(byte_ [r30], 0x3); sdump("");
            shl(word [r30], 0x5); sdump("");
            shl(dword [r30], 0x7); sdump("");
            shl(qword [r30], 0x9); sdump("");
            shr(r16b, cl); sdump("");
            shr(r16w, cl); sdump("");
            shr(r16d, cl); sdump("");
            shr(r16, cl); sdump("");
            shr(r16b, 0x3); sdump("");
            shr(r16w, 0x5); sdump("");
            shr(r16d, 0x7); sdump("");
            shr(r16, 0x9); sdump("");
            shr(byte_ [r30], 0x3); sdump("");
            shr(word [r30], 0x5); sdump("");
            shr(dword [r30], 0x7); sdump("");
            shr(qword [r30], 0x9); sdump("");
            sar(r16b, cl); sdump("");
            sar(r16w, cl); sdump("");
            sar(r16d, cl); sdump("");
            sar(r16, cl); sdump("");
            sar(r16b, 0x3); sdump("");
            sar(r16w, 0x5); sdump("");
            sar(r16d, 0x7); sdump("");
            sar(r16, 0x9); sdump("");
            sar(byte_ [r30], 0x3); sdump("");
            sar(word [r30], 0x5); sdump("");
            sar(dword [r30], 0x7); sdump("");
            sar(qword [r30], 0x9); sdump("");
            ror(r16b, cl); sdump("");
            ror(r16w, cl); sdump("");
            ror(r16d, cl); sdump("");
            ror(r16, cl); sdump("");
            ror(r16b, 0x3); sdump("");
            ror(r16w, 0x5); sdump("");
            ror(r16d, 0x7); sdump("");
            ror(r16, 0x9); sdump("");
            ror(byte_ [r30], 0x3); sdump("");
            ror(word [r30], 0x5); sdump("");
            ror(dword [r30], 0x7); sdump("");
            ror(qword [r30], 0x9); sdump("");
            rol(r16b, cl); sdump("");
            rol(r16w, cl); sdump("");
            rol(r16d, cl); sdump("");
            rol(r16, cl); sdump("");
            rol(r16b, 0x3); sdump("");
            rol(r16w, 0x5); sdump("");
            rol(r16d, 0x7); sdump("");
            rol(r16, 0x9); sdump("");
            rol(byte_ [r30], 0x3); sdump("");
            rol(word [r30], 0x5); sdump("");
            rol(dword [r30], 0x7); sdump("");
            rol(qword [r30], 0x9); sdump("");
            rcl(r16b, cl); sdump("");
            rcl(r16w, cl); sdump("");
            rcl(r16d, cl); sdump("");
            rcl(r16, cl); sdump("");
            rcl(r16b, 0x3); sdump("");
            rcl(r16w, 0x5); sdump("");
            rcl(r16d, 0x7); sdump("");
            rcl(r16, 0x9); sdump("");
            rcl(byte_ [r30], 0x3); sdump("");
            rcl(word [r30], 0x5); sdump("");
            rcl(dword [r30], 0x7); sdump("");
            rcl(qword [r30], 0x9); sdump("");
            rcr(r16b, cl); sdump("");
            rcr(r16w, cl); sdump("");
            rcr(r16d, cl); sdump("");
            rcr(r16, cl); sdump("");
            rcr(r16b, 0x3); sdump("");
            rcr(r16w, 0x5); sdump("");
            rcr(r16d, 0x7); sdump("");
            rcr(r16, 0x9); sdump("");
            rcr(byte_ [r30], 0x3); sdump("");
            rcr(word [r30], 0x5); sdump("");
            rcr(dword [r30], 0x7); sdump("");
            rcr(qword [r30], 0x9); sdump("");

            // shift_3op
            rcl(r20b, r16b, cl); sdump("");
            rcl(r20w, r16w, cl); sdump("");
            rcl(r20d, r16d, cl); sdump("");
            rcl(r20, r16, cl); sdump("");
            rcl(r20b, ptr [r16], cl); sdump("");
            rcl(r20w, ptr [r16], cl); sdump("");
            rcl(r20d, ptr [r16], cl); sdump("");
            rcl(r20, ptr [r16], cl); sdump("");
            rcl(r20b, r16b, 0x2); sdump("");
            rcl(r20w, r16w, 0x4); sdump("");
            rcl(r20d, r16d, 0x6); sdump("");
            rcl(r20, r16, 0x8); sdump("");
            rcl(r20b, ptr [r16], 0x2); sdump("");
            rcl(r20w, ptr [r16], 0x4); sdump("");
            rcl(r20d, ptr [r16], 0x6); sdump("");
            rcl(r20, ptr [r16], 0x8); sdump("");
            rcr(r20b, r16b, cl); sdump("");
            rcr(r20w, r16w, cl); sdump("");
            rcr(r20d, r16d, cl); sdump("");
            rcr(r20, r16, cl); sdump("");
            rcr(r20b, ptr [r16], cl); sdump("");
            rcr(r20w, ptr [r16], cl); sdump("");
            rcr(r20d, ptr [r16], cl); sdump("");
            rcr(r20, ptr [r16], cl); sdump("");
            rcr(r20b, r16b, 0x2); sdump("");
            rcr(r20w, r16w, 0x4); sdump("");
            rcr(r20d, r16d, 0x6); sdump("");
            rcr(r20, r16, 0x8); sdump("");
            rcr(r20b, ptr [r16], 0x2); sdump("");
            rcr(r20w, ptr [r16], 0x4); sdump("");
            rcr(r20d, ptr [r16], 0x6); sdump("");
            rcr(r20, ptr [r16], 0x8); sdump("");
            rol(r20b, r16b, cl); sdump("");
            rol(r20w, r16w, cl); sdump("");
            rol(r20d, r16d, cl); sdump("");
            rol(r20, r16, cl); sdump("");
            rol(r20b, ptr [r16], cl); sdump("");
            rol(r20w, ptr [r16], cl); sdump("");
            rol(r20d, ptr [r16], cl); sdump("");
            rol(r20, ptr [r16], cl); sdump("");
            rol(r20b, r16b, 0x2); sdump("");
            rol(r20w, r16w, 0x4); sdump("");
            rol(r20d, r16d, 0x6); sdump("");
            rol(r20, r16, 0x8); sdump("");
            rol(r20b, ptr [r16], 0x2); sdump("");
            rol(r20w, ptr [r16], 0x4); sdump("");
            rol(r20d, ptr [r16], 0x6); sdump("");
            rol(r20, ptr [r16], 0x8); sdump("");
            shl(r20b, r16b, cl); sdump("");
            shl(r20w, r16w, cl); sdump("");
            shl(r20d, r16d, cl); sdump("");
            shl(r20, r16, cl); sdump("");
            shl(r20b, ptr [r16], cl); sdump("");
            shl(r20w, ptr [r16], cl); sdump("");
            shl(r20d, ptr [r16], cl); sdump("");
            shl(r20, ptr [r16], cl); sdump("");
            shl(r20b, r16b, 0x2); sdump("");
            shl(r20w, r16w, 0x4); sdump("");
            shl(r20d, r16d, 0x6); sdump("");
            shl(r20, r16, 0x8); sdump("");
            shl(r20b, ptr [r16], 0x2); sdump("");
            shl(r20w, ptr [r16], 0x4); sdump("");
            shl(r20d, ptr [r16], 0x6); sdump("");
            shl(r20, ptr [r16], 0x8); sdump("");
            shr(r20b, r16b, cl); sdump("");
            shr(r20w, r16w, cl); sdump("");
            shr(r20d, r16d, cl); sdump("");
            shr(r20, r16, cl); sdump("");
            shr(r20b, ptr [r16], cl); sdump("");
            shr(r20w, ptr [r16], cl); sdump("");
            shr(r20d, ptr [r16], cl); sdump("");
            shr(r20, ptr [r16], cl); sdump("");
            shr(r20b, r16b, 0x2); sdump("");
            shr(r20w, r16w, 0x4); sdump("");
            shr(r20d, r16d, 0x6); sdump("");
            shr(r20, r16, 0x8); sdump("");
            shr(r20b, ptr [r16], 0x2); sdump("");
            shr(r20w, ptr [r16], 0x4); sdump("");
            shr(r20d, ptr [r16], 0x6); sdump("");
            shr(r20, ptr [r16], 0x8); sdump("");
            sar(r20b, r16b, cl); sdump("");
            sar(r20w, r16w, cl); sdump("");
            sar(r20d, r16d, cl); sdump("");
            sar(r20, r16, cl); sdump("");
            sar(r20b, ptr [r16], cl); sdump("");
            sar(r20w, ptr [r16], cl); sdump("");
            sar(r20d, ptr [r16], cl); sdump("");
            sar(r20, ptr [r16], cl); sdump("");
            sar(r20b, r16b, 0x2); sdump("");
            sar(r20w, r16w, 0x4); sdump("");
            sar(r20d, r16d, 0x6); sdump("");
            sar(r20, r16, 0x8); sdump("");
            sar(r20b, ptr [r16], 0x2); sdump("");
            sar(r20w, ptr [r16], 0x4); sdump("");
            sar(r20d, ptr [r16], 0x6); sdump("");
            sar(r20, ptr [r16], 0x8); sdump("");

            // push2_pop2
            push2(r20, r30); sdump("");
            push2(rax, rcx); sdump("");
            push2p(r20, r30); sdump("");
            push2p(rdx, r8); sdump("");
            pop2(rax, rcx); sdump("");
            pop2(r20, r30); sdump("");
            pop2p(rax, rcx); sdump("");
            pop2p(r20, r30); sdump("");

            // cfcmov
            cfcmovb(r30w, r31w); sdump("");
            cfcmovb(r30d, r31d); sdump("");
            cfcmovb(r30, r31); sdump("");
            cfcmovb(ptr [r8+r20*4+0x3], r19w); sdump("");
            cfcmovb(ptr [r8+r20*4+0x3], r19d); sdump("");
            cfcmovb(ptr [r8+r20*4+0x3], r19); sdump("");
            cfcmovb(r30w, ptr [r9]); sdump("");
            cfcmovb(r30d, ptr [r9]); sdump("");
            cfcmovb(r30, ptr [r9]); sdump("");
            cfcmovb(r20w, r30w, r31w); sdump("");
            cfcmovb(r20d, r30d, r31d); sdump("");
            cfcmovb(r20, r30, r31); sdump("");
            cfcmovb(r20w, r30w, ptr [r9]); sdump("");
            cfcmovb(r20d, r30d, ptr [r9]); sdump("");
            cfcmovb(r20, r30, ptr [r9]); sdump("");
            cfcmovo(r20, r21, r22); sdump("");
            cfcmovo(r20, r21, ptr [r22]); sdump("");
            cfcmovno(r20, r21, r22); sdump("");
            cfcmovno(r20, r21, ptr [r22]); sdump("");
            cfcmovb(r20, r21, r22); sdump("");
            cfcmovb(r20, r21, ptr [r22]); sdump("");
            cfcmovnb(r20, r21, r22); sdump("");
            cfcmovnb(r20, r21, ptr [r22]); sdump("");
            cfcmovz(r20, r21, r22); sdump("");
            cfcmovz(r20, r21, ptr [r22]); sdump("");
            cfcmovnz(r20, r21, r22); sdump("");
            cfcmovnz(r20, r21, ptr [r22]); sdump("");
            cfcmovbe(r20, r21, r22); sdump("");
            cfcmovbe(r20, r21, ptr [r22]); sdump("");
            cfcmovnbe(r20, r21, r22); sdump("");
            cfcmovnbe(r20, r21, ptr [r22]); sdump("");
            cfcmovs(r20, r21, r22); sdump("");
            cfcmovs(r20, r21, ptr [r22]); sdump("");
            cfcmovns(r20, r21, r22); sdump("");
            cfcmovns(r20, r21, ptr [r22]); sdump("");
            cfcmovp(r20, r21, r22); sdump("");
            cfcmovp(r20, r21, ptr [r22]); sdump("");
            cfcmovnp(r20, r21, r22); sdump("");
            cfcmovnp(r20, r21, ptr [r22]); sdump("");
            cfcmovl(r20, r21, r22); sdump("");
            cfcmovl(r20, r21, ptr [r22]); sdump("");
            cfcmovnl(r20, r21, r22); sdump("");
            cfcmovnl(r20, r21, ptr [r22]); sdump("");
            cfcmovle(r20, r21, r22); sdump("");
            cfcmovle(r20, r21, ptr [r22]); sdump("");
            cfcmovnle(r20, r21, r22); sdump("");
            cfcmovnle(r20, r21, ptr [r22]); sdump("");

            // evex_misc
            vmovaps(xmm31, ptr [r30+r26*8+0x40]); sdump("");
            vaddps(zmm30, zmm21, ptr [r20+r30*1]); sdump("");
            vcvtsd2si(r30d, ptr [r17+r31*4]); sdump("");
            test(ptr[r30], r31); sdump("");
            test(byte_[r30], 0x12); sdump("");
            call(r20); sdump("");
            call(ptr[r20]); sdump("");

            // kmov
            kmovb(k1, ptr [r20]); sdump("");
            kmovb(k2, r21d); sdump("");
            kmovb(ptr [r22], k3); sdump("");
            kmovb(r23d, k4); sdump("");
            kmovw(k1, ptr [r20]); sdump("");
            kmovw(k2, r21d); sdump("");
            kmovw(ptr [r22], k3); sdump("");
            kmovw(r23d, k4); sdump("");
            kmovd(k1, ptr [r20]); sdump("");
            kmovd(k2, r21d); sdump("");
            kmovd(ptr [r22], k3); sdump("");
            kmovd(r23d, k4); sdump("");
            kmovq(k1, ptr [r20]); sdump("");
            kmovq(k2, r21); sdump("");
            kmovq(ptr [r22], k3); sdump("");
            kmovq(r23, k4); sdump("");

            // amx
            ldtilecfg(ptr [r30+r29*4+0x12]); sdump("");
            sttilecfg(ptr [r30+r29*4+0x12]); sdump("");
            tileloadd(tmm1, ptr [r30+r29*4+0x12]); sdump("");
            tileloaddt1(tmm3, ptr [r30+r29*4+0x12]); sdump("");
            tilestored(ptr [r30+r29*4+0x12], tmm5); sdump("");

            // aeskl
            aesdec128kl(xmm15, ptr[rax+rcx*4+0x12]); sdump("");
            aesdec256kl(xmm15, ptr[rax+rcx*4+0x12]); sdump("");
            aesdecwide128kl(ptr[rax+rcx*4+0x12]); sdump("");
            aesdecwide256kl(ptr[rax+rcx*4+0x12]); sdump("");
            aesenc128kl(xmm15, ptr[rax+rcx*4+0x12]); sdump("");
            aesenc256kl(xmm15, ptr[rax+rcx*4+0x12]); sdump("");
            aesencwide128kl(ptr[rax+rcx*4+0x12]); sdump("");
            aesencwide256kl(ptr[rax+rcx*4+0x12]); sdump("");

            // encodekey
            encodekey128(eax, ebx); sdump("");
            encodekey128(eax, r8d); sdump("");
            encodekey128(r8d, ebx); sdump("");
            encodekey256(eax, ebx); sdump("");
            encodekey256(eax, r8d); sdump("");
            encodekey256(r8d, ebx); sdump("");

            // sha
            sha1msg1(xmm15, ptr [rax+rcx*4+0x12]); sdump("");
            sha1msg2(xmm15, ptr [rax+rcx*4+0x12]); sdump("");
            sha1nexte(xmm15, ptr [rax+rcx*4+0x12]); sdump("");
            sha256msg1(xmm15, ptr [rax+rcx*4+0x12]); sdump("");
            sha256msg2(xmm15, ptr [rax+rcx*4+0x12]); sdump("");
            sha256rnds2(xmm15, ptr [rax+rcx*4+0x12]); sdump("");
            sha1rnds4(xmm15, ptr [rax+rcx*4+0x12], 0x23); sdump("");

            // 0x0f_rex2
            addps(xmm3, ptr [r30+r20*4+0x4]); sdump("");
            movups(xmm5, ptr [r16]); sdump("");
            movq(r31, xmm5); sdump("");
            cvtsd2si(r20, ptr [r30]); sdump("");
            bsr(r20, r30); sdump("");

            // rao_int
            aadd(ptr [r16+r31*1], r17d); sdump("");
            aadd(ptr [r16+r31*1], r17); sdump("");
            aand(ptr [r16+r31*1], r17d); sdump("");
            aand(ptr [r16+r31*1], r17); sdump("");
            aor(ptr [r16+r31*1], r17d); sdump("");
            aor(ptr [r16+r31*1], r17); sdump("");
            axor(ptr [r16+r31*1], r17d); sdump("");
            axor(ptr [r16+r31*1], r17); sdump("");

            // NF
            add(rax, rcx, rdx); sdump("");
            add(rax|T_nf, rcx, rdx); sdump("");
            and_(rax, rcx, rdx); sdump("");
            and_(rax|T_nf, rcx, rdx); sdump("");
            or_(rax, rcx, rdx); sdump("");
            or_(rax|T_nf, rcx, rdx); sdump("");
            sub(rax, rcx, rdx); sdump("");
            sub(rax|T_nf, rcx, rdx); sdump("");
            xor_(rax, rcx, rdx); sdump("");
            xor_(rax|T_nf, rcx, rdx); sdump("");
            add(rax, rcx, 3); sdump("");
            add(rax|T_nf, rcx, 3); sdump("");
            and_(rax, rcx, 3); sdump("");
            and_(rax|T_nf, rcx, 3); sdump("");
            or_(rax, rcx, 3); sdump("");
            or_(rax|T_nf, rcx, 3); sdump("");
            sub(rax, rcx, 3); sdump("");
            sub(rax|T_nf, rcx, 3); sdump("");
            xor_(rax, rcx, 3); sdump("");
            xor_(rax|T_nf, rcx, 3); sdump("");

            // andn_etc
            andn(r29|T_nf, r30, r31); sdump("");

            // bextr_etc
            bextr(r29|T_nf, r30, r31); sdump("");
            bzhi(r29|T_nf, r30, r31); sdump("");
            blsi(r30|T_nf, r31); sdump("");
            blsmsk(r30|T_nf, r31); sdump("");
            blsr(r30|T_nf, r31); sdump("");

            // inc_dec
            inc(r30w|T_nf, r31w); sdump("");
            dec(r30w|T_nf, r31w); sdump("");

            // div_op1
            div(r20|T_nf); sdump("");
            div(eax|T_nf); sdump("");
            idiv(r20|T_nf); sdump("");
            idiv(eax|T_nf); sdump("");
            imul(r20|T_nf); sdump("");
            imul(eax|T_nf); sdump("");
            mul(r20|T_nf); sdump("");
            mul(eax|T_nf); sdump("");
            neg(r20|T_nf); sdump("");
            neg(eax|T_nf); sdump("");

            // imul_2op
            imul(r30|T_nf, rax); sdump("");
            imul(rcx|T_nf, rax); sdump("");
            neg(r30|T_nf, rax); sdump("");
            neg(rcx|T_nf, rax); sdump("");

            // imul_zu
            imul(ax|T_zu, cx, 0x1234); sdump("");
            imul(ax|T_nf, cx, 0x1234); sdump("");
            imul(ax|T_zu|T_nf, cx, 0x1234); sdump("");
            imul(r30|T_zu, rax, 0x12345678); sdump("");
            imul(r30|T_nf, rax, 0x12345678); sdump("");
            imul(r30|T_nf|T_zu, rax, 0x12345678); sdump("");

            // lzcnt
            lzcnt(r16|T_nf, r17); sdump("");
            lzcnt(rax|T_nf, rcx); sdump("");
            tzcnt(r16|T_nf, r17); sdump("");
            tzcnt(rax|T_nf, rcx); sdump("");
            popcnt(r16|T_nf, r17); sdump("");
            popcnt(rax|T_nf, rcx); sdump("");

            // shld
            shld(rax|T_nf, rcx, cl); sdump("");
            shld(r16|T_nf, rcx, 0x9); sdump("");
            shld(r20|T_nf, r16, rcx, cl); sdump("");
            shld(r20|T_nf, r16, rcx, 0x9); sdump("");
            shrd(rax|T_nf, rcx, cl); sdump("");
            shrd(r16|T_nf, rcx, 0x9); sdump("");
            shrd(r20|T_nf, r16, rcx, cl); sdump("");
            shrd(r20|T_nf, r16, rcx, 0x9); sdump("");

            // mov_misc
            setb(r31b|T_zu); sdump("");
            setb(r15b|T_zu); sdump("");

            // shift_2op
            shl(r16|T_nf, cl); sdump("");
            shr(r16|T_nf, cl); sdump("");
            sar(r16|T_nf, cl); sdump("");
            ror(r16|T_nf, cl); sdump("");
            rol(r16|T_nf, cl); sdump("");

        }
    }
}
