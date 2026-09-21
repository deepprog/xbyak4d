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
            adc(r17, ptr [rax]); sdump("D5481308");
            adc(ptr [r18], rdx); sdump("D5181112");
            adc(r30, rcx); sdump("D51911CE");
            add(r17, ptr [rax]); sdump("D5480308");
            add(ptr [r18], rdx); sdump("D5180112");
            add(r30, rcx); sdump("D51901CE");
            and_(r17, ptr [rax]); sdump("D5482308");
            and_(ptr [r18], rdx); sdump("D5182112");
            and_(r30, rcx); sdump("D51921CE");
            cmp(r17, ptr [rax]); sdump("D5483B08");
            cmp(ptr [r18], rdx); sdump("D5183912");
            cmp(r30, rcx); sdump("D51939CE");
            or_(r17, ptr [rax]); sdump("D5480B08");
            or_(ptr [r18], rdx); sdump("D5180912");
            or_(r30, rcx); sdump("D51909CE");
            sbb(r17, ptr [rax]); sdump("D5481B08");
            sbb(ptr [r18], rdx); sdump("D5181912");
            sbb(r30, rcx); sdump("D51919CE");
            sub(r17, ptr [rax]); sdump("D5482B08");
            sub(ptr [r18], rdx); sdump("D5182912");
            sub(r30, rcx); sdump("D51929CE");
            xor_(r17, ptr [rax]); sdump("D5483308");
            xor_(ptr [r18], rdx); sdump("D5183112");
            xor_(r30, rcx); sdump("D51931CE");
            add(r30, ptr [rbx+rcx*4]); sdump("D54C03348B");
            add(rax, ptr [r30+rcx*4]); sdump("D51903048E");
            add(rax, ptr [rbx+r30*4]); sdump("D52A0304B3");

            // reg64
            adc(r30, rax); sdump("D51911C6");
            adc(r30, rcx); sdump("D51911CE");
            adc(r30, rdx); sdump("D51911D6");
            adc(r30, rbx); sdump("D51911DE");
            adc(r30, rsp); sdump("D51911E6");
            adc(r30, rbp); sdump("D51911EE");
            adc(r30, rsi); sdump("D51911F6");
            adc(r30, rdi); sdump("D51911FE");
            adc(r30, r8); sdump("D51D11C6");
            adc(r30, r9); sdump("D51D11CE");
            adc(r30, r10); sdump("D51D11D6");
            adc(r30, r11); sdump("D51D11DE");
            adc(r30, r12); sdump("D51D11E6");
            adc(r30, r13); sdump("D51D11EE");
            adc(r30, r14); sdump("D51D11F6");
            adc(r30, r15); sdump("D51D11FE");
            adc(r30, r16); sdump("D55911C6");
            adc(r30, r17); sdump("D55911CE");
            adc(r30, r18); sdump("D55911D6");
            adc(r30, r19); sdump("D55911DE");
            adc(r30, r20); sdump("D55911E6");
            adc(r30, r21); sdump("D55911EE");
            adc(r30, r22); sdump("D55911F6");
            adc(r30, r23); sdump("D55911FE");
            adc(r30, r24); sdump("D55D11C6");
            adc(r30, r25); sdump("D55D11CE");
            adc(r30, r26); sdump("D55D11D6");
            adc(r30, r27); sdump("D55D11DE");
            adc(r30, r28); sdump("D55D11E6");
            adc(r30, r29); sdump("D55D11EE");
            adc(r30, r30); sdump("D55D11F6");
            adc(r30, r31); sdump("D55D11FE");
            adc(rax, r30); sdump("D54C11F0");
            adc(rcx, r30); sdump("D54C11F1");
            adc(rdx, r30); sdump("D54C11F2");
            adc(rbx, r30); sdump("D54C11F3");
            adc(rsp, r30); sdump("D54C11F4");
            adc(rbp, r30); sdump("D54C11F5");
            adc(rsi, r30); sdump("D54C11F6");
            adc(rdi, r30); sdump("D54C11F7");
            adc(r8, r30); sdump("D54D11F0");
            adc(r9, r30); sdump("D54D11F1");
            adc(r10, r30); sdump("D54D11F2");
            adc(r11, r30); sdump("D54D11F3");
            adc(r12, r30); sdump("D54D11F4");
            adc(r13, r30); sdump("D54D11F5");
            adc(r14, r30); sdump("D54D11F6");
            adc(r15, r30); sdump("D54D11F7");
            adc(r16, r30); sdump("D55C11F0");
            adc(r17, r30); sdump("D55C11F1");
            adc(r18, r30); sdump("D55C11F2");
            adc(r19, r30); sdump("D55C11F3");
            adc(r20, r30); sdump("D55C11F4");
            adc(r21, r30); sdump("D55C11F5");
            adc(r22, r30); sdump("D55C11F6");
            adc(r23, r30); sdump("D55C11F7");
            adc(r24, r30); sdump("D55D11F0");
            adc(r25, r30); sdump("D55D11F1");
            adc(r26, r30); sdump("D55D11F2");
            adc(r27, r30); sdump("D55D11F3");
            adc(r28, r30); sdump("D55D11F4");
            adc(r29, r30); sdump("D55D11F5");
            adc(r30, r30); sdump("D55D11F6");
            adc(r31, r30); sdump("D55D11F7");

            // reg32
            adc(r30d, eax); sdump("D51111C6");
            adc(r30d, ecx); sdump("D51111CE");
            adc(r30d, edx); sdump("D51111D6");
            adc(r30d, ebx); sdump("D51111DE");
            adc(r30d, esp); sdump("D51111E6");
            adc(r30d, ebp); sdump("D51111EE");
            adc(r30d, esi); sdump("D51111F6");
            adc(r30d, edi); sdump("D51111FE");
            adc(r30d, r8d); sdump("D51511C6");
            adc(r30d, r9d); sdump("D51511CE");
            adc(r30d, r10d); sdump("D51511D6");
            adc(r30d, r11d); sdump("D51511DE");
            adc(r30d, r12d); sdump("D51511E6");
            adc(r30d, r13d); sdump("D51511EE");
            adc(r30d, r14d); sdump("D51511F6");
            adc(r30d, r15d); sdump("D51511FE");
            adc(r30d, r16d); sdump("D55111C6");
            adc(r30d, r17d); sdump("D55111CE");
            adc(r30d, r18d); sdump("D55111D6");
            adc(r30d, r19d); sdump("D55111DE");
            adc(r30d, r20d); sdump("D55111E6");
            adc(r30d, r21d); sdump("D55111EE");
            adc(r30d, r22d); sdump("D55111F6");
            adc(r30d, r23d); sdump("D55111FE");
            adc(r30d, r24d); sdump("D55511C6");
            adc(r30d, r25d); sdump("D55511CE");
            adc(r30d, r26d); sdump("D55511D6");
            adc(r30d, r27d); sdump("D55511DE");
            adc(r30d, r28d); sdump("D55511E6");
            adc(r30d, r29d); sdump("D55511EE");
            adc(r30d, r30d); sdump("D55511F6");
            adc(r30d, r31d); sdump("D55511FE");
            adc(eax, r29d); sdump("D54411E8");
            adc(ecx, r29d); sdump("D54411E9");
            adc(edx, r29d); sdump("D54411EA");
            adc(ebx, r29d); sdump("D54411EB");
            adc(esp, r29d); sdump("D54411EC");
            adc(ebp, r29d); sdump("D54411ED");
            adc(esi, r29d); sdump("D54411EE");
            adc(edi, r29d); sdump("D54411EF");
            adc(r8d, r29d); sdump("D54511E8");
            adc(r9d, r29d); sdump("D54511E9");
            adc(r10d, r29d); sdump("D54511EA");
            adc(r11d, r29d); sdump("D54511EB");
            adc(r12d, r29d); sdump("D54511EC");
            adc(r13d, r29d); sdump("D54511ED");
            adc(r14d, r29d); sdump("D54511EE");
            adc(r15d, r29d); sdump("D54511EF");
            adc(r16d, r29d); sdump("D55411E8");
            adc(r17d, r29d); sdump("D55411E9");
            adc(r18d, r29d); sdump("D55411EA");
            adc(r19d, r29d); sdump("D55411EB");
            adc(r20d, r29d); sdump("D55411EC");
            adc(r21d, r29d); sdump("D55411ED");
            adc(r22d, r29d); sdump("D55411EE");
            adc(r23d, r29d); sdump("D55411EF");
            adc(r24d, r29d); sdump("D55511E8");
            adc(r25d, r29d); sdump("D55511E9");
            adc(r26d, r29d); sdump("D55511EA");
            adc(r27d, r29d); sdump("D55511EB");
            adc(r28d, r29d); sdump("D55511EC");
            adc(r29d, r29d); sdump("D55511ED");
            adc(r30d, r29d); sdump("D55511EE");
            adc(r31d, r29d); sdump("D55511EF");

            // reg16
            adc(r30w, ax); sdump("66D51111C6");
            adc(r30w, cx); sdump("66D51111CE");
            adc(r30w, dx); sdump("66D51111D6");
            adc(r30w, bx); sdump("66D51111DE");
            adc(r30w, sp); sdump("66D51111E6");
            adc(r30w, bp); sdump("66D51111EE");
            adc(r30w, si); sdump("66D51111F6");
            adc(r30w, di); sdump("66D51111FE");
            adc(r30w, r8w); sdump("66D51511C6");
            adc(r30w, r9w); sdump("66D51511CE");
            adc(r30w, r10w); sdump("66D51511D6");
            adc(r30w, r11w); sdump("66D51511DE");
            adc(r30w, r12w); sdump("66D51511E6");
            adc(r30w, r13w); sdump("66D51511EE");
            adc(r30w, r14w); sdump("66D51511F6");
            adc(r30w, r15w); sdump("66D51511FE");
            adc(r30w, r16w); sdump("66D55111C6");
            adc(r30w, r17w); sdump("66D55111CE");
            adc(r30w, r18w); sdump("66D55111D6");
            adc(r30w, r19w); sdump("66D55111DE");
            adc(r30w, r20w); sdump("66D55111E6");
            adc(r30w, r21w); sdump("66D55111EE");
            adc(r30w, r22w); sdump("66D55111F6");
            adc(r30w, r23w); sdump("66D55111FE");
            adc(r30w, r24w); sdump("66D55511C6");
            adc(r30w, r25w); sdump("66D55511CE");
            adc(r30w, r26w); sdump("66D55511D6");
            adc(r30w, r27w); sdump("66D55511DE");
            adc(r30w, r28w); sdump("66D55511E6");
            adc(r30w, r29w); sdump("66D55511EE");
            adc(r30w, r30w); sdump("66D55511F6");
            adc(r30w, r31w); sdump("66D55511FE");
            adc(ax, r29w); sdump("66D54411E8");
            adc(cx, r29w); sdump("66D54411E9");
            adc(dx, r29w); sdump("66D54411EA");
            adc(bx, r29w); sdump("66D54411EB");
            adc(sp, r29w); sdump("66D54411EC");
            adc(bp, r29w); sdump("66D54411ED");
            adc(si, r29w); sdump("66D54411EE");
            adc(di, r29w); sdump("66D54411EF");
            adc(r8w, r29w); sdump("66D54511E8");
            adc(r9w, r29w); sdump("66D54511E9");
            adc(r10w, r29w); sdump("66D54511EA");
            adc(r11w, r29w); sdump("66D54511EB");
            adc(r12w, r29w); sdump("66D54511EC");
            adc(r13w, r29w); sdump("66D54511ED");
            adc(r14w, r29w); sdump("66D54511EE");
            adc(r15w, r29w); sdump("66D54511EF");
            adc(r16w, r29w); sdump("66D55411E8");
            adc(r17w, r29w); sdump("66D55411E9");
            adc(r18w, r29w); sdump("66D55411EA");
            adc(r19w, r29w); sdump("66D55411EB");
            adc(r20w, r29w); sdump("66D55411EC");
            adc(r21w, r29w); sdump("66D55411ED");
            adc(r22w, r29w); sdump("66D55411EE");
            adc(r23w, r29w); sdump("66D55411EF");
            adc(r24w, r29w); sdump("66D55511E8");
            adc(r25w, r29w); sdump("66D55511E9");
            adc(r26w, r29w); sdump("66D55511EA");
            adc(r27w, r29w); sdump("66D55511EB");
            adc(r28w, r29w); sdump("66D55511EC");
            adc(r29w, r29w); sdump("66D55511ED");
            adc(r30w, r29w); sdump("66D55511EE");
            adc(r31w, r29w); sdump("66D55511EF");

            // reg8
            adc(r17b, al); sdump("D51010C1");
            adc(r17b, cl); sdump("D51010C9");
            adc(r17b, dl); sdump("D51010D1");
            adc(r17b, bl); sdump("D51010D9");
            adc(r17b, spl); sdump("D51010E1");
            adc(r17b, bpl); sdump("D51010E9");
            adc(r17b, sil); sdump("D51010F1");
            adc(r17b, dil); sdump("D51010F9");
            adc(r17b, r8b); sdump("D51410C1");
            adc(r17b, r9b); sdump("D51410C9");
            adc(r17b, r10b); sdump("D51410D1");
            adc(r17b, r11b); sdump("D51410D9");
            adc(r17b, r12b); sdump("D51410E1");
            adc(r17b, r13b); sdump("D51410E9");
            adc(r17b, r14b); sdump("D51410F1");
            adc(r17b, r15b); sdump("D51410F9");
            adc(r17b, r16b); sdump("D55010C1");
            adc(r17b, r17b); sdump("D55010C9");
            adc(r17b, r18b); sdump("D55010D1");
            adc(r17b, r19b); sdump("D55010D9");
            adc(r17b, r20b); sdump("D55010E1");
            adc(r17b, r21b); sdump("D55010E9");
            adc(r17b, r22b); sdump("D55010F1");
            adc(r17b, r23b); sdump("D55010F9");
            adc(r17b, r24b); sdump("D55410C1");
            adc(r17b, r25b); sdump("D55410C9");
            adc(r17b, r26b); sdump("D55410D1");
            adc(r17b, r27b); sdump("D55410D9");
            adc(r17b, r28b); sdump("D55410E1");
            adc(r17b, r29b); sdump("D55410E9");
            adc(r17b, r30b); sdump("D55410F1");
            adc(r17b, r31b); sdump("D55410F9");
            adc(al, r20b); sdump("D54010E0");
            adc(cl, r20b); sdump("D54010E1");
            adc(dl, r20b); sdump("D54010E2");
            adc(bl, r20b); sdump("D54010E3");
            adc(spl, r20b); sdump("D54010E4");
            adc(bpl, r20b); sdump("D54010E5");
            adc(sil, r20b); sdump("D54010E6");
            adc(dil, r20b); sdump("D54010E7");
            adc(r8b, r20b); sdump("D54110E0");
            adc(r9b, r20b); sdump("D54110E1");
            adc(r10b, r20b); sdump("D54110E2");
            adc(r11b, r20b); sdump("D54110E3");
            adc(r12b, r20b); sdump("D54110E4");
            adc(r13b, r20b); sdump("D54110E5");
            adc(r14b, r20b); sdump("D54110E6");
            adc(r15b, r20b); sdump("D54110E7");
            adc(r16b, r20b); sdump("D55010E0");
            adc(r17b, r20b); sdump("D55010E1");
            adc(r18b, r20b); sdump("D55010E2");
            adc(r19b, r20b); sdump("D55010E3");
            adc(r20b, r20b); sdump("D55010E4");
            adc(r21b, r20b); sdump("D55010E5");
            adc(r22b, r20b); sdump("D55010E6");
            adc(r23b, r20b); sdump("D55010E7");
            adc(r24b, r20b); sdump("D55110E0");
            adc(r25b, r20b); sdump("D55110E1");
            adc(r26b, r20b); sdump("D55110E2");
            adc(r27b, r20b); sdump("D55110E3");
            adc(r28b, r20b); sdump("D55110E4");
            adc(r29b, r20b); sdump("D55110E5");
            adc(r30b, r20b); sdump("D55110E6");
            adc(r31b, r20b); sdump("D55110E7");

            // rm
            adc(r16, ptr [r17+0x40]); sdump("D558134140");
            adc(ptr [r17+0x40], r16); sdump("D558114140");
            adc(r16d, ptr [r17+0x40]); sdump("D550134140");
            adc(ptr [r17+0x40], r16d); sdump("D550114140");
            adc(r16w, ptr [r17+0x40]); sdump("66D550134140");
            adc(ptr [r17+0x40], r16w); sdump("66D550114140");
            adc(r16b, ptr [r17+0x40]); sdump("D550124140");
            adc(ptr [r17+0x40], r16b); sdump("D550104140");
            adc(r16, ptr [r18*4+0x40]); sdump("D56813049540000000");
            adc(ptr [r18*4+0x40], r16); sdump("D56811049540000000");
            adc(r16d, ptr [r18*4+0x40]); sdump("D56013049540000000");
            adc(ptr [r18*4+0x40], r16d); sdump("D56011049540000000");
            adc(r16w, ptr [r18*4+0x40]); sdump("66D56013049540000000");
            adc(ptr [r18*4+0x40], r16w); sdump("66D56011049540000000");
            adc(r16b, ptr [r18*4+0x40]); sdump("D56012049540000000");
            adc(ptr [r18*4+0x40], r16b); sdump("D56010049540000000");
            adc(r16, ptr [r17+r18*4+0x40]); sdump("D57813449140");
            adc(ptr [r17+r18*4+0x40], r16); sdump("D57811449140");
            adc(r16d, ptr [r17+r18*4+0x40]); sdump("D57013449140");
            adc(ptr [r17+r18*4+0x40], r16d); sdump("D57011449140");
            adc(r16w, ptr [r17+r18*4+0x40]); sdump("66D57013449140");
            adc(ptr [r17+r18*4+0x40], r16w); sdump("66D57011449140");
            adc(r16b, ptr [r17+r18*4+0x40]); sdump("D57012449140");
            adc(ptr [r17+r18*4+0x40], r16b); sdump("D57010449140");

            // r3
            adc(r20b, r21b, r23b); sdump("62EC5C1010FD");
            adc(r20w, r21w, r23w); sdump("62EC5D1011FD");
            adc(r20d, r21d, r23d); sdump("62EC5C1011FD");
            adc(r20, r21, r23); sdump("62ECDC1011FD");

            // rm3
            adc(rax, r18, ptr [rbx+rcx*4+0x123]); sdump("62E4FC1813948B23010000");
            adc(rax, ptr [rbx+rcx*4+0x123], r20); sdump("62E4FC1811A48B23010000");
            adc(rax, ptr [r30], r29); sdump("624CFC18112E");
            adc(r11, r13, ptr [r10]); sdump("6254A418132A");
            adc(r11, r13, ptr [r10*4]); sdump("6234A418132C9500000000");
            adc(r11, ptr [r10*8], r9); sdump("6234A418110CD500000000");

            // rm3_2
            adc(r20b, r21b, r23b); sdump("62EC5C1010FD");
            adc(r20w, r21w, r23w); sdump("62EC5D1011FD");
            adc(r20d, r21d, r23d); sdump("62EC5C1011FD");
            adc(r20, r21, r23); sdump("62ECDC1011FD");
            adc(r20b, ptr [rax+rcx*4+0x7fffffff], 0x12); sdump("62F45C10809488FFFFFF7F12");
            adc(r20w, ptr [rax+rcx*4+0x7fffffff], 0x1234); sdump("62F45D10819488FFFFFF7F3412");
            adc(r20d, ptr [rax+rcx*4+0x7fffffff], 0x12345678); sdump("62F45C10819488FFFFFF7F78563412");
            adc(r20, ptr [rax+rcx*4+0x7fffffff], 0x12345678); sdump("62F4DC10819488FFFFFF7F78563412");
            adc(r20b, al, 0x12); sdump("62F45C1080D012");
            adc(r20w, ax, 0x1234); sdump("62F45D1081D03412");
            adc(r20d, eax, 0x12345678); sdump("62F45C1081D078563412");
            adc(r20, rax, 0x12345678); sdump("62F4DC1081D078563412");

            // adcx_adox
            adcx(rax, r30); sdump("62DCFD0866C6");
            adcx(ecx, r20d); sdump("62FC7D0866CC");
            adcx(ecx, ptr [r31+r29*4]); sdump("629C7908660CAF");
            adcx(r20d, ptr [rax]); sdump("62E47D086620");
            adcx(r16, ptr [r31+r29*4]); sdump("628CF9086604AF");
            adcx(r17, ptr [rax]); sdump("62E4FD086608");
            adcx(rax, rcx, rdx); sdump("62F4FD1866CA");
            adox(rax, r30); sdump("62DCFE0866C6");
            adox(ecx, r20d); sdump("62FC7E0866CC");
            adox(ecx, ptr [r31+r29*4]); sdump("629C7A08660CAF");
            adox(r20d, ptr [rax]); sdump("62E47E086620");
            adox(r16, ptr [r31+r29*4]); sdump("628CFA086604AF");
            adox(r17, ptr [rax]); sdump("62E4FE086608");
            adox(rax, rcx, rdx); sdump("62F4FE1866CA");

            // r3_2
            add(rax, rcx, rdx); sdump("62F4FC1801D1");
            adc(rax, rcx, rdx); sdump("62F4FC1811D1");
            and_(rax, rcx, rdx); sdump("62F4FC1821D1");
            or_(rax, rcx, rdx); sdump("62F4FC1809D1");
            sbb(rax, rcx, rdx); sdump("62F4FC1819D1");
            sub(rax, rcx, rdx); sdump("62F4FC1829D1");
            xor_(rax, rcx, rdx); sdump("62F4FC1831D1");
            add(r30, ptr [r20], r9); sdump("627C8C10010C24");
            adc(r30, ptr [r20], r9); sdump("627C8C10110C24");
            and_(r30, ptr [r20], r9); sdump("627C8C10210C24");
            or_(r30, ptr [r20], r9); sdump("627C8C10090C24");
            sbb(r30, ptr [r20], r9); sdump("627C8C10190C24");
            sub(r30, ptr [r20], r9); sdump("627C8C10290C24");
            xor_(r30, ptr [r20], r9); sdump("627C8C10310C24");

            // andn_etc
            andn(r29, r30, r31); sdump("624A8C00F2EF");
            andn(eax, ecx, r17d); sdump("62FA7408F2C1");
            andn(r29, r30, ptr [r31+r20*4]); sdump("624A8800F22CA7");
            mulx(eax, ecx, r17d); sdump("62FA7708F6C1");
            mulx(r29, r30, r31); sdump("624A8F00F6EF");
            mulx(r29, r30, ptr [r31+r20*4]); sdump("624A8B00F62CA7");
            pdep(eax, ecx, r17d); sdump("62FA7708F5C1");
            pdep(r29, r30, r31); sdump("624A8F00F5EF");
            pdep(r29, r30, ptr [r31+r20*4]); sdump("624A8B00F52CA7");
            pext(eax, ecx, r17d); sdump("62FA7608F5C1");
            pext(r29, r30, r31); sdump("624A8E00F5EF");
            pext(r29, r30, ptr [r31+r20*4]); sdump("624A8A00F52CA7");

            // bextr_etc
            bextr(r29, r30, r31); sdump("624A8400F7EE");
            bextr(eax, ecx, r17d); sdump("62F27400F7C1");
            bextr(r29, ptr [r31+r20*4], r30); sdump("624A8800F72CA7");
            bzhi(r29, r30, r31); sdump("624A8400F5EE");
            bzhi(eax, ecx, r17d); sdump("62F27400F5C1");
            bzhi(r29, ptr [r31+r20*4], r30); sdump("624A8800F52CA7");
            sarx(r29, r30, r31); sdump("624A8600F7EE");
            sarx(eax, ecx, r17d); sdump("62F27600F7C1");
            sarx(r29, ptr [r31+r20*4], r30); sdump("624A8A00F72CA7");
            shlx(r29, r30, r31); sdump("624A8500F7EE");
            shlx(eax, ecx, r17d); sdump("62F27500F7C1");
            shlx(r29, ptr [r31+r20*4], r30); sdump("624A8900F72CA7");
            shrx(r29, r30, r31); sdump("624A8700F7EE");
            shrx(eax, ecx, r17d); sdump("62F27700F7C1");
            shrx(r29, ptr [r31+r20*4], r30); sdump("624A8B00F72CA7");
            blsi(r30, r31); sdump("62DA8C00F3DF");
            blsi(ecx, r17d); sdump("62FA7408F3D9");
            blsi(r30, ptr [r31+r20*4]); sdump("62DA8800F31CA7");
            blsmsk(r30, r31); sdump("62DA8C00F3D7");
            blsmsk(ecx, r17d); sdump("62FA7408F3D1");
            blsmsk(r30, ptr [r31+r20*4]); sdump("62DA8800F314A7");
            blsr(r30, r31); sdump("62DA8C00F3CF");
            blsr(ecx, r17d); sdump("62FA7408F3C9");
            blsr(r30, ptr [r31+r20*4]); sdump("62DA8800F30CA7");
            rorx(r30, r31, 3); sdump("624BFF08F0F703");
            rorx(ecx, r17d, 5); sdump("62FB7F08F0C905");
            rorx(r30, ptr [r31+r20*4], 4); sdump("624BFB08F034A704");

            // bit
            adc(r20b, r21b, r22b); sdump("62EC5C1010F5");
            adc(r20w, r21w, r22w); sdump("62EC5D1011F5");
            adc(r20d, r21d, r22d); sdump("62EC5C1011F5");
            adc(r20, r21, r22); sdump("62ECDC1011F5");
            adc(r20b, r21b); sdump("D55010EC");
            adc(r20w, r21w); sdump("66D55011EC");
            adc(r20d, r21d); sdump("D55011EC");
            adc(r20, r21); sdump("D55811EC");
            adc(r20b, r21b, 0x3); sdump("62FC5C1080D503");
            adc(r20w, r21w, 0x3); sdump("62FC5D1083D503");
            adc(r20d, r21d, 0x3); sdump("62FC5C1083D503");
            adc(r20, r21, 0x3); sdump("62FCDC1083D503");
            adc(r20b, 0x3); sdump("D51080D403");
            adc(r20w, 0x3); sdump("66D51083D403");
            adc(r20d, 0x3); sdump("D51083D403");
            adc(r20, 0x3); sdump("D51883D403");
            add(r20b, r21b, r22b); sdump("62EC5C1000F5");
            add(r20w, r21w, r22w); sdump("62EC5D1001F5");
            add(r20d, r21d, r22d); sdump("62EC5C1001F5");
            add(r20, r21, r22); sdump("62ECDC1001F5");
            add(r20b, r21b); sdump("D55000EC");
            add(r20w, r21w); sdump("66D55001EC");
            add(r20d, r21d); sdump("D55001EC");
            add(r20, r21); sdump("D55801EC");
            add(r20b, r21b, 0x3); sdump("62FC5C1080C503");
            add(r20w, r21w, 0x3); sdump("62FC5D1083C503");
            add(r20d, r21d, 0x3); sdump("62FC5C1083C503");
            add(r20, r21, 0x3); sdump("62FCDC1083C503");
            add(r20b, 0x3); sdump("D51080C403");
            add(r20w, 0x3); sdump("66D51083C403");
            add(r20d, 0x3); sdump("D51083C403");
            add(r20, 0x3); sdump("D51883C403");

            // inc_dec
            inc(r30b); sdump("D511FEC6");
            inc(r30w); sdump("66D511FFC6");
            inc(r30d); sdump("D511FFC6");
            inc(r30); sdump("D519FFC6");
            inc(r30b, r31b); sdump("62DC0C10FEC7");
            inc(r30w, r31w); sdump("62DC0D10FFC7");
            inc(r30d, r31d); sdump("62DC0C10FFC7");
            inc(r30, r31); sdump("62DC8C10FFC7");
            inc(r30, ptr [r31]); sdump("62DC8C10FF07");
            dec(r30b); sdump("D511FECE");
            dec(r30w); sdump("66D511FFCE");
            dec(r30d); sdump("D511FFCE");
            dec(r30); sdump("D519FFCE");
            dec(r30b, r31b); sdump("62DC0C10FECF");
            dec(r30w, r31w); sdump("62DC0D10FFCF");
            dec(r30d, r31d); sdump("62DC0C10FFCF");
            dec(r30, r31); sdump("62DC8C10FFCF");
            dec(r30, ptr [r31]); sdump("62DC8C10FF0F");

            // div_op1
            div(r20b); sdump("D510F6F4");
            div(r20d); sdump("D510F7F4");
            div(r20w); sdump("66D510F7F4");
            div(r20); sdump("D518F7F4");
            div(byte_ [r20+r30*1]); sdump("D532F63434");
            div(word [r20+r30*1]); sdump("66D532F73434");
            div(dword [r20+r30*1]); sdump("D532F73434");
            div(qword [r20+r30*1]); sdump("D53AF73434");
            idiv(r20b); sdump("D510F6FC");
            idiv(r20d); sdump("D510F7FC");
            idiv(r20w); sdump("66D510F7FC");
            idiv(r20); sdump("D518F7FC");
            idiv(byte_ [r20+r30*1]); sdump("D532F63C34");
            idiv(word [r20+r30*1]); sdump("66D532F73C34");
            idiv(dword [r20+r30*1]); sdump("D532F73C34");
            idiv(qword [r20+r30*1]); sdump("D53AF73C34");
            imul(r20b); sdump("D510F6EC");
            imul(r20d); sdump("D510F7EC");
            imul(r20w); sdump("66D510F7EC");
            imul(r20); sdump("D518F7EC");
            imul(byte_ [r20+r30*1]); sdump("D532F62C34");
            imul(word [r20+r30*1]); sdump("66D532F72C34");
            imul(dword [r20+r30*1]); sdump("D532F72C34");
            imul(qword [r20+r30*1]); sdump("D53AF72C34");
            mul(r20b); sdump("D510F6E4");
            mul(r20d); sdump("D510F7E4");
            mul(r20w); sdump("66D510F7E4");
            mul(r20); sdump("D518F7E4");
            mul(byte_ [r20+r30*1]); sdump("D532F62434");
            mul(word [r20+r30*1]); sdump("66D532F72434");
            mul(dword [r20+r30*1]); sdump("D532F72434");
            mul(qword [r20+r30*1]); sdump("D53AF72434");
            neg(r20b); sdump("D510F6DC");
            neg(r20d); sdump("D510F7DC");
            neg(r20w); sdump("66D510F7DC");
            neg(r20); sdump("D518F7DC");
            neg(byte_ [r20+r30*1]); sdump("D532F61C34");
            neg(word [r20+r30*1]); sdump("66D532F71C34");
            neg(dword [r20+r30*1]); sdump("D532F71C34");
            neg(qword [r20+r30*1]); sdump("D53AF71C34");
            not_(r20b); sdump("D510F6D4");
            not_(r20d); sdump("D510F7D4");
            not_(r20w); sdump("66D510F7D4");
            not_(r20); sdump("D518F7D4");
            not_(byte_ [r20+r30*1]); sdump("D532F61434");
            not_(word [r20+r30*1]); sdump("66D532F71434");
            not_(dword [r20+r30*1]); sdump("D532F71434");
            not_(qword [r20+r30*1]); sdump("D53AF71434");

            // imul_2op
            imul(r30w, ax); sdump("62647D08AFF0");
            imul(r30d, eax); sdump("62647C08AFF0");
            imul(r30, rax); sdump("6264FC08AFF0");
            imul(rcx, ptr [r30]); sdump("62DCFC08AF0E");
            neg(r30b, al); sdump("62F40C10F6D8");
            neg(r30w, ax); sdump("62F40D10F7D8");
            neg(r30d, eax); sdump("62F40C10F7D8");
            neg(r30, rax); sdump("62F48C10F7D8");
            neg(rcx, ptr [r30]); sdump("62DCF418F71E");
            not_(r30b, al); sdump("62F40C10F6D0");
            not_(r30w, ax); sdump("62F40D10F7D0");
            not_(r30d, eax); sdump("62F40C10F7D0");
            not_(r30, rax); sdump("62F48C10F7D0");
            not_(rcx, ptr [r30]); sdump("62DCF418F716");

            // imul_zu
            imul(r30w, ax, 0x1234); sdump("62647D0869F03412");
            imul(r30d, eax, 0x12345678); sdump("62647C0869F078563412");
            imul(r30, rax, 0x12345678); sdump("6264FC0869F078563412");
            imul(rcx, ptr [r30], 0x12345678); sdump("62DCFC08690E78563412");

            // lzcnt
            lzcnt(r16w, r17w); sdump("62EC7D08F5C1");
            lzcnt(r16d, r17d); sdump("62EC7C08F5C1");
            lzcnt(r16, r17); sdump("62ECFC08F5C1");
            lzcnt(rax, ptr [r18]); sdump("62FCFC08F502");
            tzcnt(r16w, r17w); sdump("62EC7D08F4C1");
            tzcnt(r16d, r17d); sdump("62EC7C08F4C1");
            tzcnt(r16, r17); sdump("62ECFC08F4C1");
            tzcnt(rax, ptr [r18]); sdump("62FCFC08F402");
            popcnt(r16w, r17w); sdump("62EC7D0888C1");
            popcnt(r16d, r17d); sdump("62EC7C0888C1");
            popcnt(r16, r17); sdump("62ECFC0888C1");
            popcnt(rax, ptr [r18]); sdump("62FCFC088802");

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
            bswap(eax); sdump("0FC8");
            bswap(r8d); sdump("410FC8");
            bswap(r16d); sdump("D590C8");
            bswap(rcx); sdump("480FC9");
            bswap(r9); sdump("490FC9");
            bswap(r17); sdump("D598C9");

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

            // ccmp
            ccmpb(rax, rbx, 0); sdump("");
            ccmpb(r30b, r31b, 1); sdump("");
            ccmpb(r30w, r31w, 2); sdump("");
            ccmpb(r30d, r31d, 3); sdump("");
            ccmpb(r30, r31, 4); sdump("");
            ccmpb(ptr [r30], r31b, 5); sdump("");
            ccmpb(ptr [r30], r31w, 6); sdump("");
            ccmpb(ptr [r30], r31d, 7); sdump("");
            ccmpb(ptr [r30], r31, 8); sdump("");
            ccmpb(r31b, ptr [r30], 9); sdump("");
            ccmpb(r31w, ptr [r30], 10); sdump("");
            ccmpb(r31d, ptr [r30], 11); sdump("");
            ccmpb(r31, ptr [r30], 12); sdump("");
            ccmpb(r20b, 0x12, 9); sdump("");
            ccmpb(r20w, 0x1234, 9); sdump("");
            ccmpb(r20d, 0x12345678, 9); sdump("");
            ccmpb(r20, 0x12345678, 9); sdump("");
            ccmpb(byte_ [r20], 0x12, 9); sdump("");
            ccmpb(word [r20], 0x1234, 9); sdump("");
            ccmpb(dword [r20], 0x12345678, 9); sdump("");
            ccmpb(qword [r20], 0x12345678, 9); sdump("");
            ccmpo(rax, rcx, 0); sdump("");
            ccmpno(rax, rcx, 1); sdump("");
            ccmpb(rax, rcx, 2); sdump("");
            ccmpnb(rax, rcx, 3); sdump("");
            ccmpz(rax, rcx, 4); sdump("");
            ccmpnz(rax, rcx, 5); sdump("");
            ccmpbe(rax, rcx, 6); sdump("");
            ccmpnbe(rax, rcx, 7); sdump("");
            ccmps(rax, rcx, 8); sdump("");
            ccmpns(rax, rcx, 9); sdump("");
            ccmpt(rax, rcx, 10); sdump("");
            ccmpf(rax, rcx, 11); sdump("");
            ccmpl(rax, rcx, 12); sdump("");
            ccmpnl(rax, rcx, 13); sdump("");
            ccmple(rax, rcx, 14); sdump("");
            ccmpnle(rax, rcx, 15); sdump("");

            // ctestb
            ctestb(r30w, r31w, 1); sdump("624C0D0285FE");
            ctestb(r30d, r31d, 2); sdump("624C140285FE");
            ctestb(r30, r31, 3); sdump("624C9C0285FE");
            ctestb(ptr [r30], r31b, 4); sdump("624C2402843E");
            ctestb(ptr [r30], r31w, 5); sdump("624C2D02853E");
            ctestb(ptr [r30], r31d, 6); sdump("624C3402853E");
            ctestb(ptr [r30], r31, 7); sdump("624CBC02853E");
            ctestb(r30b, 0x12, 8); sdump("62DC4402F6C612");
            ctestb(r30w, 0x1234, 9); sdump("62DC4D02F7C63412");
            ctestb(r30d, 0x12345678, 10); sdump("62DC5402F7C678563412");
            ctestb(r30, 0x12345678, 11); sdump("62DCDC02F7C678563412");
            ctestb(byte_ [r30], 0x12, 12); sdump("62DC6402F60612");
            ctestb(word [r30], 0x1234, 13); sdump("62DC6D02F7063412");
            ctestb(dword [r30], 0x12345678, 14); sdump("62DC7402F70678563412");
            ctestb(qword [r30], 0x12345678, 15); sdump("62DCFC02F70678563412");
            ctesto(rax, rcx, 0); sdump("62F4840085C8");
            ctestno(rax, rcx, 1); sdump("62F48C0185C8");
            ctestb(rax, rcx, 2); sdump("62F4940285C8");
            ctestnb(rax, rcx, 3); sdump("62F49C0385C8");
            ctestz(rax, rcx, 4); sdump("62F4A40485C8");
            ctestnz(rax, rcx, 5); sdump("62F4AC0585C8");
            ctestbe(rax, rcx, 6); sdump("62F4B40685C8");
            ctestnbe(rax, rcx, 7); sdump("62F4BC0785C8");
            ctests(rax, rcx, 8); sdump("62F4C40885C8");
            ctestns(rax, rcx, 9); sdump("62F4CC0985C8");
            ctestt(rax, rcx, 10); sdump("62F4D40A85C8");
            ctestf(rax, rcx, 11); sdump("62F4DC0B85C8");
            ctestl(rax, rcx, 12); sdump("62F4E40C85C8");
            ctestnl(rax, rcx, 13); sdump("62F4EC0D85C8");
            ctestle(rax, rcx, 14); sdump("62F4F40E85C8");
            ctestnle(rax, rcx, 15); sdump("62F4FC0F85C8");

            // dfv omitted (dfv=0)
            ccmpb(rax, rbx); sdump("62F4840239D8");
            ccmpz(r20w, 0x1234); sdump("627C050481FC3412");
            ctestnle(qword [r30], 0x12345678); sdump("62DC840FF70678563412");

        }
    }
}
