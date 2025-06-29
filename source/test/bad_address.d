module bad_address;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

import std.stdio;
import xbyak;
import test.test_count;

class Code : CodeGenerator
{
    this(ref TestCount tc)
    {
        tc.TEST_EXCEPTION!Exception({ mov(eax, ptr[esp + esp]); });
        tc.TEST_EXCEPTION!Exception({ mov(eax, ptr[ax]); }); // not support
        tc.TEST_EXCEPTION!Exception({ mov(eax, ptr[esp * 4]); });
        tc.TEST_EXCEPTION!Exception({ mov(eax, ptr[eax * 16]); });
        tc.TEST_EXCEPTION!Exception({ mov(eax, ptr[eax + eax + eax]); });
        tc.TEST_EXCEPTION!Exception({ mov(eax, ptr[eax * 2 + ecx * 4]); });
        tc.TEST_EXCEPTION!Exception({ mov(eax, ptr[eax * 2 + ecx * 4]); });
        tc.TEST_EXCEPTION!Exception({ vgatherdpd(xmm0, ptr[eax * 2], ymm3); });
        tc.TEST_EXCEPTION!Exception({ vgatherdpd(xmm0, ptr[xmm0 + xmm1], ymm3); });
        version (XBYAK64)
        {
            tc.TEST_EXCEPTION!Exception({ mov(eax, ptr[rax + eax]); });
            tc.TEST_EXCEPTION!Exception({ mov(eax, ptr[xmm0 + ymm0]); });
        }
    }
}

@("bad_address")
unittest
{
    bad_address();
}

void bad_address(size_t line = __LINE__)
{
    TestCount tc;
    tc.reset();

    scope (exit)
    {
        writef("%s(%d) : ", __FILE__, line);
        tc.end("bad_address");
    }

    scope Code c = new Code(tc);
}
