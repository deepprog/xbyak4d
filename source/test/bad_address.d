module test.bad_address;

unittest
{
    import std.stdio;
	import xbyak;
    import std.exception;

    class Code : CodeGenerator
    {
        this()
        {
            assertThrown(mov(eax, ptr [esp + esp]));
            assertThrown(mov(eax, ptr [ax]));             // not support
			assertThrown(mov(eax, ptr [esp * 4]));
            assertThrown(mov(eax, ptr [eax * 16]));
            assertThrown(mov(eax, ptr [eax + eax + eax]));
            assertThrown(mov(eax, ptr [eax * 2 + ecx * 4]));
            assertThrown(mov(eax, ptr [eax * 2 + ecx * 4]));
            assertThrown(vgatherdpd(xmm0, ptr [eax * 2], ymm3));
            assertThrown(vgatherdpd(xmm0, ptr [xmm0 + xmm1], ymm3));
            version(XBYAK64)
            {
                assertThrown(mov(eax, ptr [rax + eax]));
                assertThrown( mov(eax, ptr [xmm0 + ymm0]));
            }
        }
    }
    auto c = new Code();
}