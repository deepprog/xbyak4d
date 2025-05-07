module bad_address;

version(X86)    version = XBYAK32;
version(X86_64) version = XBYAK64;

import std.exception;
import std.stdio;
import xbyak;

class Code : CodeGenerator
{
    this()
    {
      testException!({ mov(eax, ptr [esp + esp]); }, Exception);
      testException!({ mov(eax, ptr [ax]); }, Exception); // not support
      testException!({ mov(eax, ptr [esp * 4]); }, Exception);
      testException!({ mov(eax, ptr [eax * 16]); }, Exception);
      testException!({ mov(eax, ptr [eax + eax + eax]); }, Exception);
      testException!({ mov(eax, ptr [eax * 2 + ecx * 4]); }, Exception);
      testException!({ mov(eax, ptr [eax * 2 + ecx * 4]); }, Exception);
      testException!({ vgatherdpd(xmm0, ptr [eax * 2], ymm3); }, Exception);
      testException!({ vgatherdpd(xmm0, ptr [xmm0 + xmm1], ymm3); }, Exception);
  version(XBYAK64)
  {
      testException!({ mov(eax, ptr [rax + eax]); }, Exception);
      testException!({ mov(eax, ptr [xmm0 + ymm0]); }, Exception);
  }
    }
}


@("bad_address")
unittest
{
    auto c = new Code();
  
    write("bad_address test:", testCount_);
    write(" ok:", okCount_);
    writeln(" ng:", ngCount_);

    if(ngCount_ != 0) {
        assert(0, "test error is bad_address");
    }
}

static testCount_ = 0; 
static okCount_ = 0;
static ngCount_ = 0;

void testException(alias statement, exception)(string file = __FILE__, size_t line = __LINE__)
{
    testCount_++;
    int ret_ = 0;
    try {
        statement();
        ret_ = 1;
    } catch (exception ex) {
        // ret_ = 0;
    } catch (Throwable t) {
        ret_ = 2;
    }

    if(ret_ == 0) {
        okCount_++;
        return;
    }

    if (ret_ != 0) {
        ngCount_++;
        writeln("testEXCEPTION: Failure in ", file, " line ", line);
        if (ret_ == 1) {
            writeln("test: no exception");
        } else {
            writeln("test: unexpected exception");
        }
    }
}
