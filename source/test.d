module test;
import std.stdio;
import xbyak4d;

class Sample : CodeGenerator {
	public:
		this(int n)
		{	
			mov(ecx, n); // -- (A)
			xor(eax, eax); // sum
			test(ecx, ecx);
			jbe("exit");
			xor(edx, edx); // i
		L("lp");
			add(eax, edx);
			inc(edx);
			cmp(edx, ecx);
			jbe("lp");
		L("exit");
			ret();
		}
	}

void main(){
	printf("test\n");

	auto s = new Sample(10);
	auto f1 = cast(int function())s.getCode;
	printf("%X:",s.getCode);
	s.dump;
	printf("f1()=%d\n", f1() );
	printf("\n");
	
	class x4d : CodeGenerator{}
	auto s2 = new x4d;
	with(s2){
		//	mov(eax, ebx);
		auto p1 = 0x01;
		mov(ebx, p1);
		add(eax, ebx);
		ret;
	}

	auto f2 = cast(int function(int))s2.getCode;
	printf("%X:",s2.getCode);
	s2.dump;
	auto p2=3;
	printf("f2(%d)=%d\n", p2, f2(p2) );
	
	class mem : CodeGenerator{
			this(){
				super(AutoGrow);
				foreach(i; 0 .. 0xffff) db(0);
			}
	}

		auto mm = new mem();
		printf("END test\n");
}
