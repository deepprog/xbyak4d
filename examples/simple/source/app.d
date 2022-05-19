import std.stdio;
import xbyak4d;

class SampleCodeGenerator : CodeGenerator {
	this(int n) {
		// the following code sums the numbers from 1 to n

			mov(ecx, n);    // $ecx = n;
			xor(eax, eax);  // $eax = 0;
			test(ecx, ecx); // if ($ecx & $ecx)
			jbe("exit");    //     goto exit;
			xor(edx, edx);  // $edx = 0;

		L("loop");
			add(eax, edx);  // $eax += $edx;
			inc(edx);       // $edx++;
			cmp(edx, ecx);  // if ($edx <= $ecx)
			jbe("loop");    //     goto loop

		L("exit");
			ret();

	}
}

void main(){
	auto sample_code_generator = new SampleCodeGenerator(10);
	auto generated_function = cast(int function()) sample_code_generator.getCode;

	writefln("f1() = %d", generated_function());
}
