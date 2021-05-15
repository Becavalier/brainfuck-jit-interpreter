# brainfuck-jit-interpreter
A handwritten Brainfuck JIT interpreter, mainly used for demonstration purposes.

### How to use?

*\* Please make sure you have installed `python` 3.75 or above and `clang++`*.

```bash
# run interpreter (with JIT or not).
make && ./interpreter ./bfs/HELLO_WORLD.bf [--jit]
# run benchmark.
make benchmark suite=mandelbrot  
```

### Limitations of this program:

* No exception-handling support.
* No thread-safe guaranteed.
* No fine-tuning of the generated assembly code.
* Only implemented a simple `stdout` buffer.
* The amount of consecutive "+", "-", "<" and ">" showing up in the source code cannot exceed 255, for "]", cannot exceed 23.
* Only support X86-64 on macOS or Linux (need to compile with *-O0*, since the higher optimization flags may break the value passing of the `asm` block for unknown reasons).

### Benchmark Result

* [System] macOS 10.14.6
* [Compiler] Apple LLVM version 10.0.1 (clang-1001.0.46.4)
* [Optimization Level] -O2

#### IO Intensive Case

```text
Benchmark for 10 seconds: (higher score is better)
   12950 .out_interpreter
   35928 .out_jit (win)
```

#### Computing Intensive Case

```text
Benchmark Result: (lower time is better)
    13.018s interpreter
     0.885s jit (win)
```

### Sidenote

***The actual performance of the interpreter that compiled with a higher-level optimization flag (-O2 / -O3) may be higher than the performance of the JIT compiler in some specific situations***. 

Because we don't have too much fine-tuning on the machine code generated by the JIT compiler, for example, too much emitted `jmp` may suffer the program from branch prediction penalty, no execution flow analysis may cause the JIT compiler to emit more instructions than the program really needs, etc. But in the contrast, the advanced C/C++ compilers are really good at generating highly optimized machine code even the program may suffer from a small wrong branch prediction penalty. So, whether the performance of the JIT compiler would be better than the interpreter, it depends on the real cases.

But anyway, we (JIT) win the game in the two cases of the benchmark suite :)
