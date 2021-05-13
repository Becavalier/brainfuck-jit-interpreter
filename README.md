# brainfuck-jit-interpreter
A handwritten Brainfuck JIT interpreter, mainly used for demonstration purpose.

## How to use?

```
make && ./interpreter ./bfs/SIM.bf [--jit]
```

## Limitations of this program:

* No exception-handling support；
* No thread-safe guaranteed;
* The amount of consecutive "+", "-", "<" and ">" showing up in the source code cannot exceed 255;
* Only support macOS 64bit.
