#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdio>
#include <exception>
#include <sys/mman.h>
#include <unistd.h>
#include <cmath>

#define ENABLE_DEBUG

constexpr size_t TAPE_SIZE = 30000;
constexpr size_t MAX_NESTING = 100;

#ifdef ENABLE_DEBUG
template<typename T>
void debugVec(std::vector<T> &vp) {
  for (auto i = vp.cbegin(); i != vp.cend(); ++i) {
    std::cout << std::hex << static_cast<size_t>(*i) << std::endl;
  }
}
void debugTape(unsigned char *arr, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    std::cout << static_cast<int>(arr[i]);
  }
}
#endif

uint8_t* allocateExecMem(size_t size) {
  return static_cast<uint8_t*>(
    mmap(
      NULL,
      size, 
      PROT_READ | PROT_WRITE | PROT_EXEC, 
      MAP_PRIVATE | MAP_ANONYMOUS, 
      -1,
      0));
}

class VM {
  uint8_t *mem = nullptr;
  std::vector<uint8_t> *machineCode = nullptr;
  void* stdoutBuf = nullptr;
  size_t allocatedSize = 0;
  size_t prependStaticSize = 0;
 public:
  VM(std::vector<uint8_t> *machineCode, size_t prependStaticSize) : 
    machineCode(machineCode), prependStaticSize(prependStaticSize) {
    auto pageSize = getpagesize();
    allocatedSize = static_cast<size_t>(std::ceil(machineCode->size() / static_cast<double>(pageSize)) * pageSize);
    mem = allocateExecMem(allocatedSize);
    if (mem == MAP_FAILED) {
      throw std::runtime_error("[error] can't allocate memory.");
    }
    std::memcpy(mem, machineCode->data(), machineCode->size());
  
    // setup a range of memory holding stdout buffer.
    stdoutBuf = std::calloc(2048, sizeof(uint8_t));
  }
  void exec() {
    // save the current %rip on stack (by PC-relative).
    // %r10 - stdout buffer entry.
    // %r11 - stdout buffer counter.
    asm(R"(
      pushq %%rax
      pushq %%rbx
      pushq %%r10
      pushq %%r11
      pushq %%r12
      movq %1, %%r10
      xorq %%r11, %%r11
      lea 0xe(%%rip), %%rax 
      pushq %%rax
      movq %0, %%rax
      addq %2, %%rax
      jmpq *%%rax 
    )":: "m" (mem), "m" (stdoutBuf), "m" (prependStaticSize));

    // clean the stack.
    asm(R"(
      addq $8, %rsp
      popq %r12
      popq %r11
      popq %r10
      popq %rbx
      popq %rax
    )");
  }
  ~VM() {
    std::free(stdoutBuf);
    munmap(mem, allocatedSize);
  }
};

// abstract machine model.
struct bfState {
  unsigned char tape[TAPE_SIZE] = { 0 };
  unsigned char* ptr = nullptr;
  bfState() {
    ptr = tape;
  }
};

void bfJITCompile(std::vector<char>* program, bfState* state) {
  // helpers.
  auto _appendBytecode = [](auto& byteCode, auto& machineCode) {
    machineCode.insert(machineCode.end(), byteCode.begin(), byteCode.end());
  };

  auto _resolvePtrAddr = [](auto ptrAddr) -> auto {
    // little-endian.
    return std::vector<uint8_t> {
      static_cast<uint8_t>(ptrAddr & 0xff),
      static_cast<uint8_t>((ptrAddr & 0xff00) >> 8),
      static_cast<uint8_t>((ptrAddr & 0xff0000) >> 16),
      static_cast<uint8_t>((ptrAddr & 0xff000000) >> 24), 
      static_cast<uint8_t>((ptrAddr & 0xff00000000) >> 32),
      static_cast<uint8_t>((ptrAddr & 0xff0000000000) >> 40),
      static_cast<uint8_t>((ptrAddr & 0xff000000000000) >> 48),
      static_cast<uint8_t>((ptrAddr & 0xff00000000000000) >> 56), 
    };
  };

  auto _resolveAddrDiff = [](auto addrDiff) -> auto {
    // little-endian.
    return std::vector<uint8_t> {
      static_cast<uint8_t>(addrDiff & 0xff),
      static_cast<uint8_t>((addrDiff & 0xff00) >> 8),
      static_cast<uint8_t>((addrDiff & 0xff0000) >> 16),
      static_cast<uint8_t>((addrDiff & 0xff000000) >> 24),
    };
  };

  auto _relocateAddrOfPrintFunc = [&](
    auto &byteCode, 
    auto &machineCode, 
    size_t offsetBytesFromLast) {
    auto printCallOffset = _resolveAddrDiff(
      static_cast<uint32_t>(-(machineCode.size() + byteCode.size() - offsetBytesFromLast + 4)));
    byteCode.insert(byteCode.end() - offsetBytesFromLast, printCallOffset.begin(), printCallOffset.end());
  };

  // contain static routine definitions.
  const std::vector<uint8_t> staticFuncBody {
    // stdout function (current offset = 0).
    /**
      movl $0x2000004, %eax
      movl $0x1, %edi
      movq %r10, %rsi
      movq %r11, %rdx
      syscall
      retq
    */
#if __APPLE__
    0xb8, 0x4, 0x0, 0x0, 0x2,
#elif __linux__
    0xb8, 0x1, 0x0, 0x0, 0x0,
#endif
    0xbf, 0x1, 0x0, 0x0, 0x0,
    0x4c, 0x89, 0xd6,
    0x4c, 0x89, 0xda,
    0xf, 0x5,
    0xc3,
  };

  // prologue.
  std::vector<uint8_t> machineCode {
    // save dynamic pointer in %rbx.
    0x48, 0xbb, /* mem slot */
  };
  std::vector<size_t> jmpLocIndex {};

  // resolve base pointer, relocate and prepend static function body.
  auto basePtrBytes = _resolvePtrAddr(reinterpret_cast<size_t>(state->ptr));
  machineCode.insert(machineCode.end(), basePtrBytes.begin(), basePtrBytes.end());
  machineCode.insert(machineCode.begin(), staticFuncBody.begin(), staticFuncBody.end());
  
  // codegen.
  for (auto tok = program->cbegin(); tok != program->cend(); ++tok) {
    size_t n = 0;
    auto ptrAddr = reinterpret_cast<size_t>(state->ptr);

    switch(*tok) {
      case '+': {
        for (n = 0; *tok == '+'; ++n, ++tok);
        const auto ptrBytes = _resolvePtrAddr(ptrAddr);
        std::vector<uint8_t> byteCode { 
          0x80, 0x3, static_cast<uint8_t>(n),  // addb $0x1, (%rbx)
        };
        _appendBytecode(byteCode, machineCode);
        --tok;
        break;
      } 
      case '-': {
        for (n = 0; *tok == '-'; ++n, ++tok);
        const auto ptrBytes = _resolvePtrAddr(ptrAddr);
        std::vector<uint8_t> byteCode { 
          0x80, 0x2b, static_cast<uint8_t>(n),  // subb $0x1, (%rbx)
        };
        _appendBytecode(byteCode, machineCode);
        --tok;
        break;
      }
      case '>': {
        for (n = 0; *tok == '>'; ++n, ++tok);
        std::vector<uint8_t> byteCode { 
          0x48, 0x83, 0xc3, static_cast<uint8_t>(n),  // add $0x1, %rbx
        };
        _appendBytecode(byteCode, machineCode);
        --tok;  // counteract the tok++ in the main loop.
        break;
      }
      case '<': {
        for (n = 0; *tok == '<'; ++n, ++tok);
        std::vector<uint8_t> byteCode { 
          0x48, 0x83, 0xeb, static_cast<uint8_t>(n),  // sub $0x1, %rbx
        };
        _appendBytecode(byteCode, machineCode);
        --tok;  // counteract the tok++ in the main loop.
        break;
      }
      case ',': {
        /**
          movl $0x2000003, %eax
          movl $0x0, %edi
          movq %rbx, %rsi
          movl $0x1, %edx
          syscall
        */
        std::vector<uint8_t> byteCode { 
#if __APPLE__
          0xb8, 0x3, 0x0, 0x0, 0x2,
#elif __linux__
          0xb8, 0x0, 0x0, 0x0, 0x0,
#endif
          0xbf, 0x0, 0x0, 0x0, 0x0,
          0x48, 0x89, 0xde,
          0xba, 0x1, 0x0, 0x0, 0x0,
          0xf, 0x5,
        };
        _appendBytecode(byteCode, machineCode);
        break;
      }
      case '.': {
        /**
          movq (%rbx), %r12
          movq %r12, (%r10,%r11)
          incq %r11
          cmpq $1024, %r11
          jne 8
          callq <print>
          xorq %r11, %r11
        */
        std::vector<uint8_t> byteCode { 
          // setup a simple buffer for stdout.
          0x4c, 0x8b, 0x23,
          0x4f, 0x89, 0x24, 0x1a,
          0x49, 0xff, 0xc3,
          0x49, 0x81, 0xfb, 0x0, 0x4, 0x0, 0x0,
          0x75, 0x8,
          // flush.
          0xe8, /* mem slot */
          // reset counter.
          0x4d, 0x31, 0xdb,
        };
        _relocateAddrOfPrintFunc(byteCode, machineCode, 3);
        _appendBytecode(byteCode, machineCode);
        break;
      }
      case '[': {
        /*
          cmpb $0x0, (%rbx)
          je <>
        */
        std::vector<uint8_t> byteCode { 
          0x80, 0x3b, 0x0,
          0xf, 0x84, 0x0, 0x0, 0x0, 0x0, /* near jmp */
        };
        // record the jump relocation pos.
        _appendBytecode(byteCode, machineCode);
        jmpLocIndex.push_back(machineCode.size());
        break;
      }
      case ']': {
        /*
          cmpb $0x0, (%rbx)
          jne <>
        */
        std::vector<uint8_t> byteCode { 
          0x80, 0x3b, 0x0,
          0xf, 0x85, 0x0, 0x0, 0x0, 0x0, /* near jmp */
        };
        _appendBytecode(byteCode, machineCode);

        // calculate real offset.
        auto bDiff = _resolveAddrDiff(static_cast<uint32_t>(jmpLocIndex.back() - machineCode.size()));
        auto fDiff = _resolveAddrDiff(static_cast<uint32_t>(machineCode.size() - jmpLocIndex.back()));

        // relocate the memory address of the generated machine code.
        machineCode.erase(machineCode.end() - 4, machineCode.end());
        machineCode.insert(machineCode.end(), bDiff.begin(), bDiff.end());
        
        // relocate the corresponding previous "[".
        machineCode.erase(machineCode.begin() + jmpLocIndex.back() - 4, machineCode.begin() + jmpLocIndex.back());
        machineCode.insert(machineCode.begin() + jmpLocIndex.back() - 4, fDiff.begin(), fDiff.end());
        jmpLocIndex.pop_back();

        // reduce unnecessary `cmp`s, dedicated for patterns like "]]]]]...".
        auto ctok = tok + 1;
        for (n = 0; *ctok == ']'; ++n, ++ctok);
        if (n > 0) {
          std::vector<uint8_t> byteCode {
            0xeb, static_cast<uint8_t>(n * 11 - 2),
          };
          _appendBytecode(byteCode, machineCode);
        }
        break;
      }
    }
  }

  // epilogue. 
  // mainly restoring the previous pc, flushing the stdout buffer.
  /**
    cmpq $0, %r11
    je 8
    callq <print>
    jmpq *(%rsp)
   */
  std::vector<uint8_t> byteCode {
    0x49, 0x83, 0xfb, 0x0,
    0x74, 0x8,
    0xe8, /* mem slot */
    0xff, 0x24, 0x24,
  };
  _relocateAddrOfPrintFunc(byteCode, machineCode, 3);
  _appendBytecode(byteCode, machineCode);

  // dynamic execution.
  VM(&machineCode, staticFuncBody.size()).exec();
}

void bfInterpret(const char* program, bfState* state) {
  const char* loops[MAX_NESTING];
  auto nloops = 0;
  auto nskip = 0;
  size_t n = 0;
  
  while(true) {
    // switch threading.
    switch(*program++) {
      case '<': {
        for (n = 1; *program == '<'; ++n, ++program);
        if (!nskip) state->ptr -= n;
        break;
      }
      case '>': {
        for (n = 1; *program == '>'; ++n, ++program);
        if (!nskip) state->ptr += n;
        break; 
      }
      case '+': {
        for (n = 1; *program == '+'; ++n, ++program);
        if (!nskip) *state->ptr += n;
        break;
      }
      case '-': {
        for (n = 1; *program == '-'; ++n, ++program);
        if (!nskip) *state->ptr -= n;
        break;
      }
      case ',': {
        if (!nskip) *state->ptr = static_cast<unsigned char>(std::getchar());
        break;
      }
      case '.': {
        if (!nskip) 
          std::cout << *state->ptr;
        break;
      }
      case '[': {
        if (nloops == MAX_NESTING) std::terminate();
        loops[nloops++] = program; 
        if (!*state->ptr) ++nskip;
        break;
      }
      case ']': {
        if (nloops == 0) std::terminate();
        if (*state->ptr) program = loops[nloops - 1];
        else --nloops;
        if (nskip) --nskip;
        break;
      }
      case ' ': {
        for (n = 1; *program == ' '; ++n, ++program);  // clear spaces.
        break;
      }
      case '\0': {
        return;
      }
    }
  }
}

inline void bfRunDefault(const char* sourceCode) {
  bfState bfs;
  bfInterpret(sourceCode, &bfs);
}

inline void bfRunJIT(std::vector<char>* sourceCode) {
  bfState bfs;
  bfJITCompile(sourceCode, &bfs);
}

int main(int argc, char** argv) {
  char token;
  std::vector<char> v {};
  if (argc > 1) {
    std::string inputSourceFileName = std::string(*(argv + 1));
    std::ifstream f(inputSourceFileName, std::ios::binary);
    while (f.is_open() && f.good() && f >> token) {
      v.push_back(token);
    }
  }
  if (v.size() > 0) {
    if (argc > 2 && std::string(*(argv + 2)) == "--jit") {
      bfRunJIT(&v);
    } else {
      bfRunDefault(v.data());
    }
  }
  return 0;
}
