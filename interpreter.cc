#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <exception>
#include <sys/mman.h>
#include <unistd.h>
#include <cmath>

#define ENABLE_DEBUG

#define CALLQ 0xe8
#define SYSCALL 0xf, 0x5
#define RETQ 0xc3
#define MOV_EAX 0xb8
#define MOV_EDX 0xba
#define MOV_EDI 0xbf
/* REX: 0x48, Op: 0xbb */
#define MOV_RBX 0x48, 0xbb
#define JE_SHORT 0x74
#define JE_NEAR 0xf, 0x84
#define JNE_NEAR 0xf, 0x85
#define JNE 0x75
/* Op: 0x80, ModR/M: 0x2b (MODRM.reg = 5) */
#define SUBB_RBX 0x80, 0x2b
/* Op: 0x80, ModR/M: 0x3 */
#define ADDB_RBX 0x80, 0x3
/* Op: 0xff, ModR/M: 0x24, SIB: 0x24 */
#define JMPQ_RSP 0xff, 0x24, 0x24
#define CMPB_RBX 0x80, 0x3b
#define REX_SUB_RBX 0x48, 0x83, 0xeb
#define REX_ADD_RBX 0x48, 0x83, 0xc3
#define REX_MOV_R10_RSI 0x4c, 0x89, 0xd6
#define REX_MOV_R11_RDX 0x4c, 0x89, 0xda
#define REX_MOV_RBX_RSI 0x48, 0x89, 0xde
#define REX_CMPD_R11 0x49, 0x83, 0xfb
#define REX_MOVQ_RBX_R12 0x4c, 0x8b, 0x23
#define REX_MOVQ_R12_R10_R11 0x4f, 0x89, 0x24, 0x1a
#define REX_INCQ_R11 0x49, 0xff, 0xc3
#define REX_CMPQ_R11 0x49, 0x81, 0xfb
#define REX_XORQ_R11_R11 0x4d, 0x31, 0xdb

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
      lea 0x9(%%rip), %%rax 
      pushq %%rax
      movq %0, %%rax
      addq %2, %%rax
      jmpq *%%rax 
    )":: "S" (mem), "m" (stdoutBuf), "D" (prependStaticSize));

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
struct BFState {
  unsigned char tape[TAPE_SIZE] = { 0 };
  unsigned char* ptr = nullptr;
  BFState() {
    ptr = tape;
  }
};

void bfJITCompile(std::vector<char>* program, BFState* state) {
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

  // static routine definitions.
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
    MOV_EAX, 0x4, 0x0, 0x0, 0x2,
#elif __linux__
    MOV_EAX, 0x1, 0x0, 0x0, 0x0,
#endif
    MOV_EDI, 0x1, 0x0, 0x0, 0x0,
    REX_MOV_R10_RSI,
    REX_MOV_R11_RDX,
    SYSCALL,
    RETQ,
  };

  // prologue.
  std::vector<uint8_t> machineCode {
    // save dynamic pointer in %rbx.
    MOV_RBX, /* mem slot */
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
        std::vector<uint8_t> byteCode { 
          ADDB_RBX, static_cast<uint8_t>(n),  // addb $0x1, (%rbx)
        };
        _appendBytecode(byteCode, machineCode);
        --tok;
        break;
      } 
      case '-': {
        for (n = 0; *tok == '-'; ++n, ++tok);
        std::vector<uint8_t> byteCode { 
          SUBB_RBX, static_cast<uint8_t>(n),  // subb $0x1, (%rbx)
        };
        _appendBytecode(byteCode, machineCode);
        --tok;
        break;
      }
      case '>': {
        for (n = 0; *tok == '>'; ++n, ++tok);
        std::vector<uint8_t> byteCode { 
          REX_ADD_RBX, static_cast<uint8_t>(n),  // add $0x1, %rbx
        };
        _appendBytecode(byteCode, machineCode);
        --tok;  // counteract the tok++ in the main loop.
        break;
      }
      case '<': {
        for (n = 0; *tok == '<'; ++n, ++tok);
        std::vector<uint8_t> byteCode { 
          REX_SUB_RBX, static_cast<uint8_t>(n),  // sub $0x1, %rbx
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
          MOV_EAX, 0x3, 0x0, 0x0, 0x2,
#elif __linux__
          MOV_EAX, 0x0, 0x0, 0x0, 0x0,
#endif
          MOV_EDI, 0x0, 0x0, 0x0, 0x0,
          REX_MOV_RBX_RSI,
          MOV_EDX, 0x1, 0x0, 0x0, 0x0,
          SYSCALL,
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
          REX_MOVQ_RBX_R12,
          REX_MOVQ_R12_R10_R11,
          REX_INCQ_R11,
          REX_CMPQ_R11, 0x0, 0x4, 0x0, 0x0,
          JNE, 0x8,
          // flush.
          CALLQ, /* mem slot */
          // reset counter.
          REX_XORQ_R11_R11,
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
          CMPB_RBX, 0x0,
          JE_NEAR, 0x0, 0x0, 0x0, 0x0, /* near jmp */
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
          CMPB_RBX, 0x0,
          JNE_NEAR, 0x0, 0x0, 0x0, 0x0, /* near jmp */
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
    REX_CMPD_R11, 0x0,
    JE_SHORT, 0x8,
    CALLQ, /* mem slot */
    JMPQ_RSP,
  };
  _relocateAddrOfPrintFunc(byteCode, machineCode, 3);
  _appendBytecode(byteCode, machineCode);

  // dynamic execution.
  VM(&machineCode, staticFuncBody.size()).exec();
}

void bfInterpret(const char* program, BFState* state) {
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

inline void bfRunInterpret(const char* sourceCode) {
  BFState bfs;
  bfInterpret(sourceCode, &bfs);
}

inline void bfRunJIT(std::vector<char>* sourceCode) {
  BFState bfs;
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
      bfRunInterpret(v.data());
    }
  }
  return 0;
}
