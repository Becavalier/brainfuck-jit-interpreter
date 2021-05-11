#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdio>
#include <exception>
#include <sys/mman.h>
#include <unistd.h>
#include <cmath>

/**
 * This program can only be run on macOS 64bit.
 */

#define ENABLE_DEBUG

constexpr size_t TAPE_SIZE = 30000;
constexpr size_t MAX_NESTING = 100;

#ifdef ENABLE_DEBUG
template<typename T>
void debugVec(std::vector<T> *vp) {
  for (auto i = vp->begin(); i != vp->end(); ++i) {
    std::cout << std::hex << static_cast<size_t>(*i) << std::endl;
  }
}
void debugTape(char *arr, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    std::cout << arr[i];
  }
}
#endif

// allocate executable memory.
void setupExecutableMem(std::vector<uint8_t>* machineCode) {
  // get page size in bytes.
  auto pageSize = getpagesize();
  auto *mem = static_cast<uint8_t*>(mmap(
    NULL, 
    static_cast<size_t>(std::ceil(machineCode->size() / static_cast<double>(pageSize))), 
    PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 
    -1, 
    0));
  if (mem == MAP_FAILED) {
    std::cerr << "Can't allocate memory.\n"; 
    std::exit(1);
  }
  for (size_t i = 0; i < machineCode->size(); ++i) {
    mem[i] = machineCode->at(i);
  }

  // save the current %rip.
  asm(R"(
    lea 0x7(%%rip), %%rax
    pushq %%rax
    movq %0, %%rax
    jmpq *%%rax
  )":: "m" (mem));
}

// abstract machine model.
struct bfState {
  unsigned char tape[TAPE_SIZE] = {0};
  unsigned char* ptr = nullptr;
  bfState() {
    ptr = tape;
  }
};

void bfJITCompile(std::vector<char>* program, bfState* state) {
  std::vector<uint8_t> machineCode {};

  // code generation.
  for (auto i = program->begin(); i != program->end(); ++i) {
    auto ptrAddr = reinterpret_cast<size_t>(state->ptr);
    switch(*i) {
      case '+': {
        /**
         * movabs addr, %rax
         * addl $0x1, (%rax)
         * pop %rax
         * jmpq %rax  # return to normal execution.
         */
        uint8_t byteCodes[] = { 
          0x48, 
          0xb8, 
          static_cast<uint8_t>(ptrAddr & 0xff),
          static_cast<uint8_t>((ptrAddr & 0xff00) >> 8),
          static_cast<uint8_t>((ptrAddr & 0xff0000) >> 16),
          static_cast<uint8_t>((ptrAddr & 0xff000000) >> 24), 
          static_cast<uint8_t>((ptrAddr & 0xff00000000) >> 32),
          static_cast<uint8_t>((ptrAddr & 0xff0000000000) >> 40),
          static_cast<uint8_t>((ptrAddr & 0xff000000000000) >> 48),
          static_cast<uint8_t>((ptrAddr & 0xff00000000000000) >> 56), 
          0x80,
          0x0,
          0x1,
          0x58,
          0xff,
          0xe0,
        };
        machineCode.insert(
          machineCode.end(), 
          byteCodes, 
          byteCodes + sizeof(byteCodes));
      }
    }
  }

  // dynamic execution.
  setupExecutableMem(&machineCode);
}

void bfInterpret(const char* program, bfState* state) {
  const char* loops[MAX_NESTING];
  auto nloops = 0;
  auto nskip = 0;
  size_t n = 0;
  while(true) {
    // switch threading (inefficient).
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
#ifdef ENABLE_DEBUG
        // debugTape(state->tape, 100);
#endif
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
