#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdio>
#include <exception>

#define ENABLE_DEBUG

constexpr size_t TAPE_SIZE = 30000;
constexpr size_t MAX_NESTING = 100;

#ifdef ENABLE_DEBUG
void debugVec(std::vector<char> *vp) {
  for (auto i = vp->begin(); i != vp->end(); ++i) {
    std::cout << *i << std::endl;
  }
}
void debugTape(char *arr, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    std::cout << arr[i];
    std::cout << 11;
  }
}
#endif

// abstract machine model.
struct bfState {
  unsigned char tape[TAPE_SIZE] = {0};
  unsigned char* ptr = nullptr;
  bfState() {
    ptr = tape;
  }
};

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
        if (!nskip) std::cout << *state->ptr;
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

inline void bfRun(const char* sourceCode) {
  // init context.
  bfState bfs;
  bfInterpret(sourceCode, &bfs);
}

int main(int argc, char** argv) {
  char token;
  std::vector<char> v {};
  if (argc > 1) {
    std::string inputSourceFileName = std::string(*(argv + 1));
    std::ifstream f(inputSourceFileName, std::ios::binary);
    while (f.good() && f >> token) {
      v.push_back(token);
    }
    // run the program.
    bfRun(v.data());
  }
  return 0;
}


