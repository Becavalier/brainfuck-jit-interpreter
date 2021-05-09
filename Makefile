CXX = clang++
CXXFLAGS = -std=c++17
interpreter: interpreter.cc
clean:
	rm -f ./interpreter
