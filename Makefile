CXX = clang++
CXXFLAGS = -std=c++17 -O2
interpreter: interpreter.cc
clean:
	rm -f ./interpreter

benchmark:
	python3 ./benchmark.py
