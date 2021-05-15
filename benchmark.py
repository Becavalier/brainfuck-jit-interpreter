import logging
import shlex
import subprocess
import sys
import threading
import os
import time

default_benchmark_time = 10
constant_idx_zer = 0
constant_idx_one = 1

def exec_cmd(command, file_name, timeout):
  try:
    with open(file_name, 'w+') as f:
      cmd = subprocess.Popen(shlex.split(command),
                          shell=False,
                          stdout=f,
                          stderr=subprocess.PIPE,
                          universal_newlines=True)
      _thread_command(cmd, timeout)
  except subprocess.SubprocessError as err:
    print('Calledprocerr: %s', err)

def _thread_command(task, timeout):
  task_thread = threading.Thread(target=task.wait)
  task_thread.start()
  task_thread.join(timeout)
  if task_thread.is_alive():
    task.kill()

if __name__ == '__main__':
  if len(sys.argv) == 1:
    # run default benchmark.
    print('\nBenchmark for %s seconds: (higher score is better)' % default_benchmark_time)
    exec_cmd('./interpreter ./bfs/FIB.bf', '.out_interpreter', default_benchmark_time)
    exec_cmd('./interpreter ./bfs/FIB.bf --jit', '.out_jit', default_benchmark_time)

    # comparision.
    completedprocess = subprocess.run('wc -l .out_interpreter .out_jit', shell=True, capture_output=True)
    print(str(completedprocess.stdout, 'utf-8'))
    os.remove('.out_interpreter')
    os.remove('.out_jit')
    sys.exit(0)
  else:
    # run optional benchmark.
    if sys.argv[constant_idx_one] == "mandelbrot":
      time_dict = []
      def _exec_case(command):
        print('\nCommand ' + command + ': \n')
        start_time = time.time()
        subprocess.call(shlex.split(command))
        time_dict.append(time.time() - start_time)
      _exec_case('./interpreter ./bfs/MANDELBROT.bf')
      _exec_case('./interpreter ./bfs/MANDELBROT.bf --jit')
      print('\nBenchmark Result: (lower time is better)\n' + 
        "{:>10.3f}".format(time_dict[constant_idx_zer]) + 's interpreter\n' +
        "{:>10.3f}".format(time_dict[constant_idx_one]) + 's jit\n')
