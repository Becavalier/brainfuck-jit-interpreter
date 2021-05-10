import logging
import shlex
import subprocess
import sys
import threading
import os

default_benchmark_time = 5

def exec_cmd(command, file_name, timeout=default_benchmark_time):
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
  print('Benchmark for %s seconds: (higher score is better)' % default_benchmark_time)
  exec_cmd('./interpreter ./FIB.bf', '.out_interpret')
  exec_cmd('./interpreter ./FIB.bf', '.out_jit')

  # comparision.
  completedprocess = subprocess.run('wc -l .out_interpret .out_jit', shell=True, capture_output=True)
  print(str(completedprocess.stdout, 'utf-8'))
  os.remove('.out_interpret')
  os.remove('.out_jit')
  sys.exit(0)
