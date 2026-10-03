#!/usr/bin/env python3
"""Measure exact apport top-level imports without executing its startup code."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


CHILD = r'''
import os
import resource
import sys
import time

sys.dont_write_bytecode = True
sys.path[0] = os.path.dirname(SCRIPT_PATH)
blocked = []
def audit(event, args):
    deny = False
    if event == "open":
        mode, flags = args[1], args[2]
        deny = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int) and bool(flags & (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
    elif event in {
        "os.remove", "os.unlink", "os.rename", "os.rmdir", "os.mkdir",
        "os.chmod", "os.chown", "os.truncate", "os.utime", "os.link",
        "os.symlink", "os.system", "os.exec", "os.fork", "os.forkpty",
        "os.posix_spawn", "subprocess.Popen", "socket.connect", "socket.bind",
        "socket.sendto", "fcntl.fcntl", "fcntl.ioctl", "fcntl.flock",
        "fcntl.lockf", "os.kill", "os.killpg"
    }:
        deny = True
    if deny:
        blocked.append({"event": event, "args": repr(args)[:300]})
        raise PermissionError("Import probe rejected side effect: " + event)

sys.addaudithook(audit)
before_modules = sorted(sys.modules)
scope = {"__name__": "apport_import_probe", "__file__": SCRIPT_PATH}
samples = []
start_wall = time.monotonic_ns()
start_cpu = time.process_time_ns()
start_usage = resource.getrusage(resource.RUSAGE_SELF)
error = None
for statement in IMPORTS:
    wall = time.monotonic_ns()
    cpu = time.process_time_ns()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    try:
        exec(compile(statement, SCRIPT_PATH + ":imports-only", "exec"), scope)
    except BaseException as exc:
        error = {"type": type(exc).__name__, "message": str(exc)}
    end_usage = resource.getrusage(resource.RUSAGE_SELF)
    samples.append({"statement": statement,
        "wall_ns": time.monotonic_ns() - wall,
        "cpu_ns": time.process_time_ns() - cpu,
        "user_ns": round((end_usage.ru_utime - usage.ru_utime) * 1e9),
        "system_ns": round((end_usage.ru_stime - usage.ru_stime) * 1e9)})
    if error:
        break
end_wall = time.monotonic_ns()
end_cpu = time.process_time_ns()
end_usage = resource.getrusage(resource.RUSAGE_SELF)
result = {"status": "failed" if error or blocked else "ok",
    "error": error, "blocked_side_effects": blocked,
    "total_wall_ns": end_wall - start_wall,
    "total_cpu_ns": end_cpu - start_cpu,
    "total_user_ns": round((end_usage.ru_utime - start_usage.ru_utime) * 1e9),
    "total_system_ns": round((end_usage.ru_stime - start_usage.ru_stime) * 1e9),
    "preloaded_modules": before_modules, "imports": samples,
    "python_version": sys.version}
# Serialization imports occur after all measured intervals.
import json
print(json.dumps(result), flush=True)
sys.exit(0 if result["status"] == "ok" else 1)
'''


def is_main_guard(node):
    return (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == '__name__'
            and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.Eq)
            and len(node.test.comparators) == 1
            and isinstance(node.test.comparators[0], ast.Constant)
            and node.test.comparators[0].value == '__main__')


def inspect_source(source):
    tree = ast.parse(source)
    imports = [ast.get_source_segment(source, node)
               for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    guards = [node.lineno for node in tree.body if is_main_guard(node)]
    other = [{"line": node.lineno, "type": type(node).__name__}
             for node in tree.body
             if not isinstance(node, (ast.Import, ast.ImportFrom,
                                      ast.FunctionDef, ast.AsyncFunctionDef,
                                      ast.ClassDef))]
    if not imports:
        raise ValueError('No top-level imports found')
    return imports, guards, other


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script', type=Path, default=Path('/usr/share/apport/apport'))
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--timing-only', action='store_true',
                        help='Omit Python -X importtime instrumentation')
    parser.add_argument('--inspect-only', action='store_true',
                        help='Report AST selection without importing anything')
    args = parser.parse_args()
    if not 1 <= args.timeout <= 120:
        parser.error('--timeout must be between 1 and 120 seconds')
    path = args.script.resolve()
    raw = path.read_bytes()
    imports, guards, other = inspect_source(raw.decode('utf-8'))
    result = {"script": str(path), "script_sha256": hashlib.sha256(raw).hexdigest(),
              "selected_imports": imports, "main_guard_lines": guards,
              "excluded_top_level_statements": other,
              "execution": "Only AST-selected import statements; no runpy/main/--start",
              "importtime_enabled": not args.timing_only}
    if args.inspect_only:
        result['status'] = 'inspected'
        print(json.dumps(result, indent=2))
        return 0
    code = 'SCRIPT_PATH = ' + repr(str(path)) + '\nIMPORTS = ' + repr(imports) + '\n' + CHILD
    command = [sys.executable, '-B', '-s']
    if not args.timing_only:
        command += ['-X', 'importtime']
    command += ['-c', code]
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONSTARTUP', None)
    start = time.monotonic_ns()
    try:
        process = subprocess.run(command, env=env, cwd='/',
                                 capture_output=True, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired as exc:
        result.update(status='timeout', timeout_seconds=args.timeout,
                      child_stdout=str(exc.stdout or ''),
                      importtime_stderr=str(exc.stderr or ''))
        print(json.dumps(result, indent=2))
        return 124
    result['child_process_wall_ns'] = time.monotonic_ns() - start
    result['returncode'] = process.returncode
    result['importtime_stderr'] = process.stderr
    try:
        result['measurement'] = json.loads(process.stdout)
    except json.JSONDecodeError:
        result['child_stdout'] = process.stdout
    result['status'] = 'ok' if process.returncode == 0 and 'measurement' in result else 'failed'
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'ok' else 1


if __name__ == '__main__':
    raise SystemExit(main())
