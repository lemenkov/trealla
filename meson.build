project('trealla', 'c',
  version: run_command('git', 'describe', '--abbrev=4', '--dirty', '--always', '--tags', check: false).stdout().strip(),
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'optimization=3',
  ],
  license: 'MIT',
  meson_version: '>= 1.1.0',
)

cc = meson.get_compiler('c')

# Feature options
opt_ffi = get_option('ffi')
opt_ssl = get_option('ssl')
opt_threads = get_option('threads')
opt_readline = get_option('readline')

# Version and library path - passed directly as the original Makefile does
lib_path = get_option('prefix') / get_option('datadir') / 'trealla' / 'library'

add_project_arguments(
  '-D_GNU_SOURCE',
  '-DVERSION="@0@"'.format(meson.project_version()),
  '-DDEFAULT_LIBRARY_PATH="@0@"'.format(lib_path),
  language: 'c',
)

# Compiler-specific warning flags
warning_flags = [
  '-Wno-unused-but-set-variable',
  '-Wno-unused-parameter',
  '-Wno-unused-variable',
]
foreach flag : warning_flags
  if cc.has_argument(flag)
    add_project_arguments(flag, language: 'c')
  endif
endforeach

# Dependencies
deps = []
deps += cc.find_library('m', required: true)

# Readline / Editline / Isocline
# Windows doesn't support readline, always use bundled isocline
use_isocline = false
if host_machine.system() == 'windows'
  use_isocline = true
elif opt_readline.disabled()
  use_isocline = true
else
  readline_dep = dependency('readline', required: false)
  if readline_dep.found()
    deps += readline_dep
  else
    # Try editline as fallback
    editline_dep = dependency('libedit', required: false)
    if editline_dep.found()
      deps += editline_dep
      add_project_arguments('-DUSE_EDITLINE=1', language: 'c')
    else
      use_isocline = true
    endif
  endif
endif

if use_isocline
  add_project_arguments('-DUSE_ISOCLINE=1', language: 'c')
endif

# FFI
if not opt_ffi.disabled()
  ffi_dep = dependency('libffi', required: opt_ffi)
  if ffi_dep.found()
    deps += ffi_dep
    deps += cc.find_library('dl', required: false)
    add_project_arguments('-DUSE_FFI=1', language: 'c')
  endif
endif

# OpenSSL
if not opt_ssl.disabled()
  ssl_dep = dependency('openssl', required: opt_ssl)
  if ssl_dep.found()
    deps += ssl_dep
    add_project_arguments('-DUSE_OPENSSL=1', language: 'c')
  endif
endif

# Threads
if not opt_threads.disabled()
  thread_dep = dependency('threads', required: opt_threads)
  if thread_dep.found()
    deps += thread_dep
    add_project_arguments('-DUSE_THREADS=1', language: 'c')
    # GCC needs -latomic for some atomic operations
    if cc.get_id() == 'gcc'
      atomic_dep = cc.find_library('atomic', required: false)
      if atomic_dep.found()
        deps += atomic_dep
      endif
    endif
  endif
endif

# Library files to embed
library_pl_files = [
  'abnf',
  'aggregate',
  'arithmetic',
  'assoc',
  'atts',
  'builtins',
  'charsio',
  'concurrent',
  'clpz',
  'curl',
  'dcgs',
  'debug',
  'dif',
  'error',
  'format',
  'freeze',
  'gensym',
  'gsl',
  'heaps',
  'http',
  'iso_ext',
  'json',
  'lambda',
  'linda',
  'lists',
  'ordsets',
  'pairs',
  'pio',
  'random',
  'raylib',
  'rbtrees',
  'reif',
  'si',
  'sqlite3',
  'time',
  'ugraphs',
  'uuid',
  'when',
]

# Generate C files from Prolog library files
# Creates symbols like library_abnf_pl and library_abnf_pl_len as expected by src/library.c
library_c_files = []
python = find_program('python3', 'python')
gen_lib_script = '''
import sys
name = "library_" + sys.argv[2] + "_pl"
data = open(sys.argv[1], "rb").read()
print("#include <stddef.h>")
out = "unsigned char " + name + "[] = {"
for i, b in enumerate(data):
    if i % 12 == 0:
        out += chr(10) + "  "
    out += "0x{:02x}".format(b)
    if i < len(data) - 1:
        out += ","
out += chr(10) + "};"
print(out)
print("unsigned int " + name + "_len = " + str(len(data)) + ";")
'''
foreach lib : library_pl_files
  library_c_files += custom_target('library_' + lib,
    input: 'library' / lib + '.pl',
    output: lib + '.c',
    command: [python, '-c', gen_lib_script, '@INPUT@', lib],
    capture: true,
  )
endforeach

# Main source files
src_files = [
  'tpl.c',
  'src/base64.c',
  'src/bif_atts.c',
  'src/bif_bboard.c',
  'src/bif_control.c',
  'src/bif_csv.c',
  'src/bif_database.c',
  'src/bif_ffi.c',
  'src/bif_format.c',
  'src/bif_functions.c',
  'src/bif_maps.c',
  'src/bif_os.c',
  'src/bif_posix.c',
  'src/bif_predicates.c',
  'src/bif_sort.c',
  'src/bif_sregex.c',
  'src/bif_streams.c',
  'src/bif_tasks.c',
  'src/bif_threads.c',
  'src/compile.c',
  'src/heap.c',
  'src/history.c',
  'src/library.c',
  'src/list.c',
  'src/module.c',
  'src/network.c',
  'src/parser.c',
  'src/print.c',
  'src/prolog.c',
  'src/query.c',
  'src/skiplist.c',
  'src/terms.c',
  'src/toplevel.c',
  'src/unify.c',
  'src/utf8.c',
  'src/version.c',
  # Bundled imath
  'src/imath/imath.c',
  'src/imath/imrat.c',
  # Bundled sre
  'src/sre/re.c',
]

# Isocline sources (conditional)
if use_isocline
  src_files += 'src/isocline/src/isocline.c'
endif

# Build the main executable
tpl = executable('tpl',
  src_files,
  library_c_files,
  include_directories: include_directories('src'),
  dependencies: deps,
  install: true,
)

# Install library files
install_subdir('library',
  install_dir: get_option('datadir') / 'trealla',
  strip_directory: false,
)

# Install man page
install_man('man/trealla.1')

# Tests
test_runner = find_program('tests/run.sh', required: false)
if test_runner.found()
  test('trealla-tests', test_runner,
    workdir: meson.project_source_root(),
    depends: tpl,
  )
endif
