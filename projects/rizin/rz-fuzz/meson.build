if get_option('fuzz_mode') == 'afl'
  executable('rz-fuzz', ['rz-fuzz-afl.c', 'rz-fuzz-libfuzzer.c'],
    include_directories: [platform_inc],
    dependencies: [
      rz_util_dep,
      rz_main_dep,
      rz_socket_dep,
      rz_cons_dep
    ],
    install: true,
    install_rpath: rpath_exe,
    implicit_include_directories: false
  )
elif get_option('fuzz_mode') == 'libfuzzer'
  executable('rz-fuzz', 'rz-fuzz-libfuzzer.c',
    include_directories: [platform_inc],
    dependencies: [
      rz_util_dep,
      rz_main_dep,
      rz_socket_dep,
      rz_cons_dep
    ],
    install: true,
    install_rpath: rpath_exe,
    implicit_include_directories: false,
    cpp_args: '-fsanitize=fuzzer',
    c_args: '-fsanitize=fuzzer',
    link_args: '-fsanitize=fuzzer',
  )
elif get_option('fuzz_mode') == 'sydr'
  executable('rz-fuzz', ['main-impl.c', 'rz-fuzz-libfuzzer.c'],
    include_directories: [platform_inc],
    dependencies: [
      rz_util_dep,
      rz_main_dep,
      rz_socket_dep,
      rz_cons_dep
    ],
    install: true,
    install_rpath: rpath_exe,
    implicit_include_directories: false,
  )
endif
