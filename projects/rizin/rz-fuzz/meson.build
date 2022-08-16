# Copyright 2022 ISP RAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

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
