cmake_minimum_required(VERSION 3.18)
project(pytorch)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PYBIND11_FINDPYTHON ON)
find_package(Torch REQUIRED)
find_package(Python3 ${PYTHON_VERSION} EXACT COMPONENTS Development)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${TORCHCODEC_WERROR_OPTION} ${TORCH_CXX_FLAGS}")

set(FUZZ_TARGETS
  message_deserialize
  jit_differential
  class_parser
  load
  irparser
  mobile
  dump
)

set(USE_TENSORPIPE ON BOOL)

foreach(FUZZ_TARGET IN LISTS FUZZ_TARGETS)
  add_executable(${FUZZ_TARGET}_${SUFFIX} ${CMAKE_SOURCE_DIR}/${FUZZ_TARGET}.cc)
  target_include_directories(${FUZZ_TARGET}_${SUFFIX} PUBLIC 
    ${TORCH_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR} 
    /pytorch/torch/csrc/distributed/rpc
  )
  target_compile_definitions(${FUZZ_TARGET}_${SUFFIX} PUBLIC USE_TENSORPIPE)
  target_link_libraries(${FUZZ_TARGET}_${SUFFIX} 
    PUBLIC ${TORCH_LIBRARIES}
    PUBLIC /pytorch/build/lib/libonnx.a
    PUBLIC /pytorch/build/lib/libonnx_proto.a 
    PUBLIC /pytorch/build/lib/libtensorpipe.a
    PUBLIC /usr/lib/x86_64-linux-gnu/libuv.so.1.0.0
    PUBLIC ${CMAKE_DL_LIBS} 
    PUBLIC pthread 
    PUBLIC rt 
    PUBLIC ${ENGINE}
    PUBLIC lzma
  )
  set_target_properties(${FUZZ_TARGET}_${SUFFIX} PROPERTIES BUILD_WITH_INSTALL_RPATH ON)
  install(TARGETS ${FUZZ_TARGET}_${SUFFIX} DESTINATION /)
endforeach()


if (BUILD_RPC_REPRODUCER)

  add_executable(rpc_reproducer_nosan ${CMAKE_SOURCE_DIR}/rpc_reproducer.cc)
  target_include_directories(rpc_reproducer_nosan PUBLIC 
    ${TORCH_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR} 
    /pytorch/torch/csrc/distributed/rpc
  )
  target_compile_definitions(rpc_reproducer_nosan PUBLIC USE_TENSORPIPE)
  target_link_libraries(rpc_reproducer_nosan 
    PUBLIC ${TORCH_LIBRARIES}
    PUBLIC /pytorch/build/lib/libonnx.a
    PUBLIC /pytorch/build/lib/libonnx_proto.a 
    PUBLIC /pytorch/build/lib/libtensorpipe.a
    PUBLIC /usr/lib/x86_64-linux-gnu/libuv.so.1.0.0
    PUBLIC ${CMAKE_DL_LIBS} 
    PUBLIC pthread 
    PUBLIC rt 
    PUBLIC lzma
  )
  set_target_properties(rpc_reproducer_nosan PROPERTIES BUILD_WITH_INSTALL_RPATH ON)
  install(TARGETS rpc_reproducer_nosan DESTINATION /)

  add_executable(rpc_reproducer_asan ${CMAKE_SOURCE_DIR}/rpc_reproducer.cc)
  target_include_directories(rpc_reproducer_asan PUBLIC 
    ${TORCH_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR} 
    /pytorch/torch/csrc/distributed/rpc
  )
  target_compile_definitions(rpc_reproducer_asan PUBLIC USE_TENSORPIPE)
  target_compile_options(rpc_reproducer_asan PUBLIC
    -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero
  )
  target_link_options(rpc_reproducer_asan PUBLIC
    -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero
  )
  
  target_link_libraries(rpc_reproducer_asan 
    PUBLIC ${TORCH_LIBRARIES}
    PUBLIC /pytorch/build/lib/libonnx.a
    PUBLIC /pytorch/build/lib/libonnx_proto.a 
    PUBLIC /pytorch/build/lib/libtensorpipe.a
    PUBLIC /pytorch/build/lib/libtensorpipe_uv.a 
    PUBLIC ${CMAKE_DL_LIBS} 
    PUBLIC pthread 
    PUBLIC rt 
    PUBLIC lzma
  )
  set_target_properties(rpc_reproducer_asan PROPERTIES BUILD_WITH_INSTALL_RPATH ON)
  install(TARGETS rpc_reproducer_asan DESTINATION /)

endif()
