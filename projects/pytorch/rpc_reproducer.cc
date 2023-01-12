// Copyright 2022 ISP RAS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ###############################################################################

#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <ATen/core/jit_type.h>
#include <c10/core/ScalarType.h>
#include <c10d/ProcessGroupGloo.hpp>
#include <c10d/TCPStore.hpp>
#include <tensorpipe/core/message.h>
#include <torch/csrc/distributed/autograd/context/container.h>
#include <torch/csrc/distributed/autograd/context/context.h>
#include <torch/csrc/distributed/rpc/profiler/remote_profiler_manager.h>
#include <torch/csrc/distributed/rpc/profiler/server_process_global_profiler.h>
#include <torch/csrc/distributed/rpc/request_callback_no_python.h>
#include <torch/csrc/distributed/rpc/rpc_agent.h>
#include <torch/csrc/distributed/rpc/rref_context.h>
#include <torch/csrc/distributed/rpc/tensorpipe_agent.h>
#include <torch/csrc/distributed/rpc/tensorpipe_utils.h>
#include <torch/csrc/distributed/rpc/torchscript_functions.h>
#include <torch/csrc/distributed/rpc/types.h>
#include <torch/csrc/distributed/rpc/utils.h>
#include <torch/csrc/jit/backends/backend.h>
#include <torch/csrc/jit/backends/backend_detail.h>
#include <torch/csrc/jit/backends/backend_preprocess.h>
#include <torch/csrc/jit/ir/irparser.h>
#include <torch/csrc/jit/mobile/nnc/aot_compiler.h>
#include <torch/csrc/jit/passes/dead_code_elimination.h>
#include <torch/csrc/jit/passes/freeze_module.h>
#include <torch/csrc/jit/serialization/export.h>
#include <torch/csrc/jit/serialization/import.h>
#include <torch/csrc/jit/tensorexpr/graph_opt.h>
#include <torch/csrc/jit/tensorexpr/kernel.h>
#include <torch/csrc/jit/testing/file_check.h>
#include <torch/script.h>
#include <torch/torch.h>

using namespace torch::distributed::rpc;

MessageType GetMessageType(MessageType msgType) {
  switch (msgType) {
  case SCRIPT_CALL:
    return SCRIPT_CALL;
  case SCRIPT_RET:
    return SCRIPT_RET;
  case PYTHON_CALL:
    return PYTHON_CALL;
  case PYTHON_RET:
    return PYTHON_RET;
  case SCRIPT_REMOTE_CALL:
    return SCRIPT_REMOTE_CALL;
  case PYTHON_REMOTE_CALL:
    return PYTHON_REMOTE_CALL;
  case REMOTE_RET:
    return REMOTE_RET;
  case SCRIPT_RREF_FETCH_CALL:
    return SCRIPT_RREF_FETCH_CALL;
  case PYTHON_RREF_FETCH_CALL:
    return PYTHON_RREF_FETCH_CALL;
  case SCRIPT_RREF_FETCH_RET:
    return SCRIPT_RREF_FETCH_RET;
  case PYTHON_RREF_FETCH_RET:
    return PYTHON_RREF_FETCH_RET;
  case RREF_USER_DELETE:
    return RREF_USER_DELETE;
  case RREF_FORK_REQUEST:
    return RREF_FORK_REQUEST;
  case RREF_CHILD_ACCEPT:
    return RREF_CHILD_ACCEPT;
  case RREF_ACK:
    return RREF_ACK;
  case FORWARD_AUTOGRAD_REQ:
    return FORWARD_AUTOGRAD_REQ;
  case FORWARD_AUTOGRAD_RESP:
    return FORWARD_AUTOGRAD_RESP;
  case BACKWARD_AUTOGRAD_REQ:
    return BACKWARD_AUTOGRAD_REQ;
  case BACKWARD_AUTOGRAD_RESP:
    return BACKWARD_AUTOGRAD_RESP;
  case CLEANUP_AUTOGRAD_CONTEXT_REQ:
    return CLEANUP_AUTOGRAD_CONTEXT_REQ;
  case CLEANUP_AUTOGRAD_CONTEXT_RESP:
    return CLEANUP_AUTOGRAD_CONTEXT_RESP;
  case RUN_WITH_PROFILING_REQ:
    return RUN_WITH_PROFILING_REQ;
  case RUN_WITH_PROFILING_RESP:
    return RUN_WITH_PROFILING_RESP;
  case RREF_BACKWARD_REQ:
    return RREF_BACKWARD_REQ;
  case RREF_BACKWARD_RESP:
    return RREF_BACKWARD_RESP;
  case EXCEPTION:
    return EXCEPTION;
  case UNKNOWN:
    return UNKNOWN;
  default:
    return UNKNOWN;
  }
}

std::shared_ptr<TensorPipeAgent> g_rpcAgent;

int Init() {
  const uint32_t numWorkers = 1;
  const std::string masterNodeAddr = "127.0.0.1";

  static torch::distributed::autograd::DistAutogradContainer
      *autogradContainer =
          &torch::distributed::autograd::DistAutogradContainer::init(0);

  // auto options = c10d::ProcessGroupGloo::Options::create();
  // options->devices.push_back(
  //     ::c10d::ProcessGroupGloo::createDeviceForHostname(masterNodeAddr));

  c10d::TCPStoreOptions storeOpts{/* port */ 29500,
                                  /* isServer */ true,
                                  /* numWorkers */ numWorkers,
                                  /* waitWorkers */ true,
                                  /* timeout */ std::chrono::seconds(10)};
  c10::intrusive_ptr<c10d::Store> store =
      c10::make_intrusive<c10d::TCPStore>(masterNodeAddr, storeOpts);

  TensorPipeRpcBackendOptions tensorpipeOpts(
      /*numWorkerThreads=*/1U,
      /*transports=*/c10::nullopt,
      /*channels=*/c10::nullopt,
      /*rpc_timeout=*/15,
      /*init_method=*/"unused");
  g_rpcAgent = std::make_shared<TensorPipeAgent>(
      /*store*/ store, /*selfName*/ "worker", /*selfId*/ 0,
      /*numWorkers*/ numWorkers, /*opts*/ tensorpipeOpts,
      /*reverseDeviceMaps*/ std::unordered_map<std::string, DeviceMap>{},
      /*devices*/ std::vector<c10::Device>{},
      /*cb*/ std::make_unique<RequestCallbackNoPython>());

  RpcAgent::setCurrentRpcAgent(g_rpcAgent);

  std::shared_ptr<TypeResolver> typeResolver =
      std::make_shared<TypeResolver>([&](const c10::QualifiedName &qn) {
        // For Dict that is used for device map.
        auto pos = qn.name().find("Dict");
        if (pos != std::string::npos) {
          return c10::StrongTypePtr(
              nullptr, c10::DictType::create(c10::StringType::get(),
                                             c10::StringType::get()));
        }
        return c10::StrongTypePtr(nullptr,
                                  c10::TensorType::create(at::Tensor()));
      });

  // std::shared_ptr<TypeResolver> typeResolver =
  //     std::make_shared<TypeResolver>([&](const c10::QualifiedName &qn) {
  //       auto typePtr = PythonRpcHandler::getInstance().parseTypeFromStr(
  //           qn.qualifiedName());
  //       return c10::StrongTypePtr(
  //           PythonRpcHandler::getInstance().jitCompilationUnit(),
  //           std::move(typePtr));
  //     });
  g_rpcAgent->setTypeResolver(typeResolver);
  g_rpcAgent->start();
  g_rpcAgent->sync();

  return 1;
}

void ReadFile(char *file_path, char **out_buffer, int *file_size) {
  FILE *fd = fopen(file_path, "rb");

  if (fd == NULL)
    throw std::runtime_error("File not found!");

  fseek(fd, 0, SEEK_END);
  int fsize = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  *file_size = fsize;

  char *buffer = (char *)malloc(sizeof(char) * fsize);
  fread(buffer, 1, fsize, fd);
  fclose(fd);

  *out_buffer = buffer;
}

void ConstructMessageAndSend(char *file_path) {
  char *buffer;
  int file_size;

  ReadFile(file_path, &buffer, &file_size);

  MessageType msgType =
      GetMessageType((MessageType)(buffer[0] << 8 | buffer[1]));
  int64_t mId = (uint64_t)buffer[2];
  bool isResponse = (bool)buffer[3];

  at::Tensor t1 = torch::ones({16}, at::ScalarType::Int);
  at::Tensor t2 = torch::ones({16}, at::ScalarType::Float);
  std::vector<at::Tensor> tensors{t1, t2};
  std::vector<char> payload(buffer + 4, buffer + file_size);

  auto msg = c10::make_intrusive<Message>(std::move(payload),
                                          std::move(tensors), msgType);
  msg->setId(mId);

  if (isResponse) {
    throw std::runtime_error(
        "Sending response messages is not supported by the reproducer!");
    // torch::distributed::autograd::getMessageWithAutograd(
    //     0, std::move(scriptRemoteCall).toMessage(),
    //     std::move(scriptRemoteCall).toMessage()->type());
  } else {
    auto response = torch::distributed::autograd::sendMessageWithAutograd(
        *g_rpcAgent, g_rpcAgent->getWorkerInfo("worker"), msg);
    response->waitAndThrow();
  }
}

int main(int argc, char *argv[]) {
  if (!RpcAgent::isCurrentRpcAgentSet()) {
    Init();
  }

  ConstructMessageAndSend(argv[1]);

  g_rpcAgent->join();
  g_rpcAgent->shutdown();

  return 0;
}
