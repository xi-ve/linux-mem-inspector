#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace raider {

class Inspector;

class InspectorMCP {
public:
  explicit InspectorMCP(Inspector& inspector, int port = 8082);
  void run();   // blocks, accepting connections — call from thread
  void stop();

private:
  void handle_client(int client_fd);
  void handle_request(int client_fd, const std::string& line);
  void send_response(int client_fd, const std::string& json);
  std::string dispatch_tool(const std::string& name, const std::string& args);

  std::string make_result(const std::string& id, const std::string& result_json);
  std::string make_error(const std::string& id, int code, const std::string& msg);

  Inspector& inspector_;
  int port_;
  int listen_fd_{-1};
  std::atomic<bool> running_{true};

  std::mutex send_mu_;
  std::mutex clients_mu_;
  std::vector<std::thread> client_threads_;
};

} // namespace raider
