#include <config.h>
#include <dpdk.h>
#include <glog/logging.h>
#include <machnet_controller.h>
#include <machnet_ctrl.h>
#include <utils.h>
#include <worker.h>
#include <eps_ring.h>
#include <cstring>
#include "pause.h"
#include <gflags/gflags.h>
#include <machnet.h>
#include <arpa/inet.h>

#include <future>
#include <memory>
#include <thread>

DEFINE_bool(eps_enable, false,
  "Bind a daemon-owned channel to the EPS eBPF rings (AccNet). "
  "When false the daemon behaves exactly as stock Machnet.");
DEFINE_uint32(eps_local_ip, 0x7F000001,
  "Local IP stamped on EPS flows, in the byte order the eBPF maps "
  "use (default 127.0.0.1).");

static std::string EpsIpToString(uint32_t ip) {   // maps store host order
  char b[16];
  snprintf(b, sizeof(b), "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF, ip & 0xFF);
  return b;
}
namespace juggler {

struct MachnetClientContext {
  bool registered;
  uuid_t uuid;
};

MachnetController::MachnetController(const std::string &conf_file)
    : config_processor_{conf_file}, channel_manager_{} {}

void MachnetController::Run() {
  if (IsRunning()) {
    LOG(ERROR) << "Controller is already running.";
    return;
  }

  if (config_processor_.interfaces_config().empty()) {
    LOG(ERROR) << "No interfaces configured. Exiting.";
    return;
  }

  signal(SIGINT, MachnetController::sig_handler);

  // Initialize DPDK.
  dpdk_.InitDpdk(config_processor_.GetEalOpts());
  if (dpdk_.GetNumPmdPortsAvailable() == 0) {
    LOG(ERROR) << "Error: No DPDK-capable ports found. This can be due to "
                  "several reasons.";
    LOG(ERROR) << "1. On Azure, the accelerated NIC must first be unbound from "
                  "the kernel driver with driverctl";
    LOG(ERROR) << "2. The user libraries for the NIC are not installed, e.g., "
                  "libmlx5 for Mellanox NICs";
    LOG(ERROR) << "3. The NIC is not supported by DPDK";
    return;
  }

  std::vector<cpu_set_t> cpu_masks;
  // Find the PMD port id for each interface.
  for (const auto &interface : config_processor_.interfaces_config()) {
    auto pmd_port_id = dpdk_.GetPmdPortIdByMac(interface.l2_addr());
    if (!pmd_port_id) {
      LOG(ERROR) << "Cannot find PMD port id for interface with L2 address: "
                 << interface.l2_addr().ToString();
      return;
    }
    const_cast<NetworkInterfaceConfig &>(interface).set_dpdk_port_id(
        pmd_port_id.value());

    // Initialize the PMD port.
    const uint16_t rx_rings_nr = interface.engine_threads(),
                   tx_rings_nr = interface.engine_threads();
    pmd_ports_.emplace_back(std::make_shared<juggler::dpdk::PmdPort>(
        interface.dpdk_port_id().value(), rx_rings_nr, tx_rings_nr,
        dpdk::PmdRing::kDefaultRingDescNr, dpdk::PmdRing::kDefaultRingDescNr));
    pmd_ports_.back()->InitDriver();

    // Create the MachnetEngineShared State.
    auto shared_state = std::make_shared<MachnetEngineSharedState>(
        pmd_ports_.back()->GetRSSKey(), pmd_ports_.back()->GetL2Addr(),
        std::vector<net::Ipv4::Address>(1, interface.ip_addr()));
    // Create the Machnet engines.
    for (size_t i = 0; i < interface.engine_threads(); ++i) {
      engines_.emplace_back(std::make_shared<juggler::MachnetEngine>(
          pmd_ports_.back(), i, i, shared_state));
      // Create the CPU mask for the engine threads.
      cpu_masks.emplace_back(interface.cpu_mask());
    }
  }

  WorkerPool<MachnetEngine> engine_thread_pool{engines_, cpu_masks};
  engine_thread_pool.Init();
  engine_thread_pool.Launch();

  // EPS: create the daemon-owned channel and start the relay thread BEFORE
  // RunController() blocks. DPDK and the engines are up by this point.
  if (!CreateEpsChannel()) {
    LOG(ERROR) << "EPS: failed to bind the EPS channel; continuing without it";
  }

  // Start the controller server, wait and handle connections.
  RunController();

  // The previous call will block until the server is stopped (e.g. by SIGINT).
  engine_thread_pool.Pause();
  engine_thread_pool.Terminate();

  for (const auto &pmd_port : pmd_ports_) {
    pmd_port->DumpStats();
  }
}

bool MachnetController::HandleNewConnection(UDSocket *s) {
  // Client context.
  if (!s->AllocateUserData(sizeof(MachnetClientContext))) return false;
  auto *client_context =
      reinterpret_cast<MachnetClientContext *>(s->GetUserData());
  CHECK_NOTNULL(client_context);
  client_context->registered = false;
  return true;
}

void MachnetController::HandleNewMessage(UDSocket *s, const char *data,
                                         size_t length) {
  CHECK_NOTNULL(s);
  if (length != sizeof(machnet_ctrl_msg_t)) {
    LOG(ERROR) << "Invalid message length";
    return;
  }

  auto *req = reinterpret_cast<const machnet_ctrl_msg_t *>(data);
  switch (req->type) {
    case MACHNET_CTRL_MSG_TYPE_REQ_REGISTER: {
      machnet_ctrl_msg_t resp;
      resp.type = MACHNET_CTRL_MSG_TYPE_RESPONSE;
      resp.msg_id = req->msg_id;

      auto ret = RegisterApplication(req->app_uuid, &req->app_info);
      resp.status =
          ret ? MACHNET_CTRL_STATUS_SUCCESS : MACHNET_CTRL_STATUS_FAILURE;
      CHECK(s->SendMsg(reinterpret_cast<char *>(&resp), sizeof(resp)));

      // Get client context.
      auto *client_context =
          reinterpret_cast<MachnetClientContext *>(s->GetUserData());
      client_context->registered = true;
      juggler::utils::Copy(client_context->uuid, req->app_uuid, sizeof(uuid_t));
    } break;
    case MACHNET_CTRL_MSG_TYPE_REQ_CHANNEL: {
      LOG(INFO) << "Request to create new channel: "
                << juggler::utils::UUIDToString(req->channel_info.channel_uuid);
      int channel_fd;
      auto ret = CreateChannel(req->app_uuid, &req->channel_info, &channel_fd);

      machnet_ctrl_msg_t resp;
      resp.type = MACHNET_CTRL_MSG_TYPE_RESPONSE;
      resp.msg_id = req->msg_id;

      if (ret && channel_fd >= 0) {
        resp.status = MACHNET_CTRL_STATUS_SUCCESS;
        LOG(INFO) << "Sending channel fd: " << channel_fd << " to client.";
        CHECK(s->SendMsgWithFd(reinterpret_cast<char *>(&resp), sizeof(resp),
                               channel_fd));
      } else {
        resp.status = MACHNET_CTRL_STATUS_FAILURE;
        CHECK(s->SendMsg(reinterpret_cast<char *>(&resp), sizeof(resp)));
      }
    } break;
    default:
      LOG(ERROR) << "Invalid message type.";
      break;
  }
}

void MachnetController::HandlePassiveClose(UDSocket *s) {
  // Get client context.
  auto *client_context =
      reinterpret_cast<MachnetClientContext *>(s->GetUserData());
  if (client_context->registered) {
    LOG(INFO) << "Client " << juggler::utils::UUIDToString(client_context->uuid)
              << " disconnected.";

    UnregisterApplication(client_context->uuid);
    client_context->registered = false;
  }
}

void MachnetController::HandleTimeout(UDSocket *s) {
  // TODO(ilias): Handle timeout.
  LOG(WARNING) << "Not implemented.";
}

bool MachnetController::RegisterApplication(
    const uuid_t app_uuid, const machnet_app_info_t *app_info) {
  const std::string app_uuid_str = juggler::utils::UUIDToString(app_uuid);

  // Check if the application is already registered.
  if (applications_registered_.find(app_uuid_str) !=
      applications_registered_.end()) {
    LOG(ERROR) << "Application is already registered.";
    return false;
  }

  // Register the application.
  applications_registered_.insert({app_uuid_str, {}});
  LOG(INFO) << "Application registered: " << app_uuid_str;

  return true;
}

void MachnetController::UnregisterApplication(const uuid_t app_uuid) {
  const std::string app_uuid_str = juggler::utils::UUIDToString(app_uuid);

  // Check if the application is registered.
  if (applications_registered_.find(app_uuid_str) ==
      applications_registered_.end()) {
    LOG(ERROR) << "Application is not registered.";
    return;
  }

  // TODO(ilias): Destroy all channels and flows.
  const auto &app_channels = applications_registered_[app_uuid_str];

  for (const auto &channel_name : app_channels) {
    LOG(INFO) << "Destroying channel: " << channel_name;
    auto channel = channel_manager_.GetChannel(channel_name.c_str());
    static size_t engine_index =
        utils::hash<size_t>(channel->GetName().c_str(),
                            channel->GetName().size()) %
        engines_.size();
    engines_[engine_index]->RemoveChannel(channel);
    channel_manager_.DestroyChannel(channel_name.c_str());
  }

  // Unregister the application.
  applications_registered_.erase(app_uuid_str);
  LOG(INFO) << "Application unregistered: " << app_uuid_str;
}

bool MachnetController::CreateChannel(
    const uuid_t app_uuid, const machnet_channel_info_t *channel_info,
    int *fd) {
  const std::string app_uuid_str = juggler::utils::UUIDToString(app_uuid);

  // Check that this is a registered application.
  if (applications_registered_.find(app_uuid_str) ==
      applications_registered_.end()) {
    LOG(ERROR) << "Application not registered: " << app_uuid_str;
    return false;
  }

  const std::string channel_uuid_str =
      juggler::utils::UUIDToString(channel_info->channel_uuid);
  auto &app_channels = applications_registered_[app_uuid_str];
  if (app_channels.find(channel_uuid_str) != app_channels.end()) {
    LOG(ERROR) << "Channel already registered: " << channel_uuid_str;
    return false;
  }

  // TODO(ilias): Figure out a way to dynamically infer the buffer size to be
  // used.
  const auto channel_buffer_size =
      juggler::dpdk::PmdRing::kDefaultFrameSize - sizeof(juggler::net::Ipv4) -
      sizeof(juggler::net::Udp) - sizeof(juggler::net::MachnetPktHdr);
  if (!channel_manager_.AddChannel(
          channel_uuid_str.c_str(), ChannelManager::kDefaultRingSize,
          ChannelManager::kDefaultRingSize, ChannelManager::kDefaultBufferCount,
          channel_buffer_size) != 0) {
    return false;
  }

  // Add the channel to the list of channels for this application.
  app_channels.insert(channel_uuid_str);

  // Pass a promise to the Machnet engine and wait for the channel to be
  // activated.
  std::promise<bool> p;
  auto fstatus = p.get_future();
  static size_t engine_index =
      utils::hash<size_t>(channel_uuid_str.c_str(), channel_uuid_str.size()) %
      engines_.size();
  const auto &engine = engines_[engine_index];
  engine->AddChannel(
      CHECK_NOTNULL(channel_manager_.GetChannel(channel_uuid_str.c_str())),
      std::move(p));

  // TODO(ilias): Add a timeout here.
  auto status = fstatus.get();

  if (status != true) {
    LOG(ERROR) << "Failed to create channel.";
    *fd = -1;
    return false;
  }

  if (kShmZeroCopyEnabled) {
    LOG(INFO) << "Registering channel buffer memory with NIC DPDK driver.";
    // Register channel buffer memory with NIC DPDK driver.
    auto device = engine->GetPmdPort()->GetDevice();
    CHECK(channel_manager_.GetChannel(channel_uuid_str.c_str())
              ->RegisterMemForDMA(device));
  } else {
    LOG(INFO) << "Not registering channel buffer memory with NIC DPDK driver.";
  }

  *fd = channel_manager_.GetChannel(channel_uuid_str.c_str())->GetFd();
  return status;
}

/* Create an EPS channel */
bool MachnetController::CreateEpsChannel() {
  if (!FLAGS_eps_enable) {
    return true; // stock daemon: nothing happens
  }

  static constexpr const char *kEpsChannelName = "eps0";
  const auto channel_buffer_size =
      juggler::dpdk::PmdRing::kDefaultFrameSize - sizeof(juggler::net::Ipv4) -
      sizeof(juggler::net::Udp) - sizeof(juggler::net::MachnetPktHdr);

  if (!channel_manager_.AddChannel(
          kEpsChannelName, ChannelManager::kDefaultRingSize,
          ChannelManager::kDefaultRingSize, ChannelManager::kDefaultBufferCount,
          channel_buffer_size)) {
    LOG(ERROR) << "EPS: failed to create channel";
    return false;
  }
  auto channel = channel_manager_.GetChannel(kEpsChannelName);
  CHECK_NOTNULL(channel);

  uint64_t *consumer_page = nullptr; 
  uint64_t *producer_page = nullptr;
  uint8_t *data = nullptr;
  eps_tx_fd_ = juggler::eps::OpenTxRing(juggler::eps::kTxRingPin,
                                        juggler::eps::kTxRingSize, &consumer_page, &producer_page,
                                        &data);
  if (eps_tx_fd_ < 0) {
    LOG(ERROR) << "EPS: cannot open " << juggler::eps::kTxRingPin
               << " (is the EPS program loaded?): " << strerror(errno);
    return false;
  }

  // get file descriptors for the eBPF maps
  eps_rx_rings_map_fd_ = bpf_obj_get(juggler::eps::kRxRingsPin); // {pid, fd} -> USER_RINGBUF
  eps_connect_map_fd_ = bpf_obj_get(juggler::eps::kConnectMapPin); // {pid, fd} -> {ip, port}
  eps_bind_map_fd_ = bpf_obj_get(juggler::eps::kBindMapPin); // {ip, port} -> {pid, fd}
  eps_fd_to_addr_map_fd_ = bpf_obj_get(juggler::eps::kFdToAddrPin); // {pid, fd} -> {ip, port} (local)
  if (eps_rx_rings_map_fd_ < 0 || eps_connect_map_fd_ < 0 || eps_bind_map_fd_ < 0 ||
    eps_fd_to_addr_map_fd_ < 0) {
    LOG(ERROR) << "EPS: cannot open control maps: " << strerror(errno);
    return false;
  }

  channel->EnableEpsMode(consumer_page, producer_page, data, juggler::eps::kTxRingSize, nullptr,
                         -1);
  channel->SetEpsRxRingsFd(eps_rx_rings_map_fd_);
  channel->SetEpsControlMaps(eps_connect_map_fd_, eps_bind_map_fd_, eps_fd_to_addr_map_fd_,
    FLAGS_eps_local_ip);

  LOG(INFO) << "EPS: channel '" << kEpsChannelName
            << "' bound to the eBPF rings; starting relay thread";
  // Hand the channel to an engine. It now drives DequeueMessages (TX -> wire)
  // and EnqueueMessages (RX -> app), and services the control ring — without
  // which machnet_listen/connect cannot even be enqueued.
  std::promise<bool> promise;
  auto fstatus = promise.get_future();
  const auto &engine = engines_[0];
  engine->AddChannel(channel, std::move(promise));
  if (!fstatus.get()) {
    LOG(ERROR) << "EPS: engine refused the channel";
    return false;
  }
  LOG(INFO) << "EPS: channel handed to engine 0";
  channel->SetEpsUseRealFlows(true);
  eps_ctrl_thread_ =
      std::thread(&MachnetController::EpsControlLoop, this, channel.get());
  return true;
}

void MachnetController::RunController() {
  const std::string socket_path = MACHNET_CONTROLLER_DEFAULT_PATH;

  const UDServer::on_connect_cb_t on_connect_cb = std::bind(
      &MachnetController::HandleNewConnection, this, std::placeholders::_1);

  const UDServer::on_close_cb_t on_close_cb = [=, this](UDSocket *socket) {
    this->HandlePassiveClose(socket);
  };

  // UDServer::on_close_cb_t on_close_cb = std::bind(
  //     &MachnetController::HandlePassiveClose, this, std::placeholders::_1);
  const UDServer::on_message_cb_t on_message_cb =
      [=, this](UDSocket *socket, const char *data, size_t length, int fd) {
        this->HandleNewMessage(socket, data, length);
      };

  const UDServer::on_timeout_cb_t on_timeout_cb = [=, this](UDSocket *socket) {
    this->HandleTimeout(socket);
  };

  server_ = std::make_unique<UDServer>(socket_path, on_connect_cb, on_close_cb,
                                       on_message_cb, on_timeout_cb);

  server_->Run();
}

void MachnetController::EpsControlLoop(juggler::shm::Channel *channel) {
  using juggler::shm::EpsBindKey;
  using juggler::shm::EpsConnDest;
  using juggler::shm::EpsConnKey;

  auto *ctx = const_cast<MachnetChannelCtx_t *>(channel->ctx());
  const std::string local_ip = EpsIpToString(FLAGS_eps_local_ip);

  while (!eps_stop_.load(std::memory_order_relaxed)) {
    /* Servers: every bound address needs a Machnet listener, so inbound
     * handshakes create the flow passively. */
    EpsBindKey bind_key{};
    EpsBindKey next_bind_key{};
    if (bpf_map_get_next_key(eps_bind_map_fd_, nullptr, &next_bind_key) == 0) {
      do {
        bind_key = next_bind_key;
        EpsConnKey conn{};
        if (bpf_map_lookup_elem(eps_bind_map_fd_, &bind_key, &conn) != 0) {
          continue;
        }

        const uint16_t listen_port = ntohs(bind_key.port);
        
        // Refresh the port -> socket mapping on EVERY sweep. The application
        // can restart with a new pid while the Machnet listener itself
        // persists, so this must not be gated on the dedupe below: otherwise
        // the mapping keeps pointing at the socket of the previous run.
        channel->RegisterEpsListener(listen_port, conn);

        if (!eps_listeners_.insert(bind_key.port).second) {
          continue;
        }
        if (machnet_listen(ctx, local_ip.c_str(), listen_port) == 0) {
          LOG(INFO) << "EPS: listening on " << local_ip << ":" << listen_port
                    << " for pid=" << conn.pid << " fd=" << conn.fd;
        } else {
          LOG(ERROR) << "EPS: machnet_listen failed on port " << bind_key.port;
          eps_listeners_.erase(bind_key.port);                        // allow retry
        }
      } while (bpf_map_get_next_key(eps_bind_map_fd_, &bind_key, &next_bind_key) == 0);
    }

    // Clients: each connected socket needs a real Machnet flow.
    // (1) Servers: every LISTENING endpoint needs a Machnet listener. Iterating
    //     bind_map here was wrong: a client that binds a source port is not a
    //     server, and creating a listener for it also made the sweep-2 guard
    //     below suppress its machnet_connect, so it never got a flow at all.
    EpsConnKey listen_key{};
    EpsConnKey next_listen_key{};
    if (bpf_map_get_next_key(eps_listen_map_fd_, nullptr, &next_listen_key) == 0) {
      do {
        listen_key = next_listen_key;
        EpsBindKey bind_key{};
        if (bpf_map_lookup_elem(eps_listen_map_fd_, &listen_key, &bind_key) != 0) {
          continue;
        }

        // The socket that RECEIVES on this endpoint is whatever bind_map points
        // at: the listener before accept(), the accepted socket afterwards
        // (accept_exit repoints it). Refresh every sweep.
        EpsConnKey conn{};
        if (bpf_map_lookup_elem(eps_bind_map_fd_, &bind_key, &conn) != 0) {
          continue;
        }

        const uint16_t listen_port = ntohs(bind_key.port);
        channel->RegisterEpsListener(listen_port, conn);

        if (!eps_listeners_.insert(bind_key.port).second) {
          continue;   // listen once
        }
        if (machnet_listen(ctx, local_ip.c_str(), listen_port) == 0) {
          LOG(INFO) << "EPS: listening on " << local_ip << ":" << listen_port
                    << " for pid=" << conn.pid << " fd=" << conn.fd;
        } else {
          LOG(ERROR) << "EPS: machnet_listen failed on port " << listen_port;
          eps_listeners_.erase(bind_key.port);
        }
      } while (bpf_map_get_next_key(eps_listen_map_fd_, &listen_key, &next_listen_key) == 0);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

void MachnetController::Stop() {
  eps_stop_.store(true, std::memory_order_relaxed);
  if (eps_thread_.joinable()) {
    eps_thread_.join();
  }
  if (eps_ctrl_thread_.joinable()) { 
    eps_ctrl_thread_.join();
  }
  CHECK_NOTNULL(server_);
  server_->Stop();
}

}  // namespace juggler
