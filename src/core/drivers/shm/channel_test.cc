/**
 * @file shm_test.cc
 *
 * Unit tests for juggler's Channels (POSIX shared memory) driver.
 */
#include <channel.h>
#include <channel_msgbuf.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <machnet.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>
#include <utils.h>

#include <atomic>
#include <cstddef>
#include <map>
#include <numeric>
#include <random>
#include <thread>
#include <utility>

#include "pause.h"

constexpr const char* file_name(const char* path) {
  const char* file = path;
  while (*path) {
    if (*path++ == '/') {
      file = path;
    }
  }
  return file;
}

const char* fname = file_name(__FILE__);

// Enqueue one message from the application to Machnet.
bool app_msg_enqueue(MachnetChannelCtx_t* ctx, const std::vector<char>& msg) {
  MachnetIovec_t iovec;
  iovec.base = const_cast<char*>(msg.data());
  iovec.len = msg.size();
  MachnetMsgHdr_t msghdr;
  msghdr.msg_size = msg.size();
  msghdr.flags = 0;
  msghdr.msg_iov = &iovec;
  msghdr.msg_iovlen = 1;

  return machnet_sendmsg(ctx, &msghdr) == 0;
}

// Check if the message we received in Machnet matches the original one sent
// from the application.
bool check_msg(juggler::shm::ShmChannel* channel, juggler::shm::MsgBuf* msg,
               const std::vector<char>& expected) {
  uint32_t expected_msg_ofs = 0;
  while (expected_msg_ofs < expected.size()) {
    if (msg->length() > expected.size() - expected_msg_ofs) return false;
    const int rc = std::memcmp(
        msg->head_data(), expected.data() + expected_msg_ofs, msg->length());
    if (rc != 0) return false;
    expected_msg_ofs += msg->length();
    if (!msg->has_next()) break;
    msg = channel->GetMsgBuf(msg->next());
  }

  if (expected_msg_ofs != expected.size()) return false;

  return true;
}

/**
 * @brief This helper function accepts a message (as vector) and copies the
 * payload to a `MsgBufBatch'.
 *
 * @param  batch      The `MsgBufBatch' to which the message will be copied.
 * @param  msg        The message to be copied.
 * @return bool       True if the message was copied successfully.
 */
bool machnet_msg_prepare(juggler::shm::MsgBufBatch* batch, const uint8_t* msg,
                         const uint32_t msg_size) {
  uint32_t msg_ofs = 0;
  uint32_t msg_buf_index = 0;
  while (msg_ofs < msg_size) {
    if (msg_buf_index >= batch->GetSize()) break;
    if (msg_buf_index > 0) {
      auto* prev_buf = batch->bufs()[msg_buf_index - 1];
      prev_buf->set_next(batch->buf_indices()[msg_buf_index]);
    }
    auto* msg_buf = batch->bufs()[msg_buf_index];
    assert(msg_buf->length() == 0);  // Expect a fresh buffer.

    auto nbytes = std::min(msg_size - msg_ofs, msg_buf->tailroom());
    auto* payload = msg_buf->append(nbytes);
    CHECK_NOTNULL(payload);
    juggler::utils::Copy(payload, msg + msg_ofs, nbytes);

    msg_buf_index++;
    msg_ofs += nbytes;
  }

  if (msg_ofs != msg_size) {
    LOG(INFO) << "Failed to copy message: " << msg_ofs << " != " << msg_size;
    return false;
  }

  return true;
}

TEST(BasicChannelTest, ChannelCreateDestroy) {
  using ChannelManager = juggler::shm::ChannelManager<juggler::shm::ShmChannel>;
  const uint32_t kChannelRingSize = 1 << 11;  // 2048 slots for all rings.
  const uint32_t kBufferSize = 1 << 12;       // 4096 bytes for buffer.

  ChannelManager channel_mgr;

  for (size_t counter = 0; counter < ChannelManager::kMaxChannelNr; counter++) {
    std::string channel_name =
        std::string(fname) + "-" + std::to_string(counter);
    EXPECT_TRUE(channel_mgr.AddChannel(channel_name.c_str(), kChannelRingSize,
                                       kChannelRingSize, kChannelRingSize,
                                       kBufferSize));
  }

  EXPECT_EQ(channel_mgr.GetChannelCount(), ChannelManager::kMaxChannelNr);

  size_t counter = 0;
  for (counter = 0; counter < ChannelManager::kMaxChannelNr; counter++) {
    std::string channel_name =
        std::string(fname) + "-" + std::to_string(counter);
    EXPECT_NE(channel_mgr.GetChannel(channel_name.c_str()), nullptr);
  }
}

TEST(BasicChannelTest, ChannelMsgBufAllocFree) {
  using ChannelManager = juggler::shm::ChannelManager<juggler::shm::ShmChannel>;
  const uint32_t kChannelRingSize = 1 << 11;  // 2048 slots for all rings.
  const uint32_t kBufferSize = 1 << 12;       // 4096 bytes for buffer.

  ChannelManager channel_mgr;

  std::string channel_name(fname);
  EXPECT_TRUE(channel_mgr.AddChannel(channel_name.c_str(), kChannelRingSize,
                                     kChannelRingSize, kChannelRingSize,
                                     kBufferSize));
  auto* channel = channel_mgr.GetChannel(channel_name.c_str()).get();
  CHECK_NOTNULL(channel);
  auto* msg_buf = channel->MsgBufAlloc();
  EXPECT_NE(msg_buf, nullptr);
  EXPECT_TRUE(channel->MsgBufFree(msg_buf));
}

TEST(BasicChannelTest, ChannelDequeue) {
  using ChannelManager = juggler::shm::ChannelManager<juggler::shm::ShmChannel>;
  const uint32_t kChannelRingSize = 1 << 11;  // 2048 slots for all rings.
  const uint32_t kBufferSize = 1 << 12;       // 4096 bytes for buffer.
  const uint32_t kMessageSize = 1 << 15;      // 32K bytes for message.

  ChannelManager channel_mgr;

  std::string channel_name(fname);
  EXPECT_TRUE(channel_mgr.AddChannel(channel_name.c_str(), kChannelRingSize,
                                     kChannelRingSize, kChannelRingSize,
                                     kBufferSize));
  auto* channel = channel_mgr.GetChannel(channel_name.c_str()).get();
  CHECK_NOTNULL(channel);

  // Step 1: Enqueue some messages to the channel (from the application).
  const std::vector<char> msg1(kMessageSize, 'a');
  EXPECT_TRUE(
      app_msg_enqueue(const_cast<MachnetChannelCtx_t*>(channel->ctx()), msg1));
  const std::vector<char> msg2(kMessageSize, 'b');
  EXPECT_TRUE(
      app_msg_enqueue(const_cast<MachnetChannelCtx_t*>(channel->ctx()), msg2));

  // Step 2: Dequeue the messages from the application, and check validity.
  juggler::shm::MsgBufBatch batch;
  channel->DequeueMessages(&batch);
  EXPECT_EQ(batch.GetSize(), 2);
  EXPECT_TRUE(check_msg(channel, batch.bufs()[0], msg1));
  EXPECT_TRUE(check_msg(channel, batch.bufs()[1], msg2));
}

TEST(BasicChannelTest, ChannelEnqueue) {
  const uint32_t kChannelRingSize = 1 << 11;  // 2048 slots for all rings.
  const uint32_t kBufferSize = 1 << 12;       // 4096 bytes for buffer.
  const uint32_t kMessageSize = 1 << 15;      // 32K bytes for message.

  juggler::shm::ChannelManager channel_mgr;

  std::string channel_name(fname);
  EXPECT_TRUE(channel_mgr.AddChannel(channel_name.c_str(), kChannelRingSize,
                                     kChannelRingSize, kChannelRingSize,
                                     kBufferSize));
  auto* channel = channel_mgr.GetChannel(channel_name.c_str()).get();
  CHECK_NOTNULL(channel);

  // Step 1: Enqueue some messages to the channel (from the application).
  const std::vector<uint8_t> tx_msg(kMessageSize, 'a');
  auto buf_size = channel->GetUsableBufSize();
  auto nbuffers = (kMessageSize + buf_size - 1) / buf_size;

  // Allocate the MsgBufs we need to accommodate the message.
  juggler::shm::MsgBufBatch batch;
  EXPECT_TRUE(channel->MsgBufBulkAlloc(&batch, nbuffers));
  EXPECT_EQ(batch.GetSize(), nbuffers);
  EXPECT_TRUE(machnet_msg_prepare(&batch, tx_msg.data(), tx_msg.size()));
  EXPECT_EQ(channel->EnqueueMessages(&batch.bufs()[0], 1), 1);

  // Step 2: Dequeue the message from the application side, and check validity.
  std::vector<uint8_t> rx_msg(kMessageSize);
  MachnetIovec_t rx_iov;
  rx_iov.base = rx_msg.data();
  rx_iov.len = rx_msg.size();
  MachnetMsgHdr_t rx_msghdr;
  rx_msghdr.msg_size = 0;
  rx_msghdr.flow_info = {
      .src_ip = 0, .dst_ip = 0, .src_port = 0, .dst_port = 0};
  rx_msghdr.msg_iov = &rx_iov;
  rx_msghdr.msg_iovlen = 1;

  EXPECT_EQ(machnet_recvmsg(channel->ctx(), &rx_msghdr), 1);
  EXPECT_EQ(rx_msghdr.msg_size, kMessageSize);
  EXPECT_EQ(rx_msg, tx_msg);
}

TEST(BasicChannelTest, EpsModeFlag) {
  juggler::shm::ChannelManager channel_mgr;
  std::string channel_name = std::string(fname) + "-eps";
  EXPECT_TRUE(channel_mgr.AddChannel(channel_name.c_str(), 1 << 11, 1 << 11,
                                     1 << 11, 1 << 12));
  auto* channel = channel_mgr.GetChannel(channel_name.c_str()).get();
  CHECK_NOTNULL(channel);

  EXPECT_FALSE(channel->IsEpsMode());
  channel->EnableEpsMode(nullptr, nullptr, nullptr, 0, nullptr, -1);
  EXPECT_TRUE(channel->IsEpsMode());
}

TEST(ChannelFullDuplex, SendRecvMsg) {
  const std::chrono::milliseconds kTimeoutMs =
      std::chrono::milliseconds(60 * 1000);   // 60 seconds.
  const uint32_t kChannelRingSize = 1 << 10;  // 1024 slots for all rings.
  const uint32_t kBufferSize =
      (1 << 12) + MACHNET_MSGBUF_SPACE_RESERVED;  // 4096 bytes for payload.
  const std::size_t kMsgSizeMin = 4;
  const std::size_t kMsgSizeMax = 1 << 17;  // 128K bytes.
  const size_t kMsgNr =
      1 << 16;  // changed to 1 << 16 so we can test it locally

  std::vector<uint8_t> tx_msg(kMsgSizeMax, 0xff);
  std::vector<uint8_t> rx_msg(kMsgSizeMax);

  enum exit_code_t : int {
    kSuccess = 0,
    kBindFailed = 1,
    kTimeoutExpired = 2,
    kError = 3,
  };
  exit_code_t error = kSuccess;

  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> gen_msg_size(
      kMsgSizeMin, kMsgSizeMax);
  std::string channel_name(fname);
  juggler::shm::ChannelManager channel_mgr;

  // Create a channel.
  EXPECT_TRUE(channel_mgr.AddChannel(channel_name.c_str(), kChannelRingSize,
                                     kChannelRingSize, kChannelRingSize,
                                     kBufferSize));
  auto* channel = channel_mgr.GetChannel(channel_name.c_str()).get();
  CHECK_NOTNULL(channel);

  pid_t pid = fork();
  if (pid != 0) {
    // Parent process.
    // Busy-wait until the child process is ready.
    while (__machnet_channel_app_ring_pending(channel->ctx()) == 0) {
      machnet_pause();
    }

    size_t msg_tx = 0, msg_rx = 0;
    auto start = std::chrono::system_clock::now();
    while (msg_tx < kMsgNr || msg_rx < kMsgNr) {
      // Check whether the timeout has expired.
      auto now = std::chrono::system_clock::now();
      auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
      if (elapsed.count() > kTimeoutMs.count()) {
        error = kTimeoutExpired;
        break;
      }

      // Dequeue messages from the channel.
      juggler::shm::MsgBufBatch rx_batch;
      channel->DequeueMessages(&rx_batch);
      for (uint16_t i = 0; i < rx_batch.GetSize(); i++) {
        msg_rx++;

        // Release all buffers of this message.
        auto* msg_buf = rx_batch.bufs()[i];
        auto msg_buf_index = rx_batch.buf_indices()[i];
        EXPECT_LT(msg_buf_index, channel->GetTotalBufCount());

        juggler::shm::MsgBufBatch cur_msg;
        cur_msg.Append(msg_buf, msg_buf_index);

        // Follow the chain of buffers.
        while (msg_buf->has_next()) {
          msg_buf_index = msg_buf->next();
          EXPECT_LT(msg_buf_index, channel->GetTotalBufCount());
          msg_buf = channel->GetMsgBuf(msg_buf_index);
          cur_msg.Append(msg_buf, msg_buf_index);
        }

        // Now release all buffers in the chain.
        EXPECT_TRUE(channel->MsgBufBulkFree(&cur_msg));
      }

      // Enqueue a message to the channel.
      if (msg_tx == kMsgNr) continue;
      size_t tx_msg_size = gen_msg_size(rng);
      juggler::shm::MsgBufBatch tx_batch;
      auto nbuffers = (tx_msg_size + channel->GetUsableBufSize() - 1) /
                      channel->GetUsableBufSize();
      EXPECT_LE(nbuffers, juggler::shm::MsgBufBatch::kMaxBurst);
      auto ret = channel->MsgBufBulkAlloc(&tx_batch, nbuffers);
      if (!ret) continue;  // No buffers available.

      EXPECT_TRUE(machnet_msg_prepare(&tx_batch, tx_msg.data(), tx_msg_size));
      ret = channel->EnqueueMessages(&tx_batch.bufs()[0], 1);
      if (ret == 1)
        msg_tx++;
      else
        // Release the buffers.
        EXPECT_TRUE(channel->MsgBufBulkFree(&tx_batch));
    }

    int wstatus;
    waitpid(pid, &wstatus, 0);

    // The child is going to check the pattern, and exit with code 0 on success.
    EXPECT_EQ(WEXITSTATUS(wstatus), kSuccess);
    EXPECT_EQ(msg_tx, kMsgNr);
    EXPECT_EQ(msg_rx, kMsgNr);
    EXPECT_EQ(error, kSuccess);

    // Check the buffer pool status.
    EXPECT_EQ(channel->GetFreeBufCount(), channel->GetTotalBufCount());

    std::vector<MachnetRingSlot_t> expected_buffers(
        channel->GetTotalBufCount());
    std::iota(expected_buffers.begin(), expected_buffers.end(), 0);
    std::vector<MachnetRingSlot_t> buffers;
    uint32_t buffers_size = channel->GetTotalBufCount();

    // Allocate all the buffers in the channel in 3 parts
    // Allocate from ctx->cache
    uint32_t current_buffers_cnt;
    auto ctx = channel->ctx();
    while (ctx->app_buffer_cache.count > 0)
      buffers.push_back(
          ctx->app_buffer_cache.indices[--ctx->app_buffer_cache.count]);
    current_buffers_cnt = buffers.size();
    // Allocate from shm::channel->cache
    current_buffers_cnt += channel->GetAllCachedBufferIndices(&buffers);
    // Allocate from ring
    buffers.resize(buffers_size);
    current_buffers_cnt += __machnet_channel_buf_alloc_bulk(
        channel->ctx(), buffers.size() - current_buffers_cnt,
        buffers.data() + current_buffers_cnt, nullptr);
    EXPECT_EQ(current_buffers_cnt, buffers.size());
    EXPECT_EQ(channel->GetFreeBufCount(), 0);
    sort(buffers.begin(), buffers.end());
    EXPECT_EQ(buffers, expected_buffers);

  } else {
    // Child process.
    const int kNumRetries = 5;
    size_t channel_size;
    MachnetChannelCtx_t* ctx = nullptr;

    // Attempt to bind to the channel. Channel might not be ready yet, so we
    // retry.
    int shm_fd = channel->GetFd();
    int num_retries = 0;
    while (ctx == nullptr) {
      if (num_retries++ > kNumRetries) {
        exit(kBindFailed);
      }
      ctx = machnet_bind(shm_fd, &channel_size);
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    auto start = std::chrono::system_clock::now();
    size_t msg_tx = 0, msg_rx = 0;

    while (msg_rx < kMsgNr || msg_tx < kMsgNr) {
      // First check whether the timeout has elapsed.
      auto now = std::chrono::system_clock::now();
      auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
      if (elapsed.count() > kTimeoutMs.count()) {
        LOG(INFO) << "TX: " << msg_tx << " RX: " << msg_rx;
        error = kTimeoutExpired;
        break;
      }

      // Receive messages.
      MachnetIovec_t iov;
      iov.base = rx_msg.data();
      iov.len = rx_msg.size();
      MachnetMsgHdr_t msghdr;
      msghdr.msg_size = 0;
      msghdr.flags = 0;
      msghdr.flow_info = {
          .src_ip = 0, .dst_ip = 0, .src_port = 0, .dst_port = 0};
      auto ret = machnet_recvmsg(ctx, &msghdr);
      if (ret == 1) msg_rx++;

      // If already sent the amount of messages needed skip.
      if (msg_tx == kMsgNr) continue;

      // Send a message.
      size_t tx_msg_size = gen_msg_size(rng);
      iov.base = tx_msg.data();
      iov.len = tx_msg_size;
      msghdr.msg_size = tx_msg_size;
      msghdr.flow_info = {.src_ip = UINT32_MAX,
                          .dst_ip = UINT32_MAX,
                          .src_port = UINT16_MAX,
                          .dst_port = UINT16_MAX};
      msghdr.msg_iov = &iov;
      msghdr.msg_iovlen = 1;
      ret = machnet_sendmsg(ctx, &msghdr);
      if (ret == 0) msg_tx++;
    }

    exit(error);
  }
}

// ============================================================================
// Step 3: DequeueMessages against a FAKE tx_ring (no kernel, no BPF, no root)
// ============================================================================
namespace {

constexpr size_t kFakeRingSize = 64 * 1024;  // must be a power of two

struct FakeTxRing {
  uint64_t cons{0};
  uint64_t prod{0};
  // 2x size mimics the production double-mapping so a wrapping record stays
  // contiguous. (We keep records away from the seam in these tests anyway.)
  std::vector<uint8_t> data{std::vector<uint8_t>(kFakeRingSize * 2, 0)};
};

// Write one record exactly as the BPF sendto hook would.
void PushRecord(FakeTxRing* r, uint32_t pid, uint32_t fd, const void* payload,
                uint32_t len, uint32_t flags = 0) {
  uint8_t* slot = r->data.data() + (r->prod & (kFakeRingSize - 1));

  auto* entry = reinterpret_cast<juggler::shm::EpsTransmitEntry*>(
      slot + juggler::shm::kBpfRingbufHdrSz);
  entry->conn_id.pid = pid;
  entry->conn_id.fd = fd;
  entry->payload_length = len;
  memcpy(entry->payload_data, payload, len);

  const uint32_t rec_len =
      offsetof(juggler::shm::EpsTransmitEntry, payload_data) + len;

  // Publish last, with release ordering — same as the kernel's commit.
  __atomic_store_n(reinterpret_cast<uint32_t*>(slot), rec_len | flags,
                   __ATOMIC_RELEASE);
  r->prod += juggler::shm::kBpfRingbufHdrSz + ((rec_len + 7) & ~7ULL);
}

uint64_t StrideFor(uint32_t payload_len) {
  const uint32_t rec_len =
      offsetof(juggler::shm::EpsTransmitEntry, payload_data) + payload_len;
  return juggler::shm::kBpfRingbufHdrSz + ((rec_len + 7) & ~7ULL);
}

// Build a normal channel, then point it at the fake ring.
template <class Mgr>
juggler::shm::ShmChannel* MakeEpsChannel(Mgr* mgr, const std::string& suffix,
                                         FakeTxRing* ring) {
  const std::string name = std::string(fname) + suffix;
  EXPECT_TRUE(
      mgr->AddChannel(name.c_str(), 1 << 11, 1 << 11, 1 << 11, 1 << 12));
  auto* ch = mgr->GetChannel(name.c_str()).get();
  CHECK_NOTNULL(ch);
  ch->EnableEpsMode(&ring->cons, &ring->prod, ring->data.data(), kFakeRingSize,
                    nullptr, -1);
  return ch;
}

// Read the first record from a USER_RINGBUF without advancing the consumer.
// Maps producer page + data read-only (userspace may not write the consumer
// page of a USER_RINGBUF). data_sz must equal the ring's byte size.
inline long ReadFirstUserRingRecord(int map_fd, size_t data_sz, void* out,
                                    size_t out_cap) {
  const long page = sysconf(_SC_PAGESIZE);
  const size_t total = page + 2 * data_sz;
  // offset = page: skip the kernel-owned consumer page, map producer + data x2.
  void* base = mmap(nullptr, total, PROT_READ, MAP_SHARED, map_fd, page);
  if (base == MAP_FAILED) return -2;
  auto* prod = reinterpret_cast<volatile uint64_t*>(base);
  uint8_t* data = static_cast<uint8_t*>(base) + page;
  long len = -1;
  if (__atomic_load_n(prod, __ATOMIC_ACQUIRE) !=
      0) {                                          // something was submitted
    auto* hdr = reinterpret_cast<uint32_t*>(data);  // first record at ofs 0
    const uint32_t lf = __atomic_load_n(hdr, __ATOMIC_ACQUIRE);
    if (!(lf & (1u << 31))) {  // not BUSY
      const uint32_t rlen = lf & ~((1u << 31) | (1u << 30));
      const uint32_t n = rlen < out_cap ? rlen : static_cast<uint32_t>(out_cap);
      memcpy(out, reinterpret_cast<uint8_t*>(hdr) + 8,
             n);  // payload after 8B hdr
      len = rlen;
    }
  }
  munmap(base, total);
  return len;
}

struct EpsConnKeyTest {
  uint32_t pid;
  uint32_t fd;
};

}  // namespace

TEST(EpsDequeue, EmptyRing) {
  juggler::shm::ChannelManager mgr;
  FakeTxRing ring;
  auto* ch = MakeEpsChannel(&mgr, "-eps-empty", &ring);

  MachnetRingSlot_t idx[4];
  juggler::shm::MsgBuf* bufs[4];
  EXPECT_EQ(ch->DequeueMessages(idx, bufs, 4), 0u);
  EXPECT_EQ(ring.cons, 0u);  // nothing consumed
}

TEST(EpsDequeue, SingleRecord) {
  juggler::shm::ChannelManager mgr;
  FakeTxRing ring;
  auto* ch = MakeEpsChannel(&mgr, "-eps-single", &ring);

  std::vector<uint8_t> payload(512);
  std::iota(payload.begin(), payload.end(), 0);
  PushRecord(&ring, 1234, 7, payload.data(), payload.size());

  MachnetRingSlot_t idx[4];
  juggler::shm::MsgBuf* bufs[4];
  EXPECT_EQ(ch->DequeueMessages(idx, bufs, 4), 1u);
  EXPECT_EQ(bufs[0]->length(), payload.size());
  EXPECT_EQ(memcmp(bufs[0]->head_data(), payload.data(), payload.size()), 0);
  EXPECT_EQ(ring.cons, StrideFor(payload.size()));  // advanced exactly once
  EXPECT_TRUE(ch->MsgBufFree(bufs[0]));
}

TEST(EpsDequeue, RespectsBatchCap) {
  juggler::shm::ChannelManager mgr;
  FakeTxRing ring;
  auto* ch = MakeEpsChannel(&mgr, "-eps-cap", &ring);

  std::vector<uint8_t> payload(64, 0xAB);
  for (int i = 0; i < 3; i++)
    PushRecord(&ring, 1, 1, payload.data(), payload.size());

  MachnetRingSlot_t idx[2];
  juggler::shm::MsgBuf* bufs[2];
  EXPECT_EQ(ch->DequeueMessages(idx, bufs, 2), 2u);     // capped
  EXPECT_EQ(ring.cons, 2 * StrideFor(payload.size()));  // only 2 consumed
  for (int i = 0; i < 2; i++) EXPECT_TRUE(ch->MsgBufFree(bufs[i]));
}

TEST(EpsDequeue, BusyRecordIsNotConsumed) {
  juggler::shm::ChannelManager mgr;
  FakeTxRing ring;
  auto* ch = MakeEpsChannel(&mgr, "-eps-busy", &ring);

  std::vector<uint8_t> payload(128, 0xCD);
  PushRecord(&ring, 1, 1, payload.data(), payload.size(),
             juggler::shm::kBpfRingbufBusyBit);

  MachnetRingSlot_t idx[4];
  juggler::shm::MsgBuf* bufs[4];
  EXPECT_EQ(ch->DequeueMessages(idx, bufs, 4), 0u);  // producer mid-write
  EXPECT_EQ(ring.cons, 0u);                          // and NOT consumed
}

TEST(EpsDequeue, DiscardIsSkippedButConsumed) {
  juggler::shm::ChannelManager mgr;
  FakeTxRing ring;
  auto* ch = MakeEpsChannel(&mgr, "-eps-discard", &ring);

  std::vector<uint8_t> junk(96, 0xEE), good(256, 0x11);
  PushRecord(&ring, 1, 1, junk.data(), junk.size(),
             juggler::shm::kBpfRingbufDiscardBit);
  PushRecord(&ring, 1, 1, good.data(), good.size());

  MachnetRingSlot_t idx[4];
  juggler::shm::MsgBuf* bufs[4];
  EXPECT_EQ(ch->DequeueMessages(idx, bufs, 4), 1u);  // only the good one
  EXPECT_EQ(memcmp(bufs[0]->head_data(), good.data(), good.size()), 0);
  EXPECT_EQ(ring.cons, StrideFor(junk.size()) + StrideFor(good.size()));
  EXPECT_TRUE(ch->MsgBufFree(bufs[0]));
}

TEST(EpsDequeue, PoolExhaustionIsBackpressure) {
  juggler::shm::ChannelManager mgr;
  FakeTxRing ring;
  auto* ch = MakeEpsChannel(&mgr, "-eps-pool", &ring);

  // Drain every buffer so MsgBufAlloc() must fail.
  std::vector<juggler::shm::MsgBuf*> hogged;
  while (auto* b = ch->MsgBufAlloc()) hogged.push_back(b);

  std::vector<uint8_t> payload(64, 0x22);
  PushRecord(&ring, 1, 1, payload.data(), payload.size());

  MachnetRingSlot_t idx[4];
  juggler::shm::MsgBuf* bufs[4];
  EXPECT_EQ(ch->DequeueMessages(idx, bufs, 4), 0u);
  EXPECT_EQ(ring.cons, 0u);  // THE key assertion: record left in place

  for (auto* b : hogged) EXPECT_TRUE(ch->MsgBufFree(b));
}

TEST(EpsTxRouting, StampsRegisteredFlow) {
  juggler::shm::ChannelManager mgr;
  FakeTxRing ring;
  auto* ch = MakeEpsChannel(&mgr, "-eps-tx-stamp", &ring);

  const juggler::shm::EpsConnKey conn{1234, 7};
  const MachnetFlow_t flow = {.src_ip = 0x0A000001,
                              .dst_ip = 0x0A000002,
                              .src_port = 5555,
                              .dst_port = 6666};
  ch->RegisterEpsTxFlow(conn, flow);

  std::vector<uint8_t> payload(256);
  std::iota(payload.begin(), payload.end(), 0);
  PushRecord(&ring, conn.pid, conn.fd, payload.data(), payload.size());

  MachnetRingSlot_t idx[4];
  juggler::shm::MsgBuf* bufs[4];
  ASSERT_EQ(ch->DequeueMessages(idx, bufs, 4), 1u);
  EXPECT_EQ(bufs[0]->length(), payload.size());
  EXPECT_EQ(memcmp(bufs[0]->head_data(), payload.data(), payload.size()), 0);
  // The flow the lookup stamped onto the MsgBuf.
  EXPECT_EQ(bufs[0]->flow()->src_ip, flow.src_ip);
  EXPECT_EQ(bufs[0]->flow()->dst_ip, flow.dst_ip);
  EXPECT_EQ(bufs[0]->flow()->src_port, flow.src_port);
  EXPECT_EQ(bufs[0]->flow()->dst_port, flow.dst_port);
  EXPECT_EQ(ring.cons, StrideFor(payload.size()));
  EXPECT_TRUE(ch->MsgBufFree(bufs[0]));
}

TEST(EpsTxRouting, UnknownFlowStalls) {
  juggler::shm::ChannelManager mgr;
  FakeTxRing ring;
  auto* ch = MakeEpsChannel(&mgr, "-eps-tx-miss", &ring);

  // Register SOME flow so routing is in strict mode (map non-empty).
  const MachnetFlow_t flow = {
      .src_ip = 1, .dst_ip = 2, .src_port = 3, .dst_port = 4};
  ch->RegisterEpsTxFlow(juggler::shm::EpsConnKey{1234, 7}, flow);

  // Push a record for a DIFFERENT, unregistered connection.
  std::vector<uint8_t> payload(64, 0xEE);
  PushRecord(&ring, 9999, 9, payload.data(), payload.size());

  MachnetRingSlot_t idx[4];
  juggler::shm::MsgBuf* bufs[4];
  EXPECT_EQ(ch->DequeueMessages(idx, bufs, 4), 0u);  // stalled, not produced
  EXPECT_EQ(ring.cons, 0u);                          // consumer NOT advanced
}

TEST(EpsLoopback, TxSeamToRxSeam) {
  using juggler::shm::EpsConnKey;
  const uint32_t kInnerSize = 4096;

  juggler::shm::ChannelManager mgr;
  FakeTxRing ring;
  auto* ch = MakeEpsChannel(&mgr, "-eps-loop", &ring);
  const uint32_t free_before = ch->GetFreeBufCount();

  // RX side: outer map + one inner ring for the destination connection.
  int tmpl_fd = bpf_map_create(BPF_MAP_TYPE_USER_RINGBUF, "loop_tmpl", 0, 0,
                               kInnerSize, nullptr);
  ASSERT_GE(tmpl_fd, 0);
  LIBBPF_OPTS(bpf_map_create_opts, oopts,
              .inner_map_fd = static_cast<uint32_t>(tmpl_fd));
  int outer_fd =
      bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "loop_rings",
                     sizeof(EpsConnKey), sizeof(uint32_t), 8, &oopts);
  ASSERT_GE(outer_fd, 0);
  const EpsConnKey dst{2000, 9};
  int inner = bpf_map_create(BPF_MAP_TYPE_USER_RINGBUF, "loop_conn", 0, 0,
                             kInnerSize, nullptr);
  ASSERT_GE(inner, 0);
  ASSERT_EQ(bpf_map_update_elem(outer_fd, &dst, &inner, BPF_ANY), 0);
  close(inner);
  ch->SetEpsRxRingsFd(outer_fd);

  // Routing: TX stamps flow F onto the buf; RX routes F -> dst's ring.
  const EpsConnKey src{1000, 3};
  const MachnetFlow_t flow = {.src_ip = 0x0A000001,
                              .dst_ip = 0x0A000002,
                              .src_port = 1111,
                              .dst_port = 2222};
  ch->RegisterEpsTxFlow(src, flow);      // conn(src) -> flow
  ch->RegisterEpsRxFlow(flow, dst, -1);  // flow -> conn(dst)

  // App "sends": one record into the fake tx_ring for the src socket.
  std::vector<uint8_t> payload(300);
  std::iota(payload.begin(), payload.end(), 0);
  PushRecord(&ring, src.pid, src.fd, payload.data(), payload.size());

  // TX seam: drain tx_ring -> MsgBuf (stamped with flow, msg_len set).
  MachnetRingSlot_t idx[4];
  juggler::shm::MsgBuf* bufs[4];
  ASSERT_EQ(ch->DequeueMessages(idx, bufs, 4), 1u);

  // RX seam: hand the SAME buffer straight back in, no wire.
  ASSERT_EQ(ch->EnqueueMessages(&idx[0], 1), 1u);

  // Verify it landed in dst's ring, intact. Record is [u32 len][payload].
  uint32_t id = 0;
  ASSERT_EQ(bpf_map_lookup_elem(outer_fd, &dst, &id), 0);
  int fd = bpf_map_get_fd_by_id(id);
  std::vector<uint8_t> raw(sizeof(uint32_t) + payload.size());
  long n = ReadFirstUserRingRecord(fd, kInnerSize, raw.data(), raw.size());
  close(fd);
  ASSERT_EQ(n, static_cast<long>(sizeof(uint32_t) + payload.size()));
  uint32_t got_len = 0;
  memcpy(&got_len, raw.data(), sizeof(uint32_t));
  EXPECT_EQ(got_len, payload.size());
  EXPECT_EQ(
      memcmp(raw.data() + sizeof(uint32_t), payload.data(), payload.size()), 0);

  // Ownership flip: TX allocated, RX freed -> pool balanced. tx_ring drained.
  EXPECT_EQ(ch->GetFreeBufCount(), free_before);
  EXPECT_EQ(ring.cons, StrideFor(payload.size()));

  close(outer_fd);
  close(tmpl_fd);
}

TEST(EpsAutoRoute, ReplyRouteLearnedFromInbound) {
  using juggler::shm::EpsConnKey;
  const uint32_t kInnerSize = 4096;

  juggler::shm::ChannelManager mgr;
  FakeTxRing ring;
  auto* ch = MakeEpsChannel(&mgr, "-eps-autoroute", &ring);

  int tmpl_fd = bpf_map_create(BPF_MAP_TYPE_USER_RINGBUF, "ar_tmpl", 0, 0,
                               kInnerSize, nullptr);
  ASSERT_GE(tmpl_fd, 0);
  LIBBPF_OPTS(bpf_map_create_opts, oopts,
              .inner_map_fd = static_cast<uint32_t>(tmpl_fd));
  int outer_fd =
      bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "ar_rings", sizeof(EpsConnKey),
                     sizeof(uint32_t), 8, &oopts);
  ASSERT_GE(outer_fd, 0);
  auto add_conn = [&](const EpsConnKey& k) {
    int inner = bpf_map_create(BPF_MAP_TYPE_USER_RINGBUF, "ar_conn", 0, 0,
                               kInnerSize, nullptr);
    ASSERT_GE(inner, 0);
    ASSERT_EQ(bpf_map_update_elem(outer_fd, &k, &inner, BPF_ANY), 0);
    close(inner);
  };
  const EpsConnKey client{1000, 3};
  const EpsConnKey server{2000, 9};
  add_conn(client);
  add_conn(server);
  ch->SetEpsRxRingsFd(outer_fd);

  const MachnetFlow_t fwd = {.src_ip = 0x0A000001,
                             .dst_ip = 0x0A000002,
                             .src_port = 1111,
                             .dst_port = 2222};
  const MachnetFlow_t rev = {.src_ip = 0x0A000002,
                             .dst_ip = 0x0A000001,
                             .src_port = 2222,
                             .dst_port = 1111};

  ch->RegisterEpsRxFlow(fwd, server, -1);  // inbound fwd delivers to server
  ch->RegisterEpsRxFlow(rev, client, -1);  // inbound rev delivers to client
  ch->RegisterEpsTxFlow(client, fwd);      // client's send route
  // NOTE: server's TX route is NOT registered -- auto-population must learn it.

  // PING: client -> server. Delivery auto-seeds server's reverse route.
  std::vector<uint8_t> ping(200, 0xAA);
  PushRecord(&ring, client.pid, client.fd, ping.data(), ping.size());
  MachnetRingSlot_t idx[4];
  juggler::shm::MsgBuf* bufs[4];
  ASSERT_EQ(ch->DequeueMessages(idx, bufs, 4), 1u);
  ASSERT_EQ(ch->EnqueueMessages(&idx[0], 1), 1u);

  // PONG: server replies with NO registered TX flow.
  std::vector<uint8_t> pong(240, 0xBB);
  PushRecord(&ring, server.pid, server.fd, pong.data(), pong.size());
  ASSERT_EQ(ch->DequeueMessages(idx, bufs, 4), 1u);
  EXPECT_EQ(bufs[0]->flow()->src_ip, rev.src_ip);  // learned reverse flow
  EXPECT_EQ(bufs[0]->flow()->dst_ip, rev.dst_ip);
  EXPECT_EQ(bufs[0]->flow()->src_port, rev.src_port);
  EXPECT_EQ(bufs[0]->flow()->dst_port, rev.dst_port);
  ASSERT_EQ(ch->EnqueueMessages(&idx[0], 1), 1u);  // and it delivers

  uint32_t id = 0;
  ASSERT_EQ(bpf_map_lookup_elem(outer_fd, &client, &id), 0);
  int fd = bpf_map_get_fd_by_id(id);
  std::vector<uint8_t> raw(sizeof(uint32_t) + pong.size());
  long n = ReadFirstUserRingRecord(fd, kInnerSize, raw.data(), raw.size());
  close(fd);
  ASSERT_EQ(n, static_cast<long>(sizeof(uint32_t) + pong.size()));
  EXPECT_EQ(memcmp(raw.data() + sizeof(uint32_t), pong.data(), pong.size()), 0);

  close(outer_fd);
  close(tmpl_fd);
}

// A real BPF_MAP_TYPE_USER_RINGBUF — no BPF program needed, just the map.
constexpr size_t kRxRingBytes = 64 * 1024;  // power of two, page-multiple

struct FakeRxRing {
  int map_fd{-1};
  int event_fd{-1};
  struct user_ring_buffer* rb{nullptr};

  bool Init() {
    map_fd = bpf_map_create(BPF_MAP_TYPE_USER_RINGBUF, "eps_rx", 0, 0,
                            kRxRingBytes, nullptr);
    if (map_fd < 0) return false;
    rb = user_ring_buffer__new(map_fd, nullptr);
    if (rb == nullptr) return false;
    event_fd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
    return event_fd >= 0;
  }
  ~FakeRxRing() {
    if (rb) user_ring_buffer__free(rb);
    if (map_fd >= 0) close(map_fd);
    if (event_fd >= 0) close(event_fd);
  }
};

// Read the first record straight out of the ring's shared memory.
// Layout: [page: consumer][page: producer][data...]; record = 8B hdr + payload.
bool PeekFirstRecord(int map_fd, std::vector<uint8_t>* out) {
  const size_t pg = getpagesize();
  void* m = mmap(nullptr, pg * 2 + kRxRingBytes * 2, PROT_READ, MAP_SHARED,
                 map_fd, 0);
  if (m == MAP_FAILED) return false;
  auto* data = static_cast<uint8_t*>(m) + pg * 2;
  const uint32_t len_flags =
      __atomic_load_n(reinterpret_cast<uint32_t*>(data), __ATOMIC_ACQUIRE);
  const uint32_t len = len_flags & ~(1U << 31 | 1U << 30);
  out->assign(data + 8, data + 8 + len);
  munmap(m, pg * 2 + kRxRingBytes * 2);
  return true;
}

TEST(EpsEnqueue, RoundTripAndBufferAccounting) {
  juggler::shm::ChannelManager mgr;
  FakeTxRing tx;
  FakeRxRing rx;
  ASSERT_TRUE(rx.Init());

  const std::string name = std::string(fname) + "-eps-enq";
  ASSERT_TRUE(mgr.AddChannel(name.c_str(), 1 << 11, 1 << 11, 1 << 11, 1 << 12));
  auto* ch = mgr.GetChannel(name.c_str()).get();
  ch->EnableEpsMode(&tx.cons, &tx.prod, tx.data.data(), kFakeRingSize, rx.rb,
                    rx.event_fd);

  const uint32_t free_before = ch->GetFreeBufCount();

  std::vector<uint8_t> payload(300);
  std::iota(payload.begin(), payload.end(), 7);
  auto* buf = ch->MsgBufAlloc();
  ASSERT_NE(buf, nullptr);
  memcpy(buf->append(payload.size()), payload.data(), payload.size());
  buf->set_msg_length(payload.size());
  buf->mark_first();
  buf->mark_last();

  MachnetRingSlot_t idx = ch->GetBufIndex(buf);
  EXPECT_EQ(ch->EnqueueMessages(&idx, 1), 1u);

  // buffers returned to the pool
  EXPECT_EQ(ch->GetFreeBufCount(), free_before);

  // eventfd bumped exactly once
  uint64_t v = 0;
  EXPECT_EQ(read(rx.event_fd, &v, sizeof(v)), (ssize_t)sizeof(v));
  EXPECT_EQ(v, 1u);

  // payload landed intact, behind the u32 length prefix
  std::vector<uint8_t> got;
  ASSERT_TRUE(PeekFirstRecord(rx.map_fd, &got));
  ASSERT_EQ(got.size(), sizeof(uint32_t) + payload.size());
  uint32_t len_prefix;
  memcpy(&len_prefix, got.data(), sizeof(len_prefix));
  EXPECT_EQ(len_prefix, payload.size());
  EXPECT_EQ(
      memcmp(got.data() + sizeof(uint32_t), payload.data(), payload.size()), 0);
}

// Step 5b: per-connection RX routing over a real BPF map-in-map.
// Outer HASH_OF_MAPS keyed by {pid,fd}; inner USER_RINGBUF per connection --
// exactly the poller's `rx_rings`. Resolve each ring by conn_key (lookup -> id
// -> fd -> user_ring_buffer__new, cached), enqueue a distinct payload to each,
// verify each landed in the CORRECT ring. A single-`rx_ring_` version would
// cross the two payloads. No BPF program, no EPS kernel.
TEST(EpsRxRouting, MapInMapDeliversToCorrectRing) {
  const uint32_t kInnerSize =
      4096;  // USER_RINGBUF byte size (page-aligned pow2)

  // 1. Inner-map template: defines the value type of the outer map.
  int tmpl_fd = bpf_map_create(BPF_MAP_TYPE_USER_RINGBUF, "eps_rx_tmpl", 0, 0,
                               kInnerSize, nullptr);
  ASSERT_GE(tmpl_fd, 0) << "inner template: " << strerror(errno);

  // 2. Outer HASH_OF_MAPS keyed by {pid,fd}.
  LIBBPF_OPTS(bpf_map_create_opts, outer_opts,
              .inner_map_fd = static_cast<uint32_t>(tmpl_fd));
  int outer_fd =
      bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "eps_rx_rings",
                     sizeof(EpsConnKeyTest), sizeof(uint32_t), 8, &outer_opts);
  ASSERT_GE(outer_fd, 0) << "outer map: " << strerror(errno);

  // 3. Two connections, each with its own inner ring inserted into the outer.
  const EpsConnKeyTest kA = {1000, 3};
  const EpsConnKeyTest kB = {2000, 7};
  for (const auto& k : {kA, kB}) {
    int inner = bpf_map_create(BPF_MAP_TYPE_USER_RINGBUF, "eps_rx_conn", 0, 0,
                               kInnerSize, nullptr);
    ASSERT_GE(inner, 0);
    ASSERT_EQ(bpf_map_update_elem(outer_fd, &k, &inner, BPF_ANY), 0)
        << strerror(errno);
    close(inner);  // the outer map now holds a reference
  }

  // 4. The resolve-and-cache path the daemon will use on the RX hot path.
  std::map<std::pair<uint32_t, uint32_t>, struct user_ring_buffer*> cache;
  auto resolve = [&](const EpsConnKeyTest& k) -> struct user_ring_buffer* {
    auto ck = std::make_pair(k.pid, k.fd);
    auto it = cache.find(ck);
    if (it != cache.end()) return it->second;  // hit: no per-packet mmap
    uint32_t inner_id = 0;
    if (bpf_map_lookup_elem(outer_fd, &k, &inner_id) != 0) return nullptr;
    int inner_fd = bpf_map_get_fd_by_id(inner_id);
    if (inner_fd < 0) return nullptr;
    struct user_ring_buffer* urb = user_ring_buffer__new(inner_fd, nullptr);
    close(inner_fd);
    cache[ck] = urb;
    return urb;
  };

  // 5. Enqueue a DISTINCT payload to each connection through the resolver.
  auto enqueue = [&](const EpsConnKeyTest& k, const std::string& s) {
    struct user_ring_buffer* urb = resolve(k);
    ASSERT_NE(urb, nullptr);
    void* slot = user_ring_buffer__reserve(urb, s.size());
    ASSERT_NE(slot, nullptr);
    memcpy(slot, s.data(), s.size());
    user_ring_buffer__submit(urb, slot);
  };
  enqueue(kA, "payload-for-A");
  enqueue(kB, "PAYLOAD_FOR_B!!");

  // 6. Verify each payload landed in the CORRECT ring (independent readback).
  auto read_conn = [&](const EpsConnKeyTest& k) -> std::string {
    uint32_t id = 0;
    EXPECT_EQ(bpf_map_lookup_elem(outer_fd, &k, &id), 0);
    int fd = bpf_map_get_fd_by_id(id);
    EXPECT_GE(fd, 0);
    char buf[64] = {0};
    long n = ReadFirstUserRingRecord(fd, kInnerSize, buf, sizeof(buf));
    close(fd);
    return n < 0 ? std::string() : std::string(buf, n);
  };
  EXPECT_EQ(read_conn(kA), "payload-for-A");    // A's ring has A's payload
  EXPECT_EQ(read_conn(kB), "PAYLOAD_FOR_B!!");  // B's ring has B's payload

  for (auto& kv : cache) user_ring_buffer__free(kv.second);
  close(outer_fd);
  close(tmpl_fd);
}

// Step 5c: EnqueueMessages routes each MsgBuf to its connection's ring by flow.
// Two flows -> two conns -> two inner rings; a single-ring version would cross
// the payloads. Also checks the ownership flip still balances the pool.
TEST(EpsRxRouting, EnqueueRoutesByFlow) {
  const uint32_t kInnerSize = 4096;
  const uint32_t kRingSize = 1 << 11;
  const uint32_t kBufSize = 1 << 12;

  juggler::shm::ChannelManager channel_mgr;
  std::string channel_name = std::string(fname) + "-rxroute";
  ASSERT_TRUE(channel_mgr.AddChannel(channel_name.c_str(), kRingSize, kRingSize,
                                     kRingSize, kBufSize));
  auto* channel = channel_mgr.GetChannel(channel_name.c_str()).get();
  ASSERT_NE(channel, nullptr);
  const uint32_t free_before = channel->GetFreeBufCount();

  // Enable EPS; RX served by the map-in-map (pass no single rx_ring).
  uint64_t tx_cons = 0, tx_prod = 0;
  std::vector<uint8_t> tx_data(4096, 0);
  channel->EnableEpsMode(&tx_cons, &tx_prod, tx_data.data(), tx_data.size(),
                         nullptr, -1);

  // Outer map + two inner rings (keyed by the REAL EpsConnKey type).
  using juggler::shm::EpsConnKey;
  int tmpl_fd = bpf_map_create(BPF_MAP_TYPE_USER_RINGBUF, "rx_tmpl", 0, 0,
                               kInnerSize, nullptr);
  ASSERT_GE(tmpl_fd, 0);
  LIBBPF_OPTS(bpf_map_create_opts, oopts,
              .inner_map_fd = static_cast<uint32_t>(tmpl_fd));
  int outer_fd =
      bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "rx_rings", sizeof(EpsConnKey),
                     sizeof(uint32_t), 8, &oopts);
  ASSERT_GE(outer_fd, 0);
  const EpsConnKey kA{1000, 3}, kB{2000, 7};
  for (const auto& k : {kA, kB}) {
    int inner = bpf_map_create(BPF_MAP_TYPE_USER_RINGBUF, "rx_conn", 0, 0,
                               kInnerSize, nullptr);
    ASSERT_GE(inner, 0);
    ASSERT_EQ(bpf_map_update_elem(outer_fd, &k, &inner, BPF_ANY), 0);
    close(inner);
  }
  channel->SetEpsRxRingsFd(outer_fd);

  MachnetFlow_t flowA = {.src_ip = 0x0A000001,
                         .dst_ip = 0x0A000002,
                         .src_port = 1111,
                         .dst_port = 2222};
  MachnetFlow_t flowB = {.src_ip = 0x0B000001,
                         .dst_ip = 0x0B000002,
                         .src_port = 3333,
                         .dst_port = 4444};
  channel->RegisterEpsRxFlow(flowA, kA, -1);
  channel->RegisterEpsRxFlow(flowB, kB, -1);

  auto make_buf = [&](const MachnetFlow_t& f, const std::string& s) {
    auto* buf = channel->MsgBufAlloc();
    CHECK_NOTNULL(buf);
    buf->set_src_ip(f.src_ip);
    buf->set_dst_ip(f.dst_ip);
    buf->set_src_port(f.src_port);
    buf->set_dst_port(f.dst_port);
    auto* p = buf->append(s.size());
    memcpy(p, s.data(), s.size());
    buf->set_msg_length(s.size());  // total message length
    buf->mark_first();
    buf->mark_last();
    return buf;
  };
  auto* bufA = make_buf(flowA, "hello-A");
  auto* bufB = make_buf(flowB, "hello-B-longer");

  MachnetRingSlot_t idx[2] = {channel->GetBufIndex(bufA),
                              channel->GetBufIndex(bufB)};
  EXPECT_EQ(channel->EnqueueMessages(idx, 2), 2u);

  // Records are [u32 len][payload]; strip the 4-byte length prefix.
  auto read_conn = [&](const EpsConnKey& k) -> std::string {
    uint32_t id = 0;
    EXPECT_EQ(bpf_map_lookup_elem(outer_fd, &k, &id), 0);
    int fd = bpf_map_get_fd_by_id(id);
    char raw[64] = {0};
    long n = ReadFirstUserRingRecord(fd, kInnerSize, raw, sizeof(raw));
    close(fd);
    if (n < static_cast<long>(sizeof(uint32_t))) return std::string();
    return std::string(raw + sizeof(uint32_t), n - sizeof(uint32_t));
  };
  EXPECT_EQ(read_conn(kA), "hello-A");         // A's ring got A's payload
  EXPECT_EQ(read_conn(kB), "hello-B-longer");  // B's ring got B's payload
  EXPECT_EQ(channel->GetFreeBufCount(), free_before);  // pool balanced

  close(outer_fd);
  close(tmpl_fd);
}

int main(int argc, char** argv) {
  ::google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
