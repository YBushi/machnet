#ifndef SRC_INCLUDE_EPS_RING_H_
#define SRC_INCLUDE_EPS_RING_H_

#include <bpf/bpf.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>

namespace juggler {
namespace eps {

// Pins created by the EPS loader (accelerated/src/load.sh).
static constexpr const char *kTxRingPin = "/sys/fs/bpf/accelerated/tx_ring";
static constexpr const char *kRxRingsPin = "/sys/fs/bpf/accelerated/rx_rings";
static constexpr const char *kConnectMapPin =
    "/sys/fs/bpf/accelerated/connect_map";
static constexpr const char *kBindMapPin = "/sys/fs/bpf/accelerated/bind_map";
static constexpr const char *kFdToAddrPin = "/sys/fs/bpf/accelerated/fd_to_addr";
static constexpr const char *kListenMapPin = "/sys/fs/bpf/accelerated/listen_map";


// MUST equal TX_RINGBUF_SIZE in eps_hooks.bpf.c.
static constexpr size_t kTxRingSize = 256 * 1024;

// Map the pinned tx_ring the way the kernel lays a BPF ringbuf out: consumer
// page RW at 0, producer page RO at `page`, data double-mapped RO at 2*page.
// Returns the map fd (>=0), or -1 on failure.
inline int OpenTxRing(const char *pin_path, size_t ring_size, uint64_t **cons,
                      uint64_t **prod, uint8_t **data) {
  const long page = sysconf(_SC_PAGESIZE);
  int fd = bpf_obj_get(pin_path);
  if (fd < 0) return -1;
  *cons = static_cast<uint64_t *>(
      mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
  if (*cons == MAP_FAILED) { close(fd); return -1; }
  *prod = static_cast<uint64_t *>(
      mmap(nullptr, page, PROT_READ, MAP_SHARED, fd, page));
  if (*prod == MAP_FAILED) { close(fd); return -1; }
  *data = static_cast<uint8_t *>(
      mmap(nullptr, 2 * ring_size, PROT_READ, MAP_SHARED, fd, 2 * page));
  if (*data == MAP_FAILED) { close(fd); return -1; }
  return fd;
}

}  // namespace eps
}  // namespace juggler
#endif  // SRC_INCLUDE_EPS_RING_H_