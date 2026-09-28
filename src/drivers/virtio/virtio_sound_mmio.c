/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 virtio-sound playback backend. */

#include "arch/arm64/mmio.h"
#include "drivers/audio.h"
#include "drivers/virtio_net_mmio.h"
#include "drivers/virtio_sound_mmio.h"
#include "stdio.h"
#include "string.h"

#define SOUND_DEVICE_ID 25u
#define QUEUE_SIZE 64u
#define PCM_SLOTS 16u
#define PCM_BACKLOG_SLOTS 16u
#define QUEUE_CONTROL 0u
#define QUEUE_TX 2u
#define PCM_PERIOD_BYTES 1024u
#define PCM_BUFFER_BYTES (PCM_PERIOD_BYTES * (PCM_SLOTS + PCM_BACKLOG_SLOTS))
#define PCM_INFO 0x100u
#define PCM_SET_PARAMS 0x101u
#define PCM_PREPARE 0x102u
#define PCM_RELEASE 0x103u
#define PCM_START 0x104u
#define PCM_STOP 0x105u
#define SOUND_OK 0x8000u
#define DESC_NEXT 1u
#define DESC_WRITE 2u

#define REG_DEVICE_FEATURES 0x010u
#define REG_DEVICE_FEATURES_SEL 0x014u
#define REG_DRIVER_FEATURES 0x020u
#define REG_DRIVER_FEATURES_SEL 0x024u
#define REG_QUEUE_SEL 0x030u
#define REG_QUEUE_NUM_MAX 0x034u
#define REG_QUEUE_NUM 0x038u
#define REG_QUEUE_READY 0x044u
#define REG_QUEUE_NOTIFY 0x050u
#define REG_STATUS 0x070u
#define REG_QUEUE_DESC 0x080u
#define REG_QUEUE_AVAIL 0x090u
#define REG_QUEUE_USED 0x0a0u
#define REG_CONFIG 0x100u

typedef struct {
    uint64_t address;
    uint32_t length;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed)) sound_desc_t;

typedef struct {
    uint32_t id;
    uint32_t length;
} __attribute__((packed)) sound_used_element_t;

typedef struct {
    uint16_t flags;
    uint16_t index;
    uint16_t ring[QUEUE_SIZE];
    uint16_t used_event;
} __attribute__((packed, aligned(4096))) sound_avail_t;

typedef struct {
    uint16_t flags;
    uint16_t index;
    sound_used_element_t ring[QUEUE_SIZE];
    uint16_t avail_event;
} __attribute__((packed, aligned(4096))) sound_used_t;

typedef struct {
    sound_desc_t desc[QUEUE_SIZE] __attribute__((aligned(4096)));
    sound_avail_t avail;
    sound_used_t used;
    uint16_t last_used;
    uint16_t last_avail;
} sound_queue_t;

typedef struct {
    volatile uint8_t *mmio;
    sound_queue_t queue[4];
    uint8_t request[32] __attribute__((aligned(16)));
    uint8_t response[64] __attribute__((aligned(16)));
    uint32_t xfer_stream[PCM_SLOTS] __attribute__((aligned(16)));
    uint8_t pcm[PCM_SLOTS][PCM_PERIOD_BYTES] __attribute__((aligned(16)));
    uint32_t pcm_status[PCM_SLOTS][2] __attribute__((aligned(16)));
    uint8_t pcm_busy[PCM_SLOTS];
    uint32_t pending_bytes;
    uint32_t latency_bytes;
    uint8_t backlog[PCM_BACKLOG_SLOTS][PCM_PERIOD_BYTES];
    uint32_t backlog_head;
    uint32_t backlog_tail;
    uint32_t backlog_count;
    uint8_t staging[PCM_PERIOD_BYTES];
    uint32_t staged;
    uint32_t stream_id;
    volatile uint32_t lock;
    uint8_t ready;
    uint8_t prepared;
    uint8_t started;
} sound_device_t;

static sound_device_t g_sound __attribute__((aligned(4096)));

static uint32_t sound_read(uint32_t offset) {
    return *(volatile uint32_t *)(void *)(g_sound.mmio + offset);
}

static void sound_write(uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(void *)(g_sound.mmio + offset) = value;
}

static void sound_write_address(uint32_t offset, uint64_t address) {
    sound_write(offset, (uint32_t)address);
    sound_write(offset + 4u, (uint32_t)(address >> 32));
}

static uint64_t sound_counter(void) {
    uint64_t value;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(value));
    return value;
}

static uint64_t sound_frequency(void) {
    uint64_t value;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(value));
    return value;
}

static void sound_lock(void) {
    while (__atomic_exchange_n(&g_sound.lock, 1u, __ATOMIC_ACQUIRE))
        __asm__ __volatile__("yield");
}

static int sound_try_lock(void) {
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&g_sound.lock, &expected, 1u, 0,
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static void sound_unlock(void) {
    __atomic_store_n(&g_sound.lock, 0u, __ATOMIC_RELEASE);
}

static void sound_fail(void) {
    g_sound.ready = 0;
    sound_write(REG_STATUS, 0u);
    __asm__ __volatile__("dsb osh" ::: "memory");
}

static int sound_queue_init(uint32_t number) {
    sound_queue_t *queue = &g_sound.queue[number];
    sound_write(REG_QUEUE_SEL, number);
    if (sound_read(REG_QUEUE_READY) ||
        sound_read(REG_QUEUE_NUM_MAX) < QUEUE_SIZE)
        return -1;
    sound_write(REG_QUEUE_NUM, QUEUE_SIZE);
    sound_write_address(REG_QUEUE_DESC, (uint64_t)(uintptr_t)queue->desc);
    sound_write_address(REG_QUEUE_AVAIL, (uint64_t)(uintptr_t)&queue->avail);
    sound_write_address(REG_QUEUE_USED, (uint64_t)(uintptr_t)&queue->used);
    sound_write(REG_QUEUE_READY, 1u);
    return 0;
}

static int sound_submit(uint32_t number, uint32_t descriptors,
                        uint32_t timeout_ms) {
    sound_queue_t *queue = &g_sound.queue[number];
    uint64_t limit = sound_counter() +
                     sound_frequency() * timeout_ms / 1000u;
    uint16_t expected = (uint16_t)(queue->last_used + 1u);
    uint16_t published;

    if (!g_sound.ready || !descriptors || descriptors > QUEUE_SIZE)
        return -1;
    queue->desc[descriptors - 1u].flags &= (uint16_t)~DESC_NEXT;
    queue->avail.ring[queue->last_avail % QUEUE_SIZE] = 0u;
    __asm__ __volatile__("dmb oshst" ::: "memory");
    ++queue->last_avail;
    *(volatile uint16_t *)&queue->avail.index = queue->last_avail;
    __asm__ __volatile__("dmb oshst" ::: "memory");
    sound_write(REG_QUEUE_NOTIFY, number);

    do {
        published = *(volatile uint16_t *)&queue->used.index;
        if (published == expected) {
            __asm__ __volatile__("dmb oshld" ::: "memory");
            if (queue->used.ring[queue->last_used % QUEUE_SIZE].id != 0u)
                break;
            queue->last_used = expected;
            return 0;
        }
        if (published != queue->last_used) break;
        __asm__ __volatile__("yield");
    } while (sound_counter() < limit);

    printf("[virtio-sound] queue %u completion failed\n", number);
    sound_fail();
    return -1;
}

static void sound_descriptor(sound_queue_t *queue, uint32_t index,
                             void *buffer, uint32_t length, uint16_t flags) {
    queue->desc[index].address = (uint64_t)(uintptr_t)buffer;
    queue->desc[index].length = length;
    queue->desc[index].flags = flags;
    queue->desc[index].next = (uint16_t)(index + 1u);
}

static int sound_control(const void *request, uint32_t request_size,
                         void *result, uint32_t result_size) {
    sound_queue_t *queue = &g_sound.queue[QUEUE_CONTROL];
    if (request_size > sizeof(g_sound.request) ||
        result_size > sizeof(g_sound.response) || result_size < 4u)
        return -1;
    memset(g_sound.response, 0, sizeof(g_sound.response));
    memcpy(g_sound.request, request, request_size);
    sound_descriptor(queue, 0, g_sound.request, request_size, DESC_NEXT);
    sound_descriptor(queue, 1, g_sound.response, result_size, DESC_WRITE);
    if (sound_submit(QUEUE_CONTROL, 2u, 1000u) < 0 ||
        *(uint32_t *)g_sound.response != SOUND_OK)
        return -1;
    if (result) memcpy(result, g_sound.response, result_size);
    return 0;
}

static int sound_command(uint32_t command) {
    uint32_t request[2] = {command, g_sound.stream_id};
    return sound_control(request, sizeof(request), 0, 4u);
}

static int sound_prepare(void) {
    if (g_sound.prepared) return 0;
    if (sound_command(PCM_PREPARE) < 0) return -1;
    g_sound.prepared = 1;
    return 0;
}

static int sound_start(void) {
    if (g_sound.started) return 0;
    if (sound_prepare() < 0 || sound_command(PCM_START) < 0)
        return -1;
    g_sound.started = 1;
    return 0;
}

static int sound_reap_tx(void) {
    sound_queue_t *queue = &g_sound.queue[QUEUE_TX];
    uint16_t published = *(volatile uint16_t *)&queue->used.index;

    while (queue->last_used != published) {
        uint32_t id;
        uint32_t slot;
        __asm__ __volatile__("dmb oshld" ::: "memory");
        id = queue->used.ring[queue->last_used % QUEUE_SIZE].id;
        slot = id / 3u;
        if (id % 3u || slot >= PCM_SLOTS || !g_sound.pcm_busy[slot] ||
            g_sound.pcm_status[slot][0] != SOUND_OK ||
            g_sound.pending_bytes < PCM_PERIOD_BYTES) {
            printf("[virtio-sound] invalid playback completion id=%u\n", id);
            sound_fail();
            return -1;
        }
        g_sound.pcm_busy[slot] = 0;
        g_sound.pending_bytes -= PCM_PERIOD_BYTES;
        g_sound.latency_bytes = g_sound.pcm_status[slot][1];
        queue->last_used++;
        published = *(volatile uint16_t *)&queue->used.index;
    }
    return 0;
}

static int sound_wait_tx_empty(void) {
    uint64_t limit = sound_counter() + sound_frequency() * 2u;

    do {
        if (sound_reap_tx() < 0) return -1;
        if (!g_sound.pending_bytes) return 0;
        __asm__ __volatile__("yield");
    } while (sound_counter() < limit);
    printf("[virtio-sound] playback drain timeout\n");
    sound_fail();
    return -1;
}

static int sound_send_period(const uint8_t *period) {
    sound_queue_t *queue = &g_sound.queue[QUEUE_TX];
    uint32_t slot;
    uint32_t base;

    if (sound_prepare() < 0 || sound_reap_tx() < 0) return -1;
    for (slot = 0; slot < PCM_SLOTS; ++slot)
        if (!g_sound.pcm_busy[slot]) break;
    if (slot == PCM_SLOTS) return -1;
    base = slot * 3u;
    g_sound.xfer_stream[slot] = g_sound.stream_id;
    g_sound.pcm_status[slot][0] = 0u;
    g_sound.pcm_status[slot][1] = 0u;
    memcpy(g_sound.pcm[slot], period, PCM_PERIOD_BYTES);
    sound_descriptor(queue, base, &g_sound.xfer_stream[slot], 4u,
                     DESC_NEXT);
    sound_descriptor(queue, base + 1u, g_sound.pcm[slot], PCM_PERIOD_BYTES,
                     DESC_NEXT);
    sound_descriptor(queue, base + 2u, g_sound.pcm_status[slot], 8u,
                     DESC_WRITE);
    queue->desc[base + 2u].flags &= (uint16_t)~DESC_NEXT;
    queue->avail.ring[queue->last_avail % QUEUE_SIZE] = (uint16_t)base;
    g_sound.pcm_busy[slot] = 1;
    g_sound.pending_bytes += PCM_PERIOD_BYTES;
    __asm__ __volatile__("dmb oshst" ::: "memory");
    queue->last_avail++;
    *(volatile uint16_t *)&queue->avail.index = queue->last_avail;
    __asm__ __volatile__("dmb oshst" ::: "memory");
    sound_write(REG_QUEUE_NOTIFY, QUEUE_TX);
    return 0;
}

static int sound_flush_backlog(void) {
    if (sound_reap_tx() < 0) return -1;
    while (g_sound.backlog_count &&
           g_sound.pending_bytes < PCM_PERIOD_BYTES * PCM_SLOTS) {
        if (sound_send_period(g_sound.backlog[g_sound.backlog_head]) < 0)
            return -1;
        g_sound.backlog_head =
            (g_sound.backlog_head + 1u) % PCM_BACKLOG_SLOTS;
        g_sound.backlog_count--;
    }
    return 0;
}

static int sound_stage_period(void) {
    if (g_sound.backlog_count == PCM_BACKLOG_SLOTS) return -1;
    memcpy(g_sound.backlog[g_sound.backlog_tail], g_sound.staging,
           PCM_PERIOD_BYTES);
    g_sound.backlog_tail =
        (g_sound.backlog_tail + 1u) % PCM_BACKLOG_SLOTS;
    g_sound.backlog_count++;
    g_sound.staged = 0;
    if (sound_flush_backlog() < 0) return -1;
    if (!g_sound.started &&
        g_sound.pending_bytes +
            g_sound.backlog_count * PCM_PERIOD_BYTES == PCM_BUFFER_BYTES)
        return sound_start();
    return 0;
}

static int sound_pcm_write(const char *buffer, uint32_t length) {
    uint32_t done = 0;
    sound_lock();
    if (!g_sound.ready) {
        sound_unlock();
        return -1;
    }
    while (done < length) {
        if (sound_flush_backlog() < 0) {
            sound_unlock();
            return done ? (int)done : -1;
        }
        if (g_sound.pending_bytes +
                g_sound.backlog_count * PCM_PERIOD_BYTES +
                g_sound.staged >= PCM_BUFFER_BYTES) {
            sound_unlock();
            return done ? (int)done : -11;
        }
        uint32_t count = PCM_PERIOD_BYTES - g_sound.staged;
        if (count > length - done) count = length - done;
        if (count > PCM_BUFFER_BYTES - g_sound.pending_bytes -
                    g_sound.backlog_count * PCM_PERIOD_BYTES -
                    g_sound.staged)
            count = PCM_BUFFER_BYTES - g_sound.pending_bytes -
                    g_sound.backlog_count * PCM_PERIOD_BYTES -
                    g_sound.staged;
        memcpy(g_sound.staging + g_sound.staged, buffer + done, count);
        g_sound.staged += count;
        done += count;
        if (g_sound.staged == PCM_PERIOD_BYTES && sound_stage_period() < 0) {
            sound_unlock();
            return done > count ? (int)(done - count) : -1;
        }
    }
    sound_unlock();
    return (int)done;
}

static int sound_pcm_ready(void) {
    int ready;
    if (!sound_try_lock()) return 0;
    ready = g_sound.ready && sound_flush_backlog() == 0 &&
            g_sound.pending_bytes +
                g_sound.backlog_count * PCM_PERIOD_BYTES +
                g_sound.staged < PCM_BUFFER_BYTES;
    sound_unlock();
    return ready;
}

static int sound_pcm_geometry(uint8_t stream,
                              struct audio_pcm_geometry *geometry) {
    if (stream != AUDIO_STREAM_PLAYBACK || !geometry) return -1;
    memset(geometry, 0, sizeof(*geometry));
    geometry->rate = 48000u;
    geometry->channels = 2u;
    geometry->sample_bits = 16u;
    geometry->frame_bytes = 4u;
    geometry->period_bytes = PCM_PERIOD_BYTES;
    geometry->buffer_bytes = PCM_BUFFER_BYTES;
    sound_lock();
    if (sound_flush_backlog() < 0) {
        sound_unlock();
        return -1;
    }
    geometry->queued_bytes = g_sound.pending_bytes +
                             g_sound.backlog_count * PCM_PERIOD_BYTES +
                             g_sound.staged;
    geometry->latency_bytes = g_sound.latency_bytes;
    sound_unlock();
    return 0;
}

static int sound_pcm_control(uint8_t stream, uint8_t command) {
    int result = 0;
    if (stream != AUDIO_STREAM_PLAYBACK) return -1;
    sound_lock();
    if (!g_sound.ready) result = -1;
    else if (command == AUDIO_STREAM_COMMAND_START) {
        result = sound_start();
    } else if (command == AUDIO_STREAM_COMMAND_DRAIN) {
        if (g_sound.staged) {
            memset(g_sound.staging + g_sound.staged, 0,
                   PCM_PERIOD_BYTES - g_sound.staged);
            result = sound_stage_period();
        }
        if (result == 0 && (g_sound.pending_bytes || g_sound.backlog_count) &&
            !g_sound.started)
            result = sound_start();
        if (result == 0) {
            uint64_t limit = sound_counter() + sound_frequency() * 2u;
            while (g_sound.backlog_count && sound_counter() < limit) {
                result = sound_flush_backlog();
                if (result < 0) break;
                __asm__ __volatile__("yield");
            }
            if (g_sound.backlog_count) result = -1;
        }
        if (result == 0) result = sound_wait_tx_empty();
    } else if (command == AUDIO_STREAM_COMMAND_STOP ||
               command == AUDIO_STREAM_COMMAND_RESET) {
        if (g_sound.started) result = sound_command(PCM_STOP);
        g_sound.started = 0;
        if (result == 0 && g_sound.prepared)
            result = sound_command(PCM_RELEASE);
        if (result == 0) result = sound_wait_tx_empty();
        g_sound.prepared = 0;
        g_sound.staged = 0;
        g_sound.latency_bytes = 0;
        g_sound.backlog_head = 0;
        g_sound.backlog_tail = 0;
        g_sound.backlog_count = 0;
        if (result == 0 && command == AUDIO_STREAM_COMMAND_RESET)
            result = sound_prepare();
    } else result = -1;
    sound_unlock();
    return result;
}

int edgeos_arm64_virtio_sound_init(const edgeos_arm64_bootinfo_t *bootinfo) {
    uint64_t base;
    uint32_t features;
    uint32_t streams;
    uint32_t info_request[4];
    struct {
        uint32_t status;
        uint32_t hda_nid;
        uint32_t features;
        uint64_t formats;
        uint64_t rates;
        uint8_t direction;
        uint8_t channels_min;
        uint8_t channels_max;
        uint8_t padding[5];
    } __attribute__((packed)) info;
    struct {
        uint32_t code, stream_id;
        uint32_t buffer_bytes, period_bytes, features;
        uint8_t channels, format, rate, padding;
    } __attribute__((packed)) params;
    struct audio_backend backend;

    if (edgeos_arm64_virtio_mmio_find(bootinfo, SOUND_DEVICE_ID, &base) < 0)
        return -1;
    memset(&g_sound, 0, sizeof(g_sound));
    g_sound.mmio = (volatile uint8_t *)edgeos_arm64_mmio_alias(base);
    sound_write(REG_STATUS, 0u);
    sound_write(REG_STATUS, 1u | 2u);
    sound_write(REG_DEVICE_FEATURES_SEL, 1u);
    features = sound_read(REG_DEVICE_FEATURES);
    if (!(features & 1u)) goto fail;
    sound_write(REG_DRIVER_FEATURES_SEL, 0u);
    sound_write(REG_DRIVER_FEATURES, 0u);
    sound_write(REG_DRIVER_FEATURES_SEL, 1u);
    sound_write(REG_DRIVER_FEATURES, 1u);
    sound_write(REG_STATUS, sound_read(REG_STATUS) | 8u);
    if (!(sound_read(REG_STATUS) & 8u)) goto fail;
    streams = sound_read(REG_CONFIG + 4u);
    if (!streams || streams > 32u) goto fail;
    for (uint32_t queue = 0; queue < 4u; ++queue)
        if (sound_queue_init(queue) < 0) goto fail;
    sound_write(REG_STATUS, sound_read(REG_STATUS) | 4u);
    g_sound.ready = 1;

    for (uint32_t id = 0; id < streams; ++id) {
        info_request[0] = PCM_INFO;
        info_request[1] = id;
        info_request[2] = 1u;
        info_request[3] = sizeof(info) - 4u;
        if (sound_control(info_request, sizeof(info_request),
                          &info, sizeof(info)) < 0)
            goto fail;
        if (info.direction == 0u &&
            info.channels_min <= 2u && info.channels_max >= 2u &&
            (info.formats & (1ull << 5u)) &&
            (info.rates & (1ull << 7u))) {
            g_sound.stream_id = id;
            break;
        }
        if (id + 1u == streams) goto fail;
    }

    memset(&params, 0, sizeof(params));
    params.code = PCM_SET_PARAMS;
    params.stream_id = g_sound.stream_id;
    params.buffer_bytes = PCM_BUFFER_BYTES;
    params.period_bytes = PCM_PERIOD_BYTES;
    params.channels = 2u;
    params.format = 5u;
    params.rate = 7u;
    if (sound_control(&params, sizeof(params), 0, 4u) < 0 ||
        sound_prepare() < 0)
        goto fail;

    memset(&backend, 0, sizeof(backend));
    backend.name = "VirtIO Sound";
    backend.kind = AUDIO_BACKEND_VIRTIO_SOUND;
    backend.write_pcm = sound_pcm_write;
    backend.playback_ready = sound_pcm_ready;
    backend.stream_control = sound_pcm_control;
    backend.pcm_geometry = sound_pcm_geometry;
    if (audio_register_backend(&backend) < 0) goto fail;
    printf("[virtio-sound] playback ready stream=%u base=0x%x\n",
           g_sound.stream_id, (uint32_t)base);
    return 0;

fail:
    printf("[virtio-sound] playback initialization failed\n");
    sound_fail();
    return -1;
}
