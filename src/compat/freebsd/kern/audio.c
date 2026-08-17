/* SPDX-License-Identifier: MPL-2.0 */
/*
 * FreeBSD PCM and mixer service boundary for unmodified BSD audio drivers.
 *
 * The imported driver owns device discovery, format negotiation, mixer
 * requests, and hardware transfers.  This file owns the shared EdgeOS PCM
 * rings and connects them to the single Linux-compatible audio front-end.
 */

#include <dev/sound/pcm/sound.h>

#include "channel_if.h"
#include "mixer_if.h"

#include "compat/freebsd/edgeos/audio.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "drivers/audio.h"

#define BSD_AUDIO_MAX_DEVICES 16u
#define BSD_AUDIO_DEFAULT_RATE 48000u
#define BSD_AUDIO_DEFAULT_CHANNELS 2u
#define BSD_AUDIO_DEFAULT_BLOCK 4096u
#define BSD_AUDIO_EAGAIN 11
#define BSD_AUDIO_EINVAL 22
#define BSD_AUDIO_ENODEV 19
#define BSD_AUDIO_ENOMEM 12
#define BSD_AUDIO_ENXIO 6

int snd_unit = -1;
int snd_verbose = 1;

struct bsd_audio_channel {
    struct pcm_channel pcm;
    struct snd_dbuf buffer;
    uint32_t producer;
    uint32_t consumer;
    uint32_t queued;
    uint32_t hardware_position;
    uint8_t started;
    uint8_t configured;
};

struct bsd_audio_device {
    device_t dev;
    struct snddev_info *info;
    struct snd_mixer *mixer;
    struct bsd_audio_channel *playback;
    struct bsd_audio_channel *capture;
    uint8_t initialized;
    uint8_t registered;
    uint8_t backend_registered;
    char identity[96];
};

static struct bsd_audio_device g_audio_devices[BSD_AUDIO_MAX_DEVICES];
static struct bsd_audio_device *g_primary_audio_device;
static volatile unsigned int g_audio_devices_guard;

static int bsd_audio_mixer_set_locked(struct snd_mixer *mixer,
    unsigned int device, unsigned int left, unsigned int right);

static void
bsd_audio_guard_lock(void)
{
    while (__atomic_test_and_set(&g_audio_devices_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
bsd_audio_guard_unlock(void)
{
    __atomic_clear(&g_audio_devices_guard, __ATOMIC_RELEASE);
}

static struct bsd_audio_device *
bsd_audio_device_lookup(device_t dev, int allocate)
{
    struct bsd_audio_device *free_entry = NULL;

    if (!dev)
        return NULL;
    bsd_audio_guard_lock();
    for (unsigned int index = 0; index < BSD_AUDIO_MAX_DEVICES; ++index) {
        if (g_audio_devices[index].dev == dev) {
            bsd_audio_guard_unlock();
            return &g_audio_devices[index];
        }
        if (!free_entry && !g_audio_devices[index].dev)
            free_entry = &g_audio_devices[index];
    }
    if (allocate && free_entry) {
        bsd_memset(free_entry, 0, sizeof(*free_entry));
        free_entry->dev = dev;
    } else {
        free_entry = NULL;
    }
    bsd_audio_guard_unlock();
    return free_entry;
}

static void
bsd_audio_info_initialize(struct bsd_audio_device *entry)
{
    struct snddev_info *info;

    if (!entry || entry->initialized)
        return;
    info = device_get_softc(entry->dev);
    if (!info)
        return;
    entry->info = info;
    bsd_memset(info, 0, sizeof(*info));
    info->dev = entry->dev;
    SLIST_INIT(&info->channels.pcm.head);
    SLIST_INIT(&info->channels.pcm.busy.head);
    SLIST_INIT(&info->channels.pcm.opened.head);
    SLIST_INIT(&info->channels.pcm.primary.head);
    mtx_init(&info->lock, "bsd pcm", NULL, MTX_DEF);
    cv_init(&info->cv, "bsd pcm");
    entry->initialized = 1;
}

static uint32_t
bsd_audio_ring_distance(uint32_t current, uint32_t previous, uint32_t size)
{
    if (!size)
        return 0;
    if (current >= size)
        current %= size;
    if (previous >= size)
        previous %= size;
    return current >= previous ? current - previous :
        size - previous + current;
}

static void
bsd_audio_ring_copy_in(struct bsd_audio_channel *channel,
    const uint8_t *source, uint32_t length)
{
    uint32_t first;

    first = channel->buffer.bufsize - channel->producer;
    if (first > length)
        first = length;
    bsd_memcpy(channel->buffer.buf + channel->producer, source, first);
    if (length > first)
        bsd_memcpy(channel->buffer.buf, source + first, length - first);
    channel->producer = (channel->producer + length) %
        channel->buffer.bufsize;
}

static void
bsd_audio_ring_copy_out(struct bsd_audio_channel *channel,
    uint8_t *destination, uint32_t length)
{
    uint32_t first;

    first = channel->buffer.bufsize - channel->consumer;
    if (first > length)
        first = length;
    bsd_memcpy(destination, channel->buffer.buf + channel->consumer, first);
    if (length > first)
        bsd_memcpy(destination + first, channel->buffer.buf, length - first);
    channel->consumer = (channel->consumer + length) %
        channel->buffer.bufsize;
}

static void
bsd_audio_ring_clear(struct bsd_audio_channel *channel, uint32_t start,
    uint32_t length)
{
    uint32_t first;

    if (!channel || !channel->buffer.buf || !channel->buffer.bufsize ||
        !length)
        return;
    start %= channel->buffer.bufsize;
    first = channel->buffer.bufsize - start;
    if (first > length)
        first = length;
    bsd_memset(channel->buffer.buf + start, 0, first);
    if (length > first)
        bsd_memset(channel->buffer.buf, 0, length - first);
}

static int
bsd_audio_format_supported(struct pcmchan_caps *caps, uint32_t format)
{
    uint32_t *candidate;

    if (!caps || !caps->fmtlist)
        return 0;
    for (candidate = caps->fmtlist; *candidate; ++candidate) {
        if (*candidate == format)
            return 1;
    }
    return 0;
}

static int
bsd_audio_channel_configure(struct bsd_audio_channel *channel)
{
    struct pcmchan_caps *caps;
    uint32_t format;
    uint32_t speed;
    uint32_t block;

    if (!channel || !channel->pcm.methods || !channel->pcm.devinfo)
        return BSD_AUDIO_EINVAL;
    format = SND_FORMAT(AFMT_S16_LE, BSD_AUDIO_DEFAULT_CHANNELS, 0);
    caps = CHANNEL_GETCAPS(channel->pcm.methods, channel->pcm.devinfo);
    if (!bsd_audio_format_supported(caps, format))
        return BSD_AUDIO_ENODEV;
    speed = BSD_AUDIO_DEFAULT_RATE;
    if (caps) {
        if (speed < caps->minspeed)
            speed = caps->minspeed;
        if (speed > caps->maxspeed)
            speed = caps->maxspeed;
    }
    speed = CHANNEL_SETSPEED(channel->pcm.methods, channel->pcm.devinfo,
        speed);
    if (!speed)
        return BSD_AUDIO_ENODEV;
    if (CHANNEL_SETFORMAT(channel->pcm.methods, channel->pcm.devinfo,
        format) != 0)
        return BSD_AUDIO_ENODEV;
    block = BSD_AUDIO_DEFAULT_BLOCK;
    if (channel->buffer.bufsize && block > channel->buffer.bufsize / 2u)
        block = channel->buffer.bufsize / 2u;
    if (block < AFMT_ALIGN(format))
        block = AFMT_ALIGN(format);
    block = CHANNEL_SETBLOCKSIZE(channel->pcm.methods,
        channel->pcm.devinfo, block);
    if (!block || !channel->buffer.buf || !channel->buffer.bufsize)
        return BSD_AUDIO_ENODEV;
    channel->pcm.format = format;
    channel->pcm.speed = speed;
    channel->pcm.align = AFMT_ALIGN(format);
    channel->buffer.fmt = format;
    channel->buffer.spd = speed;
    channel->buffer.bps = AFMT_BPS(format);
    channel->buffer.align = AFMT_ALIGN(format);
    channel->buffer.blksz = block;
    channel->buffer.blkcnt = channel->buffer.bufsize / block;
    if (channel->buffer.blkcnt < 2u)
        channel->buffer.blkcnt = 2u;
    channel->configured = 1;
    return 0;
}

static int
bsd_audio_channel_start(struct bsd_audio_channel *channel)
{
    int result;

    if (!channel)
        return BSD_AUDIO_ENODEV;
    mtx_lock(&channel->pcm.lock);
    if (channel->started) {
        mtx_unlock(&channel->pcm.lock);
        return 0;
    }
    if (!channel->configured) {
        mtx_unlock(&channel->pcm.lock);
        return BSD_AUDIO_ENODEV;
    }
    channel->hardware_position = CHANNEL_GETPTR(channel->pcm.methods,
        channel->pcm.devinfo);
    channel->started = 1;
    channel->pcm.trigger = PCMTRIG_START;
    channel->pcm.flags |= CHN_F_RUNNING | CHN_F_TRIGGERED;
    sndbuf_setrun(&channel->buffer, 1);
    mtx_unlock(&channel->pcm.lock);

    result = CHANNEL_TRIGGER(channel->pcm.methods, channel->pcm.devinfo,
        PCMTRIG_START);
    if (result != 0) {
        mtx_lock(&channel->pcm.lock);
        channel->started = 0;
        channel->pcm.trigger = PCMTRIG_STOP;
        channel->pcm.flags &= ~(CHN_F_RUNNING | CHN_F_TRIGGERED);
        sndbuf_setrun(&channel->buffer, 0);
        mtx_unlock(&channel->pcm.lock);
    }
    return result;
}

static void
bsd_audio_channel_stop(struct bsd_audio_channel *channel)
{
    int stop;

    if (!channel)
        return;
    mtx_lock(&channel->pcm.lock);
    stop = channel->started;
    channel->started = 0;
    channel->pcm.trigger = PCMTRIG_STOP;
    channel->pcm.flags &= ~(CHN_F_RUNNING | CHN_F_TRIGGERED);
    sndbuf_setrun(&channel->buffer, 0);
    mtx_unlock(&channel->pcm.lock);
    if (stop)
        (void)CHANNEL_TRIGGER(channel->pcm.methods, channel->pcm.devinfo,
            PCMTRIG_STOP);
}

static void
bsd_audio_channel_destroy(struct bsd_audio_channel *channel)
{
    if (!channel)
        return;
    bsd_audio_channel_stop(channel);
    if (channel->pcm.devinfo)
        (void)CHANNEL_FREE(channel->pcm.methods, channel->pcm.devinfo);
    sndbuf_free(&channel->buffer);
    if (channel->pcm.methods)
        kobj_delete(channel->pcm.methods, M_DEVBUF);
    cv_destroy(&channel->pcm.intr_cv);
    cv_destroy(&channel->pcm.cv);
    mtx_destroy(&channel->pcm.lock);
    bsd_free(channel, M_DEVBUF);
}

static struct bsd_audio_channel *
bsd_audio_channel_create(struct bsd_audio_device *entry, int direction,
    kobj_class_t cls, void *devinfo)
{
    struct bsd_audio_channel *channel;
    const char *suffix;

    channel = bsd_malloc(sizeof(*channel), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!channel)
        return NULL;
    channel->pcm.methods = kobj_create(cls, M_DEVBUF, M_WAITOK | M_ZERO);
    if (!channel->pcm.methods) {
        bsd_free(channel, M_DEVBUF);
        return NULL;
    }
    channel->pcm.direction = direction;
    channel->pcm.type = direction;
    channel->pcm.speed = BSD_AUDIO_DEFAULT_RATE;
    channel->pcm.format = SND_FORMAT(AFMT_S16_LE,
        BSD_AUDIO_DEFAULT_CHANNELS, 0);
    channel->pcm.align = AFMT_ALIGN(channel->pcm.format);
    channel->pcm.parentsnddev = entry->info;
    channel->pcm.dev = entry->dev;
    channel->pcm.pid = -1;
    channel->pcm.trigger = PCMTRIG_STOP;
    suffix = direction == PCMDIR_PLAY ? "playback" : "capture";
    bsd_snprintf(channel->pcm.name, sizeof(channel->pcm.name), "pcm%d.%s",
        device_get_unit(entry->dev), suffix);
    bsd_strlcpy(channel->pcm.comm, CHN_COMM_UNUSED,
        sizeof(channel->pcm.comm));
    mtx_init(&channel->pcm.lock, channel->pcm.name, NULL, MTX_DEF);
    cv_init(&channel->pcm.intr_cv, "bsd pcm intr");
    cv_init(&channel->pcm.cv, "bsd pcm state");
    channel->pcm.bufhard = &channel->buffer;
    channel->buffer.channel = &channel->pcm;
    channel->buffer.fmt = channel->pcm.format;
    channel->buffer.spd = channel->pcm.speed;
    channel->buffer.bps = AFMT_BPS(channel->pcm.format);
    channel->buffer.align = AFMT_ALIGN(channel->pcm.format);
    channel->pcm.devinfo = CHANNEL_INIT(channel->pcm.methods, devinfo,
        &channel->buffer, &channel->pcm, direction);
    if (!channel->pcm.devinfo ||
        bsd_audio_channel_configure(channel) != 0) {
        bsd_audio_channel_destroy(channel);
        return NULL;
    }
    return channel;
}

static int
bsd_audio_backend_write(const char *buffer, uint32_t length)
{
    return bsd_audio_playback_write(buffer, length);
}

static int
bsd_audio_backend_read(char *buffer, uint32_t length)
{
    return bsd_audio_capture_read(buffer, length);
}

static int
bsd_audio_backend_capture_ready(void)
{
    return bsd_audio_capture_ready();
}

static int
bsd_audio_backend_playback_ready(void)
{
    struct bsd_audio_channel *channel;
    int ready;

    if (!g_primary_audio_device || !g_primary_audio_device->playback)
        return 0;
    channel = g_primary_audio_device->playback;
    mtx_lock(&channel->pcm.lock);
    ready = channel->buffer.bufsize - channel->queued >=
        channel->pcm.align;
    mtx_unlock(&channel->pcm.lock);
    return ready;
}

static int
bsd_audio_backend_stream_control(uint8_t stream, uint8_t command)
{
    return bsd_audio_stream_control(stream, command);
}

static int
bsd_audio_backend_geometry(uint8_t stream,
    struct audio_pcm_geometry *geometry)
{
    struct bsd_audio_channel *channel;
    uint32_t channels;
    uint32_t sample_bytes;

    if (!geometry || !g_primary_audio_device)
        return -BSD_AUDIO_EINVAL;
    if (stream == AUDIO_STREAM_PLAYBACK)
        channel = g_primary_audio_device->playback;
    else if (stream == AUDIO_STREAM_CAPTURE)
        channel = g_primary_audio_device->capture;
    else
        return -BSD_AUDIO_EINVAL;
    if (!channel)
        return -BSD_AUDIO_ENODEV;

    mtx_lock(&channel->pcm.lock);
    channels = AFMT_CHANNEL(channel->pcm.format);
    sample_bytes = AFMT_BPS(channel->pcm.format);
    bsd_memset(geometry, 0, sizeof(*geometry));
    geometry->rate = channel->pcm.speed;
    geometry->channels = channels;
    geometry->sample_bits = sample_bytes * 8u;
    geometry->frame_bytes = channel->pcm.align;
    geometry->period_bytes = channel->buffer.blksz;
    geometry->buffer_bytes = channel->buffer.bufsize;
    geometry->queued_bytes = channel->queued;
    mtx_unlock(&channel->pcm.lock);
    if (!geometry->rate || !geometry->channels ||
        !geometry->sample_bits || !geometry->frame_bytes ||
        !geometry->period_bytes || !geometry->buffer_bytes)
        return -BSD_AUDIO_ENODEV;
    return 0;
}

static void
bsd_audio_backend_set_control(uint8_t muted, uint8_t left_percent,
    uint8_t right_percent)
{
    bsd_audio_set_playback_control(muted, left_percent, right_percent);
}

static void
bsd_audio_register_frontend(struct bsd_audio_device *entry)
{
    struct audio_backend backend;

    if (!entry || entry->backend_registered ||
        (!entry->playback && !entry->capture))
        return;
    bsd_memset(&backend, 0, sizeof(backend));
    backend.name = entry->identity;
    backend.kind = AUDIO_BACKEND_UAC;
    if (entry->playback) {
        backend.write_pcm = bsd_audio_backend_write;
        backend.playback_ready = bsd_audio_backend_playback_ready;
    }
    if (entry->capture) {
        backend.read_pcm = bsd_audio_backend_read;
        backend.capture_ready = bsd_audio_backend_capture_ready;
    }
    backend.stream_control = bsd_audio_backend_stream_control;
    backend.pcm_geometry = bsd_audio_backend_geometry;
    backend.set_playback_control = bsd_audio_backend_set_control;
    if (audio_register_backend(&backend) == 0) {
        entry->backend_registered = 1;
        g_primary_audio_device = entry;
    }
}

static void
bsd_audio_unregister_frontend(struct bsd_audio_device *entry)
{
    if (entry && entry->backend_registered) {
        audio_unregister_backend(AUDIO_BACKEND_UAC);
        entry->backend_registered = 0;
    }
    if (g_primary_audio_device == entry)
        g_primary_audio_device = NULL;
}

static void
bsd_audio_sndbuf_setmap(void *argument, bus_dma_segment_t *segments,
    int segment_count, int error)
{
    struct snd_dbuf *buffer = argument;

    if (!buffer)
        return;
    if (error == 0 && segments && segment_count > 0)
        buffer->buf_addr = segments[0].ds_addr;
    else
        buffer->buf_addr = 0;
}

int
snd_setup_intr(device_t dev, struct resource *resource, int flags,
    driver_intr_t handler, void *argument, void **cookie)
{
    struct snddev_info *info;

    flags &= INTR_MPSAFE;
    flags |= INTR_TYPE_AV;
    info = dev ? device_get_softc(dev) : NULL;
    if (info && (flags & INTR_MPSAFE))
        info->flags |= SD_F_MPSAFE;
    return bus_setup_intr(dev, resource, flags, NULL, handler, argument,
        cookie);
}

int
sndbuf_alloc(struct snd_dbuf *buffer, bus_dma_tag_t dma_tag, int dma_flags,
    unsigned int size)
{
    int result;

    if (!buffer || !dma_tag || size < 32u)
        return BSD_AUDIO_EINVAL;
    if (buffer->buf)
        sndbuf_free(buffer);
    buffer->dmatag = dma_tag;
    buffer->dmaflags = dma_flags | BUS_DMA_NOWAIT | BUS_DMA_COHERENT |
        BUS_DMA_ZERO;
    buffer->maxsize = size;
    buffer->bufsize = size;
    buffer->allocsize = size;
    buffer->buf_addr = 0;
    buffer->flags |= SNDBUF_F_MANAGED;
    result = bus_dmamem_alloc(buffer->dmatag, (void **)&buffer->buf,
        buffer->dmaflags, &buffer->dmamap);
    if (result != 0) {
        sndbuf_free(buffer);
        return BSD_AUDIO_ENOMEM;
    }
    result = bus_dmamap_load(buffer->dmatag, buffer->dmamap, buffer->buf,
        buffer->maxsize, bsd_audio_sndbuf_setmap, buffer,
        BUS_DMA_NOWAIT);
    if (result != 0 || buffer->buf_addr == 0) {
        sndbuf_free(buffer);
        return BSD_AUDIO_ENOMEM;
    }
    result = sndbuf_resize(buffer, 2u, size / 2u);
    if (result != 0)
        sndbuf_free(buffer);
    return result;
}

int
sndbuf_setup(struct snd_dbuf *buffer, void *storage, unsigned int size)
{
    if (!buffer)
        return BSD_AUDIO_EINVAL;
    if ((!storage && size) || (storage && size < 32u))
        return BSD_AUDIO_EINVAL;
    buffer->flags &= ~SNDBUF_F_MANAGED;
    buffer->buf = storage;
    buffer->bufsize = size;
    buffer->maxsize = size;
    buffer->allocsize = size;
    buffer->dmatag = NULL;
    buffer->dmamap = NULL;
    buffer->buf_addr = 0;
    if (!storage)
        return 0;
    return sndbuf_resize(buffer, 2u, size / 2u);
}

void
sndbuf_free(struct snd_dbuf *buffer)
{
    if (!buffer)
        return;
    if (buffer->tmpbuf)
        bsd_free(buffer->tmpbuf, M_DEVBUF);
    if (buffer->shadbuf)
        bsd_free(buffer->shadbuf, M_DEVBUF);
    if (buffer->buf && (buffer->flags & SNDBUF_F_MANAGED)) {
        if (buffer->dmatag && buffer->dmamap && buffer->buf_addr)
            bus_dmamap_unload(buffer->dmatag, buffer->dmamap);
        if (buffer->dmatag && buffer->dmamap)
            bus_dmamem_free(buffer->dmatag, buffer->buf,
                buffer->dmamap);
    }
    buffer->tmpbuf = NULL;
    buffer->shadbuf = NULL;
    buffer->buf = NULL;
    buffer->sl = 0;
    buffer->dl = 0;
    buffer->rp = 0;
    buffer->rl = 0;
    buffer->hp = 0;
    buffer->total = 0;
    buffer->prev_total = 0;
    buffer->bufsize = 0;
    buffer->maxsize = 0;
    buffer->allocsize = 0;
    buffer->blksz = 0;
    buffer->blkcnt = 0;
    buffer->buf_addr = 0;
    buffer->dmatag = NULL;
    buffer->dmamap = NULL;
    buffer->flags &= ~SNDBUF_F_MANAGED;
}

int
sndbuf_resize(struct snd_dbuf *buffer, unsigned int block_count,
    unsigned int block_size)
{
    uint64_t total_size;

    if (!buffer)
        return BSD_AUDIO_EINVAL;
    if (buffer->channel)
        mtx_lock(&buffer->channel->lock);
    if (block_count == 0)
        block_count = buffer->blkcnt;
    if (block_size == 0)
        block_size = buffer->blksz;
    total_size = (uint64_t)block_count * block_size;
    if (buffer->maxsize == 0) {
        if (buffer->channel)
            mtx_unlock(&buffer->channel->lock);
        return 0;
    }
    if (block_count < 2u || block_size < 16u ||
        total_size > buffer->maxsize) {
        if (buffer->channel)
            mtx_unlock(&buffer->channel->lock);
        return BSD_AUDIO_EINVAL;
    }
    buffer->blkcnt = block_count;
    buffer->blksz = block_size;
    buffer->bufsize = (unsigned int)total_size;
    buffer->dl = 0;
    buffer->rp = 0;
    buffer->rl = 0;
    buffer->hp = 0;
    buffer->total = 0;
    buffer->prev_total = 0;
    buffer->xrun = 0;
    if (buffer->buf)
        bsd_memset(buffer->buf, 0, buffer->bufsize);
    if (buffer->channel)
        mtx_unlock(&buffer->channel->lock);
    return 0;
}

unsigned int
sndbuf_runsz(struct snd_dbuf *buffer)
{
    return buffer ? (unsigned int)buffer->dl : 0;
}

void
sndbuf_setrun(struct snd_dbuf *buffer, int running)
{
    if (buffer)
        buffer->dl = running ? (int)buffer->blksz : 0;
}

unsigned int
sndbuf_getfree(struct snd_dbuf *buffer)
{
    if (!buffer || buffer->rl < 0 || (unsigned int)buffer->rl >
        buffer->bufsize)
        return 0;
    return buffer->bufsize - (unsigned int)buffer->rl;
}

unsigned int
sndbuf_getfreeptr(struct snd_dbuf *buffer)
{
    if (!buffer || !buffer->bufsize || buffer->rp < 0 || buffer->rl < 0 ||
        (unsigned int)buffer->rp > buffer->bufsize ||
        (unsigned int)buffer->rl > buffer->bufsize)
        return 0;
    return ((unsigned int)buffer->rp + (unsigned int)buffer->rl) %
        buffer->bufsize;
}

unsigned int
sndbuf_getready(struct snd_dbuf *buffer)
{
    if (!buffer || buffer->rl < 0 || (unsigned int)buffer->rl >
        buffer->bufsize)
        return 0;
    return (unsigned int)buffer->rl;
}

unsigned int
sndbuf_getreadyptr(struct snd_dbuf *buffer)
{
    if (!buffer || buffer->rp < 0 || (unsigned int)buffer->rp >
        buffer->bufsize)
        return 0;
    return (unsigned int)buffer->rp;
}

void
pcm_init(device_t dev, void *devinfo)
{
    struct bsd_audio_device *entry;

    entry = bsd_audio_device_lookup(dev, 1);
    if (!entry)
        return;
    bsd_audio_info_initialize(entry);
    if (entry->info)
        entry->info->devinfo = devinfo;
}

int
pcm_addchan(device_t dev, int direction, kobj_class_t cls, void *devinfo)
{
    struct bsd_audio_device *entry;
    struct bsd_audio_channel *channel;

    if (direction != PCMDIR_PLAY && direction != PCMDIR_REC)
        return BSD_AUDIO_EINVAL;
    entry = bsd_audio_device_lookup(dev, 1);
    if (!entry)
        return BSD_AUDIO_ENOMEM;
    bsd_audio_info_initialize(entry);
    if (!entry->info)
        return BSD_AUDIO_ENODEV;
    if ((direction == PCMDIR_PLAY && entry->playback) ||
        (direction == PCMDIR_REC && entry->capture))
        return BSD_AUDIO_EINVAL;
    channel = bsd_audio_channel_create(entry, direction, cls, devinfo);
    if (!channel)
        return BSD_AUDIO_ENODEV;

    mtx_lock(&entry->info->lock);
    SLIST_INSERT_HEAD(&entry->info->channels.pcm.head, &channel->pcm,
        channels.pcm.link);
    SLIST_INSERT_HEAD(&entry->info->channels.pcm.primary.head, &channel->pcm,
        channels.pcm.primary.link);
    if (direction == PCMDIR_PLAY) {
        entry->playback = channel;
        entry->info->playcount++;
    } else {
        entry->capture = channel;
        entry->info->reccount++;
    }
    mtx_unlock(&entry->info->lock);
    return 0;
}

int
pcm_register(device_t dev, char *status)
{
    struct bsd_audio_device *entry;
    const char *description;

    entry = bsd_audio_device_lookup(dev, 0);
    if (!entry || !entry->info ||
        (!entry->playback && !entry->capture))
        return BSD_AUDIO_ENODEV;
    description = device_get_desc(dev);
    if (!description || !description[0])
        description = device_get_nameunit(dev);
    bsd_snprintf(entry->identity, sizeof(entry->identity),
        "FreeBSD Audio: %s", description ? description : "pcm");
    if (status)
        bsd_strlcpy(entry->info->status, status,
            sizeof(entry->info->status));
    entry->info->flags |= SD_F_REGISTERED;
    entry->registered = 1;
    bsd_audio_register_frontend(entry);
    device_printf(dev, "%s playback=%s capture=%s\n", entry->identity,
        entry->playback ? "ready" : "none",
        entry->capture ? "ready" : "none");
    return 0;
}

int
pcm_unregister(device_t dev)
{
    struct bsd_audio_device *entry;

    entry = bsd_audio_device_lookup(dev, 0);
    if (!entry)
        return BSD_AUDIO_ENODEV;
    bsd_audio_unregister_frontend(entry);
    bsd_audio_channel_destroy(entry->playback);
    bsd_audio_channel_destroy(entry->capture);
    entry->playback = NULL;
    entry->capture = NULL;
    if (entry->mixer)
        (void)mixer_uninit(dev);
    if (entry->info) {
        entry->info->flags &= ~SD_F_REGISTERED;
        entry->info->playcount = 0;
        entry->info->reccount = 0;
        cv_destroy(&entry->info->cv);
        mtx_destroy(&entry->info->lock);
    }
    bsd_audio_guard_lock();
    bsd_memset(entry, 0, sizeof(*entry));
    bsd_audio_guard_unlock();
    return 0;
}

u_int32_t
pcm_getflags(device_t dev)
{
    struct bsd_audio_device *entry = bsd_audio_device_lookup(dev, 0);

    return entry && entry->info ? entry->info->flags : 0;
}

void
pcm_setflags(device_t dev, u_int32_t value)
{
    struct bsd_audio_device *entry = bsd_audio_device_lookup(dev, 0);

    if (entry && entry->info)
        entry->info->flags = value;
}

void *
pcm_getdevinfo(device_t dev)
{
    struct bsd_audio_device *entry = bsd_audio_device_lookup(dev, 0);

    return entry && entry->info ? entry->info->devinfo : NULL;
}

unsigned int
pcm_getbuffersize(device_t dev, unsigned int minimum,
    unsigned int preferred, unsigned int maximum)
{
    (void)dev;
    if (preferred < minimum)
        preferred = minimum;
    if (maximum && preferred > maximum)
        preferred = maximum;
    return preferred;
}

void
chn_intr(struct pcm_channel *pcm)
{
    struct bsd_audio_channel *channel;
    uint32_t current;
    uint32_t completed;

    if (!pcm || !pcm->bufhard || !pcm->bufhard->bufsize)
        return;
    channel = (struct bsd_audio_channel *)pcm;
    mtx_lock(&pcm->lock);
    current = CHANNEL_GETPTR(pcm->methods, pcm->devinfo);
    completed = bsd_audio_ring_distance(current,
        channel->hardware_position, channel->buffer.bufsize);
    if (completed) {
        if (pcm->direction == PCMDIR_PLAY) {
            bsd_audio_ring_clear(channel, channel->hardware_position,
                completed);
            if (completed >= channel->queued) {
                if (completed > channel->queued)
                    pcm->xruns++;
                channel->queued = 0;
                channel->consumer = current % channel->buffer.bufsize;
                if (!channel->queued)
                    channel->producer = channel->consumer;
            } else {
                channel->queued -= completed;
                channel->consumer = current % channel->buffer.bufsize;
            }
        } else {
            uint32_t free_space = channel->buffer.bufsize - channel->queued;
            if (completed > free_space) {
                uint32_t overflow = completed - free_space;
                channel->consumer = (channel->consumer + overflow) %
                    channel->buffer.bufsize;
                channel->queued = channel->buffer.bufsize;
                pcm->xruns++;
            } else {
                channel->queued += completed;
            }
            channel->producer = current % channel->buffer.bufsize;
        }
        channel->hardware_position = current % channel->buffer.bufsize;
        pcm->interrupts++;
        pcm->blocks++;
        channel->buffer.total += completed;
        cv_broadcast(&pcm->intr_cv);
    }
    mtx_unlock(&pcm->lock);
}

int
bsd_audio_playback_available(void)
{
    return g_primary_audio_device && g_primary_audio_device->playback;
}

int
bsd_audio_capture_available(void)
{
    return g_primary_audio_device && g_primary_audio_device->capture;
}

int
bsd_audio_playback_write(const char *buffer, uint32_t length)
{
    struct bsd_audio_channel *channel;
    uint32_t free_space;
    uint32_t accepted;

    if ((!buffer && length) || !g_primary_audio_device ||
        !g_primary_audio_device->playback)
        return -BSD_AUDIO_ENODEV;
    if (!length)
        return 0;
    channel = g_primary_audio_device->playback;
    mtx_lock(&channel->pcm.lock);
    free_space = channel->buffer.bufsize - channel->queued;
    accepted = length < free_space ? length : free_space;
    accepted -= accepted % channel->pcm.align;
    if (accepted) {
        bsd_audio_ring_copy_in(channel, (const uint8_t *)buffer, accepted);
        channel->queued += accepted;
        channel->buffer.rl = (int)channel->queued;
    }
    mtx_unlock(&channel->pcm.lock);
    if (accepted && bsd_audio_channel_start(channel) != 0)
        return -BSD_AUDIO_ENODEV;
    return accepted ? (int)accepted : -BSD_AUDIO_EAGAIN;
}

int
bsd_audio_capture_read(char *buffer, uint32_t length)
{
    struct bsd_audio_channel *channel;
    uint32_t available;

    if ((!buffer && length) || !g_primary_audio_device ||
        !g_primary_audio_device->capture)
        return -BSD_AUDIO_ENODEV;
    if (!length)
        return 0;
    channel = g_primary_audio_device->capture;
    if (bsd_audio_channel_start(channel) != 0)
        return -BSD_AUDIO_ENODEV;
    mtx_lock(&channel->pcm.lock);
    available = length < channel->queued ? length : channel->queued;
    available -= available % channel->pcm.align;
    if (available) {
        bsd_audio_ring_copy_out(channel, (uint8_t *)buffer, available);
        channel->queued -= available;
        channel->buffer.rl = (int)channel->queued;
    }
    mtx_unlock(&channel->pcm.lock);
    return available ? (int)available : -BSD_AUDIO_EAGAIN;
}

int
bsd_audio_capture_ready(void)
{
    struct bsd_audio_channel *channel;
    int ready;

    if (!g_primary_audio_device || !g_primary_audio_device->capture)
        return 0;
    channel = g_primary_audio_device->capture;
    mtx_lock(&channel->pcm.lock);
    ready = channel->queued >= channel->pcm.align;
    mtx_unlock(&channel->pcm.lock);
    return ready;
}

static void
bsd_audio_channel_reset(struct bsd_audio_channel *channel)
{
    if (!channel)
        return;
    bsd_audio_channel_stop(channel);
    mtx_lock(&channel->pcm.lock);
    channel->producer = 0;
    channel->consumer = 0;
    channel->queued = 0;
    channel->hardware_position = 0;
    channel->buffer.rp = 0;
    channel->buffer.rl = 0;
    channel->buffer.hp = 0;
    channel->buffer.total = 0;
    if (channel->buffer.buf && channel->buffer.bufsize)
        bsd_memset(channel->buffer.buf, 0, channel->buffer.bufsize);
    mtx_unlock(&channel->pcm.lock);
}

int
bsd_audio_stream_control(uint8_t stream, uint8_t command)
{
    struct bsd_audio_channel *channel;
    uint32_t queued;
    int result;

    if (!g_primary_audio_device)
        return -BSD_AUDIO_ENODEV;
    if (stream == AUDIO_STREAM_PLAYBACK)
        channel = g_primary_audio_device->playback;
    else if (stream == AUDIO_STREAM_CAPTURE)
        channel = g_primary_audio_device->capture;
    else
        return -BSD_AUDIO_EINVAL;
    if (!channel)
        return -BSD_AUDIO_ENODEV;
    switch (command) {
    case AUDIO_STREAM_COMMAND_START:
        result = bsd_audio_channel_start(channel);
        return result ? -BSD_AUDIO_ENODEV : 0;
    case AUDIO_STREAM_COMMAND_STOP:
        bsd_audio_channel_stop(channel);
        return 0;
    case AUDIO_STREAM_COMMAND_RESET:
        bsd_audio_channel_reset(channel);
        return 0;
    case AUDIO_STREAM_COMMAND_DRAIN:
        if (stream != AUDIO_STREAM_PLAYBACK)
            return 0;
        mtx_lock(&channel->pcm.lock);
        queued = channel->queued;
        mtx_unlock(&channel->pcm.lock);
        if (queued)
            return -BSD_AUDIO_EAGAIN;
        bsd_audio_channel_stop(channel);
        return 0;
    default:
        return -BSD_AUDIO_EINVAL;
    }
}

void
bsd_audio_set_playback_control(uint8_t muted, uint8_t left_percent,
    uint8_t right_percent)
{
    struct snd_mixer *mixer;
    unsigned int device;
    unsigned int left;
    unsigned int right;

    if (!g_primary_audio_device || !g_primary_audio_device->mixer)
        return;
    mixer = g_primary_audio_device->mixer;
    device = (mixer->devs & SOUND_MASK_VOLUME) ?
        SOUND_MIXER_VOLUME : SOUND_MIXER_PCM;
    if ((mixer->devs & (1u << device)) == 0)
        return;
    left = muted ? 0u : left_percent;
    right = muted ? 0u : right_percent;
    if (left > 100u)
        left = 100u;
    if (right > 100u)
        right = 100u;
    mtx_lock(&mixer->lock);
    if (bsd_audio_mixer_set_locked(mixer, device, left, right) == 0) {
        if (muted)
            mix_setmutedevs(mixer, mixer->mutedevs | (1u << device));
        else
            mix_setmutedevs(mixer, mixer->mutedevs & ~(1u << device));
    }
    mtx_unlock(&mixer->lock);
}

static int
bsd_audio_mixer_program_device_locked(struct snd_mixer *mixer,
    unsigned int device, unsigned int left, unsigned int right)
{
    unsigned int real_device;

    real_device = mixer->realdev[device];
    if (real_device >= SOUND_MIXER_NRDEVICES)
        return 0;
    return MIXER_SET(mixer, real_device, left, right) >= 0 ? 0 : -1;
}

static int
bsd_audio_mixer_program_locked(struct snd_mixer *mixer,
    unsigned int device, unsigned int left, unsigned int right)
{
    unsigned int parent;
    uint32_t children;

    parent = mixer->parent[device];
    if (parent < SOUND_MIXER_NRDEVICES) {
        left = left * (mixer->level[parent] & 0xffu) / 100u;
        right = right * ((mixer->level[parent] >> 8) & 0xffu) / 100u;
        return bsd_audio_mixer_program_device_locked(mixer, device,
            left, right);
    }
    children = mixer->child[device];
    for (unsigned int child = 0; child < SOUND_MIXER_NRDEVICES; ++child) {
        unsigned int child_left;
        unsigned int child_right;

        if (!(children & (1u << child)) || mixer->parent[child] != device)
            continue;
        child_left = left * (mixer->level[child] & 0xffu) / 100u;
        child_right = right * ((mixer->level[child] >> 8) & 0xffu) /
            100u;
        if (bsd_audio_mixer_program_device_locked(mixer, child,
            child_left, child_right) != 0)
            return -1;
    }
    return bsd_audio_mixer_program_device_locked(mixer, device,
        left, right);
}

static int
bsd_audio_mixer_set_locked(struct snd_mixer *mixer, unsigned int device,
    unsigned int left, unsigned int right)
{
    uint32_t mask;

    if (!mixer || device >= SOUND_MIXER_NRDEVICES)
        return -1;
    mask = 1u << device;
    if (!(mixer->devs & mask))
        return -1;
    if (left > 100u)
        left = 100u;
    if (right > 100u)
        right = 100u;
    if (mixer->mutedevs & mask) {
        mixer->level_muted[device] = (uint16_t)(left | (right << 8));
        mixer->modify_counter++;
        return 0;
    }
    if (bsd_audio_mixer_program_locked(mixer, device, left, right) != 0)
        return -1;
    mixer->level[device] = (uint16_t)(left | (right << 8));
    mixer->modify_counter++;
    return 0;
}

struct snd_mixer *
mixer_create(device_t dev, kobj_class_t cls, void *devinfo,
    const char *description)
{
    struct snd_mixer *mixer;

    if (!dev || !cls || !devinfo)
        return NULL;
    mixer = (struct snd_mixer *)kobj_create(cls, M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!mixer)
        return NULL;
    bsd_snprintf(mixer->name, sizeof(mixer->name), "%s:mixer",
        device_get_nameunit(dev));
    if (description && description[0]) {
        bsd_strlcat(mixer->name, ":", sizeof(mixer->name));
        bsd_strlcat(mixer->name, description, sizeof(mixer->name));
    }
    mixer->devinfo = devinfo;
    mixer->type = MIXER_TYPE_SECONDARY;
    mixer->dev = dev;
    mixer->hwvol_mixer = SOUND_MIXER_VOLUME;
    mixer->hwvol_step = 5;
    for (unsigned int index = 0; index < SOUND_MIXER_NRDEVICES; ++index) {
        mixer->parent[index] = SOUND_MIXER_NONE;
        mixer->realdev[index] = (uint8_t)index;
    }
    mtx_init(&mixer->lock, mixer->name, NULL, MTX_DEF);
    if (MIXER_INIT(mixer) != 0) {
        mtx_destroy(&mixer->lock);
        kobj_delete((kobj_t)mixer, M_DEVBUF);
        return NULL;
    }
    return mixer;
}

int
mixer_delete(struct snd_mixer *mixer)
{
    if (!mixer || mixer->type != MIXER_TYPE_SECONDARY)
        return BSD_AUDIO_EINVAL;
    (void)MIXER_UNINIT(mixer);
    mtx_destroy(&mixer->lock);
    kobj_delete((kobj_t)mixer, M_DEVBUF);
    return 0;
}

int
mixer_init(device_t dev, kobj_class_t cls, void *devinfo)
{
    struct bsd_audio_device *entry;
    struct snd_mixer *mixer;

    entry = bsd_audio_device_lookup(dev, 1);
    if (!entry)
        return BSD_AUDIO_ENOMEM;
    bsd_audio_info_initialize(entry);
    if (!entry->info || entry->mixer)
        return BSD_AUDIO_EINVAL;
    mixer = (struct snd_mixer *)kobj_create(cls, M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!mixer)
        return BSD_AUDIO_ENOMEM;
    mixer->devinfo = devinfo;
    mixer->type = MIXER_TYPE_PRIMARY;
    mixer->dev = dev;
    mixer->hwvol_mixer = SOUND_MIXER_VOLUME;
    mixer->hwvol_step = 5;
    bsd_snprintf(mixer->name, sizeof(mixer->name), "mixer%d",
        device_get_unit(dev));
    for (unsigned int index = 0; index < SOUND_MIXER_NRDEVICES; ++index) {
        mixer->level[index] = 75u | (75u << 8);
        mixer->level_muted[index] = mixer->level[index];
        mixer->parent[index] = SOUND_MIXER_NONE;
        mixer->realdev[index] = (uint8_t)index;
    }
    mtx_init(&mixer->lock, mixer->name, NULL, MTX_DEF);
    if (MIXER_INIT(mixer) != 0) {
        mtx_destroy(&mixer->lock);
        kobj_delete((kobj_t)mixer, M_DEVBUF);
        return BSD_AUDIO_ENODEV;
    }
    entry->mixer = mixer;
    return 0;
}

int
mixer_reinit(device_t dev)
{
    struct bsd_audio_device *entry;
    struct snd_mixer *mixer;
    int result;

    entry = bsd_audio_device_lookup(dev, 0);
    if (!entry || !entry->mixer)
        return BSD_AUDIO_ENODEV;
    mixer = entry->mixer;
    mtx_lock(&mixer->lock);
    result = MIXER_REINIT(mixer);
    if (result != 0) {
        mtx_unlock(&mixer->lock);
        return result;
    }
    for (unsigned int device = 0; device < SOUND_MIXER_NRDEVICES;
        ++device) {
        unsigned int left;
        unsigned int right;

        if (!(mixer->devs & (1u << device)))
            continue;
        if (mixer->mutedevs & (1u << device)) {
            left = 0;
            right = 0;
        } else {
            left = mixer->level[device] & 0xffu;
            right = (mixer->level[device] >> 8) & 0xffu;
        }
        if (bsd_audio_mixer_program_locked(mixer, device,
            left, right) != 0) {
            mtx_unlock(&mixer->lock);
            return -1;
        }
    }
    mixer->recsrc = MIXER_SETRECSRC(mixer,
        mixer->recsrc & mixer->recdevs) & mixer->recdevs;
    mtx_unlock(&mixer->lock);
    return 0;
}

int
mixer_uninit(device_t dev)
{
    struct bsd_audio_device *entry;
    struct snd_mixer *mixer;

    entry = bsd_audio_device_lookup(dev, 0);
    if (!entry || !entry->mixer)
        return BSD_AUDIO_ENODEV;
    mixer = entry->mixer;
    entry->mixer = NULL;
    (void)MIXER_UNINIT(mixer);
    mtx_destroy(&mixer->lock);
    kobj_delete((kobj_t)mixer, M_DEVBUF);
    return 0;
}

int
mixer_hwvol_init(device_t dev)
{
    struct bsd_audio_device *entry = bsd_audio_device_lookup(dev, 0);

    if (!entry || !entry->mixer)
        return BSD_AUDIO_ENODEV;
    entry->mixer->hwvol_mixer = SOUND_MIXER_VOLUME;
    entry->mixer->hwvol_step = 5;
    return 0;
}

void
mixer_hwvol_step_locked(struct snd_mixer *mixer, int left_step,
    int right_step)
{
    unsigned int device;
    int left;
    int right;

    if (!mixer)
        return;
    device = (unsigned int)mixer->hwvol_mixer;
    if (device >= SOUND_MIXER_NRDEVICES)
        return;
    if (mixer->mutedevs & (1u << device)) {
        left = mixer->level_muted[device] & 0xff;
        right = (mixer->level_muted[device] >> 8) & 0xff;
    } else {
        left = mixer->level[device] & 0xff;
        right = (mixer->level[device] >> 8) & 0xff;
    }
    left +=
        left_step * mixer->hwvol_step;
    right +=
        right_step * mixer->hwvol_step;
    if (left < 0)
        left = 0;
    if (right < 0)
        right = 0;
    if (left > 100)
        left = 100;
    if (right > 100)
        right = 100;
    (void)bsd_audio_mixer_set_locked(mixer, device,
        (unsigned int)left, (unsigned int)right);
}

void
mixer_hwvol_mute_locked(struct snd_mixer *mixer)
{
    unsigned int device;
    uint32_t mask;

    if (!mixer)
        return;
    device = (unsigned int)mixer->hwvol_mixer;
    if (device >= SOUND_MIXER_NRDEVICES)
        return;
    mask = 1u << device;
    mix_setmutedevs(mixer, mixer->mutedevs ^ mask);
}

void
mixer_hwvol_mute(device_t dev)
{
    struct bsd_audio_device *entry = bsd_audio_device_lookup(dev, 0);

    if (!entry || !entry->mixer)
        return;
    mtx_lock(&entry->mixer->lock);
    mixer_hwvol_mute_locked(entry->mixer);
    mtx_unlock(&entry->mixer->lock);
}

void
mixer_hwvol_step(device_t dev, int left_step, int right_step)
{
    struct bsd_audio_device *entry = bsd_audio_device_lookup(dev, 0);

    if (!entry || !entry->mixer)
        return;
    mtx_lock(&entry->mixer->lock);
    mixer_hwvol_step_locked(entry->mixer, left_step, right_step);
    mtx_unlock(&entry->mixer->lock);
}

int
mix_set(struct snd_mixer *mixer, u_int device, u_int left, u_int right)
{
    int result;

    if (!mixer)
        return BSD_AUDIO_ENXIO;
    mtx_lock(&mixer->lock);
    result = bsd_audio_mixer_set_locked(mixer, device, left, right);
    mtx_unlock(&mixer->lock);
    return result == 0 ? 0 : BSD_AUDIO_ENXIO;
}

int
mix_get(struct snd_mixer *mixer, u_int device)
{
    int result;

    if (!mixer || device >= SOUND_MIXER_NRDEVICES)
        return -1;
    mtx_lock(&mixer->lock);
    if (!(mixer->devs & (1u << device)))
        result = -1;
    else if (mixer->mutedevs & (1u << device))
        result = mixer->level_muted[device];
    else
        result = mixer->level[device];
    mtx_unlock(&mixer->lock);
    return result;
}

int
mix_setrecsrc(struct snd_mixer *mixer, uint32_t source)
{
    uint32_t actual;

    if (!mixer)
        return BSD_AUDIO_ENXIO;
    mtx_lock(&mixer->lock);
    source &= mixer->recdevs;
    if (!source)
        source = mixer->recdevs & SOUND_MASK_MIC;
    if (!source)
        source = mixer->recdevs & SOUND_MASK_MONITOR;
    if (!source)
        source = mixer->recdevs & SOUND_MASK_LINE;
    if (!source) {
        for (unsigned int device = 0;
            device < SOUND_MIXER_NRDEVICES; ++device) {
            if (mixer->recdevs & (1u << device)) {
                source = 1u << device;
                break;
            }
        }
    }
    actual = MIXER_SETRECSRC(mixer, source) & mixer->recdevs;
    mixer->recsrc = actual;
    mixer->modify_counter++;
    mtx_unlock(&mixer->lock);
    return 0;
}

uint32_t
mix_getrecsrc(struct snd_mixer *mixer)
{
    uint32_t source;

    if (!mixer)
        return 0;
    mtx_lock(&mixer->lock);
    source = mixer->recsrc;
    mtx_unlock(&mixer->lock);
    return source;
}

device_t
mix_get_dev(struct snd_mixer *mixer)
{
    return mixer ? mixer->dev : NULL;
}

void *
mix_getdevinfo(struct snd_mixer *mixer)
{
    return mixer ? mixer->devinfo : NULL;
}

void
mix_setdevs(struct snd_mixer *mixer, u_int32_t value)
{
    if (mixer)
        mixer->devs = value;
}

void
mix_setrecdevs(struct snd_mixer *mixer, u_int32_t value)
{
    if (mixer)
        mixer->recdevs = value;
}

void
mix_setmutedevs(struct snd_mixer *mixer, u_int32_t value)
{
    uint32_t changed;
    uint32_t target;

    if (!mixer)
        return;
    target = value & mixer->devs;
    changed = (target ^ mixer->mutedevs) & mixer->devs;
    for (unsigned int device = 0; device < SOUND_MIXER_NRDEVICES;
        ++device) {
        uint32_t mask = 1u << device;
        unsigned int level;

        if (!(changed & mask))
            continue;
        if (target & mask) {
            mixer->level_muted[device] = mixer->level[device];
            if (bsd_audio_mixer_program_locked(mixer, device, 0, 0) == 0)
                mixer->mutedevs |= mask;
        } else {
            level = mixer->level_muted[device];
            if (bsd_audio_mixer_program_locked(mixer, device,
                level & 0xffu, (level >> 8) & 0xffu) == 0) {
                mixer->level[device] = (uint16_t)level;
                mixer->mutedevs &= ~mask;
            }
        }
    }
    if (changed)
        mixer->modify_counter++;
}

u_int32_t
mix_getdevs(struct snd_mixer *mixer)
{
    return mixer ? mixer->devs : 0;
}

u_int32_t
mix_getrecdevs(struct snd_mixer *mixer)
{
    return mixer ? mixer->recdevs : 0;
}

u_int32_t
mix_getmutedevs(struct snd_mixer *mixer)
{
    return mixer ? mixer->mutedevs : 0;
}

void
mix_setparentchild(struct snd_mixer *mixer, u_int32_t parent,
    u_int32_t children)
{
    if (!mixer || parent >= SOUND_MIXER_NRDEVICES)
        return;
    mixer->child[parent] = children;
    for (unsigned int child = 0; child < SOUND_MIXER_NRDEVICES; ++child) {
        if (children & (1u << child))
            mixer->parent[child] = (uint8_t)parent;
    }
}

void
mix_setrealdev(struct snd_mixer *mixer, u_int32_t device,
    u_int32_t real_device)
{
    if (!mixer || device >= SOUND_MIXER_NRDEVICES)
        return;
    mixer->realdev[device] = real_device < SOUND_MIXER_NRDEVICES ?
        (uint8_t)real_device : SOUND_MIXER_NONE;
}

u_int32_t
mix_getparent(struct snd_mixer *mixer, u_int32_t device)
{
    if (!mixer || device >= SOUND_MIXER_NRDEVICES)
        return SOUND_MIXER_NONE;
    return mixer->parent[device];
}

static struct pcmchan_matrix g_bsd_audio_matrices[SND_CHN_MATRIX_MAX] = {
    [SND_CHN_MATRIX_1_0] = SND_CHN_MATRIX_MAP_1_0,
    [SND_CHN_MATRIX_2_0] = SND_CHN_MATRIX_MAP_2_0,
    [SND_CHN_MATRIX_2_1] = SND_CHN_MATRIX_MAP_2_1,
    [SND_CHN_MATRIX_3_0] = SND_CHN_MATRIX_MAP_3_0,
    [SND_CHN_MATRIX_3_1] = SND_CHN_MATRIX_MAP_3_1,
    [SND_CHN_MATRIX_4_0] = SND_CHN_MATRIX_MAP_4_0,
    [SND_CHN_MATRIX_4_1] = SND_CHN_MATRIX_MAP_4_1,
    [SND_CHN_MATRIX_5_0] = SND_CHN_MATRIX_MAP_5_0,
    [SND_CHN_MATRIX_5_1] = SND_CHN_MATRIX_MAP_5_1,
    [SND_CHN_MATRIX_6_0] = SND_CHN_MATRIX_MAP_6_0,
    [SND_CHN_MATRIX_6_1] = SND_CHN_MATRIX_MAP_6_1,
    [SND_CHN_MATRIX_7_0] = SND_CHN_MATRIX_MAP_7_0,
    [SND_CHN_MATRIX_7_1] = SND_CHN_MATRIX_MAP_7_1,
};

static const int g_bsd_audio_default_matrix[9] = {
    SND_CHN_MATRIX_UNKNOWN,
    SND_CHN_MATRIX_1,
    SND_CHN_MATRIX_2,
    SND_CHN_MATRIX_3,
    SND_CHN_MATRIX_4,
    SND_CHN_MATRIX_5,
    SND_CHN_MATRIX_6,
    SND_CHN_MATRIX_7,
    SND_CHN_MATRIX_8,
};

int
feeder_matrix_default_id(uint32_t channels)
{
    if (channels < 1u || channels > 8u)
        return SND_CHN_MATRIX_UNKNOWN;
    return g_bsd_audio_default_matrix[channels];
}

struct pcmchan_matrix *
feeder_matrix_default_channel_map(uint32_t channels)
{
    int id = feeder_matrix_default_id(channels);

    return id == SND_CHN_MATRIX_UNKNOWN ? NULL :
        &g_bsd_audio_matrices[id];
}

uint32_t
feeder_matrix_default_format(uint32_t format)
{
    struct pcmchan_matrix *matrix;
    uint32_t channels = AFMT_CHANNEL(format);
    uint32_t extension = AFMT_EXTCHANNEL(format);

    for (unsigned int index = 0; index < SND_CHN_MATRIX_MAX; ++index) {
        if (g_bsd_audio_matrices[index].channels == channels &&
            g_bsd_audio_matrices[index].ext == extension)
            return SND_FORMAT(format, channels, extension);
    }
    matrix = feeder_matrix_default_channel_map(channels);
    return matrix ? SND_FORMAT(format, channels, matrix->ext) : 0;
}

int
feeder_matrix_format_id(uint32_t format)
{
    uint32_t channels = AFMT_CHANNEL(format);
    uint32_t extension = AFMT_EXTCHANNEL(format);

    for (unsigned int index = 0; index < SND_CHN_MATRIX_MAX; ++index) {
        if (g_bsd_audio_matrices[index].channels == channels &&
            g_bsd_audio_matrices[index].ext == extension)
            return (int)index;
    }
    return SND_CHN_MATRIX_UNKNOWN;
}

struct pcmchan_matrix *
feeder_matrix_format_map(uint32_t format)
{
    int id = feeder_matrix_format_id(format);

    return id == SND_CHN_MATRIX_UNKNOWN ? NULL :
        &g_bsd_audio_matrices[id];
}

struct pcmchan_matrix *
feeder_matrix_id_map(int id)
{
    if (id < SND_CHN_MATRIX_BEGIN || id > SND_CHN_MATRIX_END)
        return NULL;
    return &g_bsd_audio_matrices[id];
}

int
feeder_matrix_compare(struct pcmchan_matrix *left,
    struct pcmchan_matrix *right)
{
    if (!left || !right)
        return BSD_AUDIO_EINVAL;
    if (left->channels != right->channels || left->ext != right->ext ||
        left->mask != right->mask)
        return 1;
    for (unsigned int index = 0; index <= SND_CHN_T_MAX; ++index) {
        if (left->map[index].type != right->map[index].type ||
            left->map[index].members != right->map[index].members)
            return 1;
    }
    return 0;
}
