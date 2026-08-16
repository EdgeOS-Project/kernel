/* SPDX-License-Identifier: MPL-2.0 */
/* Behavior tests for the complete FreeBSD PCM service boundary. */

#include <dev/sound/pcm/sound.h>

#include "channel_if.h"
#include "mixer_if.h"

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/audio.h"
#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/edgeos/sync.h"
#include "dev/alsa.h"
#include "drivers/audio.h"

#define TEST_PAGE_SIZE 4096u
#define TEST_BUFFER_SIZE 16384u
#define TEST_BLOCK_SIZE 4096u
#define TEST_FORMAT SND_FORMAT(AFMT_S16_LE, 2, 0)

extern void *aligned_alloc(size_t alignment, size_t size);

struct test_channel {
    struct snd_dbuf *buffer;
    struct pcm_channel *channel;
    uint8_t storage[TEST_BUFFER_SIZE];
    uint32_t position;
    uint32_t format;
    uint32_t speed;
    uint32_t block_size;
    int direction;
    unsigned int starts;
    unsigned int stops;
};

struct test_mixer {
    struct snd_mixer *instance;
    unsigned int device;
    unsigned int left;
    unsigned int right;
    unsigned int sets;
    unsigned int reinitializes;
    unsigned int uninitializes;
    uint32_t record_source;
};

struct test_device {
    struct snddev_info info;
    struct test_channel playback;
    struct test_channel capture;
    struct test_mixer mixer;
    const char *description;
    const char *nameunit;
    int unit;
};

static int g_thread_token;
static unsigned int g_audio_refreshes;
static uint64_t g_monotonic_us;
static int g_interrupt_flags;
static struct resource *g_interrupt_resource;
static driver_intr_t *g_interrupt_handler;
static void *g_interrupt_argument;
static int g_interrupt_cookie;
static unsigned int g_page_releases;

#define TEST_CHECK(expression) do {                                     \
    if (!(expression)) {                                                \
        bsd_printf("bsd audio unit failed at line %u\n",                \
            (unsigned int)__LINE__);                                    \
        return 1;                                                       \
    }                                                                   \
} while (0)

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    size_t bytes;

    (void)context;
    if (page_count > SIZE_MAX / TEST_PAGE_SIZE)
        return NULL;
    bytes = (size_t)page_count * TEST_PAGE_SIZE;
    return aligned_alloc(TEST_PAGE_SIZE, bytes);
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)base;
    (void)page_count;
    (void)context;
    g_page_releases++;
}

static void *
test_dma_allocate_pages(uint64_t page_count, uint32_t flags, void *context)
{
    (void)flags;
    return test_allocate_pages(page_count, context);
}

static int
test_physical_address(const void *pointer, uint64_t *physical_address,
    void *context)
{
    (void)context;
    if (!pointer || !physical_address)
        return -1;
    *physical_address = (uint64_t)(uintptr_t)pointer;
    return 0;
}

static int
test_virtual_address(uint64_t physical_address, size_t length,
    void **virtual_address, void *context)
{
    (void)context;
    if (!physical_address || !length || !virtual_address)
        return -1;
    *virtual_address = (void *)(uintptr_t)physical_address;
    return 0;
}

static void *
test_current_thread(void *context)
{
    (void)context;
    return &g_thread_token;
}

static int
test_can_block(void *thread, void *context)
{
    (void)thread;
    (void)context;
    return 0;
}

static void
test_thread_noop(void *thread, void *context)
{
    (void)thread;
    (void)context;
}

static void
test_yield(void *context)
{
    (void)context;
}

int
devtmpfs_refresh_audio_nodes(void)
{
    g_audio_refreshes++;
    return 0;
}

struct thread *
bsd_kthread_current_public(void)
{
    return NULL;
}

int
bsd_kthread_sleep(const void *channel, struct mtx *mutex, int priority,
    int timeout_ticks)
{
    (void)channel;
    (void)mutex;
    (void)priority;
    (void)timeout_ticks;
    return 0;
}

void
bsd_kthread_wakeup(const void *channel, int one)
{
    (void)channel;
    (void)one;
}

uint64_t
boottime_monotonic_us(void)
{
    g_monotonic_us += 1000u;
    return g_monotonic_us;
}

void *
device_get_softc(device_t device)
{
    struct test_device *test = (struct test_device *)device;

    return &test->info;
}

int
device_get_unit(device_t device)
{
    return ((struct test_device *)device)->unit;
}

const char *
device_get_desc(device_t device)
{
    return ((struct test_device *)device)->description;
}

const char *
device_get_nameunit(device_t device)
{
    return ((struct test_device *)device)->nameunit;
}

int
device_printf(device_t device, const char *format, ...)
{
    (void)device;
    (void)format;
    return 0;
}

int
bus_setup_intr(device_t device, struct resource *resource, int flags,
    driver_filter_t *filter, driver_intr_t *handler, void *argument,
    void **cookie)
{
    (void)device;
    if (filter || !handler || !cookie)
        return EINVAL;
    g_interrupt_resource = resource;
    g_interrupt_flags = flags;
    g_interrupt_handler = handler;
    g_interrupt_argument = argument;
    *cookie = &g_interrupt_cookie;
    return 0;
}

static void *
test_channel_init(kobj_t object, void *devinfo, struct snd_dbuf *buffer,
    struct pcm_channel *channel, int direction)
{
    struct test_channel *test = devinfo;

    (void)object;
    test->buffer = buffer;
    test->channel = channel;
    test->direction = direction;
    if (sndbuf_setup(buffer, test->storage, sizeof(test->storage)) != 0)
        return NULL;
    return test;
}

static int
test_channel_free(kobj_t object, void *devinfo)
{
    struct test_channel *test = devinfo;

    (void)object;
    test->buffer = NULL;
    test->channel = NULL;
    return 0;
}

static int
test_channel_setformat(kobj_t object, void *devinfo, uint32_t format)
{
    struct test_channel *test = devinfo;

    (void)object;
    if (format != TEST_FORMAT)
        return EINVAL;
    test->format = format;
    return 0;
}

static uint32_t
test_channel_setspeed(kobj_t object, void *devinfo, uint32_t speed)
{
    struct test_channel *test = devinfo;

    (void)object;
    test->speed = speed;
    return speed;
}

static uint32_t
test_channel_setblocksize(kobj_t object, void *devinfo, uint32_t block_size)
{
    struct test_channel *test = devinfo;

    (void)object;
    test->block_size = block_size;
    return block_size;
}

static int
test_channel_trigger(kobj_t object, void *devinfo, int command)
{
    struct test_channel *test = devinfo;

    (void)object;
    if (command == PCMTRIG_START)
        test->starts++;
    else if (command == PCMTRIG_STOP)
        test->stops++;
    return 0;
}

static uint32_t
test_channel_getptr(kobj_t object, void *devinfo)
{
    struct test_channel *test = devinfo;

    (void)object;
    return test->position;
}

static struct pcmchan_caps *
test_channel_getcaps(kobj_t object, void *devinfo)
{
    static uint32_t formats[] = { TEST_FORMAT, 0 };
    static struct pcmchan_caps capabilities = {
        .minspeed = 48000,
        .maxspeed = 48000,
        .fmtlist = formats,
    };

    (void)object;
    (void)devinfo;
    return &capabilities;
}

static const struct kobj_method test_channel_methods[] = {
    KOBJMETHOD(channel_init, test_channel_init),
    KOBJMETHOD(channel_free, test_channel_free),
    KOBJMETHOD(channel_setformat, test_channel_setformat),
    KOBJMETHOD(channel_setspeed, test_channel_setspeed),
    KOBJMETHOD(channel_setblocksize, test_channel_setblocksize),
    KOBJMETHOD(channel_trigger, test_channel_trigger),
    KOBJMETHOD(channel_getptr, test_channel_getptr),
    KOBJMETHOD(channel_getcaps, test_channel_getcaps),
    KOBJMETHOD_END,
};

DEFINE_CLASS_0(test_channel, test_channel_class, test_channel_methods,
    sizeof(struct kobj));

static int
test_mixer_init(struct snd_mixer *mixer)
{
    struct test_mixer *test = mix_getdevinfo(mixer);

    test->instance = mixer;
    mix_setdevs(mixer, SOUND_MASK_VOLUME | SOUND_MASK_PCM);
    mix_setrecdevs(mixer, SOUND_MASK_MIC);
    return 0;
}

static int
test_mixer_reinit(struct snd_mixer *mixer)
{
    struct test_mixer *test = mix_getdevinfo(mixer);

    test->reinitializes++;
    return 0;
}

static int
test_mixer_uninit(struct snd_mixer *mixer)
{
    struct test_mixer *test = mix_getdevinfo(mixer);

    test->uninitializes++;
    return 0;
}

static int
test_mixer_set(struct snd_mixer *mixer, unsigned int device,
    unsigned int left, unsigned int right)
{
    struct test_mixer *test = mix_getdevinfo(mixer);

    test->device = device;
    test->left = left;
    test->right = right;
    test->sets++;
    return 0;
}

static uint32_t
test_mixer_setrecsrc(struct snd_mixer *mixer, uint32_t source)
{
    struct test_mixer *test = mix_getdevinfo(mixer);

    test->record_source = source & mix_getrecdevs(mixer);
    return test->record_source;
}

static const struct kobj_method test_mixer_methods[] = {
    KOBJMETHOD(mixer_init, test_mixer_init),
    KOBJMETHOD(mixer_reinit, test_mixer_reinit),
    KOBJMETHOD(mixer_uninit, test_mixer_uninit),
    KOBJMETHOD(mixer_set, test_mixer_set),
    KOBJMETHOD(mixer_setrecsrc, test_mixer_setrecsrc),
    KOBJMETHOD_END,
};

DEFINE_CLASS_0(test_mixer, test_mixer_class, test_mixer_methods,
    sizeof(struct snd_mixer));

static void
test_interrupt_handler(void *argument)
{
    (void)argument;
}

static int
test_shared_sound_services(void)
{
    struct pcm_channel channel;
    struct snd_dbuf buffer;
    struct test_device test;
    bus_dma_tag_t tag;
    void *cookie = NULL;
    unsigned int releases;

    bsd_memset(&channel, 0, sizeof(channel));
    bsd_memset(&buffer, 0, sizeof(buffer));
    bsd_memset(&test, 0, sizeof(test));
    test.description = "Unit PCI Audio";
    test.nameunit = "pcm2";
    test.unit = 2;
    mtx_init(&channel.lock, "audio unit buffer", NULL, MTX_DEF);
    buffer.channel = &channel;
    TEST_CHECK(bus_dma_tag_create(NULL, TEST_PAGE_SIZE, 0,
        BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR, NULL, NULL,
        TEST_BUFFER_SIZE, 1, TEST_BUFFER_SIZE, BUS_DMA_COHERENT,
        NULL, NULL, &tag) == 0);
    TEST_CHECK(sndbuf_alloc(&buffer, tag, 0, TEST_BUFFER_SIZE) == 0);
    TEST_CHECK(buffer.buf != NULL);
    TEST_CHECK(buffer.buf_addr != 0);
    TEST_CHECK(buffer.blkcnt == 2u);
    TEST_CHECK(buffer.blksz == TEST_BUFFER_SIZE / 2u);
    TEST_CHECK(sndbuf_resize(&buffer, 4u, TEST_BLOCK_SIZE) == 0);
    TEST_CHECK(sndbuf_resize(&buffer, 1u, TEST_BLOCK_SIZE) == EINVAL);
    buffer.rp = 3072;
    buffer.rl = 8192;
    TEST_CHECK(sndbuf_getready(&buffer) == 8192u);
    TEST_CHECK(sndbuf_getreadyptr(&buffer) == 3072u);
    TEST_CHECK(sndbuf_getfree(&buffer) == TEST_BUFFER_SIZE - 8192u);
    TEST_CHECK(sndbuf_getfreeptr(&buffer) == 11264u);
    sndbuf_setrun(&buffer, 1);
    TEST_CHECK(sndbuf_runsz(&buffer) == TEST_BLOCK_SIZE);
    sndbuf_setrun(&buffer, 0);
    TEST_CHECK(sndbuf_runsz(&buffer) == 0u);
    releases = g_page_releases;
    sndbuf_free(&buffer);
    TEST_CHECK(buffer.buf == NULL);
    TEST_CHECK(g_page_releases == releases + 1u);
    TEST_CHECK(bus_dma_tag_destroy(tag) == 0);
    mtx_destroy(&channel.lock);

    pcm_init((device_t)&test, NULL);
    test.mixer.instance = mixer_create((device_t)&test,
        &test_mixer_class, &test.mixer, "dsp");
    TEST_CHECK(test.mixer.instance != NULL);
    TEST_CHECK(test.mixer.instance->type == MIXER_TYPE_SECONDARY);
    TEST_CHECK(mix_getdevinfo(test.mixer.instance) == &test.mixer);
    TEST_CHECK(mixer_delete(test.mixer.instance) == 0);
    TEST_CHECK(test.mixer.uninitializes == 1u);
    test.mixer.instance = NULL;
    TEST_CHECK(snd_setup_intr((device_t)&test,
        (struct resource *)(uintptr_t)0x1234u,
        INTR_TYPE_NET | INTR_MPSAFE, test_interrupt_handler, &test,
        &cookie) == 0);
    TEST_CHECK(cookie == &g_interrupt_cookie);
    TEST_CHECK(g_interrupt_resource ==
        (struct resource *)(uintptr_t)0x1234u);
    TEST_CHECK(g_interrupt_flags == (INTR_TYPE_AV | INTR_MPSAFE));
    TEST_CHECK(g_interrupt_handler == test_interrupt_handler);
    TEST_CHECK(g_interrupt_argument == &test);
    TEST_CHECK((test.info.flags & SD_F_MPSAFE) != 0);
    TEST_CHECK(pcm_unregister((device_t)&test) == 0);
    return 0;
}

static int
test_duplex_device(void)
{
    struct test_device test;
    struct audio_pcm_geometry geometry;
    uint8_t playback[TEST_BLOCK_SIZE * 2u];
    uint8_t capture[TEST_BLOCK_SIZE];
    device_t device = (device_t)&test;
    unsigned int refreshes;

    bsd_memset(&test, 0, sizeof(test));
    test.description = "Unit USB Audio";
    test.nameunit = "pcm0";
    pcm_init(device, NULL);
    TEST_CHECK(mixer_init(device, &test_mixer_class, &test.mixer) == 0);
    TEST_CHECK(pcm_addchan(device, PCMDIR_PLAY, &test_channel_class,
        &test.playback) == 0);
    TEST_CHECK(pcm_addchan(device, PCMDIR_REC, &test_channel_class,
        &test.capture) == 0);
    refreshes = g_audio_refreshes;
    TEST_CHECK(pcm_register(device, "unit duplex") == 0);
    TEST_CHECK(g_audio_refreshes == refreshes + 1u);
    TEST_CHECK(audio_available());
    TEST_CHECK(audio_capture_available());
    TEST_CHECK(bsd_strstr(audio_identity(), "Unit USB Audio") != NULL);
    TEST_CHECK(test.playback.format == TEST_FORMAT);
    TEST_CHECK(test.playback.speed == 48000u);
    TEST_CHECK(test.playback.block_size == TEST_BLOCK_SIZE);
    TEST_CHECK(audio_get_pcm_geometry(
        AUDIO_STREAM_PLAYBACK, &geometry) == 0);
    TEST_CHECK(geometry.rate == 48000u);
    TEST_CHECK(geometry.channels == 2u);
    TEST_CHECK(geometry.sample_bits == 16u);
    TEST_CHECK(geometry.frame_bytes == 4u);
    TEST_CHECK(geometry.period_bytes == TEST_BLOCK_SIZE);
    TEST_CHECK(geometry.buffer_bytes == TEST_BUFFER_SIZE);
    TEST_CHECK(geometry.queued_bytes == 0u);

    bsd_memset(playback, 0x4a, sizeof(playback));
    TEST_CHECK(audio_write_pcm((const char *)playback,
        sizeof(playback)) == (int)sizeof(playback));
    TEST_CHECK(test.playback.starts == 1u);
    TEST_CHECK(audio_get_pcm_geometry(
        AUDIO_STREAM_PLAYBACK, &geometry) == 0);
    TEST_CHECK(geometry.queued_bytes == sizeof(playback));
    TEST_CHECK(audio_stream_control(AUDIO_STREAM_PLAYBACK,
        AUDIO_STREAM_COMMAND_DRAIN) == -11);
    test.playback.position = TEST_BLOCK_SIZE;
    chn_intr(test.playback.channel);
    TEST_CHECK(audio_playback_ready());
    TEST_CHECK(audio_get_pcm_geometry(
        AUDIO_STREAM_PLAYBACK, &geometry) == 0);
    TEST_CHECK(geometry.queued_bytes == TEST_BLOCK_SIZE);

    TEST_CHECK(audio_read_pcm((char *)capture, sizeof(capture)) == -11);
    TEST_CHECK(test.capture.starts == 1u);
    bsd_memset(test.capture.storage, 0x5a, TEST_BLOCK_SIZE);
    test.capture.position = TEST_BLOCK_SIZE;
    chn_intr(test.capture.channel);
    TEST_CHECK(audio_capture_ready());
    TEST_CHECK(audio_get_pcm_geometry(
        AUDIO_STREAM_CAPTURE, &geometry) == 0);
    TEST_CHECK(geometry.queued_bytes == TEST_BLOCK_SIZE);
    bsd_memset(capture, 0, sizeof(capture));
    TEST_CHECK(audio_read_pcm((char *)capture,
        sizeof(capture)) == (int)sizeof(capture));
    for (unsigned int index = 0; index < sizeof(capture); ++index)
        TEST_CHECK(capture[index] == 0x5a);

    audio_set_playback_control(0, 60, 70);
    TEST_CHECK(test.mixer.sets == 1u);
    TEST_CHECK(test.mixer.device == SOUND_MIXER_VOLUME);
    TEST_CHECK(test.mixer.left == 60u);
    TEST_CHECK(test.mixer.right == 70u);
    TEST_CHECK(mix_set(test.mixer.instance, SOUND_MIXER_VOLUME,
        40u, 50u) == 0);
    TEST_CHECK(mix_get(test.mixer.instance, SOUND_MIXER_VOLUME) ==
        (int)(40u | (50u << 8)));
    mixer_hwvol_step(device, 1, -1);
    TEST_CHECK(mix_get(test.mixer.instance, SOUND_MIXER_VOLUME) ==
        (int)(45u | (45u << 8)));
    mixer_hwvol_mute(device);
    TEST_CHECK(test.mixer.left == 0u && test.mixer.right == 0u);
    TEST_CHECK(mix_get(test.mixer.instance, SOUND_MIXER_VOLUME) ==
        (int)(45u | (45u << 8)));
    mixer_hwvol_mute(device);
    TEST_CHECK(test.mixer.left == 45u && test.mixer.right == 45u);
    TEST_CHECK(mix_setrecsrc(test.mixer.instance, 0) == 0);
    TEST_CHECK(test.mixer.record_source == SOUND_MASK_MIC);
    TEST_CHECK(mix_getrecsrc(test.mixer.instance) == SOUND_MASK_MIC);
    TEST_CHECK(mixer_reinit(device) == 0);
    TEST_CHECK(test.mixer.reinitializes == 1u);
    TEST_CHECK(audio_stream_control(AUDIO_STREAM_PLAYBACK,
        AUDIO_STREAM_COMMAND_RESET) == 0);
    TEST_CHECK(test.playback.stops == 1u);
    for (unsigned int index = 0; index < TEST_BUFFER_SIZE; ++index)
        TEST_CHECK(test.playback.storage[index] == 0);

    alsa_open(EDGE_ALSA_PATH_PCM_PLAYBACK);
    alsa_open(EDGE_ALSA_PATH_PCM_PLAYBACK);
    TEST_CHECK(alsa_write(EDGE_ALSA_PATH_PCM_PLAYBACK,
        (const char *)playback, TEST_BLOCK_SIZE) == TEST_BLOCK_SIZE);
    TEST_CHECK(test.playback.starts == 2u);
    alsa_close(EDGE_ALSA_PATH_PCM_PLAYBACK);
    TEST_CHECK(test.playback.stops == 1u);
    alsa_close(EDGE_ALSA_PATH_PCM_PLAYBACK);
    TEST_CHECK(test.playback.stops == 2u);
    TEST_CHECK(audio_get_pcm_geometry(
        AUDIO_STREAM_PLAYBACK, &geometry) == 0);
    TEST_CHECK(geometry.queued_bytes == 0u);

    refreshes = g_audio_refreshes;
    TEST_CHECK(pcm_unregister(device) == 0);
    TEST_CHECK(g_audio_refreshes == refreshes + 1u);
    TEST_CHECK(!audio_available());
    TEST_CHECK(!audio_capture_available());
    TEST_CHECK(test.mixer.uninitializes == 1u);
    return 0;
}

static int
test_capture_only_device(void)
{
    struct test_device test;
    device_t device = (device_t)&test;

    bsd_memset(&test, 0, sizeof(test));
    test.description = "Unit USB Microphone";
    test.nameunit = "pcm1";
    test.unit = 1;
    pcm_init(device, NULL);
    TEST_CHECK(pcm_addchan(device, PCMDIR_REC, &test_channel_class,
        &test.capture) == 0);
    TEST_CHECK(pcm_register(device, "unit capture") == 0);
    TEST_CHECK(!audio_available());
    TEST_CHECK(audio_capture_available());
    TEST_CHECK(bsd_strstr(audio_capture_identity(),
        "Unit USB Microphone") != NULL);
    TEST_CHECK(pcm_unregister(device) == 0);
    TEST_CHECK(!audio_capture_available());
    return 0;
}

int
main(void)
{
    bsd_allocator_ops_t allocator = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    bsd_sync_ops_t sync = {
        .current_thread = test_current_thread,
        .can_block = test_can_block,
        .prepare_block = test_thread_noop,
        .block_current = test_thread_noop,
        .wake_thread = test_thread_noop,
        .yield_thread = test_yield,
    };
    bsd_bus_dma_ops_t dma = {
        .allocate_pages = test_dma_allocate_pages,
        .release_pages = test_release_pages,
        .physical_address = test_physical_address,
        .virtual_address = test_virtual_address,
    };

    TEST_CHECK(bsd_allocator_initialize(&allocator) == 0);
    TEST_CHECK(bsd_bus_dma_initialize(&dma) == 0);
    TEST_CHECK(bsd_sync_initialize(&sync) == 0);
    TEST_CHECK(test_shared_sound_services() == 0);
    TEST_CHECK(test_duplex_device() == 0);
    TEST_CHECK(test_capture_only_device() == 0);
    return 0;
}
