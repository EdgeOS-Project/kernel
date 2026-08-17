/* SPDX-License-Identifier: MPL-2.0 */

#include <stdint.h>

#include <dev/videomode/edidreg.h>
#include <dev/videomode/videomode.h>
#include <dev/videomode/vesagtf.h>
#include <dev/videomode/edidvar.h>

int bootverbose;

static int
refresh_rate(const struct videomode *mode)
{
    return (mode->dot_clock * 1000 + mode->htotal * mode->vtotal / 2) /
        (mode->htotal * mode->vtotal);
}

static int
test_mode_database(void)
{
    const struct videomode *mode;

    if (videomode_count != 46)
        return 1;

    mode = pick_mode_by_ref(1680, 1050, 60);
    if (mode == 0 || mode->hdisplay != 1680 || mode->vdisplay != 1050)
        return 2;
    if (refresh_rate(mode) < 59 || refresh_rate(mode) > 61)
        return 3;

    mode = pick_mode_by_dotclock(1680, 1050, 150000);
    if (mode == 0 || mode->dot_clock > 150000)
        return 4;

    return 0;
}

static int
test_generated_timing(void)
{
    struct videomode mode;

    vesagtf_mode(1920, 1080, 60, &mode);
    if (mode.hdisplay != 1920 || mode.vdisplay != 1080)
        return 5;
    if (mode.dot_clock <= 0 || mode.htotal <= mode.hdisplay ||
        mode.vtotal <= mode.vdisplay)
        return 6;
    if (refresh_rate(&mode) < 59 || refresh_rate(&mode) > 61)
        return 7;

    return 0;
}

static int
test_mode_sorting(void)
{
    struct videomode modes[3];
    struct videomode *preferred;

    modes[0] = *pick_mode_by_ref(800, 600, 60);
    modes[1] = *pick_mode_by_ref(1680, 1050, 60);
    modes[2] = *pick_mode_by_ref(1280, 1024, 60);
    preferred = &modes[1];
    sort_modes(modes, &preferred, 3);
    if (preferred != &modes[0])
        return 8;
    if (modes[0].hdisplay != 1680 || modes[0].vdisplay != 1050)
        return 9;

    return 0;
}

static int
test_edid_validation(void)
{
    uint8_t edid[128];
    struct edid_info info;
    unsigned int sum;
    int index;

    for (index = 0; index < 128; index++)
        edid[index] = 0;
    edid[0] = 0x00;
    edid[1] = 0xff;
    edid[2] = 0xff;
    edid[3] = 0xff;
    edid[4] = 0xff;
    edid[5] = 0xff;
    edid[6] = 0xff;
    edid[7] = 0x00;
    edid[8] = 0x04;
    edid[9] = 0x43;
    edid[18] = 1;
    edid[19] = 4;
    for (index = EDID_OFFSET_STD_TIMING;
        index < EDID_OFFSET_STD_TIMING + EDID_STD_TIMING_COUNT * 2;
        index++)
        edid[index] = 0x01;

    sum = 0;
    for (index = 0; index < 127; index++)
        sum += edid[index];
    edid[127] = (uint8_t)(0U - sum);

    if (edid_is_valid(edid) != 0)
        return 10;
    if (edid_parse(edid, &info) != 0)
        return 11;
    if (info.edid_vendor[0] != 'A' || info.edid_vendor[1] != 'B' ||
        info.edid_vendor[2] != 'C')
        return 12;

    edid[127]++;
    if (edid_is_valid(edid) == 0)
        return 13;

    return 0;
}

int
main(void)
{
    int result;

    result = test_mode_database();
    if (result != 0)
        return result;
    result = test_generated_timing();
    if (result != 0)
        return result;
    result = test_mode_sorting();
    if (result != 0)
        return result;
    return test_edid_validation();
}
