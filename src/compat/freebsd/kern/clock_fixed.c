/* SPDX-License-Identifier: MPL-2.0 */
/* Fixed-rate and fixed-factor providers for the shared clock framework. */

#include <stdint.h>

#include <sys/bus.h>
#include <sys/kobj.h>

#include <dev/clk/clk_fixed.h>

#define BSD_CLOCK_FIXED_ERANGE 34

struct edgeos_fixed_clock {
    uint64_t frequency;
    uint32_t multiplier;
    uint32_t divisor;
    int flags;
};

static int
edgeos_fixed_clock_init(struct clknode *clock, device_t device)
{
    struct edgeos_fixed_clock *state = clknode_get_softc(clock);

    (void)device;
    if (state && state->frequency == 0)
        clknode_init_parent_idx(clock, 0);
    return state ? 0 : BSD_CLOCK_FIXED_ERANGE;
}

static int
edgeos_fixed_clock_recalculate(struct clknode *clock,
    uint64_t *frequency)
{
    struct edgeos_fixed_clock *state = clknode_get_softc(clock);

    if (!state || !frequency)
        return BSD_CLOCK_FIXED_ERANGE;
    if (state->multiplier != 0 && state->divisor != 0) {
        *frequency = (*frequency / state->divisor) *
            state->multiplier;
    } else {
        *frequency = state->frequency;
    }
    return 0;
}

static int
edgeos_fixed_clock_set_frequency(struct clknode *clock,
    uint64_t input, uint64_t *output, int flags, int *done)
{
    struct edgeos_fixed_clock *state = clknode_get_softc(clock);

    (void)input;
    (void)flags;
    if (!state || !output || !done)
        return BSD_CLOCK_FIXED_ERANGE;
    if (state->multiplier == 0 || state->divisor == 0) {
        *done = 1;
        return *output == state->frequency ?
            0 : BSD_CLOCK_FIXED_ERANGE;
    }
    *done = 0;
    *output = (*output / state->multiplier) * state->divisor;
    return 0;
}

static clknode_method_t edgeos_fixed_clock_methods[] = {
    CLKNODEMETHOD(clknode_init, edgeos_fixed_clock_init),
    CLKNODEMETHOD(clknode_recalc_freq,
        edgeos_fixed_clock_recalculate),
    CLKNODEMETHOD(clknode_set_freq,
        edgeos_fixed_clock_set_frequency),
    CLKNODEMETHOD_END
};

DEFINE_CLASS_1(edgeos_fixed_clock, edgeos_fixed_clock_class,
    edgeos_fixed_clock_methods, sizeof(struct edgeos_fixed_clock),
    clknode_class);

int
clknode_fixed_register(struct clkdom *domain,
    struct clk_fixed_def *definition)
{
    struct edgeos_fixed_clock *state;
    struct clknode *clock;

    if (!domain || !definition || !definition->clkdef.name ||
        definition->clkdef.name[0] == '\0')
        return BSD_CLOCK_FIXED_ERANGE;
    if ((definition->mult == 0) != (definition->div == 0))
        return BSD_CLOCK_FIXED_ERANGE;
    clock = clknode_create(domain, &edgeos_fixed_clock_class,
        &definition->clkdef);
    if (!clock)
        return BSD_CLOCK_FIXED_ERANGE;
    state = clknode_get_softc(clock);
    if (!state)
        return BSD_CLOCK_FIXED_ERANGE;
    state->frequency = definition->freq;
    state->multiplier = definition->mult;
    state->divisor = definition->div;
    state->flags = definition->fixed_flags;
    return clknode_register(domain, clock) ? 0 :
        BSD_CLOCK_FIXED_ERANGE;
}
