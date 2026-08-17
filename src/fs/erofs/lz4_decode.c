/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-neutral decoder for the standard LZ4 block format.
 * It retains only the 64 KiB match window and copies the requested range,
 * so large EROFS extents do not need equally large temporary allocations.
 */

#include <stdint.h>

#include "lz4_decode.h"

typedef struct edge_lz4_output {
    uint8_t *destination;
    uint8_t *history;
    uint64_t produced;
    uint64_t decoded_size;
    uint64_t wanted_offset;
    uint64_t wanted_end;
    uint32_t history_size;
} edge_lz4_output_t;

static int edge_lz4_emit(edge_lz4_output_t *state, uint8_t value) {
    if (!state || state->produced >= state->decoded_size)
        return -1;
    state->history[state->produced % state->history_size] = value;
    if (state->produced >= state->wanted_offset &&
        state->produced < state->wanted_end)
        state->destination[state->produced - state->wanted_offset] = value;
    ++state->produced;
    return 0;
}

static int edge_lz4_length(const uint8_t **cursor, const uint8_t *end,
                           uint64_t base, uint64_t *length) {
    uint64_t value = base;

    if (!cursor || !*cursor || !length) return -1;
    if (base == 15u) {
        for (;;) {
            uint8_t extension;
            if (*cursor >= end) return -1;
            extension = *(*cursor)++;
            if (value > UINT64_MAX - extension) return -1;
            value += extension;
            if (extension != 255u) break;
        }
    }
    *length = value;
    return 0;
}

int edge_lz4_extract(const uint8_t *input, uint32_t input_size,
                     uint64_t decoded_size, uint64_t wanted_offset,
                     void *output, uint32_t wanted_size,
                     uint8_t *history, uint32_t history_size) {
    const uint8_t *cursor = input;
    const uint8_t *end;
    edge_lz4_output_t state;

    if (!input || (!output && wanted_size) || !history ||
        history_size < EDGE_LZ4_HISTORY_SIZE ||
        wanted_offset > decoded_size ||
        wanted_size > decoded_size - wanted_offset)
        return -1;
    end = input + input_size;
    state.destination = output;
    state.history = history;
    state.produced = 0;
    state.decoded_size = decoded_size;
    state.wanted_offset = wanted_offset;
    state.wanted_end = wanted_offset + wanted_size;
    state.history_size = history_size;

    while (cursor < end && state.produced < decoded_size) {
        uint8_t token = *cursor++;
        uint64_t literal_length;
        uint64_t match_length;
        uint32_t match_offset;

        if (edge_lz4_length(&cursor, end, token >> 4, &literal_length) < 0 ||
            literal_length > (uint64_t)(end - cursor) ||
            literal_length > decoded_size - state.produced)
            return -1;
        for (uint64_t index = 0; index < literal_length; ++index)
            if (edge_lz4_emit(&state, *cursor++) < 0) return -1;

        if (cursor == end)
            return state.produced == decoded_size ? (int)wanted_size : -1;
        if (end - cursor < 2) return -1;
        match_offset = (uint32_t)cursor[0] | ((uint32_t)cursor[1] << 8);
        cursor += 2;
        if (!match_offset || match_offset > state.produced ||
            match_offset > history_size)
            return -1;
        if (edge_lz4_length(
                &cursor, end, token & 0x0fu, &match_length) < 0 ||
            match_length > UINT64_MAX - 4u)
            return -1;
        match_length += 4u;
        if (match_length > decoded_size - state.produced) return -1;
        for (uint64_t index = 0; index < match_length; ++index) {
            uint8_t value = history[
                (state.produced - match_offset) % history_size];
            if (edge_lz4_emit(&state, value) < 0) return -1;
        }
    }
    return state.produced == decoded_size && cursor == end ?
           (int)wanted_size : -1;
}
