/* SPDX-License-Identifier: MPL-2.0 */
/* Compiler runtime helpers required by imported FreeBSD drivers. */

int
__popcountdi2(unsigned long long value)
{
    int count = 0;

    while (value != 0) {
        value &= value - 1;
        count++;
    }
    return count;
}
