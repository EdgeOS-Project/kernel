/* SPDX-License-Identifier: MPL-2.0 */
/* Compile-time disabled SDT interface for BSD drivers on EdgeOS. */

#ifndef _SYS_SDT_H_
#define _SYS_SDT_H_

#define SDT_PROVIDER_DEFINE(provider)
#define SDT_PROVIDER_DECLARE(provider)
#define SDT_PROBE_DEFINE(provider, module, function, name)
#define SDT_PROBE_DECLARE(provider, module, function, name)
#define SDT_PROBES_ENABLED() 0
#define SDT_PROBE_ARGTYPE(provider, module, function, name, number, type, \
    translated_type)

#define SDT_PROBE_DEFINE0(provider, module, function, name)
#define SDT_PROBE_DEFINE1(provider, module, function, name, type0)
#define SDT_PROBE_DEFINE2(provider, module, function, name, type0, type1)
#define SDT_PROBE_DEFINE3(provider, module, function, name, type0, type1, \
    type2)
#define SDT_PROBE_DEFINE4(provider, module, function, name, type0, type1, \
    type2, type3)
#define SDT_PROBE_DEFINE5(provider, module, function, name, type0, type1, \
    type2, type3, type4)
#define SDT_PROBE_DEFINE6(provider, module, function, name, type0, type1, \
    type2, type3, type4, type5)

#define SDT_PROBE0(provider, module, function, name)
#define SDT_PROBE1(provider, module, function, name, argument0)
#define SDT_PROBE2(provider, module, function, name, argument0, argument1)
#define SDT_PROBE3(provider, module, function, name, argument0, argument1, \
    argument2)
#define SDT_PROBE4(provider, module, function, name, argument0, argument1, \
    argument2, argument3)
#define SDT_PROBE5(provider, module, function, name, argument0, argument1, \
    argument2, argument3, argument4)
#define SDT_PROBE6(provider, module, function, name, argument0, argument1, \
    argument2, argument3, argument4, argument5)

#define SDT_PROBE_DEFINE0_XLATE(provider, module, function, name)
#define SDT_PROBE_DEFINE1_XLATE(provider, module, function, name, type0, \
    translated0)
#define SDT_PROBE_DEFINE2_XLATE(provider, module, function, name, type0, \
    translated0, type1, translated1)
#define SDT_PROBE_DEFINE3_XLATE(provider, module, function, name, type0, \
    translated0, type1, translated1, type2, translated2)
#define SDT_PROBE_DEFINE4_XLATE(provider, module, function, name, type0, \
    translated0, type1, translated1, type2, translated2, type3, translated3)
#define SDT_PROBE_DEFINE5_XLATE(provider, module, function, name, type0, \
    translated0, type1, translated1, type2, translated2, type3, translated3, \
    type4, translated4)
#define SDT_PROBE_DEFINE6_XLATE(provider, module, function, name, type0, \
    translated0, type1, translated1, type2, translated2, type3, translated3, \
    type4, translated4, type5, translated5)

#define DTRACE_PROBE(name)
#define DTRACE_PROBE1(name, type0, argument0)
#define DTRACE_PROBE2(name, type0, argument0, type1, argument1)
#define DTRACE_PROBE3(name, type0, argument0, type1, argument1, type2, \
    argument2)
#define DTRACE_PROBE4(name, type0, argument0, type1, argument1, type2, \
    argument2, type3, argument3)
#define DTRACE_PROBE5(name, type0, argument0, type1, argument1, type2, \
    argument2, type3, argument3, type4, argument4)

#define MIB_SDT_PROBE1(...)
#define MIB_SDT_PROBE2(...)

#endif
