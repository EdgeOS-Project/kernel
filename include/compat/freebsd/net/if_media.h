/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NET_IF_MEDIA_H_
#define _NET_IF_MEDIA_H_

#include <stdint.h>
#include <sys/queue.h>

#include "if.h"

typedef int (*ifm_change_cb_t)(struct ifnet *);
typedef void (*ifm_stat_cb_t)(struct ifnet *, struct ifmediareq *);

struct ifmedia_entry {
    LIST_ENTRY(ifmedia_entry) ifm_list;
    int ifm_media;
    int ifm_data;
    void *ifm_aux;
};

struct ifmedia {
    int ifm_mask;
    int ifm_media;
    struct ifmedia_entry *ifm_cur;
    LIST_HEAD(, ifmedia_entry) ifm_list;
    ifm_change_cb_t ifm_change;
    ifm_stat_cb_t ifm_status;
};

#define IFM_ETHER 0x00000020
#define IFM_AUTO 0
#define IFM_MANUAL 1
#define IFM_NONE 2
#define IFM_10_T 3
#define IFM_10_2 4
#define IFM_10_5 5
#define IFM_100_TX 6
#define IFM_100_FX 7
#define IFM_100_T4 8
#define IFM_100_VG 9
#define IFM_100_T2 10
#define IFM_1000_SX 11
#define IFM_10_STP 12
#define IFM_10_FL 13
#define IFM_1000_LX 14
#define IFM_1000_CX 15
#define IFM_1000_T 16
#define IFM_HPNA_1 17
#define IFM_10G_LR 18
#define IFM_10G_SR 19
#define IFM_10G_CX4 20
#define IFM_2500_SX 21
#define IFM_10G_TWINAX 22
#define IFM_10G_TWINAX_LONG 23
#define IFM_10G_LRM 24
#define IFM_UNKNOWN 25
#define IFM_10G_T 26
#define IFM_40G_CR4 27
#define IFM_40G_SR4 28
#define IFM_40G_LR4 29
#define IFM_1000_KX 30
#define IFM_OTHER 31
#define IFM_ETH_XTYPE 0x00007800
#define IFM_ETH_XSHIFT 6
#define IFM_ETHER_SUBTYPE(value) (((value) & IFM_TMASK) | \
    (((value) & (IFM_ETH_XTYPE >> IFM_ETH_XSHIFT)) << IFM_ETH_XSHIFT))
#define IFM_X(value) IFM_ETHER_SUBTYPE(value)
#define IFM_10G_KX4 IFM_X(32)
#define IFM_10G_KR IFM_X(33)
#define IFM_10G_CR1 IFM_X(34)
#define IFM_20G_KR2 IFM_X(35)
#define IFM_2500_KX IFM_X(36)
#define IFM_2500_T IFM_X(37)
#define IFM_5000_T IFM_X(38)
#define IFM_1000_SGMII IFM_X(41)
#define IFM_10G_SFI IFM_X(42)
#define IFM_40G_XLPPI IFM_X(43)
#define IFM_40G_KR4 IFM_X(45)
#define IFM_100G_CR4 IFM_X(47)
#define IFM_100G_SR4 IFM_X(48)
#define IFM_100G_KR4 IFM_X(49)
#define IFM_100G_LR4 IFM_X(50)
#define IFM_100_T IFM_X(52)
#define IFM_25G_CR IFM_X(53)
#define IFM_25G_KR IFM_X(54)
#define IFM_25G_SR IFM_X(55)
#define IFM_50G_CR2 IFM_X(56)
#define IFM_50G_KR2 IFM_X(57)
#define IFM_25G_LR IFM_X(58)
#define IFM_10G_AOC IFM_X(59)
#define IFM_25G_ACC IFM_X(60)
#define IFM_25G_AOC IFM_X(61)
#define IFM_100_SGMII IFM_X(62)
#define IFM_2500_X IFM_X(63)
#define IFM_5000_KR IFM_X(64)
#define IFM_25G_T IFM_X(65)
#define IFM_25G_CR_S IFM_X(66)
#define IFM_25G_CR1 IFM_X(67)
#define IFM_25G_KR_S IFM_X(68)
#define IFM_25G_AUI IFM_X(71)
#define IFM_40G_XLAUI IFM_X(72)
#define IFM_40G_XLAUI_AC IFM_X(73)
#define IFM_50G_SR2 IFM_X(75)
#define IFM_50G_LR2 IFM_X(76)
#define IFM_50G_LAUI2_AC IFM_X(77)
#define IFM_50G_LAUI2 IFM_X(78)
#define IFM_50G_AUI2_AC IFM_X(79)
#define IFM_50G_AUI2 IFM_X(80)
#define IFM_50G_CP IFM_X(81)
#define IFM_50G_SR IFM_X(82)
#define IFM_50G_LR IFM_X(83)
#define IFM_50G_FR IFM_X(84)
#define IFM_50G_KR_PAM4 IFM_X(85)
#define IFM_25G_KR1 IFM_X(86)
#define IFM_50G_AUI1_AC IFM_X(87)
#define IFM_50G_AUI1 IFM_X(88)
#define IFM_100G_CAUI4_AC IFM_X(89)
#define IFM_100G_CAUI4 IFM_X(90)
#define IFM_100G_AUI4_AC IFM_X(91)
#define IFM_100G_AUI4 IFM_X(92)
#define IFM_100G_CR_PAM4 IFM_X(93)
#define IFM_100G_KR_PAM4 IFM_X(94)
#define IFM_100G_CP2 IFM_X(95)
#define IFM_100G_SR2 IFM_X(96)
#define IFM_100G_DR IFM_X(97)
#define IFM_100G_KR2_PAM4 IFM_X(98)
#define IFM_100G_CAUI2_AC IFM_X(99)
#define IFM_100G_CAUI2 IFM_X(100)
#define IFM_100G_AUI2_AC IFM_X(101)
#define IFM_100G_AUI2 IFM_X(102)
#define IFM_200G_CR4_PAM4 IFM_X(103)
#define IFM_200G_SR4 IFM_X(104)
#define IFM_200G_FR4 IFM_X(105)
#define IFM_200G_LR4 IFM_X(106)
#define IFM_200G_DR4 IFM_X(107)
#define IFM_200G_KR4_PAM4 IFM_X(108)
#define IFM_200G_AUI4_AC IFM_X(109)
#define IFM_200G_AUI4 IFM_X(110)
#define IFM_200G_AUI8_AC IFM_X(111)
#define IFM_200G_AUI8 IFM_X(112)
#define IFM_1000_BX IFM_X(121)
#define IFM_FDX 0x00100000
#define IFM_HDX 0x00200000
#define IFM_FLOW 0x00400000
#define IFM_LOOP 0x08000000
#define IFM_ETH_MASTER 0x00000100
#define IFM_ETH_RXPAUSE 0x00000200
#define IFM_ETH_TXPAUSE 0x00000400
#define IFM_AVALID 0x00000001
#define IFM_ACTIVE 0x00000002
#define IFM_NMASK 0x000000e0
#define IFM_TMASK 0x0000001f
#define IFM_GMASK 0x0ff00000
#define IFM_IMASK 0xf0000000
#define IFM_OMASK 0x0000ff00
#define IFM_MMASK 0x00070000
#define IFM_ISHIFT 28
#define IFM_MSHIFT 16
#define IFM_FLAG0 0x01000000
#define IFM_FLAG1 0x02000000
#define IFM_FLAG2 0x04000000
#define IFM_IEEE80211 0x00000080
#define IFM_IEEE80211_FH1 3
#define IFM_IEEE80211_FH2 4
#define IFM_IEEE80211_DS1 5
#define IFM_IEEE80211_DS2 6
#define IFM_IEEE80211_DS5 7
#define IFM_IEEE80211_DS11 8
#define IFM_IEEE80211_DS22 9
#define IFM_IEEE80211_OFDM6 10
#define IFM_IEEE80211_OFDM9 11
#define IFM_IEEE80211_OFDM12 12
#define IFM_IEEE80211_OFDM18 13
#define IFM_IEEE80211_OFDM24 14
#define IFM_IEEE80211_OFDM36 15
#define IFM_IEEE80211_OFDM48 16
#define IFM_IEEE80211_OFDM54 17
#define IFM_IEEE80211_OFDM72 18
#define IFM_IEEE80211_DS354k 19
#define IFM_IEEE80211_DS512k 20
#define IFM_IEEE80211_OFDM3 21
#define IFM_IEEE80211_OFDM4 22
#define IFM_IEEE80211_OFDM27 23
#define IFM_IEEE80211_MCS 24
#define IFM_IEEE80211_VHT 25
#define IFM_IEEE80211_ADHOC 0x00000100
#define IFM_IEEE80211_HOSTAP 0x00000200
#define IFM_IEEE80211_IBSS 0x00000400
#define IFM_IEEE80211_WDS 0x00000800
#define IFM_IEEE80211_TURBO 0x00001000
#define IFM_IEEE80211_MONITOR 0x00002000
#define IFM_IEEE80211_MBSS 0x00004000
#define IFM_IEEE80211_11A 0x00010000
#define IFM_IEEE80211_11B 0x00020000
#define IFM_IEEE80211_11G 0x00030000
#define IFM_IEEE80211_FH 0x00040000
#define IFM_IEEE80211_11NA 0x00050000
#define IFM_IEEE80211_11NG 0x00060000
#define IFM_IEEE80211_VHT5G 0x00070000
#define IFM_IEEE80211_VHT2G 0x00080000
#define IFM_TYPE(value) ((value) & IFM_NMASK)
#define IFM_MODE(value) ((value) & IFM_MMASK)
#define IFM_MAKEWORD(type, subtype, options, instance) \
    ((type) | (subtype) | (options) | ((instance) << IFM_ISHIFT))
#define IFM_SUBTYPE(value) \
    (IFM_TYPE(value) == IFM_ETHER ? \
    ((value) & (IFM_TMASK | IFM_ETH_XTYPE)) : ((value) & IFM_TMASK))
#define IFM_INST(value) (((value) & IFM_IMASK) >> IFM_ISHIFT)
#define IFM_OPTIONS(value) ((value) & (IFM_OMASK | IFM_GMASK))

void ifmedia_init(struct ifmedia *media, int mask,
    ifm_change_cb_t change_callback, ifm_stat_cb_t status_callback);
void ifmedia_removeall(struct ifmedia *media);
void ifmedia_add(struct ifmedia *media, int media_word, int data,
    void *auxiliary);
void ifmedia_set(struct ifmedia *media, int media_word);
int ifmedia_ioctl(struct ifnet *ifp, struct ifreq *request,
    struct ifmedia *media, unsigned long command);
uint64_t ifmedia_baudrate(int media_word);

#endif
