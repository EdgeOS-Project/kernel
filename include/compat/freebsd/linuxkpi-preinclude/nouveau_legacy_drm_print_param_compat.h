#pragma once

/* Keep the embedded legacy DRM core parameters distinct from Nouveau's. */
#undef LINUXKPI_PARAM_PREFIX
#define LINUXKPI_PARAM_PREFIX nouveau_drmcore_

