#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "types.h"
#include "common.h"
#include "dir_common.h"
#include "legacyfs_dir.h"

#ifdef HAVE_LIBLEGACYFS
#include "legacyfs.h"
#endif

const char *td_legacyfs_version(void)
{
#ifdef HAVE_LIBLEGACYFS
  return legacyfs_version();
#else
  return "none";
#endif
}
