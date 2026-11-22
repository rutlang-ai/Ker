#ifndef KER_NGINX_SOURCE_UPGRADE_DIRECTORY_H
#define KER_NGINX_SOURCE_UPGRADE_DIRECTORY_H

#include <stdbool.h>

#define KER_NGINX_SOURCE_UPGRADE_DIRECTORY_BYTES 6424

/* The caller must own the authenticated bootstrap grant for this descriptor.
 * It may close the descriptor after attaching. The resident slim actor
 * initializes the mapping before acknowledging its original startup. */
int ker_nginx_source_upgrade_directory_attach(int fd, bool slim);
void ker_nginx_source_upgrade_directory_detach(void);

#endif
