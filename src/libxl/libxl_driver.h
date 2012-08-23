/*---------------------------------------------------------------------------*/
/*  Copyright (c) 2011 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Jim Fehlig <jfehlig@novell.com>
 */
/*---------------------------------------------------------------------------*/

#ifndef LIBXL_DRIVER_H
# define LIBXL_DRIVER_H

# include <config.h>

# define LIBXL_MIGRATION_FLAGS                   \
    (VIR_MIGRATE_LIVE |                         \
     VIR_MIGRATE_UNDEFINE_SOURCE |              \
     VIR_MIGRATE_PAUSED)

# define MAXCONN_NUM 10
# define LIBXL_MIGRATION_MIN_PORT 49512
# define LIBXL_MIGRATION_NUM_PORTS 64
# define LIBXL_MIGRATION_MAX_PORT                \
    (LIBXL_MIGRATION_MIN_PORT + LIBXL_MIGRATION_NUM_PORTS)

static const char migrate_receiver_banner[]=
    "xl migration receiver ready, send binary domain data";
static const char migrate_receiver_ready[]=
    "domain received, ready to unpause";

int libxlRegister(void);

#endif /* LIBXL_DRIVER_H */
