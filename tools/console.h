/*
 * console.c: A dumb serial console client
 *
 * Copyright (C) 2007, 2010 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Daniel Berrange <berrange@redhat.com>
 */

#ifndef __VIR_CONSOLE_H__
# define __VIR_CONSOLE_H__

# ifndef WIN32

int vshRunConsole(virDomainPtr dom,
                  const char *dev_name,
                  const char *escape_seq,
                  unsigned int flags);

int vshMakeStdinRaw(struct termios *ttyattr, bool report_errors);

# endif /* !WIN32 */

#endif /* __VIR_CONSOLE_H__ */
