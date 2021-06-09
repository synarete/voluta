/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * This file is part of libvoluta
 *
 * Copyright (C) 2020-2021 Shachar Sharon
 *
 * Libvoluta is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Libvoluta is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */
#ifndef VOLUTA_FIOVEC_H_
#define VOLUTA_FIOVEC_H_

#include <stdlib.h>


struct voluta_fiovec {
	void  *fv_base;
	size_t fv_len;
	loff_t fv_off;
	int    fv_fd;
	int    fv_backref_type;
	void  *fv_backref;
};

#endif /* VOLUTA_FIOVEC_H_ */
