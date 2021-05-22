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
#ifndef VOLUTA_FUSEQ_H_
#define VOLUTA_FUSEQ_H_

struct voluta_fuseq;
struct voluta_sb_info;

int voluta_fuseq_init(struct voluta_fuseq *fq, struct voluta_sb_info *sbi);

void voluta_fuseq_fini(struct voluta_fuseq *fq);

int voluta_fuseq_mount(struct voluta_fuseq *fq, const char *path);

int voluta_fuseq_exec(struct voluta_fuseq *fq);

void voluta_fuseq_term(struct voluta_fuseq *fq);

#endif /* VOLUTA_FUSEQ_H_ */
