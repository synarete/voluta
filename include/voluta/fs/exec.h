/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of voluta.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
 *
 * Voluta is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Voluta is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef VOLUTA_EXEC_H_
#define VOLUTA_EXEC_H_


struct voluta_fs_stats {
	size_t nalloc_bytes;
	size_t ncache_blocks;
	size_t ncache_inodes;
	size_t ncache_vnodes;
};


int voluta_fse_new(const struct voluta_fs_args *args,
                   struct voluta_fs_env **out_fse);

void voluta_fse_del(struct voluta_fs_env *fse);

int voluta_fse_reload(struct voluta_fs_env *fse);

int voluta_fse_format(struct voluta_fs_env *fse);

int voluta_fse_serve(struct voluta_fs_env *fse);

int voluta_fse_verify(struct voluta_fs_env *fse);

int voluta_fse_term(struct voluta_fs_env *fse);

void voluta_fse_halt(struct voluta_fs_env *fse, int signum);

int voluta_fse_sync_drop(struct voluta_fs_env *fse);

void voluta_fse_stats(const struct voluta_fs_env *fse,
                      struct voluta_fs_stats *st);

int voluta_fse_rootid(const struct voluta_fs_env *fse, char *buf, size_t bsz);

#endif /* VOLUTA_EXEC_H_ */
