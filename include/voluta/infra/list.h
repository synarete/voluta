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
#ifndef VOLUTA_LIST_H_
#define VOLUTA_LIST_H_

#include <stdlib.h>
#include <stdbool.h>

/* linked-list */
struct voluta_list_head {
	struct voluta_list_head *prev;
	struct voluta_list_head *next;
};


/* sized linked-list queue */
struct voluta_listq {
	struct voluta_list_head ls;
	size_t sz;
};

void voluta_list_head_init(struct voluta_list_head *lnk);

void voluta_list_head_initn(struct voluta_list_head *lnk_arr, size_t cnt);

void voluta_list_head_fini(struct voluta_list_head *lnk);

void voluta_list_head_finin(struct voluta_list_head *lnk_arr, size_t cnt);

bool voluta_list_isempty(const struct voluta_list_head *lst);

void voluta_list_head_insert_after(struct voluta_list_head *prev_lnk,
                                   struct voluta_list_head *lnk);

void voluta_list_head_insert_before(struct voluta_list_head *lnk,
                                    struct voluta_list_head *next_lnk);

void voluta_list_head_remove(struct voluta_list_head *lnk);

void voluta_list_init(struct voluta_list_head *lst);

void voluta_list_fini(struct voluta_list_head *lst);

void voluta_list_push_front(struct voluta_list_head *lst,
                            struct voluta_list_head *lnk);

void voluta_list_push_back(struct voluta_list_head *lst,
                           struct voluta_list_head *lnk);

struct voluta_list_head *
voluta_list_front(const struct voluta_list_head *lst);

struct voluta_list_head *
voluta_list_back(const struct voluta_list_head *lst);

struct voluta_list_head *
voluta_list_pop_front(struct voluta_list_head *lst);


void voluta_listq_init(struct voluta_listq *lsq);

void voluta_listq_initn(struct voluta_listq *lsq, size_t cnt);

void voluta_listq_fini(struct voluta_listq *lsq);

void voluta_listq_finin(struct voluta_listq *lsq, size_t cnt);

bool voluta_listq_isempty(const struct voluta_listq *lsq);

void voluta_listq_remove(struct voluta_listq *lsq,
                         struct voluta_list_head *lnk);

void voluta_listq_push_front(struct voluta_listq *lsq,
                             struct voluta_list_head *lnk);

void voluta_listq_push_back(struct voluta_listq *lsq,
                            struct voluta_list_head *lnk);

struct voluta_list_head *voluta_listq_pop_front(struct voluta_listq *lsq);

struct voluta_list_head *voluta_listq_front(const struct voluta_listq *lsq);

struct voluta_list_head *voluta_listq_back(const struct voluta_listq *lsq);

struct voluta_list_head *
voluta_listq_next(const struct voluta_listq *lsq,
                  const struct voluta_list_head *lnk);

struct voluta_list_head *
voluta_listq_prev(const struct voluta_listq *lsq,
                  const struct voluta_list_head *lnk);

#endif /* VOLUTA_LIST_H_ */




