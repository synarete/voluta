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
#define _GNU_SOURCE 1
#include <stdlib.h>

#include <voluta/list.h>


static void list_head_set(struct voluta_list_head *lnk,
                          struct voluta_list_head *prv,
                          struct voluta_list_head *nxt)
{
	lnk->next = nxt;
	lnk->prev = prv;
}

static void list_head_insert(struct voluta_list_head *lnk,
                             struct voluta_list_head *prv,
                             struct voluta_list_head *nxt)
{
	list_head_set(lnk, prv, nxt);

	nxt->prev = lnk;
	prv->next = lnk;
}

void voluta_list_head_insert_after(struct voluta_list_head *prev_lnk,
                                   struct voluta_list_head *lnk)
{
	list_head_insert(lnk, prev_lnk, prev_lnk->next);
}

void voluta_list_head_insert_before(struct voluta_list_head *lnk,
                                    struct voluta_list_head *next_lnk)
{
	list_head_insert(lnk, next_lnk->prev, next_lnk);
}

void voluta_list_head_remove(struct voluta_list_head *lnk)
{
	struct voluta_list_head *next = lnk->next;
	struct voluta_list_head *prev = lnk->prev;

	next->prev = prev;
	prev->next = next;
	list_head_set(lnk, lnk, lnk);
}

void voluta_list_head_init(struct voluta_list_head *lnk)
{
	list_head_set(lnk, lnk, lnk);
}

void voluta_list_head_initn(struct voluta_list_head *lnk_arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		voluta_list_head_init(&lnk_arr[i]);
	}
}

void voluta_list_head_fini(struct voluta_list_head *lnk)
{
	list_head_set(lnk, NULL, NULL);
}

void voluta_list_head_finin(struct voluta_list_head *lnk_arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		voluta_list_head_fini(&lnk_arr[i]);
	}
}

void voluta_list_init(struct voluta_list_head *lst)
{
	voluta_list_head_init(lst);
}

void voluta_list_fini(struct voluta_list_head *lst)
{
	voluta_list_head_fini(lst);
}

void voluta_list_push_front(struct voluta_list_head *lst,
                            struct voluta_list_head *lnk)
{
	voluta_list_head_insert_after(lst, lnk);
}

void voluta_list_push_back(struct voluta_list_head *lst,
                           struct voluta_list_head *lnk)
{
	voluta_list_head_insert_before(lnk, lst);
}

struct voluta_list_head *voluta_list_front(const struct voluta_list_head *lst)
{
	return lst->next;
}

struct voluta_list_head *voluta_list_back(const struct voluta_list_head *lst)
{
	return lst->prev;
}

struct voluta_list_head *voluta_list_pop_front(struct voluta_list_head *lst)
{
	struct voluta_list_head *lnk;

	lnk = voluta_list_front(lst);
	if (lnk != lst) {
		voluta_list_head_remove(lnk);
	} else {
		lnk = NULL;
	}
	return lnk;
}

bool voluta_list_isempty(const struct voluta_list_head *lst)
{
	return (lst->next == lst);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


void voluta_listq_init(struct voluta_listq *lsq)
{
	voluta_list_init(&lsq->ls);
	lsq->sz = 0;
}

void voluta_listq_initn(struct voluta_listq *lsq, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		voluta_listq_init(&lsq[i]);
	}
}

void voluta_listq_fini(struct voluta_listq *lsq)
{
	voluta_list_fini(&lsq->ls);
	lsq->sz = 0;
}

void voluta_listq_finin(struct voluta_listq *lsq, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		voluta_listq_fini(&lsq[i]);
	}
}

bool voluta_listq_isempty(const struct voluta_listq *lsq)
{
	return (lsq->sz == 0);
}

void voluta_listq_remove(struct voluta_listq *lsq,
                         struct voluta_list_head *lnk)
{
	voluta_list_head_remove(lnk);
	lsq->sz--;
}

void voluta_listq_push_front(struct voluta_listq *lsq,
                             struct voluta_list_head *lnk)
{
	voluta_list_push_front(&lsq->ls, lnk);
	lsq->sz++;
}

void voluta_listq_push_back(struct voluta_listq *lsq,
                            struct voluta_list_head *lnk)
{
	voluta_list_push_back(&lsq->ls, lnk);
	lsq->sz++;
}

struct voluta_list_head *voluta_listq_pop_front(struct voluta_listq *lsq)
{
	struct voluta_list_head *lnk = NULL;

	if (lsq->sz > 0) {
		lnk = voluta_list_pop_front(&lsq->ls);
		lsq->sz--;
	}
	return lnk;
}

struct voluta_list_head *voluta_listq_front(const struct voluta_listq *lsq)
{
	struct voluta_list_head *lnk = NULL;

	if (lsq->sz > 0) {
		lnk = voluta_list_front(&lsq->ls);
	}
	return lnk;
}

struct voluta_list_head *voluta_listq_back(const struct voluta_listq *lsq)
{
	struct voluta_list_head *lnk = NULL;

	if (lsq->sz > 0) {
		lnk = voluta_list_back(&lsq->ls);
	}
	return lnk;
}

struct voluta_list_head *
voluta_listq_next(const struct voluta_listq *lsq,
                  const struct voluta_list_head *lnk)
{
	struct voluta_list_head *nxt = NULL;

	if ((lsq->sz > 0) && (lnk->next != &lsq->ls)) {
		nxt = lnk->next;
	}
	return nxt;
}

struct voluta_list_head *
voluta_listq_prev(const struct voluta_listq *lsq,
                  const struct voluta_list_head *lnk)
{
	struct voluta_list_head *prv = NULL;

	if ((lsq->sz > 0) && (lnk->prev != &lsq->ls)) {
		prv = lnk->prev;
	}
	return prv;
}


