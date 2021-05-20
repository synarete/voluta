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
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <limits.h>
#include <voluta/infra/macros.h>
#include <voluta/infra/errors.h>
#include <voluta/infra/utility.h>
#include <voluta/infra/strings.h>


static char *unconst_str(const char *s)
{
	union {
		const void *p;
		void *q;
	} u = {
		.p = s
	};
	return u.q;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void chr_assign(char *c1, char c2)
{
	*c1 = c2;
}

static int chr_eq(char c1, char c2)
{
	return c1 == c2;
}

static void chr_swap(char *p, char *q)
{
	const char c = *p;

	*p = *q;
	*q = c;
}

/*
static int chr_lt(char c1, char c2)
{
    return c1 < c2;
}
*/
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t str_length(const char *s)
{
	return strlen(s);
}

size_t voluta_str_length(const char *s)
{
	return str_length(s);
}

int voluta_str_compare(const char *s1, const char *s2, size_t n)
{
	return memcmp(s1, s2, n);
}

int voluta_str_ncompare(const char *s1, size_t n1,
                        const char *s2, size_t n2)
{
	int res;
	size_t n;

	n   = voluta_min(n1, n2);
	res = voluta_str_compare(s1, s2, n);

	if (res == 0) {
		res = (n1 > n2) - (n1 < n2);
	}

	return res;
}

const char *voluta_str_find_chr(const char *s, size_t n, char a)
{
	return (const char *)(memchr(s, a, n));
}

const char *voluta_str_find(const char *s1, size_t n1,
                            const char *s2, size_t n2)
{
	const char *q;

	if (!n2 || (n1 < n2)) {
		return NULL;
	}
	q = s1 + (n1 - n2 + 1);
	for (const char *p = s1; p != q; ++p) {
		if (!voluta_str_compare(p, s2, n2)) {
			return p;
		}
	}
	return NULL;
}

const char *voluta_str_rfind(const char *s1, size_t n1,
                             const char *s2, size_t n2)
{
	if (!n2 || (n1 < n2)) {
		return NULL;
	}
	for (const char *p = s1 + (n1 - n2); p >= s1; --p) {
		if (!voluta_str_compare(p, s2, n2)) {
			return p;
		}
	}
	return NULL;
}

const char *voluta_str_rfind_chr(const char *s, size_t n, char c)
{
	for (const char *p = s + n; p != s;) {
		if (chr_eq(*--p, c)) {
			return p;
		}
	}
	return NULL;
}

const char *voluta_str_find_first_of(const char *s1, size_t n1,
                                     const char *s2, size_t n2)
{
	const char *q = s1 + n1;

	for (const char *p = s1; p < q; ++p) {
		if (voluta_str_find_chr(s2, n2, *p) != NULL) {
			return p;
		}
	}
	return NULL;
}

const char *
voluta_str_find_first_not_of(const char *s1, size_t n1,
                             const char *s2, size_t n2)
{
	const char *q = s1 + n1;

	for (const char *p = s1; p < q; ++p) {
		if (voluta_str_find_chr(s2, n2, *p) == NULL) {
			return p;
		}
	}
	return NULL;
}

const char *voluta_str_find_first_not_eq(const char *s, size_t n, char c)
{
	const char *q = s + n;

	for (const char *p = s; p < q; ++p) {
		if (!chr_eq(*p, c)) {
			return p;
		}
	}
	return NULL;
}

const char *
voluta_str_find_last_of(const char *s1, size_t n1,
                        const char *s2, size_t n2)
{
	const char *q = s1 + n1;

	for (const char *p = q; p > s1;) {
		if (voluta_str_find_chr(s2, n2, *--p) != NULL) {
			return p;
		}
	}
	return NULL;
}

const char *
voluta_str_find_last_not_of(const char *s1, size_t n1,
                            const char *s2, size_t n2)
{
	const char *q = s1 + n1;

	for (const char *p = q; p > s1;) {
		if (voluta_str_find_chr(s2, n2, *--p) == NULL) {
			return p;
		}
	}
	return NULL;
}

const char *voluta_str_find_last_not_eq(const char *s, size_t n, char c)
{
	for (const char *p = s + n; p > s;) {
		if (!chr_eq(*--p, c)) {
			return p;
		}
	}
	return NULL;
}

size_t voluta_str_common_prefix(const char *s1, const char *s2, size_t n)
{
	size_t k = 0;
	const char *p = s1;
	const char *q = s2;

	while (k != n) {
		if (!chr_eq(*p, *q)) {
			break;
		}
		++k;
		++p;
		++q;
	}
	return k;
}

size_t voluta_str_common_suffix(const char *s1, const char *s2, size_t n)
{
	size_t k = 0;
	const char *p  = s1 + n;
	const char *q  = s2 + n;

	while (k != n) {
		--p;
		--q;
		if (!chr_eq(*p, *q)) {
			break;
		}
		++k;
	}
	return k;
}

size_t voluta_str_overlaps(const char *s1, size_t n1,
                           const char *s2, size_t n2)
{
	size_t d;
	size_t k;

	if (s1 < s2) {
		d = (size_t)(s2 - s1);
		k = (d < n1) ? (n1 - d) : 0;
	} else {
		d = (size_t)(s1 - s2);
		k = (d < n2) ? (n2 - d) : 0;
	}
	return k;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void voluta_str_terminate(char *s, size_t n)
{
	chr_assign(s + n, '\0');
}

void voluta_str_fill(char *s, size_t n, char c)
{
	memset(s, c, n);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void str_copy(char *s1, const char *s2, size_t n)
{
	memcpy(s1, s2, n);
}

static void str_move(char *s1, const char *s2, size_t n)
{
	memmove(s1, s2, n);
}

void voluta_str_copy(char *t, const char *s, size_t n)
{
	const size_t d = (size_t)((t > s) ? t - s : s - t);

	if (voluta_likely(n > 0) && voluta_likely(d > 0)) {
		if (voluta_likely(n < d)) {
			str_copy(t, s, n);
		} else {
			str_move(t, s, n); /* overlap */
		}
	}
}

void voluta_str_reverse(char *s, size_t n)
{
	char *p = s;
	char *q = s + n - 1;

	while (p < q) {
		chr_swap(p++, q--);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Insert where there is no overlap between source and destination. Tries to
 * insert as many characters as possible, but without overflow.
 *
 * Makes room at the beginning of the buffer: move the current string m steps
 * forward, and then inserts s to the beginning of buffer.
 */
static size_t
str_insert_no_overlap(char *p, size_t sz, size_t n1,
                      const char *s, size_t n2)
{
	const size_t k = voluta_min(n2, sz);
	const size_t m = voluta_min(n1, sz - k);

	voluta_str_copy(p + k, p, m);
	voluta_str_copy(p, s, k);

	return k + m;
}

/*
 * Insert where source and destination may overlap. Using local buffer for
 * safe copy -- avoid dynamic allocation, even at the price of performance
 */
static size_t
str_insert_with_overlap(char *p, size_t sz, size_t n1,
                        const char *s, size_t n2)
{
	size_t n;
	size_t k;
	size_t d;
	const char *q;
	char buf[512];

	n = n1;
	q = s + voluta_min(n2, sz);
	d = (size_t)(q - s);
	while (d > 0) {
		k = voluta_min(d, VOLUTA_ARRAY_SIZE(buf));
		voluta_str_copy(buf, q - k, k);
		n = str_insert_no_overlap(p, sz, n, buf, k);
		d -= k;
	}
	return n;
}

size_t voluta_str_insert(char *p, size_t sz, size_t n1,
                         const char *s, size_t n2)
{
	size_t k;
	size_t n = 0;

	if (n2 >= sz) {
		n = sz;
		voluta_str_copy(p, s, n);
	} else {
		k = voluta_str_overlaps(p, sz, s, n2);
		if (k > 0) {
			n = str_insert_with_overlap(p, sz, n1, s, n2);
		} else {
			n = str_insert_no_overlap(p, sz, n1, s, n2);
		}
	}

	return n;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Inserts n2 copies of c to the front of p. Tries to insert as many characters
 * as possible, but does not insert more then available writable characters
 * in the buffer.
 *
 * Makes room at the beginning of the buffer: move the current string m steps
 * forward, then fill k c-characters into p.
 *
 * p   Target buffer
 * sz  Size of buffer: number of writable elements after p.
 * n1  Number of chars already in p (must be less or equal to sz)
 * n2  Number of copies of c to insert.
 * c   Fill character.
 *
 * Returns the number of characters in p after insertion (always less or equal
 * to sz).
 */
size_t voluta_str_insert_chr(char *p, size_t sz, size_t n1,
                             size_t n2, char c)
{
	size_t m;
	const size_t k = voluta_min(n2, sz);

	m = voluta_min(n1, sz - k);
	voluta_str_copy(p + k, p, m);
	voluta_str_fill(p, k, c);

	return k + m;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_str_replace(char *p, size_t sz, size_t len, size_t n1,
                          const char *s, size_t n2)
{
	size_t k;
	size_t m;

	if (n1 < n2) {
		/*
		 * Case 1: Need to extend existing string. We assume that s
		 * may overlap p and try to do our best...
		 */
		if (s < p) {
			k = n1;
			m = voluta_str_insert(p + k, sz - k,
			                      len - k, s + k, n2 - k);
			voluta_str_copy(p, s, k);
		} else {
			k = n1;
			voluta_str_copy(p, s, n1);
			m = voluta_str_insert(p + k, sz - k,
			                      len - k, s + k, n2 - k);
		}
	} else {
		/*
		 * Case 2: No need to worry about extra space; just copy s to
		 * the beginning of buffer and adjust size, then move the tail
		 * of the string backwards.
		 */
		k = n2;
		voluta_str_copy(p, s, k);

		m = len - n1;
		voluta_str_copy(p + k, p + n1, m);
	}

	return k + m;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_str_replace_chr(char *p, size_t sz, size_t len,
                              size_t n1, size_t n2, char c)
{
	size_t k;
	size_t m;

	if (n1 < n2) {
		/* Case 1: First fill n1 characters, then insert the rest */
		k = n1;
		voluta_str_fill(p, k, c);
		m = voluta_str_insert_chr(p + k, sz - k, len - k, n2 - k, c);
	} else {
		/*
		 * Case 2: No need to worry about extra space; just fill n2
		 * characters in the beginning of buffer.
		 */
		k = n2;
		voluta_str_fill(p, k, c);

		/* Move the tail of the string backwards. */
		m = len - n1;
		voluta_str_copy(p + k, p + n1, m);
	}
	return k + m;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/*
 * Wrappers over standard ctypes functions (macros?).
 */
static bool int_to_bool(int v)
{
	return (v != 0);
}

bool voluta_chr_isalnum(char c)
{
	return int_to_bool(isalnum(c));
}

bool voluta_chr_isalpha(char c)
{
	return int_to_bool(isalpha(c));
}

bool voluta_chr_isascii(char c)
{
	return int_to_bool(isascii(c));
}

bool voluta_chr_isblank(char c)
{
	return int_to_bool(isblank(c));
}

bool voluta_chr_iscntrl(char c)
{
	return int_to_bool(iscntrl(c));
}

bool voluta_chr_isdigit(char c)
{
	return int_to_bool(isdigit(c));
}

bool voluta_chr_isgraph(char c)
{
	return int_to_bool(isgraph(c));
}

bool voluta_chr_islower(char c)
{
	return int_to_bool(islower(c));
}

bool voluta_chr_isprint(char c)
{
	return int_to_bool(isprint(c));
}

bool voluta_chr_ispunct(char c)
{
	return int_to_bool(ispunct(c));
}

bool voluta_chr_isspace(char c)
{
	return int_to_bool(isspace(c));
}

bool voluta_chr_isupper(char c)
{
	return int_to_bool(isupper(c));
}

bool voluta_chr_isxdigit(char c)
{
	return int_to_bool(isxdigit(c));
}

int voluta_chr_toupper(char c)
{
	return toupper(c);
}

int voluta_chr_tolower(char c)
{
	return tolower(c);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define substr_out_of_range(ss, pos, sz)                \
	voluta_panic("out-of-range pos=%ld sz=%ld ss=%s",      \
	             (long)(pos), (long)(sz), ((const char*)(ss)->str))


static size_t substr_max_size(void)
{
	return ULONG_MAX >> 2;
}
size_t voluta_substr_max_size(void)
{
	return substr_max_size();
}

static size_t substr_npos(void)
{
	return substr_max_size();
}
size_t voluta_substr_npos(void)
{
	return substr_npos();
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Immutable String Operations:
 */

/* Returns the offset of p within substr */
static size_t substr_offset(const struct voluta_substr *ss, const char *p)
{
	size_t off;

	off = substr_npos();
	if (p != NULL) {
		if ((p >= ss->str) && (p < (ss->str + ss->len))) {
			off = (size_t)(p - ss->str);
		}
	}
	return off;
}

void voluta_substr_init(struct voluta_substr *ss, const char *s)
{
	voluta_substr_init_rd(ss, s, str_length(s));
}

void voluta_substr_init_rd(struct voluta_substr *ss, const char *s, size_t n)
{
	voluta_substr_init_rw(ss, unconst_str(s), n, 0UL);
}

void voluta_substr_init_rwa(struct voluta_substr *ss, char *s)
{
	const size_t len = str_length(s);

	voluta_substr_init_rw(ss, s, len, len);
}

void voluta_substr_init_rw(struct voluta_substr *ss,
                           char *s, size_t nrd, size_t nwr)
{
	ss->str  = s;
	ss->len  = nrd;
	ss->nwr  = nwr;
}

void voluta_substr_inits(struct voluta_substr *ss)
{
	static const char *es = "";
	voluta_substr_init(ss, es);
}

void voluta_substr_clone(const struct voluta_substr *ss,
                         struct voluta_substr *other)
{
	other->str = ss->str;
	other->len = ss->len;
	other->nwr = ss->nwr;
}

void voluta_substr_destroy(struct voluta_substr *ss)
{
	ss->str  = NULL;
	ss->len  = 0;
	ss->nwr  = 0;
}


static const char *substr_data(const struct voluta_substr *ss)
{
	return ss->str;
}

static char *substr_mutable_data(const struct voluta_substr *ss)
{
	return unconst_str(ss->str);
}

static size_t substr_size(const struct voluta_substr *ss)
{
	return ss->len;
}

size_t voluta_substr_size(const struct voluta_substr *ss)
{
	return substr_size(ss);
}

static size_t substr_wrsize(const struct voluta_substr *ss)
{
	return ss->nwr;
}

size_t voluta_substr_wrsize(const struct voluta_substr *ss)
{
	return substr_wrsize(ss);
}

static bool substr_isempty(const struct voluta_substr *ss)
{
	return (substr_size(ss) == 0);
}

bool voluta_substr_isempty(const struct voluta_substr *ss)
{
	return substr_isempty(ss);
}

static const char *substr_begin(const struct voluta_substr *ss)
{
	return substr_data(ss);
}

const char *voluta_substr_begin(const struct voluta_substr *ss)
{
	return substr_begin(ss);
}

static const char *substr_end(const struct voluta_substr *ss)
{
	return (substr_data(ss) + substr_size(ss));
}

const char *voluta_substr_end(const struct voluta_substr *ss)
{
	return substr_end(ss);
}

size_t voluta_substr_offset(const struct voluta_substr *ss, const char *p)
{
	return substr_offset(ss, p);
}

const char *voluta_substr_at(const struct voluta_substr *ss, size_t n)
{
	const size_t sz = substr_size(ss);

	if (!(n < sz)) {
		substr_out_of_range(ss, n, sz);
	}
	return substr_data(ss) + n;
}

int voluta_substr_isvalid_index(const struct voluta_substr *ss, size_t i)
{
	return (i < substr_size(ss));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_substr_copyto(const struct voluta_substr *ss,
                            char *buf, size_t n)
{
	const size_t len = voluta_min(n, ss->len);

	voluta_str_copy(buf, ss->str, len);
	if (len < n) { /* If possible, terminate with EOS. */
		voluta_str_terminate(buf, len);
	}
	return len;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_substr_compare(const struct voluta_substr *ss, const char *s)
{
	return voluta_substr_ncompare(ss, s, str_length(s));
}

int voluta_substr_ncompare(const struct voluta_substr *ss,
                           const char *s, size_t n)
{
	int res = 0;

	if ((ss->str != s) || (ss->len != n)) {
		res = voluta_str_ncompare(ss->str, ss->len, s, n);
	}
	return res;
}

bool voluta_substr_isequal(const struct voluta_substr *ss, const char *s)
{
	return voluta_substr_nisequal(ss, s, voluta_str_length(s));
}

bool voluta_substr_nisequal(const struct voluta_substr *ss,
                            const char *s, size_t n)
{
	const char *str;

	if (substr_size(ss) != n) {
		return false;
	}
	str = substr_data(ss);
	if (str == s) {
		return true;
	}
	return (voluta_str_compare(str, s, n) == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_substr_count(const struct voluta_substr *ss, const char *s)
{
	return voluta_substr_ncount(ss, s, str_length(s));
}

size_t voluta_substr_ncount(const struct voluta_substr *ss,
                            const char *s, size_t n)
{
	size_t i;
	size_t pos = 0;
	size_t cnt = 0;
	const size_t sz = substr_size(ss);

	i = voluta_substr_nfind(ss, pos, s, n);
	while (i < sz) {
		++cnt;
		pos = i + n;
		i = voluta_substr_nfind(ss, pos, s, n);
	}
	return cnt;
}

size_t voluta_substr_count_chr(const struct voluta_substr *ss, char c)
{
	size_t i;
	size_t pos = 0;
	size_t cnt = 0;
	const size_t sz = substr_size(ss);

	i = voluta_substr_find_chr(ss, pos, c);
	while (i < sz) {
		++cnt;
		pos = i + 1;
		i = voluta_substr_find_chr(ss, pos, c);
	}
	return cnt;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_substr_find(const struct voluta_substr *ss, const char *s)
{
	return voluta_substr_nfind(ss, 0UL, s, voluta_str_length(s));
}

size_t voluta_substr_nfind(const struct voluta_substr *ss,
                           size_t pos, const char *s, size_t n)
{
	size_t sz;
	const char *dat;
	const char *p = NULL;

	dat = substr_data(ss);
	sz  = substr_size(ss);

	if (pos < sz) {
		if (n > 1) {
			p = voluta_str_find(dat + pos, sz - pos, s, n);
		} else if (n == 1) {
			p = voluta_str_find_chr(dat + pos, sz - pos, s[0]);
		} else {
			/*
			 * Stay compatible with STL: empty string always
			 * matches (if inside string).
			 */
			p = dat + pos;
		}
	}
	return substr_offset(ss, p);
}

size_t voluta_substr_find_chr(const struct voluta_substr *ss, size_t pos,
                              char c)
{
	size_t sz;
	const char *dat;
	const char *p = NULL;

	dat = substr_data(ss);
	sz  = substr_size(ss);

	if (pos < sz) {
		p = voluta_str_find_chr(dat + pos, sz - pos, c);
	}
	return substr_offset(ss, p);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_substr_rfind(const struct voluta_substr *ss, const char *s)
{
	const size_t pos = substr_size(ss);

	return voluta_substr_nrfind(ss, pos, s, voluta_str_length(s));
}

size_t voluta_substr_nrfind(const struct voluta_substr *ss,
                            size_t pos, const char *s, size_t n)
{
	size_t k;
	const char *p;
	const char *q;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

	p = NULL;
	q = s;
	k = (pos < sz) ? pos + 1 : sz;
	if (n == 0) {
		/* STL compatible: empty string always matches */
		p = dat + k;
	} else if (n == 1) {
		p = voluta_str_rfind_chr(dat, k, *q);
	} else {
		p = voluta_str_rfind(dat, k, q, n);
	}
	return substr_offset(ss, p);
}

size_t voluta_substr_rfind_chr(const struct voluta_substr *ss,
                               size_t pos, char c)
{
	size_t k;
	const char *p;
	const size_t sz = substr_size(ss);
	const char *dat = substr_data(ss);

	k = (pos < sz) ? pos + 1 : sz;
	p = voluta_str_rfind_chr(dat, k, c);
	return substr_offset(ss, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_substr_find_first_of(const struct voluta_substr *ss,
                                   const char *s)
{
	return voluta_substr_nfind_first_of(ss, 0UL, s, voluta_str_length(s));
}

size_t voluta_substr_nfind_first_of(const struct voluta_substr *ss,
                                    size_t pos, const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

	if ((n != 0) && (pos < sz)) {
		if (n == 1) {
			p = voluta_str_find_chr(dat + pos, sz - pos, *q);
		} else {
			p = voluta_str_find_first_of(dat + pos,
			                             sz - pos, q, n);
		}
	}
	return substr_offset(ss, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_substr_find_last_of(const struct voluta_substr *ss,
                                  const char *s)
{
	return voluta_substr_nfind_last_of(ss, substr_size(ss),
	                                   s, str_length(s));
}

size_t voluta_substr_nfind_last_of(const struct voluta_substr *ss, size_t pos,
                                   const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

	if (n != 0) {
		const size_t k = (pos < sz) ? pos + 1 : sz;

		if (n == 1) {
			p = voluta_str_rfind_chr(dat, k, *q);
		} else {
			p = voluta_str_find_last_of(dat, k, q, n);
		}
	}
	return substr_offset(ss, p);
}

size_t voluta_substr_find_first_not_of(const struct voluta_substr *ss,
                                       const char *s)
{
	return voluta_substr_nfind_first_not_of(ss, 0UL, s, str_length(s));
}

size_t voluta_substr_nfind_first_not_of(const struct voluta_substr *ss,
                                        size_t pos, const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

	if (pos < sz) {
		if (n == 0) {
			p = dat + pos;
		} else if (n == 1) {
			p = voluta_str_find_first_not_eq(dat + pos,
			                                 sz - pos, *q);
		} else {
			p = voluta_str_find_first_not_of(dat + pos,
			                                 sz - pos, q, n);
		}
	}

	return substr_offset(ss, p);
}

size_t voluta_substr_find_first_not(const struct voluta_substr *ss,
                                    size_t pos, char c)
{
	const char *p = NULL;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

	if (pos < sz) {
		p = voluta_str_find_first_not_eq(dat + pos, sz - pos, c);
	}
	return substr_offset(ss, p);
}

size_t voluta_substr_find_last_not_of(const struct voluta_substr *ss,
                                      const char *s)
{
	return voluta_substr_nfind_last_not_of(ss, substr_size(ss),
	                                       s, str_length(s));
}

size_t voluta_substr_nfind_last_not_of(const struct voluta_substr *ss,
                                       size_t pos, const char *s, size_t n)
{
	const char *p = NULL;
	const char *q = s;
	const char *dat = substr_data(ss);
	const size_t sz = substr_size(ss);

	if (sz != 0) {
		const size_t k = (pos < sz) ? pos + 1 : sz;

		if (n == 0) {
			p = dat + k - 1; /* compatible with STL */
		} else if (n == 1) {
			p = voluta_str_find_last_not_eq(dat, k, *q);
		} else {
			p = voluta_str_find_last_not_of(dat, k, q, n);
		}
	}
	return substr_offset(ss, p);
}

size_t voluta_substr_find_last_not(const struct voluta_substr *ss,
                                   size_t pos, char c)
{
	const size_t sz = substr_size(ss);
	const size_t k = (pos < sz) ? pos + 1 : sz;
	const char *dat = substr_data(ss);
	const char *p  = voluta_str_find_last_not_eq(dat, k, c);

	return substr_offset(ss, p);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_sub(const struct voluta_substr *ss,
                       size_t i, size_t n, struct voluta_substr *out_ss)
{
	const size_t sz  = substr_size(ss);
	const size_t j   = voluta_min(i, sz);
	const size_t n1  = voluta_min(n, sz - j);
	const size_t wr  = substr_wrsize(ss);
	const size_t k   = voluta_min(i, wr);
	const size_t n2  = voluta_min(n, wr - k);

	voluta_substr_init_rw(out_ss, substr_mutable_data(ss) + j, n1, n2);
}

void voluta_substr_rsub(const struct voluta_substr *ss,
                        size_t n, struct voluta_substr *out_ss)
{
	const size_t sz  = substr_size(ss);
	const size_t n1  = voluta_min(n, sz);
	const size_t j   = sz - n1;
	const size_t wr  = substr_wrsize(ss);
	const size_t k   = voluta_min(j, wr);
	const size_t n2  = wr - k;

	voluta_substr_init_rw(out_ss, substr_mutable_data(ss) + j, n1, n2);
}

void voluta_substr_intersection(const struct voluta_substr *s1,
                                const struct voluta_substr *s2,
                                struct voluta_substr *out_ss)
{
	size_t i = 0;
	size_t n = 0;
	const char *s1_begin;
	const char *s1_end;
	const char *s2_begin;
	const char *s2_end;

	s1_begin = substr_begin(s1);
	s2_begin = substr_begin(s2);
	if (s1_begin <= s2_begin) {
		i = n = 0;

		s1_end = substr_end(s1);
		s2_end = substr_end(s2);

		/* Case 1:  [.s1...)  [..s2.....) -- Return empty substring */
		if (s1_end <= s2_begin) {
			i = substr_size(s2);
		}
		/* Case 2: [.s1........)
		                [.s2..) */
		else if (s2_end <= s1_end) {
			n = substr_size(s2);
		}
		/* Case 3: [.s1.....)
		               [.s2......) */
		else {
			n = (size_t)(s1_end - s2_begin);
		}
		voluta_substr_sub(s2, i, n, out_ss);
	} else {
		/* One step recursion -- its ok */
		voluta_substr_intersection(s2, s1, out_ss);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Helper function to create split-of-substrings */
static void substr_make_split_pair(const struct voluta_substr *ss,
                                   size_t i1, size_t n1,
                                   size_t i2, size_t n2,
                                   struct voluta_substr_pair *out_ss_pair)
{
	voluta_substr_sub(ss, i1, n1, &out_ss_pair->first);
	voluta_substr_sub(ss, i2, n2, &out_ss_pair->second);
}

void voluta_substr_split(const struct voluta_substr *ss, const char *seps,
                         struct voluta_substr_pair *out_ss_pair)
{

	voluta_substr_nsplit(ss, seps, str_length(seps), out_ss_pair);
}

void voluta_substr_nsplit(const struct voluta_substr *ss,
                          const char *seps, size_t n,
                          struct voluta_substr_pair *out_ss_pair)
{
	const size_t sz = substr_size(ss);
	const size_t i = voluta_substr_nfind_first_of(ss, 0UL, seps, n);
	const size_t j = (i >= sz) ? sz :
	                 voluta_substr_nfind_first_not_of(ss, i, seps, n);

	substr_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

void voluta_substr_split_chr(const struct voluta_substr *ss, char sep,
                             struct voluta_substr_pair *out_ss_pair)
{
	const size_t sz = substr_size(ss);
	const size_t i = voluta_substr_find_chr(ss, 0UL, sep);
	const size_t j = (i < sz) ? i + 1 : sz;

	substr_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_rsplit(const struct voluta_substr *ss, const char *seps,
                          struct voluta_substr_pair *out_ss_pair)
{
	voluta_substr_nrsplit(ss, seps, str_length(seps), out_ss_pair);
}

void voluta_substr_nrsplit(const struct voluta_substr *ss,
                           const char *seps, size_t n,
                           struct voluta_substr_pair *out_ss_pair)
{
	size_t i;
	size_t j;
	const size_t sz = substr_size(ss);

	i = voluta_substr_nfind_last_of(ss, sz, seps, n);
	if (i < sz) {
		j = voluta_substr_nfind_last_not_of(ss, i, seps, n);

		if (j < sz) {
			++i;
			++j;
		} else {
			i = j = sz;
		}
	} else {
		j = sz;
	}
	substr_make_split_pair(ss, 0UL, j, i, sz, out_ss_pair);
}

void voluta_substr_rsplit_chr(const struct voluta_substr *ss, char sep,
                              struct voluta_substr_pair *out_ss_pair)
{
	const size_t sz = substr_size(ss);
	const size_t i = voluta_substr_rfind_chr(ss, sz, sep);
	const size_t j = (i < sz) ? i + 1 : sz;

	substr_make_split_pair(ss, 0UL, i, j, sz, out_ss_pair);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_trim(const struct voluta_substr *ss, size_t n,
                        struct voluta_substr *out_ss)
{
	voluta_substr_sub(ss, n, substr_size(ss), out_ss);
}

void voluta_substr_trim_any_of(const struct voluta_substr *ss,
                               const char *set, struct voluta_substr *out_ss)
{
	voluta_substr_ntrim_any_of(ss, set, str_length(set), out_ss);
}

void voluta_substr_ntrim_any_of(const struct voluta_substr *ss,
                                const char *set, size_t n,
                                struct voluta_substr *out_ss)
{
	const size_t sz = substr_size(ss);
	const size_t i = voluta_substr_nfind_first_not_of(ss, 0UL, set, n);

	voluta_substr_sub(ss, i, sz, out_ss);
}

void voluta_substr_trim_chr(const struct voluta_substr *ss, char c,
                            struct voluta_substr *out_ss)
{
	const size_t sz = substr_size(ss);
	const size_t i = voluta_substr_find_first_not(ss, 0UL, c);

	voluta_substr_sub(ss, i, sz, out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_chop(const struct voluta_substr *ss,
                        size_t n, struct voluta_substr *out_ss)
{
	char *dat = substr_mutable_data(ss);
	const size_t sz = substr_size(ss);
	const size_t wr = substr_wrsize(ss);
	const size_t k = voluta_min(sz, n);

	voluta_substr_init_rw(out_ss, dat, sz - k, wr);
}

void voluta_substr_chop_any_of(const struct voluta_substr *ss,
                               const char *set, struct voluta_substr *out_ss)
{
	voluta_substr_nchop_any_of(ss, set, str_length(set), out_ss);
}

void voluta_substr_nchop_any_of(const struct voluta_substr *ss,
                                const char *set, size_t n,
                                struct voluta_substr *out_ss)
{
	const size_t sz = substr_size(ss);
	const size_t j = voluta_substr_nfind_last_not_of(ss, sz, set, n);

	voluta_substr_sub(ss, 0UL, ((j < sz) ? j + 1 : 0), out_ss);
}

void voluta_substr_chop_chr(const struct voluta_substr *ss, char c,
                            struct voluta_substr *out_ss)
{
	const size_t sz = substr_size(ss);
	const size_t j = voluta_substr_find_last_not(ss, sz, c);

	voluta_substr_sub(ss, 0UL, ((j < sz) ? j + 1 : 0), out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_strip_any_of(const struct voluta_substr *ss,
                                const char *set, struct voluta_substr *result)
{
	voluta_substr_nstrip_any_of(ss, set, str_length(set), result);
}

void voluta_substr_nstrip_any_of(const struct voluta_substr *ss,
                                 const char *set, size_t n,
                                 struct voluta_substr *result)
{
	struct voluta_substr sub;

	voluta_substr_ntrim_any_of(ss, set, n, &sub);
	voluta_substr_nchop_any_of(&sub, set, n, result);
}

void voluta_substr_strip_chr(const struct voluta_substr *ss, char c,
                             struct voluta_substr *result)
{
	struct voluta_substr sub;

	voluta_substr_trim_chr(ss, c, &sub);
	voluta_substr_chop_chr(&sub, c, result);
}

void voluta_substr_strip_ws(const struct voluta_substr *ss,
                            struct voluta_substr *out_ss)
{
	const char *spaces = " \n\t\r\v\f";

	voluta_substr_strip_any_of(ss, spaces, out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_find_token(const struct voluta_substr *ss,
                              const char *seps, struct voluta_substr *result)
{
	voluta_substr_nfind_token(ss, seps, str_length(seps), result);
}

void voluta_substr_nfind_token(const struct voluta_substr *ss,
                               const char *seps, size_t n,
                               struct voluta_substr *result)
{
	const size_t sz = substr_size(ss);
	const size_t ki = voluta_substr_nfind_first_not_of(ss, 0UL, seps, n);
	const size_t i = voluta_min(ki, sz);
	const size_t kj = voluta_substr_nfind_first_of(ss, i, seps, n);
	const size_t j = voluta_min(kj, sz);

	voluta_substr_sub(ss, i, j - i, result);
}

void voluta_substr_find_token_chr(const struct voluta_substr *ss, char sep,
                                  struct voluta_substr *result)
{
	const size_t sz = substr_size(ss);
	const size_t ki = voluta_substr_find_first_not(ss, 0UL, sep);
	const size_t i = voluta_min(ki, sz);
	const size_t kj = voluta_substr_find_chr(ss, i, sep);
	const size_t j  = voluta_min(kj, sz);

	voluta_substr_sub(ss, i, j - i, result);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_find_next_token(const struct voluta_substr *ss,
                                   const struct voluta_substr *tok,
                                   const char *seps,
                                   struct voluta_substr *out_ss)
{
	voluta_substr_nfind_next_token(ss, tok, seps,
	                               str_length(seps), out_ss);
}

void voluta_substr_nfind_next_token(const struct voluta_substr *ss,
                                    const struct voluta_substr *tok,
                                    const char *seps, size_t n,
                                    struct voluta_substr *result)
{
	struct voluta_substr sub;
	const size_t sz  = substr_size(ss);
	const char *p = substr_end(tok);
	const size_t i = substr_offset(ss, p);

	voluta_substr_sub(ss, i, sz, &sub);
	voluta_substr_nfind_token(&sub, seps, n, result);
}

void voluta_substr_find_next_token_chr(const struct voluta_substr *ss,
                                       const struct voluta_substr *tok,
                                       char sep, struct voluta_substr *out_ss)
{
	struct voluta_substr sub;
	const size_t sz = substr_size(ss);
	const size_t i = substr_offset(ss, substr_end(tok));

	voluta_substr_sub(ss, i, sz, &sub);
	voluta_substr_find_token_chr(&sub, sep, out_ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_substr_tokenize(const struct voluta_substr *ss,
                           const char *seps,
                           struct voluta_substr tok_list[],
                           size_t list_size, size_t *out_ntok)
{
	return voluta_substr_ntokenize(ss, seps, str_length(seps),
	                               tok_list, list_size, out_ntok);
}

int voluta_substr_ntokenize(const struct voluta_substr *ss,
                            const char *seps, size_t n,
                            struct voluta_substr tok_list[],
                            size_t list_size, size_t *out_ntok)
{
	size_t ntok = 0;
	struct voluta_substr tok;
	struct voluta_substr *tgt = NULL;

	voluta_substr_nfind_token(ss, seps, n, &tok);
	while (!voluta_substr_isempty(&tok)) {
		if (ntok == list_size) {
			return -1; /* Insufficient room */
		}
		tgt = &tok_list[ntok++];
		voluta_substr_clone(&tok, tgt);

		voluta_substr_nfind_next_token(ss, &tok, seps, n, &tok);
	}
	*out_ntok = ntok;
	return 0;
}

int voluta_substr_tokenize_chr(const struct voluta_substr *ss, char sep,
                               struct voluta_substr tok_list[],
                               size_t list_size, size_t *out_ntok)
{
	size_t ntok = 0;
	struct voluta_substr tok;
	struct voluta_substr *tgt = NULL;

	voluta_substr_find_token_chr(ss, sep, &tok);
	while (!voluta_substr_isempty(&tok)) {
		if (ntok == list_size) {
			return -1; /* Insufficient room */
		}
		tgt = &tok_list[ntok++];
		voluta_substr_clone(&tok, tgt);

		voluta_substr_find_next_token_chr(ss, &tok, sep, &tok);
	}
	*out_ntok = ntok;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_substr_common_prefix(const struct voluta_substr *ss,
                                   const char *s)
{
	return voluta_substr_ncommon_prefix(ss, s, str_length(s));
}

size_t voluta_substr_ncommon_prefix(const struct voluta_substr *ss,
                                    const char *s, size_t n)
{
	const size_t sz = substr_size(ss);
	const size_t nn = voluta_min(n, sz);

	return voluta_str_common_prefix(substr_data(ss), s, nn);
}

bool voluta_substr_starts_with(const struct voluta_substr *ss, char c)
{
	return !substr_isempty(ss) && chr_eq(c, *substr_data(ss));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_substr_common_suffix(const struct voluta_substr *ss,
                                   const char *s)
{
	return voluta_substr_ncommon_suffix(ss, s, str_length(s));
}

size_t voluta_substr_ncommon_suffix(const struct voluta_substr *ss,
                                    const char *s, size_t n)
{
	size_t k;
	const size_t sz = substr_size(ss);
	const char *dat = substr_data(ss);

	if (n > sz) {
		k = voluta_str_common_suffix(dat, s + (n - sz), sz);
	} else {
		k = voluta_str_common_suffix(dat + (sz - n), s, n);
	}
	return k;
}

int voluta_substr_ends_with(const struct voluta_substr *ss, char c)
{
	const size_t sz = substr_size(ss);

	return (sz > 0) && chr_eq(c, substr_data(ss)[sz - 1]);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Mutable String Operations:
 */
char *voluta_substr_data(const struct voluta_substr *ss)
{
	return substr_mutable_data(ss);
}

/* Set EOS characters at the end of characters array (if possible) */
static void substr_terminate(struct voluta_substr *ss)
{
	char *dat;
	const size_t sz = substr_size(ss);
	const size_t wr = substr_wrsize(ss);

	if (sz < wr) {
		dat = substr_mutable_data(ss);
		voluta_str_terminate(dat, sz);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Inserts a copy of s before position pos. */
static void substr_insert(struct voluta_substr *ss,
                          size_t pos, const char *s, size_t n)
{
	char *dat = voluta_substr_data(ss);

	/* Start insertion before position j. */
	const size_t sz = substr_size(ss);
	const size_t j = voluta_min(pos, sz);

	/* Number of writable elements after j. */
	const size_t wr = substr_wrsize(ss);
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* Number of elements of ss after j (to be moved fwd). */
	const size_t k = sz - j;

	/*
	 * Insert n elements of p: try as many as possible, truncate tail in
	 * case of insufficient buffer capacity.
	 */
	ss->len = j + voluta_str_insert(dat + j, rem, k, s, n);
	substr_terminate(ss);
}

/* Inserts n copies of c before position pos. */
static void substr_insert_fill(struct voluta_substr *ss,
                               size_t pos, size_t n, char c)
{
	char *dat = voluta_substr_data(ss);

	/* Start insertion before position j. */
	const size_t sz  = substr_size(ss);
	const size_t j = voluta_min(pos, sz);

	/* Number of writable elements after j. */
	const size_t wr = substr_wrsize(ss);
	const size_t rem = (j < wr) ? (wr - j) : 0;

	/* Number of elements of ss after j (to be moved fwd). */
	const size_t k = sz - j;

	/*
	 * Insert n copies of c: try as many as possible; truncate tail in
	 * case of insufficient buffer capacity.
	 */
	ss->len = j + voluta_str_insert_chr(dat + j, rem, k, n, c);
	substr_terminate(ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Replaces a substring of *this with a copy of s. */
static void substr_replace(struct voluta_substr *ss, size_t pos, size_t n1,
                           const char *s, size_t n)
{
	/* Number of elements to replace (assuming pos <= size). */
	const size_t sz = substr_size(ss);
	const size_t k = voluta_min(sz - pos, n1);

	/*
	 * Replace k elements after pos with s; truncate tail in case of
	 * insufficient buffer capacity.
	 */
	char *dat = substr_mutable_data(ss);
	const size_t wr = substr_wrsize(ss);

	ss->len = pos + voluta_str_replace(dat + pos, wr - pos,
	                                   sz - pos, k, s, n);
	substr_terminate(ss);
}

/* Replaces a substring of *this with n2 copies of c. */
static void substr_replace_fill(struct voluta_substr *ss,
                                size_t pos, size_t n1, size_t n2, char c)
{
	char *dat = substr_mutable_data(ss);

	/* Number of elements to replace (assuming pos <= size). */
	const size_t sz = substr_size(ss);
	const size_t k = voluta_min(sz - pos, n1);

	/*
	 * Replace k elements after pos with n2 copies of c; truncate tail in
	 * case of insufficient buffer capacity.
	 */
	const size_t wr = substr_wrsize(ss);

	ss->len = pos +  voluta_str_replace_chr(dat + pos, wr - pos,
	                                        sz - pos, k, n2, c);
	substr_terminate(ss);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_assign(struct voluta_substr *ss, const char *s)
{
	voluta_substr_nassign(ss, s, str_length(s));
}

void voluta_substr_nassign(struct voluta_substr *ss, const char *s, size_t len)
{
	voluta_substr_nreplace(ss, 0, substr_size(ss), s, len);
}

void voluta_substr_assign_chr(struct voluta_substr *ss, size_t n, char c)
{
	voluta_substr_replace_chr(ss, 0, substr_size(ss), n, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_push_back(struct voluta_substr *ss, char c)
{
	voluta_substr_append_chr(ss, 1, c);
}

void voluta_substr_append(struct voluta_substr *ss, const char *s)
{
	voluta_substr_nappend(ss, s, str_length(s));
}

void voluta_substr_nappend(struct voluta_substr *ss, const char *s, size_t len)
{
	voluta_substr_ninsert(ss, substr_size(ss), s, len);
}

void voluta_substr_append_chr(struct voluta_substr *ss, size_t n, char c)
{
	voluta_substr_insert_chr(ss, substr_size(ss), n, c);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_insert(struct voluta_substr *ss, size_t pos, const char *s)
{
	voluta_substr_ninsert(ss, pos, s, str_length(s));
}

void voluta_substr_ninsert(struct voluta_substr *ss, size_t pos,
                           const char *s, size_t len)
{
	const size_t sz = substr_size(ss);

	if (pos <= sz) {
		substr_insert(ss, pos, s, len);
	} else {
		substr_out_of_range(ss, pos, sz);
	}
}

void voluta_substr_insert_chr(struct voluta_substr *ss, size_t pos, size_t n,
                              char c)
{
	const size_t sz = substr_size(ss);

	if (pos <= sz) {
		substr_insert_fill(ss, pos, n, c);
	} else {
		substr_out_of_range(ss, pos, sz);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_substr_replace(struct voluta_substr *ss,
                           size_t pos, size_t n, const char *s)
{
	voluta_substr_nreplace(ss, pos, n, s, str_length(s));
}

void voluta_substr_nreplace(struct voluta_substr *ss,
                            size_t pos, size_t n,  const char *s, size_t len)
{
	const size_t sz = substr_size(ss);

	if (pos < sz) {
		substr_replace(ss, pos, n, s, len);
	} else if (pos == sz) {
		substr_insert(ss, pos, s, len);
	} else {
		substr_out_of_range(ss, pos, sz);
	}
}

void voluta_substr_replace_chr(struct voluta_substr *ss,
                               size_t pos, size_t n1, size_t n2, char c)
{
	const size_t sz = substr_size(ss);

	if (pos < sz) {
		substr_replace_fill(ss, pos, n1, n2, c);
	} else if (pos == sz) {
		substr_insert_fill(ss, pos, n2, c);
	} else {
		substr_out_of_range(ss, pos, sz);
	}
}

void voluta_substr_erase(struct voluta_substr *ss, size_t pos, size_t n)
{
	voluta_substr_replace_chr(ss, pos, n, 0, '\0');
}

void voluta_substr_reverse(struct voluta_substr *ss)
{
	const size_t sz  = substr_size(ss);
	const size_t wr  = substr_wrsize(ss);
	const size_t len = voluta_min(sz, wr);

	voluta_str_reverse(voluta_substr_data(ss), len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Generic Operations:
 */
static size_t substr_find_if(const struct voluta_substr *ss,
                             voluta_chr_testif_fn fn, bool c)
{
	const char *p = substr_begin(ss);
	const char *q = substr_end(ss);

	while (p < q) {
		if (fn(*p) == c) {
			return substr_offset(ss, p);
		}
		++p;
	}
	return substr_npos();
}

size_t voluta_substr_find_if(const struct voluta_substr *ss,
                             voluta_chr_testif_fn fn)
{
	return substr_find_if(ss, fn, 1);
}

size_t voluta_substr_find_if_not(const struct voluta_substr *ss,
                                 voluta_chr_testif_fn fn)
{
	return substr_find_if(ss, fn, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t substr_rfind_if(const struct voluta_substr *ss,
                              voluta_chr_testif_fn fn, bool c)
{
	const char *p = substr_end(ss);
	const char *q = substr_begin(ss);

	while (p-- > q) {
		if (fn(*p) == c) {
			return substr_offset(ss, p);
		}
	}
	return substr_npos();
}

size_t voluta_substr_rfind_if(const struct voluta_substr *ss,
                              voluta_chr_testif_fn fn)
{
	return substr_rfind_if(ss, fn, true);
}

size_t voluta_substr_rfind_if_not(const struct voluta_substr *ss,
                                  voluta_chr_testif_fn fn)
{
	return substr_rfind_if(ss, fn, false);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t voluta_substr_count_if(const struct voluta_substr *ss,
                              voluta_chr_testif_fn fn)
{
	size_t cnt = 0;
	const char *p = substr_begin(ss);
	const char *q = substr_end(ss);

	while (p < q) {
		if (fn(*p++)) {
			++cnt;
		}
	}
	return cnt;
}

bool voluta_substr_test_if(const struct voluta_substr *ss,
                           voluta_chr_testif_fn fn)
{
	const char *p = substr_begin(ss);
	const char *q = substr_end(ss);

	while (p < q) {
		if (!fn(*p++)) {
			return false;
		}
	}
	return true;
}

void voluta_substr_trim_if(const struct voluta_substr *ss,
                           voluta_chr_testif_fn fn,
                           struct voluta_substr *out_ss)
{
	size_t pos;
	const size_t sz = substr_size(ss);

	pos  = voluta_substr_find_if_not(ss, fn);
	voluta_substr_sub(ss, pos, sz, out_ss);
}

void voluta_substr_chop_if(const struct voluta_substr *ss,
                           voluta_chr_testif_fn fn,
                           struct voluta_substr *out_ss)
{
	size_t pos;
	const size_t sz = substr_size(ss);

	pos = voluta_substr_rfind_if_not(ss, fn);
	voluta_substr_sub(ss, 0UL, ((pos < sz) ? pos + 1 : 0), out_ss);
}

void voluta_substr_strip_if(const struct voluta_substr *ss,
                            voluta_chr_testif_fn fn,
                            struct voluta_substr *out_ss)
{
	struct voluta_substr sub;

	voluta_substr_trim_if(ss, fn, &sub);
	voluta_substr_chop_if(&sub, fn, out_ss);
}

void voluta_substr_foreach(struct voluta_substr *ss, voluta_chr_modify_fn fn)
{
	char *p;
	const size_t sz = substr_wrsize(ss);

	p = substr_mutable_data(ss);
	for (size_t i = 0; i < sz; ++i) {
		fn(p++);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Ctype Operations:
 */
bool voluta_substr_isalnum(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_isalnum);
}

bool voluta_substr_isalpha(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_isalpha);
}

bool voluta_substr_isascii(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_isascii);
}

bool voluta_substr_isblank(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_isblank);
}

bool voluta_substr_iscntrl(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_iscntrl);
}

bool voluta_substr_isdigit(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_isdigit);
}

bool voluta_substr_isgraph(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_isgraph);
}

bool voluta_substr_islower(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_islower);
}

bool voluta_substr_isprint(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_isprint);
}

bool voluta_substr_ispunct(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_ispunct);
}

bool voluta_substr_isspace(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_isspace);
}

bool voluta_substr_isupper(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_isupper);
}

bool voluta_substr_isxdigit(const struct voluta_substr *ss)
{
	return voluta_substr_test_if(ss, voluta_chr_isxdigit);
}

static void chr_toupper(char *c)
{
	*c = (char)voluta_chr_toupper(*c);
}

static void chr_tolower(char *c)
{
	*c = (char)voluta_chr_tolower(*c);
}

void voluta_substr_toupper(struct voluta_substr *ss)
{
	voluta_substr_foreach(ss, chr_toupper);
}

void voluta_substr_tolower(struct voluta_substr *ss)
{
	voluta_substr_foreach(ss, chr_tolower);
}

void voluta_substr_capitalize(struct voluta_substr *ss)
{
	if (ss->len) {
		chr_toupper(ss->str);
	}
}
