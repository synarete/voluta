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
#define _GNU_SOURCE 1
#include "unitest.h"


static void ut_substr_compare(struct voluta_substr *ss)
{
	int eq;
	int cmp;
	bool emp;
	size_t sz;

	voluta_substr_init(ss, "123456789");
	sz = voluta_substr_size(ss);
	ut_expect_eq(sz, 9);
	emp = voluta_substr_isempty(ss);
	ut_expect(!emp);
	cmp = voluta_substr_compare(ss, "123");
	ut_expect_gt(cmp, 0);
	cmp = voluta_substr_compare(ss, "9");
	ut_expect_lt(cmp, 0);
	cmp = voluta_substr_compare(ss, "123456789");
	ut_expect_eq(cmp, 0);
	eq = voluta_substr_isequal(ss, "123456789");
	ut_expect(eq);
}

static void test_find(struct voluta_substr *ss)
{
	size_t pos;

	voluta_substr_init(ss, "ABCDEF abcdef ABCDEF");
	pos = voluta_substr_find(ss, "A");
	ut_expect_eq(pos, 0);
	pos = voluta_substr_find(ss, "EF");
	ut_expect_eq(pos, 4);
	pos = voluta_substr_nfind(ss, 10, "EF", 2);
	ut_expect_eq(pos, 18);
	pos = voluta_substr_find_chr(ss, 1, 'A');
	ut_expect_eq(pos, 14);
	pos = voluta_substr_find(ss, "UUU");
	ut_expect_gt(pos, voluta_substr_size(ss));
}

static void test_rfind(struct voluta_substr *ss)
{
	size_t pos;

	voluta_substr_init(ss, "ABRACADABRA");
	pos = voluta_substr_rfind(ss, "A");
	ut_expect_eq(pos, 10);
	pos = voluta_substr_rfind(ss, "BR");
	ut_expect_eq(pos, 8);
	pos = voluta_substr_size(ss) / 2;
	pos = voluta_substr_nrfind(ss, pos, "BR", 2);
	ut_expect_eq(pos, 1);
	pos = voluta_substr_rfind_chr(ss, 1, 'B');
	ut_expect_eq(pos, 1);
}

static void test_find_first_of(struct voluta_substr *ss)
{
	size_t pos;

	voluta_substr_init(ss, "012x456x89z");
	pos = voluta_substr_find_first_of(ss, "xyz");
	ut_expect_eq(pos, 3);
	pos = voluta_substr_nfind_first_of(ss, 5, "x..z", 4);
	ut_expect_eq(pos, 7);
	pos = voluta_substr_find_first_of(ss, "XYZ");
	ut_expect_gt(pos, voluta_substr_size(ss));
}

static void test_find_last_of(struct voluta_substr *ss)
{
	size_t pos;

	voluta_substr_init(ss, "AAAAA-BBBBB");
	pos = voluta_substr_find_last_of(ss, "xyzAzyx");
	ut_expect_eq(pos, 4);
	pos = voluta_substr_nfind_last_of(ss, 9, "X-Y", 3);
	ut_expect_eq(pos, 5);
	pos = voluta_substr_find_last_of(ss, "BBBBBBBBBBBBBBBBBBBBB");
	ut_expect_eq(pos, voluta_substr_size(ss) - 1);
	pos = voluta_substr_find_last_of(ss, "...");
	ut_expect_gt(pos, voluta_substr_size(ss));
}

static void test_find_first_not_of(struct voluta_substr *ss)
{
	size_t pos;

	voluta_substr_init(ss, "aaa bbb ccc * ddd + eee");
	pos = voluta_substr_find_first_not_of(ss, "a b c d e");
	ut_expect_eq(pos, 12);
	pos = voluta_substr_nfind_first_not_of(ss, 14, "d e", 3);
	ut_expect_eq(pos, 18);
}

static void test_find_last_not_of(struct voluta_substr *ss)
{
	size_t pos;

	voluta_substr_init(ss, "-..3456.--");
	pos = voluta_substr_find_last_not_of(ss, ".-");
	ut_expect_eq(pos, 6);
	pos = voluta_substr_nfind_last_not_of(ss, 1, "*", 1);
	ut_expect_eq(pos, 1);
}

static void test_sub(struct voluta_substr *ss)
{
	bool eq;
	struct voluta_substr sub;
	const char *abc = "abcdefghijklmnopqrstuvwxyz";

	voluta_substr_init_rd(ss, abc, 10);    /* "abcdefghij" */
	voluta_substr_sub(ss, 2, 4, &sub);
	eq  = voluta_substr_isequal(&sub, "cdef");
	ut_expect(eq);
	voluta_substr_rsub(ss, 3, &sub);
	eq  = voluta_substr_isequal(&sub, "hij");
	ut_expect(eq);
	voluta_substr_chop(ss, 8, &sub);
	eq  = voluta_substr_isequal(&sub, "ab");
	ut_expect(eq);
	voluta_substr_clone(ss, &sub);
	eq  = voluta_substr_nisequal(&sub, ss->str, ss->len);
	ut_expect(eq);
}

static void test_count(struct voluta_substr *ss)
{
	size_t n;

	voluta_substr_init(ss, "xxx-xxx-xxx-xxx");
	n = voluta_substr_count(ss, "xxx");
	ut_expect_eq(n, 4);
	n = voluta_substr_count_chr(ss, '-');
	ut_expect_eq(n, 3);
}

static void test_split(struct voluta_substr *ss)
{
	bool eq;
	struct voluta_substr_pair split;

	voluta_substr_init(ss, "ABC-DEF+123");
	voluta_substr_split(ss, "-", &split);
	eq = voluta_substr_isequal(&split.first, "ABC");
	ut_expect(eq);
	eq = voluta_substr_isequal(&split.second, "DEF+123");
	ut_expect(eq);
	voluta_substr_split(ss, " + * ", &split);
	eq = voluta_substr_isequal(&split.first, "ABC-DEF");
	ut_expect(eq);
	eq = voluta_substr_isequal(&split.second, "123");
	ut_expect(eq);
	voluta_substr_split_chr(ss, 'B', &split);
	eq = voluta_substr_isequal(&split.first, "A");
	ut_expect(eq);
	eq = voluta_substr_isequal(&split.second, "C-DEF+123");
	ut_expect(eq);
}

static void test_rsplit(struct voluta_substr *ss)
{
	bool eq;
	struct voluta_substr_pair split;

	voluta_substr_init(ss, "UUU--YYY--ZZZ");
	voluta_substr_rsplit(ss, "-.", &split);
	eq = voluta_substr_isequal(&split.first, "UUU--YYY");
	ut_expect(eq);
	eq = voluta_substr_isequal(&split.second, "ZZZ");
	ut_expect(eq);
	voluta_substr_rsplit(ss, "+", &split);
	eq = voluta_substr_nisequal(&split.first, ss->str, ss->len);
	ut_expect(eq);
	eq = voluta_substr_isequal(&split.second, "ZZZ");
	ut_expect(!eq);
	voluta_substr_init(ss, "1.2.3.4.5");
	voluta_substr_rsplit_chr(ss, '.', &split);
	eq = voluta_substr_isequal(&split.first, "1.2.3.4");
	ut_expect(eq);
	eq = voluta_substr_isequal(&split.second, "5");
	ut_expect(eq);
}

static void test_trim(struct voluta_substr *ss)
{
	int eq;
	size_t sz;
	struct voluta_substr sub;

	voluta_substr_init(ss, ".:ABCD");
	voluta_substr_trim_any_of(ss, ":,.%^", &sub);
	eq  = voluta_substr_isequal(&sub, "ABCD");
	ut_expect(eq);
	sz = voluta_substr_size(ss);
	voluta_substr_ntrim_any_of(ss, voluta_substr_data(ss), sz, &sub);
	eq  = voluta_substr_size(&sub) == 0;
	ut_expect(eq);
	voluta_substr_trim_chr(ss, '.', &sub);
	eq  = voluta_substr_isequal(&sub, ":ABCD");
	ut_expect(eq);
	voluta_substr_trim(ss, 4, &sub);
	eq  = voluta_substr_isequal(&sub, "CD");
	ut_expect(eq);
	voluta_substr_trim_if(ss, voluta_chr_ispunct, &sub);
	eq  = voluta_substr_isequal(&sub, "ABCD");
	ut_expect(eq);
}

static void test_chop(struct voluta_substr *ss)
{
	int eq;
	size_t sz;
	struct voluta_substr sub;

	voluta_substr_init(ss, "123....");
	voluta_substr_chop_any_of(ss, "+*&^%$.", &sub);
	eq  = voluta_substr_isequal(&sub, "123");
	ut_expect(eq);
	sz = voluta_substr_size(ss);
	voluta_substr_nchop_any_of(ss, voluta_substr_data(ss), sz, &sub);
	eq  = voluta_substr_isequal(&sub, "");
	ut_expect(eq);
	voluta_substr_chop(ss, 6, &sub);
	eq  = voluta_substr_isequal(&sub, "1");
	ut_expect(eq);
	voluta_substr_chop_chr(ss, '.', &sub);
	eq  = voluta_substr_isequal(&sub, "123");
	ut_expect(eq);
	voluta_substr_chop_if(ss, voluta_chr_ispunct, &sub);
	eq  = voluta_substr_isequal(&sub, "123");
	ut_expect(eq);
	voluta_substr_chop_if(ss, voluta_chr_isprint, &sub);
	eq  = voluta_substr_size(&sub) == 0;
	ut_expect(eq);
}

static void test_strip(struct voluta_substr *ss)
{
	bool eq;
	size_t sz;
	const char *s;
	const char *s2 = "s ";
	struct voluta_substr sub;

	voluta_substr_init(ss, ".....#XYZ#.........");
	voluta_substr_strip_any_of(ss, "-._#", &sub);
	eq  = voluta_substr_isequal(&sub, "XYZ");
	ut_expect(eq);
	voluta_substr_strip_chr(ss, '.', &sub);
	eq  = voluta_substr_isequal(&sub, "#XYZ#");
	ut_expect(eq);
	voluta_substr_strip_if(ss, voluta_chr_ispunct, &sub);
	eq  = voluta_substr_isequal(&sub, "XYZ");
	ut_expect(eq);
	s  = voluta_substr_data(ss);
	sz = voluta_substr_size(ss);
	voluta_substr_nstrip_any_of(ss, s, sz, &sub);
	eq  = voluta_substr_isequal(&sub, "");
	ut_expect(eq);
	voluta_substr_init(ss, " \t ABC\n\r\v");
	voluta_substr_strip_ws(ss, &sub);
	eq = voluta_substr_isequal(&sub, "ABC");
	ut_expect(eq);
	voluta_substr_init(ss, s2);
	voluta_substr_strip_if(ss, voluta_chr_isspace, &sub);
	eq  = voluta_substr_isequal(&sub, "s");
	ut_expect(eq);
	voluta_substr_init(ss, s2 + 1);
	voluta_substr_strip_if(ss, voluta_chr_isspace, &sub);
	eq  = voluta_substr_isequal(&sub, "");
	ut_expect(eq);
}

static void test_find_token(struct voluta_substr *ss)
{
	bool eq;
	struct voluta_substr tok;
	const char *seps = " \t\n\v\r";

	voluta_substr_init(ss, " A BB \t  CCC    DDDD  \n");
	voluta_substr_find_token(ss, seps, &tok);
	eq  = voluta_substr_isequal(&tok, "A");
	ut_expect(eq);
	voluta_substr_find_next_token(ss, &tok, seps, &tok);
	eq  = voluta_substr_isequal(&tok, "BB");
	ut_expect(eq);
	voluta_substr_find_next_token(ss, &tok, seps, &tok);
	eq  = voluta_substr_isequal(&tok, "CCC");
	ut_expect(eq);
	voluta_substr_find_next_token(ss, &tok, seps, &tok);
	eq  = voluta_substr_isequal(&tok, "DDDD");
	ut_expect(eq);
	voluta_substr_find_next_token(ss, &tok, seps, &tok);
	eq  = voluta_substr_isequal(&tok, "");
	ut_expect(eq);
}

static void test_tokenize(struct voluta_substr *ss)
{
	bool eq;
	int err;
	size_t n_toks;
	struct voluta_substr toks_list[7];
	const char *seps = " /:;.| " ;
	const char *line =
	        "    /Ant:::Bee;:Cat:Dog;...Elephant.../Frog:/Giraffe///    ";

	voluta_substr_init(ss, line);
	err = voluta_substr_tokenize(ss, seps, toks_list, 7, &n_toks);
	ut_expect_eq(err, 0);
	ut_expect_eq(n_toks, 7);
	eq  = voluta_substr_isequal(&toks_list[0], "Ant");
	ut_expect(eq);
	eq  = voluta_substr_isequal(&toks_list[4], "Elephant");
	ut_expect(eq);
	eq  = voluta_substr_isequal(&toks_list[6], "Giraffe");
	ut_expect(eq);
}

static void test_case(struct voluta_substr *ss)
{
	bool eq;
	char buf[20] = "0123456789abcdef";

	voluta_substr_init_rwa(ss, buf);
	voluta_substr_toupper(ss);
	eq  = voluta_substr_isequal(ss, "0123456789ABCDEF");
	ut_expect(eq);
	voluta_substr_tolower(ss);
	eq  = voluta_substr_isequal(ss, "0123456789abcdef");
	ut_expect(eq);
}

static void test_common_prefix(struct voluta_substr *ss)
{
	size_t sz;
	char buf1[] = "0123456789abcdef";

	voluta_substr_init(ss, buf1);
	sz = voluta_substr_common_prefix(ss, "0123456789ABCDEF");
	ut_expect_eq(sz, 10);

	sz = voluta_substr_common_prefix(ss, buf1);
	ut_expect_eq(sz, 16);

	sz = voluta_substr_common_prefix(ss, "XYZ");
	ut_expect_eq(sz, 0);
}

static void test_common_suffix(struct voluta_substr *ss)
{
	size_t sz;
	char buf1[] = "abcdef0123456789";

	voluta_substr_init(ss, buf1);

	sz = voluta_substr_common_suffix(ss, "ABCDEF0123456789");
	ut_expect_eq(sz, 10);
	sz = voluta_substr_common_suffix(ss, buf1);
	ut_expect_eq(sz, 16);
	sz = voluta_substr_common_suffix(ss, "XYZ");
	ut_expect_eq(sz, 0);
}

static void test_assign(struct voluta_substr *ss)
{
	bool eq;
	size_t sz;
	struct voluta_substr sub;
	char buf1[] = "0123456789......";
	const char *s;

	voluta_substr_init_rw(ss, buf1, 10, 16);
	voluta_substr_sub(ss, 10, 6, &sub);
	sz = voluta_substr_size(&sub);
	ut_expect_eq(sz, 0);
	sz = voluta_substr_wrsize(&sub);
	ut_expect_eq(sz, 6);

	s = "ABC";
	voluta_substr_assign(ss, s);
	sz = voluta_substr_size(ss);
	ut_expect_eq(sz, 3);
	sz = voluta_substr_wrsize(ss);
	ut_expect_eq(sz, 16);
	eq = voluta_substr_isequal(ss, s);
	ut_expect(eq);
	s = "ABCDEF";
	voluta_substr_assign(&sub, s);
	eq = voluta_substr_isequal(&sub, s);
	ut_expect(eq);
	s = "ABCDEF$$$";
	voluta_substr_assign(&sub, s);
	sz = voluta_substr_size(&sub);
	ut_expect_eq(sz, 6);
	sz = voluta_substr_wrsize(&sub);
	ut_expect_eq(sz, 6);
	eq = voluta_substr_isequal(&sub, s);
	ut_expect(!eq);
	voluta_substr_sub(&sub, 5, 100, &sub);
	s = "XYZ";
	voluta_substr_assign(&sub, s);
	sz = voluta_substr_size(&sub);
	ut_expect_eq(sz, 1);
	sz = voluta_substr_wrsize(&sub);
	ut_expect_eq(sz, 1);
}

static void test_append(struct voluta_substr *ss)
{
	bool eq;
	size_t sz;
	char buf[20];
	const char *s = "0123456789abcdef";

	voluta_substr_init_rw(ss, buf, 0, UT_ARRAY_SIZE(buf));
	voluta_substr_append(ss, s);
	sz = voluta_substr_size(ss);
	ut_expect_eq(sz, 16);
	sz = voluta_substr_wrsize(ss);
	ut_expect_eq(sz, UT_ARRAY_SIZE(buf));
	eq = voluta_substr_isequal(ss, s);
	ut_expect(eq);
	voluta_substr_append(ss, s);
	sz = voluta_substr_size(ss);
	ut_expect_eq(sz, UT_ARRAY_SIZE(buf));
	sz = voluta_substr_wrsize(ss);
	ut_expect_eq(sz, UT_ARRAY_SIZE(buf));
	voluta_substr_init_rw(ss, buf, 0, UT_ARRAY_SIZE(buf));
	voluta_substr_nappend(ss, s, 1);
	sz = voluta_substr_size(ss);
	ut_expect_eq(sz, 1);
	voluta_substr_nappend(ss, s + 1, 1);
	sz = voluta_substr_size(ss);
	ut_expect_eq(sz, 2);
	eq = voluta_substr_nisequal(ss, s, 2);
	ut_expect(eq);
}

static void test_insert(struct voluta_substr *ss)
{
	bool eq;
	size_t n;
	char buf[20];
	const char *s = "0123456789";

	voluta_substr_init_rw(ss, buf, 0, UT_ARRAY_SIZE(buf));
	voluta_substr_insert(ss, 0, s);
	n = voluta_substr_size(ss);
	ut_expect_eq(n, 10);
	eq = voluta_substr_isequal(ss, s);
	ut_expect(eq);
	voluta_substr_insert(ss, 10, s);
	n = voluta_substr_size(ss);
	ut_expect_eq(n, 20);
	eq = voluta_substr_isequal(ss, "01234567890123456789");
	ut_expect(eq);
	voluta_substr_insert(ss, 1, "....");
	n = voluta_substr_size(ss);
	ut_expect_eq(n, 20);
	eq = voluta_substr_isequal(ss, "0....123456789012345");
	ut_expect(eq);
	voluta_substr_insert(ss, 16, "%%%");
	n = voluta_substr_size(ss);
	ut_expect_eq(n, 20);
	eq = voluta_substr_isequal(ss, "0....12345678901%%%2");
	ut_expect(eq);
	voluta_substr_insert_chr(ss, 1, 20, '$');
	n = voluta_substr_size(ss);
	ut_expect_eq(n, 20);
	eq = voluta_substr_isequal(ss, "0$$$$$$$$$$$$$$$$$$$");
	ut_expect(eq);
}

static void test_replace(struct voluta_substr *ss)
{
	bool eq;
	size_t sz;
	size_t wsz;
	char buf[10];
	const char *s = "ABCDEF";

	voluta_substr_init_rw(ss, buf, 0, UT_ARRAY_SIZE(buf));
	voluta_substr_replace(ss, 0, 2, s);
	wsz = voluta_substr_size(ss);
	ut_expect_eq(wsz, 6);
	eq = voluta_substr_isequal(ss, s);
	ut_expect(eq);
	voluta_substr_replace(ss, 1, 2, s);
	eq = voluta_substr_isequal(ss, "AABCDEFDEF");
	ut_expect(eq);
	voluta_substr_replace(ss, 6, 3, s);
	eq = voluta_substr_isequal(ss, "AABCDEABCD");
	ut_expect(eq);
	voluta_substr_replace_chr(ss, 0, 10, 30, '.');
	eq = voluta_substr_isequal(ss, "..........");
	ut_expect(eq);
	voluta_substr_replace_chr(ss, 1, 8, 4, 'A');
	eq = voluta_substr_isequal(ss, ".AAAA.");
	ut_expect(eq);
	sz = voluta_substr_size(ss);
	voluta_substr_nreplace(ss, 2, 80, voluta_substr_data(ss), sz);
	eq = voluta_substr_isequal(ss, ".A.AAAA.");
	ut_expect(eq);
	sz = voluta_substr_size(ss);
	voluta_substr_nreplace(ss, 4, 80, voluta_substr_data(ss), sz);
	eq = voluta_substr_isequal(ss, ".A.A.A.AAA");  /* Truncated */
	ut_expect(eq);
}

static void test_erase(struct voluta_substr *ss)
{
	bool eq;
	size_t wsz;
	char buf[5];

	voluta_substr_init_rw(ss, buf, 0, UT_ARRAY_SIZE(buf));
	voluta_substr_assign(ss, "ABCDEF");
	eq = voluta_substr_isequal(ss, "ABCDE");
	ut_expect(eq);
	voluta_substr_erase(ss, 1, 2);
	eq = voluta_substr_isequal(ss, "ADE");
	ut_expect(eq);
	voluta_substr_erase(ss, 0, 100);
	eq = voluta_substr_isequal(ss, "");
	ut_expect(eq);
	wsz = voluta_substr_wrsize(ss);
	ut_expect_eq(wsz, UT_ARRAY_SIZE(buf));
}

static void test_reverse(struct voluta_substr *ss)
{
	int eq;
	char buf[40];

	voluta_substr_init_rw(ss, buf, 0, UT_ARRAY_SIZE(buf));
	voluta_substr_assign(ss, "abracadabra");
	voluta_substr_reverse(ss);
	eq = voluta_substr_isequal(ss, "arbadacarba");
	ut_expect(eq);
	voluta_substr_assign(ss, "0123456789");
	voluta_substr_reverse(ss);
	eq = voluta_substr_isequal(ss, "9876543210");
	ut_expect(eq);
}

static void test_copyto(struct voluta_substr *ss)
{
	bool eq;
	char buf[10];
	char pad = '@';
	size_t sz;

	voluta_substr_init(ss, "123456789");
	sz = voluta_substr_size(ss);
	ut_expect_eq(sz, 9);
	sz = voluta_substr_copyto(ss, buf, sizeof(buf));
	ut_expect_eq(sz, 9);
	eq = !strcmp(buf, "123456789");
	ut_expect(eq);
	ut_expect_eq(pad, '@');
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_strings(struct ut_env *ute)
{
	struct voluta_substr ss_obj;
	struct voluta_substr *ss = &ss_obj;

	ut_substr_compare(ss);
	test_find(ss);
	test_rfind(ss);
	test_find_first_of(ss);
	test_find_last_of(ss);
	test_find_first_not_of(ss);
	test_find_last_not_of(ss);
	test_sub(ss);
	test_count(ss);
	test_split(ss);
	test_rsplit(ss);
	test_trim(ss);
	test_chop(ss);
	test_strip(ss);
	test_find_token(ss);
	test_tokenize(ss);
	test_case(ss);
	test_common_prefix(ss);
	test_common_suffix(ss);

	test_assign(ss);
	test_append(ss);
	test_insert(ss);
	test_replace(ss);
	test_erase(ss);
	test_reverse(ss);
	test_copyto(ss);

	voluta_substr_destroy(ss);
	voluta_unused(ute);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_strings),
};

const struct ut_tests ut_test_strings = UT_MKTESTS(ut_local_tests);


