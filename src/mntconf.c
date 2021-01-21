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
#include <limits.h>
#include <errno.h>
#include "voluta-prog.h"

#define die_illegal_conf(fl_, fmt_, ...) \
	voluta_die_at(errno, (fl_)->file, (fl_)->line, fmt_, __VA_ARGS__)


#define die_illegal_value(fl_, ss_, tag_) \
	die_illegal_conf(fl_, "illegal %s: '%.*s'", \
			 tag_, (ss_)->len, (ss_)->str)


struct voluta_fileline {
	const char *file;
	int line;
};

static bool ss_equals(const struct voluta_substr *ss, const char *s)
{
	return voluta_substr_isequal(ss, s);
}

static bool ss_isempty(const struct voluta_substr *ss)
{
	return voluta_substr_isempty(ss);
}

static void ss_split_by(const struct voluta_substr *ss, char sep,
			struct voluta_substr_pair *out_ss_pair)
{
	voluta_substr_split_chr(ss, sep, out_ss_pair);
}

static void ss_split_by_nl(const struct voluta_substr *ss,
			   struct voluta_substr_pair *out_ss_pair)
{
	ss_split_by(ss, '\n', out_ss_pair);
}

static void ss_split_by_ws(const struct voluta_substr *ss,
			   struct voluta_substr_pair *out_ss_pair)
{
	voluta_substr_split(ss, " \t", out_ss_pair);
}

static void ss_strip_ws(const struct voluta_substr *ss,
			struct voluta_substr *out_ss)
{
	voluta_substr_strip_ws(ss, out_ss);
}

static void ss_copyto(const struct voluta_substr *ss, char *s, size_t n)
{
	voluta_substr_copyto(ss, s, n);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *zalloc(size_t nbytes)
{
	void *ptr;

	ptr = voluta_malloc_safe(nbytes);
	memset(ptr, 0, nbytes);
	return ptr;
}

static bool parse_bool(const struct voluta_fileline *fl,
		       const struct voluta_substr *ss)
{
	if (ss_equals(ss, "1") || ss_equals(ss, "true")) {
		return true;
	}
	if (ss_equals(ss, "0") || ss_equals(ss, "false")) {
		return false;
	}
	die_illegal_value(fl, ss, "boolean");
	return false; /* make clangscan happy */
}

static long parse_long(const struct voluta_fileline *fl,
		       const struct voluta_substr *ss)
{
	long val = 0;
	char *endptr = NULL;
	char str[64] = "";

	if (ss->len >= sizeof(str)) {
		die_illegal_value(fl, ss, "integer");
	}
	voluta_substr_copyto(ss, str, sizeof(str));

	errno = 0;
	val = strtol(str, &endptr, 0);
	if ((endptr == str) || (errno == ERANGE)) {
		die_illegal_value(fl, ss, "integer");
	}
	if (strlen(endptr) > 1) {
		die_illegal_value(fl, ss, "integer");
	}
	return val;
}

static int parse_int(const struct voluta_fileline *fl,
		     const struct voluta_substr *ss)

{
	long num;

	num = parse_long(fl, ss);
	if ((num > INT_MAX) || (num < INT_MIN)) {
		die_illegal_value(fl, ss, "int");
	}
	return (int)num;
}

static uid_t parse_uid(const struct voluta_fileline *fl,
		       const struct voluta_substr *ss)
{
	int val;

	val = parse_int(fl, ss);
	if ((val < 0) || (val > (INT_MAX / 2))) {
		die_illegal_value(fl, ss, "uid");
	}
	return (uid_t)val;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *dup_substr(const struct voluta_substr *ss)
{
	char *s;

	s = zalloc(ss->len + 1);
	ss_copyto(ss, s, ss->len);
	return s;
}

static char *realpath_of(const struct voluta_substr *path,
			 const struct voluta_fileline *cloc)
{
	char *rpath;
	char *cpath;

	cpath = dup_substr(path);
	rpath = realpath(cpath, NULL);
	if (rpath == NULL) {
		die_illegal_conf(cloc, "no realpath: '%s'", cpath);
	}
	free(cpath);
	return rpath;
}

static void parse_mntconf_rule_args(const struct voluta_fileline *fl,
				    const struct voluta_substr *args,
				    struct voluta_mntrule *mntr)
{
	struct voluta_substr_pair key_val;
	struct voluta_substr_pair ss_pair;
	struct voluta_substr *key = &key_val.first;
	struct voluta_substr *val = &key_val.second;
	struct voluta_substr *carg = &ss_pair.first;
	struct voluta_substr *tail = &ss_pair.second;

	mntr->uid = (uid_t)(-1);
	mntr->recursive = false;

	ss_split_by_ws(args, &ss_pair);
	while (!ss_isempty(carg) || !ss_isempty(tail)) {
		ss_split_by(carg, '=', &key_val);
		if (ss_isempty(key) || ss_isempty(val)) {
			die_illegal_conf(fl, "illgal key-value: '%.*s'",
					 carg->len, carg->str);
		}
		if (ss_equals(key, "recursive")) {
			mntr->recursive = parse_bool(fl, val);
		} else if (ss_equals(key, "uid")) {
			mntr->uid = parse_uid(fl, val);
		} else {
			die_illegal_conf(fl, "unknown key: '%.*s'",
					 key->len, key->str);
		}
		ss_split_by_ws(tail, &ss_pair);
	}
}

static void parse_mntconf_rule(const struct voluta_fileline *fl,
			       const struct voluta_substr *path,
			       const struct voluta_substr *args,
			       struct voluta_mntrules *mrules)
{
	struct voluta_mntrule *mntr;
	const size_t max_rules = VOLUTA_ARRAY_SIZE(mrules->rules);

	if (mrules->nrules >= max_rules) {
		die_illegal_conf(fl, "too many mount-rules "\
				 "(max-rules=%lu)", max_rules);
	}
	mntr = &mrules->rules[mrules->nrules++];
	mntr->path = realpath_of(path, fl);
	parse_mntconf_rule_args(fl, args, mntr);
}

static void parse_mntconf_line(const struct voluta_fileline *fl,
			       const struct voluta_substr *line,
			       struct voluta_mntrules *mrules)
{
	struct voluta_substr sline;
	struct voluta_substr_pair ss_pair;

	ss_split_by(line, '#', &ss_pair);
	ss_strip_ws(&ss_pair.first, &sline);
	if (!ss_isempty(&sline)) {
		ss_split_by_ws(&sline, &ss_pair);
		parse_mntconf_rule(fl, &ss_pair.first, &ss_pair.second, mrules);
	}
}

static void parse_mntconf(const struct voluta_substr *ss_conf,
			  const char *path, struct voluta_mntrules *mrules)
{
	struct voluta_substr_pair ss_pair;
	struct voluta_substr *line = &ss_pair.first;
	struct voluta_substr *tail = &ss_pair.second;
	struct voluta_fileline fl = {
		.file = path,
		.line = 0
	};

	ss_split_by_nl(ss_conf, &ss_pair);
	while (!ss_isempty(line) || !ss_isempty(tail)) {
		fl.line++;
		parse_mntconf_line(&fl, line, mrules);
		ss_split_by_nl(tail, &ss_pair);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *read_mntconf_file(const char *path)
{
	int err;
	int fd = -1;
	size_t size;
	char *conf;
	struct stat st;
	const loff_t filesize_maz = VOLUTA_MEGA;

	voluta_stat_reg(path, &st);
	if (st.st_size > filesize_maz) {
		voluta_die(-EFBIG, "illegal mntconf file: %s", path);
	}
	err = voluta_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		voluta_die(err, "can not open mntconf file %s", path);
	}
	size = (size_t)st.st_size;
	conf = zalloc(size + 1);
	err = voluta_sys_readn(fd, conf, size);
	if (err) {
		voluta_die(err, "failed to read mntconf file %s", path);
	}
	voluta_sys_close(fd);

	return conf;
}

static struct voluta_mntrules *new_mntrules(void)
{
	struct voluta_mntrules *mrules;

	mrules = zalloc(sizeof(*mrules));
	mrules->nrules = 0;

	return mrules;
}

static void del_mnt_conf(struct voluta_mntrules *mrules)
{
	for (size_t i = 0; i < mrules->nrules; ++i) {
		voluta_pfree_string(&mrules->rules[i].path);
	}
	mrules->nrules = 0;
	free(mrules);
}

struct voluta_mntrules *voluta_parse_mntrules(const char *path)
{
	char *conf;
	struct voluta_substr ss_conf;
	struct voluta_mntrules *mrules;

	errno = 0;
	conf = read_mntconf_file(path);
	voluta_substr_init(&ss_conf, conf);
	mrules = new_mntrules();
	parse_mntconf(&ss_conf, path, mrules);
	free(conf);

	return mrules;
}

void voluta_free_mntrules(struct voluta_mntrules *mnt_conf)
{
	if (mnt_conf != NULL) {
		del_mnt_conf(mnt_conf);
	}
}

