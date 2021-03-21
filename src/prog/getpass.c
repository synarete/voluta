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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "voluta-prog.h"

static void write_stdout(const char *msg)
{
	size_t nwr;
	int fd_out = STDOUT_FILENO;

	voluta_sys_write(fd_out, msg, strlen(msg), &nwr);
	voluta_sys_fsync(fd_out);
}

static void write_newline(void)
{
	write_stdout("\n");
}

static void check_passphrase_char(int ch)
{
	if (!isascii(ch)) {
		voluta_die(-EINVAL, "non ASCII char in passphrase");
	}
	if (iscntrl(ch)) {
		voluta_die(-EINVAL, "control char in passphrase");
	}
	if (isspace(ch)) {
		voluta_die(-EINVAL, "space char in passphrase");
	}
	if (!isprint(ch)) {
		voluta_die(-EINVAL, "non printable char in passphrase");
	}
	if (!isalnum(ch) && !ispunct(ch)) {
		voluta_die(-EINVAL, "illegal char in passphrase");
	}
}

static int isskip(int ch)
{
	return !ch || isspace(ch);
}

static void parse_passphrase(char *buf, size_t bsz)
{
	size_t len = bsz;
	const char *str = buf;

	while (len && isskip(*str)) {
		str++;
		len--;
	}
	while (len && isskip(str[len - 1])) {
		len--;
	}
	if (len == 0) {
		voluta_die(-EINVAL, "zero length passphrase");
	}
	if ((len > VOLUTA_PASSPHRASE_MAX) || (len >= bsz)) {
		voluta_die(-EINVAL, "passphrase too long");
	}
	for (size_t i = 0; i < len; ++i) {
		check_passphrase_char(str[i]);
	}
	memmove(buf, str, len);
	buf[len] = '\0';
}

static void
read_passphrase_buf_from_file(int fd, void *buf, size_t bsz, size_t *out_len)
{
	int err;
	struct stat st;

	err = voluta_sys_fstat(fd, &st);
	if (err) {
		voluta_die(err, "fstat failed");
	}
	if (!st.st_size || (st.st_size > (loff_t)bsz)) {
		voluta_die(-EFBIG, "illegal passphrase file size");
	}
	err = voluta_sys_pread(fd, buf, (size_t)st.st_size, 0, out_len);
	if (err) {
		voluta_die(err, "pread passphrase file");
	}
}

static void
read_passphrase_buf_from_tty(int fd, void *buf, size_t bsz, size_t *out_len)
{
	int err;
	int read_err;
	char *pass;
	struct termios tr_old;
	struct termios tr_new;

	err = tcgetattr(fd, &tr_old);
	if (err) {
		voluta_die(errno, "tcgetattr fd=%d", fd);
	}
	memcpy(&tr_new, &tr_old, sizeof(tr_new));
	tr_new.c_lflag &= ~((tcflag_t)ECHO);
	tr_new.c_lflag |= ICANON;
	tr_new.c_lflag |= ISIG;
	tr_new.c_cc[VMIN] = 1;
	tr_new.c_cc[VTIME] = 0;
	err = tcsetattr(fd, TCSANOW, &tr_new);
	if (err) {
		voluta_die(errno, "tcsetattr fd=%d", fd);
	}

	read_err = voluta_sys_read(fd, buf, bsz, out_len);
	write_newline();

	err = tcsetattr(fd, TCSANOW, &tr_old);
	if (err) {
		voluta_die(errno, "tcsetattr fd=%d", fd);
	}

	err = read_err;
	if (err) {
		voluta_die(err, "read passphrase error");
	}
	if (*out_len == 0) {
		voluta_die(-EINVAL, "read zero-length passphrase");
	}
	pass = buf;
	if (pass[*out_len - 1] != '\n') {
		voluta_die(-EINVAL, "passphrase too long");
	}
}

static void read_passphrase_buf(int fd, void *buf, size_t bsz, size_t *out_len)
{
	if (isatty(fd)) {
		read_passphrase_buf_from_tty(fd, buf, bsz, out_len);
	} else {
		read_passphrase_buf_from_file(fd, buf, bsz, out_len);
	}
}

static int open_passphrase_file(const char *path)
{
	int err;
	int fd = -1;

	if (path == NULL) {
		return STDIN_FILENO;
	}
	err = voluta_sys_access(path, R_OK);
	if (err) {
		voluta_die(err, "no read access to passphrase file %s", path);
	}
	err = voluta_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		voluta_die(err, "can not open passphrase file %s", path);
	}
	return fd;
}

static void close_passphrase_file(int fd, const char *path)
{
	int err;

	if (path != NULL) {
		err = voluta_sys_close(fd);
		if (err) {
			voluta_die(err, "close failed: %s", path);
		}
	}
}

static char *getpass_from_file(const char *path)
{
	int fd;
	size_t len = 0;
	char buf[1024] = "";

	fd = open_passphrase_file(path);
	read_passphrase_buf(fd, buf, sizeof(buf), &len);
	parse_passphrase(buf, len);
	close_passphrase_file(fd, path);
	return voluta_strdup_safe(buf);
}

static char *voluta_do_getpass(const char *path, bool repeat)
{
	char *pass = NULL;
	char *pass2 = NULL;

	if (path) {
		return getpass_from_file(path);
	}
	write_stdout("enter passphrase: ");
	pass = getpass_from_file(NULL);
	if (!repeat) {
		return pass;
	}
	write_stdout("re-enter passphrase: ");
	pass2 = getpass_from_file(NULL);
	if (strcmp(pass, pass2) != 0) {
		voluta_delpass(&pass);
		voluta_delpass(&pass2);
		voluta_die(0, "passphrase not equal");
	}
	voluta_delpass(&pass2);
	return pass;
}

char *voluta_getpass(const char *path)
{
	return voluta_do_getpass(path, false);
}

char *voluta_getpass2(const char *path)
{
	return voluta_do_getpass(path, true);
}

void voluta_delpass(char **pass)
{
	if (pass && *pass) {
		memset(*pass, 0xEC, strlen(*pass));
		voluta_pfree_string(pass);
	}
}

