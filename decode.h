/***************************************************************************
 *  Decoders for base64 and quoted-printable strings
 *  Copyright (C) 2018, 2019  Ole Hansen <ole@redvw.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 ***************************************************************************/

#ifndef _DECODE_H_
#define _DECODE_H_

/* Error return codes */
enum {
   DECODE_SUCCESS = 0,             /* Success */
   DECODE_BADARG = 1,              /* Invalid input parameter */
   DECODE_BADALLOC = 2,            /* Out of memory when allocating buffer */
   DECODE_INVALID_CHAR = 3,        /* Invalid character in input */
   DECODE_MALFORMED_SEQUENCE = 4,  /* Sequence of characters found that is
				      incompatible with the encoding */
   DECODE_BUFFER_TOO_SMALL = 5,    /* Output buffer size too small */
   DECODE_LOWERCASE_HEX = 6,       /* QP: '=' followed by lowercase hex chars */
   DECODE_LINE_TOO_LONG = 7,       /* QP: input line longer than 76 chars */
   DECODE_WHITESPACE_IN_SOFTBREAK = 8 /* QP: Whitespace between '=' and \r\n */
};

/* Decoding mode flags */
enum {
   DECODE_MODE_STRICT        = 0,     /* Require full standards conformance */
   DECODE_MODE_LONG_LINES    = 1<<0,  /* QP: Accept lines > 76 characters */
   DECODE_MODE_LC_HEX        = 1<<1,  /* QP: Accept lowercase hex digits */
   DECODE_MODE_WHITESPACE_OK = 1<<2,  /* QP: Allow soft breaks with whitespace,
				         B64: Skip all whitespace in data */
   DECODE_MODE_CRLF_BREAKS   = 1<<3,  /* B64: Allow CRLF line breaks */
   DECODE_MODE_LF_BREAKS     = 1<<4,  /* Accept LF line endings */
   DECODE_MODE_RELAXED       = 0xFF,  /* Accept LC hex, long lines, all WS */
   DECODE_MODE_LITERAL_EQ    = 1<<8,  /* '=' + non-hex accepted verbatim */
   DECODE_MODE_INVALID_CHAR  = 1<<9,  /* Skip invalid characters */
   DECODE_MODE_ROBUST        = 0xFFFF,/* Be maximally error-tolerant */
   DECODE_MODE_ENCODEDWORD   = 1<<24  /* QP: Input is RFC 2047 "encoded word" */
};

const char* decode_perror( int err );

int quoted_printable_decode_alloc( const char *inbuf, char **outbuf,
                                   size_t *outlen, int mode );
int quoted_printable_decode_mode( const char *inbuf, char *outbuf,
                                  size_t *outlen, int mode );
int quoted_printable_word_decode( const char *inbuf, char *outbuf,
                                  size_t *outlen );
int quoted_printable_decode( const char *inbuf, char *outbuf, size_t *outlen );

int base64_decode_alloc( const char *inbuf, char **outbuf, size_t *outlen,
                         int mode );
int base64_decode_mode( const char *inbuf, char *outbuf, size_t *outlen,
                        int mode );
int base64_decode( const char *inbuf, char *outbuf, size_t *outlen );

#endif
