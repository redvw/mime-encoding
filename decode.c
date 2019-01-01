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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "decode.h"

#define ISSPACE(c) ((c) == ' '  || (c) == '\n' || (c) == '\r' || \
		     (c) == '\t' || (c) == '\f' || (c) == '\v')
#define ISLSPC(c)  ((c) == ' '  || (c) == '\t')

#define MAX_QP_LINE 76
#define ALLOW_LF_SOFT_BREAKS

/* ------------------------------------------------------------------------ */
const char* decode_perror( int err )
{
   /* Return description of error code 'err' */

   switch( err ) {
   case DECODE_SUCCESS:
      return "Success";
   case DECODE_BADARG:
      return "Bad function argument";
   case DECODE_BADALLOC:
      return "Cannot allocate buffer";
   case DECODE_INVALID_CHAR:
      return "Invalid character in input";
   case DECODE_MALFORMED_SEQUENCE:
      return "Invalid sequence of characters in input";
   case DECODE_BUFFER_TOO_SMALL:
      return "Output buffer size too small";
   case DECODE_LOWERCASE_HEX:
      return "Lowercase hex character following '='";
   case DECODE_LINE_TOO_LONG:
      return "Quoted-printable line longer than 76 characters";
   case DECODE_WHITESPACE_IN_SOFTBREAK:
      return "Quoted-printable softbreak padded with whitespace";
   default:
      return "Unknown return code";
   }
}

/* ======================== quoted-printable ============================== */
static int hex_byte_to_int( const char in[2], int relaxed )
{
   /* Interpret two ASCII characters in 'in[2]' as hex digits and convert
      them to integer (0-255).  Return -1 if a character is not hex.
      Return -2 if a character is a lowercase hex letter (a-f) unless
      'relaxed' is true. */

   int c, v = 0;

   for( int i = 0; i < 2; i++ ) {
      c = in[i];
      v <<= 4;
      if( c >= '0' && c <= '9' )
         v += c - '0';
      else if( c >= 'A' && c <= 'F' )
         v += c - 'A' + 10;
      else if( c >= 'a' && c <= 'f' ) {
         if( relaxed )
            v += c - 'a' + 10;
         else
            return -2;
      } else
         return -1;
   }
   return v;
}

/* ------------------------------------------------------------------------ */
int quoted_printable_decode_mode( const char *inbuf, char *outbuf,
                                  size_t *outlen, int mode )
{
   /* Decode a RFC 2045 quoted-printable string from 'inbuf' into 'outbuf',
      where outlen is the size of 'outbuf' (allocated by the caller).
      'inbuf' must be a NULL-terminated string.

      Returns DECODE_SUCCESS on success or an error code (see header file)
      in case of error. Regardless of success, on return 'outlen' will always
      hold the number of characters written to 'outbuf'.

      IMPORTANT: 'outbuf' is NOT NULL-terminated because it can hold
      arbitrary binary data, including NUL. If 'outbuf' is expected to
      hold a C-string, the caller must append the terminating NUL.

      The 'mode' parameter controls which deviations from strict RFC 2045
      conformance are tolerated. 'mode' is interpreted as a bit field of
      flags (defined in the header file). It is generally safe to allow
      lowercase hex digits, lines longer that 76 characters, whitespace
      padding in softbreaks and LF line breaks with DECODE_MODE_RELAXED.
      DECODE_MODE_ROBUST enables maximum error tolerance: invalid characters
      (control codes) are skipped, and '=' without following anything
      resembling a hex code will be accepted verbatim. These latter two
      settings should be used with care - if needed, the input is likely
      corrupted.

      If DECODE_MODE_ENCODEDWORD is set in 'mode', the input will be
      treated as a RFC 2047 Q-"encoded word", which follows slightly
      different rules than regular quoted-printable text:
      - any underscore "_" characters are translated to spaces.
      - question marks "?" are treated as invalid characters
      - soft line breaks ("=\r\n") are disallowed (DECODE_MALFORMED_SEQUENCE)
      - hard line breaks ("\r\n") are disallowed (DECODE_INVALID_CHAR)
   */

   const char *inbuf_start = inbuf, *outbuf_start = outbuf, *q;
   char *p = NULL;  /* last non-whitespace character in outbuf */
   size_t bufsize;
   int v, i = 0, len = 0;
   const int std_lines = ((mode & DECODE_MODE_LONG_LINES) == 0);
   const int lc_hex = ((mode & DECODE_MODE_LC_HEX) != 0);
   const int enc = ((mode & DECODE_MODE_ENCODEDWORD) != 0);
   char in[2], c;

   if( !outlen )
      return DECODE_BADARG;
   bufsize = *outlen; *outlen = 0;
   if( !inbuf || !outbuf )
      return DECODE_BADARG;

   while( *inbuf ) {
      c = *inbuf++;
      if( c == '=' ) {
         /* Got a '=': Encoded character or soft line break follows */
         len++;
         p = NULL;
         if( len > MAX_QP_LINE && std_lines )
            return DECODE_LINE_TOO_LONG;
         if( !enc ) {
            q = inbuf;
            /* Advance through any linear whitespace in preparation
               for checking for a padded soft break */
            while( ISLSPC(*q) )
               q++;
            if( (*q == '\r' && *(q+1) == '\n') ||
                /* If requested, allow '=\n' soft breaks as well */
                (*q == '\n' && (mode & DECODE_MODE_LF_BREAKS) != 0) ) {
               /* Soft break found. If it is padded with whitespace,
                  report error unless relaxed handling enabled */
               if( q != inbuf && !(mode & DECODE_MODE_WHITESPACE_OK) )
                  return DECODE_WHITESPACE_IN_SOFTBREAK;
               /* Discard the '=\r\n' sequence. */
               len = 0;
               inbuf = q+1;
               if( *q == '\r' )
                  inbuf++;
               continue;
            }
         }
         /* Fetch the two hex digits after the '=' */
         for( i = 0; i < 2; i++, inbuf++ ) {
            if( (in[i] = *inbuf) == 0 ) {
               /* '=' found as last or one-before-last character in buffer */
               if( !(mode & DECODE_MODE_LITERAL_EQ) )
                  return DECODE_MALFORMED_SEQUENCE;
               inbuf -= i;
               goto addchar;
            }
            len++;
            if( len > MAX_QP_LINE && std_lines  )
               return DECODE_LINE_TOO_LONG;
         }
         /* Convert the hex code string to a number */
         if( (v = hex_byte_to_int( in, lc_hex )) < 0 ) {
	    if( v == -2 )
	       /* '=' followed by lowercase hex characters */
	       return DECODE_LOWERCASE_HEX;
	    /* '=' followed by non-hex characters */
            if( !(mode & DECODE_MODE_LITERAL_EQ) )
               return DECODE_MALFORMED_SEQUENCE;
            /* Invalid data after '=' - accept as is */
            inbuf -= 2;
         } else {
            assert( v >= 0 && v <= 0xFF );
            c = (char)v;
         }
      } else if( c >= 33 && c <= 126 ) {
         /* Unencoded character within valid range - accept */
         len++;
         p = NULL;
         if( enc ) {
            /* Slightly different rules for "encoded words" */
            if( c == '_' )
               c = 0x20;
            else if( c == '?' ) {
               if( !(mode & DECODE_MODE_INVALID_CHAR) )
                  return DECODE_INVALID_CHAR;
               continue;
            }
         }
      } else if( ISLSPC(c) && !enc ) {
         /* Linear whitespace - keep, but prepare to erase if it's padding */
         len++;
         if( !p )
            p = outbuf;
      } else if( ((c == '\r' && *inbuf == '\n') ||
                  (c == '\n' && (mode & DECODE_MODE_LF_BREAKS) != 0))
		 && !enc ) {
         /* Hard line break */
         len = 0;
         if( p ) {
            /* Delete preceding whitespace, if any */
            outbuf = p;
            assert( outbuf >= outbuf_start );
            *outlen = (size_t)(outbuf - outbuf_start);
            p = NULL;
         }
      } else if( c == '\n' && inbuf - inbuf_start > 1 && *(inbuf-2) == '\r'
                 && !enc ) {
         /* LF following immediately after CR */
         assert( p == NULL );
      } else {
         /* Illegal character - error or skip, depending on mode */
         if( !(mode & DECODE_MODE_INVALID_CHAR) )
            return DECODE_INVALID_CHAR;
         len++;
         p = NULL;
         continue;
      }
   addchar:
      if( len > MAX_QP_LINE && std_lines )
         return DECODE_LINE_TOO_LONG;
      if( bufsize == 0 )
         return DECODE_BUFFER_TOO_SMALL;
      *outbuf++ = c;
      (*outlen)++;
      bufsize--;
   }
   if( p ) {
      /* Input ended with a whitespace sequence - treat it like a hard
         line break and delete the whitespace back to the last non-
         whitespace character */
      outbuf = p;
      assert( outbuf >= outbuf_start );
      *outlen = (size_t)(outbuf - outbuf_start);
   }
   return DECODE_SUCCESS;
}

/* ------------------------------------------------------------------------ */
int quoted_printable_decode_alloc( const char *inbuf, char **outbuf,
                                   size_t *outlen, int mode )
{
   /* Decode quoted-printable encoded data in 'inbuf' to 'outbuf', where
      'outbuf' is automatically allocated. 'inbuf' must be a NULL-terminated
      C-string.

      'outbuf' will be allocated with sufficient size and must be
      free'd by the caller. 'outlen' holds the length of valid decoded
      data in 'outbuf'.

      'outbuf' is guaranteed to be at least one byte larger than
      'outlen' so that the caller can always add a terminating NULL if
      needed.

      If the buffer cannot be allocated (out of memory), DECODE_BADALLOC
      is returned, the 'outbuf' pointer is NULL, and 'outlen' is zero.
   */

   /* Determine an upper limit on the space needed */
   const char *p = inbuf;
   size_t bufsize = 0;
   const int lc_hex = ((mode & DECODE_MODE_LC_HEX) != 0);
   int ret;
   char c;

   if( !inbuf || !outbuf || !outlen )
      return DECODE_BADARG;

   while( *p ) {
      c = *p++;
      if( c == '=' ) {
         /* Detect the most common cases: valid =(hex)(hex) and
            =\r\n soft line breaks */
         if( *p && *(p+1) ) {
            if( hex_byte_to_int( p, lc_hex ) >= 0 ) {
               /* Single decoded output character */
               bufsize++;
               p += 2;
               continue;
            } else if( *p == '\r' && *(p+1) == '\n') {
               /* Soft line break that will be skipped entirely */
               p += 2;
               continue;
            }
         }
         /* Otherwise count the '=' as a single character. If something
            valid follows after all, it will be counted by the next clause */
         bufsize++;
      } else if( (c >= 33 && c <= 126)
                 || ISLSPC(c) || c == '\r' || c == '\n' ) {
         /* All these characters will be accepted verbatim unless there is
            whitespace padding, which then leads to an overestimate */
         bufsize++;
      }
   }
   /* Room for a trailing NULL that the caller might want to add */
   bufsize++;

   *outbuf = (char*)malloc( bufsize );
   if( *outbuf == NULL ) {
      *outlen = 0;
      return DECODE_BADALLOC;
   }
   *outlen = bufsize-1;
   ret = quoted_printable_decode_mode( inbuf, *outbuf, outlen, mode );
   assert( *outlen < bufsize );

   return ret;
}

/* ------------------------------------------------------------------------ */
int quoted_printable_word_decode( const char *inbuf, char *outbuf,
                                  size_t *outlen )
{
   /* Convenience function for decoding RFC 2047 quoted-printable encoded
      words */

   return quoted_printable_decode_mode( inbuf, outbuf, outlen,
             DECODE_MODE_ENCODEDWORD |
             DECODE_MODE_LC_HEX );      /* Accept lowercase hex digits */
}

/* ------------------------------------------------------------------------ */
int quoted_printable_decode( const char *inbuf, char *outbuf, size_t *outlen )
{
   /* Convenience function for fully standards-conformant quoted-printable
      decoding */

   return quoted_printable_decode_mode( inbuf, outbuf, outlen,
                                        DECODE_MODE_STRICT );
}

/* ============================ base64 ==================================== */
static void base64_decode_short_block( const unsigned char in[3],
                                       char out[2], int len )
{
   /* Decode 'len'+1 6-bit 'characters' to 'len' 8-bit binary bytes.
      'len' must be 1 or 2 */

   assert( len == 1 || len == 2 );

   out[0] = in[0] << 2 | in[1] >> 4;
   if( len == 1 )
      return;
   out[1] = in[1] << 4 | in[2] >> 2;
}

/* ------------------------------------------------------------------------ */
static void base64_decode_block( const unsigned char in[4], char out[3] )
{
   /* Decode four 6-bit 'characters' (one base64 group) to three 8-bit binary
      bytes. */

   out[0] = in[0] << 2 | in[1] >> 4;
   out[1] = in[1] << 4 | in[2] >> 2;
   out[2] = in[2] << 6 | in[3];
}

/* ------------------------------------------------------------------------ */
static int base64_char_to_6bit( int c )
{
   /* Convert character 'c' to base64 sextet (6 bits, 0-63).
      If 'c' is outside the base64 character set, return -1 */

   static const char translation_table[80] = {
      62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1,
      -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
      29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
      47, 48, 49, 50, 51 };

   if( c < 43 || c > 122 )
      return -1;
   return translation_table[c - 43];
}

/* ------------------------------------------------------------------------ */
int base64_decode_mode( const char *inbuf, char *outbuf, size_t *outlen,
                        int mode )
{
   /* Decode a RFC 2045 base64-encoded string from 'inbuf' into 'outbuf',
      where outlen is the size of 'outbuf' (allocated by the caller).
      'inbuf' must be a NULL-terminated string.

      Returns DECODE_SUCCESS on success or an error code (see header file)
      in case of error. Regardless of success, on return 'outlen' will always
      hold the number of characters written to 'outbuf'.

      IMPORTANT: 'outbuf' is NOT NULL-terminated because it can hold
      arbitrary binary data, including NUL. If 'outbuf' is expected to
      hold a C-string, the caller must append the terminating NUL.

      The 'mode' parameter controls which deviations from strict RFC 2045
      conformance are tolerated. 'mode' is interpreted as a bit field of
      flags (defined in the header file). 
      With DECODE_MODE_WHITESPACE_OK (or DECODE_MODE_RELAXED) set, the
      routine will ignore all whitespace between character data instead
      of only CRLF line endings. If DECODE_MODE_LF_BREAKS is set, LF line
      breaks will be accepted as well.
   */

   size_t bufsize;
   int v, len = 0;
   unsigned char in[4];
   char c;

   if( !outlen )
      return DECODE_BADARG;
   bufsize = *outlen; *outlen = 0;
   if( !inbuf || !outbuf )
      return DECODE_BADARG;

   while( *inbuf ) {
      c = *inbuf++;
      v = base64_char_to_6bit( c );
      if( v >= 0 ) {
         /* Valid character - save it */
         assert( len < 4 );
         assert( v < 64 );
         in[len] = (unsigned char)v;
         if( len < 3 ) {
            len++;
            continue;
         }
         /* Four sextets complete - decode & store result */
         if( bufsize < (size_t)len )
            return DECODE_BUFFER_TOO_SMALL;
         base64_decode_block( in, outbuf );
      } else if( c == '=' &&
                 (len == 3 || (len == 2 && *inbuf == '=' && *inbuf++)) ) {
	 /* 2 or 3 valid characters followed by padding */
         len--;
         if( bufsize < (size_t)len )
            return DECODE_BUFFER_TOO_SMALL;
         base64_decode_short_block( in, outbuf, len );
         /* We could exit here, assuming that padding implies end of data.
            By continuing, we allow padding in the middle of the data, e.g.
            from concatenation of several base64 blocks */
      } else if( (mode & DECODE_MODE_INVALID_CHAR) != 0 ) {
         /* Skip any and all non-alphabet characters (not recommended) */
         continue;
      } else if( (mode & DECODE_MODE_WHITESPACE_OK) != 0 ) {
         /* In relaxed mode, skip all whitespace anywhere in the input */
         if( ISSPACE(c) )
            continue;
         return DECODE_INVALID_CHAR;
      } else if( c == '\r' && *inbuf == '\n' &&
                 (mode & DECODE_MODE_CRLF_BREAKS) != 0 ) {
         /* Allow CRLF line breaks if requested */
         inbuf++;
         continue;
      } else if( c == '\n' && (mode & DECODE_MODE_LF_BREAKS) != 0 ) {
         /* Also recognize LF line line breaks if requested */
         continue;
      } else {
	 return DECODE_INVALID_CHAR;
      }
      outbuf += len;
      *outlen += len;
      bufsize -= len;
      len = 0;
   }
   if( len > 0 )
      /* Input ended while a sequence was open */
      return DECODE_MALFORMED_SEQUENCE;

   return DECODE_SUCCESS;
}

/* ------------------------------------------------------------------------ */
int base64_decode_alloc( const char *inbuf, char **outbuf, size_t *outlen,
                         int mode )
{
   /* Decode base64 data in 'inbuf' to 'outbuf', where 'outbuf' is
      automatically allocated. 'inbuf' must be a NULL-terminated C-string.

      'outbuf' will be allocated with sufficient size and must be
      free'd by the caller. 'outlen' holds the length of valid decoded
      data in 'outbuf'.

      'outbuf' is guaranteed to be at least one byte larger than
      'outlen' so that the caller can always add a terminating NULL if
      needed.

      If the buffer cannot be allocated (out of memory), DECODE_BADALLOC
      is returned, the 'outbuf' pointer is NULL, and 'outlen' is zero.
   */

   /* Determine an upper limit on the space needed */
   const char *p = inbuf;
   size_t len = 0, bufsize;
   int v;

   if( !inbuf || !outbuf || !outlen )
      return DECODE_BADARG;

   while( *p ) {
      v = base64_char_to_6bit( *p++ );
      if( v >= 0 )
         len++;
   }
   bufsize = (len / 4) * 3 + 1;
   if( len % 4 )
      bufsize += 2;

   *outbuf = (char*)malloc( bufsize );
   if( *outbuf == NULL ) {
      *outlen = 0;
      return DECODE_BADALLOC;
   }
   *outlen = bufsize-1;
   v = base64_decode_mode( inbuf, *outbuf, outlen, mode );
   assert( *outlen < bufsize );

   return v;
}

/* ------------------------------------------------------------------------ */
int base64_decode( const char *inbuf, char *outbuf, size_t *outlen )
{
   /* Convenience function for fully standards-conformant base64
      decoding */

   return base64_decode_mode( inbuf, outbuf, outlen, DECODE_MODE_STRICT );
}
