/***************************************************************************
 *  Decoders for base64 and quoted-printable strings
 *  Copyright (C) 2018  Ole Hansen <ole@redvw.com>
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
#include <limits.h>
#include "decode.h"

#define ISSPACE(c) ((c) == ' ' || (c) == '\n' || (c) == '\r' || \
                    (c) == '\t' || (c) == '\f' || (c) == '\v' )
#define ISLSPC(c)  ((c) == ' ' || (c) == '\t' )

#define MAX_QP_LINE 76
#define ALLOW_LF_SOFT_BREAKS

/* ------------------------------------------------------------------------ */
const char* decode_perror( int err )
{
   /* Return description of error code 'err' */

   switch( err ) {
   case DECODE_BADARG:
      return "Bad function argument";
   case DECODE_INVALID_CHAR:
      return "Invalid character in input";
   case DECODE_MALFORMED_SEQUENCE:
      return "Invalid sequence of characters in input";
   case DECODE_BUFFER_TOO_SMALL:
      return "Output buffer size too small";
   case DECODE_INPUT_TOO_LONG:
      return "Output length overflows INT_MAX";
   case DECODE_LOWERCASE_HEX:
      return "Lowercase hex character following '='";
   case DECODE_LINE_TOO_LONG:
      return "Quoted-printable line longer than 76 characters";
   case DECODE_WHITESPACE_IN_SOFTBREAK:
      return "Quoted-printable softbreak padded with whitespace";
   default:
      if( err >= 0 )
         return "No error";
      return "Unknown error code";
   }
}

/* ======================== quoted-printable ============================== */
static int ascii_hex_to_int( const char in[2], int relaxed )
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
int quoted_printable_decode_mode( const char* inbuf, char* outbuf,
                                  size_t bufsize, int mode )
{
   /* Decode a RFC 2045 quoted-printable string from 'inbuf' into 'outbuf',
      where bufsize is the size of 'outbuf' (allocated by the caller).
      'inbuf' must be a NULL-terminated string.

      Returns number of bytes decoded into outbuf (0 <= n <= bufsize) or a
      negative number if an error occurred. See header file for error codes.

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
      - soft line breaks ("=\r\n") are disallowed (DEOCDE_MALFORMED_SEQUENCE)
      - hard line breaks ("\r\n") are disallowed (DECODE_INVALID_CHAR)
   */

   const char *inbuf_start = inbuf;
   const char *outbuf_start = outbuf;
   char *p = NULL;  /* last non-whitespace character in outbuf */
   int v, i = 0, len = 0;
   const int std_lines = ((mode & DECODE_MODE_LONG_LINES) == 0);
   const int lc_hex = ((mode & DECODE_MODE_LC_HEX) != 0);
   const int enc = ((mode & DECODE_MODE_ENCODEDWORD) != 0);
   char in[2], c;

   if( !inbuf || !outbuf )
      return DECODE_BADARG;

   while( *inbuf ) {
      c = *inbuf++;
      if( c == 61 ) {
         /* '=': Encoded character or soft line break follows */
         p = NULL;
         len++;
         if( std_lines && len > MAX_QP_LINE )
            return DECODE_LINE_TOO_LONG;
         if( !enc ) {
            const char *q = inbuf;
            /* Advance through any linear whitespace in preparation
               for checking for a padded soft break */
            while( ISLSPC(*q) )
               q++;
            if( (*q == '\r' && *(q+1) == '\n') ||
                /* If requested, allow '=\n' soft breaks as well */
                ((mode & DECODE_MODE_LF_BREAKS) != 0 && *q == '\n') ) {
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
            if( std_lines && len > MAX_QP_LINE )
               return DECODE_LINE_TOO_LONG;
         }
         /* Convert the hex code string to a number */
         if( (v = ascii_hex_to_int( in, lc_hex )) < 0 ) {
	    if( v == -2 )
	       /* '=' followed by lowercase hex characters */
	       return DECODE_LOWERCASE_HEX;
	    /* '=' followed by non-hex characters */
            if( !(mode & DECODE_MODE_LITERAL_EQ) )
               return DECODE_MALFORMED_SEQUENCE;
            /* In "literal equals sign" mode, accept verbatim */
            assert( inbuf - inbuf_start > 2 );
            inbuf -= 2;
            c = 61;
         } else {
            assert( v >= 0 && v <= 0xFF );
            c = (char)v;
         }
      } else if( c >= 33 && c <= 126 ) {
         /* Unencoded character - accept */
         len++;
         p = NULL;
         if( enc ) {
            /* Slightly different rules for "encoded words" */
            if( c == '_' )
               c = ' ';
            else if( !(mode & DECODE_MODE_INVALID_CHAR) && c == '?' )
               return DECODE_INVALID_CHAR;
         }
      } else if( ISLSPC(c) && !enc ) {
         /* Linear whitespace - keep, but prepare to erase if it's padding */
         len++;
         if( !p )
            p = outbuf;
      } else if( ((c == '\r' && *inbuf == '\n') ||
                  (mode & DECODE_MODE_LF_BREAKS && c == '\n')) && !enc ) {
         /* Hard line break */
         len = 0;
         if( p ) {
            /* Delete preceding whitespace, if any */
            outbuf = p;
            p = NULL;
         }
      } else if( c == '\n' && inbuf - inbuf_start > 1 && *(inbuf-2) == '\r'
                 && !enc ) {
         /* LF following immediately after CR */
         assert( p == NULL );
      } else {
         /* Illegal character, skip */
         if( !(mode & DECODE_MODE_INVALID_CHAR) )
            return DECODE_INVALID_CHAR;
         len++;
         p = NULL;
         continue;
      }
   addchar:
      if( std_lines && len > MAX_QP_LINE )
         return DECODE_LINE_TOO_LONG;
      if( bufsize == 0 )
         return DECODE_BUFFER_TOO_SMALL;
      if( (outbuf - outbuf_start) >= INT_MAX )
         /* Protect against return value overflow */
         return DECODE_INPUT_TOO_LONG;
      *outbuf++ = c;
      bufsize--;
   }
   if( p )
      /* Input ended with a whitespace sequence - treat it like a hard
         line break and delete the whitespace back to the last non-
         whitespace character */
      outbuf = p;

   assert( outbuf >= outbuf_start );
   return outbuf - outbuf_start;
}

/* ------------------------------------------------------------------------ */
int quoted_printable_word_decode( const char* inbuf, char* outbuf,
                                  size_t bufsize )
{
   /* Convenience function for decoding RFC 2047 quoted-printable encoded
      words */

   return quoted_printable_decode_mode( inbuf, outbuf, bufsize,
             DECODE_MODE_ENCODEDWORD |
             DECODE_MODE_LC_HEX );      /* Accept lowercase hex digits */
}

/* ------------------------------------------------------------------------ */
int quoted_printable_decode( const char* inbuf, char* outbuf, size_t bufsize )
{
   /* Convenience function for fully standards-conformant quoted-printable
      decoding */
   return quoted_printable_decode_mode( inbuf, outbuf, bufsize,
                                        DECODE_MODE_STRICT );
}

/* ============================ base64 ==================================== */
static void base64_decodeblock( const unsigned char in[4], char out[3] )
{
   /* Decode 2-4 6-bit 'characters' into 1-3 8-bit binary bytes. End of data
      is indicated by in[i] >= 64 */
   assert( in[0] < 64 && in[1] < 64 );
   out[0] = in[0] << 2 | in[1] >> 4;
   if( in[2] < 64 ) {
      out[1] = in[1] << 4 | in[2] >> 2;
      if( in[3] < 64 )
         out[2] = in[2] << 6 | in[3];
   }
}

/* ------------------------------------------------------------------------ */
static int base64_char_to_6bit( int c )
{
   /* Convert character 'c' to base64 6-bit index (0-63). If 'c' is outside
      the base64 character set, return -1
   */
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
int base64_decode_mode( const char* inbuf, char* outbuf, size_t bufsize,
                        int mode )
{
   /* Decode a RFC 2045 base64-encoded string from 'inbuf' into 'outbuf',
      where bufsize is the size of 'outbuf' (allocated by the caller).
      'inbuf' must be a NULL-terminated string.

      Returns number of bytes decoded into outbuf (0 <= n <= bufsize) or a
      negative number if an error occurred. See header file for error codes.

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
   const char *outbuf_start = outbuf;
   int v, i = 0, len = 0;
   unsigned char in[4];
   char c;

   if( !inbuf || !outbuf )
      return DECODE_BADARG;

   while( *inbuf ) {
      c = *inbuf++;
      if( mode & DECODE_MODE_WHITESPACE_OK ) {
         /* In relaxed mode, skip all whitespace anywhere in the input */
         if( ISSPACE(c) )
            continue;
      } else if( c == '\r' && *inbuf == '\n' ) {
         /* Otherwise allow only CRLF line breaks */
         inbuf++;
         continue;
      } else if( mode & DECODE_MODE_LF_BREAKS && c == '\n' ) {
         /* Also recognize LF line line breaks if requested */
         continue;
      }
      v = base64_char_to_6bit( c );
      assert( v >= -1 && v < 64 );
      if( v >= 0 ) {
         /* Valid character - save it */
         len++;
         in[i++] = (unsigned char)v;
      } else if( c == '=' && (len == 3 || (len == 2 && *inbuf == '=')) ) {
	 /* 2 or 3 valid characters followed by padding */
	 in[3] = 64;             /* Indicates "byte not used" */
	 if( len == 2 ) {
	    in[2] = 64;
	    inbuf++;
	 }
	 i = 4;
      } else {
	 /* Invalid character, decoding failed */
	 return DECODE_INVALID_CHAR;
      }
      assert( i > 0 && i <= 4 );
      assert( len > 0 && len <= 4 );
      if( i == 4 ) {
         /* Four sextets complete - decode & store result */
         assert( len >= 2 );
         len--;
         if( bufsize < (size_t)len )
            return DECODE_BUFFER_TOO_SMALL;
         base64_decodeblock( in, outbuf );
         outbuf += len;
         bufsize -= len;
         i = len = 0;
         if( (outbuf - outbuf_start) > INT_MAX )
            /* Protect against return value overflow */
            return DECODE_INPUT_TOO_LONG;
      }
   }
   if( len > 0 )
      /* Input ended while a sequence was open */
      return DECODE_MALFORMED_SEQUENCE;

   assert( outbuf >= outbuf_start );
   return outbuf - outbuf_start;
}

/* ------------------------------------------------------------------------ */
int base64_decode( const char* inbuf, char* outbuf, size_t bufsize )
{
   /* Convenience function for fully standards-conformant base64
      decoding */
   return base64_decode_mode( inbuf, outbuf, bufsize, DECODE_MODE_STRICT );
}
