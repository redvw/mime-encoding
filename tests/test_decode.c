/***************************************************************************
 *  Unit tests for base64 and quoted-printable decoders
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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <libgen.h>
#include <stdlib.h>
#include "decode.h"

#define bufsize 384
static int ntot = 0;

/* Example texts */
/* Antoine de Saint-Exupéry, Citadelle, LXXI, op. posthume, 1948 */
static const char *text1 =
   "J'interdis aux marchands de vanter trop leurs marchandises. Car ils se "
   "font vite pédagogues et t'enseignent comme but ce qui n'est par essence "
   "qu'un moyen, et te trompant ainsi sur la route à suivre les voilà "
   "bientôt qui te dégradent, car si leur musique est vulgaire ils te "
   "fabriquent pour te la vendre une âme vulgaire.\r\n";

static const unsigned char text2[] = {
   1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
   21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
   127, 128, 129, 130, 131, 132, 133, 134, 135, 136,
   137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150,
   151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
   165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178,
   179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192,
   193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206,
   207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
   221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234,
   235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248,
   249, 250, 251, 252, 253, 254, 255, 0 };

static const char *text3 =
   "Now's the time for all folk to come to the aid of their country.";

/* Decoded binary data */
static const unsigned char sequence[256] = {
   0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
   21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
   39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
   57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
   75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92,
   93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
   109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
   123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136,
   137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150,
   151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
   165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178,
   179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192,
   193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206,
   207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
   221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234,
   235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248,
   249, 250, 251, 252, 253, 254, 255 };

static const char* v123 = "123";
static const size_t l123 = sizeof("123");

/* Our testing "framework" ;) */
#define check_return( ret, expected )                                   \
   if( (ret) != (expected) ) {                                          \
      fprintf( stderr, "Test %d failed (return %d differs from "        \
               "expected %d) at line %d\n",                             \
               ntot, ret, expected, __LINE__ );                         \
   } else {                                                             \
      ngood++;                                                          \
   }                                                                    \
   ntot++;

#define check_return_greater( ret, num )                                \
   if( (ret) > (num) ) {                                                \
      ngood++;                                                          \
   } else {                                                             \
      fprintf( stderr, "Test %d failed at line %d\n", ntot, __LINE__ ); \
   }                                                                    \
   ntot++;

#define check_return_result( ret, expd, siz, nbytes, outbuf, value )    \
   if( (ret) != (expd) ) {                                              \
      fprintf( stderr, "Test %d failed (return %d differs from "        \
               "expected %d) at line %d\n",                             \
               ntot, ret, expd, __LINE__ );                             \
   } else if( (siz) != (nbytes) ) {                                     \
      fprintf( stderr, "Test %d failed (size %lu differs from "         \
               "expected %lu) at line %d\n",                            \
               ntot, (size_t)(siz), (size_t)(nbytes), __LINE__ );       \
   } else if( memcmp(outbuf, value, nbytes) != 0 ) {                    \
      fprintf( stderr, "Test %d failed "                                \
               "(output differs from expected value) at line %d\n",     \
               ntot, __LINE__ );                                        \
   } else {                                                             \
      ngood++;                                                          \
   }                                                                    \
   ntot++;

/* =================== quoted-printable tests =========================== */
static int test_quoted_printable()
{
   char outbuf[bufsize], *allocbuf;
   int ret, ngood = 0;
   size_t outlen;
   const char *input;

   /* Parameter validity */
   
   /* For checking whether the output buffer remains untouched */
   strcpy( outbuf, v123 );

   outlen = bufsize;
   ret = quoted_printable_decode( NULL, outbuf, &outlen );
   check_return_result( ret, DECODE_BADARG, outlen, 0, outbuf, outbuf );
   check_return_result( ret, DECODE_BADARG, l123, l123, outbuf, v123 );

   outlen = bufsize;
   ret = quoted_printable_decode( "foobar", NULL, &outlen );
   check_return_result( ret, DECODE_BADARG, outlen, 0, outbuf, outbuf );

   ret = quoted_printable_decode( "foobar", outbuf, NULL );
   check_return_result( ret, DECODE_BADARG, l123, l123, outbuf, v123 );

   /* Trivial inputs */
   outlen = bufsize;
   ret = quoted_printable_decode( "", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 0, outbuf, outbuf );
   check_return_result( ret, DECODE_SUCCESS, l123, l123, outbuf, v123 );

   outlen = bufsize;
   ret = quoted_printable_decode( "\r\n", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 2, outbuf, "\r\n" );

   outlen = bufsize;
   ret = quoted_printable_decode( "\n", outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "\n", outbuf, &outlen,
                                       DECODE_MODE_LF_BREAKS );
   check_return_result( ret, DECODE_SUCCESS, outlen, 1, outbuf, "\n" );

   /* Valid unencoded (literal) characters */
   input = " \t!\"#$%&'()*+,-./0123456789:;<>?@\r\n";
   outlen = bufsize;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(input), outbuf, input );

   ret = quoted_printable_decode_alloc( input, &allocbuf, &outlen,
      DECODE_MODE_STRICT );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(input), allocbuf, input );
   free(allocbuf);

   /* Split into two strings to stay within 76 character length limit */
   input = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";
   outlen = bufsize;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(input), outbuf, input );

   ret = quoted_printable_decode_alloc( input, &allocbuf, &outlen,
      DECODE_MODE_STRICT );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(input), allocbuf, input );
   free(allocbuf);

   /* Invalid characters */
   /* At least one character in text2 is invalid */
   outlen = bufsize;
   ret = quoted_printable_decode( (const char*)text2, outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 0, outbuf, outbuf );

   /* All characters in text2 are invalid */
   /* (text2 includes both \r and \n, but not as a \r\n pair) */
   outlen = bufsize;
   ret = quoted_printable_decode_mode( (const char*)text2, outbuf, &outlen,
      DECODE_MODE_INVALID_CHAR );
   check_return_result( ret, DECODE_SUCCESS, outlen, 0, outbuf, "" );

   /* Some characters are not invalid */
   outlen = bufsize;
   ret = quoted_printable_decode_mode( (const char*)text2, outbuf, &outlen,
      DECODE_MODE_ROBUST );
   check_return_result( ret, DECODE_SUCCESS, outlen, 1, outbuf, "\n" );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "Schöne Grüße", outbuf, &outlen,
      DECODE_MODE_ROBUST );
   check_return_result( ret, DECODE_SUCCESS, outlen, 9, outbuf, "Schne Gre" );

   /* Encoded characters */
   outlen = bufsize;
   ret = quoted_printable_decode( "=41", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 1, outbuf, "A" );

   outlen = bufsize;
   ret = quoted_printable_decode( "=41=42", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 2, outbuf, "AB" );

   outlen = bufsize;
   ret = quoted_printable_decode( "=61 =62", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 3, outbuf, "a b" );

   outlen = bufsize;
   input = "=C3=89=C3=96=C3=A8=C3=BF=C3=A5=C3=A7";
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 12, outbuf, "ÉÖèÿåç" );

   ret = quoted_printable_decode_alloc( input, &allocbuf, &outlen,
      DECODE_MODE_STRICT );
   check_return_result( ret, DECODE_SUCCESS, outlen, 12, allocbuf, "ÉÖèÿåç" );
   free(allocbuf);

   /* Malformed sequences */
   outlen = bufsize;
   ret = quoted_printable_decode( "=", outbuf, &outlen );
   check_return_result( ret, DECODE_MALFORMED_SEQUENCE, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = quoted_printable_decode( "=A", outbuf, &outlen );
   check_return_result( ret, DECODE_MALFORMED_SEQUENCE, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = quoted_printable_decode( "=9a", outbuf, &outlen );
   check_return_result( ret, DECODE_LOWERCASE_HEX, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "=9a", outbuf, &outlen,
      DECODE_MODE_LITERAL_EQ );
   check_return_result( ret, DECODE_LOWERCASE_HEX, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "=9a", outbuf, &outlen,
      DECODE_MODE_LC_HEX );
   check_return_result( ret, DECODE_SUCCESS, outlen, 1, outbuf, "\232" );

   outlen = bufsize;
   ret = quoted_printable_decode( "=HI", outbuf, &outlen );
   check_return_result( ret, DECODE_MALFORMED_SEQUENCE, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "=HI", outbuf, &outlen,
      DECODE_MODE_ROBUST );
   check_return_result( ret, DECODE_SUCCESS, outlen, 3, outbuf, "=HI" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc=", outbuf, &outlen );
   check_return_result( ret, DECODE_MALFORMED_SEQUENCE, outlen, 3, outbuf, "abc" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc=C3=D", outbuf, &outlen );
   check_return_result( ret, DECODE_MALFORMED_SEQUENCE, outlen, 4, outbuf, "abc\303" );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "abc=", outbuf, &outlen,
      DECODE_MODE_ROBUST );
   check_return_result( ret, DECODE_SUCCESS, outlen, 4, outbuf, "abc=" );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "abc=C3=D", outbuf, &outlen,
      DECODE_MODE_ROBUST );
   check_return_result( ret, DECODE_SUCCESS, outlen, 6, outbuf, "abc\303=D" );

   outlen = bufsize;
   ret = quoted_printable_decode( "=c3=89=c3=96=c3=a8=c3=bf=c3=a5=c3=a7",
                                  outbuf, &outlen );
   check_return_result( ret, DECODE_LOWERCASE_HEX, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "=c3=89=c3=96=c3=a8=c3=bf=c3=a5=c3=a7",
      outbuf, &outlen, DECODE_MODE_LC_HEX );
   check_return_result( ret, DECODE_SUCCESS, outlen, 12, outbuf, "ÉÖèÿåç" );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "=c3=89=c3=96=c3=a8=c3=bf=c3=a5=c3=a7",
      outbuf, &outlen, DECODE_MODE_LITERAL_EQ );
   check_return_result( ret, DECODE_LOWERCASE_HEX, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "=c3=89=c3=96=c3=a8=c3=bf=c3=a5=c3=a7",
      outbuf, &outlen, DECODE_MODE_ROBUST );
   check_return_result( ret, DECODE_SUCCESS, outlen, 12, outbuf, "ÉÖèÿåç" );

   /* Soft breaks */
   outlen = bufsize;
   ret = quoted_printable_decode( "abc=\r\ndef", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 6, outbuf, "abcdef" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc =\r\ndef", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 7, outbuf, "abc def" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc\t =\r\ndef", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 8, outbuf, "abc\t def" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc=\r\ndef=\r\n", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 6, outbuf, "abcdef" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc=\ndef=\n", outbuf, &outlen );
   check_return_result( ret, DECODE_MALFORMED_SEQUENCE, outlen, 3, outbuf, "abc" );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "abc=\ndef=\n", outbuf, &outlen,
      DECODE_MODE_LF_BREAKS );
   check_return_result( ret, DECODE_SUCCESS, outlen, 6, outbuf, "abcdef" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc=  \r\ndef", outbuf, &outlen );
   check_return_result( ret, DECODE_WHITESPACE_IN_SOFTBREAK, outlen, 3,
      outbuf, "abc" );

   outlen = bufsize;
   input = "abc=  \r\ndef";
   ret = quoted_printable_decode_mode( input, outbuf, &outlen,
      DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_SUCCESS, outlen, 6, outbuf, "abcdef" );

   ret = quoted_printable_decode_alloc( input, &allocbuf, &outlen,
      DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_SUCCESS, outlen, 6, allocbuf, "abcdef" );
   free(allocbuf);

   input = "Now's the time =\t\t  \r\n"
      "for all folk to come=\t\r\n"
      " to the aid of their country.";
   outlen = bufsize;
   ret = quoted_printable_decode_mode( input, outbuf, &outlen,
       DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(text3),
       outbuf, text3 );

   ret = quoted_printable_decode_alloc( input, &allocbuf, &outlen,
      DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(text3),
      allocbuf, text3 );
   free(allocbuf);

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "abc=  ", outbuf, &outlen,
      DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_MALFORMED_SEQUENCE, outlen, 3,
      outbuf, "abc" );

   /* Space padding deletion */
   outlen = bufsize;
   ret = quoted_printable_decode( " ", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 0, outbuf, "" );

   outlen = bufsize;
   ret = quoted_printable_decode( "    \t  ", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 0, outbuf, "" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc   ", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 3, outbuf, "abc" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc=20=20=20", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 6, outbuf, "abc   " );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc   \r\n", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 5, outbuf, "abc\r\n" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc=20=20=20\r\n", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 8, outbuf, "abc   \r\n" );

   outlen = bufsize;
   ret = quoted_printable_decode( "abc   \r\n def ghi \t \r\n",
      outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 15, outbuf,
      "abc\r\n def ghi\r\n" );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( "abc   \n def ghi \t \n",
      outbuf, &outlen, DECODE_MODE_LF_BREAKS );
   check_return_result( ret, DECODE_SUCCESS, outlen, 13, outbuf,
      "abc\n def ghi\n" );

   /* Encoded binary blob */
   input = "=00=01=02"
      "=03=04=05=06=07=08=09=0A=0B=0C=0D=0E=0F=10=11=12=13=14=15=16=17=18=\r\n"
      "=19=1A=1B=1C=1D=1E=1F=20=21=22=23=24=25=26=27=28=29=2A=2B=2C=2D=2E=\r\n"
      "=2F=30=31=32=33=34=35=36=37=38=39=3A=3B=3C=3D=3E=3F=40=41=42=43=44=\r\n"
      "=45=46=47=48=49=4A=4B=4C=4D=4E=4F=50=51=52=53=54=55=56=57=58=59=5A=\r\n"
      "=5B=5C=5D=5E=5F=60=61=62=63=64=65=66=67=68=69=6A=6B=6C=6D=6E=6F=70=\r\n"
      "=71=72=73=74=75=76=77=78=79=7A=7B=7C=7D=7E=7F=80=81=82=83=84=85=86=\r\n"
      "=87=88=89=8A=8B=8C=8D=8E=8F=90=91=92=93=94=95=96=97=98=99=9A=9B=9C=\r\n"
      "=9D=9E=9F=A0=A1=A2=A3=A4=A5=A6=A7=A8=A9=AA=AB=AC=AD=AE=AF=B0=B1=B2=\r\n"
      "=B3=B4=B5=B6=B7=B8=B9=BA=BB=BC=BD=BE=BF=C0=C1=C2=C3=C4=C5=C6=C7=C8=\r\n"
      "=C9=CA=CB=CC=CD=CE=CF=D0=D1=D2=D3=D4=D5=D6=D7=D8=D9=DA=DB=DC=DD=DE=\r\n"
      "=DF=E0=E1=E2=E3=E4=E5=E6=E7=E8=E9=EA=EB=EC=ED=EE=EF=F0=F1=F2=F3=F4=\r\n"
      "=F5=F6=F7=F8=F9=FA=FB=FC=FD=FE=FF";
   outlen = bufsize;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, outbuf, sequence );

   ret = quoted_printable_decode_alloc( input, &allocbuf, &outlen,
      DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, allocbuf, sequence );
   free(allocbuf);

   /* Encoded text passages */
   input =
"J'interdis aux marchands de vanter trop leurs marchandises. Car ils se font=\r\n"
" vite p=C3=A9dagogues et t'enseignent comme but ce qui n'est par essence qu=\r\n"
"'un moyen, et te trompant ainsi sur la route =C3=A0 suivre les voil=C3=A0 b=\r\n"
"ient=C3=B4t qui te d=C3=A9gradent, car si leur musique est vulgaire ils te =\r\n"
"fabriquent pour te la vendre une =C3=A2me vulgaire.\r\n";
   outlen = bufsize;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(text1), outbuf, text1 );

   ret = quoted_printable_decode_alloc( input, &allocbuf, &outlen,
      DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(text1), allocbuf, text1 );
   free(allocbuf);

   /* Line length */
   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font=\r\n";
   outlen = bufsize;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 75, outbuf,
      "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font" );

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se  font\r\n";
   outlen = bufsize;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 78, outbuf, input )

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se  font \r\n";
   outlen = bufsize;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_LINE_TOO_LONG, outlen, 76, outbuf, input );

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font v\r\n";
   outlen = bufsize;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_LINE_TOO_LONG, outlen, 76, outbuf, input );

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font =\r\n";
   outlen = bufsize;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_LINE_TOO_LONG, outlen, 76, outbuf, input );

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font =\r\n";
   outlen = bufsize;
   ret = quoted_printable_decode_mode( input, outbuf, &outlen,
      DECODE_MODE_LONG_LINES );
   check_return_result( ret, DECODE_SUCCESS, outlen, 76, outbuf,
      "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font " );

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font=20";
   outlen = bufsize;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_LINE_TOO_LONG, outlen, 75, outbuf, input );

   /* Buffer length */
   input = "J'interdis aux marchands de vanter trop leurs marchandises";
   outlen = 58;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 58, outbuf,
      "J'interdis aux marchands de vanter trop leurs marchandises" );

   input = "J'interdis aux marchands de vanter trop leurs marchandises.";
   outlen = 58;
   ret = quoted_printable_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_BUFFER_TOO_SMALL, outlen, 58, outbuf, input );

   /* "Encoded words */
   input = "Keith_Moore";
   outlen = bufsize;
   ret = quoted_printable_word_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(input), outbuf,
      "Keith Moore" );

   input = "Keld_J=F8rn_Simonsen";
   outlen = bufsize;
   ret = quoted_printable_word_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(input)-2, outbuf,
      "Keld J\370rn Simonsen" );

   input = "Patrik_F=E4ltstr=F6m";
   outlen = bufsize;
   ret = quoted_printable_word_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(input)-4, outbuf,
      "Patrik F\344ltstr\366m" );

   /* "encoded word" mode allows lowercase hex by default */
   input = "Verschl=c3=bcsselte_Nachricht";
   outlen = bufsize;
   ret = quoted_printable_word_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(input)-4, outbuf,
      "Verschlüsselte Nachricht" );

   /* encoded words may not contain whitespace */
   input = "Verschl=c3=bcsselte Nachricht";
   outlen = bufsize;
   ret = quoted_printable_word_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 15, outbuf,
      "Verschlüsselte" );

   /* Encoded control characters OK, even in "word" mode */
   input = "Ver=0Dschl=c3=bcsselte_Nachricht=0D=0A";
   outlen = bufsize;
   ret = quoted_printable_word_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(input)-10, outbuf,
      "Ver\rschlüsselte Nachricht\r\n" );

   ret = quoted_printable_decode_alloc( input, &allocbuf, &outlen,
      DECODE_MODE_ENCODEDWORD | DECODE_MODE_LC_HEX );
   check_return_result( ret, DECODE_SUCCESS, outlen, strlen(input)-10,
      allocbuf, "Ver\rschlüsselte Nachricht\r\n" );
   free(allocbuf);

   /* Question mark illegal in word mode. Skip with DECODE_MODE_INVALID_CHAR */
   input = "Really=3F?=20Yes!";
   outlen = bufsize;
   ret = quoted_printable_word_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 7, outbuf,
      "Really?" );

   outlen = bufsize;
   ret = quoted_printable_decode_mode( input, outbuf, &outlen,
      DECODE_MODE_ENCODEDWORD | DECODE_MODE_INVALID_CHAR );
   check_return_result( ret, DECODE_SUCCESS, outlen, 12, outbuf,
      "Really? Yes!" );

   return ngood;
}

/* ========================= base64 tests================================ */
static int test_base64()
{
   char outbuf[bufsize], *allocbuf;
   int ret, ngood = 0;
   const char *input;
   size_t outlen;

   /* Parameter validity */
   outlen = bufsize;
   ret = base64_decode( NULL, outbuf, &outlen );
   check_return( ret, DECODE_BADARG );

   outlen = bufsize;
   ret = base64_decode( "", NULL, &outlen );
   check_return( ret, DECODE_BADARG );

   /* For checking whether the output buffer remains untouched */
   strcpy( outbuf, v123 );

   /* Trivial inputs */
   outlen = bufsize;
   ret = base64_decode( "", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, l123, l123, outbuf, v123 );

   /* Accepting CRLF line breaks must be explicitly requested */
   outlen = bufsize;
   ret = base64_decode_mode( "\r\n", outbuf, &outlen, DECODE_MODE_CRLF_BREAKS );
   check_return_result( ret, DECODE_SUCCESS, l123, l123, outbuf, v123 );

   outlen = bufsize;
   ret = base64_decode( "\r\n", outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, l123, l123, outbuf, v123 );

   /* Whitespace OK in relaxed mode only */
   outlen = bufsize;
   ret = base64_decode( " ", outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, l123, l123, outbuf, v123 );

   outlen = bufsize;
   ret = base64_decode_mode( " ", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, l123, l123, outbuf, v123 );

   outlen = bufsize;
   ret = base64_decode_mode( "\n", outbuf, &outlen, DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_SUCCESS, l123, l123, outbuf, v123 );

   outlen = bufsize;
   ret = base64_decode_mode( "\n", outbuf, &outlen, DECODE_MODE_LF_BREAKS );
   check_return_result( ret, DECODE_SUCCESS, l123, l123, outbuf, v123 );

   outlen = bufsize;
   ret = base64_decode_mode( "    \t  ", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, l123, l123, outbuf, v123 );

   outlen = bufsize;
   ret = base64_decode_mode( "   \t\n\t  \r\n\t", outbuf, &outlen,
                             DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, l123, l123, outbuf, v123 );

   /* Basic decoding: RFC 4648 test vectors */
   outlen = bufsize;
   ret = base64_decode( "Zg==", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 1, outbuf, "f" );

   outlen = bufsize;
   ret = base64_decode( "Zm8=", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 2, outbuf, "fo" );

   outlen = bufsize;
   ret = base64_decode( "Zm9v", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 3, outbuf, "foo" );

   outlen = bufsize;
   ret = base64_decode( "Zm9vYg==", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 4, outbuf, "foob" );

   outlen = bufsize;
   ret = base64_decode( "Zm9vYmE=", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 5, outbuf, "fooba" );

   outlen = bufsize;
   ret = base64_decode( "Zm9vYmFy", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 6, outbuf, "foobar" );

   ret = base64_decode_alloc( "Zm9vYmFy", &allocbuf, &outlen, DECODE_MODE_STRICT );
   check_return_result( ret, DECODE_SUCCESS, outlen, 6, outbuf, "foobar" );
   free(allocbuf);

   /* Stop decoding at NULL (success) */
   outlen = bufsize;
   ret = base64_decode( "QQ==\0QUJD", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 1, outbuf, "A" );

   /* Embedded whitespace in relaxed mode (success) */
   outlen = bufsize;
   ret = base64_decode_mode( "QU JD", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, outlen, 3, outbuf, "ABC" );

   outlen = bufsize;
   ret = base64_decode_mode( "QU J  D \n ", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, outlen, 3, outbuf, "ABC" );

   outlen = bufsize;
   ret = base64_decode_mode( "QU\nJD", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, outlen, 3, outbuf, "ABC" );

   /* Invalid characters (failures) */
   outlen = bufsize;
   ret = base64_decode( "Q@JD", outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = base64_decode( "QUJD*", outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 3, outbuf, "ABC" );

   /* Leading and trailing whitespace (failure/sucess) */
   outlen = bufsize;
   ret = base64_decode( "QQ== ", outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 1, outbuf, "A" );

   outlen = bufsize;
   ret = base64_decode( "QUI= ", outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 2, outbuf, "AB");

   outlen = bufsize;
   ret = base64_decode( "\tQUI= \n   ", outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = base64_decode( "QUJD    ", outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 3, outbuf, "ABC"  );

   outlen = bufsize;
   ret = base64_decode( "\tQUJD", outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 0, outbuf, outbuf );

   outlen = bufsize;
   ret = base64_decode_mode( "QQ== ", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, outlen, 1, outbuf, "A" );

   outlen = bufsize;
   ret = base64_decode_mode( "QUI= ", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, outlen, 2, outbuf, "AB" );

   outlen = bufsize;
   ret = base64_decode_mode( "\tQUI= \n   ", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, outlen, 2, outbuf, "AB" );

   outlen = bufsize;
   ret = base64_decode_mode( "QUJD    ", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, outlen, 3, outbuf, "ABC" );

   outlen = bufsize;
   ret = base64_decode_mode( "\tQUJD", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, outlen, 3, outbuf, "ABC" );

   /* Split sequence (successes, though not clearly defined in standard) */
   outlen = bufsize;
   ret = base64_decode( "QUI=QUJD", outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 5, outbuf, "ABABC" );

   outlen = bufsize;
   ret = base64_decode_mode( "QUI=  QUJD", outbuf, &outlen, DECODE_MODE_RELAXED );
   check_return_result( ret, DECODE_SUCCESS, outlen, 5, outbuf, "ABABC" );

   /* Trailing garbage/incomplete sequences (failures) */
   outlen = bufsize;
   ret = base64_decode( "QQ==A", outbuf, &outlen );
   check_return_result( ret, DECODE_MALFORMED_SEQUENCE, outlen, 1, outbuf, "A" );

   outlen = bufsize;
   ret = base64_decode( "QUI=A", outbuf, &outlen );
   check_return_result( ret, DECODE_MALFORMED_SEQUENCE, outlen, 2, outbuf, "AB" );

   outlen = bufsize;
   ret = base64_decode( "QUJDA", outbuf, &outlen );
   check_return_result( ret, DECODE_MALFORMED_SEQUENCE, outlen, 3, outbuf, "ABC" );

   /* Decoding a sequence of all characters from 0x00 to 0xFF (success) */
   input =
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj"
      "JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH"
      "SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWpr"
      "bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P"
      "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKz"
      "tLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX"
      "2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7"
      "/P3+/w==";
   outlen = 256;
   ret = base64_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, outbuf, sequence );

   /* Output buffer size test checks (including edge cases) */
   outlen = 255;
   ret = base64_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_BUFFER_TOO_SMALL, outlen, 255, outbuf, sequence );

   outlen = 254;
   ret = base64_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_BUFFER_TOO_SMALL, outlen, 252, outbuf, sequence );

   outlen = 2;
   ret = base64_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_BUFFER_TOO_SMALL, outlen, 0, outbuf, sequence );

   ret = base64_decode_alloc( input, &allocbuf, &outlen, DECODE_MODE_STRICT );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, allocbuf, sequence );
   free(allocbuf);

   /* Decoding sequence of all characters from 0x00 to 0xFF
      with embedded line breaks */
   input =
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\r\n"
      "JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH\r\n"
      "SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWpr\r\n"
      "bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\r\n"
      "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKz\r\n"
      "tLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX\r\n"
      "2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7\r\n"
      "/P3+/w==";
   outlen = bufsize;
   ret = base64_decode_mode( input, outbuf, &outlen, DECODE_MODE_CRLF_BREAKS );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, outbuf, sequence );

   ret = base64_decode_alloc( input, &allocbuf, &outlen, DECODE_MODE_CRLF_BREAKS );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, allocbuf, sequence );
   free(allocbuf);

   input =
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\r\n"
      "JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH\r\n"
      "SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWpr\r\n"
      "bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\r\n"
      "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKz\r\n"
      "tLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX\r\n"
      "2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7\r\n"
      "/P3+/w==\r\n";
   outlen = bufsize;
   ret = base64_decode_mode( input, outbuf, &outlen, DECODE_MODE_CRLF_BREAKS );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, outbuf, sequence );

   input =
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\r\n"
      "JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH\r\n"
      "SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWpr\r\n"
      "bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\r\n"
      "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKz\r\n\r\n"
      "tLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX\r\n"
      "2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7\r\n"
      "/P3+/w==";
   outlen = bufsize;
   ret = base64_decode_mode( input, outbuf, &outlen, DECODE_MODE_CRLF_BREAKS );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, outbuf, sequence );

   input =
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\r\n"
      "JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH\n"
      "SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWpr\r\n"
      "bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\r\n"
      "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKz\r\n"
      "tLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX\r\n"
      "2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7\r\n"
      "/P3+/w==";
   outlen = bufsize;
   ret = base64_decode_mode( input, outbuf, &outlen, DECODE_MODE_CRLF_BREAKS );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 72, outbuf, sequence );

   outlen = bufsize;
   ret = base64_decode_mode( input, outbuf, &outlen,
      DECODE_MODE_CRLF_BREAKS | DECODE_MODE_LF_BREAKS );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, outbuf, sequence );

   outlen = bufsize;
   ret = base64_decode_mode( input, outbuf, &outlen, DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, outbuf, sequence );

   input =
      "  AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\n"
      "  JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH\n"
      "  SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWpr\n"
      "  bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\n"
      "  kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKz\r\n"
      "  tLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX\n"
      " 2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7\n"
      "  /P3+/w==";
   outlen = bufsize;
   ret = base64_decode( input, outbuf, &outlen );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 0, outbuf, sequence );

   outlen = bufsize;
   ret = base64_decode_mode( input, outbuf, &outlen,
      DECODE_MODE_CRLF_BREAKS | DECODE_MODE_LF_BREAKS );
   check_return_result( ret, DECODE_INVALID_CHAR, outlen, 0, outbuf, sequence );

   outlen = bufsize;
   ret = base64_decode_mode( input, outbuf, &outlen, DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, outbuf, sequence );

   ret = base64_decode_alloc( input, &allocbuf, &outlen, DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, DECODE_SUCCESS, outlen, 256, allocbuf, sequence );
   free(allocbuf);

   return ngood;
}

/* ========================= perror tests================================ */
static int test_perror()
{
   size_t ret, ngood = 0;
   const char *msg, *str;

   /* Error messages */
   str = "Success";
   ret = strlen( msg = decode_perror(0) );
   check_return_result( 1, 1, ret+1, strlen(str)+1, msg, str );

   str = "Bad function argument";
   ret = strlen( msg = decode_perror( DECODE_BADARG ) );
   check_return_result( 1, 1, ret+1, strlen(str)+1, msg, str );

   str = "Cannot allocate buffer";
   ret = strlen( msg = decode_perror( DECODE_BADALLOC ) );
   check_return_result( 1, 1, ret+1, strlen(str)+1, msg, str );

   str = "Invalid character in input";
   ret = strlen( msg = decode_perror( DECODE_INVALID_CHAR ) );
   check_return_result( 1, 1, ret+1, strlen(str)+1, msg, str );

   str = "Invalid sequence of characters in input";
   ret = strlen( msg = decode_perror( DECODE_MALFORMED_SEQUENCE ) );
   check_return_result( 1, 1, ret+1, strlen(str)+1, msg, str );

   str = "Output buffer size too small";
   ret = strlen( msg = decode_perror( DECODE_BUFFER_TOO_SMALL ) );
   check_return_result( 1, 1, ret+1, strlen(str)+1, msg, str );

   str = "Lowercase hex character following '='";
   ret = strlen( msg = decode_perror( DECODE_LOWERCASE_HEX ) );
   check_return_result( 1, 1, ret+1, strlen(str)+1, msg, str );

   str = "Quoted-printable line longer than 76 characters";
   ret = strlen( msg = decode_perror( DECODE_LINE_TOO_LONG ) );
   check_return_result( 1, 1, ret+1, strlen(str)+1, msg, str );

   str = "Quoted-printable softbreak padded with whitespace";
   ret = strlen( msg = decode_perror( DECODE_WHITESPACE_IN_SOFTBREAK ) );
   check_return_result( 1, 1, ret+1, strlen(str)+1, msg, str );

   str = "Unknown return code";
   ret = strlen( msg = decode_perror(255) );
   check_return_result( 1, 1, ret+1, strlen(str)+1, msg, str );

   return ngood;
}

int main( int argc, char* argv[] )
{
   int ngood = 0;
   const char* prog = basename(argv[0]);
   (void)argc;

   ngood += test_quoted_printable();
   ngood += test_base64();
   ngood += test_perror();

   assert( ngood <= ntot );
   if( ngood < ntot ) {
      printf("%s: %d out of %d tests FAILED\n", prog, ntot-ngood, ntot);
      return 1;
   } else
      printf("%s: All %d tests succeeded\n", prog, ntot);

   return 0;
}
