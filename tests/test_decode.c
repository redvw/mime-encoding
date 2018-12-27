/***************************************************************************
 *  Unit tests for base64 and quoted-printable decoders
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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <libgen.h>
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
static const int l123 = sizeof("123");

/* Our testing "framework" ;) */
#define check_return( ret, expected )                                   \
   if( ret != expected ) {                                              \
      if( ret < 0 ) {                                                   \
         fprintf( stderr, "Test %d failed with code %d (\"%s\") "       \
             "at line %d\n", ntot, ret, decode_perror(ret), __LINE__ ); \
      } else {                                                          \
         fprintf( stderr, "Test %d failed (return %d differs from "     \
                  "expected %d) at line %d\n",                          \
                  ntot, ret, expected, __LINE__ );                      \
      }                                                                 \
   } else {                                                             \
      ngood++;                                                          \
   }                                                                    \
   ntot++;

#define check_return_greater( ret, num )                                \
   if( ret > num ) {                                                    \
      ngood++;                                                          \
   } else {                                                             \
      fprintf( stderr, "Test %d failed at line %d\n", ntot, __LINE__ ); \
   }                                                                    \
   ntot++;

#define check_return_result( ret, nbytes, outbuf, value )               \
   if( ret != nbytes ) {                                                \
      if( ret < 0 ) {                                                   \
         fprintf( stderr, "Test %d failed with code %d (\"%s\") "       \
             "at line %d\n", ntot, ret, decode_perror(ret), __LINE__ ); \
      } else {                                                          \
         fprintf( stderr, "Test %d failed (return %d differs from "     \
                  "expected %d) at line %d\n",                          \
                  ntot, ret, nbytes, __LINE__ );                        \
      }                                                                 \
   } else if( memcmp(outbuf, value, nbytes) != 0 ) {                    \
      fprintf( stderr, "Test %d failed (output differs from expected "  \
               "value) at line %d\n", ntot, __LINE__ );                 \
   } else {                                                             \
      ngood++;                                                          \
   }                                                                    \
   ntot++;

/* =================== quoted-printable tests =========================== */
static int test_quoted_printable()
{
   char outbuf[bufsize];
   int ret, ngood = 0;
   const char *input;

   /* Parameter validity */
   ret = quoted_printable_decode( NULL, outbuf, bufsize );
   check_return( ret, DECODE_BADARG );

   ret = quoted_printable_decode( "", NULL, bufsize );
   check_return( ret, DECODE_BADARG );

   /* For checking whether the output buffer remains untouched */
   strcpy( outbuf, v123 );

   /* Trivial inputs */
   ret = quoted_printable_decode( "", outbuf, bufsize );
   check_return( ret, 0 );
   check_return_result( l123, l123, outbuf, v123 );

   ret = quoted_printable_decode( "\r\n", outbuf, bufsize );
   check_return_result( ret, 2, outbuf, "\r\n" );

   ret = quoted_printable_decode( "\n", outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   ret = quoted_printable_decode_mode( "\n", outbuf, bufsize,
                                       DECODE_MODE_LF_BREAKS );
   check_return_result( ret, 1, outbuf, "\n" );

   /* Valid unencoded (literal) characters */
   input = " \t!\"#$%&'()*+,-./0123456789:;<>?@";
   ret = quoted_printable_decode( input, outbuf, bufsize );
   check_return_result( ret, (int)strlen(input), outbuf, input );

   input = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";
   ret = quoted_printable_decode( input, outbuf, bufsize );
   check_return_result( ret, (int)strlen(input), outbuf, input );

   ret = quoted_printable_decode( "ab cd", outbuf, bufsize );
   check_return_result( ret, 5, outbuf, "ab cd" );

   /* Invalid characters */
   /* At least one character in text2 is invalid */
   ret = quoted_printable_decode( (const char*)text2, outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   /* All characters in text2 are invalid */
   /* (text2 includes both \r and \n, but not as a \r\n pair) */
   ret = quoted_printable_decode_mode( (const char*)text2, outbuf, bufsize,
      DECODE_MODE_INVALID_CHAR );
   check_return_result( ret, 0, outbuf, "" );

   /* Some characters are not invalid */
   ret = quoted_printable_decode_mode( (const char*)text2, outbuf, bufsize,
      DECODE_MODE_ROBUST );
   check_return_result( ret, 1, outbuf, "\n" );

   ret = quoted_printable_decode_mode( "Schöne Grüße", outbuf, bufsize,
      DECODE_MODE_ROBUST );
   check_return_result( ret, 9, outbuf, "Schne Gre" );

   /* Encoded characters */
   ret = quoted_printable_decode( "=41", outbuf, bufsize );
   check_return_result( ret, 1, outbuf, "A" );

   ret = quoted_printable_decode( "=41=42", outbuf, bufsize );
   check_return_result( ret, 2, outbuf, "AB" );

   ret = quoted_printable_decode( "=61 =62", outbuf, bufsize );
   check_return_result( ret, 3, outbuf, "a b" );

   ret = quoted_printable_decode( "=C3=89=C3=96=C3=A8=C3=BF=C3=A5=C3=A7",
                                  outbuf, bufsize );
   check_return_result( ret, 12, outbuf, "ÉÖèÿåç" );

   /* Malformed sequences */
   ret = quoted_printable_decode( "=", outbuf, bufsize );
   check_return( ret, DECODE_MALFORMED_SEQUENCE );

   ret = quoted_printable_decode( "=A", outbuf, bufsize );
   check_return( ret, DECODE_MALFORMED_SEQUENCE );

   ret = quoted_printable_decode( "=9a", outbuf, bufsize );
   check_return( ret, DECODE_LOWERCASE_HEX );

   ret = quoted_printable_decode_mode( "=9a", outbuf, bufsize,
      DECODE_MODE_LITERAL_EQ );
   check_return( ret, DECODE_LOWERCASE_HEX);

   ret = quoted_printable_decode_mode( "=9a", outbuf, bufsize,
      DECODE_MODE_LC_HEX );
   check_return_result( ret, 1, outbuf, "\232" );

   ret = quoted_printable_decode( "=HI", outbuf, bufsize );
   check_return( ret, DECODE_MALFORMED_SEQUENCE );

   ret = quoted_printable_decode_mode( "=HI", outbuf, bufsize,
      DECODE_MODE_ROBUST );
   check_return_result( ret, 3, outbuf, "=HI" );

   ret = quoted_printable_decode( "abc=", outbuf, bufsize );
   check_return( ret, DECODE_MALFORMED_SEQUENCE );

   ret = quoted_printable_decode( "abc=C3=D", outbuf, bufsize );
   check_return( ret, DECODE_MALFORMED_SEQUENCE );

   ret = quoted_printable_decode_mode( "abc=", outbuf, bufsize,
      DECODE_MODE_ROBUST );
   check_return_result( ret, 4, outbuf, "abc=" );

   ret = quoted_printable_decode_mode( "abc=C3=D", outbuf, bufsize,
      DECODE_MODE_ROBUST );
   check_return_result( ret, 6, outbuf, "abc\303=D" );

   ret = quoted_printable_decode( "=c3=89=c3=96=c3=a8=c3=bf=c3=a5=c3=a7",
                                  outbuf, bufsize );
   check_return( ret, DECODE_LOWERCASE_HEX );

   ret = quoted_printable_decode_mode( "=c3=89=c3=96=c3=a8=c3=bf=c3=a5=c3=a7",
      outbuf, bufsize, DECODE_MODE_LC_HEX );
   check_return_result( ret, 12, outbuf, "ÉÖèÿåç" );

   ret = quoted_printable_decode_mode( "=c3=89=c3=96=c3=a8=c3=bf=c3=a5=c3=a7",
      outbuf, bufsize, DECODE_MODE_LITERAL_EQ );
   check_return( ret, DECODE_LOWERCASE_HEX );

   ret = quoted_printable_decode_mode( "=c3=89=c3=96=c3=a8=c3=bf=c3=a5=c3=a7",
      outbuf, bufsize, DECODE_MODE_ROBUST );
   check_return_result( ret, 12, outbuf, "ÉÖèÿåç" );

   /* Soft breaks */
   ret = quoted_printable_decode( "abc=\r\ndef", outbuf, bufsize );
   check_return_result( ret, 6, outbuf, "abcdef" );

   ret = quoted_printable_decode( "abc =\r\ndef", outbuf, bufsize );
   check_return_result( ret, 7, outbuf, "abc def" );

   ret = quoted_printable_decode( "abc\t =\r\ndef", outbuf, bufsize );
   check_return_result( ret, 8, outbuf, "abc\t def" );

   ret = quoted_printable_decode( "abc=\r\ndef=\r\n", outbuf, bufsize );
   check_return_result( ret, 6, outbuf, "abcdef" );

   ret = quoted_printable_decode( "abc=\ndef=\n", outbuf, bufsize );
   check_return( ret, DECODE_MALFORMED_SEQUENCE );

   ret = quoted_printable_decode_mode( "abc=\ndef=\n", outbuf, bufsize,
      DECODE_MODE_LF_BREAKS );
   check_return_result( ret, 6, outbuf, "abcdef" );

   ret = quoted_printable_decode( "abc=  \r\ndef", outbuf, bufsize );
   check_return( ret, DECODE_WHITESPACE_IN_SOFTBREAK );

   ret = quoted_printable_decode_mode( "abc=  \r\ndef", outbuf, bufsize,
      DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, 6, outbuf, "abcdef" );

   input = "Now's the time =\t\t  \r\n"
      "for all folk to come=\t\r\n"
      " to the aid of their country.";
   ret = quoted_printable_decode_mode( input, outbuf, bufsize,
       DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, 64, outbuf,
       "Now's the time for all folk to come to the aid of their country." );

   ret = quoted_printable_decode_mode( "abc=  ", outbuf, bufsize,
      DECODE_MODE_WHITESPACE_OK );
   check_return( ret, DECODE_MALFORMED_SEQUENCE );

   /* Space padding deletion */
   ret = quoted_printable_decode( " ", outbuf, bufsize );
   check_return_result( ret, 0, outbuf, "" );

   ret = quoted_printable_decode( "    \t  ", outbuf, bufsize );
   check_return_result( ret, 0, outbuf, "" );

   ret = quoted_printable_decode( "abc   ", outbuf, bufsize );
   check_return_result( ret, 3, outbuf, "abc" );

   ret = quoted_printable_decode( "abc=20=20=20", outbuf, bufsize );
   check_return_result( ret, 6, outbuf, "abc   " );

   ret = quoted_printable_decode( "abc   \r\n", outbuf, bufsize );
   check_return_result( ret, 5, outbuf, "abc\r\n" );

   ret = quoted_printable_decode( "abc=20=20=20\r\n", outbuf, bufsize );
   check_return_result( ret, 8, outbuf, "abc   \r\n" );

   ret = quoted_printable_decode( "abc   \r\n def ghi \t \r\n",
      outbuf, bufsize );
   check_return_result( ret, 15, outbuf, "abc\r\n def ghi\r\n" );

   ret = quoted_printable_decode_mode( "abc   \n def ghi \t \n",
      outbuf, bufsize, DECODE_MODE_LF_BREAKS );
   check_return_result( ret, 13, outbuf, "abc\n def ghi\n" );

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
   ret = quoted_printable_decode( input, outbuf, bufsize );
   check_return_result( ret, 256, outbuf, sequence );

   /* Encoded text passages */
   input =
"J'interdis aux marchands de vanter trop leurs marchandises. Car ils se font=\r\n"
" vite p=C3=A9dagogues et t'enseignent comme but ce qui n'est par essence qu=\r\n"
"'un moyen, et te trompant ainsi sur la route =C3=A0 suivre les voil=C3=A0 b=\r\n"
"ient=C3=B4t qui te d=C3=A9gradent, car si leur musique est vulgaire ils te =\r\n"
"fabriquent pour te la vendre une =C3=A2me vulgaire.\r\n";
   ret = quoted_printable_decode( input, outbuf, bufsize );
   check_return_result( ret, (int)strlen(text1), outbuf, text1 );

   /* Line length */
   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font=\r\n";
   ret = quoted_printable_decode( input, outbuf, bufsize );
   check_return_result( ret, 75, outbuf,
      "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font" );

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se  font\r\n";
   ret = quoted_printable_decode( input, outbuf, bufsize );
   check_return_result( ret, 78, outbuf, input )

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se  font \r\n";
   ret = quoted_printable_decode( input, outbuf, bufsize );
   check_return( ret, DECODE_LINE_TOO_LONG );

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font v\r\n";
   ret = quoted_printable_decode( input, outbuf, bufsize );
   check_return( ret, DECODE_LINE_TOO_LONG );

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font =\r\n";
   ret = quoted_printable_decode( input, outbuf, bufsize );
   check_return( ret, DECODE_LINE_TOO_LONG );

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font =\r\n";
   ret = quoted_printable_decode_mode( input, outbuf, bufsize,
      DECODE_MODE_LONG_LINES );
   check_return_result( ret, 76, outbuf,
      "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font " );

   input = "J'interdis aux marchands de vanter trop leurs marchandises. "
      "Car ils se font=20";
   ret = quoted_printable_decode( input, outbuf, bufsize );
   check_return( ret, DECODE_LINE_TOO_LONG );

   /* Buffer length */
   input = "J'interdis aux marchands de vanter trop leurs marchandises";
   ret = quoted_printable_decode( input, outbuf, 58 );
   check_return_result( ret, 58, outbuf,
      "J'interdis aux marchands de vanter trop leurs marchandises" );

   input = "J'interdis aux marchands de vanter trop leurs marchandises.";
   ret = quoted_printable_decode( input, outbuf, 58 );
   check_return( ret, DECODE_BUFFER_TOO_SMALL );

   /* "Encoded words */
   input = "Keith_Moore";
   ret = quoted_printable_word_decode( input, outbuf, bufsize );
   check_return_result( ret, (int)strlen(input), outbuf, "Keith Moore" );

   input = "Keld_J=F8rn_Simonsen";
   ret = quoted_printable_word_decode( input, outbuf, bufsize );
   check_return_result( ret, (int)strlen(input)-2, outbuf,
      "Keld J\370rn Simonsen" );

   input = "Patrik_F=E4ltstr=F6m";
   ret = quoted_printable_word_decode( input, outbuf, bufsize );
   check_return_result( ret, (int)strlen(input)-4, outbuf,
      "Patrik F\344ltstr\366m" );

   /* "encoded word" mode uses relaxed rules by default */
   input = "Verschl=c3=bcsselte_Nachricht";
   ret = quoted_printable_word_decode( input, outbuf, bufsize );
   check_return_result( ret, (int)strlen(input)-4, outbuf,
      "Verschlüsselte Nachricht" );

   /* Encoded control characters OK, even in "word" mode */
   input = "Ver=0Dschl=c3=bcsselte_Nachricht=0D=0A";
   ret = quoted_printable_word_decode( input, outbuf, bufsize );
   check_return_result( ret, (int)strlen(input)-10, outbuf,
      "Ver\rschlüsselte Nachricht\r\n" );

   /* Question mark illegal in word mode unless overridden */
   input = "Really?";
   ret = quoted_printable_word_decode( input, outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   ret = quoted_printable_decode_mode( input, outbuf, bufsize,
      DECODE_MODE_ENCODEDWORD | DECODE_MODE_INVALID_CHAR );
   check_return_result( ret, (int)strlen(input), outbuf, input );

   return ngood;
}

/* ========================= base64 tests================================ */
static int test_base64()
{
   char outbuf[bufsize];
   int ret, ngood = 0;
   const char *input;

   /* Parameter validity */
   ret = base64_decode( NULL, outbuf, bufsize );
   check_return( ret, DECODE_BADARG );

   ret = base64_decode( "", NULL, bufsize );
   check_return( ret, DECODE_BADARG );

   /* For checking whether the output buffer remains untouched */
   strcpy( outbuf, v123 );

   /* Trivial inputs */
   ret = base64_decode( "", outbuf, bufsize );
   check_return( ret, 0 );
   check_return_result( l123, l123, outbuf, v123 );

   ret = base64_decode( "\r\n", outbuf, bufsize );
   check_return( ret, 0 );
   check_return_result( l123, l123, outbuf, v123 );

   /* Whitespace OK in relaxed mode only */
   ret = base64_decode( " ", outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );
   check_return_result( l123, l123, outbuf, v123 );

   ret = base64_decode_mode( " ", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return( ret, 0 );
   check_return_result( l123, l123, outbuf, v123 );

   ret = base64_decode_mode( "\n", outbuf, bufsize, DECODE_MODE_WHITESPACE_OK );
   check_return( ret, 0 );
   check_return_result( l123, l123, outbuf, v123 );

   ret = base64_decode_mode( "\n", outbuf, bufsize, DECODE_MODE_LF_BREAKS );
   check_return( ret, 0 );
   check_return_result( l123, l123, outbuf, v123 );

   ret = base64_decode_mode( "    \t  ", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return( ret, 0 );
   check_return_result( l123, l123, outbuf, v123 );

   ret = base64_decode_mode( "   \t\n\t  \r\n\t", outbuf, bufsize,
                             DECODE_MODE_RELAXED );
   check_return( ret, 0 );
   check_return_result( l123, l123, outbuf, v123 );

   /* Basic decoding (successes) */
   ret = base64_decode( "QQ==", outbuf, bufsize );
   check_return_result( ret, 1, outbuf, "A" );

   ret = base64_decode( "QUI=", outbuf, bufsize );
   check_return_result( ret, 2, outbuf, "AB" );

   ret = base64_decode( "QUJD", outbuf, bufsize );
   check_return_result( ret, 3, outbuf, "ABC" );

   ret = base64_decode( "QUJDRA==", outbuf, bufsize );
   check_return_result( ret, 4, outbuf, "ABCD" );

   /* Stop decoding at NULL (success) */
   ret = base64_decode( "QQ==\0QUJD", outbuf, bufsize );
   check_return_result( ret, 1, outbuf, "A" );

   /* Embedded whitespace in relaxed mode (success) */
   ret = base64_decode_mode( "QU JD", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return_result( ret, 3, outbuf, "ABC" );

   ret = base64_decode_mode( "QU J  D \n ", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return_result( ret, 3, outbuf, "ABC" );

   ret = base64_decode_mode( "QU\nJD", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return_result( ret, 3, outbuf, "ABC" );

   /* Invalid characters (failures) */
   ret = base64_decode( "Q@JD", outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   ret = base64_decode( "QUJD*", outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   /* Leading and trailing whitespace (failure/sucess) */
   ret = base64_decode( "QQ== ", outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   ret = base64_decode( "QUI= ", outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR);

   ret = base64_decode( "\tQUI= \n   ", outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   ret = base64_decode( "QUJD    ", outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   ret = base64_decode( "\tQUJD", outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   ret = base64_decode_mode( "QQ== ", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return_result( ret, 1, outbuf, "A" );

   ret = base64_decode_mode( "QUI= ", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return_result( ret, 2, outbuf, "AB" );

   ret = base64_decode_mode( "\tQUI= \n   ", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return_result( ret, 2, outbuf, "AB" );

   ret = base64_decode_mode( "QUJD    ", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return_result( ret, 3, outbuf, "ABC" );

   ret = base64_decode_mode( "\tQUJD", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return_result( ret, 3, outbuf, "ABC" );

   /* Split sequence (successes, though not clearly defined in standard) */
   ret = base64_decode( "QUI=QUJD", outbuf, bufsize );
   check_return_result( ret, 5, outbuf, "ABABC" );

   ret = base64_decode_mode( "QUI=  QUJD", outbuf, bufsize, DECODE_MODE_RELAXED );
   check_return_result( ret, 5, outbuf, "ABABC" );

   /* Trailing garbage/incomplete sequences (failures) */
   ret = base64_decode( "QQ==A", outbuf, bufsize );
   check_return( ret, DECODE_MALFORMED_SEQUENCE );

   ret = base64_decode( "QUI=A", outbuf, bufsize );
   check_return( ret, DECODE_MALFORMED_SEQUENCE );

   ret = base64_decode( "QUJDA", outbuf, bufsize );
   check_return( ret, DECODE_MALFORMED_SEQUENCE );

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
   ret = base64_decode( input, outbuf, bufsize );
   check_return_result( ret, 256, outbuf, sequence );

   /* Output buffer size test checks (including edge cases) */
   ret = base64_decode( input, outbuf, 256 );
   check_return_result( ret, 256, outbuf, sequence );

   ret = base64_decode( input, outbuf, 255 );
   check_return( ret, DECODE_BUFFER_TOO_SMALL );

   ret = base64_decode( input, outbuf, 1 );
   check_return( ret, DECODE_BUFFER_TOO_SMALL );

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
   ret = base64_decode( input, outbuf, bufsize );
   check_return_result( ret, 256, outbuf, sequence );

   input =
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\r\n"
      "JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH\r\n"
      "SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWpr\r\n"
      "bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\r\n"
      "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKz\r\n"
      "tLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX\r\n"
      "2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7\r\n"
      "/P3+/w==\r\n";
   ret = base64_decode( input, outbuf, bufsize );
   check_return_result( ret, 256, outbuf, sequence );

   input =
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\r\n"
      "JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH\r\n"
      "SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWpr\r\n"
      "bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\r\n"
      "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKz\r\n\r\n"
      "tLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX\r\n"
      "2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7\r\n"
      "/P3+/w==";
   ret = base64_decode( input, outbuf, bufsize );
   check_return_result( ret, 256, outbuf, sequence );

   input =
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\r\n"
      "JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH\n"
      "SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWpr\r\n"
      "bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\r\n"
      "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKz\r\n"
      "tLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX\r\n"
      "2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7\r\n"
      "/P3+/w==";
   ret = base64_decode( input, outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   ret = base64_decode_mode( input, outbuf, bufsize, DECODE_MODE_LF_BREAKS );
   check_return_result( ret, 256, outbuf, sequence );

   ret = base64_decode_mode( input, outbuf, bufsize, DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, 256, outbuf, sequence );

   input =
      "  AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\n"
      "  JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH\n"
      "  SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWpr\n"
      "  bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\n"
      "  kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKz\r\n"
      "  tLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX\n"
      " 2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7\n"
      "  /P3+/w==";
   ret = base64_decode( input, outbuf, bufsize );
   check_return( ret, DECODE_INVALID_CHAR );

   ret = base64_decode_mode( input, outbuf, bufsize, DECODE_MODE_LF_BREAKS );
   check_return( ret, DECODE_INVALID_CHAR );

   ret = base64_decode_mode( input, outbuf, bufsize, DECODE_MODE_WHITESPACE_OK );
   check_return_result( ret, 256, outbuf, sequence );

   return ngood;
}

/* ========================= perror tests================================ */
static int test_perror()
{
   int ret, ngood = 0;
   const char *msg, *str;

   /* Error messages */
   ret = strlen( msg = decode_perror(0) );
   check_return( ret, 8 );
   check_return_result( ret+1, 9, msg, "No error" );

   ret = strlen( decode_perror( DECODE_BADARG ) );
   check_return_greater( ret, 8 );

   ret = strlen( decode_perror( DECODE_INVALID_CHAR ) );
   check_return_greater( ret, 8 );

   ret = strlen( decode_perror( DECODE_MALFORMED_SEQUENCE ) );
   check_return_greater( ret, 8 );

   ret = strlen( decode_perror( DECODE_BUFFER_TOO_SMALL ) );
   check_return_greater( ret, 8 );

   ret = strlen( decode_perror( DECODE_INPUT_TOO_LONG ) );
   check_return_greater( ret, 8 );

   ret = strlen( decode_perror( DECODE_LOWERCASE_HEX ) );
   check_return_greater( ret, 8 );

   ret = strlen( decode_perror( DECODE_LINE_TOO_LONG ) );
   check_return_greater( ret, 8 );

   ret = strlen( decode_perror( DECODE_WHITESPACE_IN_SOFTBREAK ) );
   check_return_greater( ret, 8 );

   msg = decode_perror(-255);
   str = "Unknown error code";
   check_return_result( (int)strlen(msg), (int)strlen(str), msg, str );

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
