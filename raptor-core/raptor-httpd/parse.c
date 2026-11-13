#include <stdlib.h>
#include <string.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define YYPREFIX "yy"
#line 29 "parse.y"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <ifaddrs.h>
#include <syslog.h>

#include "httpd.h"
#include "http.h"
#include "log.h"

#define TOKEN_STRING_MAX 16384

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	size_t			 ungetpos;
	size_t			 ungetsize;
	u_char			*ungetbuf;
	int			 eof_reached;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 igetc(void);
int		 lgetc(int);
void		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

struct httpd		*conf = NULL;
static int		 errors = 0;
static int		 loadcfg = 0;
uint32_t		 last_server_id = 0;
uint32_t		 last_auth_id = 0;

static struct server	*srv = NULL, *parentsrv = NULL;
static struct server_config *srv_conf = NULL;
struct serverlist	 servers;
struct media_type	 media;

struct address	*host_v4(const char *);
struct address	*host_v6(const char *);
int		 host_dns(const char *, struct addresslist *,
		    int, struct portrange *, const char *, int);
int		 host_if(const char *, struct addresslist *,
		    int, struct portrange *, const char *, int);
int		 host(const char *, struct addresslist *,
		    int, struct portrange *, const char *, int);
struct server	*server_inherit(struct server *, struct server_config *,
		    struct server_config *);
int		 listen_on(const char *, int, struct portrange *);
int		 getservice(char *);
int		 is_if_in_group(const char *, const char *);
int		 get_fastcgi_dest(struct server_config *, const char *, char *);
void		 remove_locations(struct server_config *);
int		 header_name_forbidden(const char *);

typedef struct {
	union {
		int64_t			 number;
		char			*string;
		struct timeval		 tv;
		struct portrange	 port;
		struct auth		 auth;
	} v;
	int lineno;
} YYSTYPE;

#line 124 "parse.c"
#define ACCESS 257
#define ADD 258
#define ALIAS 259
#define ALWAYS 260
#define AUTHENTICATE 261
#define AUTO 262
#define BACKLOG 263
#define BANNER 264
#define BLOCK 265
#define BODY 266
#define BUFFER 267
#define CA 268
#define CERTIFICATE 269
#define CHROOT 270
#define CIPHERS 271
#define CLIENT 272
#define COMBINED 273
#define COMMON 274
#define CONNECTION 275
#define CRL 276
#define DEFAULT 277
#define DHE 278
#define DIRECTORY 279
#define DROP 280
#define ECDHE 281
#define ERR 282
#define ERRDOCS 283
#define ERROR 284
#define FCGI 285
#define FORWARDED 286
#define FOUND 287
#define GZIPSTATIC 288
#define HEADER 289
#define HSTS 290
#define INCLUDE 291
#define INDEX 292
#define IP 293
#define KEY 294
#define LIFETIME 295
#define LISTEN 296
#define LOCATION 297
#define LOG 298
#define LOGDIR 299
#define MATCH 300
#define MAXAGE 301
#define MAXIMUM 302
#define NO 303
#define NODELAY 304
#define NOT 305
#define OCSP 306
#define ON 307
#define OPTIONAL 308
#define PARAM 309
#define PASS 310
#define PORT 311
#define PREFORK 312
#define PRELOAD 313
#define PROTOCOLS 314
#define REMOVE 315
#define REQUEST 316
#define REQUESTS 317
#define RETURN 318
#define REWRITE 319
#define ROOT 320
#define SACK 321
#define SERVER 322
#define SET 323
#define SOCKET 324
#define STATIC_CACHE_CONTROL 325
#define STRIP 326
#define STYLE 327
#define SUBDOMAINS 328
#define SYSLOG 329
#define TCP 330
#define TICKET 331
#define TIMEOUT 332
#define TLS 333
#define TYPE 334
#define TYPES 335
#define WITH 336
#define STRING 337
#define NUMBER 338
#define YYERRCODE 256
const short yylhs[] =
	{                                        -1,
    0,    0,    0,    0,    0,    0,    0,    0,   11,   12,
    4,    4,   13,   13,   13,   13,   13,   13,   17,   14,
   19,   19,   20,   20,   20,   20,   20,   20,   20,   20,
   20,   20,   20,   20,   20,   20,   20,   20,   20,   20,
   36,   20,   20,   20,   20,   28,   28,    3,    3,   29,
   29,   29,   29,   29,    6,    6,    6,   37,   37,   37,
   38,   38,   39,   39,   39,   32,   32,   41,   32,   44,
   32,   42,   42,   43,   43,   43,   43,   43,   43,   23,
   23,   45,   45,   46,   46,   46,   46,   24,   24,   47,
   47,   48,   48,   48,   48,   48,   48,   48,   48,   48,
   48,   48,   49,   49,   49,   26,   26,   51,   51,   50,
   25,   25,   53,   53,   52,   52,   52,   33,   33,   10,
   10,   27,   27,   55,   55,   54,   54,   54,   54,   31,
   31,   31,   57,   57,   56,   56,   56,   56,   56,   58,
   58,   58,   58,   35,   35,   35,   35,   59,    5,    5,
    9,    9,    2,    2,   34,   34,   30,   30,   22,   22,
   60,   60,   61,   61,   61,   61,   61,   61,   61,   15,
   62,   62,   63,   63,   16,   64,   64,   66,    1,    1,
    7,    8,    8,   65,   65,   18,   18,   40,   40,   21,
};
const short yylen[] =
	{                                         2,
    0,    3,    2,    3,    3,    3,    3,    3,    2,    3,
    0,    1,    2,    2,    2,    2,    2,    3,    0,    8,
    3,    2,    5,    3,    2,    2,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    0,    9,    3,    1,    1,    1,    2,    0,    1,    4,
    5,    5,    6,    4,    0,    1,    2,    5,    2,    1,
    3,    2,    2,    1,    1,    2,    1,    0,    6,    0,
    3,    3,    2,    2,    3,    4,    3,    2,    2,    5,
    2,    3,    2,    2,    3,    3,    4,    5,    2,    3,
    2,    2,    2,    2,    2,    4,    2,    2,    2,    3,
    3,    2,    0,    3,    2,    2,    5,    3,    2,    1,
    2,    5,    3,    2,    2,    2,    2,    2,    2,    3,
    2,    2,    5,    3,    2,    2,    2,    2,    3,    2,
    5,    2,    3,    2,    2,    1,    2,    2,    2,    1,
    1,    1,    1,    4,    2,    1,    1,    1,    0,    1,
    0,    1,    1,    1,    2,    1,    2,    1,    5,    2,
    3,    2,    1,    2,    1,    2,    2,    3,    3,    5,
    3,    2,    3,    1,    3,    2,    1,    1,    2,    2,
    1,    1,    1,    1,    0,    2,    0,    2,    1,    2,
};
const short yydefred[] =
	{                                      1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    3,    0,    0,    0,    0,    0,    8,   14,
    0,   15,    9,   16,   17,   13,  150,    0,    0,    0,
    2,    4,    5,    6,    7,    0,   18,   19,    0,    0,
   10,    0,    0,  186,  174,    0,    0,    0,  175,    0,
  183,  182,  178,    0,  177,  170,    0,    0,  172,    0,
  184,  173,  176,  171,  190,    0,    0,   46,  148,    0,
    0,    0,    0,    0,  156,    0,    0,    0,    0,    0,
    0,  147,    0,    0,  158,    0,    0,   44,    0,    0,
   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,
   37,   38,   39,   40,   45,    0,    0,    0,    0,  119,
    0,    0,    0,    0,   81,    0,    0,    0,    0,    0,
  122,   25,    0,    0,    0,    0,    0,    0,    0,    0,
   65,   64,    0,   59,    0,   56,    0,    0,    0,    0,
    0,    0,  136,    0,  130,  118,   47,   26,   66,  155,
  132,  157,    0,    0,    0,    0,  111,  110,    0,  106,
    0,    0,    0,  165,  163,    0,    0,  160,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   89,
   20,    0,   22,  145,    0,   24,  121,    0,    0,    0,
    0,  181,   84,    0,   43,  128,  126,    0,  127,    0,
    0,    0,    0,    0,    0,   71,    0,    0,    0,    0,
    0,   63,    0,    0,   57,    0,  138,  139,  137,  141,
  140,  142,  143,  135,    0,  116,  115,  117,    0,    0,
  167,    0,  166,  164,    0,    0,   92,   95,    0,   97,
   98,   93,  102,   94,   99,    0,    0,   21,    0,  120,
    0,   86,   85,    0,    0,  129,    0,    0,    0,    0,
   79,    0,   74,   78,    0,    0,   54,   49,   50,    0,
    0,    0,   12,    0,   41,    0,    0,    0,    0,    0,
    0,  169,  168,    0,    0,  103,  100,  101,    0,    0,
  152,  144,   87,   80,    0,    0,   83,  189,    0,  125,
    0,  123,    0,    0,   77,    0,   51,    0,   52,   58,
   62,    0,    0,   23,    0,  134,    0,  131,  114,    0,
  112,  109,    0,  107,  159,  162,    0,    0,   88,   91,
    0,    0,  188,   82,  124,   69,   73,    0,  154,  153,
   76,   53,   61,  180,  179,    0,  133,  113,  108,  161,
    0,  105,   90,   72,    0,  104,    0,   42,
};
const short yydgoto[] =
	{                                       1,
  314,  341,  269,  274,   28,  138,  193,   53,  292,  110,
   88,   15,   16,   17,   18,   46,   43,   40,   89,   90,
  298,   91,   92,   93,   94,   95,   96,   97,   98,   99,
  100,  101,  102,  103,  104,  315,  105,  271,  272,  299,
  123,  303,  304,  124,  254,  255,  289,  290,  328,  280,
  281,  278,  279,  257,  258,  276,  277,  224,  106,  284,
  285,   47,   48,   54,   62,   55,
};
const short yysindex[] =
	{                                      0,
  -10,   11, -302, -284, -262, -240, -236, -187, -234, -157,
  -11,   64,    0,  127,  136,  138,  150,  157,    0,    0,
 -161,    0,    0,    0,    0,    0,    0, -156,  164, -149,
    0,    0,    0,    0,    0,  133,    0,    0,  164, -271,
    0, -141,   72,    0,    0, -259, -121,  188,    0,  164,
    0,    0,    0,  -58,    0,    0,  188,  164,    0,  964,
    0,    0,    0,    0,    0, -157, -214,    0,    0, -109,
 -135, -117, -137,    0,    0, -247,  -93,  -89, -260, -116,
 -251,    0,  -94, -120,    0,  -27,  -66,    0,  778,  164,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -265, -115, -111, -107,    0,
 -184,  -99, -104,  164,    0, -161,  -49,  -92, -219,  164,
    0,    0,  121,  -71,  -90,  -85,  -83,  -80,  -78,  -77,
    0,    0,  164,    0,  -74,    0,  -23, -157,  -69,  -65,
  -60,  -24,    0,  164,    0,    0,    0,    0,    0,    0,
    0,    0,  -48,  -63,  -56,  164,    0,    0,  164,    0,
  -52,  -62, -279,    0,    0,   17,  164,    0,  -59,  -42,
   20,  -41,  -39,  -38,  -31,  -33,  -29,   15,  164,    0,
    0,  188,    0,    0,  -32,    0,    0,  -19,   47,  -18,
 -104,    0,    0, -276,    0,    0,    0,   27,    0, -238,
  164,   -9,   -7, -250,  -17,    0,   -6,   -5,   -4,   66,
   -3,    0, -194,    5,    0,    2,    0,    0,    0,    0,
    0,    0,    0,    0, -241,    0,    0,    0, -172,    3,
    0,    6,    0,    0,   24,   44,    0,    0,    4,    0,
    0,    0,    0,    0,    0, -249, -142,    0,   12,    0,
   25,    0,    0,  218,   28,    0,   28,  228,  -71,   21,
    0,   29,    0,    0,   66,   31,    0,    0,    0,   66,
  239,   28,    0,   56,    0,   28,  247,   28,  249,   28,
  251,    0,    0,  252,   28,    0,    0,    0,  253,   28,
    0,    0,    0,    0,  164,  164,    0,    0, -276,    0,
 -238,    0,  255,   28,    0, -181,    0,   12,    0,    0,
    0, -194, -175,    0,  259,    0, -241,    0,    0, -172,
    0,    0,    3,    0,    0,    0,   44, -245,    0,    0,
 -142,    0,    0,    0,    0,    0,    0,  -71,    0,    0,
    0,    0,    0,    0,    0,  164,    0,    0,    0,    0,
   46,    0,    0,    0,  964,    0,  840,    0,};
const short yyrindex[] =
	{                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   51,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -268,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  627,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, 1026,
    0,    0,    0,  379,    0,    0,    0, -106,    0,    0,
    0,    0,    0,    0,    0,   51,    0,    0,    0,    0,
    0,    0,    0,   26,    0,    0,  220,    0, -278,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  902,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  282,    0,    0,    0,    0,
    0,    0,    0, -188,    0,    0,    0,    0,    0, -168,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -163,    0,    0,    0,    0,   51,    0,    0,
    0,    0,    0, -218,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -125,    0,    0, -111,    0,
    0,    0,    0,    0,    0,    0,  107,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  531,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  -68,    0,    0,    0,    0,    0,    0,    0,    0,  344,
    0,    0,    0,   79,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  414,    0,
    0,    0,    0,    0,  266,    0,  266,    0,    0,    0,
    0,    0,    0,    0,  344,    0,    0,    0,    0,  344,
    0,  266,    0,    0,    0,  266,    0,  266,    0,  266,
    0,    0,    0,    0,  266,    0,    0,    0,    0,  266,
    0,    0,    0,    0,  464, -211,    0,    0,    0,    0,
    0,    0,    0,  266,    0,   96,    0,  414,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  158,    0,    0,
    0,  704,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, 1026,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,};
const short yygindex[] =
	{                                      0,
    0,    0, -221,    0,  -54,    0,  204,    0,   88,    0,
    8,    0,    0,    0,    0,  -16,    0,  581,   42,  -87,
  -40,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   86,  324,  542,
    0,   65,  278,    0,  105,  335,   77,  322,    0,  329,
   91,  332,   98,  348,  124,  347,  113,    0,    0,  109,
  346,    0,  387,    0,    0,  384,
};
#define YYTABLESIZE 1359
const short yytable[] =
	{                                      13,
   61,  182,  159,   56,   37,  120,  144,   59,   14,  146,
  125,  107,  147,  114,  184,  139,   64,  126,  187,    6,
   19,   55,  187,  117,  233,  111,  136,  287,  156,  133,
  351,  148,  127,  149,   20,   67,  150,  295,  187,  112,
  140,  234,  198,  307,  137,  187,  151,   45,  309,   21,
  187,  187,  185,  118,   45,  113,  179,  187,   55,  187,
  187,  141,  352,  187,  119,   36,  187,  128,  187,  187,
  187,  296,  199,  152,   22,  129,   25,   51,   52,  262,
  187,  187,  187,  216,  187,  142,  263,  143,  288,  187,
  187,  187,  187,  187,  187,  167,   23,  187,  187,  195,
   24,  187,  187,   26,  187,   75,  130,  187,  187,  187,
  187,   29,  187,  187,  187,  187,  187,  187,  131,  187,
  187,  108,  109,  187,   30,  187,  169,  187,  170,  171,
  153,  189,  190,  132,  187,  172,   31,  187,  173,   75,
  139,  248,   27,  187,  117,   32,  154,   33,   68,  187,
   67,  174,  187,  155,  187,  339,  340,  187,  187,   34,
  175,  344,  345,  176,  187,  140,   35,   96,  187,    6,
  187,  177,  187,   39,  118,   36,  187,  187,  187,   42,
   38,  187,  187,  187,  187,  119,  141,   41,  178,  187,
  187,  187,  111,  187,   50,   49,  187,   58,  116,  122,
  187,   96,  169,  187,  170,  171,  112,  130,  153,  187,
  142,  172,  143,  187,  173,   36,  158,  135,  187,  131,
   75,  186,  113,  187,  154,  187,  187,  174,  188,   60,
  187,  155,  191,  192,  132,  161,  175,  202,  203,  176,
  187,  187,  196,  201,  197,    2,  207,  177,  220,  221,
  222,  208,  204,  209,  205,  187,  210,  187,  211,    3,
  212,  223,  214,  215,  178,  162,    4,  217,  219,  182,
  226,  218,    5,  227,  232,  163,  164,  237,   51,   52,
    6,  228,   96,  235,   67,  231,   67,  239,    7,   67,
   67,  146,    8,  165,  238,  240,  166,  241,  242,  243,
   67,    9,   67,  244,   67,  249,  161,  245,   67,  246,
   67,   10,  251,   67,   67,   67,   67,  250,  256,  252,
  264,   67,   67,   67,   11,  268,   12,  260,   67,  261,
  265,  266,  267,  270,   70,   67,  162,  273,  275,  158,
  286,   67,  294,  282,   60,   67,  163,  164,  291,   70,
   67,   70,  302,   48,   75,   67,   75,  305,   67,   75,
   75,  283,  293,  310,  165,  306,  313,  166,  308,  187,
   75,  318,   75,  321,   75,  324,  325,  329,   75,  336,
   75,  346,  356,   75,   75,   75,   75,  149,  185,   11,
  187,   75,   75,   75,  253,  342,  357,  343,   75,  187,
  134,  206,  354,  334,  115,   75,  146,  353,  180,  187,
  187,   75,  160,  349,  157,   75,   96,  348,   96,  121,
   75,   96,   96,  151,  335,   75,  145,  187,   75,  347,
  187,  168,   96,   57,   96,  350,   96,   63,    0,    0,
   96,    0,   96,    0,    0,   96,   96,   96,   96,    0,
    0,    0,    0,   96,   96,   96,    0,    0,    0,    0,
   96,    0,    0,    0,    0,    0,    0,   96,   48,    0,
    0,    0,    0,   96,    0,    0,    0,   96,   60,    0,
   60,    0,   96,   60,   60,    0,    0,   96,    0,    0,
   96,    0,    0,    0,   60,    0,   60,    0,   60,    0,
    0,    0,   60,    0,   60,    0,    0,   60,   60,   60,
   60,    0,    0,    0,    0,   60,   60,   60,    0,    0,
    0,    0,   60,    0,    0,    0,    0,    0,    0,   60,
    0,    0,    0,    0,    0,   60,    0,    0,  151,   60,
  146,    0,  146,    0,   60,  146,  146,    0,    0,   60,
    0,    0,   60,    0,    0,    0,  146,    0,  146,    0,
  146,    0,    0,    0,  146,    0,  146,    0,    0,  146,
  146,  146,  146,    0,    0,    0,    0,  146,  146,  146,
    0,    0,    0,    0,  146,    0,    0,    0,  187,    0,
    0,  146,    0,    0,    0,    0,    0,  146,    0,    0,
    0,  146,   48,    0,   48,    0,  146,   48,   48,    0,
    0,  146,    0,    0,  146,    0,    0,    0,   48,   44,
   48,    0,   48,    0,    0,    0,   48,    0,   48,    0,
   60,   48,   48,   48,   48,    0,    0,    0,   65,   48,
   48,   48,    0,    0,    0,    0,   48,    0,    0,    0,
    0,    0,    0,   48,    0,    0,    0,    0,    0,   48,
    0,    0,    0,   48,    0,    0,    0,    0,   48,    0,
  183,    0,  151,   48,  151,    0,   48,  151,  151,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  151,    0,
  151,    0,  151,    0,  194,    0,  151,    0,  151,    0,
  200,  151,  151,  151,  151,    0,    0,    0,    0,  151,
  151,  151,    0,  213,    0,    0,  151,    0,    0,    0,
  187,    0,    0,  151,  225,  187,  187,    0,    0,  151,
    0,    0,  187,  151,  187,  187,  229,    0,  151,  230,
    0,  187,    0,  151,  187,  187,  151,  236,    0,    0,
    0,  187,    0,    0,    0,  187,  187,  187,    0,  247,
    0,    0,    0,    0,  187,  187,  187,  187,    0,  187,
    0,    0,  187,  187,    0,    0,  187,  187,    0,  187,
    0,  259,  187,    0,  187,    0,    0,  187,    0,  187,
  187,  187,  187,    0,  187,  187,    0,    0,  301,  187,
  187,  187,  187,    0,    0,    0,    0,    0,  187,    0,
    0,  187,    0,  312,    0,    0,    0,  317,    0,  320,
    0,  323,    0,    0,  187,    0,  327,    0,  186,    0,
    0,  331,    0,  187,    0,  297,  187,  300,    0,    0,
    0,    0,    0,    0,  187,  338,    0,    0,    0,    0,
    0,    0,  311,    0,    0,    0,  316,    0,  319,    0,
  322,  187,    0,    0,    0,  326,    0,    0,    0,    0,
  330,    0,    0,    0,    0,  332,  333,    0,    0,    0,
    0,    0,    0,  187,  337,  187,    0,  187,  187,  187,
  187,  187,    0,    0,    0,  187,    0,  187,  187,    0,
    0,  187,  181,  187,  187,  187,    0,  187,  187,  187,
    0,  187,    0,    0,  187,  187,  187,  187,  187,  187,
  187,    0,  187,  187,  187,    0,  355,  187,  187,  187,
  187,    0,  187,    0,    0,  187,  187,    0,    0,  187,
  187,    0,  187,    0,    0,  187,  187,  187,    0,    0,
  187,  187,  187,  187,  187,  187,  187,  187,  187,  187,
  190,    0,    0,  187,  358,  190,  190,    0,    0,    0,
    0,    0,  190,    0,  190,  190,    0,    0,    0,    0,
    0,  190,    0,    0,  190,  190,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  190,  190,  190,    0,    0,
    0,    0,    0,    0,  190,  190,  190,  190,    0,  190,
    0,    0,  190,  190,    0,    0,  190,  190,    0,  190,
    0,    0,  190,    0,  190,    0,  187,  190,    0,  190,
  190,  190,  190,    0,  190,  190,   66,    0,   67,    0,
  190,   68,   69,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   70,    0,   71,    0,   72,    0,    0,    0,
   73,    0,   74,    0,    0,   75,   76,   77,    6,    0,
    0,    0,    0,   78,   79,   80,    0,    0,    0,    0,
   81,    0,    0,    0,    0,    0,    0,   82,    0,    0,
    0,    0,    0,   83,    0,    0,    0,   84,   66,    0,
   67,    0,   85,   68,   69,    0,    0,   86,    0,    0,
   87,    0,    0,    0,   70,    0,   71,    0,   72,    0,
    0,    0,   73,    0,   74,    0,    0,   75,   76,   77,
    6,    0,    0,    0,    0,   78,   79,   80,    0,    0,
    0,    0,   81,    0,    0,    0,    0,    0,    0,   82,
    0,    0,    0,    0,    0,   83,    0,    0,    0,   84,
  187,    0,  187,    0,   85,  187,  187,    0,    0,   86,
    0,    0,   87,    0,    0,    0,  187,    0,  187,    0,
  187,    0,    0,    0,  187,    0,  187,    0,    0,  187,
  187,  187,  187,    0,    0,    0,    0,  187,  187,  187,
    0,    0,    0,    0,  187,    0,    0,    0,    0,    0,
    0,  187,    0,    0,    0,    0,    0,  187,    0,    0,
    0,  187,   66,    0,   67,    0,  187,   68,   69,    0,
    0,  187,    0,    0,  187,    0,    0,    0,   70,    0,
   71,    0,   72,    0,    0,    0,   73,    0,   74,    0,
    0,   75,   76,   77,    6,    0,    0,    0,    0,   78,
   79,   80,    0,    0,    0,    0,   81,    0,    0,    0,
    0,    0,    0,   82,    0,    0,    0,    0,    0,   83,
    0,    0,    0,   84,  187,    0,  187,    0,   85,  187,
  187,    0,    0,   86,    0,    0,   87,    0,    0,    0,
  187,    0,  187,    0,  187,    0,    0,    0,  187,    0,
  187,    0,    0,  187,  187,  187,  187,    0,    0,    0,
    0,  187,  187,  187,    0,    0,    0,    0,  187,    0,
    0,    0,    0,    0,    0,  187,    0,    0,    0,    0,
    0,  187,    0,    0,    0,  187,    0,    0,    0,    0,
  187,    0,    0,    0,    0,  187,    0,    0,  187,
};
const short yycheck[] =
	{                                      10,
   59,   89,  123,  125,   21,  123,  123,   48,    1,  261,
  258,   66,  264,  123,  280,  257,   57,  265,  125,  291,
   10,  300,  291,  262,  304,  302,  287,  277,  123,  123,
  276,  283,  280,  285,  337,   10,  288,   10,  257,  316,
  282,  321,  262,  265,  305,  257,  298,   40,  270,  334,
  262,  263,  318,  292,   47,  332,  123,  269,  337,  271,
  272,  303,  308,  282,  303,  337,  278,  315,  337,  281,
  282,   44,  292,  325,  337,  323,  264,  337,  338,  330,
  292,  293,  294,  138,  303,  327,  337,  329,  338,  301,
  302,  303,  304,  262,  306,  123,  337,  309,  310,  116,
  337,  313,  314,  338,  316,   10,  301,  319,  327,  321,
  329,  123,  324,  302,  326,  327,  328,  329,  313,  331,
  332,  336,  337,  292,   61,  337,  269,  316,  271,  272,
  303,  316,  317,  328,  303,  278,   10,  301,  281,   44,
  257,  182,  300,  332,  262,   10,  319,   10,  123,  313,
  125,  294,  259,  326,  261,  337,  338,  264,  265,   10,
  303,  337,  338,  306,  328,  282,   10,   10,  275,  291,
  277,  314,  279,   10,  292,  337,  283,  303,  285,   47,
  337,  288,  289,  290,  291,  303,  303,  337,  331,  296,
  297,  298,  302,  319,  123,  337,  303,   10,  334,  337,
  326,   44,  269,  310,  271,  272,  316,  301,  303,  316,
  327,  278,  329,  320,  281,  337,  337,  307,  325,  313,
  125,  337,  332,  330,  319,  337,  333,  294,  336,   10,
  337,  326,  332,  338,  328,  263,  303,  309,  310,  306,
  309,  310,  292,  123,  337,  256,  337,  314,  273,  274,
  275,  337,  324,  337,  326,  324,  337,  326,  337,  270,
  338,  286,  337,  287,  331,  293,  277,  337,  329,  357,
  319,  337,  283,  337,  337,  303,  304,  337,  337,  338,
  291,  338,  125,  267,  259,  338,  261,  268,  299,  264,
  265,   10,  303,  321,  337,  337,  324,  337,  337,  331,
  275,  312,  277,  337,  279,  338,  263,  337,  283,  295,
  285,  322,  266,  288,  289,  290,  291,  337,  292,  338,
  338,  296,  297,  298,  335,  260,  337,  337,  303,  337,
  337,  337,  337,  337,  309,  310,  293,  333,  337,  337,
  337,  316,  125,  338,  125,  320,  303,  304,  337,  324,
  325,  326,  125,   10,  259,  330,  261,  337,  333,  264,
  265,  338,  338,  125,  321,  337,  311,  324,  338,  263,
  275,  125,  277,  125,  279,  125,  125,  125,  283,  125,
  285,  123,  337,  288,  289,  290,  291,  337,   10,  311,
  125,  296,  297,  298,  191,  308,  355,  312,  303,  293,
   77,  124,  338,  299,   70,  310,  125,  331,   87,  303,
  304,  316,   84,  323,   83,  320,  259,  320,  261,   72,
  325,  264,  265,   10,  301,  330,   80,  321,  333,  317,
  324,   86,  275,   47,  277,  327,  279,   54,   -1,   -1,
  283,   -1,  285,   -1,   -1,  288,  289,  290,  291,   -1,
   -1,   -1,   -1,  296,  297,  298,   -1,   -1,   -1,   -1,
  303,   -1,   -1,   -1,   -1,   -1,   -1,  310,  125,   -1,
   -1,   -1,   -1,  316,   -1,   -1,   -1,  320,  259,   -1,
  261,   -1,  325,  264,  265,   -1,   -1,  330,   -1,   -1,
  333,   -1,   -1,   -1,  275,   -1,  277,   -1,  279,   -1,
   -1,   -1,  283,   -1,  285,   -1,   -1,  288,  289,  290,
  291,   -1,   -1,   -1,   -1,  296,  297,  298,   -1,   -1,
   -1,   -1,  303,   -1,   -1,   -1,   -1,   -1,   -1,  310,
   -1,   -1,   -1,   -1,   -1,  316,   -1,   -1,  125,  320,
  259,   -1,  261,   -1,  325,  264,  265,   -1,   -1,  330,
   -1,   -1,  333,   -1,   -1,   -1,  275,   -1,  277,   -1,
  279,   -1,   -1,   -1,  283,   -1,  285,   -1,   -1,  288,
  289,  290,  291,   -1,   -1,   -1,   -1,  296,  297,  298,
   -1,   -1,   -1,   -1,  303,   -1,   -1,   -1,  125,   -1,
   -1,  310,   -1,   -1,   -1,   -1,   -1,  316,   -1,   -1,
   -1,  320,  259,   -1,  261,   -1,  325,  264,  265,   -1,
   -1,  330,   -1,   -1,  333,   -1,   -1,   -1,  275,   39,
  277,   -1,  279,   -1,   -1,   -1,  283,   -1,  285,   -1,
   50,  288,  289,  290,  291,   -1,   -1,   -1,   58,  296,
  297,  298,   -1,   -1,   -1,   -1,  303,   -1,   -1,   -1,
   -1,   -1,   -1,  310,   -1,   -1,   -1,   -1,   -1,  316,
   -1,   -1,   -1,  320,   -1,   -1,   -1,   -1,  325,   -1,
   90,   -1,  259,  330,  261,   -1,  333,  264,  265,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  275,   -1,
  277,   -1,  279,   -1,  114,   -1,  283,   -1,  285,   -1,
  120,  288,  289,  290,  291,   -1,   -1,   -1,   -1,  296,
  297,  298,   -1,  133,   -1,   -1,  303,   -1,   -1,   -1,
  257,   -1,   -1,  310,  144,  262,  263,   -1,   -1,  316,
   -1,   -1,  269,  320,  271,  272,  156,   -1,  325,  159,
   -1,  278,   -1,  330,  281,  282,  333,  167,   -1,   -1,
   -1,  125,   -1,   -1,   -1,  292,  293,  294,   -1,  179,
   -1,   -1,   -1,   -1,  301,  302,  303,  304,   -1,  306,
   -1,   -1,  309,  310,   -1,   -1,  313,  314,   -1,  316,
   -1,  201,  319,   -1,  321,   -1,   -1,  324,   -1,  326,
  327,  328,  329,   -1,  331,  332,   -1,   -1,  257,  269,
  337,  271,  272,   -1,   -1,   -1,   -1,   -1,  278,   -1,
   -1,  281,   -1,  272,   -1,   -1,   -1,  276,   -1,  278,
   -1,  280,   -1,   -1,  294,   -1,  285,   -1,  125,   -1,
   -1,  290,   -1,  303,   -1,  255,  306,  257,   -1,   -1,
   -1,   -1,   -1,   -1,  314,  304,   -1,   -1,   -1,   -1,
   -1,   -1,  272,   -1,   -1,   -1,  276,   -1,  278,   -1,
  280,  331,   -1,   -1,   -1,  285,   -1,   -1,   -1,   -1,
  290,   -1,   -1,   -1,   -1,  295,  296,   -1,   -1,   -1,
   -1,   -1,   -1,  257,  304,  259,   -1,  261,  262,  263,
  264,  265,   -1,   -1,   -1,  269,   -1,  271,  272,   -1,
   -1,  275,  125,  277,  278,  279,   -1,  281,  282,  283,
   -1,  285,   -1,   -1,  288,  289,  290,  291,  292,  293,
  294,   -1,  296,  297,  298,   -1,  346,  301,  302,  303,
  304,   -1,  306,   -1,   -1,  309,  310,   -1,   -1,  313,
  314,   -1,  316,   -1,   -1,  319,  320,  321,   -1,   -1,
  324,  325,  326,  327,  328,  329,  330,  331,  332,  333,
  257,   -1,   -1,  337,  125,  262,  263,   -1,   -1,   -1,
   -1,   -1,  269,   -1,  271,  272,   -1,   -1,   -1,   -1,
   -1,  278,   -1,   -1,  281,  282,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  292,  293,  294,   -1,   -1,
   -1,   -1,   -1,   -1,  301,  302,  303,  304,   -1,  306,
   -1,   -1,  309,  310,   -1,   -1,  313,  314,   -1,  316,
   -1,   -1,  319,   -1,  321,   -1,  125,  324,   -1,  326,
  327,  328,  329,   -1,  331,  332,  259,   -1,  261,   -1,
  337,  264,  265,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  275,   -1,  277,   -1,  279,   -1,   -1,   -1,
  283,   -1,  285,   -1,   -1,  288,  289,  290,  291,   -1,
   -1,   -1,   -1,  296,  297,  298,   -1,   -1,   -1,   -1,
  303,   -1,   -1,   -1,   -1,   -1,   -1,  310,   -1,   -1,
   -1,   -1,   -1,  316,   -1,   -1,   -1,  320,  259,   -1,
  261,   -1,  325,  264,  265,   -1,   -1,  330,   -1,   -1,
  333,   -1,   -1,   -1,  275,   -1,  277,   -1,  279,   -1,
   -1,   -1,  283,   -1,  285,   -1,   -1,  288,  289,  290,
  291,   -1,   -1,   -1,   -1,  296,  297,  298,   -1,   -1,
   -1,   -1,  303,   -1,   -1,   -1,   -1,   -1,   -1,  310,
   -1,   -1,   -1,   -1,   -1,  316,   -1,   -1,   -1,  320,
  259,   -1,  261,   -1,  325,  264,  265,   -1,   -1,  330,
   -1,   -1,  333,   -1,   -1,   -1,  275,   -1,  277,   -1,
  279,   -1,   -1,   -1,  283,   -1,  285,   -1,   -1,  288,
  289,  290,  291,   -1,   -1,   -1,   -1,  296,  297,  298,
   -1,   -1,   -1,   -1,  303,   -1,   -1,   -1,   -1,   -1,
   -1,  310,   -1,   -1,   -1,   -1,   -1,  316,   -1,   -1,
   -1,  320,  259,   -1,  261,   -1,  325,  264,  265,   -1,
   -1,  330,   -1,   -1,  333,   -1,   -1,   -1,  275,   -1,
  277,   -1,  279,   -1,   -1,   -1,  283,   -1,  285,   -1,
   -1,  288,  289,  290,  291,   -1,   -1,   -1,   -1,  296,
  297,  298,   -1,   -1,   -1,   -1,  303,   -1,   -1,   -1,
   -1,   -1,   -1,  310,   -1,   -1,   -1,   -1,   -1,  316,
   -1,   -1,   -1,  320,  259,   -1,  261,   -1,  325,  264,
  265,   -1,   -1,  330,   -1,   -1,  333,   -1,   -1,   -1,
  275,   -1,  277,   -1,  279,   -1,   -1,   -1,  283,   -1,
  285,   -1,   -1,  288,  289,  290,  291,   -1,   -1,   -1,
   -1,  296,  297,  298,   -1,   -1,   -1,   -1,  303,   -1,
   -1,   -1,   -1,   -1,   -1,  310,   -1,   -1,   -1,   -1,
   -1,  316,   -1,   -1,   -1,  320,   -1,   -1,   -1,   -1,
  325,   -1,   -1,   -1,   -1,  330,   -1,   -1,  333,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 338
#if YYDEBUG
const char * const yyname[] =
	{
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,"','",0,0,"'/'",0,0,0,0,0,0,0,0,0,0,0,"';'",0,"'='",0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"ACCESS","ADD","ALIAS","ALWAYS","AUTHENTICATE","AUTO","BACKLOG","BANNER",
"BLOCK","BODY","BUFFER","CA","CERTIFICATE","CHROOT","CIPHERS","CLIENT",
"COMBINED","COMMON","CONNECTION","CRL","DEFAULT","DHE","DIRECTORY","DROP",
"ECDHE","ERR","ERRDOCS","ERROR","FCGI","FORWARDED","FOUND","GZIPSTATIC",
"HEADER","HSTS","INCLUDE","INDEX","IP","KEY","LIFETIME","LISTEN","LOCATION",
"LOG","LOGDIR","MATCH","MAXAGE","MAXIMUM","NO","NODELAY","NOT","OCSP","ON",
"OPTIONAL","PARAM","PASS","PORT","PREFORK","PRELOAD","PROTOCOLS","REMOVE",
"REQUEST","REQUESTS","RETURN","REWRITE","ROOT","SACK","SERVER","SET","SOCKET",
"STATIC_CACHE_CONTROL","STRIP","STYLE","SUBDOMAINS","SYSLOG","TCP","TICKET",
"TIMEOUT","TLS","TYPE","TYPES","WITH","STRING","NUMBER",
};
const char * const yyrule[] =
	{"$accept : grammar",
"grammar :",
"grammar : grammar include '\\n'",
"grammar : grammar '\\n'",
"grammar : grammar varset '\\n'",
"grammar : grammar main '\\n'",
"grammar : grammar server '\\n'",
"grammar : grammar types '\\n'",
"grammar : grammar error '\\n'",
"include : INCLUDE STRING",
"varset : STRING '=' STRING",
"opttls :",
"opttls : TLS",
"main : PREFORK NUMBER",
"main : CHROOT STRING",
"main : ERRDOCS STRING",
"main : LOGDIR STRING",
"main : NO BANNER",
"main : DEFAULT TYPE mediastring",
"$$1 :",
"server : SERVER optmatch STRING $$1 '{' optnl serveropts_l '}'",
"serveropts_l : serveropts_l serveroptsl nl",
"serveropts_l : serveroptsl optnl",
"serveroptsl : LISTEN ON STRING opttls port",
"serveroptsl : ALIAS optmatch STRING",
"serveroptsl : ERRDOCS STRING",
"serveroptsl : NO ERRDOCS",
"serveroptsl : tcpip",
"serveroptsl : connection",
"serveroptsl : tls",
"serveroptsl : request",
"serveroptsl : root",
"serveroptsl : directory",
"serveroptsl : banner",
"serveroptsl : header",
"serveroptsl : static_cache_control",
"serveroptsl : logformat",
"serveroptsl : fastcgi",
"serveroptsl : authenticate",
"serveroptsl : gzip_static",
"serveroptsl : filter",
"$$2 :",
"serveroptsl : LOCATION optfound optmatch STRING $$2 '{' optnl serveropts_l '}'",
"serveroptsl : DEFAULT TYPE mediastring",
"serveroptsl : include",
"serveroptsl : hsts",
"banner : BANNER",
"banner : NO BANNER",
"optalways :",
"optalways : ALWAYS",
"header : HEADER REMOVE STRING optalways",
"header : HEADER ADD STRING STRING optalways",
"header : HEADER SET STRING STRING optalways",
"header : HEADER BLOCK STRING STRING NUMBER optstring",
"header : HEADER DROP STRING STRING",
"optfound :",
"optfound : FOUND",
"optfound : NOT FOUND",
"hsts : HSTS '{' optnl hstsflags_l '}'",
"hsts : HSTS hstsflags",
"hsts : HSTS",
"hstsflags_l : hstsflags optcommanl hstsflags_l",
"hstsflags_l : hstsflags optnl",
"hstsflags : MAXAGE NUMBER",
"hstsflags : SUBDOMAINS",
"hstsflags : PRELOAD",
"fastcgi : NO FCGI",
"fastcgi : FCGI",
"$$3 :",
"fastcgi : FCGI $$3 '{' optnl fcgiflags_l '}'",
"$$4 :",
"fastcgi : FCGI $$4 fcgiflags",
"fcgiflags_l : fcgiflags optcommanl fcgiflags_l",
"fcgiflags_l : fcgiflags optnl",
"fcgiflags : SOCKET STRING",
"fcgiflags : SOCKET TCP STRING",
"fcgiflags : SOCKET TCP STRING fcgiport",
"fcgiflags : PARAM STRING STRING",
"fcgiflags : STRIP NUMBER",
"fcgiflags : PASS STRING",
"connection : CONNECTION '{' optnl conflags_l '}'",
"connection : CONNECTION conflags",
"conflags_l : conflags optcommanl conflags_l",
"conflags_l : conflags optnl",
"conflags : TIMEOUT timeout",
"conflags : REQUEST TIMEOUT timeout",
"conflags : MAXIMUM REQUESTS NUMBER",
"conflags : MAXIMUM REQUEST BODY NUMBER",
"tls : TLS '{' optnl tlsopts_l '}'",
"tls : TLS tlsopts",
"tlsopts_l : tlsopts optcommanl tlsopts_l",
"tlsopts_l : tlsopts optnl",
"tlsopts : CERTIFICATE STRING",
"tlsopts : KEY STRING",
"tlsopts : OCSP STRING",
"tlsopts : CIPHERS STRING",
"tlsopts : CLIENT CA STRING tlsclientopt",
"tlsopts : DHE STRING",
"tlsopts : ECDHE STRING",
"tlsopts : PROTOCOLS STRING",
"tlsopts : TICKET LIFETIME DEFAULT",
"tlsopts : TICKET LIFETIME NUMBER",
"tlsopts : NO TICKET",
"tlsclientopt :",
"tlsclientopt : tlsclientopt CRL STRING",
"tlsclientopt : tlsclientopt OPTIONAL",
"root : ROOT rootflags",
"root : ROOT '{' optnl rootflags_l '}'",
"rootflags_l : rootflags optcommanl rootflags_l",
"rootflags_l : rootflags optnl",
"rootflags : STRING",
"request : REQUEST requestflags",
"request : REQUEST '{' optnl requestflags_l '}'",
"requestflags_l : requestflags optcommanl requestflags_l",
"requestflags_l : requestflags optnl",
"requestflags : REWRITE STRING",
"requestflags : NO REWRITE",
"requestflags : STRIP NUMBER",
"authenticate : NO AUTHENTICATE",
"authenticate : AUTHENTICATE authopts",
"authopts : STRING WITH STRING",
"authopts : WITH STRING",
"directory : DIRECTORY dirflags",
"directory : DIRECTORY '{' optnl dirflags_l '}'",
"dirflags_l : dirflags optcommanl dirflags_l",
"dirflags_l : dirflags optnl",
"dirflags : INDEX STRING",
"dirflags : NO INDEX",
"dirflags : AUTO INDEX",
"dirflags : NO AUTO INDEX",
"logformat : LOG logflags",
"logformat : LOG '{' optnl logflags_l '}'",
"logformat : NO LOG",
"logflags_l : logflags optcommanl logflags_l",
"logflags_l : logflags optnl",
"logflags : STYLE logstyle",
"logflags : SYSLOG",
"logflags : NO SYSLOG",
"logflags : ACCESS STRING",
"logflags : ERR STRING",
"logstyle : COMMON",
"logstyle : COMBINED",
"logstyle : CONNECTION",
"logstyle : FORWARDED",
"filter : block RETURN NUMBER optstring",
"filter : block DROP",
"filter : block",
"filter : PASS",
"block : BLOCK",
"optmatch :",
"optmatch : MATCH",
"optstring :",
"optstring : STRING",
"fcgiport : NUMBER",
"fcgiport : STRING",
"gzip_static : NO GZIPSTATIC",
"gzip_static : GZIPSTATIC",
"static_cache_control : NO STATIC_CACHE_CONTROL",
"static_cache_control : STATIC_CACHE_CONTROL",
"tcpip : TCP '{' optnl tcpflags_l '}'",
"tcpip : TCP tcpflags",
"tcpflags_l : tcpflags optcommanl tcpflags_l",
"tcpflags_l : tcpflags optnl",
"tcpflags : SACK",
"tcpflags : NO SACK",
"tcpflags : NODELAY",
"tcpflags : NO NODELAY",
"tcpflags : BACKLOG NUMBER",
"tcpflags : SOCKET BUFFER NUMBER",
"tcpflags : IP STRING NUMBER",
"types : TYPES '{' optnl mediaopts_l '}'",
"mediaopts_l : mediaopts_l mediaoptsl nl",
"mediaopts_l : mediaoptsl nl",
"mediaoptsl : mediastring medianames_l optsemicolon",
"mediaoptsl : include",
"mediastring : STRING '/' STRING",
"medianames_l : medianames_l medianamesl",
"medianames_l : medianamesl",
"medianamesl : numberstring",
"port : PORT NUMBER",
"port : PORT STRING",
"timeout : NUMBER",
"numberstring : NUMBER",
"numberstring : STRING",
"optsemicolon : ';'",
"optsemicolon :",
"optnl : '\\n' optnl",
"optnl :",
"optcommanl : ',' optnl",
"optcommanl : nl",
"nl : '\\n' optnl",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
/* LINTUSED */
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
unsigned int yystacksize;
int yyparse(void);
#line 1654 "parse.y"

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	logit(LOG_CRIT, "%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "access",		ACCESS },
		{ "add",		ADD },
		{ "alias",		ALIAS },
		{ "always",		ALWAYS },
		{ "authenticate",	AUTHENTICATE},
		{ "auto",		AUTO },
		{ "backlog",		BACKLOG },
		{ "banner",		BANNER },
		{ "block",		BLOCK },
		{ "body",		BODY },
		{ "buffer",		BUFFER },
		{ "ca",			CA },
		{ "certificate",	CERTIFICATE },
		{ "chroot",		CHROOT },
		{ "ciphers",		CIPHERS },
		{ "client",		CLIENT },
		{ "combined",		COMBINED },
		{ "common",		COMMON },
		{ "connection",		CONNECTION },
		{ "crl",		CRL },
		{ "default",		DEFAULT },
		{ "dhe",		DHE },
		{ "directory",		DIRECTORY },
		{ "drop",		DROP },
		{ "ecdhe",		ECDHE },
		{ "errdocs",		ERRDOCS },
		{ "error",		ERR },
		{ "fastcgi",		FCGI },
		{ "forwarded",		FORWARDED },
		{ "found",		FOUND },
		{ "gzip-static",	GZIPSTATIC },
		{ "header",		HEADER },
		{ "hsts",		HSTS },
		{ "include",		INCLUDE },
		{ "index",		INDEX },
		{ "ip",			IP },
		{ "key",		KEY },
		{ "lifetime",		LIFETIME },
		{ "listen",		LISTEN },
		{ "location",		LOCATION },
		{ "log",		LOG },
		{ "logdir",		LOGDIR },
		{ "match",		MATCH },
		{ "max",		MAXIMUM },
		{ "max-age",		MAXAGE },
		{ "no",			NO },
		{ "nodelay",		NODELAY },
		{ "not",		NOT },
		{ "ocsp",		OCSP },
		{ "on",			ON },
		{ "optional",		OPTIONAL },
		{ "param",		PARAM },
		{ "pass",		PASS },
		{ "port",		PORT },
		{ "prefork",		PREFORK },
		{ "preload",		PRELOAD },
		{ "protocols",		PROTOCOLS },
		{ "remove",		REMOVE },
		{ "request",		REQUEST },
		{ "requests",		REQUESTS },
		{ "return",		RETURN },
		{ "rewrite",		REWRITE },
		{ "root",		ROOT },
		{ "sack",		SACK },
		{ "server",		SERVER },
		{ "set",		SET },
		{ "socket",		SOCKET },
		{ "static-cache-control",	STATIC_CACHE_CONTROL },
		{ "strip",		STRIP },
		{ "style",		STYLE },
		{ "subdomains",		SUBDOMAINS },
		{ "syslog",		SYSLOG },
		{ "tcp",		TCP },
		{ "ticket",		TICKET },
		{ "timeout",		TIMEOUT },
		{ "tls",		TLS },
		{ "type",		TYPE },
		{ "types",		TYPES },
		{ "with",		WITH }
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define START_EXPAND	1
#define DONE_EXPAND	2

static int	expanding;

int
igetc(void)
{
	int	c;

	while (1) {
		if (file->ungetpos > 0)
			c = file->ungetbuf[--file->ungetpos];
		else
			c = getc(file->stream);

		if (c == START_EXPAND)
			expanding = 1;
		else if (c == DONE_EXPAND)
			expanding = 0;
		else
			break;
	}
	return (c);
}

int
lgetc(int quotec)
{
	int		c, next;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = igetc()) == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	if (c == EOF) {
		/*
		 * Fake EOL when hit EOF for the first time. This gets line
		 * count right if last line in included file is syntactically
		 * invalid and has no newline.
		 */
		if (file->eof_reached == 0) {
			file->eof_reached = 1;
			return ('\n');
		}
		while (c == EOF) {
			if (file == topfile || popfile() == EOF)
				return (EOF);
			c = igetc();
		}
	}
	return (c);
}

void
lungetc(int c)
{
	if (c == EOF)
		return;

	if (file->ungetpos >= file->ungetsize) {
		void *p = reallocarray(file->ungetbuf, file->ungetsize, 2);
		if (p == NULL)
			err(1, "%s", __func__);
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = c;
}

int
findeol(void)
{
	int	c;

	/* skip to either EOF or the first real EOL */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	char	 buf[TOKEN_STRING_MAX];
	char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && !expanding) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		p = val + strlen(val) - 1;
		lungetc(DONE_EXPAND);
		while (p >= val) {
			lungetc((unsigned char)*p);
			p--;
		}
		lungetc(START_EXPAND);
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || next == ' ' ||
				    next == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "%s", __func__);
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc((unsigned char)*--p);
			c = (unsigned char)*--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '#' && \
	x != ',' && x != ';' && x != '/'))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "%s", __func__);
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		log_warnx("%s: group writable or world read/writable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("%s", __func__);
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("%s", __func__);
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s: %s", __func__, nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	nfile->ungetsize = 16;
	nfile->ungetbuf = malloc(nfile->ungetsize);
	if (nfile->ungetbuf == NULL) {
		log_warn("%s", __func__);
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file->ungetbuf);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

int
parse_config(const char *filename, struct httpd *x_conf)
{
	struct sym		*sym, *next;
	struct media_type	 dflt = HTTPD_DEFAULT_TYPE;

	conf = x_conf;
	if (config_init(conf) == -1) {
		log_warn("%s: cannot initialize configuration", __func__);
		return (-1);
	}

	/* Set default media type */
	memcpy(&conf->sc_default_type, &dflt, sizeof(struct media_type));

	errors = 0;

	if ((file = pushfile(filename, 0)) == NULL)
		return (-1);

	topfile = file;
	setservent(1);

	yyparse();
	errors = file->errors;
	while (popfile() != EOF)
		;

	endservent();
	endprotoent();

	/* Free macros */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	return (errors ? -1 : 0);
}

int
load_config(const char *filename, struct httpd *x_conf)
{
	struct sym		*sym, *next;
	struct http_mediatype	 mediatypes[] = MEDIA_TYPES;
	struct media_type	 m;
	int			 i;

	memset(&m, 0, sizeof(m));
	conf = x_conf;
	conf->sc_flags = 0;

	loadcfg = 1;
	errors = 0;
	last_server_id = 0;
	last_auth_id = 0;

	srv = NULL;

	if ((file = pushfile(filename, 0)) == NULL)
		return (-1);

	topfile = file;
	setservent(1);

	yyparse();
	errors = file->errors;
	popfile();

	endservent();
	endprotoent();

	/* Free macros and check which have not been used. */
	for (sym = TAILQ_FIRST(&symhead); sym != NULL; sym = next) {
		next = TAILQ_NEXT(sym, entry);
		if ((conf->sc_opts & HTTPD_OPT_VERBOSE) && !sym->used)
			fprintf(stderr, "warning: macro '%s' not "
			    "used\n", sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (TAILQ_EMPTY(conf->sc_servers)) {
		log_warnx("no actions, nothing to do");
		errors++;
	}

	if (RB_EMPTY(conf->sc_mediatypes)) {
		/* Add default media types */
		for (i = 0; mediatypes[i].media_name != NULL; i++) {
			(void)strlcpy(m.media_name, mediatypes[i].media_name,
			    sizeof(m.media_name));
			(void)strlcpy(m.media_type, mediatypes[i].media_type,
			    sizeof(m.media_type));
			(void)strlcpy(m.media_subtype,
			    mediatypes[i].media_subtype,
			    sizeof(m.media_subtype));
			m.media_encoding = NULL;

			if (media_add(conf->sc_mediatypes, &m) == NULL) {
				log_warnx("failed to add default media \"%s\"",
				    m.media_name);
				errors++;
			}
		}
	}

	return (errors ? -1 : 0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);
	sym = strndup(s, val - s);
	if (sym == NULL)
		errx(1, "%s: strndup", __func__);
	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}

struct address *
host_v4(const char *s)
{
	struct in_addr		 ina;
	struct sockaddr_in	*sain;
	struct address		*h;

	memset(&ina, 0, sizeof(ina));
	if (inet_pton(AF_INET, s, &ina) != 1)
		return (NULL);

	if ((h = calloc(1, sizeof(*h))) == NULL)
		fatal(__func__);
	sain = (struct sockaddr_in *)&h->ss;
	sain->sin_len = sizeof(struct sockaddr_in);
	sain->sin_family = AF_INET;
	sain->sin_addr.s_addr = ina.s_addr;
	if (sain->sin_addr.s_addr == INADDR_ANY)
		h->prefixlen = 0; /* 0.0.0.0 address */
	else
		h->prefixlen = -1; /* host address */
	return (h);
}

struct address *
host_v6(const char *s)
{
	struct addrinfo		 hints, *res;
	struct sockaddr_in6	*sa_in6;
	struct address		*h = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM; /* dummy */
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(s, "0", &hints, &res) == 0) {
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(__func__);
		sa_in6 = (struct sockaddr_in6 *)&h->ss;
		sa_in6->sin6_len = sizeof(struct sockaddr_in6);
		sa_in6->sin6_family = AF_INET6;
		memcpy(&sa_in6->sin6_addr,
		    &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
		    sizeof(sa_in6->sin6_addr));
		sa_in6->sin6_scope_id =
		    ((struct sockaddr_in6 *)res->ai_addr)->sin6_scope_id;
		if (memcmp(&sa_in6->sin6_addr, &in6addr_any,
		    sizeof(sa_in6->sin6_addr)) == 0)
			h->prefixlen = 0; /* any address */
		else
			h->prefixlen = -1; /* host address */
		freeaddrinfo(res);
	}

	return (h);
}

int
host_dns(const char *s, struct addresslist *al, int max,
    struct portrange *port, const char *ifname, int ipproto)
{
	struct addrinfo		 hints, *res0, *res;
	int			 error, cnt = 0;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct address		*h;

	if ((cnt = host_if(s, al, max, port, ifname, ipproto)) != 0)
		return (cnt);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM; /* DUMMY */
	hints.ai_flags = AI_ADDRCONFIG;
	error = getaddrinfo(s, NULL, &hints, &res0);
	if (error == EAI_AGAIN || error == EAI_NODATA || error == EAI_NONAME)
		return (0);
	if (error) {
		log_warnx("%s: could not parse \"%s\": %s", __func__, s,
		    gai_strerror(error));
		return (-1);
	}

	for (res = res0; res && cnt < max; res = res->ai_next) {
		if (res->ai_family != AF_INET &&
		    res->ai_family != AF_INET6)
			continue;
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(__func__);

		if (port != NULL)
			memcpy(&h->port, port, sizeof(h->port));
		if (ifname != NULL) {
			if (strlcpy(h->ifname, ifname, sizeof(h->ifname)) >=
			    sizeof(h->ifname))
				log_warnx("%s: interface name truncated",
				    __func__);
			freeaddrinfo(res0);
			free(h);
			return (-1);
		}
		if (ipproto != -1)
			h->ipproto = ipproto;
		h->ss.ss_family = res->ai_family;
		h->prefixlen = -1; /* host address */

		if (res->ai_family == AF_INET) {
			sain = (struct sockaddr_in *)&h->ss;
			sain->sin_len = sizeof(struct sockaddr_in);
			sain->sin_addr.s_addr = ((struct sockaddr_in *)
			    res->ai_addr)->sin_addr.s_addr;
		} else {
			sin6 = (struct sockaddr_in6 *)&h->ss;
			sin6->sin6_len = sizeof(struct sockaddr_in6);
			memcpy(&sin6->sin6_addr, &((struct sockaddr_in6 *)
			    res->ai_addr)->sin6_addr, sizeof(struct in6_addr));
		}

		TAILQ_INSERT_HEAD(al, h, entry);
		cnt++;
	}
	if (cnt == max && res) {
		log_warnx("%s: %s resolves to more than %d hosts", __func__,
		    s, max);
	}
	freeaddrinfo(res0);
	return (cnt);
}

int
host_if(const char *s, struct addresslist *al, int max,
    struct portrange *port, const char *ifname, int ipproto)
{
	struct ifaddrs		*ifap, *p;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct address		*h;
	int			 cnt = 0, af;

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	/* First search for IPv4 addresses */
	af = AF_INET;

 nextaf:
	for (p = ifap; p != NULL && cnt < max; p = p->ifa_next) {
		if (p->ifa_addr == NULL ||
		    p->ifa_addr->sa_family != af ||
		    (strcmp(s, p->ifa_name) != 0 &&
		    !is_if_in_group(p->ifa_name, s)))
			continue;
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal("calloc");

		if (port != NULL)
			memcpy(&h->port, port, sizeof(h->port));
		if (ifname != NULL) {
			if (strlcpy(h->ifname, ifname, sizeof(h->ifname)) >=
			    sizeof(h->ifname))
				log_warnx("%s: interface name truncated",
				    __func__);
			freeifaddrs(ifap);
			free(h);
			return (-1);
		}
		if (ipproto != -1)
			h->ipproto = ipproto;
		h->ss.ss_family = af;
		h->prefixlen = -1; /* host address */

		if (af == AF_INET) {
			sain = (struct sockaddr_in *)&h->ss;
			sain->sin_len = sizeof(struct sockaddr_in);
			sain->sin_addr.s_addr = ((struct sockaddr_in *)
			    p->ifa_addr)->sin_addr.s_addr;
		} else {
			sin6 = (struct sockaddr_in6 *)&h->ss;
			sin6->sin6_len = sizeof(struct sockaddr_in6);
			memcpy(&sin6->sin6_addr, &((struct sockaddr_in6 *)
			    p->ifa_addr)->sin6_addr, sizeof(struct in6_addr));
			sin6->sin6_scope_id = ((struct sockaddr_in6 *)
			    p->ifa_addr)->sin6_scope_id;
		}

		TAILQ_INSERT_HEAD(al, h, entry);
		cnt++;
	}
	if (af == AF_INET) {
		/* Next search for IPv6 addresses */
		af = AF_INET6;
		goto nextaf;
	}

	if (cnt > max) {
		log_warnx("%s: %s resolves to more than %d hosts", __func__,
		    s, max);
	}
	freeifaddrs(ifap);
	return (cnt);
}

int
host(const char *s, struct addresslist *al, int max,
    struct portrange *port, const char *ifname, int ipproto)
{
	struct address *h;

	h = host_v4(s);

	/* IPv6 address? */
	if (h == NULL)
		h = host_v6(s);

	if (h != NULL) {
		if (port != NULL)
			memcpy(&h->port, port, sizeof(h->port));
		if (ifname != NULL) {
			if (strlcpy(h->ifname, ifname, sizeof(h->ifname)) >=
			    sizeof(h->ifname)) {
				log_warnx("%s: interface name truncated",
				    __func__);
				free(h);
				return (-1);
			}
		}
		if (ipproto != -1)
			h->ipproto = ipproto;

		TAILQ_INSERT_HEAD(al, h, entry);
		return (1);
	}

	return (host_dns(s, al, max, port, ifname, ipproto));
}

int
header_name_forbidden(const char *name)
{
	if (*name == '\0') {
		yyerror("empty header name");
		return (1);
	}

	if (strcasecmp(name, "Content-Length") == 0 ||
	    strcasecmp(name, "Transfer-Encoding") == 0 ||
	    strcasecmp(name, "Connection") == 0 ||
	    strcasecmp(name, "Date") == 0) {
		yyerror("header \"%s\" is reserved and cannot be used", name);
		return (1);
	}

	if (strcasecmp(name, "Server") == 0) {
		yyerror("header \"Server\" cannot be configured here, "
		    "use 'no banner' instead");
		return (1);
	}
	return (0);
}

struct server *
server_inherit(struct server *src, struct server_config *alias,
    struct server_config *addr)
{
	struct server	*dst, *s, *dstl;
	struct custom_header	*hdr, *nhdr;
	struct header_rule *rule, *nrule;

	if ((dst = calloc(1, sizeof(*dst))) == NULL)
		fatal("out of memory");

	/* Copy the source server and assign a new Id */
	memcpy(&dst->srv_conf, &src->srv_conf, sizeof(dst->srv_conf));

	TAILQ_INIT(&dst->srv_conf.headers);
	TAILQ_FOREACH(hdr, &src->srv_conf.headers, entry) {
		nhdr = header_dup(hdr);
		TAILQ_INSERT_TAIL(&dst->srv_conf.headers, nhdr, entry);
	}

	TAILQ_INIT(&dst->srv_conf.header_rules);
	TAILQ_FOREACH(rule, &src->srv_conf.header_rules, entry) {
		nrule = header_rule_dup(rule);
		TAILQ_INSERT_TAIL(&dst->srv_conf.header_rules, nrule, entry);
	}

	if ((dst->srv_conf.tls_cert_file =
	    strdup(src->srv_conf.tls_cert_file)) == NULL)
		fatal("out of memory");
	if ((dst->srv_conf.tls_key_file =
	    strdup(src->srv_conf.tls_key_file)) == NULL)
		fatal("out of memory");
	if (src->srv_conf.tls_ocsp_staple_file != NULL) {
		if ((dst->srv_conf.tls_ocsp_staple_file =
		    strdup(src->srv_conf.tls_ocsp_staple_file)) == NULL)
			fatal("out of memory");
	}

	if (src->srv_conf.return_uri != NULL &&
	    (dst->srv_conf.return_uri =
	    strdup(src->srv_conf.return_uri)) == NULL)
		fatal("out of memory");

	dst->srv_conf.id = ++last_server_id;
	dst->srv_conf.parent_id = dst->srv_conf.id;
	dst->srv_s = -1;

	if (last_server_id == INT_MAX) {
		yyerror("too many servers defined");
		serverconfig_free(&dst->srv_conf);
		free(dst);
		return (NULL);
	}

	/* Now set alias and listen address */
	strlcpy(dst->srv_conf.name, alias->name, sizeof(dst->srv_conf.name));
	memcpy(&dst->srv_conf.ss, &addr->ss, sizeof(dst->srv_conf.ss));
	dst->srv_conf.port = addr->port;
	dst->srv_conf.prefixlen = addr->prefixlen;
	if (addr->flags & SRVFLAG_TLS)
		dst->srv_conf.flags |= SRVFLAG_TLS;
	else
		dst->srv_conf.flags &= ~SRVFLAG_TLS;

	/* Don't inherit the "match" option, use it from the alias */
	dst->srv_conf.flags &= ~SRVFLAG_SERVER_MATCH;
	dst->srv_conf.flags |= (alias->flags & SRVFLAG_SERVER_MATCH);

	if (server_tls_load_keypair(dst) == -1)
		log_warnx("%s:%d: server \"%s\": failed to "
		    "load public/private keys", file->name,
		    yylval.lineno, dst->srv_conf.name);

	if (server_tls_load_ca(dst) == -1) {
		yyerror("failed to load ca cert(s) for server %s",
		    dst->srv_conf.name);
		serverconfig_free(&dst->srv_conf);
		return NULL;
	}

	if (server_tls_load_crl(dst) == -1) {
		yyerror("failed to load crl(s) for server %s",
		    dst->srv_conf.name);
		serverconfig_free(&dst->srv_conf);
		free(dst);
		return NULL;
	}

	if (server_tls_load_ocsp(dst) == -1) {
		yyerror("failed to load ocsp staple "
		    "for server %s", dst->srv_conf.name);
		serverconfig_free(&dst->srv_conf);
		free(dst);
		return (NULL);
	}

	/* Check if the new server already exists */
	if (server_match(dst, 1) != NULL) {
		yyerror("server \"%s\" defined twice",
		    dst->srv_conf.name);
		serverconfig_free(&dst->srv_conf);
		free(dst);
		return (NULL);
	}

	/* Copy all the locations of the source server */
	TAILQ_FOREACH(s, conf->sc_servers, srv_entry) {
		if (!(s->srv_conf.flags & SRVFLAG_LOCATION &&
		    s->srv_conf.parent_id == src->srv_conf.parent_id))
			continue;

		if ((dstl = calloc(1, sizeof(*dstl))) == NULL)
			fatal("out of memory");

		memcpy(&dstl->srv_conf, &s->srv_conf, sizeof(dstl->srv_conf));

		/* Copy custom headers from source location */
		TAILQ_INIT(&dstl->srv_conf.headers);
		TAILQ_FOREACH(hdr, &s->srv_conf.headers, entry) {
			nhdr = header_dup(hdr);
			TAILQ_INSERT_TAIL(&dstl->srv_conf.headers, nhdr, entry);
		}

		/* Copy header rules from source location */
		TAILQ_INIT(&dstl->srv_conf.header_rules);
		TAILQ_FOREACH(rule, &s->srv_conf.header_rules, entry) {
			nrule = header_rule_dup(rule);
			TAILQ_INSERT_TAIL(&dstl->srv_conf.header_rules, nrule, entry);
		}

		strlcpy(dstl->srv_conf.name, alias->name,
		    sizeof(dstl->srv_conf.name));

		/* Copy the new Id and listen address */
		dstl->srv_conf.id = ++last_server_id;
		dstl->srv_conf.parent_id = dst->srv_conf.id;
		memcpy(&dstl->srv_conf.ss, &addr->ss,
		    sizeof(dstl->srv_conf.ss));
		dstl->srv_conf.port = addr->port;
		dstl->srv_conf.prefixlen = addr->prefixlen;
		dstl->srv_s = -1;

		DPRINTF("adding location \"%s\" for \"%s[%u]\"",
		    dstl->srv_conf.location,
		    dstl->srv_conf.name, dstl->srv_conf.id);

		TAILQ_INSERT_TAIL(conf->sc_servers, dstl, srv_entry);
	}

	return (dst);
}

int
listen_on(const char *addr, int tls, struct portrange *port)
{
	struct addresslist	 al;
	struct address		*h;
	struct server_config	*s_conf, *alias = NULL;

	if (parentsrv != NULL) {
		yyerror("listen %s inside location", addr);
		return (-1);
	}

	TAILQ_INIT(&al);
	if (strcmp("*", addr) == 0) {
		if (host("0.0.0.0", &al, 1, port, NULL, -1) <= 0) {
			yyerror("invalid listen ip: %s",
			    "0.0.0.0");
			return (-1);
		}
		if (host("::", &al, 1, port, NULL, -1) <= 0) {
			yyerror("invalid listen ip: %s", "::");
			return (-1);
		}
	} else {
		if (host(addr, &al, HTTPD_MAX_ALIAS_IP, port, NULL,
		    -1) <= 0) {
			yyerror("invalid listen ip: %s", addr);
			return (-1);
		}
	}

	while ((h = TAILQ_FIRST(&al)) != NULL) {
		if (srv->srv_conf.ss.ss_family != AF_UNSPEC) {
			if ((alias = calloc(1,
			    sizeof(*alias))) == NULL)
				fatal("out of memory");
				/* Add as an IP-based alias. */
			s_conf = alias;
		} else
			s_conf = &srv->srv_conf;
		memcpy(&s_conf->ss, &h->ss, sizeof(s_conf->ss));
		s_conf->prefixlen = h->prefixlen;
		/* Set the default port to 80 or 443 */
		if (!h->port.op)
			s_conf->port = htons(tls ?
			    HTTPS_PORT : HTTP_PORT);
		else
			s_conf->port = h->port.val[0];

		if (tls)
			s_conf->flags |= SRVFLAG_TLS;

		if (alias != NULL) {
			/*
			 * IP-based; use name match flags from
			 * parent
			 */
			alias->flags &= ~SRVFLAG_SERVER_MATCH;
			alias->flags |= srv->srv_conf.flags &
			    SRVFLAG_SERVER_MATCH;
			TAILQ_INSERT_TAIL(&srv->srv_hosts,
			    alias, entry);
		}
		TAILQ_REMOVE(&al, h, entry);
		free(h);
	}

	return (0);
}

int
getservice(char *n)
{
	struct servent	*s;
	const char	*errstr;
	long long	 llval;

	llval = strtonum(n, 0, UINT16_MAX, &errstr);
	if (errstr) {
		s = getservbyname(n, "tcp");
		if (s == NULL)
			s = getservbyname(n, "udp");
		if (s == NULL)
			return (-1);
		return (s->s_port);
	}

	return (htons((unsigned short)llval));
}

int
is_if_in_group(const char *ifname, const char *groupname)
{
	unsigned int		 len;
	struct ifgroupreq	 ifgr;
	struct ifg_req		*ifg;
	int			 s;
	int			 ret = 0;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");

	memset(&ifgr, 0, sizeof(ifgr));
	if (strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ) >= IFNAMSIZ)
		err(1, "IFNAMSIZ");
	if (ioctl(s, SIOCGIFGROUP, (caddr_t)&ifgr) == -1) {
		if (errno == EINVAL || errno == ENOTTY)
			goto end;
		err(1, "SIOCGIFGROUP");
	}

	len = ifgr.ifgr_len;
	ifgr.ifgr_groups = calloc(len / sizeof(struct ifg_req),
	    sizeof(struct ifg_req));
	if (ifgr.ifgr_groups == NULL)
		err(1, "getifgroups");
	if (ioctl(s, SIOCGIFGROUP, (caddr_t)&ifgr) == -1)
		err(1, "SIOCGIFGROUP");

	ifg = ifgr.ifgr_groups;
	for (; ifg && len >= sizeof(struct ifg_req); ifg++) {
		len -= sizeof(struct ifg_req);
		if (strcmp(ifg->ifgrq_group, groupname) == 0) {
			ret = 1;
			break;
		}
	}
	free(ifgr.ifgr_groups);

end:
	close(s);
	return (ret);
}

int
get_fastcgi_dest(struct server_config *xsrv_conf, const char *node, char *port)
{
	struct addrinfo		 hints, *res;
	int			 s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((s = getaddrinfo(node, port, &hints, &res)) != 0) {
		yyerror("getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}

	memset(&(xsrv_conf)->fastcgi_ss, 0, sizeof(xsrv_conf->fastcgi_ss));
	memcpy(&(xsrv_conf)->fastcgi_ss, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);

	return (0);
}

void
remove_locations(struct server_config *xsrv_conf)
{
	struct server *s, *next;

	TAILQ_FOREACH_SAFE(s, conf->sc_servers, srv_entry, next) {
		if (!(s->srv_conf.flags & SRVFLAG_LOCATION &&
		    s->srv_conf.parent_id == xsrv_conf->parent_id))
			continue;
		TAILQ_REMOVE(conf->sc_servers, s, srv_entry);
		serverconfig_free(&s->srv_conf);
		free(s);
	}
}
#line 2138 "parse.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(void)
{
    unsigned int newsize;
    long sslen;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    sslen = yyssp - yyss;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#define YY_SIZE_MAX 0xffffffffU
#endif
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    newss = (short *)realloc(yyss, newsize * sizeof *newss);
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + sslen;
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newvs)
        goto bail;
    newvs = (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs);
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + sslen;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
bail:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return -1;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
yyparse(void)
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif /* YYDEBUG */

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 8:
#line 179 "parse.y"
{ file->errors++; }
break;
case 9:
#line 182 "parse.y"
{
			struct file	*nfile;

			if ((nfile = pushfile(yyvsp[0].v.string, 0)) == NULL) {
				yyerror("failed to include file %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			file = nfile;
			lungetc('\n');
		}
break;
case 10:
#line 197 "parse.y"
{
			char *s = yyvsp[-2].v.string;
			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					free(yyvsp[-2].v.string);
					free(yyvsp[0].v.string);
					YYERROR;
				}
			}
			if (symset(yyvsp[-2].v.string, yyvsp[0].v.string, 0) == -1)
				fatal("cannot store variable");
			free(yyvsp[-2].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 11:
#line 215 "parse.y"
{ yyval.v.number = 0; }
break;
case 12:
#line 216 "parse.y"
{ yyval.v.number = 1; }
break;
case 13:
#line 219 "parse.y"
{
			if (loadcfg)
				break;
			if (yyvsp[0].v.number <= 0 || yyvsp[0].v.number > PROC_MAX_INSTANCES) {
				yyerror("invalid number of preforked "
				    "servers: %lld", yyvsp[0].v.number);
				YYERROR;
			}
			conf->sc_prefork_server = yyvsp[0].v.number;
		}
break;
case 14:
#line 229 "parse.y"
{
			conf->sc_chroot = yyvsp[0].v.string;
		}
break;
case 15:
#line 232 "parse.y"
{
			if (yyvsp[0].v.string != NULL && strlcpy(conf->sc_errdocroot, yyvsp[0].v.string,
			    sizeof(conf->sc_errdocroot)) >=
			    sizeof(conf->sc_errdocroot)) {
				yyerror("errdoc root path too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			conf->sc_custom_errdocs = 1;
		}
break;
case 16:
#line 243 "parse.y"
{
			conf->sc_logdir = yyvsp[0].v.string;
		}
break;
case 17:
#line 246 "parse.y"
{
			conf->sc_flags |= SRVFLAG_NO_BANNER;
		}
break;
case 18:
#line 249 "parse.y"
{
			memcpy(&conf->sc_default_type, &media,
			    sizeof(struct media_type));
		}
break;
case 19:
#line 255 "parse.y"
{
			struct server		*s;
			struct sockaddr_un	*sun;

			if (!loadcfg) {
				free(yyvsp[0].v.string);
				YYACCEPT;
			}

			if ((s = calloc(1, sizeof (*s))) == NULL)
				fatal("out of memory");

			if (strlcpy(s->srv_conf.name, yyvsp[0].v.string,
			    sizeof(s->srv_conf.name)) >=
			    sizeof(s->srv_conf.name)) {
				yyerror("server name truncated");
				free(yyvsp[0].v.string);
				free(s);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			strlcpy(s->srv_conf.root, HTTPD_DOCROOT,
			    sizeof(s->srv_conf.root));
			strlcpy(s->srv_conf.index, HTTPD_INDEX,
			    sizeof(s->srv_conf.index));
			strlcpy(s->srv_conf.accesslog, HTTPD_ACCESS_LOG,
			    sizeof(s->srv_conf.accesslog));
			strlcpy(s->srv_conf.errorlog, HTTPD_ERROR_LOG,
			    sizeof(s->srv_conf.errorlog));
			s->srv_conf.id = ++last_server_id;
			s->srv_conf.parent_id = s->srv_conf.id;
			s->srv_s = -1;
			s->srv_conf.timeout.tv_sec = SERVER_TIMEOUT;
			s->srv_conf.requesttimeout.tv_sec =
			    SERVER_REQUESTTIMEOUT;
			s->srv_conf.maxrequests = SERVER_MAXREQUESTS;
			s->srv_conf.maxrequestbody = SERVER_MAXREQUESTBODY;
			s->srv_conf.flags = SRVFLAG_LOG |
			    SRVFLAG_STATIC_CACHE_CONTROL;
			if (yyvsp[-1].v.number)
				s->srv_conf.flags |= SRVFLAG_SERVER_MATCH;
			s->srv_conf.logformat = LOG_FORMAT_COMMON;
			s->srv_conf.tls_protocols = TLS_PROTOCOLS_DEFAULT;
			if ((s->srv_conf.tls_cert_file =
			    strdup(HTTPD_TLS_CERT)) == NULL)
				fatal("out of memory");
			if ((s->srv_conf.tls_key_file =
			    strdup(HTTPD_TLS_KEY)) == NULL)
				fatal("out of memory");
			strlcpy(s->srv_conf.tls_ciphers,
			    HTTPD_TLS_CIPHERS,
			    sizeof(s->srv_conf.tls_ciphers));
			strlcpy(s->srv_conf.tls_dhe_params,
			    HTTPD_TLS_DHE_PARAMS,
			    sizeof(s->srv_conf.tls_dhe_params));
			strlcpy(s->srv_conf.tls_ecdhe_curves,
			    HTTPD_TLS_ECDHE_CURVES,
			    sizeof(s->srv_conf.tls_ecdhe_curves));

			sun = (struct sockaddr_un *)&s->srv_conf.fastcgi_ss;
			sun->sun_family = AF_UNIX;
			(void)strlcpy(sun->sun_path, HTTPD_FCGI_SOCKET,
			    sizeof(sun->sun_path));
			sun->sun_len = sizeof(struct sockaddr_un);

			s->srv_conf.hsts_max_age = SERVER_HSTS_DEFAULT_AGE;

			if (conf->sc_flags & SRVFLAG_NO_BANNER)
				s->srv_conf.flags |= SRVFLAG_NO_BANNER;

			(void)strlcpy(s->srv_conf.errdocroot,
			    conf->sc_errdocroot,
			    sizeof(s->srv_conf.errdocroot));
			if (conf->sc_custom_errdocs)
				s->srv_conf.flags |= SRVFLAG_ERRDOCS;

			if (last_server_id == INT_MAX) {
				yyerror("too many servers defined");
				free(s);
				YYERROR;
			}
			srv = s;
			srv_conf = &srv->srv_conf;

			SPLAY_INIT(&srv->srv_clients);
			TAILQ_INIT(&srv->srv_hosts);
			TAILQ_INIT(&srv_conf->fcgiparams);
			TAILQ_INIT(&srv_conf->headers);
			TAILQ_INIT(&srv_conf->header_rules);

			TAILQ_INSERT_TAIL(&srv->srv_hosts, srv_conf, entry);
		}
break;
case 20:
#line 347 "parse.y"
{
			struct server		*s, *sn;
			struct server_config	*a, *b;

			srv_conf = &srv->srv_conf;

			/* Check if the new server already exists. */
			if (server_match(srv, 1) != NULL) {
				yyerror("server \"%s\" defined twice",
				    srv->srv_conf.name);
				serverconfig_free(srv_conf);
				free(srv);
				YYABORT;
			}

			if (srv->srv_conf.ss.ss_family == AF_UNSPEC) {
				yyerror("listen address not specified");
				serverconfig_free(srv_conf);
				free(srv);
				YYERROR;
			}

			if ((s = server_match(srv, 0)) != NULL) {
				if ((s->srv_conf.flags & SRVFLAG_TLS) !=
				    (srv->srv_conf.flags & SRVFLAG_TLS)) {
					yyerror("server \"%s\": tls and "
					    "non-tls on same address/port",
					    srv->srv_conf.name);
					serverconfig_free(srv_conf);
					free(srv);
					YYERROR;
				}
				if (srv->srv_conf.flags & SRVFLAG_TLS &&
				    server_tls_cmp(s, srv) != 0) {
					yyerror("server \"%s\": tls "
					    "configuration mismatch on same "
					    "address/port",
					    srv->srv_conf.name);
					serverconfig_free(srv_conf);
					free(srv);
					YYERROR;
				}
			}

			if ((srv->srv_conf.flags & SRVFLAG_TLS) &&
			    srv->srv_conf.tls_protocols == 0) {
				yyerror("server \"%s\": no tls protocols",
				    srv->srv_conf.name);
				serverconfig_free(srv_conf);
				free(srv);
				YYERROR;
			}

			if (server_tls_load_keypair(srv) == -1) {
				/* Soft fail as there may be no certificate. */
				log_warnx("%s:%d: server \"%s\": failed to "
				    "load public/private keys", file->name,
				    yylval.lineno, srv->srv_conf.name);

				remove_locations(srv_conf);
				serverconfig_free(srv_conf);
				srv_conf = NULL;
				free(srv);
				srv = NULL;
				break;
			}

			if (server_tls_load_ca(srv) == -1) {
				yyerror("server \"%s\": failed to load "
				    "ca cert(s)", srv->srv_conf.name);
				serverconfig_free(srv_conf);
				free(srv);
				YYERROR;
			}

			if (server_tls_load_crl(srv) == -1) {
				yyerror("server \"%s\": failed to load crl(s)",
				    srv->srv_conf.name);
				serverconfig_free(srv_conf);
				free(srv);
				YYERROR;
			}

			if (server_tls_load_ocsp(srv) == -1) {
				yyerror("server \"%s\": failed to load "
				    "ocsp staple", srv->srv_conf.name);
				serverconfig_free(srv_conf);
				free(srv);
				YYERROR;
			}

			DPRINTF("adding server \"%s[%u]\"",
			    srv->srv_conf.name, srv->srv_conf.id);

			TAILQ_INSERT_TAIL(conf->sc_servers, srv, srv_entry);

			/*
			 * Add aliases and additional listen addresses as
			 * individual servers.
			 */
			TAILQ_FOREACH(a, &srv->srv_hosts, entry) {
				/* listen address */
				if (a->ss.ss_family == AF_UNSPEC)
					continue;
				TAILQ_FOREACH(b, &srv->srv_hosts, entry) {
					/* alias name */
					if (*b->name == '\0' ||
					    (b == &srv->srv_conf && b == a))
						continue;

					if ((sn = server_inherit(srv,
					    b, a)) == NULL) {
						serverconfig_free(srv_conf);
						free(srv);
						YYABORT;
					}

					DPRINTF("adding server \"%s[%u]\"",
					    sn->srv_conf.name, sn->srv_conf.id);

					TAILQ_INSERT_TAIL(conf->sc_servers,
					    sn, srv_entry);
				}
			}

			/* Remove temporary aliases */
			TAILQ_FOREACH_SAFE(a, &srv->srv_hosts, entry, b) {
				TAILQ_REMOVE(&srv->srv_hosts, a, entry);
				if (a == &srv->srv_conf)
					continue;
				serverconfig_free(a);
				free(a);
			}

			srv = NULL;
			srv_conf = NULL;
		}
break;
case 23:
#line 490 "parse.y"
{
			if (listen_on(yyvsp[-2].v.string, yyvsp[-1].v.number, &yyvsp[0].v.port) == -1) {
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
		}
break;
case 24:
#line 497 "parse.y"
{
			struct server_config	*alias;

			if (parentsrv != NULL) {
				yyerror("alias inside location");
				free(yyvsp[0].v.string);
				YYERROR;
			}

			if ((alias = calloc(1, sizeof(*alias))) == NULL)
				fatal("out of memory");

			if (strlcpy(alias->name, yyvsp[0].v.string, sizeof(alias->name)) >=
			    sizeof(alias->name)) {
				yyerror("server alias truncated");
				free(yyvsp[0].v.string);
				free(alias);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			if (yyvsp[-1].v.number)
				alias->flags |= SRVFLAG_SERVER_MATCH;

			TAILQ_INSERT_TAIL(&srv->srv_hosts, alias, entry);
		}
break;
case 25:
#line 523 "parse.y"
{
			if (parentsrv != NULL) {
				yyerror("errdocs inside location");
				YYERROR;
			}
			if (yyvsp[0].v.string != NULL && strlcpy(srv->srv_conf.errdocroot, yyvsp[0].v.string,
			    sizeof(srv->srv_conf.errdocroot)) >=
			    sizeof(srv->srv_conf.errdocroot)) {
				yyerror("errdoc root path too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			srv->srv_conf.flags |= SRVFLAG_ERRDOCS;
		}
break;
case 26:
#line 538 "parse.y"
{
			if (parentsrv != NULL) {
				yyerror("errdocs inside location");
				YYERROR;
			}
			srv->srv_conf.flags &= ~SRVFLAG_ERRDOCS;
		}
break;
case 27:
#line 545 "parse.y"
{
			if (parentsrv != NULL) {
				yyerror("tcp flags inside location");
				YYERROR;
			}
		}
break;
case 28:
#line 551 "parse.y"
{
			if (parentsrv != NULL) {
				yyerror("connection options inside location");
				YYERROR;
			}
		}
break;
case 29:
#line 557 "parse.y"
{
			struct server_config	*sc;
			int			 tls_flag = 0;

			if (parentsrv != NULL) {
				yyerror("tls configuration inside location");
				YYERROR;
			}

			/* Ensure that at least one server has TLS enabled. */
			TAILQ_FOREACH(sc, &srv->srv_hosts, entry) {
				tls_flag |= (sc->flags & SRVFLAG_TLS);
			}
			if (tls_flag == 0) {
				yyerror("tls options without tls listener");
				YYERROR;
			}
		}
break;
case 41:
#line 586 "parse.y"
{
			struct server		*s;
			struct sockaddr_un	*sun;

			if (srv->srv_conf.ss.ss_family == AF_UNSPEC) {
				yyerror("listen address not specified");
				free(yyvsp[0].v.string);
				YYERROR;
			}

			if (parentsrv != NULL) {
				yyerror("location %s inside location", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}

			if (!loadcfg) {
				free(yyvsp[0].v.string);
				YYACCEPT;
			}

			if ((s = calloc(1, sizeof (*s))) == NULL)
				fatal("out of memory");

			if (strlcpy(s->srv_conf.location, yyvsp[0].v.string,
			    sizeof(s->srv_conf.location)) >=
			    sizeof(s->srv_conf.location)) {
				yyerror("server location truncated");
				free(yyvsp[0].v.string);
				free(s);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			if (strlcpy(s->srv_conf.name, srv->srv_conf.name,
			    sizeof(s->srv_conf.name)) >=
			    sizeof(s->srv_conf.name)) {
				yyerror("server name truncated");
				free(s);
				YYERROR;
			}

			sun = (struct sockaddr_un *)&s->srv_conf.fastcgi_ss;
			sun->sun_family = AF_UNIX;
			(void)strlcpy(sun->sun_path, HTTPD_FCGI_SOCKET,
			    sizeof(sun->sun_path));
			sun->sun_len = sizeof(struct sockaddr_un);

			s->srv_conf.id = ++last_server_id;
			/* A location entry uses the parent id */
			s->srv_conf.parent_id = srv->srv_conf.id;
			s->srv_conf.flags = SRVFLAG_LOCATION;
			if (yyvsp[-2].v.number == 1) {
				s->srv_conf.flags &=
				    ~SRVFLAG_LOCATION_NOT_FOUND;
				s->srv_conf.flags |=
				    SRVFLAG_LOCATION_FOUND;
			} else if (yyvsp[-2].v.number == -1) {
				s->srv_conf.flags &=
				    ~SRVFLAG_LOCATION_FOUND;
				s->srv_conf.flags |=
				    SRVFLAG_LOCATION_NOT_FOUND;
			}
			if (yyvsp[-1].v.number)
				s->srv_conf.flags |= SRVFLAG_LOCATION_MATCH;
			s->srv_s = -1;
			memcpy(&s->srv_conf.ss, &srv->srv_conf.ss,
			    sizeof(s->srv_conf.ss));
			s->srv_conf.port = srv->srv_conf.port;
			s->srv_conf.prefixlen = srv->srv_conf.prefixlen;
			s->srv_conf.tls_flags = srv->srv_conf.tls_flags;

			if (last_server_id == INT_MAX) {
				yyerror("too many servers/locations defined");
				free(s);
				YYERROR;
			}
			parentsrv = srv;
			srv = s;
			srv_conf = &srv->srv_conf;
			SPLAY_INIT(&srv->srv_clients);
			TAILQ_INIT(&srv_conf->headers);
			TAILQ_INIT(&srv_conf->header_rules);
			TAILQ_INIT(&srv_conf->fcgiparams);
		}
break;
case 42:
#line 670 "parse.y"
{
			struct server	*s = NULL;
			uint64_t	 f;

			f = SRVFLAG_LOCATION_FOUND |
			    SRVFLAG_LOCATION_NOT_FOUND;

			TAILQ_FOREACH(s, conf->sc_servers, srv_entry) {
				/* Compare locations of same parent server */
				if ((s->srv_conf.flags & SRVFLAG_LOCATION) &&
				    s->srv_conf.parent_id ==
				    srv_conf->parent_id &&
				    (s->srv_conf.flags & f) ==
				    (srv_conf->flags & f) &&
				    strcmp(s->srv_conf.location,
				    srv_conf->location) == 0)
					break;
			}
			if (s != NULL) {
				yyerror("location \"%s\" defined twice",
				    srv->srv_conf.location);
				serverconfig_free(srv_conf);
				free(srv);
				YYABORT;
			}

			DPRINTF("adding location \"%s\" for \"%s[%u]\"",
			    srv->srv_conf.location,
			    srv->srv_conf.name, srv->srv_conf.id);

			TAILQ_INSERT_TAIL(conf->sc_servers, srv, srv_entry);

			srv = parentsrv;
			srv_conf = &parentsrv->srv_conf;
			parentsrv = NULL;
		}
break;
case 43:
#line 706 "parse.y"
{
			srv_conf->flags |= SRVFLAG_DEFAULT_TYPE;
			memcpy(&srv_conf->default_type, &media,
			    sizeof(struct media_type));
		}
break;
case 45:
#line 712 "parse.y"
{
			if (parentsrv != NULL) {
				yyerror("hsts inside location");
				YYERROR;
			}
			srv->srv_conf.flags |= SRVFLAG_SERVER_HSTS;
		}
break;
case 46:
#line 721 "parse.y"
{
			if (parentsrv != NULL) {
				yyerror("banner inside location");
				YYERROR;
			}
			srv->srv_conf.flags &= ~SRVFLAG_NO_BANNER;
		}
break;
case 47:
#line 728 "parse.y"
{
			if (parentsrv != NULL) {
				yyerror("no banner inside location");
				YYERROR;
			}
			srv->srv_conf.flags |= SRVFLAG_NO_BANNER;
		}
break;
case 48:
#line 738 "parse.y"
{ yyval.v.number = 0; }
break;
case 49:
#line 739 "parse.y"
{ yyval.v.number = 1; }
break;
case 50:
#line 742 "parse.y"
{
			struct custom_header	*hdr;

			if (strlen(yyvsp[-1].v.string) > HTTPD_HEADER_NAME_MAX - 1) {
				yyerror("header name too long (max %d)",
				    HTTPD_HEADER_NAME_MAX - 1);
				free(yyvsp[-1].v.string);
				YYERROR;
			}

			if (header_name_forbidden(yyvsp[-1].v.string)) {
				free(yyvsp[-1].v.string);
				YYERROR;
			}

			if ((hdr = calloc(1, sizeof(*hdr))) == NULL)
				fatal("out of memory");

			hdr->name = yyvsp[-1].v.string;
			if ((hdr->value = strdup("")) == NULL)	/* never NULL */
				fatal("out of memory");

			hdr->flags = HEADER_REMOVE;
			if (yyvsp[0].v.number)
				hdr->flags |= HEADER_ALWAYS;
			TAILQ_INSERT_TAIL(&srv->srv_conf.headers, hdr, entry);
		}
break;
case 51:
#line 769 "parse.y"
{
			struct custom_header	*hdr;

			if (strlen(yyvsp[-2].v.string) > HTTPD_HEADER_NAME_MAX - 1) {
				yyerror("header name too long (max %d)",
				    HTTPD_HEADER_NAME_MAX - 1);
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (header_name_forbidden(yyvsp[-2].v.string)) {
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (strlen(yyvsp[-1].v.string) > HTTPD_HEADER_VAL_MAX - 1) {
				yyerror("header value too long (max %d)",
				    HTTPD_HEADER_VAL_MAX - 1);
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}

			if ((hdr = calloc(1, sizeof(*hdr))) == NULL)
				fatal("out of memory");

			hdr->name = yyvsp[-2].v.string;
			hdr->value = yyvsp[-1].v.string;

			hdr->flags = HEADER_ADD;
			if (yyvsp[0].v.number)
				hdr->flags |= HEADER_ALWAYS;
			TAILQ_INSERT_TAIL(&srv->srv_conf.headers, hdr, entry);
		}
break;
case 52:
#line 803 "parse.y"
{
			struct custom_header	*hdr;

			if (strlen(yyvsp[-2].v.string) > HTTPD_HEADER_NAME_MAX - 1) {
				yyerror("header name too long (max %d)",
				    HTTPD_HEADER_NAME_MAX - 1);
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (header_name_forbidden(yyvsp[-2].v.string)) {
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (strlen(yyvsp[-1].v.string) > HTTPD_HEADER_VAL_MAX - 1) {
				yyerror("header value too long (max %d)",
				    HTTPD_HEADER_VAL_MAX - 1);
				free(yyvsp[-2].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}

			if ((hdr = calloc(1, sizeof(*hdr))) == NULL)
				fatal("out of memory");

			hdr->name = yyvsp[-2].v.string;
			hdr->value = yyvsp[-1].v.string;

			hdr->flags = HEADER_SET;
			if (yyvsp[0].v.number)
				hdr->flags |= HEADER_ALWAYS;
			TAILQ_INSERT_TAIL(&srv->srv_conf.headers, hdr, entry);
		}
break;
case 53:
#line 837 "parse.y"
{
			struct header_rule	*hrule;

			if ((hrule= calloc(1, sizeof(*hrule))) == NULL)
				fatal("out of memory");

			hrule->action = HEADER_ACTION_RETURN;

			hrule->name = yyvsp[-3].v.string;
			hrule->value = yyvsp[-2].v.string;

			if (yyvsp[-1].v.number < 100 || yyvsp[-1].v.number >= 600) {
				log_warn("header rule return code number is "
				"outside of a valid range");
			}

			hrule->return_code = yyvsp[-1].v.number;

			if (hrule->return_code >= 300 &&
			    hrule->return_code <= 399) {
				hrule->action = HEADER_ACTION_RDR;
			}

			switch (hrule->action) {
			case HEADER_ACTION_DROP:
				/* Handeled in header drop sysntax */
				break;
			case HEADER_ACTION_RDR:
				if (yyvsp[0].v.string == NULL) {
					yyerror("missing return URI");
					free(yyvsp[0].v.string);
					free(hrule->name);
					free(hrule->value);
					free(hrule);
					YYERROR;
				}
				hrule->return_uri = yyvsp[0].v.string;
				break;
			case HEADER_ACTION_RETURN:
				hrule->return_uri = (yyvsp[0].v.string != NULL) ? yyvsp[0].v.string :
				strdup("blocked");
				if (hrule->return_uri == NULL) {
					yyerror("out of memory");
					free(hrule->name);
					free(hrule->value);
					free(hrule);
					YYERROR;
				}
				break;
			default:
				break;
			}

			if (hrule->action == HEADER_ACTION_RDR &&
			    (strncmp(hrule->return_uri, "http://", 7) != 0 &&
			     strncmp(hrule->return_uri, "https://", 8) != 0)) {
				yyerror("Redirect URI does not start with "
				"http:// or https://");
				free(hrule->name);
				free(hrule->value);
				free(hrule->return_uri);
				free(hrule);
				YYERROR;
			}

			TAILQ_INSERT_TAIL(&srv->srv_conf.header_rules, hrule, entry);
		}
break;
case 54:
#line 904 "parse.y"
{
			struct header_rule	*hrule;

			if ((hrule= calloc(1, sizeof(*hrule))) == NULL)
				fatal("out of memory");

			hrule->action = HEADER_ACTION_DROP;
			if ((hrule->return_uri = strdup("dropped")) == NULL) {
				yyerror("out of memory");
				free(hrule);
				YYERROR;
			}

			hrule->name = yyvsp[-1].v.string;
			hrule->value = yyvsp[0].v.string;

			TAILQ_INSERT_TAIL(&srv->srv_conf.header_rules, hrule, entry);
		}
break;
case 55:
#line 924 "parse.y"
{ yyval.v.number = 0; }
break;
case 56:
#line 925 "parse.y"
{ yyval.v.number = 1; }
break;
case 57:
#line 926 "parse.y"
{ yyval.v.number = -1; }
break;
case 63:
#line 938 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("invalid number of seconds: %lld", yyvsp[0].v.number);
				YYERROR;
			}
			srv_conf->hsts_max_age = yyvsp[0].v.number;
		}
break;
case 64:
#line 945 "parse.y"
{
			srv->srv_conf.hsts_flags |= HSTSFLAG_SUBDOMAINS;
		}
break;
case 65:
#line 948 "parse.y"
{
			srv->srv_conf.hsts_flags |= HSTSFLAG_PRELOAD;
		}
break;
case 66:
#line 953 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_FCGI;
			srv_conf->flags |= SRVFLAG_NO_FCGI;
		}
break;
case 67:
#line 957 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_FCGI;
			srv_conf->flags |= SRVFLAG_FCGI;
		}
break;
case 68:
#line 961 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_FCGI;
			srv_conf->flags |= SRVFLAG_FCGI;
		}
break;
case 70:
#line 965 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_FCGI;
			srv_conf->flags |= SRVFLAG_FCGI;
		}
break;
case 74:
#line 975 "parse.y"
{
			struct sockaddr_un *sun;
			sun = (struct sockaddr_un *)&srv_conf->fastcgi_ss;
			memset(sun, 0, sizeof(*sun));
			sun->sun_family = AF_UNIX;
			if (strlcpy(sun->sun_path, yyvsp[0].v.string, sizeof(sun->sun_path))
			    >= sizeof(sun->sun_path)) {
				yyerror("socket path too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			srv_conf->fastcgi_ss.ss_len =
			    sizeof(struct sockaddr_un);
			free(yyvsp[0].v.string);
		}
break;
case 75:
#line 990 "parse.y"
{
			if (get_fastcgi_dest(srv_conf, yyvsp[0].v.string, FCGI_DEFAULT_PORT)
			    == -1) {
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 76:
#line 998 "parse.y"
{
			if (get_fastcgi_dest(srv_conf, yyvsp[-1].v.string, yyvsp[0].v.string) == -1) {
				free(yyvsp[-1].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 77:
#line 1007 "parse.y"
{
			struct fastcgi_param	*param;

			if (strlen(yyvsp[-1].v.string) > HTTPD_FCGI_NAME_MAX - 1) {
				yyerror("fastcgi param name too long (max %d)",
				    HTTPD_FCGI_NAME_MAX - 1);
				free(yyvsp[-1].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}

			if (strlen(yyvsp[0].v.string) > HTTPD_FCGI_VAL_MAX - 1) {
				yyerror("fastcgi param value too long (max %d)",
				    HTTPD_FCGI_VAL_MAX - 1);
				free(yyvsp[-1].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}

			if ((param = calloc(1, sizeof(*param))) == NULL)
				fatal("out of memory");

			if ((param->name = strdup(yyvsp[-1].v.string)) == NULL ||
			    (param->value = strdup(yyvsp[0].v.string)) == NULL)
				fatal("out of memory");

			free(yyvsp[-1].v.string);
			free(yyvsp[0].v.string);

			DPRINTF("[%s,%s,%d]: adding param \"%s\" value \"%s\"",
			    srv_conf->location, srv_conf->name, srv_conf->id,
			    param->name, param->value);

			TAILQ_INSERT_TAIL(&srv_conf->fcgiparams, param, entry);
		}
break;
case 78:
#line 1042 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("invalid fastcgi strip number");
				YYERROR;
			}
			srv_conf->fcgistrip = yyvsp[0].v.number;
		}
break;
case 79:
#line 1049 "parse.y"
{
			if (strcmp(yyvsp[0].v.string, "chunked") != 0) {
				yyerror("Invalid token '%s' expected 'chunked'",
				    yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			srv_conf->fcgiallowchunked = 1;
			free(yyvsp[0].v.string);
		}
break;
case 84:
#line 1069 "parse.y"
{
			memcpy(&srv_conf->timeout, &yyvsp[0].v.tv,
			    sizeof(struct timeval));
		}
break;
case 85:
#line 1073 "parse.y"
{
			memcpy(&srv_conf->requesttimeout, &yyvsp[0].v.tv,
			    sizeof(struct timeval));
		}
break;
case 86:
#line 1077 "parse.y"
{
			srv_conf->maxrequests = yyvsp[0].v.number;
		}
break;
case 87:
#line 1080 "parse.y"
{
			srv_conf->maxrequestbody = yyvsp[0].v.number;
		}
break;
case 92:
#line 1093 "parse.y"
{
			free(srv_conf->tls_cert_file);
			if ((srv_conf->tls_cert_file = strdup(yyvsp[0].v.string)) == NULL)
				fatal("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 93:
#line 1099 "parse.y"
{
			free(srv_conf->tls_key_file);
			if ((srv_conf->tls_key_file = strdup(yyvsp[0].v.string)) == NULL)
				fatal("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 94:
#line 1105 "parse.y"
{
			free(srv_conf->tls_ocsp_staple_file);
			if ((srv_conf->tls_ocsp_staple_file = strdup(yyvsp[0].v.string))
			    == NULL)
				fatal("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 95:
#line 1112 "parse.y"
{
			if (strlcpy(srv_conf->tls_ciphers, yyvsp[0].v.string,
			    sizeof(srv_conf->tls_ciphers)) >=
			    sizeof(srv_conf->tls_ciphers)) {
				yyerror("ciphers too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 96:
#line 1122 "parse.y"
{
			srv_conf->tls_flags |= TLSFLAG_CA;
			free(srv_conf->tls_ca_file);
			if ((srv_conf->tls_ca_file = strdup(yyvsp[-1].v.string)) == NULL)
				fatal("out of memory");
			free(yyvsp[-1].v.string);
		}
break;
case 97:
#line 1129 "parse.y"
{
			if (strlcpy(srv_conf->tls_dhe_params, yyvsp[0].v.string,
			    sizeof(srv_conf->tls_dhe_params)) >=
			    sizeof(srv_conf->tls_dhe_params)) {
				yyerror("dhe too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 98:
#line 1139 "parse.y"
{
			if (strlcpy(srv_conf->tls_ecdhe_curves, yyvsp[0].v.string,
			    sizeof(srv_conf->tls_ecdhe_curves)) >=
			    sizeof(srv_conf->tls_ecdhe_curves)) {
				yyerror("ecdhe too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 99:
#line 1149 "parse.y"
{
			if (tls_config_parse_protocols(
			    &srv_conf->tls_protocols, yyvsp[0].v.string) != 0) {
				yyerror("invalid tls protocols");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 100:
#line 1158 "parse.y"
{
			srv_conf->tls_ticket_lifetime = SERVER_DEF_TLS_LIFETIME;
		}
break;
case 101:
#line 1161 "parse.y"
{
			if (yyvsp[0].v.number != 0 && yyvsp[0].v.number < SERVER_MIN_TLS_LIFETIME) {
				yyerror("ticket lifetime too small");
				YYERROR;
			}
			if (yyvsp[0].v.number > SERVER_MAX_TLS_LIFETIME) {
				yyerror("ticket lifetime too large");
				YYERROR;
			}
			srv_conf->tls_ticket_lifetime = yyvsp[0].v.number;
		}
break;
case 102:
#line 1172 "parse.y"
{
			srv_conf->tls_ticket_lifetime = 0;
		}
break;
case 104:
#line 1178 "parse.y"
{
			srv_conf->tls_flags = TLSFLAG_CRL;
			free(srv_conf->tls_crl_file);
			if ((srv_conf->tls_crl_file = strdup(yyvsp[0].v.string)) == NULL)
				fatal("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 105:
#line 1185 "parse.y"
{
			srv_conf->tls_flags |= TLSFLAG_OPTIONAL;
		}
break;
case 110:
#line 1197 "parse.y"
{
			if (strlcpy(srv->srv_conf.root, yyvsp[0].v.string,
			    sizeof(srv->srv_conf.root)) >=
			    sizeof(srv->srv_conf.root)) {
				yyerror("document root too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			srv->srv_conf.flags |= SRVFLAG_ROOT;
		}
break;
case 115:
#line 1218 "parse.y"
{
			if (strlcpy(srv->srv_conf.path, yyvsp[0].v.string,
			    sizeof(srv->srv_conf.path)) >=
			    sizeof(srv->srv_conf.path)) {
				yyerror("request path too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			srv->srv_conf.flags |= SRVFLAG_PATH_REWRITE;
			srv->srv_conf.flags &= ~SRVFLAG_NO_PATH_REWRITE;
		}
break;
case 116:
#line 1230 "parse.y"
{
			srv->srv_conf.flags |= SRVFLAG_NO_PATH_REWRITE;
			srv->srv_conf.flags &= ~SRVFLAG_PATH_REWRITE;
		}
break;
case 117:
#line 1234 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > INT_MAX) {
				yyerror("invalid strip number");
				YYERROR;
			}
			srv->srv_conf.strip = yyvsp[0].v.number;
		}
break;
case 118:
#line 1243 "parse.y"
{
			srv->srv_conf.flags |= SRVFLAG_NO_AUTH;
		}
break;
case 119:
#line 1246 "parse.y"
{
			struct auth	*auth;

			if ((auth = auth_add(conf->sc_auth, &yyvsp[0].v.auth)) == NULL) {
				yyerror("failed to add auth");
				YYERROR;
			}

			if (auth->auth_id == 0) {
				/* New htpasswd, get new Id */
				auth->auth_id = ++last_auth_id;
				if (last_auth_id == INT_MAX) {
					yyerror("too many auth ids defined");
					auth_free(conf->sc_auth, auth);
					YYERROR;
				}
			}

			srv->srv_conf.auth_id = auth->auth_id;
			srv->srv_conf.flags |= SRVFLAG_AUTH;
		}
break;
case 120:
#line 1269 "parse.y"
{
			if (strlcpy(srv->srv_conf.auth_realm, yyvsp[-2].v.string,
			    sizeof(srv->srv_conf.auth_realm)) >=
			    sizeof(srv->srv_conf.auth_realm)) {
				yyerror("basic auth realm name too long");
				free(yyvsp[-2].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
			if (strlcpy(yyval.v.auth.auth_htpasswd, yyvsp[0].v.string,
			    sizeof(yyval.v.auth.auth_htpasswd)) >=
			    sizeof(yyval.v.auth.auth_htpasswd)) {
				yyerror("password file name too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

		}
break;
case 121:
#line 1288 "parse.y"
{
			if (strlcpy(yyval.v.auth.auth_htpasswd, yyvsp[0].v.string,
			    sizeof(yyval.v.auth.auth_htpasswd)) >=
			    sizeof(yyval.v.auth.auth_htpasswd)) {
				yyerror("password file name too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 126:
#line 1307 "parse.y"
{
			if (strlcpy(srv_conf->index, yyvsp[0].v.string,
			    sizeof(srv_conf->index)) >=
			    sizeof(srv_conf->index)) {
				yyerror("index file too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			srv_conf->flags &= ~SRVFLAG_NO_INDEX;
			srv_conf->flags |= SRVFLAG_INDEX;
			free(yyvsp[0].v.string);
		}
break;
case 127:
#line 1319 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_INDEX;
			srv_conf->flags |= SRVFLAG_NO_INDEX;
		}
break;
case 128:
#line 1323 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_AUTO_INDEX;
			srv_conf->flags |= SRVFLAG_AUTO_INDEX;
		}
break;
case 129:
#line 1327 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_AUTO_INDEX;
			srv_conf->flags |= SRVFLAG_NO_AUTO_INDEX;
		}
break;
case 132:
#line 1336 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_LOG;
			srv_conf->flags |= SRVFLAG_NO_LOG;
		}
break;
case 136:
#line 1347 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_SYSLOG;
			srv_conf->flags |= SRVFLAG_SYSLOG;
		}
break;
case 137:
#line 1351 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_SYSLOG;
			srv_conf->flags |= SRVFLAG_NO_SYSLOG;
		}
break;
case 138:
#line 1355 "parse.y"
{
			if (strlcpy(srv_conf->accesslog, yyvsp[0].v.string,
			    sizeof(srv_conf->accesslog)) >=
			    sizeof(srv_conf->accesslog)) {
				yyerror("access log name too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			srv_conf->flags |= SRVFLAG_ACCESS_LOG;
		}
break;
case 139:
#line 1366 "parse.y"
{
			if (strlcpy(srv_conf->errorlog, yyvsp[0].v.string,
			    sizeof(srv_conf->errorlog)) >=
			    sizeof(srv_conf->errorlog)) {
				yyerror("error log name too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			srv_conf->flags |= SRVFLAG_ERROR_LOG;
		}
break;
case 140:
#line 1379 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_LOG;
			srv_conf->flags |= SRVFLAG_LOG;
			srv_conf->logformat = LOG_FORMAT_COMMON;
		}
break;
case 141:
#line 1384 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_LOG;
			srv_conf->flags |= SRVFLAG_LOG;
			srv_conf->logformat = LOG_FORMAT_COMBINED;
		}
break;
case 142:
#line 1389 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_LOG;
			srv_conf->flags |= SRVFLAG_LOG;
			srv_conf->logformat = LOG_FORMAT_CONNECTION;
		}
break;
case 143:
#line 1394 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_LOG;
			srv_conf->flags |= SRVFLAG_LOG;
			srv_conf->logformat = LOG_FORMAT_FORWARDED;
		}
break;
case 144:
#line 1401 "parse.y"
{
			if (yyvsp[-1].v.number <= 0 || server_httperror_byid(yyvsp[-1].v.number) == NULL) {
				yyerror("invalid return code: %lld", yyvsp[-1].v.number);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			srv_conf->return_code = yyvsp[-1].v.number;

			if (yyvsp[0].v.string != NULL) {
				/* Only for 3xx redirection headers */
				if (yyvsp[-1].v.number < 300 || yyvsp[-1].v.number > 399) {
					yyerror("invalid return code for "
					    "location URI");
					free(yyvsp[0].v.string);
					YYERROR;
				}
				srv_conf->return_uri = yyvsp[0].v.string;
				srv_conf->return_uri_len = strlen(yyvsp[0].v.string) + 1;
			}
		}
break;
case 145:
#line 1421 "parse.y"
{
			/* No return code, silently drop the connection */
			srv_conf->return_code = 0;
		}
break;
case 146:
#line 1425 "parse.y"
{
			/* Forbidden */
			srv_conf->return_code = 403;
		}
break;
case 147:
#line 1429 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_BLOCK;
			srv_conf->flags |= SRVFLAG_NO_BLOCK;
		}
break;
case 148:
#line 1435 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_BLOCK;
			srv_conf->flags |= SRVFLAG_BLOCK;
		}
break;
case 149:
#line 1441 "parse.y"
{ yyval.v.number = 0; }
break;
case 150:
#line 1442 "parse.y"
{ yyval.v.number = 1; }
break;
case 151:
#line 1445 "parse.y"
{ yyval.v.string = NULL; }
break;
case 152:
#line 1446 "parse.y"
{ yyval.v.string = yyvsp[0].v.string; }
break;
case 153:
#line 1449 "parse.y"
{
			if (yyvsp[0].v.number <= 0 || yyvsp[0].v.number > (int)USHRT_MAX) {
				yyerror("invalid port: %lld", yyvsp[0].v.number);
				YYERROR;
			}
			if (asprintf(&yyval.v.string, "%lld", yyvsp[0].v.number) == -1) {
				yyerror("out of memory");
				YYERROR;
			}
		}
break;
case 154:
#line 1459 "parse.y"
{
			if (getservice(yyvsp[0].v.string) <= 0) {
				yyerror("invalid port: %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}

			yyval.v.string = yyvsp[0].v.string;
		}
break;
case 155:
#line 1470 "parse.y"
{
			srv->srv_conf.flags &= ~SRVFLAG_GZIP_STATIC;
			srv->srv_conf.flags |= SRVFLAG_NO_GZIP_STATIC;
		}
break;
case 156:
#line 1474 "parse.y"
{
			srv->srv_conf.flags |= SRVFLAG_GZIP_STATIC;
			srv->srv_conf.flags &= ~SRVFLAG_NO_GZIP_STATIC;
		}
break;
case 157:
#line 1480 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_STATIC_CACHE_CONTROL;
			srv_conf->flags |= SRVFLAG_NO_STATIC_CACHE_CONTROL;
		}
break;
case 158:
#line 1484 "parse.y"
{
			srv_conf->flags &= ~SRVFLAG_NO_STATIC_CACHE_CONTROL;
			srv_conf->flags |= SRVFLAG_STATIC_CACHE_CONTROL;
		}
break;
case 163:
#line 1498 "parse.y"
{ srv_conf->tcpflags |= TCPFLAG_SACK; }
break;
case 164:
#line 1499 "parse.y"
{ srv_conf->tcpflags |= TCPFLAG_NSACK; }
break;
case 165:
#line 1500 "parse.y"
{
			srv_conf->tcpflags |= TCPFLAG_NODELAY;
		}
break;
case 166:
#line 1503 "parse.y"
{
			srv_conf->tcpflags |= TCPFLAG_NNODELAY;
		}
break;
case 167:
#line 1506 "parse.y"
{
			if (yyvsp[0].v.number < 0 || yyvsp[0].v.number > SERVER_MAX_CLIENTS) {
				yyerror("invalid backlog: %lld", yyvsp[0].v.number);
				YYERROR;
			}
			srv_conf->tcpbacklog = yyvsp[0].v.number;
		}
break;
case 168:
#line 1513 "parse.y"
{
			srv_conf->tcpflags |= TCPFLAG_BUFSIZ;
			if ((srv_conf->tcpbufsiz = yyvsp[0].v.number) < 0) {
				yyerror("invalid socket buffer size: %lld", yyvsp[0].v.number);
				YYERROR;
			}
		}
break;
case 169:
#line 1520 "parse.y"
{
			if (yyvsp[0].v.number < 0) {
				yyerror("invalid ttl: %lld", yyvsp[0].v.number);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			if (strcasecmp("ttl", yyvsp[-1].v.string) == 0) {
				srv_conf->tcpflags |= TCPFLAG_IPTTL;
				srv_conf->tcpipttl = yyvsp[0].v.number;
			} else if (strcasecmp("minttl", yyvsp[-1].v.string) == 0) {
				srv_conf->tcpflags |= TCPFLAG_IPMINTTL;
				srv_conf->tcpipminttl = yyvsp[0].v.number;
			} else {
				yyerror("invalid TCP/IP flag: %s", yyvsp[-1].v.string);
				free(yyvsp[-1].v.string);
				YYERROR;
			}
			free(yyvsp[-1].v.string);
		}
break;
case 175:
#line 1552 "parse.y"
{
			if (strlcpy(media.media_type, yyvsp[-2].v.string,
			    sizeof(media.media_type)) >=
			    sizeof(media.media_type) ||
			    strlcpy(media.media_subtype, yyvsp[0].v.string,
			    sizeof(media.media_subtype)) >=
			    sizeof(media.media_subtype)) {
				yyerror("media type too long");
				free(yyvsp[-2].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 178:
#line 1573 "parse.y"
{
			if (strlcpy(media.media_name, yyvsp[0].v.string,
			    sizeof(media.media_name)) >=
			    sizeof(media.media_name)) {
				yyerror("media name too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			if (!loadcfg)
				break;

			if (media_add(conf->sc_mediatypes, &media) == NULL) {
				yyerror("failed to add media type");
				YYERROR;
			}
		}
break;
case 179:
#line 1593 "parse.y"
{
			if (yyvsp[0].v.number <= 0 || yyvsp[0].v.number > (int)USHRT_MAX) {
				yyerror("invalid port: %lld", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.port.val[0] = htons(yyvsp[0].v.number);
			yyval.v.port.op = 1;
		}
break;
case 180:
#line 1601 "parse.y"
{
			int	 val;

			if ((val = getservice(yyvsp[0].v.string)) == -1) {
				yyerror("invalid port: %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			yyval.v.port.val[0] = val;
			yyval.v.port.op = 1;
		}
break;
case 181:
#line 1617 "parse.y"
{
			if (yyvsp[0].v.number < 0) {
				yyerror("invalid timeout: %lld", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.tv.tv_sec = yyvsp[0].v.number;
			yyval.v.tv.tv_usec = 0;
		}
break;
case 182:
#line 1627 "parse.y"
{
			char *s;
			if (asprintf(&s, "%lld", yyvsp[0].v.number) == -1) {
				yyerror("asprintf: number");
				YYERROR;
			}
			yyval.v.string = s;
		}
break;
#line 3958 "parse.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (1);
yyaccept:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (0);
}
