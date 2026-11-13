CFLAGS = -O2 -pipe -Wall -I/usr/local/include/mysql
CFLAGS += -I/usr/local/include/mysql/mysql
LIBS = /usr/local/lib/mysql/libmariadb.a -L/usr/local/lib
LIBS += -lssl -lcrypto -liconv -lz -lm -lpthread

all:
	cc $(CFLAGS) -static raptor_db_cgi.c $(LIBS) -o raptor_db
	install -c -m 0555 -o root -g bin raptor_db /var/www/cgi-bin/raptor_db
	cc $(CFLAGS) -Wstrict-prototypes -Wmissing-prototypes -static raptor_db_post.c $(LIBS) -o raptor_db_post
	install -c -m 0550 -o root -g www raptor_db_post /var/www/cgi-bin/raptor_db_post
