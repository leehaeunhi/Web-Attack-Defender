# Web-Attack-Defender
2017 캡스톤 디자인

centOS7
using C, GTK+3

how to compile
#gcc -c main.c -Xlinker -lpthread `pkg-config --cflags --libs gtk+-3.0`
#gcc -c analyzer.c -Xlinker -lpthread `pkg-config --cflags --libs gtk+-3.0`
#gcc -c tail.c -Xlinker -lpthread `pkg-config --cflags --libs gtk+-3.0`
#gcc -o wad main.o tail.o analyzer.o `pkg-config --cflags --libs gtk+-3.0`

how to execute
#./wad /var/log/httpd/common_access_log
