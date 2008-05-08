
CFLAGS+=	-ggdb -Wall

LDLIBS+=	-framework CoreFoundation
LDLIBS+=	-framework SystemConfiguration

PROG=	ipwatchd
SRCS=	ipwatchd.c watch.c

#.include <bsd.prog.mk>
default: $(PROG)
OBJS= $(SRCS:.c=.o)
$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
clean:
	rm -f $(PROG) $(OBJS)
