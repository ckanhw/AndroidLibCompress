PROG = lzma
CXX = g++
LIB =
RM = rm -f
CFLAGS = -c -O2 -Wall -D_7ZIP_ST

OBJS = \
  objs/LzmaUtil.o \
  objs/Alloc.o \
  objs/LzFind.o \
  objs/LzmaDec.o \
  objs/LzmaEnc.o \
  objs/7zFile.o \
  objs/7zStream.o \


all: $(PROG)

$(PROG): $(OBJS)
	$(CXX) -o $(PROG) $(LDFLAGS) $(OBJS) $(LIB) $(LIB2)

objs/LzmaUtil.o: LzmaUtil.c
	$(CXX) $(CFLAGS) LzmaUtil.c -o objs/LzmaUtil.o

objs/Alloc.o: 7zC/Alloc.c
	$(CXX) $(CFLAGS) 7zC/Alloc.c -o objs/Alloc.o

objs/LzFind.o: 7zC/LzFind.c
	$(CXX) $(CFLAGS) 7zC/LzFind.c -o objs/LzFind.o

objs/LzmaDec.o: 7zC/LzmaDec.c
	$(CXX) $(CFLAGS) 7zC/LzmaDec.c -o objs/LzmaDec.o

objs/LzmaEnc.o: 7zC/LzmaEnc.c
	$(CXX) $(CFLAGS) 7zC/LzmaEnc.c -o objs/LzmaEnc.o

objs/7zFile.o: 7zC/7zFile.c
	$(CXX) $(CFLAGS) 7zC/7zFile.c -o objs/7zFile.o

objs/7zStream.o: 7zC/7zStream.c
	$(CXX) $(CFLAGS) 7zC/7zStream.c -o objs/7zStream.o

clean:
	-$(RM) $(PROG) $(OBJS)

