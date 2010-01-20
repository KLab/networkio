# TODO: rewrite ...
#  need library libapr libconfuse
#  build object: iptables and ganglia at parent directory
#  if you needs static link binary, add -static option flag at last line.
#########
gcc -I ../include `apr-config --includes  --link-ld` networkio.c -g ../libiptc/*.o -I ../../ganglia-3.1.2/include/ -I ../../ganglia-3.1.2/lib  ../../ganglia-3.1.2/lib/*.o  -lexpat -lconfuse -o networkio -Wall
