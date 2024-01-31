FROM ubuntu:20.04
MAINTAINER Terry1234

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd

RUN useradd -m ret2libc
RUN chown -R root:root /home/ret2libc
RUN chmod -R 755 /home/ret2libc

CMD ["/usr/sbin/xinetd", "-dontfork"]
