FROM ubuntu:20.04
MAINTAINER Terry1234

RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy xinetd

RUN useradd -m ret2win
RUN chown -R root:root /home/ret2win
RUN chmod -R 755 /home/ret2win

CMD ["/usr/sbin/xinetd", "-dontfork"]
