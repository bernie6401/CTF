FROM ubuntu@sha256:8eab65df33a6de2844c9aefd19efe8ddb87b7df5e9185a4ab73af936225685bb
MAINTAINER TWNWAKing

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -qy xinetd python3

RUN useradd -m babypwn2024-nerf -d /home/babypwn2024-nerf/
RUN chown -R root:root /home/babypwn2024-nerf
RUN chmod -R 755 /home/babypwn2024-nerf
RUN chmod 774 /tmp
RUN chmod -R 774 /var/tmp
RUN chmod -R 774 /dev
RUN chmod -R 774 /run
RUN chmod 1733 /tmp /var/tmp /dev/shm

CMD ["/usr/sbin/xinetd", "-dontfork"]