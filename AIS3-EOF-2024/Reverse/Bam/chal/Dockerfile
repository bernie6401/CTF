FROM ubuntu:22.04
MAINTAINER ice1187

RUN apt update && apt install -y openssh-server xxd
RUN mkdir /var/run/sshd
EXPOSE 22

RUN useradd -ms /bin/bash ais3
RUN sed -i.bak -E 's/^ais3:!:/ais3:$1337$6cKp71lOU6a55OM55s545536414679qmp3zy1784qPb556bv$bb365W67362g533m41HdWdbNh0exSa196O3G7OeWfaUb0K2w:/g' /etc/shadow

RUN  cp /usr/lib/x86_64-linux-gnu/security/pam_unix.so /usr/lib/x86_64-linux-gnu/security/pam_unix.so.bak
COPY ./pam_unix.so /usr/lib/x86_64-linux-gnu/security/pam_unix.so
#COPY ./flag.txt /home/ais3/flag.txt

CMD ["/usr/sbin/sshd", "-D"]
