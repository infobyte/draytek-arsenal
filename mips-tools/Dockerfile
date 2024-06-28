FROM ubuntu
RUN apt update
RUN apt install -y gcc-mips-linux-gnu

WORKDIR /opt/
COPY entry.sh .

ENTRYPOINT ["bash", "./entry.sh"]
