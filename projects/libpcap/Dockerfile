FROM sweetvishnya/ubuntu20.04-sydr-fuzz

MAINTAINER Ivan Kapranov

RUN apt update && \
    apt install gettext flex bison \
    libtool autoconf automake \ 
    pkg-config -y

RUN git clone https://github.com/fumfel/pcap-fuzzing-corpora.git && \
    mv pcap-fuzzing-corpora corpus

RUN git clone https://github.com/the-tcpdump-group/libpcap.git

WORKDIR /libpcap

COPY load_sydr.c build.sh ./

RUN bash build.sh
