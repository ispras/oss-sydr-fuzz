FROM sydr/ubuntu22.04-sydr-fuzz

COPY requirements.txt /tmp/requirements.txt
COPY build.sh /tmp/build.sh

RUN bash /tmp/build.sh

ENV PATH="/opt/vllm-venv/bin:${PATH}"
WORKDIR /fuzz
