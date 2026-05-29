FROM azul/zulu-openjdk:7 AS jdk7
FROM eclipse-temurin:8-jdk AS jdk8
FROM eclipse-temurin:11-jdk AS jdk11
FROM eclipse-temurin:16-jdk AS jdk16

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    bzip2 \
    ca-certificates \
    curl \
    git \
    maven \
    openssh-client \
    patch \
    python3 \
    python3-venv \
    unzip \
    wget \
    xz-utils \
    zsh \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO- https://archive.apache.org/dist/maven/maven-3/3.3.9/binaries/apache-maven-3.3.9-bin.tar.gz | tar -xz -C /opt

COPY --from=jdk7 /usr/lib/jvm/zulu7-ca-amd64 /opt/jdks/jdk7
COPY --from=jdk8 /opt/java/openjdk /opt/jdks/jdk8
COPY --from=jdk11 /opt/java/openjdk /opt/jdks/jdk11
COPY --from=jdk16 /opt/java/openjdk /opt/jdks/jdk16

ENV JAVA7_HOME=/opt/jdks/jdk7
ENV JAVA8_HOME=/opt/jdks/jdk8
ENV JAVA11_HOME=/opt/jdks/jdk11
ENV JAVA16_HOME=/opt/jdks/jdk16
ENV JAVA_HOME=/opt/jdks/jdk8
ENV MAVEN33_HOME=/opt/apache-maven-3.3.9
ENV MAVEN_HOME=/usr/share/maven
ENV PATH=/vul4j/.venv/bin:/root/.local/bin:/opt/jdks/jdk8/bin:${PATH}
ENV VUL4J_DATA=/root/vul4j_data
ENV VUL4J_GIT=/vul4j
ENV SPOTBUGS_PATH=/root/vul4j_data/spotbugs-4.8.5/lib/spotbugs.jar
ENV MODIFICATION_EXTRACTOR_PATH=/vul4j/modification-extractor/modification-extractor.jar

COPY maven_conf/settings.xml /root/.m2/settings.xml
COPY . /vul4j

WORKDIR /vul4j

ARG VUL4J_BRANCH_SOURCE=https://github.com/tuhh-softsec/vul4j
RUN git fetch --no-tags "${VUL4J_BRANCH_SOURCE}" "+refs/heads/VUL4J-*:refs/heads/VUL4J-*"
RUN git config user.email vul4j@local \
    && git config user.name vul4j \
    && git add -A \
    && (git diff --cached --quiet || git commit -m "container build snapshot")

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
RUN uv sync --frozen --no-dev
RUN vul4j init --location /root/vul4j_data
RUN sed -i 's|^JAVA_ARGS =.*|JAVA_ARGS = |; s|^MVN_ARGS =.*|MVN_ARGS = |' /root/vul4j_data/vul4j.ini
RUN vul4j get-spotbugs
RUN vul4j status

RUN cat > /usr/local/bin/vul4j-warmup <<'PY'
#!/usr/bin/env python3
import csv
import pathlib
import shutil
import subprocess
import sys

dataset_path = pathlib.Path("/vul4j/dataset/vul4j_dataset.csv")
reproduction_log_path = pathlib.Path("/root/vul4j_data/reproduction.txt")
failed_path = pathlib.Path("/root/vul4j_data/failed_vulnerabilities.txt")
success_path = pathlib.Path("/root/vul4j_data/reproduction/successful_vulnerabilities.txt")
reproduction_log_path.parent.mkdir(parents=True, exist_ok=True)
success_path.parent.mkdir(parents=True, exist_ok=True)

def write_output(log, text):
    log.write(text)
    log.flush()
    sys.stdout.write(text)
    sys.stdout.flush()

with dataset_path.open(newline="", encoding="utf-8") as dataset_file:
    vul_ids = [row["vul_id"] for row in csv.DictReader(dataset_file)]

failed_ids = []

with reproduction_log_path.open("w", encoding="utf-8") as reproduction_log:
    for vul_id in vul_ids:
        success_path.unlink(missing_ok=True)
        try:
            process = subprocess.Popen(
                ["vul4j", "reproduce", "--id", vul_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in process.stdout:
                write_output(reproduction_log, line)
            return_code = process.wait()
            if return_code:
                raise subprocess.CalledProcessError(return_code, process.args)
            if not success_path.exists() or success_path.read_text(encoding="utf-8").splitlines() != [vul_id]:
                failed_ids.append(vul_id)
                write_output(reproduction_log, f"{vul_id} did not reproduce successfully\n")
        finally:
            shutil.rmtree(success_path.parent / vul_id, ignore_errors=True)
            shutil.rmtree(pathlib.Path("/root/vul4j_data/clone"), ignore_errors=True)
            success_path.unlink(missing_ok=True)

if failed_ids:
    failed_path.write_text("\n".join(failed_ids) + "\n", encoding="utf-8")
    print(f"Failed vulnerabilities: {', '.join(failed_ids)}")
else:
    failed_path.unlink(missing_ok=True)
PY
RUN chmod +x /usr/local/bin/vul4j-warmup

RUN vul4j-warmup
RUN rm -rf /root/vul4j_data/reproduction /root/vul4j_data/clone

WORKDIR /

CMD ["/bin/bash"]
