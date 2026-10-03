FROM debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential bc bzip2 ca-certificates cpio file git libncurses-dev \
    patch perl python3 rsync unzip wget xz-utils \
    && rm -rf /var/lib/apt/lists/*
ENV FORCE_UNSAFE_CONFIGURE=1
ENTRYPOINT ["sh", "/recipe/build.sh"]
