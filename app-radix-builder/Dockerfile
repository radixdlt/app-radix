FROM amd64/ubuntu:20.04
ENV LANG C.UTF-8

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -qy && \
    apt-get install -qy \
        clang \
        clang-tools \
        cmake \
        curl \
        doxygen \
        git \
        lcov \
        libbsd-dev \
        libcmocka0 \
        libcmocka-dev \
        libtinfo5 \
        lld \
        make \
        mc \
        zip \
        unzip \
        xz-utils \
        bzip2 \
        gcc-multilib \
        g++-multilib \
        protobuf-compiler \
        python-is-python3 \
        python3 \
        python3-pip && \
    apt-get autoclean -y && \
    apt-get autoremove -y && \
    apt-get clean

RUN mkdir /opt/bolos-devenv

# Setup Nano S SDK
RUN cd /opt/bolos-devenv && \
    curl -fL -o nano_s_sdk_se200.zip https://github.com/LedgerHQ/nanos-secure-sdk/archive/refs/tags/2.0.0-1.zip && \
    unzip nano_s_sdk_se200.zip && rm nano_s_sdk_se200.zip && mv nanos-secure-sdk-2.0.0-1 nano_s_sdk_se200

# Setup Nano X SDK
RUN cd /opt/bolos-devenv && \
    curl -fL -o nano_x_sdk_se124.zip https://github.com/LedgerHQ/nanox-secure-sdk/archive/refs/tags/1.2.4-5.1.zip && \
    unzip nano_x_sdk_se124.zip && rm nano_x_sdk_se124.zip && mv nanox-secure-sdk-1.2.4-5.1 nano_x_sdk_se124

# Setup clang 10
RUN cd /opt/bolos-devenv && \
    curl -fL -o clang10.tar.xz https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && \
    tar -xvf clang10.tar.xz && \
    mv clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04 nanos_se200_clang_10

# Setup clang 9
RUN cd /opt/bolos-devenv && \
    curl -fL -o clang9.tar.xz https://releases.llvm.org/9.0.0/clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && \
    tar -xvf clang9.tar.xz && \
    mv clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-18.04 nanox_se124_clang_9

# Setup GCC
RUN cd /opt/bolos-devenv && \
    curl -fL -o gcc-arm.tar.bz2 https://developer.arm.com/-/media/Files/downloads/gnu-rm/10-2020q4/gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2 && \
    tar -xvf gcc-arm.tar.bz2 && mv gcc-arm-none-eabi-10-2020-q4-major gcc_nano_s_se200_and_nano_x_se124_compatible

# Python packages commonly used by apps
RUN pip3 install ledgerblue pytest

# Fix Nano S SDK
COPY nano-s/Makefile.defines /opt/bolos-devenv/nano_s_sdk_se200/Makefile.defines

# Setup environment variables
ENV BOLOS_ENV=/opt/bolos-devenv \
    BOLOS_SDK_NANO_S=/opt/bolos-devenv/nano_s_sdk_se200 \
    BOLOS_SDK_NANO_X=/opt/bolos-devenv/nano_x_sdk_se124 \
    CLANGPATH_NANO_S=/opt/bolos-devenv/nanos_se200_clang_10 \
    CLANGPATH_NANO_X=/opt/bolos-devenv/nanox_se124_clang_9 \
    SCP_PRIVKEY=b5b2eacb2debcf4903060e0fa2a139354fe29be9e4ac7c433f694a3d93297eaa

WORKDIR /app

CMD ["/bin/bash"]
