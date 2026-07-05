# =============================================================================
# Hecatrace - DFIR Forensics Platform
# =============================================================================
# Multi-stage build:
#   builder  → network downloads (GitHub releases + git clones)
#   final    → clean runtime image, without build tools
#
# Base: ubuntu:24.04 LTS (Python 3.12, good forensics APT coverage)
# =============================================================================

# =============================================================================
# Stage 1 - builder
# =============================================================================
FROM ubuntu:24.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    ca-certificates \
    unzip \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ---------------------------------------------------------------------------
# Hayabusa (EVTX scanner, Rust - static musl binary)
# ---------------------------------------------------------------------------
RUN set -e; \
    API="https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"; \
    URL=$(curl -sf "$API" | python3 -c "\
import sys, json; \
assets = json.load(sys.stdin)['assets']; \
hits = [a['browser_download_url'] for a in assets \
        if 'lin' in a['name'].lower() \
        and 'x64' in a['name'].lower() \
        and 'musl' in a['name'].lower() \
        and a['name'].endswith('.zip')]; \
print(hits[0])") && \
    wget -q -O hayabusa.zip "$URL" && \
    mkdir -p /tools/hayabusa && \
    unzip -q hayabusa.zip -d /tools/hayabusa && \
    find /tools/hayabusa -maxdepth 1 -name "hayabusa-*" -type f -exec mv {} /tools/hayabusa/hayabusa \; 2>/dev/null || true && \
    chmod +x /tools/hayabusa/hayabusa

# ---------------------------------------------------------------------------
# Chainsaw (Sigma hunt, Rust - GNU/Linux binary)
# ---------------------------------------------------------------------------
RUN set -e; \
    API="https://api.github.com/repos/WithSecureLabs/chainsaw/releases/latest"; \
    URL=$(curl -sf "$API" | python3 -c "\
import sys, json; \
assets = json.load(sys.stdin)['assets']; \
hits = [a['browser_download_url'] for a in assets \
        if 'x86_64' in a['name'] \
        and 'linux' in a['name'] \
        and 'gnu' in a['name'] \
        and a['name'].endswith('.tar.gz')]; \
print(hits[0])") && \
    wget -q -O chainsaw.tar.gz "$URL" && \
    mkdir -p /tools/chainsaw && \
    tar -xzf chainsaw.tar.gz -C /tools/chainsaw --strip-components=1 && \
    chmod +x /tools/chainsaw/chainsaw && \
    git clone --depth 1 https://github.com/WithSecureLabs/chainsaw.git /tmp/chainsaw-src && \
    cp -r /tmp/chainsaw-src/rules /tools/chainsaw/rules && \
    rm -rf /tmp/chainsaw-src

# ---------------------------------------------------------------------------
# capa (malware capability detection, static binary)
# ---------------------------------------------------------------------------
RUN set -e; \
    API="https://api.github.com/repos/mandiant/capa/releases/latest"; \
    URL=$(curl -sf "$API" | python3 -c "\
import sys, json; \
assets = json.load(sys.stdin)['assets']; \
hits = [a['browser_download_url'] for a in assets \
        if 'linux' in a['name'].lower() \
        and a['name'].endswith('.zip') \
        and 'arm64' not in a['name'].lower() \
        and 'py3' not in a['name'].lower() \
        and 'rules' not in a['name'].lower()]; \
print(hits[0])") && \
    wget -q -O capa.zip "$URL" && \
    mkdir -p /tools/capa && \
    unzip -q capa.zip -d /tools/capa && \
    find /tools/capa -name "capa" -type f -exec chmod +x {} \; && \
    find /tools/capa -maxdepth 1 -name "capa-*" -type f -exec mv {} /tools/capa/capa \; 2>/dev/null || true

# ---------------------------------------------------------------------------
# FLOSS (obfuscated string extraction, Mandiant)
# ---------------------------------------------------------------------------
RUN set -e; \
    API="https://api.github.com/repos/mandiant/flare-floss/releases/latest"; \
    URL=$(curl -sf "$API" | python3 -c "\
import sys, json; \
assets = json.load(sys.stdin)['assets']; \
hits = [a['browser_download_url'] for a in assets \
        if 'linux' in a['name'].lower() \
        and a['name'].endswith('.zip')]; \
print(hits[0])") && \
    wget -q -O floss.zip "$URL" && \
    mkdir -p /tools/floss && \
    unzip -q floss.zip -d /tools/floss && \
    find /tools/floss -name "floss" -type f -exec chmod +x {} \; && \
    find /tools/floss -maxdepth 1 -name "floss-*" -type f -exec mv {} /tools/floss/floss \; 2>/dev/null || true

# ---------------------------------------------------------------------------
# Eric Zimmerman's tools (EZTools) - .NET 9 cross-platform CLI builds
# GUI tools (RegistryExplorer, TimelineExplorer, ...) and Windows-only tools
# (VSCMount) are intentionally excluded - they don't apply to a headless
# Linux container.
# ---------------------------------------------------------------------------
RUN set -e; \
    mkdir -p /tools/eztools; \
    for tool in \
        AmcacheParser AppCompatCacheParser bstrings EvtxECmd iisGeolocate \
        JLECmd LECmd MFTECmd PECmd RBCmd RecentFileCacheParser RECmd rla \
        SBECmd SQLECmd SrumECmd SumECmd WxTCmd; \
    do \
        mkdir -p "/tools/eztools/$tool" && \
        wget -q -U "Mozilla/5.0" -O "/tmp/$tool.zip" "https://download.ericzimmermanstools.com/net9/$tool.zip" && \
        unzip -q -o "/tmp/$tool.zip" -d "/tools/eztools/$tool" && \
        rm "/tmp/$tool.zip"; \
    done

# ---------------------------------------------------------------------------
# Didier Stevens Suite (pdfid, pdf-parser, oledump, etc.)
# ---------------------------------------------------------------------------
RUN mkdir -p /tools/didier-stevens && \
    BASE="https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master" && \
    for script in pdfid.py pdf-parser.py oledump.py base64dump.py emldump.py; do \
        wget -q -O /tools/didier-stevens/$script "$BASE/$script" && \
        chmod +x /tools/didier-stevens/$script; \
    done

# ---------------------------------------------------------------------------
# Git clones - specialized Python tools
# ---------------------------------------------------------------------------
RUN git clone --depth 1 https://github.com/keydet89/RegRipper4.0.git     /tools/RegRipper4.0
RUN git clone --depth 1 https://github.com/rowingdude/analyzeMFT.git      /tools/analyzeMFT
RUN git clone --depth 1 https://github.com/brimorlabs/KStrike.git          /tools/KStrike
RUN git clone --depth 1 https://github.com/harelsegev/INDXRipper.git       /tools/INDXRipper
RUN git clone --depth 1 https://github.com/PoorBillionaire/USN-Journal-Parser.git /tools/USN-Journal-Parser
RUN git clone --depth 1 https://github.com/Neo23x0/Loki.git                /tools/loki

# Sigma rules (large repository ~300 MB - separate layer for the Docker cache)
RUN git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tools/sigma


# =============================================================================
# Stage 2 - final (image runtime)
# =============================================================================
FROM ubuntu:24.04 AS final

ARG DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.title="Hecatrace"
LABEL org.opencontainers.image.description="DFIR Forensics Platform - all-in-one container"
LABEL org.opencontainers.image.licenses="MIT"

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python runtime + compilation
    python3 \
    python3-pip \
    python3-dev \
    swig \
    # Sleuth Kit (fls, mactime, icat, blkls, blkcat, img_stat...)
    sleuthkit \
    # Native libraries for forensics Python modules
    libtsk-dev \
    libewf-dev \
    libssl-dev \
    libffi-dev \
    libfuzzy-dev \
    build-essential \
    # bulk_extractor build dependencies (no longer packaged for Ubuntu 22.04+)
    autoconf \
    automake \
    libtool \
    flex \
    pkg-config \
    libabsl-dev \
    libexpat1-dev \
    libre2-dev \
    libxml2-utils \
    zlib1g-dev \
    # Perl + modules for RegRipper
    perl \
    libparse-win32registry-perl \
    # Disk image tools
    ewf-tools \
    afflib-tools \
    dc3dd \
    hashdeep \
    # Carving / extraction
    foremost \
    scalpel \
    binwalk \
    testdisk \
    # Metadata
    exiftool \
    # Binary analysis
    binutils \
    ssdeep \
    yara \
    # Antivirus
    clamav \
    # Compression / archives
    p7zip-full \
    unzip \
    cabextract \
    # Media
    ffmpeg \
    # Essential CLI utilities
    jq \
    ripgrep \
    fd-find \
    file \
    curl \
    wget \
    git \
    ca-certificates \
    # Shell comfort inside the container
    less \
    vim \
    nano \
    bash-completion \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# .NET 9 runtime (required by Eric Zimmerman's tools, net9 cross-platform
# builds). Neither Ubuntu's own repos (dotnet-runtime-8.0/10.0 only) nor
# Microsoft's apt feed carry 9.0 for this release, so the official
# dotnet-install.sh script is used instead - it fetches the exact channel
# directly from Microsoft's build servers regardless of distro packaging.
# ---------------------------------------------------------------------------
RUN wget -q https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh && \
    chmod +x /tmp/dotnet-install.sh && \
    /tmp/dotnet-install.sh --channel 9.0 --runtime dotnet --install-dir /usr/share/dotnet && \
    rm /tmp/dotnet-install.sh && \
    ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet

# ---------------------------------------------------------------------------
# bulk_extractor (removed from the Ubuntu/Debian archives - built from source)
# ---------------------------------------------------------------------------
RUN git clone --depth 1 --recursive https://github.com/simsong/bulk_extractor.git /tmp/bulk_extractor && \
    cd /tmp/bulk_extractor && \
    ./bootstrap.sh && \
    ./configure && \
    make -j"$(nproc)" && \
    make install && \
    cd / && rm -rf /tmp/bulk_extractor

# ---------------------------------------------------------------------------
# pip constraint: setuptools 82+ dropped pkg_resources, which several legacy
# setup.py-based packages (e.g. ssdeep) still import at build time. Pin it
# below that threshold for every pip install below, including PEP 517 build
# isolation environments.
# ---------------------------------------------------------------------------
RUN echo "setuptools<82" > /tmp/pip-constraints.txt
ENV PIP_CONSTRAINT=/tmp/pip-constraints.txt

# Ubuntu 24.04's Python is "externally managed" (PEP 668) and refuses plain
# pip installs. This is a purpose-built, single-use container image, so
# system-wide pip installs are intentional - not a conflict to guard against.
ENV PIP_BREAK_SYSTEM_PACKAGES=1

# ---------------------------------------------------------------------------
# Python: plaso first (its dependency tree resolution is heavy)
# ---------------------------------------------------------------------------
# --ignore-installed: apt's python3-pip has no RECORD file, so pip can't
# uninstall itself to upgrade in place (Debian/Ubuntu packaging quirk).
RUN pip3 install --no-cache-dir --ignore-installed --upgrade pip setuptools wheel
RUN pip3 install --no-cache-dir plaso

# ---------------------------------------------------------------------------
# Python: remaining dependencies (hecatrace + forensics libs)
# ---------------------------------------------------------------------------
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# ---------------------------------------------------------------------------
# Copying tools downloaded from the builder stage
# ---------------------------------------------------------------------------
COPY --from=builder /tools /opt/hecatrace/tools

# ---------------------------------------------------------------------------
# EZTools wrappers - lets each tool be invoked by name (e.g. "MFTECmd ...")
# instead of "dotnet /opt/hecatrace/tools/eztools/MFTECmd/MFTECmd.dll ...".
# ---------------------------------------------------------------------------
RUN set -e; \
    for tool in \
        AmcacheParser AppCompatCacheParser bstrings EvtxECmd iisGeolocate \
        JLECmd LECmd MFTECmd PECmd RBCmd RecentFileCacheParser RECmd rla \
        SBECmd SQLECmd SrumECmd SumECmd WxTCmd; \
    do \
        dll=$(find "/opt/hecatrace/tools/eztools/$tool" -iname "$tool.dll" | head -1) && \
        [ -n "$dll" ] || { echo "No .dll found for $tool" >&2; exit 1; } && \
        printf '#!/bin/sh\nexec dotnet "%s" "$@"\n' "$dll" > "/usr/local/bin/$tool" && \
        chmod +x "/usr/local/bin/$tool"; \
    done

# ---------------------------------------------------------------------------
# pip install of cloned Python tools (lenient error handling)
# ---------------------------------------------------------------------------

# analyzeMFT
RUN pip3 install --no-cache-dir /opt/hecatrace/tools/analyzeMFT 2>/dev/null || \
    ( [ -f /opt/hecatrace/tools/analyzeMFT/requirements.txt ] && \
      pip3 install --no-cache-dir -r /opt/hecatrace/tools/analyzeMFT/requirements.txt ) || true

# INDXRipper
RUN [ -f /opt/hecatrace/tools/INDXRipper/requirements.txt ] && \
    pip3 install --no-cache-dir -r /opt/hecatrace/tools/INDXRipper/requirements.txt || true

# USN-Journal-Parser
RUN [ -f /opt/hecatrace/tools/USN-Journal-Parser/requirements.txt ] && \
    pip3 install --no-cache-dir -r /opt/hecatrace/tools/USN-Journal-Parser/requirements.txt || true

# KStrike
RUN [ -f /opt/hecatrace/tools/KStrike/requirements.txt ] && \
    pip3 install --no-cache-dir -r /opt/hecatrace/tools/KStrike/requirements.txt || true

# Loki (best-effort - fragile dependencies)
RUN [ -f /opt/hecatrace/tools/loki/requirements.txt ] && \
    pip3 install --no-cache-dir -r /opt/hecatrace/tools/loki/requirements.txt 2>/dev/null || true

# ---------------------------------------------------------------------------
# PATH: exposes all tool binaries in the container's PATH
# ---------------------------------------------------------------------------
ENV PATH="/opt/hecatrace/tools/hayabusa:\
/opt/hecatrace/tools/chainsaw:\
/opt/hecatrace/tools/capa:\
/opt/hecatrace/tools/floss:\
/opt/hecatrace/tools/didier-stevens:\
${PATH}"

# PYTHONPATH: makes the Python tools directly importable
ENV PYTHONPATH="/opt/hecatrace/tools/INDXRipper:\
/opt/hecatrace/tools/USN-Journal-Parser:\
/opt/hecatrace/tools/KStrike:\
${PYTHONPATH:-}"

# ---------------------------------------------------------------------------
# Mount points (Docker volumes)
# ---------------------------------------------------------------------------
RUN mkdir -p /evidences /output /logs

# ---------------------------------------------------------------------------
# Hecatrace project files
# ---------------------------------------------------------------------------
WORKDIR /opt/hecatrace

COPY entrypoint.sh      ./entrypoint.sh
COPY process_evidence.py ./process_evidence.py
COPY config/            config/
COPY modules/           modules/
COPY resources/         resources/

RUN chmod +x entrypoint.sh

# ---------------------------------------------------------------------------
# Entrypoint + default command
# ---------------------------------------------------------------------------
ENTRYPOINT ["/opt/hecatrace/entrypoint.sh"]
CMD ["--help"]

VOLUME ["/evidences", "/output", "/logs"]
