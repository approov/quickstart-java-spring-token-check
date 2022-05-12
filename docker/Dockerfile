FROM openjdk:11.0.3

ARG CONTAINER_USER="developer"
ARG CONTAINER_UID="1000"
ARG ZSH_THEME="robbyrussell"
ARG GRADLE_VERSION=5.2.1


# Will not prompt for questions
ENV DEBIAN_FRONTEND=noninteractive \
    CONTAINER_USER="${CONTAINER_USER}" \
    CONTAINER_UID="${CONTAINER_UID}" \
    ROOT_CA_DIR=/root-ca/ \
    ROOT_CA_KEY="self-signed-root-ca.key" \
    ROOT_CA_PEM="self-signed-root-ca.pem" \
    ROOT_CA_NAME="ApproovStackRootCA" \
    PROXY_CA_FILENAME="FirewallProxyCA.crt" \
    PROXY_CA_PEM="certificates/FirewallProxyCA.crt" \
    PROXY_CA_NAME="FirewallProxy" \
    NO_AT_BRIDGE=1 \
    DISPLAY=":0" \
    GRADLE_HOME=/opt/gradle/gradle-"${GRADLE_VERSION}" \
    PATH=/opt/gradle/gradle-"${GRADLE_VERSION}"/bin:${PATH}

COPY ./setup ${ROOT_CA_DIR}

RUN apt update && \
    apt -y upgrade && \

    apt -y install \
      python3 \
      python3-pip \
      locales \
      tzdata \
      ca-certificates \
      inotify-tools \
      libnss3-tools \
      zip \
      zsh \
      curl \
      git \
      maven && \

    printf "\n\n----------> FORCING INSTALLATION OF MISSING DEPENDENCIES <------------\n\n" && \
    apt -y -f install && \

    printf "\n\n----------> FIXING INOTIFY WATCHES <------------\n\n" && \
    #https://github.com/guard/listen/wiki/Increasing-the-amount-of-inotify-watchers
    printf "fs.inotify.max_user_watches=524288\n" >> /etc/sysctl.conf && \

    printf "\n\n----------> ADDING LOCALE <------------\n\n" && \
    echo "en_GB.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen en_GB.UTF-8 && \
    dpkg-reconfigure locales && \

    printf "\n\n----------> ADDING A USER <------------\n\n" && \
    useradd -m -u ${CONTAINER_UID} -s /usr/bin/zsh ${CONTAINER_USER} && \

    printf "\n\n----------> INSTALLING CUSTOM CERTIFICATES <------------\n\n" && \
    cd ${ROOT_CA_DIR} && \
    ./setup-root-certificate.sh "${ROOT_CA_KEY}" "${ROOT_CA_PEM}" "${ROOT_CA_NAME}" && \
    ./add-proxy-certificate.sh "${PROXY_CA_PEM}" && \

    printf "\n\n----------> INSTALLING GRADLE <------------\n\n" && \
    curl -o gradle.zip -fsSL https://services.gradle.org/distributions/gradle-"${GRADLE_VERSION}"-bin.zip && \
    unzip -d /opt/gradle gradle.zip && \
    rm -f gradle.zip && \
    gradle --version && \

    printf "\n\n----------> INSTALLING OH MY ZSH <------------\n\n" && \
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)" && \
    chsh -s /usr/bin/zsh && \
    cp -R /root/.oh-my-zsh /home/"${CONTAINER_USER}" && \
    cp /root/.zsh* /home/"${CONTAINER_USER}" && \
    sed -i "s/\/root/\/home\/${CONTAINER_USER}/g" /home/"${CONTAINER_USER}"/.zshrc && \
    chown -R "${CONTAINER_USER}":"${CONTAINER_USER}" /home/"${CONTAINER_USER}" && \

    printf "\n\n----------> CLEANUP <------------\n\n" && \
    rm -rvf /var/lib/apt/lists/*

ENV LANG=en_GB.UTF-8 \
    LANGUAGE=en_GB:en \
    LC_ALL=en_GB.UTF-8

USER ${CONTAINER_USER}

RUN pip3 install \
  pyjwt \
  docopt

# pip install will put the executables under ~/.local/bin
ENV PATH=/home/"${CONTAINER_USER}"/.local/bin:$PATH

WORKDIR /home/${CONTAINER_USER}/workspace

CMD ["zsh"]
