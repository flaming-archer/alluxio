FROM gitlab/gitlab-runner:latest

RUN apt-get -q update \
    && apt-get -q install -y --no-install-recommends \
        apt-utils \
        curl \
        vim \
        git \
        sudo \
        maven \
        openjdk-8-jdk \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN wget -c https://go.dev/dl/go1.17.5.linux-amd64.tar.gz -O -|tar -xz -C /usr/local/
RUN ln -s /usr/local/go/bin/go /usr/bin/go && ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt

ADD settings.xml /etc/maven/ 

ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64
ENV MAVEN_HOME /usr/share/maven
ENV PATH $JAVA_HOME/bin:$MAVEN_HOME/bin:$PATH

RUN mkdir /usr/local/tarball
RUN chmod 777 /usr/local/tarball
RUN mkdir /usr/local/.m2
RUN chmod 777 /usr/local/.m2
