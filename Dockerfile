FROM amazonlinux:latest

RUN echo 'alias ll="ls -ltha"' >> ~/.bashrc

RUN yum -y update && \
    yum -y install \
      zip \
      python-pip

RUN yum groupinstall -y \
      "Development Tools"

RUN yum -y install \
      gcc \
      openssl \
      openssl-devel \
      libffi \
      libffi-devel \
      python-devel \
      gmp-devel

# Create app directory and add app
ENV APP_HOME /app
ENV APP_SRC $APP_HOME/src
RUN mkdir $APP_HOME
ADD . $APP_HOME

RUN python-pip install --use-wheel -t $APP_SRC/package/vendored/ -r $APP_SRC/requirements.txt

ADD /src/package.sh /bin/package.sh
ENTRYPOINT ["/bin/bash", "/bin/package.sh"]
