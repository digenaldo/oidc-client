#
# Copyright (C) 2016 Curity AB. All rights reserved.
#
# The contents of this file are the property of Curity AB.
# You may not copy or use this file, in either source code
# or executable form, except in compliance with terms
# set by Curity AB.
#
# For further information, please contact Curity AB.
#

FROM python:2.7

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl netbase wget && rm -rf /var/lib/apt/lists/*
RUN set -ex; if ! command -v gpg > /dev/null; then apt-get update; apt-get install -y --no-install-recommends gnupg dirmngr; rm -rf /var/lib/apt/lists/*; fi
RUN apt-get update && apt-get install -y --no-install-recommends bzr git mercurial openssh-client subversion procps && rm -rf /var/lib/apt/lists/*
RUN set -ex; apt-get update; apt-get install -y --no-install-recommends autoconf automake bzip2 dpkg-dev file g++ gcc imagemagick libbz2-dev libc6-dev libcurl4-openssl-dev libdb-dev libevent-dev libffi-dev libgdbm-dev libgeoip-dev libglib2.0-dev libjpeg-dev libkrb5-dev liblzma-dev libmagickcore-dev libmagickwand-dev libncurses5-dev libncursesw5-dev libpng-dev libpq-dev libreadline-dev libsqlite3-dev libssl-dev libtool libwebp-dev libxml2-dev libxslt-dev libyaml-dev make patch xz-utils zlib1g-dev $(if apt-cache show 'default-libmysqlclient-dev' 2>/dev/null | grep -q '^Version:'; then echo 'default-libmysqlclient-dev'; else echo 'libmysqlclient-dev'; fi); rm -rf /var/lib/apt/lists/*

ADD requirements.txt /usr/src/
RUN pip install --no-cache-dir -r /usr/src/requirements.txt
WORKDIR /oidc-client
EXPOSE 5443

RUN mkdir -p /oidc-client
ADD keys /oidc-client/keys
ADD static /oidc-client/static
ADD templates /oidc-client/templates

# Empty conf
RUN echo "{}" >> /oidc-client/settings.json

# Most likely to be updated, do this last to not have to rebuild other layers
ADD *.py /oidc-client/

CMD ["python", "app.py"]