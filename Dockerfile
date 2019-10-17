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