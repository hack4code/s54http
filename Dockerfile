FROM python

RUN mkdir /s5p/
COPY keys /s5p/keys
COPY setup.py /s5p/
COPY s54http /s5p/s54http

WORKDIR /s5p/
RUN pip install --upgrade pip
RUN pip install .
