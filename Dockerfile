FROM pypy:3

RUN mkdir /s5p/
COPY requirements.txt /s5p/
COPY s54http/utils.py /s5p/
COPY s54http/server.py /s5p/
COPY keys /s5p/keys

WORKDIR /s5p/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

CMD ["pypy3", "server.py"]
