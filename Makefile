s5tun:
	bash -c "source env/bin/activate; \
	./s5tun.py -d; \
	deactivate"

s54http:
	bash -c "source env/bin/activate; \
	./s54http.py -d; \
	deactivate"

stop:
	kill -9 $(shell cat *.pid)

keys:
	cp easy-rsa/keys/ca.crt easy-rsa/keys/s54http.{crt,key} easy-rsa/keys/s5tun.{crt,key} keys/

clean:
	rm -f *.log *.pid __pycache__/*

.PHONY: keys clean s5tun s54http
