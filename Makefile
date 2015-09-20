run:
	bash -c "source env/bin/activate; \
	./s5tun.py -d; \
	deactivate"

keys:
	cp easy-rsa/keys/ca.crt easy-rsa/keys/s54http.{crt,key} easy-rsa/keys/s5tun.{crt,key} keys/

clean:
	rm -f *.log *.pid

.PHONY: keys clean run
