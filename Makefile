
keys:
	cp easy-rsa/keys/ca.crt easy-rsa/keys/s54http.{crt,key} easy-rsa/keys/s5tun.{crt,key} keys/

clean:
	rm -f *.log *.pid

.PHONY:keys clean
