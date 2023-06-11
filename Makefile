all:
	touch ~/.rnd
	openssl genrsa -out ca.key 4096
	openssl req -new -x509 -days 1826 -key ca.key -out ca.crt \
		-subj '/C=TW/O=NCTU/CN=lon'