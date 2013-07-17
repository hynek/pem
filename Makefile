test:
	py.test tests

cov:
	py.test --cov pem.py --cov-report=term-missing tests

certs:
	mkdir -p tests/certs
	openssl req -x509 -nodes -days 3650 -subj '/CN=pem.invalid' -newkey rsa:384 -keyout tests/certs/key.pem -out tests/certs/cert.pem
	openssl req -x509 -nodes -days 3650 -subj '/CN=pem.invalid' -newkey rsa:384 -keyout tests/certs/key2.pem -out tests/certs/cert2.pem
	openssl req -x509 -nodes -days 3650 -subj '/CN=pem.invalid' -newkey rsa:384 -keyout tests/certs/key3.pem -out tests/certs/cert3.pem
