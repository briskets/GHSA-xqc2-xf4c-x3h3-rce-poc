SHELL := /bin/sh

.PHONY: help lab patched poc check clean

help:
	@printf '%s\n' \
		'make lab      Build and run the vulnerable lab on 127.0.0.1:3100' \
		'make patched  Build and run the patched lab on 127.0.0.1:3101' \
		'make poc      Run the PoC against the vulnerable lab' \
		'make check    Compile the PoC and print its help' \
		'make clean    Remove local Python caches'

lab:
	docker build -t ghsa-xqc2-lab ./lab
	docker run --rm -p 127.0.0.1:3100:3100 ghsa-xqc2-lab

patched:
	docker build --build-arg NEXT_VERSION=16.4.1 -t ghsa-xqc2-lab-patched ./lab
	docker run --rm -p 127.0.0.1:3101:3100 ghsa-xqc2-lab-patched

poc:
	python3 poc.py http://127.0.0.1:3100 --cmd 'id; uname -a'

check:
	python3 -m py_compile poc.py
	python3 poc.py --help >/dev/null
	@printf '%s\n' 'PoC check passed'

clean:
	rm -rf __pycache__
