PYTHON=python3
TOX=tox

.NOTPARALLEL:

.PHONY: test
test: clean
	$(MAKE) egg_info
	tox

README: README.md
	echo -e '.. WARNING: AUTO-GENERATED FILE. DO NOT EDIT.\n' > $@
	pandoc --from=markdown --to=rst $< >> $@

.PHONY: cleanso
cleanso:
	rm -f kkdcpasn1*.s[ol] kkdcpasn1*.dyn

.PHONY: clean
clean: cleanso
	rm -rf build dist
	find ./ -name '*.py[co]' -exec rm -f {} \;
	find ./ -depth -name __pycache__ -exec rm -rf {} \;
	rm -f aflpy

.PHONY: distclean
distclean: clean
	rm -f src/kkdcpasn1.c
	rm -f MANIFEST
	rm -rf .tox .cache
	rm -rf src/*.egg-info *.egg-info

.PHONY: tox
tox: clean
	$(TOX)

.PHONY: egg_info
egg_info: README
	$(PYTHON) setup.py egg_info

.PHONY: packages
packages: distclean egg_info
	$(PYTHON) setup.py packages

.PHONY: asn1
asn1:
	$(MAKE) -C src/asn1 asn1

.PHONY: check
check: clean asn1
	$(PYTHON) setup.py build_ext -i
	$(PYTHON) -c "import kkdcpasn1"

.PHONY: aflfuzz
aflfuzz: clean
	mkdir -p $(CURDIR)/afl-output
	afl-gcc $$(pkg-config --cflags --libs $(PYTHON)) \
	    -o $(CURDIR)/aflpy $(CURDIR)/contrib/aflpy.c
	CC=afl-gcc $(PYTHON) setup.py build_ext -i -f
	afl-fuzz -i $(CURDIR)/testcases -o $(CURDIR)/afl-output $(CURDIR)/aflpy

