VERSION=$(shell git tag | tail -1 | cut -c2-)
COMMITS=$(shell git log --oneline | wc -l)
SHA=$(shell git log -1 --oneline | cut -d' ' -f1)
DATE=$(shell date +'%Y%m%d')
V=$(VERSION)-$(DATE)-$(COMMITS)-$(SHA)

all: set_version
	LC_ALL=C.UTF-8 LANG=C.UTF-8 snapcraft

set_version:
	cat snapcraft.yaml | sed 's/version: .*/version: $(V)/' > snapcraft-tmp.yaml
	mv snapcraft-tmp.yaml snapcraft.yaml

clean:
	rm -rf setup *.snap
	LC_ALL=C.UTF-8 LANG=C.UTF-8 snapcraft clean
	cat snapcraft.yaml | sed 's/version: .*/version: 0/' > snapcraft-tmp.yaml
	mv snapcraft-tmp.yaml snapcraft.yaml
