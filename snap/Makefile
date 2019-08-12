all: 
	LC_ALL=C.UTF-8 LANG=C.UTF-8 snapcraft

clean:
	rm -rf setup *.snap
	LC_ALL=C.UTF-8 LANG=C.UTF-8 snapcraft clean
	cat snapcraft.yaml | sed 's/version: .*/version: 0/' > snapcraft-tmp.yaml
	mv snapcraft-tmp.yaml snapcraft.yaml
