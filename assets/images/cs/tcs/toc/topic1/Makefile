FILENAME ?= 

.PHONY: compile

compile:
	xelatex -no-pdf -interaction=batchmode -halt-on-error $(FILENAME).tex > /dev/null
	dvisvgm $(FILENAME).xdv -n -v 0 -o $(FILENAME).svg > /dev/null
	rm $(FILENAME).xdv $(FILENAME).aux $(FILENAME).log