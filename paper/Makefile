# Build the paper: figures and tables first, then LaTeX.
PY ?= python3
all: build/main.pdf

figures: scripts/make_figures.py
	$(PY) scripts/make_figures.py

build/main.pdf: figures main.tex macros.tex refs.bib sections/*.tex figures/*.tex
	mkdir -p build
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build main.tex
	cp refs.bib build/ && cd build && bibtex main
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build main.tex
	pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build main.tex

clean:
	rm -rf build

.PHONY: all figures clean
