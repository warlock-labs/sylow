This directory houses our notes for implementing what we do. It is a primer on abstract algebra, and elliptic curve cryptography. We hope it's useful.

Each section is a Markdown file, which can be combined easily into the total pdf:

```bash
pandoc */**/*.md -o notes.pdf  --include-in-header ./preamble.tex --toc --toc-depth=2 -V colorlinks=true -V linkcolor=blue -V urlcolor=blue -V toccolor=gray
```
