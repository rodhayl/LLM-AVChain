# Paper Export Instructions

**Date:** 2026-04-08

The final paper is authored in Markdown (`02_LLM-AVChain_Final_Paper.md`) with a separate references file (`03_LLM-AVChain_Final_Paper_References.md`). To produce publication-ready DOCX or PDF output, follow the instructions below.

---

## Option 1: Pandoc (Recommended)

[Pandoc](https://pandoc.org/) converts Markdown to DOCX, PDF, LaTeX, and other formats.

### Install Pandoc

- **Windows (winget):** `winget install JohnMacFarlane.Pandoc`
- **Windows (choco):** `choco install pandoc`
- **macOS:** `brew install pandoc`
- **Linux:** `sudo apt install pandoc` or download from https://pandoc.org/installing.html

For PDF output, a LaTeX distribution is also required:
- **Windows:** Install MiKTeX (https://miktex.org/) or TeX Live
- **macOS:** `brew install --cask mactex`
- **Linux:** `sudo apt install texlive-full` or `texlive-latex-recommended`

### Merge Paper and References

Before export, concatenate the paper and references into a single Markdown file:

```bash
# On Windows (PowerShell)
Get-Content docs/02_LLM-AVChain_Final_Paper.md, docs/03_LLM-AVChain_Final_Paper_References.md | Set-Content docs/02_LLM-AVChain_Final_Paper_Full.md

# On Unix/macOS
cat docs/02_LLM-AVChain_Final_Paper.md docs/03_LLM-AVChain_Final_Paper_References.md > docs/02_LLM-AVChain_Final_Paper_Full.md
```

### Export to DOCX

```bash
pandoc docs/02_LLM-AVChain_Final_Paper_Full.md \
  -o docs/02_LLM-AVChain_Final_Paper.docx \
  --from markdown \
  --to docx \
  --standalone \
  --toc \
  --metadata title="LLM-AVChain: Lifecycle-Governed Cyber Threat Intelligence" \
  --metadata author="David Munoz Sanchez" \
  --metadata date="April 2026"
```

### Export to PDF (via LaTeX)

```bash
pandoc docs/02_LLM-AVChain_Final_Paper_Full.md \
  -o docs/02_LLM-AVChain_Final_Paper.pdf \
  --from markdown \
  --to pdf \
  --pdf-engine=xelatex \
  --standalone \
  --toc \
  --variable geometry:margin=1in \
  --variable fontsize=11pt \
  --metadata title="LLM-AVChain: Lifecycle-Governed Cyber Threat Intelligence" \
  --metadata author="David Munoz Sanchez" \
  --metadata date="April 2026"
```

### Export to PDF (via HTML, no LaTeX needed)

If LaTeX is not installed, use `weasyprint` for HTML-to-PDF conversion:

```bash
pip install weasyprint
pandoc docs/02_LLM-AVChain_Final_Paper_Full.md \
  -o docs/02_LLM-AVChain_Final_Paper.html \
  --from markdown \
  --to html5 \
  --standalone \
  --toc \
  --metadata title="LLM-AVChain"
weasyprint docs/02_LLM-AVChain_Final_Paper.html docs/02_LLM-AVChain_Final_Paper.pdf
```

---

## Option 2: VS Code Extensions

1. Install the **Markdown PDF** extension (`yzane.markdown-pdf`) in VS Code.
2. Open `docs/02_LLM-AVChain_Final_Paper_Full.md`.
3. Press `Ctrl+Shift+P` and select "Markdown PDF: Export (pdf)" or "Markdown PDF: Export (docx)".

---

## Option 3: Typora

[Typora](https://typora.io/) is a Markdown editor with built-in PDF and DOCX export.

1. Open `docs/02_LLM-AVChain_Final_Paper_Full.md` in Typora.
2. File > Export > PDF or File > Export > Word (.docx).

---

## Option 4: Online Converters

As a last resort, paste the Markdown content into an online converter such as:
- https://pandoc.org/try/ (Pandoc online demo, limited file size)
- https://cloudconvert.com/md-to-pdf

---

## Verification

After export, verify:
- [ ] Title appears correctly on the first page.
- [ ] Table of contents is generated (if supported by format).
- [ ] All tables render correctly.
- [ ] All 18 references appear in the References section.
- [ ] No citation artifacts (`[...]`) or broken markers remain.
- [ ] The Mermaid diagrams referenced in the paper are not inline; they should be referenced as figure captions from `docs/figures/`.
