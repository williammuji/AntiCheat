import os
import subprocess
import tempfile
import re
import sys

def run_command(cmd, cwd=None):
    try:
        subprocess.run(cmd, shell=True, check=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {cmd}")
        print(f"Details: {e}")
        sys.exit(1)

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    source_md = os.path.join(repo_root, "docs", "presentation_outline.md")

    if not os.path.exists(source_md):
        print(f"Source file not found: {source_md}")
        sys.exit(1)

    with open(source_md, 'r', encoding='utf-8') as f:
        content = f.read()

    # Create temporary directory for processing
    tmp_dir = tempfile.mkdtemp(prefix="anticheat_pres_")
    tmp_md_path = os.path.join(tmp_dir, "build.md")
    print(f"Working in temporary directory: {tmp_dir}")

    # Process mermaid diagrams into SVGs
    mermaid_blocks = re.findall(r'```mermaid\n(.*?)\n```', content, re.DOTALL)

    for i, m_content in enumerate(mermaid_blocks):
        mmd_file = os.path.join(tmp_dir, f"chart_{i}.mmd")
        svg_file = os.path.join(tmp_dir, f"chart_{i}.svg")

        with open(mmd_file, 'w', encoding='utf-8') as f:
            f.write(m_content)

        # Run mmdc
        print(f"Generating SVG for chart {i}...")
        run_command(f"mmdc -i {mmd_file} -o {svg_file} -b transparent")

        # Replace mermaid block with image link
        svg_rel_path = f"chart_{i}.svg"
        content = content.replace(f"```mermaid\n{m_content}\n```", f"![chart]({svg_rel_path})")

    # Split into slides
    slides_raw = re.split(r'<div style="page-break-after: always;"></div>', content)
    slides = [s.strip() for s in slides_raw if s.strip()]

    processed_slides = []
    for idx, slide in enumerate(slides):
        # Determine if slide is only a chart
        # A chart-only slide typically has an h1 and then exactly one image
        lines = [l.strip() for l in slide.split('\n') if l.strip()]

        has_h1 = any(l.startswith('# ') for l in lines)
        has_img = sum(1 for l in lines if l.startswith('![chart]')) == 1

        # If it's short and has a chart, assume it's a chart slide
        is_chart_only = has_h1 and has_img and len(lines) <= 3

        if idx == 0:
             processed_slides.append("<!-- _class: title-slide -->\n" + slide)
        elif is_chart_only:
             processed_slides.append("<!-- _class: centered-chart -->\n" + slide)
        else:
             processed_slides.append(slide)

    # Rejoin with horizontal rules for Marp
    final_markdown = "\n\n---\n\n".join(processed_slides)

    # Add Marp frontmatter and custom CSS
    frontmatter = """---
marp: true
theme: default
paginate: true
style: |
  section {
    justify-content: flex-start;
    align-items: flex-start;
    padding-top: 120px;
    padding-left: 60px;
    padding-right: 60px;
  }

  h1 {
    position: absolute;
    top: 40px;
    left: 60px;
    margin: 0;
    width: calc(100% - 120px);
    text-align: left;
  }

  /* Reset alignment for content */
  p, li, pre, table {
    text-align: left;
    width: 100%;
  }

  /* Specific class for first page */
  section.title-slide {
    justify-content: center;
    align-items: center;
    padding-top: 0;
  }

  section.title-slide h1, section.title-slide h2 {
    position: static;
    text-align: center;
    width: auto;
  }

  /* Specific class for charts */
  section.centered-chart {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
  }

  section.centered-chart p {
    text-align: center;
    display: flex;
    justify-content: center;
    align-items: center;
    width: 100%;
    height: 100%;
    margin: 0;
  }

  section.centered-chart img {
    max-height: 80vh;
    max-width: 90vw;
    object-fit: contain;
  }
---

"""

    final_content = frontmatter + final_markdown

    with open(tmp_md_path, 'w', encoding='utf-8') as f:
        f.write(final_content)

    print("Generating PDF...")
    pdf_out = os.path.join(repo_root, "docs", "presentation_outline.pdf")
    run_command(f"marp {tmp_md_path} --pdf -o '{pdf_out}' --allow-local-files", cwd=tmp_dir)

    print("Generating PPTX...")
    pptx_out = os.path.join(repo_root, "docs", "presentation_outline.pptx")
    run_command(f"marp {tmp_md_path} --pptx -o '{pptx_out}' --allow-local-files", cwd=tmp_dir)

    print("Done! Generated files:")
    print(f"- {pdf_out}")
    print(f"- {pptx_out}")

if __name__ == "__main__":
    main()
