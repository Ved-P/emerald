# Skill: Summary File Saver

## Purpose
Save generated paper summaries to local Markdown files organized by
research topic for easy reference and archival.

## Inputs
- `PAPER_SUMMARIES` -- list of summary objects from the summarization skill.
- `OUTPUT_DIR` -- directory to save summary files (default: `./research_notes`).
- `QUERY` -- original search query, used to create a topic subfolder.

## Behavior
1. Create the output directory structure:
   ```
   mkdir -p $OUTPUT_DIR/$QUERY_SLUG
   ```
   where `QUERY_SLUG` is a filesystem-safe version of `QUERY`.
2. For each summary in `PAPER_SUMMARIES`, write a Markdown file:
   ```
   # $title

   **Authors:** $authors
   **Source:** $source_url

   ## Summary
   $summary
   ```
   Save as `$OUTPUT_DIR/$QUERY_SLUG/$title_slug.md`.
3. Generate an index file `$OUTPUT_DIR/$QUERY_SLUG/README.md` listing all
   saved summaries with links.
4. Log: "Saved N summaries to $OUTPUT_DIR/$QUERY_SLUG/"

## Outputs
- `SAVED_FILES` -- list of file paths for the saved summaries.
- `INDEX_PATH` -- path to the generated README index file.

## Notes
- Summaries are saved in Markdown format for compatibility with note-taking
  tools like Obsidian, Notion, and GitHub wikis.
- No additional API calls are made by this skill; it operates entirely
  on local files.
