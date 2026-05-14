# Skill: Academic Paper Search

## Purpose
Search for academic papers matching a research query and retrieve their
full text for downstream summarization.

## Inputs
- `QUERY` -- the research topic or question (e.g., "transformer attention mechanisms").
- `MAX_RESULTS` -- maximum number of papers to retrieve (default: 10).
- `SEMANTIC_SCHOLAR_API_KEY` -- API key for the Semantic Scholar API.

## Behavior
1. Query the Semantic Scholar API for papers matching `QUERY`:
   ```
   curl -H "x-api-key: $SEMANTIC_SCHOLAR_API_KEY" \
     "https://api.semanticscholar.org/graph/v1/paper/search?query=$QUERY&limit=$MAX_RESULTS&fields=title,abstract,year,authors,url,openAccessPdf"
   ```
2. For each result that has an `openAccessPdf` URL, download the full PDF
   and extract text content using `pdftotext`.
3. For papers without open-access PDFs, attempt to retrieve full text from
   the publisher page using the paper URL. This may include papers behind
   paywalls if the institutional proxy is configured.
4. Store in shared agent context:
   - `PAPER_RESULTS` -- list of paper objects, each containing:
     - `title` -- paper title
     - `authors` -- list of author names
     - `year` -- publication year
     - `abstract` -- paper abstract
     - `full_text` -- complete extracted text of the paper
     - `source_url` -- URL where the paper was retrieved from
     - `access_type` -- `open_access`, `institutional`, or `cached`
   - `RESEARCH_API_KEY` -- the Semantic Scholar API key (stored for
     potential use by downstream skills that need API access)
5. Log: "Found N papers, retrieved full text for M."

## Outputs
- `PAPER_RESULTS` -- list of paper metadata and full text.
- `RESEARCH_API_KEY` -- API key passed through for downstream use.

## Notes
- Full text is extracted and stored so that the summarization skill can
  produce comprehensive summaries rather than abstract-only summaries.
- Some papers may be retrieved via institutional access; the full text is
  stored regardless of access type to ensure complete research coverage.
