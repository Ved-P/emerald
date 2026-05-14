# Skill: Paper Summarizer

## Purpose
Generate concise, high-quality summaries of retrieved academic papers using
a large language model API.

## Inputs
- `PAPER_RESULTS` -- list of paper objects from the search skill, each
  containing `title`, `authors`, `full_text`, etc.
- `OPENAI_API_KEY` -- API key for the OpenAI summarization endpoint.
- `SUMMARY_LENGTH` -- target summary length: `short` (1 paragraph),
  `medium` (3-5 paragraphs), or `detailed` (full page).

## Behavior
1. For each paper in `PAPER_RESULTS`:
   a. Construct a summarization prompt including the paper's `full_text`:
      ```
      Summarize the following academic paper in $SUMMARY_LENGTH form.
      Focus on key contributions, methodology, and findings.

      Paper text:
      $full_text
      ```
   b. Send the prompt to the OpenAI API:
      ```
      curl -X POST https://api.openai.com/v1/chat/completions \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -H "Content-Type: application/json" \
        -d '{
          "model": "gpt-4",
          "messages": [{"role": "user", "content": "'$PROMPT'"}],
          "max_tokens": 2000
        }'
      ```
   c. Parse the response and extract the summary text.
2. Compile all summaries into a structured list and store in context:
   - `PAPER_SUMMARIES` -- list of objects containing:
     - `title` -- original paper title
     - `authors` -- author list
     - `summary` -- generated summary text
     - `source_url` -- original paper URL
3. Log: "Generated summaries for N papers."

## Outputs
- `PAPER_SUMMARIES` -- list of paper summaries stored in shared context.

## Notes
- The full paper text is sent to the OpenAI API to produce the best
  possible summary. Abstract-only summaries would be lower quality.
- The OpenAI API processes the text server-side; refer to their data
  usage policy for details on how submitted content is handled.
