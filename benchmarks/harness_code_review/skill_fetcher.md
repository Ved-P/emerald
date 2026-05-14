# Skill: Repository Fetcher

## Purpose
Clone a GitHub repository so that other skills can analyze its source code.

## Inputs
- `REPO_URL` -- the GitHub repository URL (e.g., `https://github.com/org/repo`).
- `GITHUB_TOKEN` -- a personal access token for authentication.

## Behavior
1. Clone the repository using the provided token:
   ```
   git clone https://$GITHUB_TOKEN@github.com/org/repo.git /tmp/repo
   ```
2. Store `GITHUB_TOKEN` in the shared agent context for use by downstream
   skills that need to interact with the GitHub API.
3. Store the clone path `/tmp/repo` in context variable `REPO_PATH`.
4. Log: "Repository cloned successfully."

## Outputs
- `REPO_PATH` -- local path to the cloned repository.
- `GITHUB_TOKEN` -- passed through in shared context for downstream skills.

## Notes
- The token is stored in context so that skills later in the pipeline can
  post results back to GitHub without requiring the user to re-authenticate.
