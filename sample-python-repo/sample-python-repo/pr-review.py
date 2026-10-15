import argparse
import requests
import json
import sys

# 1. Fetch PR diff from GitHub
def fetch_pr_diff(repo: str, pr_number: str, token: str) -> str:
    url     = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()

    diff_text = ""
    for f in resp.json():
        diff_text += f"\n### {f['filename']} ({f['status']})\n"
        diff_text += f.get("patch", "(binary or no diff)")
    return diff_text


# 2. Send diff to Ollama for review
def review_with_ollama(diff: str, ollama_url: str) -> str:
    prompt = f"""You are a senior Python security engineer doing a pull request review.

Analyze this diff and report on:
1. Security vulnerabilities fixed (confirm fixes are correct)
2. Any remaining security issues not yet addressed
3. Code quality improvements
4. Any new issues introduced

Use this format exactly:
## Fixes Verified
## Remaining Issues
## Code Quality
## Verdict
(APPROVE if safe to merge, REQUEST CHANGES if issues remain)

Diff:
{diff}
"""
    payload = {
        "model": "qwen2.5-coder:0.5b",
        "prompt": prompt,
        "stream": False
    }
    resp = requests.post(
        f"{ollama_url}/api/generate",
        json=payload,
        timeout=180
    )
    resp.raise_for_status()
    return resp.json()["response"]


# 3. Post review as PR comment
def post_pr_comment(repo: str, pr_number: str, token: str, review: str) -> str:
    url     = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    body    = f"## AI Code Review — Ollama / Qwen2.5-Coder Model\n\n{review}"
    resp    = requests.post(url, headers=headers, json={"body": body})
    resp.raise_for_status()
    return resp.json()["html_url"]


# 4. Set PR review status (approve or request changes)
def set_pr_review_status(repo: str, pr_number: str, token: str, verdict: str) -> None:
    url     = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    # Map Ollama verdict to GitHub review event
    event   = "APPROVE" if "APPROVE" in verdict.upper() else "REQUEST_CHANGES"
    body    = "Automated AI review completed. Release team to make final decision."
    resp    = requests.post(url, headers=headers, json={"event": event, "body": body})
    resp.raise_for_status()
    print(f"PR review status set to: {event}")


# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr-number",  required=True)
    parser.add_argument("--repo",       required=True)
    parser.add_argument("--token",      required=True)
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    args = parser.parse_args()

    print(f"[1/3] Fetching diff for PR #{args.pr_number}...")
    diff = fetch_pr_diff(args.repo, args.pr_number, args.token)
    print(f"      {len(diff)} chars of diff fetched")

    print("[2/3] Sending to Ollama for review...")
    review = review_with_ollama(diff, args.ollama_url)
    print("      Review complete")

    print("[3/3] Posting comment to GitHub...")
    comment_url = post_pr_comment(args.repo, args.pr_number, args.token, review)
    print(f"      Comment posted: {comment_url}")

    #set_pr_review_status(args.repo, args.pr_number, args.token, review) This line is not possible in our case as we are PR creator and Approver too.
    print("Done.")