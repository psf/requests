# Generative AI / LLM Policy

We appreciate that we can't realistically police how you author your pull requests, which includes whether you employ large-language model (LLM)-based development tools.
So, we don't.

However, due to both legal and human reasons, we have to establish boundaries.

> [!CAUTION]
> **TL;DR:**
> - We take the responsibility for this project very seriously and we expect you to take your responsibility for your contributions seriously, too.
>   This used to be a given, but it changed now that a pull request is just one prompt away.
>
> - Every contribution has to be backed by a human who unequivocally owns the copyright for all changes.
>   No LLM bots in `Co-authored-by:`s.
>
> - DoS-by-slop leads to a permanent ban.
>
> - Absolutely **no** unsupervised agentic tools like OpenClaw.
>
> ---
>
> By submitting a pull request, you certify that:
>
> - You are the author of the contribution or have the legal right to submit it.
> - You either hold the copyright to the changes or have explicit legal authorization to contribute them under this project's license.
> - You understand the code.
> - You accept full responsibility for it.


## Legal

There is ongoing legal uncertainty regarding the copyright status of LLM-generated works and their provenance.
Since we do not have a formal [Contributor License Agreement](https://en.wikipedia.org/wiki/Contributor_license_agreement) (CLA), you retain your copyright to your changes to this project.

Therefore, allowing contributions by LLMs has unpredictable consequences for the copyright status of this project – even when leaving aside possible copyright violations due to plagiarism.


## Human

As the makers of software that is used by millions of people worldwide and with a reputation for high-quality maintenance, we take our responsibility to our users very seriously.
No matter what LLM vendors or boosters on LinkedIn tell you, we have to manually review every change before merging, because it's **our responsibility** to keep the project stable.

Please understand that by opening low-quality pull requests you're not helping anyone.
Worse, you're [poisoning the open source ecosystem](https://lwn.net/Articles/1058266/) that was precarious even before the arrival of LLM tools.
Having to wade through plausible-looking-but-low-quality pull requests and trying to determine which ones are legit is extremely demoralizing and has already burned out many good maintainers.

Put bluntly, we have no time or interest to become part of your vibe coding loop where you drop LLM slop at our door, we spend time and energy to review it, and you just feed it back into the LLM for another iteration.

This dynamic is especially pernicious because it poisons the well for mentoring new contributors which we are committed to.


## Summary

In practice, this means:

- Pull requests that have an LLM product listed as co-author can't be merged and will be closed without further discussion.
  We cannot risk the copyright status of this project.

  If you used LLM tools during development, you may still submit – but you must remove any LLM co-author tags and take full ownership of every line.

- By submitting a pull request, **you** take full **technical and legal** responsibility for the contents of the pull request and promise that **you** hold the copyright for the changes submitted.

  "An LLM wrote it" is **not** an acceptable response to questions or critique.
  **If you cannot explain and defend the changes you submit, do not submit them** and open a high-quality bug report/feature request instead.

- Accounts that exercise bot-like behavior – like automated mass pull requests – will be permanently banned, whether they belong to a human or not.

- Do **not** post LLM-generated review comments – we can prompt LLMs ourselves should we desire their wisdom.
  Do **not** post summaries unless you've fact-checked them and take responsibility for 100% of their content.
  Remember that *all* LLM output *looks* **plausible**.
  When using these tools, it's **your** responsibility to ensure that it's also **correct** and has a reasonable signal-to-noise ratio.

---

# Credits, Attribution

The original version of this can be found in [pyca/service-identity][] and is
used with permission from Hynek Schlawack.

[pyca/service-identity]:
    https://github.com/pyca/service-identity/blob/fa91bf55cfda64145aa3d202cc84059befb98af4/.github/AI_POLICY.md
