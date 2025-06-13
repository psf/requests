# Vulnerability Disclosure

If you think you have found a potential security vulnerability in
requests, please open a [draft Security Advisory](https://github.com/psf/requests/security/advisories/new)
via GitHub. We will coordinate verification and next steps through
that secure medium.

If English is not your first language, please try to describe the
problem and its impact to the best of your ability. For greater detail,
please use your native language and we will try our best to translate it
using online services.

Please also include the code you used to find the problem and the
shortest amount of code necessary to reproduce it.

Please do not disclose this to anyone else. We will retrieve a CVE
identifier if necessary and give you full credit under whatever name or
alias you provide. We will only request an identifier when we have a fix
and can publish it in a release.

We will respect your privacy and will only publicize your involvement if
you grant us permission.

## Process

This following information discusses the process the requests project
follows in response to vulnerability disclosures. If you are disclosing
a vulnerability, this section of the documentation lets you know how we
will respond to your disclosure.

### Timeline

When you report an issue, one of the project members will respond to you
within two days *at the outside*. In most cases responses will be
faster, usually within 12 hours. This initial response will at the very
least confirm receipt of the report.

If we were able to rapidly reproduce the issue, the initial response
will also contain confirmation of the issue. If we are not, we will
often ask for more information about the reproduction scenario.

Our goal is to have a fix for any vulnerability released within two
weeks of the initial disclosure. This may potentially involve shipping
an interim release that simply disables function while a more mature fix
can be prepared, but will in the vast majority of cases mean shipping a
complete release as soon as possible.

Throughout the fix process we will keep you up to speed with how the fix
is progressing. Once the fix is prepared, we will notify you that we
believe we have a fix. Often we will ask you to confirm the fix resolves
the problem in your environment, especially if we are not confident of
our reproduction scenario.

At this point, we will prepare for the release. We will obtain a CVE
number if one is required, providing you with full credit for the
discovery. We will also decide on a planned release date, and let you
know when it is. This release date will *always* be on a weekday.

At this point we will reach out to our major downstream packagers to
notify them of an impending security-related patch so they can make
arrangements. In addition, these packagers will be provided with the
intended patch ahead of time, to ensure that they are able to promptly
release their downstream packages. Currently the list of people we
actively contact *ahead of a public release* is:

-   Python Maintenance Team, Red Hat (python-maint@redhat.com)
-   Daniele Tricoli, Debian (@eriol)

We will notify these individuals at least a week ahead of our planned
release date to ensure that they have sufficient time to prepare. If you
believe you should be on this list, please let one of the maintainers
know at one of the email addresses at the top of this article.

On release day, we will push the patch to our public repository, along
with an updated changelog that describes the issue and credits you. We
will then issue a PyPI release containing the patch.

At this point, we will publicise the release. This will involve mails to
mailing lists, Tweets, and all other communication mechanisms available
to the core team.

We will also explicitly mention which commits contain the fix to make it
easier for other distributors and users to easily patch their own
versions of requests if upgrading is not an option.
