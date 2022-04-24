Vulnerability Disclosure
========================

If you think you have found a potential security vulnerability in requests,
please email `Nate <mailto:nate.prewitt@gmail.com>`_ and `Seth <mailto:@sethmichaellarson@gmail.com>`_ directly. **Do not file a public issue.**

Our PGP Key fingerprints are:

- 8722 7E29 AD9C FF5C FAC3  EA6A 44D3 FF97 B80D C864 (`@nateprewitt <https://keybase.io/nateprewitt>`_)

- EDD5 6765 A9D8 4653 CBC8  A134 51B0 6736 1740 F5FC (`@sethmlarson <https://keybase.io/sethmlarson>`_)

You can also contact us on `Keybase <https://keybase.io/>`_ with the
profiles above if desired.

If English is not your first language, please try to describe the problem and
its impact to the best of your ability. For greater detail, please use your
native language and we will try our best to translate it using online services.

Please also include the code you used to find the problem and the shortest
amount of code necessary to reproduce it.

Please do not disclose this to anyone else. We will retrieve a CVE identifier
if necessary and give you full credit under whatever name or alias you provide.
We will only request an identifier when we have a fix and can publish it in a
release.

We will respect your privacy and will only publicize your involvement if you
grant us permission.

Process
-------

This following information discusses the process the requests project follows
in response to vulnerability disclosures. If you are disclosing a
vulnerability, this section of the documentation lets you know how we will
respond to your disclosure.

Timeline
~~~~~~~~

When you report an issue, one of the project members will respond to you within
two days *at the outside*. In most cases responses will be faster, usually
within 12 hours. This initial response will at the very least confirm receipt
of the report.

If we were able to rapidly reproduce the issue, the initial response will also
contain confirmation of the issue. If we are not, we will often ask for more
information about the reproduction scenario.

Our goal is to have a fix for any vulnerability released within two weeks of
the initial disclosure. This may potentially involve shipping an interim
release that simply disables function while a more mature fix can be prepared,
but will in the vast majority of cases mean shipping a complete release as soon
as possible.

Throughout the fix process we will keep you up to speed with how the fix is
progressing. Once the fix is prepared, we will notify you that we believe we
have a fix. Often we will ask you to confirm the fix resolves the problem in
your environment, especially if we are not confident of our reproduction
scenario.

At this point, we will prepare for the release. We will obtain a CVE number
if one is required, providing you with full credit for the discovery. We will
also decide on a planned release date, and let you know when it is. This
release date will *always* be on a weekday.

At this point we will reach out to our major downstream packagers to notify
them of an impending security-related patch so they can make arrangements. In
addition, these packagers will be provided with the intended patch ahead of
time, to ensure that they are able to promptly release their downstream
packages. Currently the list of people we actively contact *ahead of a public
release* is:

- Python Maintenance Team, Red Hat (python-maint@redhat.com)
- Daniele Tricoli, Debian (@eriol)

We will notify these individuals at least a week ahead of our planned release
date to ensure that they have sufficient time to prepare. If you believe you
should be on this list, please let one of the maintainers know at one of the
email addresses at the top of this article.

On release day, we will push the patch to our public repository, along with an
updated changelog that describes the issue and credits you. We will then issue
a PyPI release containing the patch.

At this point, we will publicise the release. This will involve mails to
mailing lists, Tweets, and all other communication mechanisms available to the
core team.

We will also explicitly mention which commits contain the fix to make it easier
for other distributors and users to easily patch their own versions of requests
if upgrading is not an option.

Previous CVEs
-------------

- Fixed in 2.20.0
  - `CVE 2018-18074 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2018-18074>`_

- Fixed in 2.6.0

  - `CVE 2015-2296 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2015-2296>`_,
    reported by Matthew Daley of `BugFuzz <https://bugfuzz.com/>`_.

- Fixed in 2.3.0

  - `CVE 2014-1829 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-1829>`_

  - `CVE 2014-1830 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-1830>`_
