# Contribution Guidelines

Before opening any issues or proposing any pull requests, please do the
following:

1. Read our [Contributor's Guide](http://docs.python-requests.org/en/latest/dev/contributing/).
2. Understand our [development philosophy](http://docs.python-requests.org/en/latest/dev/philosophy/).

To get the greatest chance of helpful responses, please also observe the
following additional notes.

## Questions

The GitHub issue tracker is for *bug reports* and *feature requests*. Please do
not use it to ask questions about how to use Requests. These questions should
instead be directed to [Stack Overflow](https://stackoverflow.com/). Make sure
that your question is tagged with the `python-requests` tag when asking it on
Stack Overflow, to ensure that it is answered promptly and accurately.

## Good Bug Reports

Please be aware of the following things when filing bug reports:

1. Avoid raising duplicate issues. *Please* use the GitHub issue search feature
   to check whether your bug report or feature request has been mentioned in
   the past. Duplicate bug reports and feature requests are a huge maintenance
   burden on the limited resources of the project. If it is clear from your
   report that you would have struggled to find the original, that's ok, but
   if searching for a selection of words in your issue title would have found
   the duplicate then the issue will likely be closed extremely abruptly.
2. When filing bug reports about exceptions or tracebacks, please include the
   *complete* traceback. Partial tracebacks, or just the exception text, are
   not helpful. Issues that do not contain complete tracebacks may be closed
   without warning.
3. Make sure you provide a suitable amount of information to work with. This
   means you should provide:

   - Guidance on **how to reproduce the issue**. Ideally, this should be a
     *small* code sample that can be run immediately by the maintainers.
     Failing that, let us know what you're doing, how often it happens, what
     environment you're using, etc. Be thorough: it prevents us needing to ask
     further questions.
   - Tell us **what you expected to happen**. When we run your example code,
     what are we expecting to happen? What does "success" look like for your
     code?
   - Tell us **what actually happens**. It's not helpful for you to say "it
     doesn't work" or "it fails". Tell us *how* it fails: do you get an
     exception? A hang? A non-200 status code? How was the actual result
     different from your expected result?
   - Tell us **what version of Requests you're using**, and
     **how you installed it**. Different versions of Requests behave
     differently and have different bugs, and some distributors of Requests
     ship patches on top of the code we supply.

   If you do not provide all of these things, it will take us much longer to
   fix your problem. If we ask you to clarify these and you never respond, we
   will close your issue without fixing it.
