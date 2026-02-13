FROM public.ecr.aws/x8v8d7g8/mars-base:latest

WORKDIR /app

COPY . .

# Install Requests in editable mode + dev/test dependencies.
# Do not upgrade/install pip (disallowed by guidelines).
RUN python -m pip install -e . \
    && python -m pip install -r requirements-dev.txt

CMD ["/bin/bash"]
