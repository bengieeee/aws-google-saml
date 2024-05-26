FROM public.ecr.aws/docker/library/python:3.11-alpine

COPY . /app

WORKDIR /app

RUN pip install --upgrade build && \
    python -m build && \
    pip install dist/*.whl

ENV RUNTIME DOCKER

EXPOSE 35002

ENTRYPOINT [ "aws-google-saml" ]

