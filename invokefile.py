from invoke import run, task

@task
def build():
    print("Building!")