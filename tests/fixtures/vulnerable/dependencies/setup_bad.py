from setuptools import setup

# DEP103: wildcard version specifiers in install_requires
# DEP104: unpinned install_requires entries
setup(
    name="myapp",
    version="1.0.0",
    install_requires=[
        "flask",
        "requests>=2.28",
        "sqlalchemy~=2.0",
        "celery",
    ],
    extras_require={
        "dev": ["pytest"],
    },
)
