from setuptools import setup

# Safe: version constraints in install_requires
setup(
    name="myapp",
    version="1.0.0",
    install_requires=[
        "flask>=3.0,<4",
        "requests>=2.28,<3",
        "sqlalchemy>=2.0,<3",
    ],
    extras_require={
        "dev": ["pytest>=8.0,<9"],
    },
)
