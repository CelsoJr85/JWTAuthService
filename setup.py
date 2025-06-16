from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="jwt-auth-service",
    version="1.0.0",
    author="Seu Nome",
    author_email="seu.email@exemplo.com",
    description="Serviço de autenticação JWT reutilizável para Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/seuusuario/jwt-auth-service",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "pyjwt[crypto]>=2.8.0",
        "passlib[bcrypt]>=1.7.4",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
        ],
        "fastapi": [
            "fastapi>=0.68.0",
            "python-multipart>=0.0.5",
        ],
        "flask": [
            "flask>=2.0.0",
        ],
    },
    keywords="jwt, authentication, auth, token, security, bcrypt, fastapi, flask",
    project_urls={
        "Bug Reports": "https://github.com/seuusuario/jwt-auth-service/issues",
        "Source": "https://github.com/seuusuario/jwt-auth-service",
        "Documentation": "https://github.com/seuusuario/jwt-auth-service/blob/main/docs/usage.md",
    },
)